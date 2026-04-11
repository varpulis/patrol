//! Patrol's SASE engine — manages NFA runs and produces matches.
//!
//! Windows are measured against **event time** when events carry a timestamp;
//! otherwise the engine falls back to wall-clock time. This matters because
//! log analysis replays historical data — the previous implementation used
//! `Instant::now()` and silently rejected any run whose wall-clock duration
//! exceeded the window, regardless of when the events actually happened.

use std::collections::HashMap;
use std::time::Instant;

use crate::event::Event;
use crate::nfa::{eval_predicate, forbidden_matches, predicate_references_alias, Nfa, StateType};

/// A single active run (partial match in progress)
#[derive(Debug, Clone)]
struct Run {
    current_state: usize,
    captured: HashMap<String, Event>,
    events: Vec<Event>,
    /// Event time (Unix seconds) of the event that started this run.
    started_event_time: Option<f64>,
    /// Wall-clock start — only used as a fallback when events lack timestamps.
    started_wall: Instant,
}

/// A completed match
#[derive(Debug)]
pub struct Match {
    pub events: Vec<Event>,
    pub captured: HashMap<String, Event>,
}

pub struct Engine {
    nfa: Nfa,
    runs: Vec<Run>,
    partitioned_runs: HashMap<String, Vec<Run>>,
}

enum Advance {
    Continue,
    Complete(Match),
    Emit(Match),
    NoMatch,
}

impl Engine {
    pub fn new(nfa: Nfa) -> Self {
        Self {
            nfa,
            runs: Vec::new(),
            partitioned_runs: HashMap::new(),
        }
    }

    pub fn process(&mut self, event: &Event) -> Vec<Match> {
        let mut completed = Vec::new();
        let now = event.timestamp;

        if let Some(ref partition_field) = self.nfa.partition_by.clone() {
            let key = event
                .get(partition_field)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let runs = self.partitioned_runs.entry(key.clone()).or_default();
            advance_runs(&self.nfa, runs, event, now, &mut completed);

            // For monotonic patterns, only one run per partition
            let has_active =
                self.nfa.has_monotonic() && runs.iter().any(|r| !is_timed_out(&self.nfa, r, now));

            if !has_active {
                try_start_or_complete(&self.nfa, event, runs, &mut completed);
            }
        } else {
            advance_runs(&self.nfa, &mut self.runs, event, now, &mut completed);

            // For monotonic patterns we want a single run; for everything else
            // we allow overlapping runs so multiple concurrent matches can fire.
            let suppress_new = self.nfa.has_monotonic() && !self.runs.is_empty();
            if !suppress_new {
                try_start_or_complete(&self.nfa, event, &mut self.runs, &mut completed);
            }
        }

        completed
    }

    /// Drain any runs that are still alive but should complete — specifically,
    /// trailing-negation runs whose absence window has effectively expired.
    /// Call this at end-of-input.
    pub fn flush(&mut self) -> Vec<Match> {
        let mut completed = Vec::new();
        let states = &self.nfa.states;

        self.runs.retain_mut(|run| {
            if states[run.current_state].trailing_negation {
                completed.push(Match {
                    events: std::mem::take(&mut run.events),
                    captured: std::mem::take(&mut run.captured),
                });
                false
            } else {
                true
            }
        });

        for runs in self.partitioned_runs.values_mut() {
            runs.retain_mut(|run| {
                if states[run.current_state].trailing_negation {
                    completed.push(Match {
                        events: std::mem::take(&mut run.events),
                        captured: std::mem::take(&mut run.captured),
                    });
                    false
                } else {
                    true
                }
            });
        }

        completed
    }
}

/// Try to spawn a new run starting from this event. If the resulting run is
/// already at a terminal state (single-step pattern / predicate filter), emit
/// the completed match immediately rather than parking the run.
fn try_start_or_complete(
    nfa: &Nfa,
    event: &Event,
    runs: &mut Vec<Run>,
    completed: &mut Vec<Match>,
) {
    if let Some(mut run) = try_start_run(nfa, event) {
        let state = &nfa.states[run.current_state];
        if is_terminal(nfa, state) {
            completed.push(Match {
                events: std::mem::take(&mut run.events),
                captured: std::mem::take(&mut run.captured),
            });
        } else {
            runs.push(run);
        }
    }
}

/// A state is "terminal" when it has a direct transition to Accept AND it is
/// not a Kleene loop (which has additional accumulation semantics) AND it is
/// not a trailing-negation state (which completes via timeout, not a transition).
fn is_terminal(nfa: &Nfa, state: &crate::nfa::State) -> bool {
    if state.state_type == StateType::Kleene || state.trailing_negation {
        return false;
    }
    state
        .transitions
        .iter()
        .any(|&id| nfa.states[id].state_type == StateType::Accept)
}

fn advance_runs(
    nfa: &Nfa,
    runs: &mut Vec<Run>,
    event: &Event,
    now_event_time: Option<f64>,
    completed: &mut Vec<Match>,
) {
    let mut i = 0;
    while i < runs.len() {
        // 1) Timeout check first. Trailing-negation runs that time out succeed
        //    (absence confirmed); all others fail.
        if is_timed_out(nfa, &runs[i], now_event_time) {
            let state = &nfa.states[runs[i].current_state];
            if state.trailing_negation {
                completed.push(Match {
                    events: std::mem::take(&mut runs[i].events),
                    captured: std::mem::take(&mut runs[i].captured),
                });
            }
            runs.swap_remove(i);
            continue;
        }

        // 2) Forbidden (negation) check. If the current event matches a forbidden
        //    spec at this state, kill the run.
        let state = &nfa.states[runs[i].current_state];
        let mut killed = false;
        for fb in &state.forbidden {
            if forbidden_matches(fb, event, &runs[i].captured) {
                killed = true;
                break;
            }
        }
        if killed {
            runs.swap_remove(i);
            continue;
        }

        // 3) Trailing-negation states don't advance on events — only time.
        if state.trailing_negation {
            i += 1;
            continue;
        }

        // 4) Normal advancement.
        match advance_run(nfa, &mut runs[i], event) {
            Advance::Continue => i += 1,
            Advance::Complete(m) => {
                completed.push(m);
                runs.swap_remove(i);
            }
            Advance::Emit(m) => {
                completed.push(m);
                i += 1;
            }
            Advance::NoMatch => i += 1,
        }
    }
}

fn advance_run(nfa: &Nfa, run: &mut Run, event: &Event) -> Advance {
    let state = &nfa.states[run.current_state];

    if state.state_type == StateType::Accept {
        return Advance::Complete(Match {
            events: std::mem::take(&mut run.events),
            captured: std::mem::take(&mut run.captured),
        });
    }

    // Kleene self-loop
    if state.state_type == StateType::Kleene && state.self_loop {
        let kleene_matches = event_matches_kleene(nfa, state, event, &run.captured, &run.events);

        if kleene_matches {
            run.events.push(event.clone());
            if let Some(ref alias) = state.alias {
                run.captured.insert(alias.clone(), event.clone());
            }

            if state.is_monotonic {
                return Advance::Continue; // Accumulate silently
            }
            return Advance::Emit(Match {
                events: run.events.clone(),
                captured: run.captured.clone(),
            });
        }

        // Kleene break — check epsilon to Accept
        for &eps_id in &state.epsilon_transitions {
            if nfa.states[eps_id].state_type == StateType::Accept && !run.events.is_empty() {
                return Advance::Complete(Match {
                    events: std::mem::take(&mut run.events),
                    captured: std::mem::take(&mut run.captured),
                });
            }
        }

        // Fall through to check transitions (e.g., terminator after Kleene)
    }

    // Check transitions
    for &next_id in &state.transitions {
        let next_state = &nfa.states[next_id];

        // Skip accept state in transitions (handled above)
        if next_state.state_type == StateType::Accept {
            // Accept reached via transition — pattern complete
            return Advance::Complete(Match {
                events: std::mem::take(&mut run.events),
                captured: std::mem::take(&mut run.captured),
            });
        }

        // Check event type
        if let Some(ref expected) = next_state.event_type {
            if event.event_type != *expected {
                continue;
            }
        }

        // Evaluate predicate
        let pred_ok = if let Some(ref pred) = next_state.predicate {
            if next_state.state_type == StateType::Kleene
                && next_state.self_loop
                && next_state.alias.as_ref().is_some_and(|a| {
                    !run.captured.contains_key(a.as_str()) && predicate_references_alias(pred, a)
                })
            {
                // First Kleene entry with self-ref: bind to previous event
                if let Some(prev) = run.events.last() {
                    let mut tmp = run.captured.clone();
                    let alias = next_state.alias.as_ref().unwrap();
                    tmp.insert(alias.clone(), prev.clone());
                    eval_predicate(pred, event, &tmp)
                } else {
                    true
                }
            } else {
                eval_predicate(pred, event, &run.captured)
            }
        } else {
            true
        };

        if pred_ok {
            run.current_state = next_id;
            run.events.push(event.clone());
            if let Some(ref alias) = next_state.alias {
                run.captured.insert(alias.clone(), event.clone());
            }

            if next_state.state_type == StateType::Kleene && next_state.self_loop {
                if next_state.is_monotonic {
                    return Advance::Continue;
                }
                return Advance::Emit(Match {
                    events: run.events.clone(),
                    captured: run.captured.clone(),
                });
            }

            // Eagerly complete when the next state leads straight to Accept.
            // Without this, runs at the final step of a pattern sit forever
            // unless another event happens to arrive later.
            if is_terminal(nfa, next_state) {
                return Advance::Complete(Match {
                    events: std::mem::take(&mut run.events),
                    captured: std::mem::take(&mut run.captured),
                });
            }

            return Advance::Continue;
        }
    }

    Advance::NoMatch
}

fn event_matches_kleene(
    _nfa: &Nfa,
    state: &crate::nfa::State,
    event: &Event,
    captured: &HashMap<String, Event>,
    events: &[Event],
) -> bool {
    if let Some(ref expected) = state.event_type {
        if event.event_type != *expected {
            return false;
        }
    }

    if let Some(ref pred) = state.predicate {
        if state.is_monotonic {
            if let Some(alias) = &state.alias {
                if !captured.contains_key(alias.as_str()) {
                    if let Some(prev) = events.last() {
                        let mut tmp = captured.clone();
                        tmp.insert(alias.clone(), prev.clone());
                        return eval_predicate(pred, event, &tmp);
                    }
                    return true;
                }
            }
        }
        return eval_predicate(pred, event, captured);
    }

    true
}

fn try_start_run(nfa: &Nfa, event: &Event) -> Option<Run> {
    let start = &nfa.states[nfa.start_state];

    for &next_id in &start.transitions {
        let next_state = &nfa.states[next_id];

        if let Some(ref expected) = next_state.event_type {
            if event.event_type != *expected {
                continue;
            }
        }

        let pred_ok = if let Some(ref pred) = next_state.predicate {
            if next_state.state_type == StateType::Kleene
                && next_state.self_loop
                && next_state
                    .alias
                    .as_ref()
                    .is_some_and(|a| predicate_references_alias(pred, a))
            {
                true // Skip self-ref predicate on first entry
            } else {
                eval_predicate(pred, event, &HashMap::new())
            }
        } else {
            true
        };

        if pred_ok {
            let mut run = Run {
                current_state: next_id,
                captured: HashMap::new(),
                events: vec![event.clone()],
                started_event_time: event.timestamp,
                started_wall: Instant::now(),
            };
            if let Some(ref alias) = next_state.alias {
                run.captured.insert(alias.clone(), event.clone());
            }
            return Some(run);
        }
    }

    None
}

/// Has this run's window expired? Uses event time if both the run and the
/// current event carry timestamps; otherwise falls back to wall clock.
fn is_timed_out(nfa: &Nfa, run: &Run, now_event_time: Option<f64>) -> bool {
    let within = match nfa.within {
        Some(w) => w,
        None => return false,
    };
    match (run.started_event_time, now_event_time) {
        (Some(start), Some(now)) => (now - start) > within.as_secs_f64(),
        _ => run.started_wall.elapsed() > within,
    }
}
