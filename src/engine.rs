//! Patrol's SASE engine — manages NFA runs and produces matches.

use std::collections::HashMap;
use std::time::Instant;

use crate::event::Event;
use crate::nfa::{eval_predicate, predicate_references_alias, Nfa, StateType};

/// A single active run (partial match in progress)
#[derive(Debug, Clone)]
struct Run {
    current_state: usize,
    captured: HashMap<String, Event>,
    events: Vec<Event>,
    started_at: Instant,
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

        if let Some(ref partition_field) = self.nfa.partition_by.clone() {
            let key = event
                .get(&partition_field)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_default();

            let runs = self.partitioned_runs.entry(key.clone()).or_default();
            advance_runs(&self.nfa, runs, event, &mut completed);

            // For monotonic patterns, only one run per partition
            let has_active = self.nfa.has_monotonic()
                && runs.iter().any(|r| !is_timed_out(&self.nfa, r));

            if !has_active {
                if let Some(run) = try_start_run(&self.nfa, event) {
                    runs.push(run);
                }
            }
        } else {
            advance_runs(&self.nfa, &mut self.runs, event, &mut completed);

            if let Some(run) = try_start_run(&self.nfa, event) {
                self.runs.push(run);
            }
        }

        completed
    }
}

fn advance_runs(nfa: &Nfa, runs: &mut Vec<Run>, event: &Event, completed: &mut Vec<Match>) {
    let mut i = 0;
    while i < runs.len() {
        if is_timed_out(nfa, &runs[i]) {
            runs.swap_remove(i);
            continue;
        }

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
                && next_state
                    .alias
                    .as_ref()
                    .is_some_and(|a| !run.captured.contains_key(a.as_str()) && predicate_references_alias(pred, a))
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
                started_at: Instant::now(),
            };
            if let Some(ref alias) = next_state.alias {
                run.captured.insert(alias.clone(), event.clone());
            }
            return Some(run);
        }
    }

    None
}

fn is_timed_out(nfa: &Nfa, run: &Run) -> bool {
    if let Some(within) = nfa.within {
        run.started_at.elapsed() > within
    } else {
        false
    }
}
