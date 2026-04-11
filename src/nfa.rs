//! Minimal NFA engine for patrol — extracted from varpulis-sase, stripped to essentials.
//!
//! Supports: sequences (A -> B -> C), Kleene+ (all B), predicates (field > value),
//! cross-event references (b.field > a.field), self-referencing (.increasing),
//! regex predicates (field =~ "pat"), negation (A -> NOT B -> C), trailing negation
//! with windows (A -> NOT B .within(5m)), temporal windows, and partition-by.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::event::Event;
use crate::pattern::{Comparison, Monotonic, PatternStep};

// ============================================================================
// NFA Types
// ============================================================================

#[derive(Debug, Clone, PartialEq)]
pub enum StateType {
    Start,
    Normal,
    Kleene,
    Accept,
}

#[derive(Debug, Clone)]
pub struct State {
    pub id: usize,
    pub state_type: StateType,
    pub event_type: Option<String>,
    pub predicate: Option<Predicate>,
    pub alias: Option<String>,
    pub self_loop: bool,
    pub transitions: Vec<usize>,
    pub epsilon_transitions: Vec<usize>,
    /// True when this Kleene state references its own alias in the predicate
    pub is_monotonic: bool,
    /// Forbidden events that kill this run while waiting at this state
    pub forbidden: Vec<Forbidden>,
    /// True if this state completes via timeout (A -> NOT B .within(5m))
    pub trailing_negation: bool,
}

#[derive(Debug, Clone)]
pub struct Forbidden {
    pub event_type: String,
    pub predicate: Option<Predicate>,
}

#[derive(Debug, Clone)]
pub enum Predicate {
    /// field op value
    Compare {
        field: String,
        op: CmpOp,
        value: serde_json::Value,
    },
    /// field op alias.field (cross-event reference)
    CompareRef {
        field: String,
        op: CmpOp,
        ref_alias: String,
        ref_field: String,
    },
    /// field matches regex (compiled at NFA build time)
    Regex {
        field: String,
        pattern: Arc<regex_lite::Regex>,
        negate: bool,
    },
    And(Box<Predicate>, Box<Predicate>),
}

#[derive(Debug, Clone, Copy)]
pub enum CmpOp {
    Eq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    /// `~` — string contains
    Contains,
    /// `!~` — string does not contain
    NotContains,
}

// ============================================================================
// NFA Structure
// ============================================================================

#[derive(Debug)]
pub struct Nfa {
    pub states: Vec<State>,
    pub start_state: usize,
    pub within: Option<Duration>,
    pub partition_by: Option<String>,
}

impl Nfa {
    fn new() -> Self {
        let start = State {
            id: 0,
            state_type: StateType::Start,
            event_type: None,
            predicate: None,
            alias: None,
            self_loop: false,
            transitions: Vec::new(),
            epsilon_transitions: Vec::new(),
            is_monotonic: false,
            forbidden: Vec::new(),
            trailing_negation: false,
        };
        Self {
            states: vec![start],
            start_state: 0,
            within: None,
            partition_by: None,
        }
    }

    fn add_state(&mut self, mut state: State) -> usize {
        let id = self.states.len();
        state.id = id;
        self.states.push(state);
        id
    }

    fn add_transition(&mut self, from: usize, to: usize) {
        self.states[from].transitions.push(to);
    }

    fn add_epsilon(&mut self, from: usize, to: usize) {
        self.states[from].epsilon_transitions.push(to);
    }

    /// Does this NFA have a monotonic (self-referencing) Kleene state?
    pub fn has_monotonic(&self) -> bool {
        self.states.iter().any(|s| s.is_monotonic)
    }
}

// ============================================================================
// NFA Compiler
// ============================================================================

pub fn compile(
    steps: &[PatternStep],
    within: Option<Duration>,
    partition_by: Option<&str>,
) -> Result<Nfa, String> {
    if steps.is_empty() {
        return Err("pattern must have at least one step".into());
    }
    if steps[0].negated {
        return Err("pattern cannot start with NOT".into());
    }

    // Pair each non-negated step with the negated steps that follow it.
    // [A, !B, C]  → [(A, forbidden=[B]), (C, forbidden=[])]
    // [A, !B]     → [(A, forbidden=[B], trailing)]
    let mut groups: Vec<(&PatternStep, Vec<&PatternStep>)> = Vec::new();
    for step in steps {
        if step.negated {
            match groups.last_mut() {
                Some((_, forbidden)) => forbidden.push(step),
                None => return Err("pattern cannot start with NOT".into()),
            }
        } else {
            groups.push((step, Vec::new()));
        }
    }

    let trailing = steps.last().map(|s| s.negated).unwrap_or(false);
    if trailing && within.is_none() {
        return Err("trailing NOT requires .within(duration) — absence must have a window".into());
    }

    let mut nfa = Nfa::new();
    nfa.within = within;
    nfa.partition_by = partition_by.map(|s| s.to_string());

    let mut prev = nfa.start_state;
    let groups_len = groups.len();

    for (i, (step, forbidden_steps)) in groups.iter().enumerate() {
        let predicate = build_predicate(step)?;
        let is_monotonic = step.monotonic.is_some();

        let state_type = if step.match_all || step.monotonic.is_some() {
            StateType::Kleene
        } else {
            StateType::Normal
        };

        let mut alias = step.alias.clone();
        if is_monotonic && alias.is_none() {
            alias = Some(step.event_type.clone());
        }

        let mut forbidden = Vec::with_capacity(forbidden_steps.len());
        for fb in forbidden_steps {
            forbidden.push(Forbidden {
                event_type: fb.event_type.clone(),
                predicate: build_predicate(fb)?,
            });
        }

        let is_last = i == groups_len - 1;
        let state = State {
            id: 0,
            state_type,
            event_type: Some(step.event_type.clone()),
            predicate,
            alias,
            self_loop: step.match_all || step.monotonic.is_some(),
            transitions: Vec::new(),
            epsilon_transitions: Vec::new(),
            is_monotonic,
            forbidden,
            trailing_negation: is_last && trailing,
        };

        let state_id = nfa.add_state(state);
        nfa.add_transition(prev, state_id);
        prev = state_id;
    }

    // Add Accept state unless the last state completes via timeout (trailing negation).
    if !nfa.states[prev].trailing_negation {
        let accept = State {
            id: 0,
            state_type: StateType::Accept,
            event_type: None,
            predicate: None,
            alias: None,
            self_loop: false,
            transitions: Vec::new(),
            epsilon_transitions: Vec::new(),
            is_monotonic: false,
            forbidden: Vec::new(),
            trailing_negation: false,
        };
        let accept_id = nfa.add_state(accept);
        nfa.add_transition(prev, accept_id);

        // For the last Kleene state, add epsilon to Accept so it can complete on break
        if prev > 0 && nfa.states[prev].state_type == StateType::Kleene {
            nfa.add_epsilon(prev, accept_id);
        }
    }

    Ok(nfa)
}

fn build_predicate(step: &PatternStep) -> Result<Option<Predicate>, String> {
    let mut pred: Option<Predicate> = None;

    // Explicit comparisons from where clause
    for cmp in &step.comparisons {
        let p = build_comparison_predicate(cmp)?;
        pred = Some(match pred {
            Some(existing) => Predicate::And(Box::new(existing), Box::new(p)),
            None => p,
        });
    }

    // Monotonic operator generates self-referencing predicate
    if let Some(ref mono) = step.monotonic {
        let alias = step
            .alias
            .as_deref()
            .unwrap_or(&step.event_type)
            .to_string();
        let op = match mono {
            Monotonic::Increasing(f) => (f.clone(), CmpOp::Gt),
            Monotonic::Decreasing(f) => (f.clone(), CmpOp::Lt),
        };
        let mono_pred = Predicate::CompareRef {
            field: op.0.clone(),
            op: op.1,
            ref_alias: alias,
            ref_field: op.0,
        };
        pred = Some(match pred {
            Some(existing) => Predicate::And(Box::new(existing), Box::new(mono_pred)),
            None => mono_pred,
        });
    }

    Ok(pred)
}

fn build_comparison_predicate(cmp: &Comparison) -> Result<Predicate, String> {
    if cmp.op == "=~" || cmp.op == "!=~" {
        let pattern_str = cmp
            .value
            .as_str()
            .ok_or_else(|| format!("regex operator '{}' requires a string pattern", cmp.op))?;
        let re = regex_lite::Regex::new(pattern_str)
            .map_err(|e| format!("invalid regex '{pattern_str}': {e}"))?;
        return Ok(Predicate::Regex {
            field: cmp.field.clone(),
            pattern: Arc::new(re),
            negate: cmp.op == "!=~",
        });
    }

    if let Some(ref ref_alias) = cmp.ref_alias {
        Ok(Predicate::CompareRef {
            field: cmp.field.clone(),
            op: cmp_op_from(&cmp.op),
            ref_alias: ref_alias.clone(),
            ref_field: cmp.ref_field.clone().unwrap_or_else(|| cmp.field.clone()),
        })
    } else {
        Ok(Predicate::Compare {
            field: cmp.field.clone(),
            op: cmp_op_from(&cmp.op),
            value: cmp.value.clone(),
        })
    }
}

fn cmp_op_from(s: &str) -> CmpOp {
    match s {
        "==" | "=" => CmpOp::Eq,
        "!=" => CmpOp::NotEq,
        "<" => CmpOp::Lt,
        "<=" => CmpOp::Le,
        ">" => CmpOp::Gt,
        ">=" => CmpOp::Ge,
        "~" => CmpOp::Contains,
        "!~" => CmpOp::NotContains,
        _ => CmpOp::Eq,
    }
}

// ============================================================================
// Predicate Evaluation
// ============================================================================

pub fn eval_predicate(pred: &Predicate, event: &Event, captured: &HashMap<String, Event>) -> bool {
    match pred {
        Predicate::Compare { field, op, value } => {
            if let Some(ev) = event.get(field) {
                compare_json(ev, value, *op)
            } else {
                false
            }
        }
        Predicate::CompareRef {
            field,
            op,
            ref_alias,
            ref_field,
        } => {
            let event_val = event.get(field);
            let ref_val = captured.get(ref_alias).and_then(|e| e.get(ref_field));
            match (event_val, ref_val) {
                (Some(ev), Some(rv)) => compare_json(ev, rv, *op),
                _ => false,
            }
        }
        Predicate::Regex {
            field,
            pattern,
            negate,
        } => {
            let val = event
                .get(field)
                .and_then(|v| match v {
                    serde_json::Value::String(s) => Some(s.as_str()),
                    _ => None,
                })
                .unwrap_or("");
            let m = pattern.is_match(val);
            if *negate {
                !m
            } else {
                m
            }
        }
        Predicate::And(l, r) => {
            eval_predicate(l, event, captured) && eval_predicate(r, event, captured)
        }
    }
}

fn compare_json(left: &serde_json::Value, right: &serde_json::Value, op: CmpOp) -> bool {
    use serde_json::Value::*;
    let ord = match (left, right) {
        (Number(a), Number(b)) => {
            let fa = a.as_f64().unwrap_or(0.0);
            let fb = b.as_f64().unwrap_or(0.0);
            fa.partial_cmp(&fb)
        }
        (String(a), String(b)) => Some(a.cmp(b)),
        (Bool(a), Bool(b)) => Some(a.cmp(b)),
        _ => None,
    };

    match op {
        CmpOp::Eq => left == right,
        CmpOp::NotEq => left != right,
        CmpOp::Lt => ord == Some(std::cmp::Ordering::Less),
        CmpOp::Le => matches!(
            ord,
            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
        ),
        CmpOp::Gt => ord == Some(std::cmp::Ordering::Greater),
        CmpOp::Ge => matches!(
            ord,
            Some(std::cmp::Ordering::Greater | std::cmp::Ordering::Equal)
        ),
        CmpOp::Contains => {
            let l = left.as_str().unwrap_or("");
            let r = right.as_str().unwrap_or("");
            l.contains(r)
        }
        CmpOp::NotContains => {
            let l = left.as_str().unwrap_or("");
            let r = right.as_str().unwrap_or("");
            !l.contains(r)
        }
    }
}

/// Check if a predicate references a given alias (for self-referencing detection)
pub fn predicate_references_alias(pred: &Predicate, alias: &str) -> bool {
    match pred {
        Predicate::CompareRef { ref_alias, .. } => ref_alias == alias,
        Predicate::And(l, r) => {
            predicate_references_alias(l, alias) || predicate_references_alias(r, alias)
        }
        Predicate::Compare { .. } | Predicate::Regex { .. } => false,
    }
}

/// True if the event matches a forbidden spec (would kill the run).
pub fn forbidden_matches(fb: &Forbidden, event: &Event, captured: &HashMap<String, Event>) -> bool {
    if fb.event_type != "_" && event.event_type != fb.event_type {
        return false;
    }
    match fb.predicate {
        Some(ref pred) => eval_predicate(pred, event, captured),
        None => true,
    }
}
