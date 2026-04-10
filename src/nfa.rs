//! Minimal NFA engine for patrol — extracted from varpulis-sase, stripped to essentials.
//!
//! Supports: sequences (A -> B -> C), Kleene+ (all B), predicates (field > value),
//! cross-event references (b.field > a.field), self-referencing (.increasing),
//! temporal windows (.within), and partition-by.

use std::collections::HashMap;
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

    #[allow(dead_code)]
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

pub fn compile(steps: &[PatternStep], within: Option<Duration>, partition_by: Option<&str>) -> Nfa {
    let mut nfa = Nfa::new();
    nfa.within = within;
    nfa.partition_by = partition_by.map(|s| s.to_string());

    let mut prev = nfa.start_state;

    for step in steps {
        let predicate = build_predicate(step);
        let is_monotonic = step.monotonic.is_some();

        let mut state = State {
            id: 0,
            state_type: if step.match_all || step.monotonic.is_some() {
                StateType::Kleene
            } else {
                StateType::Normal
            },
            event_type: Some(step.event_type.clone()),
            predicate,
            alias: step.alias.clone(),
            self_loop: step.match_all || step.monotonic.is_some(),
            transitions: Vec::new(),
            epsilon_transitions: Vec::new(),
            is_monotonic,
        };

        // For monotonic steps, alias is required (defaulting to event type name)
        if is_monotonic && state.alias.is_none() {
            state.alias = Some(step.event_type.clone());
        }

        let state_id = nfa.add_state(state);
        nfa.add_transition(prev, state_id);
        prev = state_id;
    }

    // Add accept state
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
    };
    let accept_id = nfa.add_state(accept);
    nfa.add_transition(prev, accept_id);

    // For the last Kleene state, add epsilon to Accept so it can complete on break
    if prev > 0 && nfa.states[prev].state_type == StateType::Kleene {
        nfa.add_epsilon(prev, accept_id);
    }

    nfa
}

fn build_predicate(step: &PatternStep) -> Option<Predicate> {
    let mut pred: Option<Predicate> = None;

    // Explicit comparisons from where clause
    for cmp in &step.comparisons {
        let p = if let Some(ref ref_alias) = cmp.ref_alias {
            Predicate::CompareRef {
                field: cmp.field.clone(),
                op: cmp_op_from(&cmp.op),
                ref_alias: ref_alias.clone(),
                ref_field: cmp.ref_field.clone().unwrap_or_else(|| cmp.field.clone()),
            }
        } else {
            Predicate::Compare {
                field: cmp.field.clone(),
                op: cmp_op_from(&cmp.op),
                value: cmp.value.clone(),
            }
        };
        pred = Some(match pred {
            Some(existing) => Predicate::And(Box::new(existing), Box::new(p)),
            None => p,
        });
    }

    // Monotonic operator generates self-referencing predicate
    if let Some(ref mono) = step.monotonic {
        let alias = step.alias.as_deref().unwrap_or(&step.event_type).to_string();
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

    pred
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

pub fn eval_predicate(
    pred: &Predicate,
    event: &Event,
    captured: &HashMap<String, Event>,
) -> bool {
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
        CmpOp::Le => matches!(ord, Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)),
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
        Predicate::Compare { .. } => false,
    }
}
