//! End-to-end tests for the engine: parse → compile → process events → assert.
//!
//! These verify the actual matching semantics, not just the parser. Every test
//! uses explicit event timestamps so window behavior is deterministic and does
//! not depend on wall-clock time.

use std::collections::HashMap;

use patrol::engine::{Engine, Match};
use patrol::event::Event;
use patrol::nfa;
use patrol::pattern;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ev(ty: &str, t: f64, fields: &[(&str, serde_json::Value)]) -> Event {
    let mut data = HashMap::new();
    for (k, v) in fields {
        data.insert((*k).to_string(), v.clone());
    }
    Event {
        event_type: ty.to_string(),
        data,
        timestamp: Some(t),
        line_num: 0,
    }
}

fn s(v: &str) -> serde_json::Value {
    serde_json::Value::String(v.to_string())
}

fn n(v: i64) -> serde_json::Value {
    serde_json::json!(v)
}

fn run(pattern: &str, events: &[Event]) -> Vec<Match> {
    let pat = pattern::parse(pattern).expect("pattern parse");
    let nfa =
        nfa::compile(&pat.steps, pat.within, pat.partition_by.as_deref()).expect("nfa compile");
    let mut eng = Engine::new(nfa);
    let mut out = Vec::new();
    for e in events {
        out.extend(eng.process(e));
    }
    out.extend(eng.flush());
    out
}

// ---------------------------------------------------------------------------
// Basic sequences
// ---------------------------------------------------------------------------

#[test]
fn simple_sequence_matches() {
    let events = vec![ev("A", 1.0, &[]), ev("B", 2.0, &[]), ev("C", 3.0, &[])];
    let matches = run("A -> B -> C", &events);
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].events.len(), 3);
}

#[test]
fn sequence_does_not_match_when_step_missing() {
    let events = vec![ev("A", 1.0, &[]), ev("C", 2.0, &[])];
    assert!(run("A -> B -> C", &events).is_empty());
}

#[test]
fn sequence_does_not_match_wrong_order() {
    let events = vec![ev("C", 1.0, &[]), ev("B", 2.0, &[]), ev("A", 3.0, &[])];
    assert!(run("A -> B -> C", &events).is_empty());
}

#[test]
fn sequence_ignores_interleaved_unrelated_events() {
    let events = vec![
        ev("A", 1.0, &[]),
        ev("X", 2.0, &[]),
        ev("Y", 3.0, &[]),
        ev("B", 4.0, &[]),
        ev("Z", 5.0, &[]),
        ev("C", 6.0, &[]),
    ];
    let matches = run("A -> B -> C", &events);
    assert_eq!(matches.len(), 1);
}

// ---------------------------------------------------------------------------
// Predicates
// ---------------------------------------------------------------------------

#[test]
fn predicate_filters_by_equality() {
    let events = vec![
        ev("Login", 1.0, &[("status", s("failed"))]),
        ev("Login", 2.0, &[("status", s("ok"))]),
    ];
    let matches = run(r#"Login[status=="failed"]"#, &events);
    assert_eq!(matches.len(), 1);
}

#[test]
fn predicate_filters_by_numeric_comparison() {
    let events = vec![
        ev("Read", 1.0, &[("temp", n(30))]),
        ev("Read", 2.0, &[("temp", n(70))]),
        ev("Read", 3.0, &[("temp", n(99))]),
    ];
    let matches = run("Read[temp>50]", &events);
    // Two events cross the threshold.
    assert_eq!(matches.len(), 2);
}

#[test]
fn substring_matches_with_tilde() {
    let events = vec![
        ev("sshd", 1.0, &[("message", s("Failed password for alice"))]),
        ev(
            "sshd",
            2.0,
            &[("message", s("Accepted password for alice"))],
        ),
    ];
    let matches = run(
        r#"sshd[message~"Failed"] -> sshd[message~"Accepted"]"#,
        &events,
    );
    assert_eq!(matches.len(), 1);
}

// ---------------------------------------------------------------------------
// Event-time windows (the bug we fixed)
// ---------------------------------------------------------------------------

#[test]
fn within_uses_event_time_not_wall_clock() {
    // Events span 10s in event time — well within a 5-minute window. This would
    // have failed under wall-clock timing in the previous implementation only
    // if processing took > 5 minutes; with event time it's deterministic.
    let events = vec![ev("A", 100.0, &[]), ev("B", 110.0, &[])];
    let matches = run("A -> B .within(5m)", &events);
    assert_eq!(matches.len(), 1);
}

#[test]
fn within_rejects_when_event_time_exceeds_window() {
    // Six minutes between events → 5m window must reject.
    let events = vec![
        ev("A", 0.0, &[]),
        ev("B", 360.0, &[]), // 6 minutes later
    ];
    let matches = run("A -> B .within(5m)", &events);
    assert!(
        matches.is_empty(),
        "6-minute gap should exceed 5-minute window"
    );
}

#[test]
fn within_accepts_events_at_boundary() {
    // 4 minutes 59 seconds — inside a 5m window.
    let events = vec![ev("A", 0.0, &[]), ev("B", 299.0, &[])];
    let matches = run("A -> B .within(5m)", &events);
    assert_eq!(matches.len(), 1);
}

// ---------------------------------------------------------------------------
// Kleene+ and monotonic
// ---------------------------------------------------------------------------

#[test]
fn monotonic_increasing_captures_strictly_rising_sequence() {
    let events = vec![
        ev("R", 1.0, &[("t", n(10))]),
        ev("R", 2.0, &[("t", n(20))]),
        ev("R", 3.0, &[("t", n(30))]),
        ev("R", 4.0, &[("t", n(25))]), // break
    ];
    let matches = run("R.increasing(t)", &events);
    // One emitted match on break; contains the three rising readings.
    assert_eq!(matches.len(), 1);
    assert!(matches[0].events.len() >= 3);
}

#[test]
fn partition_by_isolates_matches_per_key() {
    let events = vec![
        ev("R", 1.0, &[("sid", s("A")), ("t", n(10))]),
        ev("R", 2.0, &[("sid", s("B")), ("t", n(5))]),
        ev("R", 3.0, &[("sid", s("A")), ("t", n(20))]),
        ev("R", 4.0, &[("sid", s("B")), ("t", n(15))]),
        ev("R", 5.0, &[("sid", s("A")), ("t", n(5))]), // A breaks
        ev("R", 6.0, &[("sid", s("B")), ("t", n(2))]), // B breaks
    ];
    let matches = run("R.increasing(t) .partition_by(sid)", &events);
    // One match per partition on break.
    assert_eq!(matches.len(), 2);
}

// ---------------------------------------------------------------------------
// Negation (between events)
// ---------------------------------------------------------------------------

#[test]
fn not_between_kills_run_when_forbidden_arrives() {
    let events = vec![
        ev("A", 1.0, &[]),
        ev("B", 2.0, &[]), // forbidden — kills the run
        ev("C", 3.0, &[]),
    ];
    let matches = run("A -> NOT B -> C", &events);
    assert!(matches.is_empty(), "B between A and C must abort the match");
}

#[test]
fn not_between_allows_unrelated_events() {
    let events = vec![
        ev("A", 1.0, &[]),
        ev("X", 2.0, &[]), // unrelated; fine
        ev("C", 3.0, &[]),
    ];
    let matches = run("A -> NOT B -> C", &events);
    assert_eq!(matches.len(), 1);
}

#[test]
fn not_between_matches_second_occurrence() {
    // First A→B aborts, but a second A→C succeeds.
    let events = vec![
        ev("A", 1.0, &[]),
        ev("B", 2.0, &[]),
        ev("A", 3.0, &[]),
        ev("C", 4.0, &[]),
    ];
    let matches = run("A -> NOT B -> C", &events);
    assert_eq!(matches.len(), 1);
}

// ---------------------------------------------------------------------------
// Trailing negation (absence within a window)
// ---------------------------------------------------------------------------

#[test]
fn trailing_not_matches_when_forbidden_absent_within_window() {
    // Request followed by 10s of silence → absence confirmed.
    let events = vec![
        ev("Request", 0.0, &[]),
        ev("Heartbeat", 5.0, &[]),
        ev("Heartbeat", 30.0, &[]), // past 10s deadline — triggers absence-accept
    ];
    let matches = run("Request -> NOT Response .within(10s)", &events);
    assert_eq!(
        matches.len(),
        1,
        "absence should be confirmed past the deadline"
    );
}

#[test]
fn trailing_not_kills_when_forbidden_arrives_in_window() {
    let events = vec![
        ev("Request", 0.0, &[]),
        ev("Response", 3.0, &[]), // within window → not an absence
        ev("Heartbeat", 30.0, &[]),
    ];
    let matches = run("Request -> NOT Response .within(10s)", &events);
    assert!(matches.is_empty());
}

#[test]
fn trailing_not_flushes_on_eof_if_no_later_events() {
    // Only the Request event exists; input ends before the window could close.
    // flush() should still complete the run because EOF means we're not going
    // to see anything further, so absence is the safe interpretation.
    let events = vec![ev("Request", 0.0, &[])];
    let matches = run("Request -> NOT Response .within(10s)", &events);
    assert_eq!(matches.len(), 1, "EOF must flush trailing-negation runs");
}

#[test]
fn trailing_not_requires_within_at_compile_time() {
    let pat = pattern::parse("A -> NOT B").expect("parse");
    let result = nfa::compile(&pat.steps, pat.within, pat.partition_by.as_deref());
    assert!(
        result.is_err(),
        "trailing NOT without .within() must be rejected"
    );
}

#[test]
fn pattern_starting_with_not_is_rejected() {
    let pat = pattern::parse("NOT A -> B").expect("parse");
    let result = nfa::compile(&pat.steps, pat.within, pat.partition_by.as_deref());
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Regex operator
// ---------------------------------------------------------------------------

#[test]
fn regex_operator_matches_patterns() {
    let events = vec![
        ev("log", 1.0, &[("msg", s("error: connection refused"))]),
        ev("log", 2.0, &[("msg", s("info: ok"))]),
    ];
    let matches = run(r#"log[msg=~"^error:"]"#, &events);
    assert_eq!(matches.len(), 1);
}

#[test]
fn regex_operator_captures_with_alternation() {
    let events = vec![
        ev("log", 1.0, &[("code", s("E401"))]),
        ev("log", 2.0, &[("code", s("E403"))]),
        ev("log", 3.0, &[("code", s("200"))]),
    ];
    let matches = run(r#"log[code=~"^E(401|403)$"]"#, &events);
    assert_eq!(matches.len(), 2);
}

#[test]
fn regex_not_operator_matches_inverse() {
    let events = vec![
        ev("log", 1.0, &[("lvl", s("DEBUG"))]),
        ev("log", 2.0, &[("lvl", s("ERROR"))]),
    ];
    let matches = run(r#"log[lvl!=~"^DEBUG$"]"#, &events);
    assert_eq!(matches.len(), 1);
}

#[test]
fn invalid_regex_rejected_at_compile_time() {
    let pat = pattern::parse(r#"log[msg=~"["]"#).expect("parse");
    let result = nfa::compile(&pat.steps, pat.within, pat.partition_by.as_deref());
    assert!(
        result.is_err(),
        "unbalanced bracket should fail compilation"
    );
}
