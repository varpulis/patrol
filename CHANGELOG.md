# Changelog

All notable changes to patrol are documented in this file. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [0.2.0] — 2026-04-11

This is the first release where the `.within()` operator is actually correct
on historical log files. v0.1.0 measured time windows against wall-clock
elapsed time while the binary was running, which meant replaying last week's
`auth.log` for a `.within(5m)` query would silently drop every match if the
file took less than 5 minutes to read. Event-time windows are the headline
fix; negation, regex, and context lines round out the set.

### Fixed

- **Event-time windows.** `.within(...)` now compares timestamps extracted
  from log lines rather than `Instant::now()`. BSD syslog, ISO 8601, Apache
  CLF, logfmt `time=`, and numeric epoch (s / ms / μs / ns) are all parsed.
  Wall-clock time is used only as a fallback when events carry no timestamp.
- **Terminal-state latent bug.** Patterns whose final step matched on the
  last input event previously produced no output — the run sat at the final
  NFA state waiting for a "next event" that never came. Single-step
  predicate filters (`Read[temp>50]`) were effectively broken.
- **Monotonic patterns without `partition_by`.** `.increasing()` /
  `.decreasing()` with no partition spawned one run per event and emitted
  `N` overlapping completions on each break. Monotonic dedup now applies in
  both partitioned and non-partitioned branches.
- **ISO syslog parser.** Lines like `2026-04-11T10:00:05Z host prog: msg`
  were being sliced as a fake 15-byte BSD timestamp, producing garbage
  hostnames (`":05Z"`). The traditional parser now rejects non-month
  prefixes and the ISO path handles them properly.

### Added

- **Negation between events.** `A -> NOT B -> C` matches A followed by C
  with no B in between. Multiple NOTs compose: `A -> NOT B -> NOT C -> D`.
- **Trailing negation.** `A -> NOT B .within(5m)` matches when no B arrives
  within 5 minutes of A — the "missing heartbeat / stuck request" pattern.
  Requires `.within(...)`; the compiler rejects it otherwise.
- **Regex operators.** `field=~"pattern"` and `field!=~"pattern"` via
  `regex-lite`. Compiled at NFA build time; invalid regex is a compile error.
- **`--multiline` / `-m`.** Folds indented continuation lines (stack traces,
  wrapped fields) into the preceding record so one Java exception becomes
  one event instead of N.
- **`--pattern-file` / `-p <path>`.** Load the pattern from a file — useful
  for long patterns that are painful to shell-quote.
- **Context lines.** `-C N`, `-B N`, `-A N` — grep-style framed context in
  TTY mode; embedded as a `context` array in piped JSONL output. Match
  events are marked with `>>`.
- **Grep-style exit codes.** `0` match, `1` no match, `2` error.
- **Event `line_num`.** Every event now knows which physical line it came
  from; match output can reference source lines for context rendering.
- **Library crate.** `src/lib.rs` exposes `engine`, `event`, `format`, `nfa`,
  `pattern`, and `timestamp` for downstream use and for integration tests.
- **End-to-end test suite.** `tests/engine_tests.rs` — 24 tests covering
  sequence matching, event-time window boundaries, Kleene accumulation,
  `partition_by`, negation (between and trailing), regex operators, and
  compile-time validation of bad patterns.

### Changed

- **Binary size** is now ~540 KB (was 441 KB). The `regex-lite` dependency
  adds ~85 KB; this is the smallest regex crate in the ecosystem and does
  not pull Unicode tables. If you want the old size, v0.1.0 is tagged.
- **`nfa::compile` returns `Result<Nfa, String>`** instead of panicking.
  Invalid regex, malformed negation, and missing `within()` on trailing
  negation surface as parse errors instead of crashes.

### Known limits (unchanged)

- No real-time streaming from Kafka/MQTT — patrol is for files and pipes.
- No aggregation over matches. Use Varpulis for count/sum/avg.
- No grouping or alternation in sequences. `A -> (B|C) -> D` is not
  supported; patterns are linear.
- `regex-lite` is ASCII-only (no Unicode classes). Works for 99% of log
  content; if you need Unicode, open an issue.

## [0.1.0] — 2026-04

Initial release. Pattern DSL, NFA engine, auto-detection of syslog / JSON /
logfmt / Apache CLF / plain text, temporal windows (wall-clock), Kleene+,
monotonic `.increasing()` / `.decreasing()`, partition_by, JSONL output.
