# patrol

**Temporal grep — find multi-step patterns in log files.**

```bash
# Brute force: repeated failed logins followed by success within 5 minutes
patrol 'sshd[message~"Failed"] -> sshd[message~"Failed"] -> sshd[message~"Accepted"] .within(5m)' /var/log/auth.log

# Missing heartbeat: a request with no matching response within 30 seconds
patrol 'Request -> NOT Response .within(30s) .partition_by(request_id)' api.jsonl

# Error escalation: timeout → refused → circuit open, across regex-matched logs
patrol 'error[msg=~"timeout"] -> error[msg=~"refused"] -> error[msg=~"circuit"]' app.log
```

536 KB. Single binary. Two dependencies (`serde_json`, `regex-lite`). Auto-detects syslog, JSON, logfmt, and Apache/Nginx formats. Event-time windows, negation, regex, stack-trace folding.

`grep` finds strings. `patrol` finds **sequences**.

## Install

```bash
curl -sSf https://raw.githubusercontent.com/varpulis/patrol/main/install.sh | sh
```

Or via Cargo:

```bash
cargo install patrol
```

Prebuilt binaries for Linux, macOS, and Windows are available on the [Releases](https://github.com/varpulis/patrol/releases) page.

## The three patterns patrol exists for

### 1. Brute force / intrusion attempts (sequence)

Detect repeated failed logins followed by a successful one — the classic credential stuffing signature that `grep | awk | uniq -c` can't express because it needs *order*.

```bash
patrol 'sshd[message~"Failed"] -> sshd[message~"Failed"] -> sshd[message~"Accepted"] .within(5m)' /var/log/auth.log
```

Auto-detects syslog. Event-time window — the 5-minute limit is measured against the timestamps in the log, not wall-clock time. You can run this on a week-old `auth.log` and it works.

### 2. Missing response / stuck request (trailing negation)

Find requests that never got a response — one of the hardest patterns to express in traditional log tools, because you're searching for the *absence* of an event.

```bash
patrol 'Request as r -> NOT Response .within(30s) .partition_by(request_id)' api.jsonl
```

`NOT Response .within(30s)` means "after each Request, if no matching Response arrives within 30 seconds, emit a match." `partition_by(request_id)` tracks each request independently. Also works for missing heartbeats, missing ACKs, missing build completions.

### 3. Error escalation with regex (sequence + regex)

Detect the progression pattern that precedes an outage: connection timeouts, then refused connections, then circuit breakers tripping.

```bash
patrol 'error[msg=~"timeout"] -> error[msg=~"refused"] -> error[msg=~"circuit"]' app.log
```

`=~` is regex match (via `regex-lite` — no Unicode / backreferences / lookaround, but fast and tiny). Use `!=~` for negation. `~` is still available for plain substring match.

## Install and run

```bash
cargo install patrol
# or
curl -sSf https://raw.githubusercontent.com/varpulis/patrol/main/install.sh | sh
```

Prebuilt binaries for Linux, macOS, Windows on the [Releases](https://github.com/varpulis/patrol/releases) page.

## Pattern syntax

```
EventType[field=="value"] -> EventType[field>10] .within(5m) .partition_by(key)
```

| Syntax | Meaning |
|--------|---------|
| `A -> B -> C` | A followed by B followed by C |
| `A[field=="value"]` | Field equality (`==`, `!=`, `<`, `>`, `<=`, `>=`) |
| `A[field~"substring"]` | Field contains substring (`!~` for doesn't) |
| `A[field=~"regex"]` | Regex match (`!=~` for doesn't match) |
| `all A as items` | One or more A events (Kleene+) |
| `A -> NOT B -> C` | B must not occur between A and C |
| `A -> NOT B .within(5m)` | Absence: no B within 5m of A |
| `A.increasing(field)` | Strictly rising values |
| `A.decreasing(field)` | Strictly falling values |
| `A where field > value` | Alternative filter syntax |
| `.within(5m)` | Event-time window (ms, s, m, h) |
| `.partition_by(field)` | Independent matching per key |

Patterns can reference earlier events by alias: `Login as l1 -> Login[user==l1.user]` matches two logins from the same user.

## Command-line flags

| Flag | Meaning |
|------|---------|
| `-p`, `--pattern-file <path>` | Read pattern from file (for long patterns) |
| `-m`, `--multiline` | Fold indented continuation lines (stack traces) into the previous record |
| `-C`, `--context <N>` | Show N lines before and after each match |
| `-B`, `--before-context <N>` | Show N lines before each match |
| `-A`, `--after-context <N>` | Show N lines after each match |
| `-h`, `--help` | Show help |
| `-V`, `--version` | Show version |

## Auto-detected formats

| Format | Detection | Fields extracted |
|--------|-----------|------------------|
| **JSON Lines** | Starts with `{` | All fields; `event_type` from `event_type`/`type`; event time from `timestamp`/`ts`/`time`/`@timestamp` |
| **Syslog** | Starts with month abbrev *or* ISO date | `hostname`, `program`, `pid`, `message`, `timestamp` |
| **logfmt** | 2+ `key=value` pairs | All key-value pairs; `event_type` from `level`/`severity`; event time from `time`/`ts` |
| **Apache/Nginx** | IP + brackets + quoted request | `ip`, `method`, `path`, `status`, `size`, `timestamp` |
| **Plain text** | Fallback | `message` = full line, `event_type` = `_` |

Event time is parsed from format-specific timestamps (BSD syslog, ISO 8601, Apache CLF, epoch numbers). `.within()` measures gaps in event time, not wall-clock time.

## Output

**TTY** (interactive):

```
MATCH #1 (3 events)
  fail: sshd { message=Failed password for alice, pid=1234, ... }
  ok:   sshd { message=Accepted password for alice, pid=1238, ... }
```

**With `-C N`** (context framing, TTY):

```
== MATCH #1 (2 events, lines 3–7) ==
   1 | Apr 11 10:00:00 srv other: boot
   2 | Apr 11 10:00:01 srv other: loading
>> 3 | Apr 11 10:00:02 srv sshd[1]: Failed password for alice
   4 | Apr 11 10:00:03 srv other: heartbeat
>> 7 | Apr 11 10:00:06 srv sshd[3]: Accepted password for alice
   8 | Apr 11 10:00:07 srv other: after1
```

**Piped** (scripting): JSON Lines, one object per match. With `-C`, context lines are embedded:

```json
{"match":1,"events":2,"captured":{...},"first_line":3,"last_line":7,"context":[{"line":3,"matched":true,"text":"..."},...]}
```

## Exit codes

Follows `grep`:

- `0` — at least one match found
- `1` — no matches
- `2` — error (bad pattern, unreadable file)

## Why patrol?

| | grep | ripgrep | patrol |
|---|---|---|---|
| Find a string | Yes | Yes | Yes (`msg~"error"`, `msg=~"^E\d+"`) |
| Find A **followed by** B | No | No | **Yes** (`A -> B`) |
| Find A **not followed by** B | No | No | **Yes** (`A -> NOT B .within(5m)`) |
| Event-time window | No | No | **Yes** (`.within(5m)`, measured against log timestamps) |
| Rising / falling trends | No | No | **Yes** (`.increasing(temp)`) |
| Structured field access | No | No | **Yes** (`[status==500]`) |
| Regex predicates | — | `ripgrep`'s only mode | **Yes** (`field=~"..."`) |
| Auto-detect log format | No | No | **Yes** |
| Stack-trace folding | No | No | **Yes** (`-m`) |
| Grep-style context lines | `-C` | `-C` | `-C` |
| Binary size | ~200 KB | ~5.6 MB | **~540 KB** |

patrol is narrower than ripgrep and narrower than Splunk. It is the best thing to reach for when you have a log file and need to express a *temporal* or *relational* question at the command line. Everything else it intentionally does not try to do.

## How it works

patrol compiles your pattern into a lightweight NFA (Non-deterministic Finite Automaton) and streams events through it. The engine supports Kleene closures (one-or-more matching), self-referencing predicates (for `.increasing()` / `.decreasing()`), cross-event references, negation (via guarded transitions), and temporal windows measured in event time.

Based on the [SASE+](https://people.cs.umass.edu/~immerman/pub/sase+sigmod08.pdf) algorithm from SIGMOD 2008 — the canonical formulation for complex event processing over event streams. Same engine that powers [Varpulis](https://github.com/varpulis/varpulis), stripped to 536 KB.

## Limits (and what to reach for instead)

- **No real-time streaming from Kafka/MQTT** — patrol is for files and pipes. For streams, use [Varpulis](https://github.com/varpulis/varpulis).
- **No aggregation** — patrol counts matches but doesn't sum/avg/percentile over them.
- **No Unicode in regex** — `regex-lite` supports ASCII only. Most log use cases are fine with this.
- **No grouping or alternation in sequences** — patterns are linear. `A -> (B | C) -> D` is not supported.

## License

MIT OR Apache-2.0
