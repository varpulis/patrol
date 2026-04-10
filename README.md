# patrol

**Temporal grep — find multi-step patterns in log files.**

```bash
# Brute force: 3 failed logins then success
patrol 'sshd[message~"Failed"] -> sshd[message~"Failed"] -> sshd[message~"Accepted"]' /var/log/auth.log

# Rising temperature across sensors
cat sensors.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'

# API errors followed by outage
patrol 'error -> error -> error .within(30s)' app.log
```

441 KB. Single binary. Zero dependencies. Auto-detects syslog, JSON, logfmt, and Apache/Nginx formats.

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

## Quick Examples

### Syslog — SSH brute force

```bash
patrol 'sshd[message~"Failed"] -> sshd[message~"Accepted"] .within(5m)' /var/log/auth.log
```

Finds: failed login → successful login within 5 minutes. Auto-detects syslog format, extracts `program`, `hostname`, `pid`, `message` fields.

### JSON — Rising sensor values

```bash
cat metrics.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'
```

Detects strictly rising temperature sequences per sensor. Emits one match when the trend breaks.

### logfmt — Error escalation

```bash
patrol 'error[msg~"timeout"] -> error[msg~"connection refused"] -> error[msg~"circuit open"]' app.log
```

Finds: timeout → connection refused → circuit breaker open. Auto-detects `key=value` format.

### Apache/Nginx — Repeated 401s then success

```bash
patrol 'client_error -> client_error -> client_error -> request .within(1m)' access.log
```

Status codes are auto-mapped: 2xx→`request`, 3xx→`redirect`, 4xx→`client_error`, 5xx→`error`.

### Plain text — Keyword sequences

```bash
patrol '_[message~"ERROR"] -> _[message~"FATAL"]' application.log
```

For unstructured logs, use `_` as the event type and `message~"keyword"` for substring matching.

## Pattern Syntax

```
EventType[field=="value"] -> EventType[field>10] .within(5m) .partition_by(key)
```

| Syntax | Meaning |
|--------|---------|
| `A -> B -> C` | A followed by B followed by C |
| `A[field=="value"]` | Field comparison (==, !=, <, >, <=, >=) |
| `A[field~"substring"]` | Field contains substring |
| `A[field!~"substring"]` | Field does not contain substring |
| `all A as items` | One or more A events (Kleene+) |
| `A.increasing(field)` | Strictly rising values |
| `A.decreasing(field)` | Strictly falling values |
| `A where field > value` | Alternative filter syntax |
| `.within(5m)` | Time window (ms, s, m, h) |
| `.partition_by(field)` | Independent matching per key |

## Auto-Detected Formats

| Format | Detection | Fields extracted |
|--------|-----------|-----------------|
| **JSON Lines** | Starts with `{` | All fields; `event_type` from `event_type`/`type` key |
| **Syslog** | Starts with month or ISO timestamp | `hostname`, `program`, `pid`, `message`, `timestamp` |
| **logfmt** | Contains 2+ `key=value` pairs | All key-value pairs; event_type from `level`/`severity` |
| **Apache/Nginx** | IP + brackets + quotes | `ip`, `method`, `path`, `status`, `size`, `timestamp` |
| **Plain text** | Fallback | `message` = full line, event_type = `_` |

## Output

**TTY** (interactive): Colored match summaries

```
MATCH #1 (5 events)
  rising: TempReading { sensor_id=HVAC-01, temperature=55 }
```

**Pipe** (scripting): JSON Lines — one JSON object per match

```json
{"match":1,"events":5,"captured":{"rising":{"event_type":"TempReading","sensor_id":"HVAC-01","temperature":55}}}
```

## Why patrol?

| | grep | ripgrep | patrol |
|---|---|---|---|
| Find a string | Yes | Yes | Yes (`message~"error"`) |
| Find A **followed by** B | No | No | **Yes** (`A -> B`) |
| Time window | No | No | **Yes** (`.within(5m)`) |
| Rising/falling trends | No | No | **Yes** (`.increasing()`) |
| Structured field access | No | No | **Yes** (`[status==500]`) |
| Auto-detect log format | No | No | **Yes** |
| Binary size | 200 KB | 5.6 MB | **441 KB** |

## How It Works

patrol compiles your pattern into a lightweight NFA (Non-deterministic Finite Automaton) and streams events through it. No regex engine, no JVM, no runtime dependencies. The NFA supports Kleene closures (one-or-more matching), self-referencing predicates (for `.increasing()`/`.decreasing()`), and temporal windows.

Based on the [SASE+](https://people.cs.umass.edu/~immerman/pub/sase+sigmod08.pdf) algorithm from SIGMOD 2008. Same engine that powers [Varpulis](https://github.com/varpulis/varpulis), stripped to 441 KB.

## License

MIT OR Apache-2.0
