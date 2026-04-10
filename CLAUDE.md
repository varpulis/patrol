# patrol — AI Agent Instructions

patrol is a 441 KB CLI that finds multi-step temporal patterns in log files and event streams. Think "grep for sequences."

## When to use patrol

- User asks to find patterns across multiple log lines (e.g., "find failed logins followed by a success")
- User has log files in syslog, JSON, logfmt, or Apache format
- User needs to detect rising/falling trends in time-series data
- User wants to correlate events across a time window

## Pattern syntax

```
EventType[field=="value"] -> EventType[field>10] .within(5m) .partition_by(key)
```

### Operators
- `->` : followed by (temporal sequence)
- `[field=="value"]` : field equals value
- `[field>10]` : numeric comparison (==, !=, <, >, <=, >=)
- `[field~"substring"]` : string contains
- `[field!~"substring"]` : string does not contain
- `all EventType as alias` : one or more events (Kleene+)
- `.increasing(field)` : strictly rising values
- `.decreasing(field)` : strictly falling values
- `.within(5m)` : time window (ms/s/m/h)
- `.partition_by(field)` : match independently per key

### Auto-detected event types by format
- **Syslog**: event_type = program name (e.g., `sshd`, `cron`, `systemd`)
- **JSON Lines**: event_type = `event_type` or `type` field
- **logfmt**: event_type = `level` or `severity` field (e.g., `error`, `info`)
- **Apache/Nginx**: event_type = status category (`request`, `redirect`, `client_error`, `error`)
- **Plain text**: event_type = `_`, use `message~"keyword"` for matching

## Common patterns

```bash
# SSH brute force (syslog)
patrol 'sshd[message~"Failed"] -> sshd[message~"Failed"] -> sshd[message~"Accepted"] .within(5m)' /var/log/auth.log

# Rising temperature (JSON)
cat sensors.jsonl | patrol 'Reading.increasing(temperature) .partition_by(sensor_id)'

# Error escalation (logfmt)
patrol 'error -> error -> error .within(30s)' app.log

# HTTP brute force (Apache/Nginx)
patrol 'client_error -> client_error -> client_error -> request .within(1m)' access.log

# Keyword sequence (plain text)
patrol '_[message~"ERROR"] -> _[message~"FATAL"]' app.log

# API latency spike followed by errors
patrol 'request[path~"/api"] -> error[path~"/api"] .within(10s)' access.log
```

## Output format

- **TTY**: Colored match summaries with captured fields
- **Pipe**: JSON Lines, one object per match:
  ```json
  {"match":1,"events":3,"captured":{"alias":{"event_type":"sshd","message":"Accepted password for alice"}}}
  ```

## Limits
- No regex support (use `~` for substring matching)
- No aggregation (use Varpulis for count/sum/avg over matches)
- No real-time streaming from Kafka/MQTT (use Varpulis for that)
- Time windows use wall-clock time, not event timestamps
