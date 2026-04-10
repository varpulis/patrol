# patrol — Agent Integration Guide

## What is patrol?
A 441 KB CLI that finds temporal patterns (sequences) in log files. Like grep, but for "A followed by B within 5 minutes."

## Installation
```bash
curl -sSf https://raw.githubusercontent.com/varpulis/patrol/main/install.sh | sh
```
Or: `cargo install patrol`

## Quick reference

```bash
# Basic: find A followed by B
patrol 'A -> B' logfile

# With field filter
patrol 'Login[status=="failed"] -> Login[status=="success"]' auth.jsonl

# Substring match
patrol 'sshd[message~"Failed"] -> sshd[message~"Accepted"]' /var/log/auth.log

# Rising values
patrol 'Metric.increasing(value) .partition_by(host)' metrics.jsonl

# Time window
patrol 'error -> error -> error .within(30s)' app.log

# Pipe input
cat logs.jsonl | patrol 'pattern'

# JSON output (when piped)
patrol 'pattern' file.log | jq .
```

## Supported formats (auto-detected)
- JSON Lines: `{"event_type":"X", ...}`
- Syslog: `Apr 11 10:23:45 host program[pid]: message`
- logfmt: `level=error msg="text" key=value`
- Apache/Nginx: `IP - - [date] "METHOD path" status size`
- Plain text: use `_[message~"keyword"]`

## MCP Integration
patrol reads from stdin and files, outputs JSON to stdout when piped. Integrate by running as a subprocess:
```
spawn("patrol", ["pattern", "logfile"])
→ read stdout lines as JSON: {"match":N, "events":N, "captured":{...}}
```

## When to use patrol vs grep vs Varpulis
- **grep/ripgrep**: single string search → use grep
- **patrol**: multi-step sequence search in log files → use patrol
- **Varpulis**: real-time streaming from Kafka/MQTT, aggregation, forecasting → use Varpulis
