//! Auto-detect and parse common log formats.
//!
//! Supported formats:
//! 1. JSON Lines         {"event_type": "Login", "field": "value"}
//! 2. Syslog (RFC 3164)  Apr 11 10:23:45 server sshd[1234]: message
//! 3. logfmt (key=value) time=... level=error msg="something" user=alice
//! 4. Apache/Nginx CLF   10.0.0.1 - - [11/Apr/2026:10:23:45 +0000] "GET / HTTP/1.1" 200 1234
//! 5. Plain text          (fallback — entire line as `message` field)

use crate::event::Event;

/// Detected log format
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Format {
    JsonLines,
    Syslog,
    Logfmt,
    ApacheClf,
    PlainText,
}

/// Auto-detect the log format from the first non-empty line.
pub fn detect(line: &str) -> Format {
    let trimmed = line.trim();

    // JSON: starts with {
    if trimmed.starts_with('{') {
        return Format::JsonLines;
    }

    // Apache CLF: IP - - [date] "METHOD path HTTP/x.x" status size
    if is_apache_clf(trimmed) {
        return Format::ApacheClf;
    }

    // Syslog: starts with month abbreviation and day
    if is_syslog(trimmed) {
        return Format::Syslog;
    }

    // logfmt: contains multiple key=value pairs
    if is_logfmt(trimmed) {
        return Format::Logfmt;
    }

    Format::PlainText
}

/// Parse a line according to the detected format.
pub fn parse_line(line: &str, format: Format) -> Option<Event> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
        return None;
    }

    match format {
        Format::JsonLines => Event::from_json_line(trimmed),
        Format::Syslog => parse_syslog(trimmed),
        Format::Logfmt => parse_logfmt(trimmed),
        Format::ApacheClf => parse_apache_clf(trimmed),
        Format::PlainText => Some(parse_plain(trimmed)),
    }
}

// ============================================================================
// Syslog (RFC 3164)
// ============================================================================
// Format: Apr 11 10:23:45 hostname program[pid]: message
// Also:   2026-04-11T10:23:45.123Z hostname program[pid]: message (RFC 5424-ish)

fn is_syslog(line: &str) -> bool {
    // Check for traditional syslog: "Mon DD HH:MM:SS"
    let months = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    if line.len() > 15 {
        let first3 = &line[..3];
        if months.iter().any(|m| *m == first3) && line.as_bytes().get(3) == Some(&b' ') {
            return true;
        }
    }
    // Check for ISO 8601 syslog: "2026-04-11T..."
    if line.len() > 20 && line.as_bytes().get(4) == Some(&b'-') && line.as_bytes().get(10) == Some(&b'T') {
        return true;
    }
    false
}

fn parse_syslog(line: &str) -> Option<Event> {
    // Try traditional format: "Apr 11 10:23:45 hostname program[pid]: message"
    if let Some(ev) = parse_syslog_traditional(line) {
        return Some(ev);
    }
    // Try ISO format: "2026-04-11T10:23:45.123Z hostname program[pid]: message"
    if let Some(ev) = parse_syslog_iso(line) {
        return Some(ev);
    }
    // Fallback
    Some(parse_plain(line))
}

fn parse_syslog_traditional(line: &str) -> Option<Event> {
    // "Apr 11 10:23:45 hostname program[pid]: message"
    // Positions: timestamp=0..15, hostname after space, program/pid, message after ": "

    if line.len() < 16 {
        return None;
    }

    let timestamp_str = &line[..15];
    let rest = &line[16..];

    // hostname (next word)
    let hostname_end = rest.find(' ')?;
    let hostname = &rest[..hostname_end];
    let rest = &rest[hostname_end + 1..];

    // program[pid] or program: message
    let (program, pid, message) = if let Some(bracket_pos) = rest.find('[') {
        let program = &rest[..bracket_pos];
        let after = &rest[bracket_pos + 1..];
        if let Some(close) = after.find(']') {
            let pid = &after[..close];
            let msg_start = after[close + 1..].find(": ").map(|p| close + 1 + p + 2).unwrap_or(close + 2);
            let message = if msg_start < after.len() {
                after[msg_start..].trim()
            } else {
                ""
            };
            (program, Some(pid), message)
        } else {
            (rest, None, "")
        }
    } else if let Some(colon_pos) = rest.find(": ") {
        let program = &rest[..colon_pos];
        let message = &rest[colon_pos + 2..];
        (program, None, message)
    } else {
        (rest, None, "")
    };

    // Use program name as event_type
    let event_type = program.to_string();
    let mut data = std::collections::HashMap::new();
    data.insert("timestamp".into(), serde_json::Value::String(timestamp_str.to_string()));
    data.insert("hostname".into(), serde_json::Value::String(hostname.to_string()));
    data.insert("program".into(), serde_json::Value::String(program.to_string()));
    if let Some(pid) = pid {
        data.insert("pid".into(), serde_json::Value::String(pid.to_string()));
    }
    data.insert("message".into(), serde_json::Value::String(message.to_string()));
    data.insert("line".into(), serde_json::Value::String(line.to_string()));

    Some(Event {
        event_type,
        data,
        timestamp: None,
    })
}

fn parse_syslog_iso(line: &str) -> Option<Event> {
    // "2026-04-11T10:23:45.123Z hostname program[pid]: message"
    let space1 = line.find(' ')?;
    let timestamp_str = &line[..space1];

    // Validate looks like ISO timestamp
    if !timestamp_str.contains('T') {
        return None;
    }

    let rest = &line[space1 + 1..];

    // Reuse the traditional parser for the rest (hostname program[pid]: message)
    let mut ev = parse_syslog_traditional(&format!("Jan  1 00:00:00 {rest}"))?;
    ev.data.insert("timestamp".into(), serde_json::Value::String(timestamp_str.to_string()));
    Some(ev)
}

// ============================================================================
// logfmt (key=value)
// ============================================================================
// Format: time=2026-04-11T10:23:45Z level=error msg="something happened" user=alice

fn is_logfmt(line: &str) -> bool {
    // Must have at least 2 key=value pairs
    let mut count = 0;
    let mut i = 0;
    let bytes = line.as_bytes();
    while i < bytes.len() {
        if bytes[i] == b'=' && i > 0 && bytes[i - 1] != b' ' {
            count += 1;
            if count >= 2 {
                return true;
            }
        }
        i += 1;
    }
    false
}

fn parse_logfmt(line: &str) -> Option<Event> {
    let mut data = std::collections::HashMap::new();
    let mut event_type = "_".to_string();

    // Parse key=value pairs
    let mut remaining = line.trim();
    while !remaining.is_empty() {
        // Find key
        let eq_pos = match remaining.find('=') {
            Some(p) => p,
            None => break,
        };
        let key = remaining[..eq_pos].trim_start();
        remaining = &remaining[eq_pos + 1..];

        // Find value (quoted or unquoted)
        let value = if remaining.starts_with('"') {
            // Quoted value — find closing quote
            let end = remaining[1..].find('"').map(|p| p + 2).unwrap_or(remaining.len());
            let val = &remaining[1..end - 1];
            remaining = &remaining[end..].trim_start();
            serde_json::Value::String(val.to_string())
        } else {
            // Unquoted — until next space
            let end = remaining.find(' ').unwrap_or(remaining.len());
            let val_str = &remaining[..end];
            remaining = &remaining[end..].trim_start();

            // Try to parse as number
            if let Ok(n) = val_str.parse::<i64>() {
                serde_json::json!(n)
            } else if let Ok(f) = val_str.parse::<f64>() {
                serde_json::json!(f)
            } else if val_str == "true" {
                serde_json::Value::Bool(true)
            } else if val_str == "false" {
                serde_json::Value::Bool(false)
            } else {
                serde_json::Value::String(val_str.to_string())
            }
        };

        // Use "level" or "severity" as event_type if present
        if key == "level" || key == "severity" || key == "event" || key == "event_type" {
            if let Some(s) = value.as_str() {
                event_type = s.to_string();
            }
        }

        data.insert(key.to_string(), value);
    }

    data.insert("line".into(), serde_json::Value::String(line.to_string()));

    Some(Event {
        event_type,
        data,
        timestamp: None,
    })
}

// ============================================================================
// Apache / Nginx Combined Log Format
// ============================================================================
// 10.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.0" 200 2326

fn is_apache_clf(line: &str) -> bool {
    // Quick heuristic: has IP-like start, brackets, quotes
    let bytes = line.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    // First char is digit (IP address) and line contains [date] and "METHOD
    bytes[0].is_ascii_digit()
        && line.contains('[')
        && line.contains(']')
        && line.contains('"')
}

fn parse_apache_clf(line: &str) -> Option<Event> {
    let mut data = std::collections::HashMap::new();

    // Split: ip - user [date] "request" status size
    let parts: Vec<&str> = line.splitn(4, ' ').collect();
    if parts.len() < 4 {
        return Some(parse_plain(line));
    }

    let ip = parts[0];
    // parts[1] is "-" (ident)
    let user = parts[2];
    let rest = parts[3..].join(" ");

    // Extract [date]
    let date_start = rest.find('[')?;
    let date_end = rest.find(']')?;
    let date = &rest[date_start + 1..date_end];
    let rest = &rest[date_end + 2..]; // skip "] "

    // Extract "METHOD path HTTP/x.x"
    let (method, path, status, size) = if rest.starts_with('"') {
        let quote_end = rest[1..].find('"').map(|p| p + 1)?;
        let request = &rest[1..quote_end];
        let after = &rest[quote_end + 2..]; // skip '" '

        let req_parts: Vec<&str> = request.splitn(3, ' ').collect();
        let method = req_parts.first().copied().unwrap_or("-");
        let path = req_parts.get(1).copied().unwrap_or("-");

        let status_size: Vec<&str> = after.split_whitespace().collect();
        let status = status_size.first().copied().unwrap_or("0");
        let size = status_size.get(1).copied().unwrap_or("0");

        (method, path, status, size)
    } else {
        ("-", "-", "0", "0")
    };

    let status_code: i64 = status.parse().unwrap_or(0);

    // event_type based on status code range
    let event_type = if status_code >= 500 {
        "error"
    } else if status_code >= 400 {
        "client_error"
    } else if status_code >= 300 {
        "redirect"
    } else {
        "request"
    };

    data.insert("ip".into(), serde_json::Value::String(ip.to_string()));
    data.insert("user".into(), serde_json::Value::String(user.to_string()));
    data.insert("timestamp".into(), serde_json::Value::String(date.to_string()));
    data.insert("method".into(), serde_json::Value::String(method.to_string()));
    data.insert("path".into(), serde_json::Value::String(path.to_string()));
    data.insert("status".into(), serde_json::json!(status_code));
    data.insert("size".into(), serde_json::Value::String(size.to_string()));
    data.insert("line".into(), serde_json::Value::String(line.to_string()));

    Some(Event {
        event_type: event_type.to_string(),
        data,
        timestamp: None,
    })
}

// ============================================================================
// Plain text (fallback)
// ============================================================================

fn parse_plain(line: &str) -> Event {
    let mut data = std::collections::HashMap::new();
    data.insert("message".into(), serde_json::Value::String(line.to_string()));
    data.insert("line".into(), serde_json::Value::String(line.to_string()));
    Event {
        event_type: "_".to_string(),
        data,
        timestamp: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_json() {
        assert_eq!(detect(r#"{"event_type": "Login"}"#), Format::JsonLines);
    }

    #[test]
    fn test_detect_syslog() {
        assert_eq!(
            detect("Apr 11 10:23:45 server sshd[1234]: Failed password for alice"),
            Format::Syslog
        );
    }

    #[test]
    fn test_detect_logfmt() {
        assert_eq!(
            detect("time=2026-04-11T10:23:45Z level=error msg=\"test\""),
            Format::Logfmt
        );
    }

    #[test]
    fn test_detect_apache() {
        assert_eq!(
            detect(r#"10.0.0.1 - - [11/Apr/2026:10:23:45 +0000] "GET / HTTP/1.1" 200 1234"#),
            Format::ApacheClf
        );
    }

    #[test]
    fn test_detect_plain() {
        assert_eq!(detect("just some plain text"), Format::PlainText);
    }

    #[test]
    fn test_parse_syslog() {
        let ev = parse_syslog("Apr 11 10:23:45 myhost sshd[1234]: Failed password for alice from 10.0.0.1").unwrap();
        assert_eq!(ev.event_type, "sshd");
        assert_eq!(ev.get("hostname").and_then(|v| v.as_str()), Some("myhost"));
        assert_eq!(ev.get("pid").and_then(|v| v.as_str()), Some("1234"));
        assert!(ev.get("message").and_then(|v| v.as_str()).unwrap().contains("Failed password"));
    }

    #[test]
    fn test_parse_logfmt() {
        let ev = parse_logfmt("time=2026-04-11 level=error msg=\"disk full\" host=web1 code=500").unwrap();
        assert_eq!(ev.event_type, "error");
        assert_eq!(ev.get("host").and_then(|v| v.as_str()), Some("web1"));
        assert_eq!(ev.get("code"), Some(&serde_json::json!(500)));
    }

    #[test]
    fn test_parse_apache_clf() {
        let ev = parse_apache_clf(
            r#"10.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /page HTTP/1.0" 200 2326"#
        ).unwrap();
        assert_eq!(ev.event_type, "request");
        assert_eq!(ev.get("ip").and_then(|v| v.as_str()), Some("10.0.0.1"));
        assert_eq!(ev.get("method").and_then(|v| v.as_str()), Some("GET"));
        assert_eq!(ev.get("path").and_then(|v| v.as_str()), Some("/page"));
        assert_eq!(ev.get("status"), Some(&serde_json::json!(200)));
    }

    #[test]
    fn test_parse_apache_500_is_error() {
        let ev = parse_apache_clf(
            r#"10.0.0.1 - - [11/Apr/2026:10:23:45 +0000] "POST /api HTTP/1.1" 500 0"#
        ).unwrap();
        assert_eq!(ev.event_type, "error");
    }
}
