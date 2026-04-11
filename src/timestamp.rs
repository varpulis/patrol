//! Dependency-free timestamp parsing for common log formats.
//!
//! All parsers return Unix epoch seconds as f64 (fractional seconds preserved).
//! Supported inputs:
//!   - ISO 8601: 2026-04-11T10:23:45.123Z, 2026-04-11T10:23:45+02:00, 2026-04-11 10:23:45
//!   - Apache CLF: 10/Oct/2000:13:55:36 -0700
//!   - RFC 3164 syslog BSD: Apr 11 10:23:45 (no year — inferred from wall clock)
//!   - Numeric epoch: seconds, milliseconds, or microseconds (auto-detected)

use std::time::{SystemTime, UNIX_EPOCH};

/// Parse a timestamp string. Tries ISO 8601, Apache CLF, BSD syslog, and numeric epoch in order.
pub fn parse(s: &str) -> Option<f64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    parse_iso8601(s)
        .or_else(|| parse_apache_clf(s))
        .or_else(|| parse_syslog_bsd(s))
        .or_else(|| parse_numeric(s))
}

/// Coerce a numeric epoch (seconds / millis / micros / nanos) to seconds.f.
pub fn from_number(n: f64) -> f64 {
    if n > 1e17 {
        n / 1e9 // nanoseconds
    } else if n > 1e14 {
        n / 1e6 // microseconds
    } else if n > 1e11 {
        n / 1e3 // milliseconds
    } else {
        n
    }
}

fn parse_numeric(s: &str) -> Option<f64> {
    s.parse::<f64>().ok().map(from_number)
}

// ----------------------------------------------------------------------------
// ISO 8601
// ----------------------------------------------------------------------------

fn parse_iso8601(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    if b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    if b[10] != b'T' && b[10] != b' ' {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }

    let year = parse_int_range(b, 0, 4)?;
    let month = parse_int_range(b, 5, 7)?;
    let day = parse_int_range(b, 8, 10)?;
    let hour = parse_int_range(b, 11, 13)?;
    let min = parse_int_range(b, 14, 16)?;
    let sec = parse_int_range(b, 17, 19)?;

    let mut idx = 19;
    let mut frac = 0.0f64;
    if idx < b.len() && b[idx] == b'.' {
        idx += 1;
        let start = idx;
        while idx < b.len() && b[idx].is_ascii_digit() {
            idx += 1;
        }
        if idx > start {
            let digits = std::str::from_utf8(&b[start..idx]).ok()?;
            let num: f64 = digits.parse().ok()?;
            frac = num / 10f64.powi((idx - start) as i32);
        }
    }

    let tz_offset = if idx < b.len() {
        parse_tz_offset(&b[idx..]).unwrap_or(0)
    } else {
        0
    };

    let base = days_from_civil(year, month, day) * 86400
        + (hour as i64) * 3600
        + (min as i64) * 60
        + sec as i64;

    Some(base as f64 + frac - tz_offset as f64)
}

// ----------------------------------------------------------------------------
// Apache CLF: DD/Mon/YYYY:HH:MM:SS +ZZZZ
// ----------------------------------------------------------------------------

fn parse_apache_clf(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.len() < 20 {
        return None;
    }
    if b[2] != b'/' || b[6] != b'/' || b[11] != b':' || b[14] != b':' || b[17] != b':' {
        return None;
    }

    let day = parse_int_range(b, 0, 2)?;
    let month = month_from_abbrev(&b[3..6])?;
    let year = parse_int_range(b, 7, 11)?;
    let hour = parse_int_range(b, 12, 14)?;
    let min = parse_int_range(b, 15, 17)?;
    let sec = parse_int_range(b, 18, 20)?;

    let tz_offset = if b.len() >= 26 && b[20] == b' ' && (b[21] == b'+' || b[21] == b'-') {
        parse_tz_offset(&b[21..]).unwrap_or(0)
    } else {
        0
    };

    let base = days_from_civil(year, month, day) * 86400
        + (hour as i64) * 3600
        + (min as i64) * 60
        + sec as i64;
    Some(base as f64 - tz_offset as f64)
}

// ----------------------------------------------------------------------------
// BSD syslog: "Mon DD HH:MM:SS" — no year
// ----------------------------------------------------------------------------

fn parse_syslog_bsd(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    if b.len() < 15 {
        return None;
    }
    let month = month_from_abbrev(&b[0..3])?;
    if b[3] != b' ' {
        return None;
    }
    // Day may be space-padded: "Apr  1" vs "Apr 11"
    let day_slice = &b[4..6];
    let day_str = std::str::from_utf8(day_slice).ok()?.trim();
    let day: i32 = day_str.parse().ok()?;
    if b[6] != b' ' || b[9] != b':' || b[12] != b':' {
        return None;
    }
    let hour = parse_int_range(b, 7, 9)?;
    let min = parse_int_range(b, 10, 12)?;
    let sec = parse_int_range(b, 13, 15)?;

    let now = system_now_secs();
    let mut year = current_year(now);
    let ts = (days_from_civil(year, month, day) * 86400
        + (hour as i64) * 3600
        + (min as i64) * 60
        + sec as i64) as f64;

    // If parsed timestamp is > 30 days in the future, assume it's from last year.
    if ts > now + 30.0 * 86400.0 {
        year -= 1;
        let adj = (days_from_civil(year, month, day) * 86400
            + (hour as i64) * 3600
            + (min as i64) * 60
            + sec as i64) as f64;
        return Some(adj);
    }
    Some(ts)
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

fn parse_int_range(b: &[u8], start: usize, end: usize) -> Option<i32> {
    if end > b.len() {
        return None;
    }
    std::str::from_utf8(&b[start..end]).ok()?.parse().ok()
}

fn month_from_abbrev(b: &[u8]) -> Option<i32> {
    match b {
        b"Jan" => Some(1),
        b"Feb" => Some(2),
        b"Mar" => Some(3),
        b"Apr" => Some(4),
        b"May" => Some(5),
        b"Jun" => Some(6),
        b"Jul" => Some(7),
        b"Aug" => Some(8),
        b"Sep" => Some(9),
        b"Oct" => Some(10),
        b"Nov" => Some(11),
        b"Dec" => Some(12),
        _ => None,
    }
}

/// Parse +HH:MM, -HH:MM, +HHMM, -HHMM, or Z. Returns offset in seconds east of UTC.
fn parse_tz_offset(b: &[u8]) -> Option<i64> {
    if b.is_empty() {
        return Some(0);
    }
    if b[0] == b'Z' || b[0] == b'z' {
        return Some(0);
    }
    let sign: i64 = match b[0] {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    if b.len() < 3 {
        return None;
    }
    let h: i64 = std::str::from_utf8(&b[1..3]).ok()?.parse().ok()?;
    let m: i64 = if b.len() >= 6 && b[3] == b':' {
        std::str::from_utf8(&b[4..6]).ok()?.parse().ok()?
    } else if b.len() >= 5 && b[3].is_ascii_digit() {
        std::str::from_utf8(&b[3..5]).ok()?.parse().unwrap_or(0)
    } else {
        0
    };
    Some(sign * (h * 3600 + m * 60))
}

/// Days from 1970-01-01 (Unix epoch) to the given civil date.
/// Howard Hinnant's formula; valid for any Gregorian proleptic date.
fn days_from_civil(y: i32, m: i32, d: i32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y } as i64;
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mm = m as i64;
    let dd = d as i64;
    let doy = (153 * if mm > 2 { mm - 3 } else { mm + 9 } + 2) / 5 + dd - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn system_now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

fn current_year(now_secs: f64) -> i32 {
    // Approximate then refine.
    let approx = 1970 + (now_secs / 31_556_952.0) as i32;
    let mut y = approx;
    while (days_from_civil(y + 1, 1, 1) * 86400) as f64 <= now_secs {
        y += 1;
    }
    while (days_from_civil(y, 1, 1) * 86400) as f64 > now_secs {
        y -= 1;
    }
    y
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_utc_z() {
        // 2026-04-11T10:23:45Z
        let t = parse_iso8601("2026-04-11T10:23:45Z").unwrap();
        // sanity: matches ISO epoch for that moment
        let expected =
            days_from_civil(2026, 4, 11) as f64 * 86400.0 + 10.0 * 3600.0 + 23.0 * 60.0 + 45.0;
        assert!((t - expected).abs() < 0.001);
    }

    #[test]
    fn iso_with_offset() {
        // 2026-04-11T10:23:45+02:00 is 08:23:45 UTC
        let t = parse_iso8601("2026-04-11T10:23:45+02:00").unwrap();
        let z = parse_iso8601("2026-04-11T08:23:45Z").unwrap();
        assert!((t - z).abs() < 0.001);
    }

    #[test]
    fn iso_fractional() {
        let t = parse_iso8601("2026-04-11T10:23:45.500Z").unwrap();
        let whole = parse_iso8601("2026-04-11T10:23:45Z").unwrap();
        assert!((t - whole - 0.5).abs() < 0.001);
    }

    #[test]
    fn iso_space_separator() {
        let a = parse_iso8601("2026-04-11 10:23:45").unwrap();
        let b = parse_iso8601("2026-04-11T10:23:45").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn apache_clf_format() {
        // 10/Oct/2000:13:55:36 -0700 → 2000-10-10T13:55:36-0700 → 20:55:36 UTC
        let a = parse_apache_clf("10/Oct/2000:13:55:36 -0700").unwrap();
        let b = parse_iso8601("2000-10-10T20:55:36Z").unwrap();
        assert!((a - b).abs() < 0.001);
    }

    #[test]
    fn parse_entry_detects_format() {
        assert!(parse("2026-04-11T10:23:45Z").is_some());
        assert!(parse("10/Oct/2000:13:55:36 -0700").is_some());
        assert!(parse("1728648000").is_some());
        assert!(parse("").is_none());
        assert!(parse("not a timestamp").is_none());
    }

    #[test]
    fn numeric_epoch_variants() {
        // seconds
        assert!((from_number(1_000_000_000.0) - 1_000_000_000.0).abs() < 0.001);
        // milliseconds
        assert!((from_number(1_000_000_000_000.0) - 1_000_000_000.0).abs() < 0.001);
        // microseconds
        assert!((from_number(1_000_000_000_000_000.0) - 1_000_000_000.0).abs() < 0.001);
    }

    #[test]
    fn days_from_civil_epoch() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(1970, 1, 2), 1);
        assert_eq!(days_from_civil(2000, 1, 1), 10957);
    }
}
