//! Hand-written pattern parser for patrol.
//!
//! Syntax (simplified VPL):
//!   Login -> Transfer -> Logout .within(5m)
//!   Login[status=="failed"] -> Login[status=="failed"] -> Login[status=="success"]
//!   all Reading .partition_by(sensor_id)
//!   Reading.increasing(temperature) .partition_by(sensor_id)
//!   Request -> NOT Response .within(30s)

use std::time::Duration;

#[derive(Debug, Clone)]
pub struct Pattern {
    pub steps: Vec<PatternStep>,
    pub within: Option<Duration>,
    pub partition_by: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PatternStep {
    pub event_type: String,
    pub match_all: bool,
    pub alias: Option<String>,
    pub comparisons: Vec<Comparison>,
    pub monotonic: Option<Monotonic>,
    pub negated: bool,
}

#[derive(Debug, Clone)]
pub struct Comparison {
    pub field: String,
    pub op: String,
    pub value: serde_json::Value,
    /// If set, compare against a captured alias's field instead of a literal
    pub ref_alias: Option<String>,
    pub ref_field: Option<String>,
}

#[derive(Debug, Clone)]
pub enum Monotonic {
    Increasing(String),
    Decreasing(String),
}

pub fn parse(input: &str) -> Result<Pattern, String> {
    let input = input.trim();
    let mut remaining = input;
    let mut within = None;
    let mut partition_by = None;

    // Extract trailing .within(duration) and .partition_by(field)
    // Process from right to left — partition_by is typically last
    loop {
        let trimmed = remaining.trim();
        if let Some(pos) = trimmed.rfind(".partition_by(") {
            let after = &trimmed[pos + 14..];
            if let Some(end) = after.find(')') {
                partition_by = Some(after[..end].trim().to_string());
                remaining = &trimmed[..pos];
                continue;
            }
        }
        if let Some(pos) = trimmed.rfind(".within(") {
            let after = &trimmed[pos + 8..];
            if let Some(end) = after.find(')') {
                let dur_str = &after[..end];
                within = parse_duration(dur_str);
                remaining = &trimmed[..pos];
                continue;
            }
        }
        remaining = trimmed;
        break;
    }

    let remaining = remaining.trim();

    // Split on `->`
    let raw_steps: Vec<&str> = remaining.split("->").collect();
    let mut steps = Vec::new();

    for raw in raw_steps {
        let step = parse_step(raw.trim())?;
        steps.push(step);
    }

    if steps.is_empty() {
        return Err("pattern must have at least one step".into());
    }

    Ok(Pattern {
        steps,
        within,
        partition_by,
    })
}

fn parse_step(input: &str) -> Result<PatternStep, String> {
    let mut remaining = input.trim();
    let mut match_all = false;
    let mut negated = false;
    let mut monotonic = None;
    let mut alias = None;

    // Check for `all` prefix
    if remaining.starts_with("all ") {
        match_all = true;
        remaining = remaining[4..].trim();
    }

    // Check for `NOT` prefix
    if remaining.starts_with("NOT ") || remaining.starts_with("not ") {
        negated = true;
        remaining = remaining[4..].trim();
    }

    // Check for `as alias` suffix
    if let Some(pos) = remaining.rfind(" as ") {
        alias = Some(remaining[pos + 4..].trim().to_string());
        remaining = remaining[..pos].trim();
    }

    // Check for .increasing(field) or .decreasing(field)
    if let Some(pos) = remaining.find(".increasing(") {
        let after = &remaining[pos + 12..];
        if let Some(end) = after.find(')') {
            let field = after[..end].trim().to_string();
            monotonic = Some(Monotonic::Increasing(field));
            match_all = true;
            remaining = remaining[..pos].trim();
        }
    } else if let Some(pos) = remaining.find(".decreasing(") {
        let after = &remaining[pos + 12..];
        if let Some(end) = after.find(')') {
            let field = after[..end].trim().to_string();
            monotonic = Some(Monotonic::Decreasing(field));
            match_all = true;
            remaining = remaining[..pos].trim();
        }
    }

    // Parse event type and optional [predicate]
    let (event_type, comparisons) = if let Some(bracket_pos) = remaining.find('[') {
        let event_type = remaining[..bracket_pos].trim().to_string();
        let pred_str = &remaining[bracket_pos + 1..];
        let end = pred_str
            .find(']')
            .ok_or("unclosed bracket in predicate")?;
        let pred_inner = &pred_str[..end];
        let comparisons = parse_comparisons(pred_inner)?;
        (event_type, comparisons)
    } else if remaining.contains(" where ") {
        // Alternative syntax: Event where field > value
        let parts: Vec<&str> = remaining.splitn(2, " where ").collect();
        let event_type = parts[0].trim().to_string();
        let comparisons = parse_comparisons(parts[1].trim())?;
        (event_type, comparisons)
    } else {
        (remaining.to_string(), Vec::new())
    };

    Ok(PatternStep {
        event_type,
        match_all,
        alias,
        comparisons,
        monotonic,
        negated,
    })
}

fn parse_comparisons(input: &str) -> Result<Vec<Comparison>, String> {
    let mut comparisons = Vec::new();

    // Split on " and " or " && "
    let parts: Vec<&str> = input
        .split(" and ")
        .flat_map(|s| s.split(" && "))
        .collect();

    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        // Find the comparison operator
        let ops = ["==", "!=", "!~", "<=", ">=", "<", ">", "~"];
        let mut found = false;

        for op in ops {
            if let Some(pos) = part.find(op) {
                let field = part[..pos].trim();
                let value_str = part[pos + op.len()..].trim();

                // Check if RHS is a reference (alias.field)
                if value_str.contains('.') && !value_str.starts_with('"') && !value_str.parse::<f64>().is_ok() {
                    let ref_parts: Vec<&str> = value_str.splitn(2, '.').collect();
                    comparisons.push(Comparison {
                        field: field.to_string(),
                        op: op.to_string(),
                        value: serde_json::Value::Null,
                        ref_alias: Some(ref_parts[0].to_string()),
                        ref_field: Some(ref_parts[1].to_string()),
                    });
                } else {
                    let value = parse_value(value_str);
                    comparisons.push(Comparison {
                        field: field.to_string(),
                        op: op.to_string(),
                        value,
                        ref_alias: None,
                        ref_field: None,
                    });
                }
                found = true;
                break;
            }
        }

        if !found {
            return Err(format!("cannot parse comparison: '{part}'"));
        }
    }

    Ok(comparisons)
}

fn parse_value(s: &str) -> serde_json::Value {
    let s = s.trim();
    // Try string (quoted)
    if (s.starts_with('"') && s.ends_with('"')) || (s.starts_with('\'') && s.ends_with('\'')) {
        return serde_json::Value::String(s[1..s.len() - 1].to_string());
    }
    // Try number
    if let Ok(n) = s.parse::<i64>() {
        return serde_json::json!(n);
    }
    if let Ok(f) = s.parse::<f64>() {
        return serde_json::json!(f);
    }
    // Try bool
    match s {
        "true" => return serde_json::Value::Bool(true),
        "false" => return serde_json::Value::Bool(false),
        "null" | "nil" => return serde_json::Value::Null,
        _ => {}
    }
    // Fallback: treat as string
    serde_json::Value::String(s.to_string())
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix("ms") {
        return num.trim().parse::<u64>().ok().map(Duration::from_millis);
    }
    if let Some(num) = s.strip_suffix('s') {
        return num.trim().parse::<u64>().ok().map(Duration::from_secs);
    }
    if let Some(num) = s.strip_suffix('m') {
        return num
            .trim()
            .parse::<u64>()
            .ok()
            .map(|n| Duration::from_secs(n * 60));
    }
    if let Some(num) = s.strip_suffix('h') {
        return num
            .trim()
            .parse::<u64>()
            .ok()
            .map(|n| Duration::from_secs(n * 3600));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_sequence() {
        let p = parse("Login -> Transfer -> Logout").unwrap();
        assert_eq!(p.steps.len(), 3);
        assert_eq!(p.steps[0].event_type, "Login");
        assert_eq!(p.steps[1].event_type, "Transfer");
        assert_eq!(p.steps[2].event_type, "Logout");
    }

    #[test]
    fn test_with_within_and_partition() {
        let p =
            parse("Login -> Transfer .within(5m) .partition_by(user_id)").unwrap();
        assert_eq!(p.steps.len(), 2);
        assert_eq!(p.within, Some(Duration::from_secs(300)));
        assert_eq!(p.partition_by.as_deref(), Some("user_id"));
    }

    #[test]
    fn test_bracket_predicate() {
        let p = parse("Login[status==\"failed\"]").unwrap();
        assert_eq!(p.steps[0].comparisons.len(), 1);
        assert_eq!(p.steps[0].comparisons[0].field, "status");
        assert_eq!(
            p.steps[0].comparisons[0].value,
            serde_json::Value::String("failed".to_string())
        );
    }

    #[test]
    fn test_increasing() {
        let p = parse("Reading.increasing(temperature) .partition_by(sensor_id)").unwrap();
        assert!(matches!(
            p.steps[0].monotonic,
            Some(Monotonic::Increasing(_))
        ));
        assert!(p.steps[0].match_all);
    }

    #[test]
    fn test_match_all() {
        let p = parse("Start -> all Event as e -> End").unwrap();
        assert!(!p.steps[0].match_all);
        assert!(p.steps[1].match_all);
        assert_eq!(p.steps[1].alias.as_deref(), Some("e"));
        assert!(!p.steps[2].match_all);
    }

    #[test]
    fn test_where_clause() {
        let p = parse("Event where status == \"ok\" and count > 10").unwrap();
        assert_eq!(p.steps[0].comparisons.len(), 2);
    }
}
