//! Minimal event type for patrol — just a wrapper around JSON with an event_type field.

use std::collections::HashMap;

use crate::timestamp;

#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: String,
    pub data: HashMap<String, serde_json::Value>,
    /// Event time as Unix epoch seconds (parsed from the log line). None if unavailable.
    pub timestamp: Option<f64>,
    /// 1-based line number of the source record; 0 if unknown (e.g. tests).
    pub line_num: u64,
}

impl Event {
    /// Parse a JSON line into an Event.
    ///
    /// Supports two formats:
    /// 1. JSON with explicit "event_type" field: `{"event_type": "Login", "user": "alice"}`
    /// 2. Plain JSON (event_type = "_"): `{"user": "alice", "status": "failed"}`
    pub fn from_json_line(line: &str) -> Option<Self> {
        let v: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
        let obj = v.as_object()?;

        let event_type = obj
            .get("event_type")
            .and_then(|v| v.as_str())
            .or_else(|| obj.get("type").and_then(|v| v.as_str()))
            .or_else(|| obj.get("_type").and_then(|v| v.as_str()))
            .unwrap_or("_")
            .to_string();

        let mut data = HashMap::new();
        for (k, v) in obj {
            if k != "event_type" && k != "type" && k != "_type" {
                data.insert(k.clone(), v.clone());
            }
        }

        // Try timestamp / ts / time / @timestamp fields in that order.
        let ts_value = obj
            .get("timestamp")
            .or_else(|| obj.get("ts"))
            .or_else(|| obj.get("time"))
            .or_else(|| obj.get("@timestamp"));
        let timestamp = ts_value.and_then(|v| match v {
            serde_json::Value::Number(n) => n.as_f64().map(timestamp::from_number),
            serde_json::Value::String(s) => timestamp::parse(s),
            _ => None,
        });

        Some(Event {
            event_type,
            data,
            timestamp,
            line_num: 0,
        })
    }

    /// Parse a plain text log line.
    ///
    /// If the line isn't JSON, treat the entire line as a single-field event
    /// with event_type = "_" and data = {"line": "<the line>"}.
    #[allow(dead_code)]
    pub fn from_text_line(line: &str) -> Self {
        let mut data = HashMap::new();
        data.insert(
            "line".to_string(),
            serde_json::Value::String(line.to_string()),
        );
        Event {
            event_type: "_".to_string(),
            data,
            timestamp: None,
            line_num: 0,
        }
    }

    pub fn get(&self, field: &str) -> Option<&serde_json::Value> {
        self.data.get(field)
    }
}
