use serde_json::{Value, json};
use shroudb_scroll_core::LogEntry;
use shroudb_scroll_engine::{GroupInfo, LogInfo};

/// Uniform response envelope. The TCP/HTTP layer flattens `Ok` to a RESP3
/// bulk-string JSON object and `Error` to a RESP3 simple-error.
#[derive(Debug, Clone)]
pub enum ScrollResponse {
    Ok(Value),
    Error(String),
}

impl ScrollResponse {
    pub fn ok(value: Value) -> Self {
        Self::Ok(value)
    }

    pub fn ok_status() -> Self {
        Self::Ok(json!({"status": "ok"}))
    }

    pub fn error(msg: impl Into<String>) -> Self {
        Self::Error(msg.into())
    }

    pub fn pong() -> Self {
        Self::Ok(json!("PONG"))
    }

    pub fn health() -> Self {
        Self::Ok(json!({"status": "ok"}))
    }

    pub fn append_result(offset: u64) -> Self {
        Self::Ok(json!({"status": "ok", "offset": offset}))
    }

    pub fn entries(entries: Vec<LogEntry>) -> Self {
        use base64::Engine as _;
        // Re-encode payloads to base64 for wire safety; headers are plain JSON.
        let b64 = base64::engine::general_purpose::STANDARD;
        let wire: Vec<Value> = entries
            .into_iter()
            .map(|e| {
                json!({
                    "offset": e.offset,
                    "tenant_id": e.tenant_id,
                    "log": e.log,
                    "payload_b64": b64.encode(&e.payload),
                    "headers": e.headers,
                    "appended_at_ms": e.appended_at_ms,
                    "expires_at_ms": e.expires_at_ms,
                })
            })
            .collect();
        Self::Ok(json!({"status": "ok", "entries": wire}))
    }

    pub fn log_info(info: LogInfo) -> Self {
        Self::Ok(serde_json::to_value(info).unwrap_or_else(|_| json!({"status": "error"})))
    }

    pub fn group_info(info: GroupInfo) -> Self {
        Self::Ok(serde_json::to_value(info).unwrap_or_else(|_| json!({"status": "error"})))
    }

    pub fn claimed(offsets: Vec<u64>) -> Self {
        Self::Ok(json!({"status": "ok", "claimed": offsets}))
    }

    pub fn trimmed(count: u64) -> Self {
        Self::Ok(json!({"status": "ok", "deleted": count}))
    }

    pub fn command_list() -> Self {
        Self::Ok(json!({
            "commands": [
                "APPEND <log> <payload_b64> [HEADERS <json>] [TTL <ms>]",
                "READ <log> <from_offset> <limit>",
                "CREATE_GROUP <log> <group> <start_offset>",
                "READ_GROUP <log> <group> <reader_id> <limit>",
                "ACK <log> <group> <offset>",
                "DELETE_LOG <log>",
                "LOG_INFO <log>",
                "GROUP_INFO <log> <group>",
                "CLAIM <log> <group> <reader_id> <min_idle_ms>",
                "TRIM <log> MAX_LEN <n> | MAX_AGE <ms>",
                "TAIL <log> <from_offset> <limit> [TIMEOUT <ms>]",
                "AUTH <token>",
                "HEALTH",
                "PING",
                "HELLO",
                "COMMAND LIST",
            ]
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok(r: ScrollResponse) -> Value {
        match r {
            ScrollResponse::Ok(v) => v,
            ScrollResponse::Error(e) => panic!("expected Ok, got Error({e})"),
        }
    }

    #[test]
    fn ok_status_shape() {
        assert_eq!(ok(ScrollResponse::ok_status())["status"], "ok");
    }

    #[test]
    fn pong_shape() {
        assert_eq!(ok(ScrollResponse::pong()), json!("PONG"));
    }

    #[test]
    fn append_result_includes_offset() {
        let v = ok(ScrollResponse::append_result(42));
        assert_eq!(v["status"], "ok");
        assert_eq!(v["offset"], 42);
    }

    #[test]
    fn claimed_lists_offsets() {
        let v = ok(ScrollResponse::claimed(vec![1, 2, 5]));
        assert_eq!(v["claimed"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn trimmed_reports_count() {
        let v = ok(ScrollResponse::trimmed(7));
        assert_eq!(v["deleted"], 7);
    }

    #[test]
    fn entries_base64_encodes_payload() {
        let entries = vec![LogEntry::new(
            0,
            "t".into(),
            "l".into(),
            b"hello".to_vec(),
            std::collections::BTreeMap::new(),
            1,
            None,
        )];
        let v = ok(ScrollResponse::entries(entries));
        assert_eq!(v["entries"][0]["payload_b64"], "aGVsbG8=");
    }

    #[test]
    fn command_list_covers_all_p1_commands() {
        let v = ok(ScrollResponse::command_list());
        let cmds: Vec<&str> = v["commands"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        for expected in ["APPEND", "CLAIM", "TRIM", "TAIL", "COMMAND LIST"] {
            assert!(
                cmds.iter().any(|c| c.contains(expected)),
                "missing {expected}"
            );
        }
    }
}
