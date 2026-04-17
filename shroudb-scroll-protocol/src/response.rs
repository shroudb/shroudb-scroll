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
                "AUTH <token>",
                "HEALTH",
                "PING",
                "HELLO",
                "COMMAND LIST",
            ]
        }))
    }
}
