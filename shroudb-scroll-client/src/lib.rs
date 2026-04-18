pub mod connection;
pub mod error;

use base64::Engine as _;
use connection::Connection;
pub use error::ClientError;
use serde_json::Value;
use shroudb_scroll_core::LogEntry;
use std::collections::BTreeMap;
use tokio::sync::Mutex;

/// Typed Rust SDK for the Scroll engine.
///
/// All methods encode binary payloads as base64 on the wire and decode
/// returned `LogEntry.payload_b64` back to bytes.
pub struct ScrollClient {
    conn: Mutex<Connection>,
}

impl ScrollClient {
    pub async fn connect(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect(addr).await?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub async fn connect_moat(addr: &str) -> Result<Self, ClientError> {
        let conn = Connection::connect_moat(addr).await?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    // ── Meta ────────────────────────────────────────────────────────────

    pub async fn auth(&self, token: &str) -> Result<(), ClientError> {
        let resp = self
            .conn
            .lock()
            .await
            .meta_command(&["AUTH", token])
            .await?;
        check_status(&resp)?;
        Ok(())
    }

    pub async fn health(&self) -> Result<Value, ClientError> {
        self.conn.lock().await.meta_command(&["HEALTH"]).await
    }

    pub async fn ping(&self) -> Result<String, ClientError> {
        let resp = self.conn.lock().await.meta_command(&["PING"]).await?;
        Ok(resp.as_str().unwrap_or("PONG").to_string())
    }

    pub async fn hello(&self) -> Result<Value, ClientError> {
        self.conn.lock().await.meta_command(&["HELLO"]).await
    }

    // ── Data plane ──────────────────────────────────────────────────────

    /// Append an entry; returns the allocated offset.
    pub async fn append(
        &self,
        log: &str,
        payload: &[u8],
        headers: Option<&BTreeMap<String, String>>,
        ttl_ms: Option<i64>,
    ) -> Result<u64, ClientError> {
        let b64 = base64::engine::general_purpose::STANDARD.encode(payload);
        let mut cmd: Vec<String> = vec!["APPEND".into(), log.into(), b64];
        let headers_json;
        if let Some(h) = headers
            && !h.is_empty()
        {
            headers_json =
                serde_json::to_string(h).map_err(|e| ClientError::Serialization(e.to_string()))?;
            cmd.push("HEADERS".into());
            cmd.push(headers_json);
        }
        let ttl_str;
        if let Some(ms) = ttl_ms {
            ttl_str = ms.to_string();
            cmd.push("TTL".into());
            cmd.push(ttl_str);
        }
        let refs: Vec<&str> = cmd.iter().map(|s| s.as_str()).collect();
        let resp = self.conn.lock().await.command(&refs).await?;
        check_status(&resp)?;
        resp["offset"]
            .as_u64()
            .ok_or_else(|| ClientError::Protocol("missing offset in APPEND response".into()))
    }

    pub async fn read(
        &self,
        log: &str,
        from_offset: u64,
        limit: u32,
    ) -> Result<Vec<LogEntry>, ClientError> {
        let from = from_offset.to_string();
        let lim = limit.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["READ", log, &from, &lim])
            .await?;
        check_status(&resp)?;
        entries_from_value(&resp)
    }

    pub async fn tail(
        &self,
        log: &str,
        from_offset: u64,
        limit: u32,
        timeout_ms: Option<u64>,
    ) -> Result<Vec<LogEntry>, ClientError> {
        let from = from_offset.to_string();
        let lim = limit.to_string();
        let mut cmd = vec!["TAIL", log, &from, &lim];
        let timeout_str;
        if let Some(t) = timeout_ms {
            timeout_str = t.to_string();
            cmd.push("TIMEOUT");
            cmd.push(&timeout_str);
        }
        let resp = self.conn.lock().await.command(&cmd).await?;
        check_status(&resp)?;
        entries_from_value(&resp)
    }

    // ── Reader groups ───────────────────────────────────────────────────

    /// Create a reader group. `start_offset` accepts `"earliest"`,
    /// `"latest"`, or a decimal u64 literal.
    pub async fn create_group(
        &self,
        log: &str,
        group: &str,
        start_offset: &str,
    ) -> Result<(), ClientError> {
        let resp = self
            .conn
            .lock()
            .await
            .command(&["CREATE_GROUP", log, group, start_offset])
            .await?;
        check_status(&resp)?;
        Ok(())
    }

    pub async fn read_group(
        &self,
        log: &str,
        group: &str,
        reader_id: &str,
        limit: u32,
    ) -> Result<Vec<LogEntry>, ClientError> {
        let lim = limit.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["READ_GROUP", log, group, reader_id, &lim])
            .await?;
        check_status(&resp)?;
        entries_from_value(&resp)
    }

    pub async fn ack(&self, log: &str, group: &str, offset: u64) -> Result<(), ClientError> {
        let off = offset.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["ACK", log, group, &off])
            .await?;
        check_status(&resp)?;
        Ok(())
    }

    pub async fn claim(
        &self,
        log: &str,
        group: &str,
        reader_id: &str,
        min_idle_ms: i64,
    ) -> Result<Vec<u64>, ClientError> {
        let idle = min_idle_ms.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["CLAIM", log, group, reader_id, &idle])
            .await?;
        check_status(&resp)?;
        let arr = resp["claimed"]
            .as_array()
            .ok_or_else(|| ClientError::Protocol("missing claimed array".into()))?;
        arr.iter()
            .map(|v| {
                v.as_u64()
                    .ok_or_else(|| ClientError::Protocol("non-u64 offset in claimed".into()))
            })
            .collect()
    }

    // ── Retention / teardown ────────────────────────────────────────────

    pub async fn trim_max_len(&self, log: &str, n: u64) -> Result<u64, ClientError> {
        let n_str = n.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["TRIM", log, "MAX_LEN", &n_str])
            .await?;
        check_status(&resp)?;
        Ok(resp["deleted"].as_u64().unwrap_or(0))
    }

    pub async fn trim_max_age_ms(&self, log: &str, ms: i64) -> Result<u64, ClientError> {
        let ms_str = ms.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["TRIM", log, "MAX_AGE", &ms_str])
            .await?;
        check_status(&resp)?;
        Ok(resp["deleted"].as_u64().unwrap_or(0))
    }

    pub async fn delete_log(&self, log: &str) -> Result<(), ClientError> {
        let resp = self.conn.lock().await.command(&["DELETE_LOG", log]).await?;
        check_status(&resp)?;
        Ok(())
    }

    /// Resolves SPEC §17 Q4. Move a DLQ entry at `offset` back into the
    /// given group's pending set. Preserves the original reader_id, resets
    /// delivery_count to 1. Returns `Server` error for `DlqEntryNotFound`
    /// or `GroupNotFound`.
    pub async fn replay(&self, log: &str, group: &str, offset: u64) -> Result<(), ClientError> {
        let off = offset.to_string();
        let resp = self
            .conn
            .lock()
            .await
            .command(&["REPLAY", log, group, &off])
            .await?;
        check_status(&resp)?;
        Ok(())
    }

    /// Resolves SPEC §17 Q7. Tear down a single reader group: deletes
    /// every pending record for the group, then removes the group row.
    /// Other groups on the same log are untouched.
    pub async fn delete_group(&self, log: &str, group: &str) -> Result<(), ClientError> {
        let resp = self
            .conn
            .lock()
            .await
            .command(&["DELETE_GROUP", log, group])
            .await?;
        check_status(&resp)?;
        Ok(())
    }

    // ── Introspection ───────────────────────────────────────────────────

    pub async fn log_info(&self, log: &str) -> Result<Value, ClientError> {
        self.conn.lock().await.command(&["LOG_INFO", log]).await
    }

    pub async fn group_info(&self, log: &str, group: &str) -> Result<Value, ClientError> {
        self.conn
            .lock()
            .await
            .command(&["GROUP_INFO", log, group])
            .await
    }
}

fn check_status(resp: &Value) -> Result<(), ClientError> {
    if resp.get("status").and_then(|s| s.as_str()) == Some("ok") {
        return Ok(());
    }
    if resp.is_string() {
        return Ok(());
    }
    Err(ClientError::Server(resp.to_string()))
}

fn entries_from_value(resp: &Value) -> Result<Vec<LogEntry>, ClientError> {
    let arr = resp["entries"]
        .as_array()
        .ok_or_else(|| ClientError::Protocol("missing entries array".into()))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    arr.iter()
        .map(|v| {
            let payload_b64 = v["payload_b64"].as_str().unwrap_or("");
            let payload = b64
                .decode(payload_b64)
                .map_err(|e| ClientError::Protocol(format!("bad payload b64: {e}")))?;
            let offset = v["offset"].as_u64().unwrap_or(0);
            let tenant_id = v["tenant_id"].as_str().unwrap_or("").to_string();
            let log = v["log"].as_str().unwrap_or("").to_string();
            let appended_at_ms = v["appended_at_ms"].as_i64().unwrap_or(0);
            let expires_at_ms = v["expires_at_ms"].as_i64();
            let headers: BTreeMap<String, String> =
                serde_json::from_value(v["headers"].clone()).unwrap_or_default();
            Ok(LogEntry {
                offset,
                tenant_id,
                log,
                payload,
                headers,
                appended_at_ms,
                expires_at_ms,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn entries_from_value_decodes_base64() {
        let resp = json!({
            "status": "ok",
            "entries": [
                {
                    "offset": 7,
                    "tenant_id": "t",
                    "log": "l",
                    "payload_b64": "aGVsbG8=",
                    "headers": {"k": "v"},
                    "appended_at_ms": 1234,
                    "expires_at_ms": null,
                }
            ]
        });
        let entries = entries_from_value(&resp).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].offset, 7);
        assert_eq!(entries[0].payload, b"hello");
        assert_eq!(entries[0].headers.get("k").unwrap(), "v");
    }

    #[test]
    fn check_status_rejects_missing_status() {
        let resp = json!({"foo": 1});
        assert!(check_status(&resp).is_err());
    }

    #[test]
    fn check_status_accepts_string() {
        assert!(check_status(&json!("PONG")).is_ok());
    }
}
