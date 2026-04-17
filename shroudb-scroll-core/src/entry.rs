use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEntry {
    pub offset: u64,
    pub tenant_id: String,
    pub log: String,
    pub payload: Vec<u8>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    pub appended_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
}

impl LogEntry {
    pub fn new(
        offset: u64,
        tenant_id: String,
        log: String,
        payload: Vec<u8>,
        headers: BTreeMap<String, String>,
        appended_at_ms: i64,
        expires_at_ms: Option<i64>,
    ) -> Self {
        Self {
            offset,
            tenant_id,
            log,
            payload,
            headers,
            appended_at_ms,
            expires_at_ms,
        }
    }

    /// Total byte cost for size budgeting: payload + serialized header pairs.
    pub fn size_bytes(&self) -> usize {
        let headers_bytes: usize = self.headers.iter().map(|(k, v)| k.len() + v.len()).sum();
        self.payload.len() + headers_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let mut headers = BTreeMap::new();
        headers.insert("content-type".into(), "application/json".into());
        let entry = LogEntry::new(
            42,
            "t1".into(),
            "orders".into(),
            b"hello".to_vec(),
            headers,
            1_700_000_000_000,
            Some(1_700_000_060_000),
        );
        let bytes = serde_json::to_vec(&entry).unwrap();
        let parsed: LogEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, entry);
    }

    #[test]
    fn skips_empty_headers_and_absent_ttl() {
        let entry = LogEntry::new(
            0,
            "t".into(),
            "l".into(),
            b"x".to_vec(),
            BTreeMap::new(),
            1,
            None,
        );
        let s = serde_json::to_string(&entry).unwrap();
        assert!(!s.contains("headers"));
        assert!(!s.contains("expires_at_ms"));
    }

    #[test]
    fn size_bytes_counts_payload_and_headers() {
        let mut headers = BTreeMap::new();
        headers.insert("k".into(), "vv".into());
        let entry = LogEntry::new(0, "t".into(), "l".into(), vec![0u8; 10], headers, 1, None);
        assert_eq!(entry.size_bytes(), 10 + 1 + 2);
    }
}
