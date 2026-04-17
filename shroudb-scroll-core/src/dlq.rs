use serde::{Deserialize, Serialize};

/// Record persisted to `scroll.dlq` when an entry's `delivery_count` crosses
/// the configured `max_delivery_count` during `CLAIM`. Keeps the full pending
/// history so operators can diagnose why delivery failed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DlqEntry {
    pub offset: u64,
    pub reader_id: String,
    pub delivered_at_ms: i64,
    /// Final `delivery_count` at the moment of the DLQ move.
    pub delivery_count: u32,
    pub moved_to_dlq_at_ms: i64,
    /// Reason the entry was moved. Currently always
    /// `"max_delivery_count_exceeded"`, but kept as a free-form string so
    /// future reason codes (e.g. manual DLQ placement) don't break the
    /// record shape.
    pub reason: String,
}
