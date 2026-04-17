use serde::{Deserialize, Serialize};

/// Per-log persisted config + wrapped DEK. Lives in the `scroll.meta` namespace
/// under key `{tenant_id}/{log}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogMeta {
    /// Base64-encoded Cipher envelope wrapping the per-log DEK.
    /// On DELETE_LOG this row (and therefore the wrapped DEK) is destroyed,
    /// which crypto-shreds every ciphertext previously written under this log.
    pub wrapped_dek: String,
    /// Cipher key version that wrapped the DEK at generation time.
    pub key_version: u32,
    pub created_at_ms: i64,
    /// Hard cap for `APPEND` payload+headers. Defaults mirror
    /// `EngineConfig::default_max_entry_bytes`.
    pub max_entry_bytes: u64,
    pub max_header_bytes: u64,
    /// Optional per-log default entry TTL in milliseconds. `None` or `0`
    /// means retention is driven by explicit TRIM only.
    pub default_ttl_ms: Option<i64>,
}
