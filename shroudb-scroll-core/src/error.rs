use thiserror::Error;

#[derive(Debug, Error)]
pub enum ScrollError {
    #[error("invalid entry: {0}")]
    InvalidEntry(String),

    #[error("entry too large: {size} bytes (max {max})")]
    EntryTooLarge { size: usize, max: usize },

    #[error("log not found: {0}")]
    LogNotFound(String),

    #[error("group not found: {log}/{group}")]
    GroupNotFound { log: String, group: String },

    #[error("group already exists: {log}/{group}")]
    GroupExists { log: String, group: String },

    /// Requested offset range has been retained-away (SPEC §8).
    #[error("range compacted: earliest available offset is {earliest}")]
    CompactedRange { earliest: u64 },

    /// CAS retry budget exhausted on offset or group cursor.
    #[error("version conflict: exhausted retry budget on {target}")]
    VersionConflict { target: String },

    /// Live-tail consumer fell behind its channel buffer (SPEC §9).
    #[error("tail overflow")]
    TailOverflow,

    /// Named capability (Cipher, Sentry, Chronicle) is required for this
    /// operation but wasn't provided at engine construction time. Fail-closed:
    /// Scroll does not silently downgrade to plaintext or open policy.
    #[error("capability not available: {0}")]
    CapabilityMissing(String),

    #[error("store error: {0}")]
    Store(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("access denied: {action} on {resource} (policy: {policy})")]
    AccessDenied {
        action: String,
        resource: String,
        policy: String,
    },
}
