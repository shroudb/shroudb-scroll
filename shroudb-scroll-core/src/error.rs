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

    /// Requested DLQ entry is not present (already reaped, replayed, or
    /// never there). Returned by `REPLAY` when the target offset has no
    /// record in `scroll.dlq` for the log.
    #[error("dlq entry not found: {log}/{offset}")]
    DlqEntryNotFound { log: String, offset: u64 },

    /// Requested offset range has been retained-away.
    #[error("range compacted: earliest available offset is {earliest}")]
    CompactedRange { earliest: u64 },

    /// CAS retry budget exhausted on offset or group cursor.
    #[error("version conflict: exhausted retry budget on {target}")]
    VersionConflict { target: String },

    /// Live-tail consumer fell behind its channel buffer.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_entry_too_large_shows_size_and_max() {
        let e = ScrollError::EntryTooLarge {
            size: 2048,
            max: 1024,
        };
        let s = e.to_string();
        assert!(s.contains("2048"));
        assert!(s.contains("1024"));
    }

    #[test]
    fn display_group_not_found_shows_log_and_group() {
        let e = ScrollError::GroupNotFound {
            log: "orders".into(),
            group: "workers".into(),
        };
        let s = e.to_string();
        assert!(s.contains("orders"));
        assert!(s.contains("workers"));
    }

    #[test]
    fn display_dlq_entry_not_found_shows_log_and_offset() {
        let e = ScrollError::DlqEntryNotFound {
            log: "orders".into(),
            offset: 42,
        };
        let s = e.to_string();
        assert!(s.contains("orders"));
        assert!(s.contains("42"));
    }

    #[test]
    fn display_access_denied_shows_all_three_fields() {
        let e = ScrollError::AccessDenied {
            action: "append".into(),
            resource: "orders".into(),
            policy: "tenant-isolation".into(),
        };
        let s = e.to_string();
        assert!(s.contains("append"));
        assert!(s.contains("orders"));
        assert!(s.contains("tenant-isolation"));
    }

    #[test]
    fn display_capability_missing_shows_name() {
        let e = ScrollError::CapabilityMissing("cipher".into());
        assert!(e.to_string().contains("cipher"));
    }
}
