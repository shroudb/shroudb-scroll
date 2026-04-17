use shroudb_scroll_core::{ReaderGroup, ScrollError};
use shroudb_store::{Store, StoreError};

pub const GROUPS_NS: &str = "scroll.groups";
pub const PENDING_NS: &str = "scroll.pending";

pub fn group_key(tenant_id: &str, log: &str, group: &str) -> Vec<u8> {
    format!("{tenant_id}/{log}/{group}").into_bytes()
}

pub fn pending_key(tenant_id: &str, log: &str, group: &str, offset: u64) -> Vec<u8> {
    format!("{tenant_id}/{log}/{group}/{offset:020}").into_bytes()
}

pub fn pending_prefix(tenant_id: &str, log: &str, group: &str) -> Vec<u8> {
    format!("{tenant_id}/{log}/{group}/").into_bytes()
}

/// Load a `ReaderGroup` along with its Store version (for CAS).
pub async fn load<S: Store>(
    store: &S,
    tenant_id: &str,
    log: &str,
    group: &str,
) -> Result<(ReaderGroup, u64), ScrollError> {
    let key = group_key(tenant_id, log, group);
    match store.get(GROUPS_NS, &key, None).await {
        Ok(entry) => {
            let g: ReaderGroup = serde_json::from_slice(&entry.value)
                .map_err(|e| ScrollError::Store(format!("corrupt group record: {e}")))?;
            Ok((g, entry.version))
        }
        Err(StoreError::NotFound) => Err(ScrollError::GroupNotFound {
            log: log.to_string(),
            group: group.to_string(),
        }),
        Err(e) => Err(ScrollError::Store(format!("group get: {e}"))),
    }
}

/// CAS-persist an updated `ReaderGroup`. Returns `VersionConflict` error
/// on race; caller retries.
pub async fn put_cas<S: Store>(
    store: &S,
    g: &ReaderGroup,
    expected_version: u64,
) -> Result<u64, ScrollError> {
    let key = group_key(&g.tenant_id, &g.log, &g.group);
    let value =
        serde_json::to_vec(g).map_err(|e| ScrollError::Internal(format!("group encode: {e}")))?;
    match store
        .put_if_version(GROUPS_NS, &key, &value, None, expected_version)
        .await
    {
        Ok(v) => Ok(v),
        Err(StoreError::VersionConflict { .. }) => Err(ScrollError::VersionConflict {
            target: format!("{GROUPS_NS}/{}/{}/{}", g.tenant_id, g.log, g.group),
        }),
        Err(e) => Err(ScrollError::Store(format!("group CAS: {e}"))),
    }
}
