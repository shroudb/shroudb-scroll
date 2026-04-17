use serde::{Deserialize, Serialize};
use shroudb_scroll_core::ScrollError;
use shroudb_store::{Store, StoreError};

pub const OFFSETS_NS: &str = "scroll.offsets";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OffsetCounter {
    next: u64,
}

pub fn offset_key(tenant_id: &str, log: &str) -> Vec<u8> {
    format!("{tenant_id}/{log}").into_bytes()
}

/// Reserve the next offset for `(tenant, log)` via CAS.
///
/// Protocol:
///   1. GET current `{next}` + store version. On NotFound: treat as `next=0`, version=0.
///   2. `put_if_version(expected=version, value={next: current+1})`.
///   3. Return the allocated offset (= `current`).
///   4. On `VersionConflict`, retry up to `retry_max` times.
///
/// After success, the caller writes `scroll.logs/{tenant}/{log}/{offset:020}`
/// with the encrypted entry. A crash between step 2 and the entry put leaves a
/// gap — delivery at that offset returns NotFound and the group cursor moves past.
pub async fn allocate<S: Store>(
    store: &S,
    tenant_id: &str,
    log: &str,
    retry_max: u32,
) -> Result<u64, ScrollError> {
    let key = offset_key(tenant_id, log);

    for _ in 0..=retry_max {
        let (current_next, expected_version) = match store.get(OFFSETS_NS, &key, None).await {
            Ok(entry) => {
                let counter: OffsetCounter = serde_json::from_slice(&entry.value)
                    .map_err(|e| ScrollError::Store(format!("corrupt offset counter: {e}")))?;
                (counter.next, entry.version)
            }
            Err(StoreError::NotFound) => (0, 0),
            Err(e) => return Err(ScrollError::Store(format!("offset get: {e}"))),
        };

        let new_value = serde_json::to_vec(&OffsetCounter {
            next: current_next + 1,
        })
        .map_err(|e| ScrollError::Internal(format!("offset encode: {e}")))?;

        match store
            .put_if_version(OFFSETS_NS, &key, &new_value, None, expected_version)
            .await
        {
            Ok(_) => return Ok(current_next),
            Err(StoreError::VersionConflict { .. }) => continue,
            Err(e) => return Err(ScrollError::Store(format!("offset CAS: {e}"))),
        }
    }

    Err(ScrollError::VersionConflict {
        target: format!("{OFFSETS_NS}/{tenant_id}/{log}"),
    })
}
