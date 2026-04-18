use serde::{Deserialize, Serialize};
use shroudb_scroll_core::ScrollError;
use shroudb_store::{Store, StoreError};

pub const OFFSETS_NS: &str = "scroll.offsets";

/// Persisted shape of the `scroll.offsets` counter row — a bare `next` field,
/// kept as a struct (rather than raw u64) so the value is self-describing at
/// the Store layer and easy to version if fields are added later.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OffsetCounter {
    pub next: u64,
}

pub fn offset_key(tenant_id: &str, log: &str) -> Vec<u8> {
    format!("{tenant_id}/{log}").into_bytes()
}

/// Load the persisted counter for a log. `NotFound` → `next = 0`.
///
/// Used by the per-log `LogAppender` serializer to seed its in-memory
/// counter on first APPEND, and by `current_next_offset` for
/// `CREATE_GROUP ... latest` resolution.
pub async fn load<S: Store>(store: &S, tenant_id: &str, log: &str) -> Result<u64, ScrollError> {
    let key = offset_key(tenant_id, log);
    match store.get(OFFSETS_NS, &key, None).await {
        Ok(entry) => {
            let counter: OffsetCounter = serde_json::from_slice(&entry.value)
                .map_err(|e| ScrollError::Store(format!("corrupt offset counter: {e}")))?;
            Ok(counter.next)
        }
        Err(StoreError::NotFound) => Ok(0),
        Err(e) => Err(ScrollError::Store(format!("offset get: {e}"))),
    }
}

/// Persist the counter. Called by the serializer after it's already handed
/// out the offset in memory; Store write failures propagate so the caller
/// can decide whether to abort the APPEND.
pub async fn persist<S: Store>(
    store: &S,
    tenant_id: &str,
    log: &str,
    next: u64,
) -> Result<(), ScrollError> {
    let key = offset_key(tenant_id, log);
    let value = serde_json::to_vec(&OffsetCounter { next })
        .map_err(|e| ScrollError::Internal(format!("offset encode: {e}")))?;
    store
        .put(OFFSETS_NS, &key, &value, None)
        .await
        .map_err(|e| ScrollError::Store(format!("offset put: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offset_key_is_tenant_slash_log() {
        assert_eq!(offset_key("t1", "orders"), b"t1/orders".to_vec());
        assert_eq!(
            offset_key("acme", "billing/invoices"),
            b"acme/billing/invoices".to_vec()
        );
    }

    #[test]
    fn offset_counter_roundtrips_json() {
        let c = OffsetCounter { next: 42 };
        let bytes = serde_json::to_vec(&c).unwrap();
        let back: OffsetCounter = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.next, 42);
    }

    #[tokio::test]
    async fn load_missing_counter_returns_zero() {
        let store = shroudb_storage::test_util::create_test_store("offsets-load-missing").await;
        shroudb_store::Store::namespace_create(store.as_ref(), OFFSETS_NS, Default::default())
            .await
            .ok();
        let n = load(store.as_ref(), "t", "new-log").await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn persist_then_load_roundtrip() {
        let store = shroudb_storage::test_util::create_test_store("offsets-roundtrip").await;
        shroudb_store::Store::namespace_create(store.as_ref(), OFFSETS_NS, Default::default())
            .await
            .ok();
        persist(store.as_ref(), "t", "l", 7).await.unwrap();
        let n = load(store.as_ref(), "t", "l").await.unwrap();
        assert_eq!(n, 7);
    }
}
