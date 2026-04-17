use std::sync::Arc;

use dashmap::DashMap;
use shroudb_crypto::SensitiveBytes;
use shroudb_scroll_core::ScrollError;
use shroudb_store::{Store, StoreError};

use crate::capabilities::ScrollCipherOps;
use crate::meta::LogMeta;

pub const META_NS: &str = "scroll.meta";

fn meta_key(tenant_id: &str, log: &str) -> Vec<u8> {
    format!("{tenant_id}/{log}").into_bytes()
}

/// Lazy per-log DEK provisioning + in-process plaintext cache.
///
/// On first APPEND to a log, calls `cipher.generate_data_key` once, persists the
/// wrapped DEK alongside the log's config in `scroll.meta`, and caches the
/// plaintext DEK. Subsequent reads unwrap lazily on cache miss.
///
/// Cached DEKs are `Arc<SensitiveBytes>` so they zeroize once every reader and
/// the cache entry have dropped. `evict` is called on DELETE_LOG.
pub struct KeyManager {
    cache: DashMap<String, Arc<SensitiveBytes>>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self {
            cache: DashMap::new(),
        }
    }

    fn cache_key(tenant_id: &str, log: &str) -> String {
        format!("{tenant_id}/{log}")
    }

    /// Fetch (or load-and-cache) the plaintext DEK for an existing log.
    /// Returns `LogNotFound` when the log has no meta record.
    pub async fn get_existing<S: Store>(
        &self,
        store: &S,
        cipher: &dyn ScrollCipherOps,
        tenant_id: &str,
        log: &str,
    ) -> Result<(Arc<SensitiveBytes>, LogMeta), ScrollError> {
        let ck = Self::cache_key(tenant_id, log);
        let meta = self.load_meta(store, tenant_id, log).await?;
        if let Some(dek) = self.cache.get(&ck) {
            return Ok((dek.clone(), meta));
        }
        let unwrapped = cipher.unwrap_data_key(&meta.wrapped_dek).await?;
        let dek = Arc::new(unwrapped);
        self.cache.insert(ck, dek.clone());
        Ok((dek, meta))
    }

    /// Fetch existing meta+DEK, or provision a fresh DEK if the log is new.
    ///
    /// When the log is new, `new_meta_with_dek` is invoked to fill in the
    /// per-log config (caps, TTL). The caller supplies the DataKeyPair fields.
    pub async fn get_or_create<S: Store>(
        &self,
        store: &S,
        cipher: &dyn ScrollCipherOps,
        tenant_id: &str,
        log: &str,
        defaults: ProvisionDefaults,
    ) -> Result<(Arc<SensitiveBytes>, LogMeta), ScrollError> {
        match self.get_existing(store, cipher, tenant_id, log).await {
            Ok(pair) => Ok(pair),
            Err(ScrollError::LogNotFound(_)) => {
                self.provision(store, cipher, tenant_id, log, defaults)
                    .await
            }
            Err(e) => Err(e),
        }
    }

    async fn load_meta<S: Store>(
        &self,
        store: &S,
        tenant_id: &str,
        log: &str,
    ) -> Result<LogMeta, ScrollError> {
        let key = meta_key(tenant_id, log);
        match store.get(META_NS, &key, None).await {
            Ok(entry) => serde_json::from_slice(&entry.value)
                .map_err(|e| ScrollError::Store(format!("corrupt log meta: {e}"))),
            Err(StoreError::NotFound) => Err(ScrollError::LogNotFound(log.to_string())),
            Err(e) => Err(ScrollError::Store(format!("meta get: {e}"))),
        }
    }

    async fn provision<S: Store>(
        &self,
        store: &S,
        cipher: &dyn ScrollCipherOps,
        tenant_id: &str,
        log: &str,
        defaults: ProvisionDefaults,
    ) -> Result<(Arc<SensitiveBytes>, LogMeta), ScrollError> {
        let pair = cipher.generate_data_key(Some(256)).await?;
        let meta = LogMeta {
            wrapped_dek: pair.wrapped_key,
            key_version: pair.key_version,
            created_at_ms: defaults.now_ms,
            max_entry_bytes: defaults.max_entry_bytes,
            max_header_bytes: defaults.max_header_bytes,
            default_ttl_ms: defaults.default_ttl_ms,
        };
        let value = serde_json::to_vec(&meta)
            .map_err(|e| ScrollError::Internal(format!("meta encode: {e}")))?;
        let key = meta_key(tenant_id, log);

        // CAS-insert: if two workers race to provision the same log, one wins,
        // the other sees VersionConflict and falls back to the existing meta.
        match store.put_if_version(META_NS, &key, &value, None, 0).await {
            Ok(_) => {
                let dek = Arc::new(pair.plaintext_key);
                self.cache
                    .insert(Self::cache_key(tenant_id, log), dek.clone());
                Ok((dek, meta))
            }
            Err(StoreError::VersionConflict { .. }) => {
                // Another caller provisioned first; drop our DEK, load theirs.
                drop(pair.plaintext_key);
                self.get_existing(store, cipher, tenant_id, log).await
            }
            Err(e) => Err(ScrollError::Store(format!("meta CAS: {e}"))),
        }
    }

    /// Drop the cached plaintext DEK for a log. Invoked on DELETE_LOG.
    /// Safe to call when no entry exists.
    pub fn evict(&self, tenant_id: &str, log: &str) {
        self.cache.remove(&Self::cache_key(tenant_id, log));
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Parameters used when lazily provisioning a new log's meta record.
#[derive(Debug, Clone)]
pub struct ProvisionDefaults {
    pub now_ms: i64,
    pub max_entry_bytes: u64,
    pub max_header_bytes: u64,
    pub default_ttl_ms: Option<i64>,
}
