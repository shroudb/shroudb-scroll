use std::sync::Arc;

use shroudb_cipher_engine::engine::CipherEngine;
use shroudb_crypto::SensitiveBytes;
use shroudb_scroll_core::ScrollError;
use shroudb_scroll_engine::capabilities::{BoxFut, DataKeyPair, ScrollCipherOps};
use shroudb_store::Store;

/// `ScrollCipherOps` backed by an in-process `CipherEngine`.
///
/// Used when Scroll is deployed as a single process that bundles its own
/// Cipher — no TCP hop, no separate service. The `CipherEngine` runs on
/// the same `StorageEngine` as Scroll (distinct namespace), so the same
/// master key protects Scroll's log data and Cipher's wrapped keys.
pub struct EmbeddedCipherOps<S: Store> {
    engine: Arc<CipherEngine<S>>,
    keyring: String,
}

impl<S: Store> EmbeddedCipherOps<S> {
    pub fn new(engine: Arc<CipherEngine<S>>, keyring: String) -> Self {
        Self { engine, keyring }
    }
}

impl<S: Store + 'static> ScrollCipherOps for EmbeddedCipherOps<S> {
    fn generate_data_key(&self, bits: Option<u32>) -> BoxFut<'_, DataKeyPair> {
        Box::pin(async move {
            let result = self
                .engine
                .generate_data_key(&self.keyring, bits)
                .map_err(|e| ScrollError::Crypto(format!("cipher generate_data_key: {e}")))?;
            Ok(DataKeyPair {
                plaintext_key: result.plaintext_key,
                wrapped_key: result.wrapped_key,
                key_version: result.key_version,
            })
        })
    }

    fn unwrap_data_key(&self, wrapped_key: &str) -> BoxFut<'_, SensitiveBytes> {
        let wrapped = wrapped_key.to_string();
        Box::pin(async move {
            let result = self
                .engine
                .decrypt(&self.keyring, &wrapped, None)
                .await
                .map_err(|e| ScrollError::Crypto(format!("cipher decrypt: {e}")))?;
            Ok(result.plaintext)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shroudb_cipher_core::keyring::KeyringAlgorithm;
    use shroudb_cipher_engine::engine::{CipherConfig, CipherEngine};
    use shroudb_storage::EmbeddedStore;
    use shroudb_storage::test_util::create_test_store;

    async fn build_cipher() -> Arc<CipherEngine<EmbeddedStore>> {
        let store = create_test_store("cipher").await;
        let engine = CipherEngine::new(store, CipherConfig::default(), None, None)
            .await
            .expect("cipher engine init");
        engine
            .keyring_create(
                "scroll-logs",
                KeyringAlgorithm::Aes256Gcm,
                None,
                None,
                false,
                None,
            )
            .await
            .expect("keyring create");
        Arc::new(engine)
    }

    #[tokio::test]
    async fn generate_and_unwrap_round_trip_yields_original_dek() {
        let cipher = build_cipher().await;
        let ops = EmbeddedCipherOps::new(cipher, "scroll-logs".into());

        let pair = ops.generate_data_key(Some(256)).await.expect("generate");
        assert_eq!(pair.plaintext_key.as_bytes().len(), 32);
        assert!(!pair.wrapped_key.is_empty());
        assert!(pair.key_version >= 1);

        let unwrapped = ops
            .unwrap_data_key(&pair.wrapped_key)
            .await
            .expect("unwrap");
        assert_eq!(unwrapped.as_bytes(), pair.plaintext_key.as_bytes());
    }

    #[tokio::test]
    async fn unwrap_rejects_tampered_envelope() {
        let cipher = build_cipher().await;
        let ops = EmbeddedCipherOps::new(cipher, "scroll-logs".into());

        let pair = ops.generate_data_key(None).await.expect("generate");
        let mut tampered = pair.wrapped_key.into_bytes();
        // Flip a byte in the middle of the envelope — AEAD tag must fail.
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x01;
        let tampered = String::from_utf8(tampered).expect("still utf8");

        let err = ops
            .unwrap_data_key(&tampered)
            .await
            .expect_err("tampered envelope must not decrypt");
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("cipher") || msg.contains("decrypt") || msg.contains("decode"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn generate_rejects_unknown_keyring() {
        let cipher = build_cipher().await;
        let ops = EmbeddedCipherOps::new(cipher, "does-not-exist".into());

        let err = match ops.generate_data_key(None).await {
            Ok(_) => panic!("unknown keyring must reject"),
            Err(e) => e,
        };
        assert!(err.to_string().to_ascii_lowercase().contains("cipher"));
    }
}
