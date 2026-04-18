use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::PolicyEvaluator;
use shroudb_audit::ChronicleOps;
use shroudb_crypto::SensitiveBytes;
use shroudb_scroll_core::ScrollError;
use shroudb_server_bootstrap::Capability;

pub type BoxFut<'a, T> = Pin<Box<dyn Future<Output = Result<T, ScrollError>> + Send + 'a>>;

pub struct DataKeyPair {
    /// Plaintext DEK for local encryption. Zeroized on drop.
    pub plaintext_key: SensitiveBytes,
    /// Base64-encoded Cipher envelope wrapping the DEK.
    pub wrapped_key: String,
    /// Cipher key version that wrapped this DEK.
    pub key_version: u32,
}

/// Cipher operations required by Scroll's per-log envelope encryption model.
///
/// Parallels Stash's `StashCipherOps`: Scroll generates one DEK per log via
/// `generate_data_key`, and unwraps it lazily on subsequent reads via
/// `unwrap_data_key`. Scroll performs the actual AES-256-GCM entry
/// encryption/decryption locally using the plaintext DEK.
pub trait ScrollCipherOps: Send + Sync {
    fn generate_data_key(&self, bits: Option<u32>) -> BoxFut<'_, DataKeyPair>;
    fn unwrap_data_key(&self, wrapped_key: &str) -> BoxFut<'_, SensitiveBytes>;
}

/// Engine capabilities provided at construction time.
///
/// Every slot is a [`Capability<T>`] — the explicit tri-state from
/// `shroudb-server-bootstrap`. *Absence is never silent.* The engine
/// cannot be constructed without a concrete choice for every slot:
/// either wired to a concrete impl, or `DisabledForTests`, or
/// `DisabledWithJustification("<reason>")`.
///
/// In practice: `APPEND`, `READ`, and `READ_GROUP` require Cipher (every
/// payload is DEK-encrypted) and fail-closed at the use site with
/// `ScrollError::CapabilityMissing("cipher")` if the slot is not
/// `Enabled`. Metadata commands (`CREATE_GROUP`, `ACK`, `DELETE_LOG`,
/// `LOG_INFO`, `GROUP_INFO`) don't need crypto and still work without
/// Cipher — useful for inspection/teardown of a Cipher-less recovery
/// deployment (which must explicitly set
/// `Capability::DisabledWithJustification` for cipher).
pub struct Capabilities {
    pub cipher: Capability<Arc<dyn ScrollCipherOps>>,
    pub sentry: Capability<Arc<dyn PolicyEvaluator>>,
    pub chronicle: Capability<Arc<dyn ChronicleOps>>,
}

impl Capabilities {
    /// Construct a Capabilities set for unit tests where every slot is
    /// intentionally absent.
    ///
    /// Never use this in production code — the load-bearing word is
    /// *tests*. Standalone server binaries must build each slot from
    /// config, naming a justification if they opt out.
    pub fn for_tests() -> Self {
        Self {
            cipher: Capability::DisabledForTests,
            sentry: Capability::DisabledForTests,
            chronicle: Capability::DisabledForTests,
        }
    }

    /// Construct a Capabilities set with explicit values for every slot.
    ///
    /// Standalone servers should build each `Capability<…>` from config
    /// (via `shroudb-engine-bootstrap`'s `AuditConfig::resolve` and
    /// `PolicyConfig::resolve` + their own cipher wiring) and pass the
    /// resulting triple here. The absence of a default constructor is
    /// intentional — every slot requires a conscious operator choice.
    pub fn new(
        cipher: Capability<Arc<dyn ScrollCipherOps>>,
        sentry: Capability<Arc<dyn PolicyEvaluator>>,
        chronicle: Capability<Arc<dyn ChronicleOps>>,
    ) -> Self {
        Self {
            cipher,
            sentry,
            chronicle,
        }
    }

    /// Install a concrete Cipher implementation.
    pub fn with_cipher(mut self, cipher: Arc<dyn ScrollCipherOps>) -> Self {
        self.cipher = Capability::Enabled(cipher);
        self
    }

    /// Install a concrete Sentry (policy evaluator) implementation.
    pub fn with_sentry(mut self, sentry: Arc<dyn PolicyEvaluator>) -> Self {
        self.sentry = Capability::Enabled(sentry);
        self
    }

    /// Install a concrete Chronicle (audit sink) implementation.
    pub fn with_chronicle(mut self, chronicle: Arc<dyn ChronicleOps>) -> Self {
        self.chronicle = Capability::Enabled(chronicle);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_tests_initializes_all_slots_disabled_for_tests() {
        let caps = Capabilities::for_tests();
        assert!(!caps.cipher.is_enabled());
        assert!(!caps.sentry.is_enabled());
        assert!(!caps.chronicle.is_enabled());
        assert_eq!(caps.cipher.justification(), Some("test harness"));
    }

    #[test]
    fn with_cipher_marks_slot_enabled() {
        struct Noop;
        impl ScrollCipherOps for Noop {
            fn generate_data_key(&self, _: Option<u32>) -> BoxFut<'_, DataKeyPair> {
                Box::pin(async { Err(ScrollError::Crypto("noop".into())) })
            }
            fn unwrap_data_key(&self, _: &str) -> BoxFut<'_, SensitiveBytes> {
                Box::pin(async { Err(ScrollError::Crypto("noop".into())) })
            }
        }
        let caps = Capabilities::for_tests().with_cipher(Arc::new(Noop));
        assert!(caps.cipher.is_enabled());
        assert!(!caps.sentry.is_enabled());
    }
}
