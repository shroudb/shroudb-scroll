use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use shroudb_acl::PolicyEvaluator;
use shroudb_chronicle_core::ops::ChronicleOps;
use shroudb_crypto::SensitiveBytes;
use shroudb_scroll_core::ScrollError;

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
/// Every capability is optional at construction — Scroll follows Sigil's
/// pattern: a missing capability is not a silent downgrade to plaintext /
/// open policy. Operations that *need* the capability fail-closed at the
/// use site with `ScrollError::CapabilityMissing`; operations that don't
/// need it continue to work.
///
/// In practice: `APPEND`, `READ`, and `READ_GROUP` require Cipher (every
/// payload is DEK-encrypted). `CREATE_GROUP`, `ACK`, `DELETE_LOG`,
/// `LOG_INFO`, and `GROUP_INFO` run without Cipher — useful for operators
/// inspecting or tearing down logs in a Cipher-less recovery deployment.
#[derive(Default)]
pub struct Capabilities {
    pub cipher: Option<Arc<dyn ScrollCipherOps>>,
    pub sentry: Option<Arc<dyn PolicyEvaluator>>,
    pub chronicle: Option<Arc<dyn ChronicleOps>>,
}

impl Capabilities {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cipher(mut self, cipher: Arc<dyn ScrollCipherOps>) -> Self {
        self.cipher = Some(cipher);
        self
    }

    pub fn with_sentry(mut self, sentry: Arc<dyn PolicyEvaluator>) -> Self {
        self.sentry = Some(sentry);
        self
    }

    pub fn with_chronicle(mut self, chronicle: Arc<dyn ChronicleOps>) -> Self {
        self.chronicle = Some(chronicle);
        self
    }
}
