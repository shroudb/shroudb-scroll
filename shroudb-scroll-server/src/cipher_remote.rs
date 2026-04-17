use base64::Engine as _;
use shroudb_cipher_client::CipherClient;
use shroudb_crypto::SensitiveBytes;
use shroudb_scroll_core::ScrollError;
use shroudb_scroll_engine::capabilities::{BoxFut, DataKeyPair, ScrollCipherOps};
use tokio::sync::Mutex;

/// `ScrollCipherOps` backed by a remote `shroudb-cipher` server over TCP.
///
/// Holds one `CipherClient` behind a `Mutex` — calls are serialized per
/// Scroll-server. Adequate for P1; a connection pool (Sigil's pattern) is
/// a viable future optimization.
pub struct RemoteCipherOps {
    client: Mutex<CipherClient>,
    keyring: String,
}

impl RemoteCipherOps {
    pub async fn connect(
        addr: &str,
        keyring: String,
        auth_token: Option<&str>,
    ) -> anyhow::Result<Self> {
        let mut client = CipherClient::connect(addr).await?;
        if let Some(t) = auth_token {
            client.auth(t).await?;
        }
        Ok(Self {
            client: Mutex::new(client),
            keyring,
        })
    }
}

impl ScrollCipherOps for RemoteCipherOps {
    fn generate_data_key(&self, bits: Option<u32>) -> BoxFut<'_, DataKeyPair> {
        Box::pin(async move {
            let mut client = self.client.lock().await;
            let result = client
                .generate_data_key(&self.keyring, bits)
                .await
                .map_err(|e| ScrollError::Crypto(format!("cipher generate_data_key: {e}")))?;
            let plaintext = base64::engine::general_purpose::STANDARD
                .decode(&result.plaintext_key)
                .map_err(|e| ScrollError::Crypto(format!("plaintext_key not base64: {e}")))?;
            Ok(DataKeyPair {
                plaintext_key: SensitiveBytes::new(plaintext),
                wrapped_key: result.wrapped_key,
                key_version: result.key_version,
            })
        })
    }

    fn unwrap_data_key(&self, wrapped_key: &str) -> BoxFut<'_, SensitiveBytes> {
        let wrapped = wrapped_key.to_string();
        Box::pin(async move {
            let mut client = self.client.lock().await;
            // The Cipher envelope is the wrapped DEK; `decrypt` unwraps it.
            let result = client
                .decrypt(&self.keyring, &wrapped, None)
                .await
                .map_err(|e| ScrollError::Crypto(format!("cipher decrypt: {e}")))?;
            let plaintext = base64::engine::general_purpose::STANDARD
                .decode(result.plaintext.as_str())
                .map_err(|e| ScrollError::Crypto(format!("unwrapped DEK not base64: {e}")))?;
            Ok(SensitiveBytes::new(plaintext))
        })
    }
}

#[cfg(test)]
mod tests {
    // Requires a running Cipher server; exercised through full server
    // integration tests in downstream deployments rather than unit tests.
    #[test]
    fn placeholder() {}
}
