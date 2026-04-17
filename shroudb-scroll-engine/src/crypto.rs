use shroudb_crypto::{aes_gcm_decrypt, aes_gcm_encrypt};
use shroudb_scroll_core::ScrollError;

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Build the AEAD AAD that binds a ciphertext to its position in a log.
/// Transplanting a ciphertext to a different `(tenant, log, offset)`
/// tuple causes authentication to fail.
pub fn build_aad(tenant_id: &str, log: &str, offset: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(tenant_id.len() + log.len() + 22);
    out.extend_from_slice(tenant_id.as_bytes());
    out.push(0);
    out.extend_from_slice(log.as_bytes());
    out.push(0);
    out.extend_from_slice(format!("{offset:020}").as_bytes());
    out
}

/// Encrypt a serialized `LogEntry` with the per-log DEK.
///
/// Output format (from `shroudb_crypto::aes_gcm_encrypt`):
///   `nonce (12) ‖ ciphertext ‖ tag (16)`.
pub fn encrypt_entry(dek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ScrollError> {
    if dek.len() != KEY_LEN {
        return Err(ScrollError::Crypto(format!(
            "DEK must be {KEY_LEN} bytes, got {}",
            dek.len()
        )));
    }
    aes_gcm_encrypt(dek, plaintext, aad).map_err(|e| ScrollError::Crypto(e.to_string()))
}

/// Decrypt a stored entry ciphertext with the per-log DEK.
pub fn decrypt_entry(dek: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ScrollError> {
    if dek.len() != KEY_LEN {
        return Err(ScrollError::Crypto(format!(
            "DEK must be {KEY_LEN} bytes, got {}",
            dek.len()
        )));
    }
    if ciphertext.len() < NONCE_LEN + TAG_LEN {
        return Err(ScrollError::Crypto(format!(
            "ciphertext too short: {} bytes (minimum {})",
            ciphertext.len(),
            NONCE_LEN + TAG_LEN
        )));
    }
    aes_gcm_decrypt(dek, ciphertext, aad).map_err(|e| ScrollError::Crypto(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key(seed: u8) -> Vec<u8> {
        (0..KEY_LEN as u8).map(|i| i.wrapping_add(seed)).collect()
    }
    fn random_key() -> Vec<u8> {
        test_key(0x42)
    }

    #[test]
    fn aad_binds_tenant_log_offset() {
        let a = build_aad("t1", "orders", 7);
        let b = build_aad("t1", "orders", 8);
        let c = build_aad("t1", "refunds", 7);
        let d = build_aad("t2", "orders", 7);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn roundtrip() {
        let k = random_key();
        let aad = build_aad("t", "l", 5);
        let ct = encrypt_entry(&k, b"hello", &aad).unwrap();
        let pt = decrypt_entry(&k, &ct, &aad).unwrap();
        assert_eq!(pt, b"hello");
    }

    #[test]
    fn transplanted_ciphertext_fails() {
        let k = random_key();
        let aad_src = build_aad("t", "l", 5);
        let aad_dst = build_aad("t", "l", 6);
        let ct = encrypt_entry(&k, b"hello", &aad_src).unwrap();
        assert!(decrypt_entry(&k, &ct, &aad_dst).is_err());
    }

    #[test]
    fn wrong_dek_fails() {
        let k1 = test_key(0x01);
        let k2 = test_key(0x02);
        let aad = build_aad("t", "l", 5);
        let ct = encrypt_entry(&k1, b"hello", &aad).unwrap();
        assert!(decrypt_entry(&k2, &ct, &aad).is_err());
    }

    #[test]
    fn wrong_key_length_rejected() {
        let short = vec![0u8; 16];
        let aad = build_aad("t", "l", 0);
        assert!(encrypt_entry(&short, b"x", &aad).is_err());
        assert!(decrypt_entry(&short, &[0u8; 40], &aad).is_err());
    }

    #[test]
    fn short_ciphertext_rejected() {
        let k = random_key();
        let aad = build_aad("t", "l", 0);
        assert!(decrypt_entry(&k, &[0u8; 10], &aad).is_err());
    }
}
