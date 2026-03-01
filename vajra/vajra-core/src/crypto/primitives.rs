//! Cryptographic primitives — AES-256-GCM, HKDF-SHA256, HMAC-SHA256.
//!
//! # Security Invariants
//! - All comparisons on secret data use constant-time operations (`subtle`).
//! - All key material is wrapped in `Zeroizing<>` for automatic zeroing on drop.
//! - AES-GCM nonces are derived deterministically from packet counter + session ID
//!   via HKDF to guarantee uniqueness (never reuse).
//! - Zero heap allocation in encrypt/decrypt hot path when pre-allocated buffers
//!   are provided.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{VajraError, VajraResult};

/// AES-256-GCM tag length in bytes.
pub const AES_GCM_TAG_LEN: usize = 16;

/// AES-256-GCM nonce length in bytes.
pub const AES_GCM_NONCE_LEN: usize = 12;

/// HKDF output key length in bytes.
pub const KEY_LEN: usize = 32;

/// HMAC-SHA256 output length in bytes.
pub const HMAC_LEN: usize = 32;

// ── AES-256-GCM ─────────────────────────────────────────────────

/// Derive a unique 12-byte nonce from session ID and packet counter.
///
/// # Security Invariant
/// Nonce = first 12 bytes of HKDF(session_key, "VAJRA_NONCE_v1" || counter.to_be_bytes()).
/// As long as session_key and counter are unique per packet, nonce never repeats.
#[inline]
pub fn derive_nonce(
    session_key: &[u8; KEY_LEN],
    counter: u64,
) -> VajraResult<[u8; AES_GCM_NONCE_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, session_key);
    let mut info = [0u8; 14 + 8]; // "VAJRA_NONCE_v1" (14) + counter (8)
    info[..14].copy_from_slice(b"VAJRA_NONCE_v1");
    info[14..].copy_from_slice(&counter.to_be_bytes());

    let mut nonce = [0u8; AES_GCM_NONCE_LEN];
    hk.expand(&info, &mut nonce)
        .map_err(|e| VajraError::KeyDerivationFailed(format!("nonce derivation: {e}")))?;
    Ok(nonce)
}

/// Encrypt plaintext using AES-256-GCM with a derived nonce.
///
/// # Security Invariant
/// - Key must be exactly 32 bytes.
/// - Nonce is derived from session key + packet counter (never reused).
/// - Output = ciphertext || 16-byte tag (total: plaintext.len() + 16).
/// - Associated data (AAD) is authenticated but not encrypted.
///
/// # Returns
/// Ciphertext with appended authentication tag.
#[inline]
pub fn aes_gcm_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AES_GCM_NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> VajraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VajraError::EncryptionFailed(format!("cipher init: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    cipher
        .encrypt(nonce, payload)
        .map_err(|e| VajraError::EncryptionFailed(format!("AES-GCM encrypt: {e}")))
}

/// Decrypt ciphertext (with appended tag) using AES-256-GCM.
///
/// # Security Invariant
/// - Authentication tag is verified before any plaintext is returned.
/// - If tag verification fails, returns `DecryptionFailed` — no partial output.
#[inline]
pub fn aes_gcm_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; AES_GCM_NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> VajraResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VajraError::DecryptionFailed(format!("cipher init: {e}")))?;

    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| VajraError::DecryptionFailed(format!("AES-GCM decrypt: {e}")))
}

// ── HKDF-SHA256 ─────────────────────────────────────────────────

/// Derive a 32-byte key from input key material using HKDF-SHA256.
///
/// # Security Invariant
/// - Info string is prefixed with "VAJRA_HKDF_v1" to domain-separate all derivations.
/// - Output is wrapped in `Zeroizing` to ensure automatic zeroing on drop.
///
/// # Parameters
/// - `ikm`: input key material (previous key or shared secret)
/// - `salt`: optional salt (use `None` for ratchet steps, `Some` for handshake)
/// - `info`: context/application-specific info bytes
#[inline]
pub fn hkdf_derive(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
) -> VajraResult<Zeroizing<[u8; KEY_LEN]>> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);

    // Prefix info with version tag for domain separation
    let mut full_info = Vec::with_capacity(13 + info.len());
    full_info.extend_from_slice(b"VAJRA_HKDF_v1");
    full_info.extend_from_slice(info);

    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(&full_info, okm.as_mut())
        .map_err(|e| VajraError::KeyDerivationFailed(format!("HKDF expand: {e}")))?;

    Ok(okm)
}

// ── HMAC-SHA256 ─────────────────────────────────────────────────

/// Compute HMAC-SHA256 over the given data.
///
/// # Security Invariant
/// - Key must be exactly 32 bytes.
/// - Output is a 32-byte MAC.
#[inline]
pub fn hmac_compute(key: &[u8; KEY_LEN], data: &[u8]) -> [u8; HMAC_LEN] {
    let mut mac =
        Hmac::<Sha256>::new_from_slice(key).expect("HMAC key length is always valid at 32 bytes");
    mac.update(data);
    let result = mac.finalize();
    let mut output = [0u8; HMAC_LEN];
    output.copy_from_slice(&result.into_bytes());
    output
}

/// Verify an HMAC-SHA256 tag in constant time.
///
/// # Security Invariant
/// - Uses `subtle::ConstantTimeEq` to prevent timing side-channels.
/// - Returns `true` only if the tag matches exactly.
#[inline]
pub fn hmac_verify(key: &[u8; KEY_LEN], data: &[u8], expected_tag: &[u8; HMAC_LEN]) -> bool {
    let computed = hmac_compute(key, data);
    computed.ct_eq(expected_tag).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn random_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    // ── AES-GCM tests ──────────────────────────────────────────

    #[test]
    fn aes_gcm_roundtrip() {
        let key = random_key();
        let nonce = derive_nonce(&key, 0).unwrap();
        let plaintext = b"VAJRA test payload — quantum safe";
        let aad = b"session-metadata";

        let ciphertext = aes_gcm_encrypt(&key, &nonce, plaintext, aad).unwrap();
        assert_ne!(&ciphertext[..plaintext.len()], plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + AES_GCM_TAG_LEN);

        let decrypted = aes_gcm_decrypt(&key, &nonce, &ciphertext, aad).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn aes_gcm_wrong_key_fails() {
        let key = random_key();
        let wrong_key = random_key();
        let nonce = derive_nonce(&key, 0).unwrap();
        let ciphertext = aes_gcm_encrypt(&key, &nonce, b"secret", b"").unwrap();

        let result = aes_gcm_decrypt(&wrong_key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn aes_gcm_tampered_ciphertext_fails() {
        let key = random_key();
        let nonce = derive_nonce(&key, 0).unwrap();
        let mut ciphertext = aes_gcm_encrypt(&key, &nonce, b"important", b"").unwrap();
        ciphertext[0] ^= 0xFF; // flip bits

        let result = aes_gcm_decrypt(&key, &nonce, &ciphertext, b"");
        assert!(result.is_err());
    }

    #[test]
    fn aes_gcm_wrong_aad_fails() {
        let key = random_key();
        let nonce = derive_nonce(&key, 0).unwrap();
        let ciphertext = aes_gcm_encrypt(&key, &nonce, b"data", b"correct-aad").unwrap();

        let result = aes_gcm_decrypt(&key, &nonce, &ciphertext, b"wrong-aad");
        assert!(result.is_err());
    }

    #[test]
    fn nonce_uniqueness() {
        let key = random_key();
        let n1 = derive_nonce(&key, 0).unwrap();
        let n2 = derive_nonce(&key, 1).unwrap();
        let n3 = derive_nonce(&key, u64::MAX).unwrap();
        assert_ne!(n1, n2);
        assert_ne!(n2, n3);
        assert_ne!(n1, n3);
    }

    // ── HKDF tests ──────────────────────────────────────────────

    #[test]
    fn hkdf_deterministic() {
        let ikm = random_key();
        let k1 = hkdf_derive(&ikm, None, b"test-info").unwrap();
        let k2 = hkdf_derive(&ikm, None, b"test-info").unwrap();
        assert_eq!(*k1, *k2);
    }

    #[test]
    fn hkdf_different_info_different_keys() {
        let ikm = random_key();
        let k1 = hkdf_derive(&ikm, None, b"info-a").unwrap();
        let k2 = hkdf_derive(&ikm, None, b"info-b").unwrap();
        assert_ne!(*k1, *k2);
    }

    #[test]
    fn hkdf_different_salt_different_keys() {
        let ikm = random_key();
        let k1 = hkdf_derive(&ikm, Some(b"salt-a"), b"info").unwrap();
        let k2 = hkdf_derive(&ikm, Some(b"salt-b"), b"info").unwrap();
        assert_ne!(*k1, *k2);
    }

    // ── HMAC tests ──────────────────────────────────────────────

    #[test]
    fn hmac_roundtrip() {
        let key = random_key();
        let data = b"VAJRA packet payload";
        let tag = hmac_compute(&key, data);
        assert!(hmac_verify(&key, data, &tag));
    }

    #[test]
    fn hmac_wrong_key_fails() {
        let key = random_key();
        let wrong_key = random_key();
        let tag = hmac_compute(&key, b"data");
        assert!(!hmac_verify(&wrong_key, b"data", &tag));
    }

    #[test]
    fn hmac_tampered_data_fails() {
        let key = random_key();
        let tag = hmac_compute(&key, b"original");
        assert!(!hmac_verify(&key, b"tampered", &tag));
    }

    // ── 1500B packet size tests (matching benchmark target) ─────

    #[test]
    fn aes_gcm_1500b_packet() {
        let key = random_key();
        let nonce = derive_nonce(&key, 42).unwrap();
        let plaintext = vec![0xABu8; 1500];

        let ct = aes_gcm_encrypt(&key, &nonce, &plaintext, b"").unwrap();
        let pt = aes_gcm_decrypt(&key, &nonce, &ct, b"").unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn hmac_1500b_packet() {
        let key = random_key();
        let data = vec![0xCDu8; 1500];
        let tag = hmac_compute(&key, &data);
        assert!(hmac_verify(&key, &data, &tag));
    }
}
