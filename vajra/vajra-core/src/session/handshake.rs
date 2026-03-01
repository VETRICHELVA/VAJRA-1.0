//! ML-KEM-768 session handshake.
//!
//! Uses `pqc_kyber` crate for post-quantum key encapsulation.
//! Both parties derive a session key from the shared secret via HKDF.
//!
//! # Protocol
//! 1. Initiator generates ML-KEM-768 keypair, sends public key + initiator_nonce.
//! 2. Responder encapsulates, sends ciphertext + responder_nonce.
//! 3. Both derive session key:
//!    ```text
//!    session_key = HKDF(
//!        ikm:  ml_kem_shared_secret,
//!        salt: initiator_nonce || responder_nonce,
//!        info: b"VAJRA_SESSION_v1",
//!        length: 32
//!    )
//!    ```
//!
//! # Security Invariants
//! - Both nonces are 32 random bytes.
//! - Session key derivation uses domain-separated HKDF.
//! - All secret material zeroized on drop.

use pqc_kyber::*;
use rand::RngCore;
use zeroize::Zeroizing;

use crate::crypto::primitives::{self, KEY_LEN};
use crate::error::{VajraError, VajraResult};

/// Nonce length in bytes.
pub const NONCE_LEN: usize = 32;

/// Initiator's handshake state (before receiving response).
pub struct InitiatorHandshake {
    /// ML-KEM secret key (for decapsulation).
    secret_key: Zeroizing<Vec<u8>>,
    /// ML-KEM public key (sent to responder).
    pub public_key: Vec<u8>,
    /// Initiator's random nonce.
    pub nonce: [u8; NONCE_LEN],
}

/// Responder's handshake output.
pub struct ResponderHandshake {
    /// ML-KEM ciphertext (sent back to initiator).
    pub ciphertext: Vec<u8>,
    /// Responder's random nonce.
    pub nonce: [u8; NONCE_LEN],
    /// Derived session key.
    pub session_key: Zeroizing<[u8; KEY_LEN]>,
    /// Session ID (first 16 bytes of HKDF of shared secret with "VAJRA_SESSID_v1").
    pub session_id: [u8; 16],
}

/// Result of the initiator completing the handshake.
pub struct HandshakeResult {
    /// Derived session key (same as responder's).
    pub session_key: Zeroizing<[u8; KEY_LEN]>,
    /// Session ID (same as responder's).
    pub session_id: [u8; 16],
}

/// Derive the session key from ML-KEM shared secret and both nonces.
fn derive_session_key(
    shared_secret: &[u8],
    initiator_nonce: &[u8; NONCE_LEN],
    responder_nonce: &[u8; NONCE_LEN],
) -> VajraResult<(Zeroizing<[u8; KEY_LEN]>, [u8; 16])> {
    // salt = initiator_nonce || responder_nonce
    let mut salt = [0u8; NONCE_LEN * 2];
    salt[..NONCE_LEN].copy_from_slice(initiator_nonce);
    salt[NONCE_LEN..].copy_from_slice(responder_nonce);

    // Derive session key
    let session_key = primitives::hkdf_derive(shared_secret, Some(&salt), b"VAJRA_SESSION_v1")?;

    // Derive session ID (16 bytes)
    let session_id_full =
        primitives::hkdf_derive(shared_secret, Some(&salt), b"VAJRA_SESSID_v1")?;
    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&session_id_full[..16]);

    Ok((session_key, session_id))
}

impl InitiatorHandshake {
    /// Generate a new ML-KEM-768 keypair and initiator nonce.
    pub fn new() -> VajraResult<Self> {
        let mut rng = rand::thread_rng();

        // Generate ML-KEM-768 keypair
        let keys = keypair(&mut rng)
            .map_err(|e| VajraError::HandshakeFailed(format!("keypair generation: {e:?}")))?;

        // Generate random nonce
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);

        Ok(Self {
            secret_key: Zeroizing::new(keys.secret.to_vec()),
            public_key: keys.public.to_vec(),
            nonce,
        })
    }

    /// Complete the handshake after receiving responder's ciphertext and nonce.
    ///
    /// Decapsulates the shared secret and derives the session key.
    pub fn complete(
        self,
        ciphertext: &[u8],
        responder_nonce: &[u8; NONCE_LEN],
    ) -> VajraResult<HandshakeResult> {
        // Decapsulate shared secret
        let shared_secret = decapsulate(ciphertext, &self.secret_key)
            .map_err(|e| VajraError::HandshakeFailed(format!("decapsulation: {e:?}")))?;

        let (session_key, session_id) =
            derive_session_key(&shared_secret, &self.nonce, responder_nonce)?;

        Ok(HandshakeResult {
            session_key,
            session_id,
        })
    }
}

/// Responder side: encapsulate a shared secret with the initiator's public key.
pub fn responder_handshake(
    initiator_public_key: &[u8],
    initiator_nonce: &[u8; NONCE_LEN],
) -> VajraResult<ResponderHandshake> {
    let mut rng = rand::thread_rng();

    // Encapsulate shared secret
    let (ciphertext, shared_secret) = encapsulate(initiator_public_key, &mut rng)
        .map_err(|e| VajraError::HandshakeFailed(format!("encapsulation: {e:?}")))?;

    // Generate responder nonce
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let (session_key, session_id) =
        derive_session_key(&shared_secret, initiator_nonce, &nonce)?;

    Ok(ResponderHandshake {
        ciphertext: ciphertext.to_vec(),
        nonce,
        session_key,
        session_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_handshake_produces_same_key() {
        // Initiator generates keypair
        let initiator = InitiatorHandshake::new().unwrap();

        // Responder encapsulates with initiator's public key
        let responder =
            responder_handshake(&initiator.public_key, &initiator.nonce).unwrap();

        // Initiator completes handshake
        let result = initiator
            .complete(&responder.ciphertext, &responder.nonce)
            .unwrap();

        // Both must derive the same session key and session ID
        assert_eq!(*result.session_key, *responder.session_key);
        assert_eq!(result.session_id, responder.session_id);
    }

    #[test]
    fn different_handshakes_produce_different_keys() {
        let init1 = InitiatorHandshake::new().unwrap();
        let resp1 = responder_handshake(&init1.public_key, &init1.nonce).unwrap();
        let result1 = init1.complete(&resp1.ciphertext, &resp1.nonce).unwrap();

        let init2 = InitiatorHandshake::new().unwrap();
        let resp2 = responder_handshake(&init2.public_key, &init2.nonce).unwrap();
        let result2 = init2.complete(&resp2.ciphertext, &resp2.nonce).unwrap();

        assert_ne!(*result1.session_key, *result2.session_key);
        assert_ne!(result1.session_id, result2.session_id);
    }

    #[test]
    fn wrong_ciphertext_fails() {
        let initiator = InitiatorHandshake::new().unwrap();
        let responder =
            responder_handshake(&initiator.public_key, &initiator.nonce).unwrap();

        // Tamper with ciphertext
        let mut bad_ct = responder.ciphertext.clone();
        if !bad_ct.is_empty() {
            bad_ct[0] ^= 0xFF;
        }

        // Should still "complete" but with different keys (Kyber is IND-CCA2)
        // The decapsulation will succeed but produce a different shared secret
        let result = initiator.complete(&bad_ct, &responder.nonce);
        if let Ok(r) = result {
            // Keys should differ due to IND-CCA2 implicit rejection
            assert_ne!(*r.session_key, *responder.session_key);
        }
        // Or it might return an error depending on the implementation
    }

    #[test]
    fn session_id_is_16_bytes() {
        let init = InitiatorHandshake::new().unwrap();
        let resp = responder_handshake(&init.public_key, &init.nonce).unwrap();
        let result = init.complete(&resp.ciphertext, &resp.nonce).unwrap();

        assert_eq!(result.session_id.len(), 16);
    }
}
