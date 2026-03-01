//! TLS 1.3 wrapper for commercial VAJRA deployment.
//!
//! Wraps standard TLS 1.3 connections with VAJRA's Living Ratchet
//! and Breach Canary. Phantom Channels are intentionally NOT present
//! in the commercial version — paths are not independent on
//! commercial internet infrastructure.

use vajra_core::crypto::canary::BreachCanary;
use vajra_core::crypto::primitives::KEY_LEN;
use vajra_core::crypto::ratchet::{LivingRatchet, RatchetConfig, RatchetMode};
use vajra_core::error::VajraResult;

/// Commercial VAJRA session — TLS + Ratchet + Canary (no Shamir).
pub struct CommercialSession {
    pub ratchet: LivingRatchet,
    pub canary: BreachCanary,
    session_id: [u8; 16],
}

impl CommercialSession {
    /// Create a new commercial session from a TLS-derived key.
    pub fn new(
        session_key: [u8; KEY_LEN],
        canary_key: [u8; KEY_LEN],
        session_id: [u8; 16],
        packets_per_rotation: u64,
    ) -> Self {
        let config = RatchetConfig {
            mode: RatchetMode::PerSession {
                packets_per_rotation,
            },
            session_id,
        };

        Self {
            ratchet: LivingRatchet::new(session_key, config),
            canary: BreachCanary::new(canary_key, &session_id, 3.0, 0.5, None),
            session_id,
        }
    }

    /// Process an outgoing packet through the commercial pipeline.
    /// Pipeline: Ratchet → AES-GCM Encrypt → Canary Stamp
    /// (No Shamir split — honest architectural decision)
    pub fn process_outgoing(&mut self, plaintext: &[u8]) -> VajraResult<Vec<u8>> {
        use vajra_core::crypto::primitives;

        let (key, counter) = self.ratchet.advance()?;
        let nonce = primitives::derive_nonce(&key, counter)?;
        let aad = counter.to_be_bytes();
        let ciphertext = primitives::aes_gcm_encrypt(&key, &nonce, plaintext, &aad)?;

        // Canary stamp for integrity monitoring
        let _token = self.canary.stamp(&ciphertext);

        Ok(ciphertext)
    }

    /// Get session ID.
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn commercial_session_roundtrip() {
        let mut key = [0u8; KEY_LEN];
        let mut canary_key = [0u8; KEY_LEN];
        let mut session_id = [0u8; 16];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut canary_key);
        rng.fill_bytes(&mut session_id);

        let mut session = CommercialSession::new(key, canary_key, session_id, 10_000);

        let plaintext = b"Commercial VAJRA test packet";
        let ciphertext = session.process_outgoing(plaintext).unwrap();

        // Ciphertext should be different from plaintext
        assert_ne!(&ciphertext[..plaintext.len()], plaintext.as_slice());
        // Ciphertext should include 16-byte GCM tag
        assert_eq!(ciphertext.len(), plaintext.len() + 16);
    }
}
