//! VAJRA error types.
//!
//! Single unified error enum covering all failure modes across
//! the VAJRA cryptographic pipeline. Every variant carries
//! descriptive context for debugging without leaking secrets.

use thiserror::Error;

/// Unified error type for all VAJRA operations.
#[derive(Debug, Error)]
pub enum VajraError {
    // ── Cryptographic failures ──────────────────────────────────

    /// AES-GCM encryption failed (e.g., invalid key length, nonce collision).
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// AES-GCM decryption failed (e.g., authentication tag mismatch).
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// HKDF key derivation failed (e.g., invalid input key material).
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// Key material has wrong length.
    #[error("Invalid key length: expected {expected} bytes, got {got} bytes")]
    InvalidKeyLength { expected: usize, got: usize },

    // ── Ratchet failures ────────────────────────────────────────

    /// Packet counter approaching u64::MAX — session must be rotated.
    #[error("Packet counter overflow: session must be rotated")]
    PacketCounterOverflow,

    /// Received packet with counter behind current state.
    #[error("Out of order packet: expected >= {expected}, got {got}")]
    OutOfOrderPacket { expected: u64, got: u64 },

    /// Ratchet state on two ends has diverged irrecoverably.
    #[error("Ratchet desynchronized: re-handshake required")]
    RatchetDesynchronized,

    // ── Shamir failures ─────────────────────────────────────────

    /// Not enough shares to reconstruct the secret.
    #[error("Insufficient shares: need {needed}, got {got}")]
    InsufficientShares { needed: usize, got: usize },

    /// Share index is out of valid range (must be 1..=n).
    #[error("Invalid share index: {0} (must be 1..=n)")]
    InvalidShareIndex(u8),

    /// Lagrange reconstruction produced invalid output.
    #[error("Reconstruction failed: {0}")]
    ReconstructionFailed(String),

    // ── Canary failures ─────────────────────────────────────────

    /// HMAC proof chain verification failed — packet was modified in transit.
    #[error("Proof chain broken at packet {packet_id}")]
    ProofChainBroken { packet_id: u64 },

    /// Inter-packet timing exceeds configured sigma threshold.
    #[error("Timing anomaly detected: {sigma:.2} sigma deviation")]
    TimingAnomaly { sigma: f64 },

    /// Traffic entropy dropped below baseline — potential covert channel.
    #[error("Entropy anomaly: dropped {drop_bits:.2} bits below baseline")]
    EntropyAnomaly { drop_bits: f64 },

    // ── Session failures ────────────────────────────────────────

    /// ML-KEM handshake did not complete successfully.
    #[error("Handshake failed: {0}")]
    HandshakeFailed(String),

    /// Initiator nonce was already seen — replay attack rejected.
    #[error("Replay detected: initiator nonce already seen")]
    ReplayDetected,

    /// Requested session ID not found in session table.
    #[error("Session not found: {0}")]
    SessionNotFound(u64),

    /// Session has exceeded its maximum lifetime.
    #[error("Session expired: {0}")]
    SessionExpired(u64),

    // ── I/O failures ────────────────────────────────────────────

    /// Network read/write/connect error.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Serialization or deserialization error (bincode/serde).
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Convenience type alias used throughout VAJRA.
pub type VajraResult<T> = Result<T, VajraError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        let err = VajraError::EncryptionFailed("nonce reuse".into());
        assert_eq!(err.to_string(), "Encryption failed: nonce reuse");

        let err = VajraError::InvalidKeyLength {
            expected: 32,
            got: 16,
        };
        assert_eq!(
            err.to_string(),
            "Invalid key length: expected 32 bytes, got 16 bytes"
        );

        let err = VajraError::InsufficientShares {
            needed: 3,
            got: 2,
        };
        assert_eq!(
            err.to_string(),
            "Insufficient shares: need 3, got 2"
        );

        let err = VajraError::ProofChainBroken { packet_id: 42 };
        assert_eq!(err.to_string(), "Proof chain broken at packet 42");

        let err = VajraError::TimingAnomaly { sigma: 4.5 };
        assert_eq!(
            err.to_string(),
            "Timing anomaly detected: 4.50 sigma deviation"
        );
    }

    #[test]
    fn error_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<VajraError>();
    }
}
