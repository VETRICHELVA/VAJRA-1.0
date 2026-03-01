//! Living Ratchet — per-session key evolution using HKDF-SHA256.
//!
//! # Architecture
//! - **Sovereign mode (`PerPacket`)**: Key ratchets on every packet.
//!   Maximum forward secrecy — blast radius is exactly 1 packet.
//! - **Commercial mode (`PerSession`)**: Key ratchets every N packets.
//!   Default N = 10,000. Blast radius is at most N packets.
//!
//! # Security Invariants
//! 1. After ratchet step, previous key is zeroed (`Zeroizing` wrapper).
//! 2. Packet counter never wraps — returns `PacketCounterOverflow` near u64::MAX.
//! 3. Cannot decrypt a packet with counter < current counter (no rollback).
//! 4. `session_id` must be unique per session (from ML-KEM handshake).
//!
//! # Key Derivation Chain
//! ```text
//! session_key_0 = ML-KEM shared secret (initial)
//! session_key_N = HKDF(
//!     ikm:  session_key_{N-1},
//!     info: b"VAJRA_RATCHET_v1" || session_id (16 bytes) || session_counter (8 bytes),
//!     len:  32
//! )
//! ```

use zeroize::Zeroizing;

use crate::crypto::primitives::{self, KEY_LEN};
use crate::error::{VajraError, VajraResult};

/// Safety margin before u64::MAX to prevent counter overflow.
const COUNTER_OVERFLOW_MARGIN: u64 = 1_000;

/// Controls how often the ratchet advances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetMode {
    /// Sovereign backbone: ratchet every single packet.
    PerPacket,
    /// Commercial default: ratchet every `packets_per_rotation` packets.
    PerSession {
        packets_per_rotation: u64,
    },
}

impl Default for RatchetMode {
    fn default() -> Self {
        RatchetMode::PerSession {
            packets_per_rotation: 10_000,
        }
    }
}

/// Configuration for a ratchet instance.
#[derive(Debug, Clone)]
pub struct RatchetConfig {
    pub mode: RatchetMode,
    pub session_id: [u8; 16],
}

/// The Living Ratchet state machine.
///
/// Holds the current session key and advances it according to the
/// configured `RatchetMode`. Previous keys are automatically zeroed.
pub struct LivingRatchet {
    current_key: Zeroizing<[u8; KEY_LEN]>,
    packet_counter: u64,
    session_counter: u64,
    config: RatchetConfig,
}

impl LivingRatchet {
    /// Create a new ratchet from an initial shared secret and configuration.
    ///
    /// # Parameters
    /// - `initial_key`: 32-byte shared secret from ML-KEM handshake.
    /// - `config`: session ID and ratchet mode.
    pub fn new(initial_key: [u8; KEY_LEN], config: RatchetConfig) -> Self {
        Self {
            current_key: Zeroizing::new(initial_key),
            packet_counter: 0,
            session_counter: 0,
            config,
        }
    }

    /// Get the current encryption key (read-only reference).
    #[inline]
    pub fn current_key(&self) -> &[u8; KEY_LEN] {
        &self.current_key
    }

    /// Get the current packet counter.
    #[inline]
    pub fn packet_counter(&self) -> u64 {
        self.packet_counter
    }

    /// Get the current session (rotation) counter.
    #[inline]
    pub fn session_counter(&self) -> u64 {
        self.session_counter
    }

    /// Advance the ratchet by one packet.
    ///
    /// Returns the key to use for this packet and the current packet counter.
    /// The ratchet may or may not rotate the key depending on the mode.
    ///
    /// # Errors
    /// - `PacketCounterOverflow` if counter is near u64::MAX.
    pub fn advance(&mut self) -> VajraResult<(Zeroizing<[u8; KEY_LEN]>, u64)> {
        // Check for overflow
        if self.packet_counter >= u64::MAX - COUNTER_OVERFLOW_MARGIN {
            return Err(VajraError::PacketCounterOverflow);
        }

        let current_counter = self.packet_counter;
        self.packet_counter += 1;

        // Determine if we need to ratchet
        let should_ratchet = match self.config.mode {
            RatchetMode::PerPacket => true,
            RatchetMode::PerSession { packets_per_rotation } => {
                packets_per_rotation > 0 && current_counter > 0 && current_counter % packets_per_rotation == 0
            }
        };

        if should_ratchet {
            self.ratchet_step()?;
        }

        // Return a copy of the current key for encryption
        Ok((Zeroizing::new(*self.current_key), current_counter))
    }

    /// Perform one ratchet step: derive the next key and zero the old one.
    ///
    /// # Key Derivation
    /// ```text
    /// next_key = HKDF(
    ///     ikm:  current_key,
    ///     info: "VAJRA_RATCHET_v1" || session_id || session_counter.to_be_bytes(),
    ///     len:  32
    /// )
    /// ```
    fn ratchet_step(&mut self) -> VajraResult<()> {
        self.session_counter += 1;

        // Build info: "VAJRA_RATCHET_v1" (16) + session_id (16) + counter (8) = 40 bytes
        let mut info = [0u8; 16 + 16 + 8];
        info[..16].copy_from_slice(b"VAJRA_RATCHET_v1");
        info[16..32].copy_from_slice(&self.config.session_id);
        info[32..40].copy_from_slice(&self.session_counter.to_be_bytes());

        // Derive new key — old key in ikm will be consumed
        let new_key = primitives::hkdf_derive(&*self.current_key, None, &info)?;

        // Replace current key — Zeroizing drops (and zeroes) the old value
        self.current_key = Zeroizing::new(*new_key);

        Ok(())
    }

    /// Validate that an incoming packet counter is not behind our state.
    ///
    /// # Security Invariant
    /// Prevents replay attacks — once a counter is seen, lower values are rejected.
    pub fn validate_counter(&self, incoming: u64) -> VajraResult<()> {
        if incoming < self.packet_counter {
            return Err(VajraError::OutOfOrderPacket {
                expected: self.packet_counter,
                got: incoming,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    fn test_config(mode: RatchetMode) -> RatchetConfig {
        let mut session_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut session_id);
        RatchetConfig { mode, session_id }
    }

    fn random_key() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn per_packet_produces_different_keys() {
        let initial = random_key();
        let config = test_config(RatchetMode::PerPacket);
        let mut ratchet = LivingRatchet::new(initial, config);

        let (k0, c0) = ratchet.advance().unwrap();
        let (k1, c1) = ratchet.advance().unwrap();
        let (k2, c2) = ratchet.advance().unwrap();

        // Counters increment
        assert_eq!(c0, 0);
        assert_eq!(c1, 1);
        assert_eq!(c2, 2);

        // Keys differ after ratchet (k0 is used before first ratchet,
        // k1 after first ratchet, k2 after second)
        assert_ne!(*k1, *k0);
        assert_ne!(*k2, *k1);
        assert_ne!(*k2, *k0);
    }

    #[test]
    fn per_session_keeps_key_within_window() {
        let initial = random_key();
        let config = test_config(RatchetMode::PerSession {
            packets_per_rotation: 3,
        });
        let mut ratchet = LivingRatchet::new(initial, config);

        // Packets 0, 1, 2 — no rotation yet (rotation happens at counter 3)
        let (k0, _) = ratchet.advance().unwrap(); // counter 0
        let (k1, _) = ratchet.advance().unwrap(); // counter 1
        let (k2, _) = ratchet.advance().unwrap(); // counter 2

        // Key should be the same for first 3 packets (no rotation triggered)
        assert_eq!(*k0, *k1);
        assert_eq!(*k1, *k2);

        // Packet 3 triggers rotation
        let (k3, _) = ratchet.advance().unwrap(); // counter 3, triggers ratchet
        assert_ne!(*k3, *k0);

        // Session counter should have incremented
        assert_eq!(ratchet.session_counter(), 1);
    }

    #[test]
    fn counter_overflow_returns_error() {
        let initial = random_key();
        let config = test_config(RatchetMode::PerPacket);
        let mut ratchet = LivingRatchet::new(initial, config);

        // Manually set counter near max
        ratchet.packet_counter = u64::MAX - COUNTER_OVERFLOW_MARGIN;

        let result = ratchet.advance();
        assert!(matches!(result, Err(VajraError::PacketCounterOverflow)));
    }

    #[test]
    fn out_of_order_packet_rejected() {
        let initial = random_key();
        let config = test_config(RatchetMode::PerPacket);
        let mut ratchet = LivingRatchet::new(initial, config);

        // Advance to packet 5
        for _ in 0..5 {
            ratchet.advance().unwrap();
        }

        // Packet counter 3 < current 5 → rejected
        let result = ratchet.validate_counter(3);
        assert!(matches!(
            result,
            Err(VajraError::OutOfOrderPacket {
                expected: 5,
                got: 3
            })
        ));

        // Packet counter 5 = current → accepted
        assert!(ratchet.validate_counter(5).is_ok());

        // Packet counter 10 > current → accepted
        assert!(ratchet.validate_counter(10).is_ok());
    }

    #[test]
    fn deterministic_with_same_inputs() {
        let initial = [42u8; KEY_LEN];
        let session_id = [7u8; 16];
        let config1 = RatchetConfig {
            mode: RatchetMode::PerPacket,
            session_id,
        };
        let config2 = RatchetConfig {
            mode: RatchetMode::PerPacket,
            session_id,
        };

        let mut r1 = LivingRatchet::new(initial, config1);
        let mut r2 = LivingRatchet::new(initial, config2);

        for _ in 0..10 {
            let (k1, c1) = r1.advance().unwrap();
            let (k2, c2) = r2.advance().unwrap();
            assert_eq!(*k1, *k2);
            assert_eq!(c1, c2);
        }
    }

    #[test]
    fn different_session_id_different_keys() {
        let initial = [42u8; KEY_LEN];
        let config1 = RatchetConfig {
            mode: RatchetMode::PerPacket,
            session_id: [1u8; 16],
        };
        let config2 = RatchetConfig {
            mode: RatchetMode::PerPacket,
            session_id: [2u8; 16],
        };

        let mut r1 = LivingRatchet::new(initial, config1);
        let mut r2 = LivingRatchet::new(initial, config2);

        // First packet: PerPacket ratchets immediately,
        // session_id is mixed into HKDF info, so keys already diverge.
        let (k1_0, _) = r1.advance().unwrap();
        let (k2_0, _) = r2.advance().unwrap();
        assert_ne!(*k1_0, *k2_0); // different session_id → different key after ratchet

        // Second advance: still diverged
        let (k1_1, _) = r1.advance().unwrap();
        let (k2_1, _) = r2.advance().unwrap();
        assert_ne!(*k1_1, *k2_1);
    }
}
