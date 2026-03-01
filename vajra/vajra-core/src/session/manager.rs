//! Session manager — tracks active sessions.

use std::collections::HashMap;
use zeroize::Zeroizing;

use crate::crypto::canary::BreachCanary;
use crate::crypto::primitives::KEY_LEN;
use crate::crypto::ratchet::{LivingRatchet, RatchetConfig, RatchetMode};
use crate::error::{VajraError, VajraResult};

/// A live VAJRA session containing all cryptographic state.
pub struct VajraSession {
    pub session_id: [u8; 16],
    pub ratchet: LivingRatchet,
    pub canary: BreachCanary,
    pub created_at: std::time::Instant,
}

/// Manages the table of active sessions.
pub struct SessionManager {
    sessions: HashMap<u128, VajraSession>,
    default_mode: RatchetMode,
}

impl SessionManager {
    /// Create a new session manager.
    pub fn new(default_mode: RatchetMode) -> Self {
        Self {
            sessions: HashMap::new(),
            default_mode,
        }
    }

    /// Register a new session from a completed handshake.
    pub fn register(
        &mut self,
        session_id: [u8; 16],
        session_key: Zeroizing<[u8; KEY_LEN]>,
        canary_key: [u8; KEY_LEN],
    ) -> u128 {
        let id = u128::from_le_bytes(session_id);

        let config = RatchetConfig {
            mode: self.default_mode,
            session_id,
        };

        let ratchet = LivingRatchet::new(*session_key, config);
        let canary = BreachCanary::new(canary_key, &session_id, 3.0, 0.5, None);

        let session = VajraSession {
            session_id,
            ratchet,
            canary,
            created_at: std::time::Instant::now(),
        };

        self.sessions.insert(id, session);
        id
    }

    /// Look up a session by its numeric ID.
    pub fn get(&self, id: u128) -> VajraResult<&VajraSession> {
        self.sessions
            .get(&id)
            .ok_or(VajraError::SessionNotFound(id as u64))
    }

    /// Look up a mutable session by its numeric ID.
    pub fn get_mut(&mut self, id: u128) -> VajraResult<&mut VajraSession> {
        self.sessions
            .get_mut(&id)
            .ok_or(VajraError::SessionNotFound(id as u64))
    }

    /// Remove and destroy a session (key material zeroized on drop).
    pub fn remove(&mut self, id: u128) -> bool {
        self.sessions.remove(&id).is_some()
    }

    /// Number of active sessions.
    pub fn active_count(&self) -> usize {
        self.sessions.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn register_and_lookup() {
        let mut mgr = SessionManager::new(RatchetMode::default());
        let mut session_id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut session_id);
        let key = Zeroizing::new([42u8; KEY_LEN]);
        let canary_key = [7u8; KEY_LEN];

        let id = mgr.register(session_id, key, canary_key);
        assert_eq!(mgr.active_count(), 1);

        let session = mgr.get(id).unwrap();
        assert_eq!(session.session_id, session_id);
    }

    #[test]
    fn session_not_found() {
        let mgr = SessionManager::new(RatchetMode::default());
        assert!(mgr.get(12345).is_err());
    }

    #[test]
    fn remove_session() {
        let mut mgr = SessionManager::new(RatchetMode::default());
        let session_id = [1u8; 16];
        let key = Zeroizing::new([42u8; KEY_LEN]);

        let id = mgr.register(session_id, key, [0u8; KEY_LEN]);
        assert!(mgr.remove(id));
        assert_eq!(mgr.active_count(), 0);
        assert!(!mgr.remove(id)); // already removed
    }
}
