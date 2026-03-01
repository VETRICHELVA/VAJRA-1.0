//! Breach Canary — real-time integrity monitoring.
//!
//! Monitors traffic for:
//! 1. **HMAC proof chain**: Chained HMAC across packets — any modification breaks the chain.
//! 2. **Timing anomaly**: Welford's online algorithm detects inter-packet timing deviations.
//! 3. **Entropy monitoring**: Tracks entropy of traffic patterns for covert channel detection.
//!
//! On breach detection, emits a `BreachAlert` and can trigger automated session kill.

use crossbeam_channel::Sender;
use zeroize::Zeroizing;

use crate::crypto::primitives::{self, HMAC_LEN, KEY_LEN};
use crate::error::{VajraError, VajraResult};

// ── Welford's Online Algorithm ──────────────────────────────────

/// Online mean/variance tracker using Welford's algorithm.
/// O(1) per update, no allocation, no history buffer.
#[derive(Debug, Clone)]
pub struct WelfordState {
    count: u64,
    mean: f64,
    m2: f64, // sum of squared deviations
}

impl WelfordState {
    /// Create a new empty Welford state.
    pub fn new() -> Self {
        Self {
            count: 0,
            mean: 0.0,
            m2: 0.0,
        }
    }

    /// Update with a new observation value.
    #[inline]
    pub fn update(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
    }

    /// Compute sample standard deviation.
    #[inline]
    pub fn std_dev(&self) -> f64 {
        if self.count < 2 {
            return 0.0;
        }
        (self.m2 / (self.count - 1) as f64).sqrt()
    }

    /// Compute z-score for a given value relative to the running distribution.
    #[inline]
    pub fn z_score(&self, value: f64) -> f64 {
        let std = self.std_dev();
        if std == 0.0 {
            return 0.0;
        }
        (value - self.mean).abs() / std
    }

    /// Get the running mean.
    #[inline]
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Get the number of observations.
    #[inline]
    pub fn count(&self) -> u64 {
        self.count
    }
}

impl Default for WelfordState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Entropy Tracker ─────────────────────────────────────────────

/// Tracks byte-frequency entropy of traffic patterns.
#[derive(Debug, Clone)]
pub struct EntropyTracker {
    /// Frequency count for each byte value (0..255).
    freq: [u64; 256],
    /// Total bytes observed.
    total: u64,
    /// Baseline entropy (set after warmup).
    baseline: Option<f64>,
    /// Number of bytes needed before baseline is established.
    warmup_bytes: u64,
}

impl EntropyTracker {
    /// Create a new entropy tracker.
    ///
    /// `warmup_bytes`: how many bytes to observe before establishing baseline.
    pub fn new(warmup_bytes: u64) -> Self {
        Self {
            freq: [0u64; 256],
            total: 0,
            baseline: None,
            warmup_bytes,
        }
    }

    /// Feed packet data into the entropy tracker.
    pub fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.freq[b as usize] += 1;
        }
        self.total += data.len() as u64;

        // Establish baseline after warmup
        if self.baseline.is_none() && self.total >= self.warmup_bytes {
            self.baseline = Some(self.current_entropy());
        }
    }

    /// Compute Shannon entropy of observed byte distribution (in bits).
    pub fn current_entropy(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let total = self.total as f64;
        let mut entropy = 0.0;
        for &count in &self.freq {
            if count > 0 {
                let p = count as f64 / total;
                entropy -= p * p.log2();
            }
        }
        entropy
    }

    /// Check if entropy has dropped significantly from baseline.
    /// Returns `Some(bits_dropped)` if anomalous, `None` if normal.
    pub fn check_anomaly(&self, threshold_bits: f64) -> Option<f64> {
        if let Some(baseline) = self.baseline {
            let current = self.current_entropy();
            let drop = baseline - current;
            if drop > threshold_bits {
                return Some(drop);
            }
        }
        None
    }
}

// ── Breach Alert ────────────────────────────────────────────────

/// Alert types emitted by the Breach Canary.
#[derive(Debug, Clone)]
pub enum BreachAlert {
    /// Inter-packet timing exceeded sigma threshold.
    TimingAnomaly { packet_id: u64, sigma: f64 },
    /// HMAC proof chain verification failed.
    ProofChainBroken { packet_id: u64 },
    /// Traffic entropy dropped below baseline.
    EntropyDrop { bits_dropped: f64 },
    /// Multiple detection methods triggered simultaneously.
    MultiMethodBreach { methods: Vec<String> },
}

// ── Breach Canary ───────────────────────────────────────────────

/// Real-time integrity monitor for VAJRA sessions.
///
/// # Proof Chain
/// ```text
/// proof_chain_0 = HMAC(canary_key, session_id)
/// proof_chain_N = HMAC(canary_key, proof_chain_{N-1} || SHA256(packet_data))
/// ```
pub struct BreachCanary {
    hmac_key: Zeroizing<[u8; KEY_LEN]>,
    proof_chain: [u8; HMAC_LEN],
    packet_count: u64,
    timing: WelfordState,
    entropy: EntropyTracker,
    sigma_threshold: f64,
    entropy_threshold_bits: f64,
    alert_tx: Option<Sender<BreachAlert>>,
}

/// Canary token attached to each packet header.
#[derive(Debug, Clone)]
pub struct CanaryToken {
    /// Current proof chain value.
    pub proof_chain: [u8; HMAC_LEN],
    /// Packet ID for this token.
    pub packet_id: u64,
}

impl BreachCanary {
    /// Create a new Breach Canary for a session.
    ///
    /// # Parameters
    /// - `hmac_key`: 32-byte key for proof chain computation.
    /// - `session_id`: unique session identifier.
    /// - `sigma_threshold`: z-score threshold for timing anomaly detection (default: 3.0).
    /// - `alert_tx`: optional channel to send alerts to a monitoring system.
    pub fn new(
        hmac_key: [u8; KEY_LEN],
        session_id: &[u8],
        sigma_threshold: f64,
        entropy_threshold_bits: f64,
        alert_tx: Option<Sender<BreachAlert>>,
    ) -> Self {
        // proof_chain_0 = HMAC(canary_key, session_id)
        let proof_chain = primitives::hmac_compute(&hmac_key, session_id);

        Self {
            hmac_key: Zeroizing::new(hmac_key),
            proof_chain,
            packet_count: 0,
            timing: WelfordState::new(),
            entropy: EntropyTracker::new(10_000), // 10KB warmup
            sigma_threshold,
            entropy_threshold_bits,
            alert_tx,
        }
    }

    /// Stamp a packet: update proof chain and return the canary token.
    ///
    /// # Proof Chain Update
    /// ```text
    /// data_hash = SHA256(packet_data)
    /// proof_chain_N = HMAC(key, proof_chain_{N-1} || data_hash)
    /// ```
    pub fn stamp(&mut self, packet_data: &[u8]) -> CanaryToken {
        use sha2::{Digest, Sha256};

        let data_hash = Sha256::digest(packet_data);

        // proof_chain_N = HMAC(key, proof_chain_{N-1} || data_hash)
        let mut hmac_input = Vec::with_capacity(HMAC_LEN + 32);
        hmac_input.extend_from_slice(&self.proof_chain);
        hmac_input.extend_from_slice(&data_hash);

        self.proof_chain = primitives::hmac_compute(&self.hmac_key, &hmac_input);
        self.packet_count += 1;

        // Update entropy tracker
        self.entropy.update(packet_data);

        CanaryToken {
            proof_chain: self.proof_chain,
            packet_id: self.packet_count,
        }
    }

    /// Verify a received packet's canary token.
    ///
    /// The receiver maintains their own proof chain and compares.
    /// Returns `Ok(())` if valid, `Err(ProofChainBroken)` if mismatch.
    pub fn verify(&self, token: &CanaryToken) -> VajraResult<()> {
        if !primitives::hmac_verify(
            &[0u8; KEY_LEN], // placeholder — in practice, the receiver
            // recomputes and compares its own chain
            &[],
            &[0u8; HMAC_LEN],
        ) {
            // This is a simplified check — real verification is done by
            // comparing sender's proof_chain with receiver's computed chain
        }

        // In a real system, both sides maintain the chain and compare
        if self.proof_chain != token.proof_chain {
            return Err(VajraError::ProofChainBroken {
                packet_id: token.packet_id,
            });
        }
        Ok(())
    }

    /// Record an inter-packet timing observation and check for anomalies.
    ///
    /// # Parameters
    /// - `interval_ms`: time since last packet in milliseconds.
    ///
    /// # Returns
    /// `Some(BreachAlert)` if timing anomaly detected, `None` otherwise.
    pub fn record_timing(&mut self, interval_ms: f64) -> Option<BreachAlert> {
        self.timing.update(interval_ms);

        // Need at least 10 observations for meaningful statistics
        if self.timing.count() < 10 {
            return None;
        }

        let z = self.timing.z_score(interval_ms);
        if z > self.sigma_threshold {
            let alert = BreachAlert::TimingAnomaly {
                packet_id: self.packet_count,
                sigma: z,
            };

            // Send alert if channel is available
            if let Some(tx) = &self.alert_tx {
                let _ = tx.try_send(alert.clone());
            }

            return Some(alert);
        }

        None
    }

    /// Check for entropy anomalies in traffic patterns.
    pub fn check_entropy(&self) -> Option<BreachAlert> {
        if let Some(drop) = self.entropy.check_anomaly(self.entropy_threshold_bits) {
            let alert = BreachAlert::EntropyDrop {
                bits_dropped: drop,
            };
            if let Some(tx) = &self.alert_tx {
                let _ = tx.try_send(alert.clone());
            }
            return Some(alert);
        }
        None
    }

    /// Get the current proof chain value.
    pub fn current_proof_chain(&self) -> &[u8; HMAC_LEN] {
        &self.proof_chain
    }

    /// Get the current packet count.
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    /// Get a reference to the timing state for inspection.
    pub fn timing_state(&self) -> &WelfordState {
        &self.timing
    }
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

    // ── Welford tests ───────────────────────────────────────────

    #[test]
    fn welford_basic() {
        let mut w = WelfordState::new();
        // Known dataset: [2, 4, 4, 4, 5, 5, 7, 9]
        // Mean = 5.0, Variance = 4.571, StdDev ≈ 2.138
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            w.update(v);
        }
        assert!((w.mean() - 5.0).abs() < 1e-10);
        assert!((w.std_dev() - 2.138).abs() < 0.01);
    }

    #[test]
    fn welford_z_score() {
        let mut w = WelfordState::new();
        for v in [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.1] {
            w.update(v);
        }
        // A value of 20.0 should have a very high z-score
        let z = w.z_score(20.0);
        assert!(z > 10.0, "z-score should be very high, got {z}");
    }

    #[test]
    fn welford_single_value() {
        let mut w = WelfordState::new();
        w.update(5.0);
        assert_eq!(w.std_dev(), 0.0);
        assert_eq!(w.z_score(5.0), 0.0);
    }

    // ── Entropy tracker tests ───────────────────────────────────

    #[test]
    fn entropy_random_data_near_8_bits() {
        let mut tracker = EntropyTracker::new(0);
        // Feed in uniformly random data
        let mut rng = rand::thread_rng();
        let mut data = vec![0u8; 100_000];
        rng.fill_bytes(&mut data);
        tracker.update(&data);

        let entropy = tracker.current_entropy();
        // Random data should have entropy close to 8 bits
        assert!(
            entropy > 7.9,
            "Random data entropy should be near 8.0, got {entropy}"
        );
    }

    #[test]
    fn entropy_constant_data_zero_bits() {
        let mut tracker = EntropyTracker::new(0);
        let data = vec![0x42u8; 10_000];
        tracker.update(&data);

        let entropy = tracker.current_entropy();
        assert!(
            entropy < 0.01,
            "Constant data should have near-zero entropy, got {entropy}"
        );
    }

    // ── Proof chain tests ───────────────────────────────────────

    #[test]
    fn proof_chain_changes_per_packet() {
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"session-1", 3.0, 0.5, None);

        let t1 = canary.stamp(b"packet-1");
        let t2 = canary.stamp(b"packet-2");
        let t3 = canary.stamp(b"packet-3");

        assert_ne!(t1.proof_chain, t2.proof_chain);
        assert_ne!(t2.proof_chain, t3.proof_chain);
        assert_ne!(t1.proof_chain, t3.proof_chain);
    }

    #[test]
    fn proof_chain_deterministic() {
        let key = [99u8; KEY_LEN];
        let session = b"deterministic-session";

        let mut c1 = BreachCanary::new(key, session, 3.0, 0.5, None);
        let mut c2 = BreachCanary::new(key, session, 3.0, 0.5, None);

        let packets = [b"pkt-a".as_slice(), b"pkt-b", b"pkt-c"];
        for pkt in &packets {
            let t1 = c1.stamp(pkt);
            let t2 = c2.stamp(pkt);
            assert_eq!(t1.proof_chain, t2.proof_chain);
            assert_eq!(t1.packet_id, t2.packet_id);
        }
    }

    #[test]
    fn proof_chain_different_data_different_chain() {
        let key = random_key();
        let mut c1 = BreachCanary::new(key, b"session", 3.0, 0.5, None);
        let mut c2 = BreachCanary::new(key, b"session", 3.0, 0.5, None);

        let t1 = c1.stamp(b"legitimate-packet");
        let t2 = c2.stamp(b"tampered-packet!");

        assert_ne!(t1.proof_chain, t2.proof_chain);
    }

    // ── Timing anomaly tests ────────────────────────────────────

    #[test]
    fn timing_no_alert_normal_traffic() {
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"session", 3.0, 0.5, None);

        // Feed normal-ish timing: ~10ms ± small jitter
        for i in 0..100 {
            let interval = 10.0 + (i as f64 % 3.0) * 0.1;
            let alert = canary.record_timing(interval);
            assert!(alert.is_none(), "False positive at interval {interval}");
        }
    }

    #[test]
    fn timing_alert_on_anomaly() {
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"session", 3.0, 0.5, None);

        // Establish baseline: ~10ms intervals
        for _ in 0..100 {
            canary.record_timing(10.0);
        }

        // Inject 50ms spike (should be well above 3-sigma)
        let alert = canary.record_timing(60.0);
        assert!(
            alert.is_some(),
            "Should detect 50ms spike as timing anomaly"
        );

        if let Some(BreachAlert::TimingAnomaly { sigma, .. }) = alert {
            assert!(sigma > 3.0, "Sigma should exceed threshold, got {sigma}");
        }
    }

    // ── Alert channel tests ─────────────────────────────────────

    #[test]
    fn alert_sent_to_channel() {
        let (tx, rx) = crossbeam_channel::bounded(10);
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"session", 3.0, 0.5, Some(tx));

        // Establish baseline
        for _ in 0..100 {
            canary.record_timing(10.0);
        }

        // Trigger anomaly
        canary.record_timing(100.0);

        // Should receive alert on channel
        let alert = rx.try_recv();
        assert!(alert.is_ok(), "Alert should be sent to channel");
    }
}
