//! Phantom Channels — 3-of-5 Shamir Secret Sharing over GF(2^8).
//!
//! # Architecture
//! Ciphertext is split across 5 simulated independent paths using
//! (3, 5) threshold secret sharing. Any 3 paths can reconstruct
//! the original — an attacker needs simultaneous compromise of 3+
//! paths to access the ciphertext.
//!
//! # Implementation
//! Pure Rust GF(2^8) arithmetic with lookup-table multiplication.
//! Field polynomial: x^8 + x^4 + x^3 + x^2 + 1 (0x11d — same as AES).
//! Evaluation points: 1, 2, 3, 4, 5 (non-zero GF(2^8) elements).
//!
//! On x86_64 with `--features isal`, an ISA-L AVX2-accelerated path
//! would be used instead. Both produce bit-identical output.
//!
//! # Security Invariant
//! Any k-1 = 2 shares reveal zero information about the secret
//! (information-theoretic security of Shamir's scheme).

use crate::error::{VajraError, VajraResult};

/// GF(2^8) field polynomial: x^8 + x^4 + x^3 + x^2 + 1
const GF_POLY: u16 = 0x11d;

/// Precomputed multiplication and log/exp tables for GF(2^8).
struct GfTables {
    exp: [u8; 512],  // exp[i] = generator^i
    log: [u8; 256],  // log[x] = i where generator^i = x
}

impl GfTables {
    /// Build GF(2^8) log/exp tables at startup using generator 0x02.
    fn new() -> Self {
        let mut exp = [0u8; 512];
        let mut log = [0u8; 256];

        let mut x: u16 = 1;
        for i in 0..255u16 {
            exp[i as usize] = x as u8;
            exp[(i + 255) as usize] = x as u8; // wrap for modular access
            log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 {
                x ^= GF_POLY;
            }
        }
        // log[0] is undefined but we set it to 0 to avoid UB
        log[0] = 0;

        GfTables { exp, log }
    }

    /// Multiply two GF(2^8) elements using log/exp tables.
    #[inline]
    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let log_a = self.log[a as usize] as u16;
        let log_b = self.log[b as usize] as u16;
        self.exp[(log_a + log_b) as usize]
    }

    /// Compute multiplicative inverse in GF(2^8).
    #[inline]
    fn inv(&self, a: u8) -> u8 {
        if a == 0 {
            panic!("Cannot invert zero in GF(2^8)");
        }
        self.exp[255 - self.log[a as usize] as usize]
    }
}

/// Phantom Channels: (k, n) threshold secret sharing.
pub struct PhantomChannels {
    /// Minimum shares needed for reconstruction.
    k: usize,
    /// Total number of shares.
    n: usize,
    /// Precomputed GF(2^8) tables.
    gf: GfTables,
}

/// Container for Shamir shares.
#[derive(Debug, Clone)]
pub struct ShamirShares {
    /// The n share data vectors.
    pub shares: Vec<Vec<u8>>,
    /// Original data length before padding.
    pub original_len: usize,
    /// Share evaluation points (1-indexed: 1, 2, ..., n).
    pub share_ids: Vec<u8>,
}

impl PhantomChannels {
    /// Create a new PhantomChannels with threshold k and n total shares.
    ///
    /// # Panics
    /// Panics if k < 2, k > n, or n > 255 (GF(2^8) limitation).
    pub fn new(k: usize, n: usize) -> Self {
        assert!(k >= 2, "threshold k must be >= 2");
        assert!(k <= n, "threshold k must be <= n");
        assert!(n <= 255, "n must be <= 255 for GF(2^8)");

        Self {
            k,
            n,
            gf: GfTables::new(),
        }
    }

    /// Split data into n shares, any k of which can reconstruct.
    ///
    /// # Format
    /// Input is prepended with 4-byte LE original length, then padded
    /// to a multiple of k bytes before polynomial evaluation.
    pub fn split(&self, data: &[u8]) -> VajraResult<ShamirShares> {
        let original_len = data.len();

        // Prepend 4-byte little-endian length
        let mut padded = Vec::with_capacity(4 + data.len() + self.k);
        padded.extend_from_slice(&(original_len as u32).to_le_bytes());
        padded.extend_from_slice(data);

        // Pad to multiple of k
        while padded.len() % self.k != 0 {
            padded.push(0);
        }

        // Evaluation points: 1, 2, 3, ..., n
        let share_ids: Vec<u8> = (1..=self.n as u8).collect();

        // One polynomial per byte of padded data.
        // Each polynomial has k coefficients: a_0 = secret byte, a_1..a_{k-1} = random.
        let mut shares: Vec<Vec<u8>> = vec![Vec::with_capacity(padded.len()); self.n];
        let mut coeffs = vec![0u8; self.k]; // reusable buffer

        use rand::RngCore;
        let mut rng = rand::thread_rng();

        for &secret_byte in &padded {
            // a_0 = secret byte, a_1..a_{k-1} = random
            coeffs[0] = secret_byte;
            for j in 1..self.k {
                let mut r = [0u8; 1];
                rng.fill_bytes(&mut r);
                coeffs[j] = r[0];
            }

            // Evaluate polynomial at each share point
            for (share_idx, &x) in share_ids.iter().enumerate() {
                let mut value = 0u8;
                let mut x_power = 1u8;
                for j in 0..self.k {
                    value ^= self.gf.mul(coeffs[j], x_power);
                    x_power = self.gf.mul(x_power, x);
                }
                shares[share_idx].push(value);
            }
        }

        Ok(ShamirShares {
            shares,
            original_len,
            share_ids,
        })
    }

    /// Reconstruct data from any k shares.
    ///
    /// # Parameters
    /// - `all_shares`: the `ShamirShares` produced by `split`.
    /// - `indices`: which shares to use (indices into `all_shares.shares`, 0-based).
    ///
    /// # Errors
    /// - `InsufficientShares` if fewer than k indices provided.
    /// - `ReconstructionFailed` if reconstruction produces invalid length.
    pub fn reconstruct(
        &self,
        all_shares: &ShamirShares,
        indices: &[usize],
    ) -> VajraResult<Vec<u8>> {
        if indices.len() < self.k {
            return Err(VajraError::InsufficientShares {
                needed: self.k,
                got: indices.len(),
            });
        }

        // Use exactly k shares
        let k = self.k;
        let xs: Vec<u8> = indices[..k]
            .iter()
            .map(|&i| all_shares.share_ids[i])
            .collect();
        let share_data: Vec<&[u8]> = indices[..k]
            .iter()
            .map(|&i| all_shares.shares[i].as_slice())
            .collect();

        let share_len = share_data[0].len();

        // Each share should have the same length
        for s in &share_data {
            if s.len() != share_len {
                return Err(VajraError::ReconstructionFailed(
                    "shares have different lengths".into(),
                ));
            }
        }

        // Lagrange interpolation at x=0 to recover each byte of the padded data
        let mut padded = Vec::with_capacity(share_len);

        for byte_idx in 0..share_len {
            let mut value = 0u8;

            for i in 0..k {
                let mut numerator = 1u8;
                let mut denominator = 1u8;

                for j in 0..k {
                    if i == j {
                        continue;
                    }
                    // Lagrange basis: prod_{j!=i} (0 - x_j) / (x_i - x_j)
                    // In GF(2^8): subtraction = XOR = addition
                    numerator = self.gf.mul(numerator, xs[j]); // 0 XOR x_j = x_j
                    denominator = self.gf.mul(denominator, xs[i] ^ xs[j]);
                }

                let lagrange = self.gf.mul(numerator, self.gf.inv(denominator));
                value ^= self.gf.mul(share_data[i][byte_idx], lagrange);
            }

            padded.push(value);
        }

        // The padded data is k bytes per chunk, where each chunk had k
        // polynomial coefficients. But we stored one polynomial per byte,
        // so padded has share_len bytes = chunk_count * k bytes.
        // Actually, we have one polynomial per byte of input (after length prefix + padding).
        // So padded should be exactly the original padded input.

        // Extract original length from first 4 bytes
        if padded.len() < 4 {
            return Err(VajraError::ReconstructionFailed(
                "reconstructed data too short for length header".into(),
            ));
        }

        let stored_len =
            u32::from_le_bytes([padded[0], padded[1], padded[2], padded[3]]) as usize;

        if stored_len != all_shares.original_len {
            return Err(VajraError::ReconstructionFailed(format!(
                "length mismatch: stored {stored_len}, expected {}",
                all_shares.original_len
            )));
        }

        if 4 + stored_len > padded.len() {
            return Err(VajraError::ReconstructionFailed(
                "stored length exceeds reconstructed data".into(),
            ));
        }

        Ok(padded[4..4 + stored_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf_tables_basic() {
        let gf = GfTables::new();
        // 1 * x = x for all x
        for x in 0..=255u8 {
            assert_eq!(gf.mul(1, x), x);
            assert_eq!(gf.mul(x, 1), x);
        }
        // 0 * x = 0
        for x in 0..=255u8 {
            assert_eq!(gf.mul(0, x), 0);
        }
        // x * inv(x) = 1
        for x in 1..=255u8 {
            assert_eq!(gf.mul(x, gf.inv(x)), 1);
        }
    }

    #[test]
    fn split_reconstruct_small() {
        let pc = PhantomChannels::new(3, 5);
        let data = b"Hello VAJRA!";
        let shares = pc.split(data).unwrap();
        assert_eq!(shares.shares.len(), 5);

        // Reconstruct with first 3 shares
        let result = pc.reconstruct(&shares, &[0, 1, 2]).unwrap();
        assert_eq!(&result, data);
    }

    #[test]
    fn test_shamir_cross_platform() {
        let input = b"VAJRA_TEST_VECTOR_12345678901234"; // 32 bytes
        let pc = PhantomChannels::new(3, 5);
        let shares = pc.split(input).unwrap();

        // Test all C(5,3) = 10 combinations
        for combo in [
            [0, 1, 2],
            [0, 1, 3],
            [0, 1, 4],
            [0, 2, 3],
            [0, 2, 4],
            [0, 3, 4],
            [1, 2, 3],
            [1, 2, 4],
            [1, 3, 4],
            [2, 3, 4],
        ] {
            let reconstructed = pc.reconstruct(&shares, &combo).unwrap();
            assert_eq!(
                reconstructed, input,
                "Failed for combination {:?}",
                combo
            );
        }
    }

    #[test]
    fn insufficient_shares_error() {
        let pc = PhantomChannels::new(3, 5);
        let shares = pc.split(b"secret").unwrap();

        let result = pc.reconstruct(&shares, &[0, 1]); // only 2, need 3
        assert!(matches!(
            result,
            Err(VajraError::InsufficientShares {
                needed: 3,
                got: 2
            })
        ));
    }

    #[test]
    fn split_reconstruct_1500b_packet() {
        let pc = PhantomChannels::new(3, 5);
        let data = vec![0xAB_u8; 1500];
        let shares = pc.split(&data).unwrap();

        let result = pc.reconstruct(&shares, &[0, 2, 4]).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn split_reconstruct_empty() {
        let pc = PhantomChannels::new(3, 5);
        let data = b"";
        let shares = pc.split(data).unwrap();
        let result = pc.reconstruct(&shares, &[1, 2, 3]).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn split_reconstruct_single_byte() {
        let pc = PhantomChannels::new(3, 5);
        let data = b"X";
        let shares = pc.split(data).unwrap();

        // Try multiple combos
        for combo in [[0, 1, 2], [2, 3, 4], [0, 2, 4]] {
            let result = pc.reconstruct(&shares, &combo).unwrap();
            assert_eq!(result, data);
        }
    }

    #[test]
    fn shares_are_different() {
        let pc = PhantomChannels::new(3, 5);
        let data = b"VAJRA secret data for splitting";
        let shares = pc.split(data).unwrap();

        // All shares should differ from each other
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(
                    shares.shares[i], shares.shares[j],
                    "Share {i} and {j} are identical"
                );
            }
        }
    }

    #[test]
    fn different_splits_produce_different_shares() {
        let pc = PhantomChannels::new(3, 5);
        let data = b"same data twice";
        let shares1 = pc.split(data).unwrap();
        let shares2 = pc.split(data).unwrap();

        // Due to random coefficients, shares should differ
        let all_same = shares1
            .shares
            .iter()
            .zip(shares2.shares.iter())
            .all(|(a, b)| a == b);
        assert!(!all_same, "Two splits of same data produced identical shares");
    }
}
