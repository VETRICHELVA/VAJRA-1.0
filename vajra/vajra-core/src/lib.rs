//! VAJRA Core — Quantum-safe multi-path secure transport library.
//!
//! This crate provides the cryptographic foundation for VAJRA:
//! - **Living Ratchet**: Per-session key evolution using HKDF-SHA256 over ML-KEM-768
//! - **Phantom Channels**: 3-of-5 Shamir Secret Sharing over GF(2^8)
//! - **Breach Canary**: Real-time integrity monitoring via HMAC proof chains

pub mod crypto;
pub mod error;
pub mod session;

pub use error::{VajraError, VajraResult};
