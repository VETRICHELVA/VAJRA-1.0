//! VAJRA Commercial — TLS 1.3 wrapper for commercial deployment.
//!
//! The commercial version uses standard TLS 1.3 as transport.
//! VAJRA innovations layered on top:
//! - Living Ratchet (per-session rotation)
//! - Breach Canary (timing + proof chain)
//! - NO Phantom Channels (paths not independent on commercial internet)

pub mod tls_wrapper;
