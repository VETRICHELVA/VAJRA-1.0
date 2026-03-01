//! Benchmark: Living Ratchet key evolution.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::RngCore;
use std::time::Duration;
use vajra_core::crypto::ratchet::{LivingRatchet, RatchetConfig, RatchetMode};

fn configure() -> Criterion {
    Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(10))
}

fn random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut key);
    key
}

fn random_session_id() -> [u8; 16] {
    let mut sid = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut sid);
    sid
}

fn bench_ratchet_per_packet(c: &mut Criterion) {
    c.bench_function("ratchet_per_packet_advance", |b| {
        let key = random_key();
        let config = RatchetConfig {
            mode: RatchetMode::PerPacket,
            session_id: random_session_id(),
        };
        let mut ratchet = LivingRatchet::new(key, config);

        b.iter(|| {
            black_box(ratchet.advance().unwrap());
        });
    });
}

fn bench_ratchet_per_session(c: &mut Criterion) {
    c.bench_function("ratchet_per_session_advance", |b| {
        let key = random_key();
        let config = RatchetConfig {
            mode: RatchetMode::PerSession {
                packets_per_rotation: 10_000,
            },
            session_id: random_session_id(),
        };
        let mut ratchet = LivingRatchet::new(key, config);

        b.iter(|| {
            black_box(ratchet.advance().unwrap());
        });
    });
}

fn bench_ratchet_rotation(c: &mut Criterion) {
    // Measure just the rotation cost (HKDF derivation)
    c.bench_function("ratchet_rotation_step", |b| {
        let key = random_key();
        let config = RatchetConfig {
            mode: RatchetMode::PerSession {
                packets_per_rotation: 1, // rotate every packet
            },
            session_id: random_session_id(),
        };

        b.iter_custom(|iters| {
            let mut ratchet = LivingRatchet::new(key, config.clone());
            let start = std::time::Instant::now();
            for _ in 0..iters {
                let _ = black_box(ratchet.advance().unwrap());
            }
            start.elapsed()
        });
    });
}

criterion_group! {
    name = benches;
    config = configure();
    targets = bench_ratchet_per_packet,
              bench_ratchet_per_session,
              bench_ratchet_rotation
}
criterion_main!(benches);
