//! Full-stack benchmark: Encrypt → Ratchet → Shamir → Canary pipeline.
//!
//! This is the most important benchmark for the iDEX application.
//! It measures the complete per-packet cryptographic pipeline throughput.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use rand::RngCore;
use std::time::Duration;

use vajra_core::crypto::canary::BreachCanary;
use vajra_core::crypto::primitives;
use vajra_core::crypto::ratchet::{LivingRatchet, RatchetConfig, RatchetMode};
use vajra_core::crypto::shamir::PhantomChannels;

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

/// Full VAJRA pipeline: ratchet → encrypt → shamir split → canary stamp.
/// Returns the 5 shares + canary token.
fn full_pipeline_process(
    ratchet: &mut LivingRatchet,
    phantom: &PhantomChannels,
    canary: &mut BreachCanary,
    plaintext: &[u8],
) -> Vec<Vec<u8>> {
    // 1. Ratchet: get current key and advance
    let (key, counter) = ratchet.advance().unwrap();

    // 2. Derive nonce from key + counter
    let nonce = primitives::derive_nonce(&key, counter).unwrap();

    // 3. AES-GCM encrypt with AAD containing counter
    let aad = counter.to_be_bytes();
    let ciphertext = primitives::aes_gcm_encrypt(&key, &nonce, plaintext, &aad).unwrap();

    // 4. Shamir split the ciphertext into 5 shares
    let shares = phantom.split(&ciphertext).unwrap();

    // 5. Canary stamp the original ciphertext
    let _token = canary.stamp(&ciphertext);

    shares.shares
}

fn bench_full_stack(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_stack");

    for size in [512, 1024, 1500, 4096, 9000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt_ratchet_shamir_canary", size),
            size,
            |b, &size| {
                let key = random_key();
                let mut session_id = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut session_id);

                let config = RatchetConfig {
                    mode: RatchetMode::PerSession {
                        packets_per_rotation: 10_000,
                    },
                    session_id,
                };
                let mut ratchet = LivingRatchet::new(key, config);
                let phantom = PhantomChannels::new(3, 5);
                let mut canary = BreachCanary::new(random_key(), &session_id, 3.0, 0.5, None);
                let plaintext = vec![0xABu8; size];

                b.iter(|| {
                    black_box(full_pipeline_process(
                        &mut ratchet,
                        &phantom,
                        &mut canary,
                        black_box(&plaintext),
                    ))
                });
            },
        );
    }
    group.finish();
}

fn bench_full_stack_sovereign(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_stack_sovereign");

    for size in [1500].iter() {
        group.throughput(Throughput::Bytes(*size as u64));

        group.bench_with_input(
            BenchmarkId::new("per_packet_ratchet", size),
            size,
            |b, &size| {
                let key = random_key();
                let mut session_id = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut session_id);

                let config = RatchetConfig {
                    mode: RatchetMode::PerPacket, // sovereign mode
                    session_id,
                };
                let mut ratchet = LivingRatchet::new(key, config);
                let phantom = PhantomChannels::new(3, 5);
                let mut canary = BreachCanary::new(random_key(), &session_id, 3.0, 0.5, None);
                let plaintext = vec![0xABu8; size];

                b.iter(|| {
                    black_box(full_pipeline_process(
                        &mut ratchet,
                        &phantom,
                        &mut canary,
                        black_box(&plaintext),
                    ))
                });
            },
        );
    }
    group.finish();
}

criterion_group! {
    name = benches;
    config = configure();
    targets = bench_full_stack,
              bench_full_stack_sovereign
}
criterion_main!(benches);
