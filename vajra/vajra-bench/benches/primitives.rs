//! Benchmark: AES-256-GCM, HKDF-SHA256, HMAC-SHA256 primitives.

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use rand::RngCore;
use std::time::Duration;
use vajra_core::crypto::primitives;

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

fn bench_aes_gcm_encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_encrypt");

    for size in [512, 1024, 1500, 4096, 9000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let key = random_key();
            let nonce = primitives::derive_nonce(&key, 0).unwrap();
            let plaintext = vec![0xABu8; size];
            let aad = b"bench-aad";

            b.iter(|| {
                black_box(
                    primitives::aes_gcm_encrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&plaintext),
                        black_box(aad),
                    )
                    .unwrap(),
                )
            });
        });
    }
    group.finish();
}

fn bench_aes_gcm_decrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("aes_gcm_decrypt");

    for size in [512, 1024, 1500, 4096, 9000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let key = random_key();
            let nonce = primitives::derive_nonce(&key, 0).unwrap();
            let plaintext = vec![0xABu8; size];
            let ciphertext =
                primitives::aes_gcm_encrypt(&key, &nonce, &plaintext, b"bench-aad").unwrap();

            b.iter(|| {
                black_box(
                    primitives::aes_gcm_decrypt(
                        black_box(&key),
                        black_box(&nonce),
                        black_box(&ciphertext),
                        black_box(b"bench-aad"),
                    )
                    .unwrap(),
                )
            });
        });
    }
    group.finish();
}

fn bench_hkdf_derive(c: &mut Criterion) {
    let mut group = c.benchmark_group("hkdf_derive");

    group.bench_function("32B_key", |b| {
        let ikm = random_key();
        b.iter(|| {
            black_box(
                primitives::hkdf_derive(black_box(&ikm), None, black_box(b"bench-info")).unwrap(),
            )
        });
    });

    group.finish();
}

fn bench_hmac_compute(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_compute");

    for size in [512, 1024, 1500, 4096].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let key = random_key();
            let data = vec![0xCDu8; size];

            b.iter(|| black_box(primitives::hmac_compute(black_box(&key), black_box(&data))));
        });
    }
    group.finish();
}

fn bench_hmac_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("hmac_verify");

    group.throughput(Throughput::Bytes(1500));
    group.bench_function("1500B", |b| {
        let key = random_key();
        let data = vec![0xCDu8; 1500];
        let tag = primitives::hmac_compute(&key, &data);

        b.iter(|| {
            black_box(primitives::hmac_verify(
                black_box(&key),
                black_box(&data),
                black_box(&tag),
            ))
        });
    });

    group.finish();
}

criterion_group! {
    name = benches;
    config = configure();
    targets = bench_aes_gcm_encrypt,
              bench_aes_gcm_decrypt,
              bench_hkdf_derive,
              bench_hmac_compute,
              bench_hmac_verify
}
criterion_main!(benches);
