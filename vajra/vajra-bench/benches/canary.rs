//! Benchmark: Breach Canary (proof chain + timing).

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use rand::RngCore;
use std::time::Duration;
use vajra_core::crypto::canary::BreachCanary;

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

fn bench_canary_stamp(c: &mut Criterion) {
    let mut group = c.benchmark_group("canary_stamp");

    group.throughput(Throughput::Bytes(1500));
    group.bench_function("1500B", |b| {
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"bench-session", 3.0, 0.5, None);
        let packet = vec![0xABu8; 1500];

        b.iter(|| black_box(canary.stamp(black_box(&packet))));
    });
    group.finish();
}

fn bench_canary_timing_check(c: &mut Criterion) {
    c.bench_function("canary_timing_record", |b| {
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"bench-session", 3.0, 0.5, None);

        // Establish baseline
        for i in 0..100 {
            canary.record_timing(10.0 + (i as f64 % 3.0) * 0.1);
        }

        b.iter(|| black_box(canary.record_timing(black_box(10.1))));
    });
}

fn bench_canary_full_packet(c: &mut Criterion) {
    let mut group = c.benchmark_group("canary_full_packet");

    group.throughput(Throughput::Bytes(1500));
    group.bench_function("stamp_and_timing_1500B", |b| {
        let key = random_key();
        let mut canary = BreachCanary::new(key, b"bench-session", 3.0, 0.5, None);
        let packet = vec![0xABu8; 1500];

        // Warmup timing
        for _ in 0..50 {
            canary.record_timing(10.0);
        }

        b.iter(|| {
            let token = canary.stamp(black_box(&packet));
            let alert = canary.record_timing(black_box(10.0));
            black_box((token, alert));
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = configure();
    targets = bench_canary_stamp,
              bench_canary_timing_check,
              bench_canary_full_packet
}
criterion_main!(benches);
