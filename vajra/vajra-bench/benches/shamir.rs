//! Benchmark: Shamir Secret Sharing (Phantom Channels).

use criterion::{
    black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput,
};
use rand::RngCore;
use std::time::Duration;
use vajra_core::crypto::shamir::PhantomChannels;

fn configure() -> Criterion {
    Criterion::default()
        .sample_size(100)
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(10))
}

fn bench_shamir_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_split_3of5");

    for size in [512, 1024, 1500, 4096, 9000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let pc = PhantomChannels::new(3, 5);
            let mut data = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut data);

            b.iter(|| black_box(pc.split(black_box(&data)).unwrap()));
        });
    }
    group.finish();
}

fn bench_shamir_reconstruct(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_reconstruct_3of5");

    for size in [512, 1024, 1500, 4096, 9000].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &size| {
            let pc = PhantomChannels::new(3, 5);
            let mut data = vec![0u8; size];
            rand::thread_rng().fill_bytes(&mut data);
            let shares = pc.split(&data).unwrap();

            b.iter(|| {
                black_box(
                    pc.reconstruct(black_box(&shares), black_box(&[0, 2, 4]))
                        .unwrap(),
                )
            });
        });
    }
    group.finish();
}

fn bench_shamir_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_roundtrip_3of5");

    group.throughput(Throughput::Bytes(1500));
    group.bench_function("1500B", |b| {
        let pc = PhantomChannels::new(3, 5);
        let mut data = vec![0u8; 1500];
        rand::thread_rng().fill_bytes(&mut data);

        b.iter(|| {
            let shares = pc.split(black_box(&data)).unwrap();
            black_box(pc.reconstruct(&shares, &[1, 3, 4]).unwrap());
        });
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = configure();
    targets = bench_shamir_split,
              bench_shamir_reconstruct,
              bench_shamir_roundtrip
}
criterion_main!(benches);
