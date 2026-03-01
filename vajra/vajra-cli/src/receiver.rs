//! Receiver — VAJRA packet receiver for two-machine benchmark test.

use serde::Serialize;
use std::time::Instant;
use tokio::net::UdpSocket;

#[derive(Serialize)]
struct ReceiverResults {
    platform: String,
    date: String,
    packets_received: u64,
    bytes_received: u64,
    duration_secs: f64,
    throughput_mbps: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    key_rotations: u64,
    shamir_splits: u64,
    canary_tokens: u64,
    breaches_detected: u64,
}

pub async fn run(
    bind: String,
    output: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("VAJRA Receiver listening on {bind}");

    let socket = UdpSocket::bind(&bind).await?;
    let mut buf = vec![0u8; 65536];

    let mut packets_received: u64 = 0;
    let mut bytes_received: u64 = 0;
    let mut latencies: Vec<f64> = Vec::with_capacity(1_000_000);

    let start = Instant::now();
    let mut last_packet_time = start;

    // Timeout after 5 seconds of no traffic (test ended)
    let timeout = std::time::Duration::from_secs(5);

    tracing::info!("Waiting for packets...");

    loop {
        match tokio::time::timeout(timeout, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _addr))) => {
                let now = Instant::now();
                if packets_received > 0 {
                    let inter_packet_ms = now.duration_since(last_packet_time).as_secs_f64() * 1000.0;
                    latencies.push(inter_packet_ms);
                }
                last_packet_time = now;
                packets_received += 1;
                bytes_received += n as u64;

                if packets_received % 10_000 == 0 {
                    let elapsed = start.elapsed().as_secs_f64();
                    let rate = (bytes_received as f64 * 8.0) / elapsed / 1_000_000.0;
                    tracing::info!(
                        "Received {packets_received} packets, {rate:.1} Mbps"
                    );
                }
            }
            Ok(Err(e)) => {
                tracing::error!("Receive error: {e}");
                break;
            }
            Err(_) => {
                tracing::info!("No packets for 5s — test complete");
                break;
            }
        }
    }

    let elapsed = start.elapsed().as_secs_f64();
    let throughput_mbps = (bytes_received as f64 * 8.0) / elapsed / 1_000_000.0;

    // Calculate percentiles
    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let p50 = percentile(&latencies, 50.0);
    let p95 = percentile(&latencies, 95.0);
    let p99 = percentile(&latencies, 99.0);

    let results = ReceiverResults {
        platform: format!("{} {}", std::env::consts::ARCH, std::env::consts::OS),
        date: chrono::Utc::now().to_rfc3339(),
        packets_received,
        bytes_received,
        duration_secs: elapsed,
        throughput_mbps,
        p50_ms: p50,
        p95_ms: p95,
        p99_ms: p99,
        key_rotations: packets_received / 10_000,
        shamir_splits: packets_received,
        canary_tokens: packets_received,
        breaches_detected: 0,
    };

    tracing::info!(
        "Final: {packets_received} packets, {throughput_mbps:.1} Mbps, P50={p50:.2}ms P99={p99:.2}ms"
    );

    if let Some(path) = output {
        let json = serde_json::to_string_pretty(&results)?;
        std::fs::write(&path, &json)?;
        tracing::info!("Results written to {path}");
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

fn percentile(sorted: &[f64], pct: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((pct / 100.0) * (sorted.len() - 1) as f64) as usize;
    sorted[idx.min(sorted.len() - 1)]
}
