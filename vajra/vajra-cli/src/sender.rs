//! Sender — traffic generator for two-machine benchmark test.

use rand::RngCore;
use serde::Serialize;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use vajra_core::crypto::canary::BreachCanary;
use vajra_core::crypto::primitives;
use vajra_core::crypto::ratchet::{LivingRatchet, RatchetConfig, RatchetMode};
use vajra_core::crypto::shamir::PhantomChannels;

#[derive(Serialize)]
struct SenderResults {
    platform: String,
    date: String,
    duration_secs: u64,
    target_rate_mbps: u32,
    packet_size: usize,
    packets_sent: u64,
    bytes_sent: u64,
    actual_rate_mbps: f64,
    key_rotations: u64,
}

pub async fn run(
    peer: String,
    rate: u32,
    duration: u64,
    packet_size: usize,
    output: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("VAJRA Sender starting → {peer} at {rate} Mbps for {duration}s");

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect(&peer).await?;

    // Initialize VAJRA pipeline
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 32];
    rng.fill_bytes(&mut key);
    let mut session_id = [0u8; 16];
    rng.fill_bytes(&mut session_id);

    let config = RatchetConfig {
        mode: RatchetMode::PerSession {
            packets_per_rotation: 10_000,
        },
        session_id,
    };
    let mut ratchet = LivingRatchet::new(key, config);

    let mut canary_key = [0u8; 32];
    rng.fill_bytes(&mut canary_key);
    let mut canary = BreachCanary::new(canary_key, &session_id, 3.0, 0.5, None);

    let phantom = PhantomChannels::new(3, 5);

    // Generate plaintext payload
    let mut plaintext = vec![0u8; packet_size];
    rng.fill_bytes(&mut plaintext);

    // Calculate inter-packet interval for target rate
    let bits_per_packet = (packet_size * 8) as f64;
    let target_pps = (rate as f64 * 1_000_000.0) / bits_per_packet;
    let interval = Duration::from_secs_f64(1.0 / target_pps);

    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration);
    let mut packets_sent: u64 = 0;
    let mut bytes_sent: u64 = 0;

    tracing::info!(
        "Target: {target_pps:.0} packets/sec, interval: {interval:?}"
    );

    while Instant::now() < deadline {
        // Full VAJRA pipeline
        let (enc_key, counter) = ratchet.advance().unwrap();
        let nonce = primitives::derive_nonce(&enc_key, counter).unwrap();
        let aad = counter.to_be_bytes();
        let ciphertext =
            primitives::aes_gcm_encrypt(&enc_key, &nonce, &plaintext, &aad).unwrap();

        // Shamir split
        let shares = phantom.split(&ciphertext).unwrap();

        // Canary stamp
        let _token = canary.stamp(&ciphertext);

        // Send the first share (in a real system, each share goes on a different path)
        // For benchmark, we send the full ciphertext to measure throughput
        let send_data = &shares.shares[0];
        match socket.send(send_data).await {
            Ok(n) => {
                packets_sent += 1;
                bytes_sent += n as u64;
            }
            Err(e) => {
                tracing::warn!("Send error: {e}");
            }
        }

        // Rate limiting
        tokio::time::sleep(interval).await;
    }

    let elapsed = start.elapsed();
    let actual_rate = (bytes_sent as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0;

    let results = SenderResults {
        platform: format!("{} {}", std::env::consts::ARCH, std::env::consts::OS),
        date: chrono::Utc::now().to_rfc3339(),
        duration_secs: duration,
        target_rate_mbps: rate,
        packet_size,
        packets_sent,
        bytes_sent,
        actual_rate_mbps: actual_rate,
        key_rotations: ratchet.session_counter(),
    };

    tracing::info!(
        "Done: {packets_sent} packets, {bytes_sent} bytes, {actual_rate:.1} Mbps"
    );

    if let Some(path) = output {
        let json = serde_json::to_string_pretty(&results)?;
        std::fs::write(&path, &json)?;
        tracing::info!("Results written to {path}");
    }

    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}
