//! VAJRA CLI — two-machine network throughput test.
//!
//! # Usage
//! ```bash
//! # On Instance A (receiver):
//! vajra-cli receiver --bind 0.0.0.0:7777
//!
//! # On Instance B (sender):
//! vajra-cli sender --peer <IP>:7777 --rate 500 --duration 60
//!
//! # Generate report:
//! vajra-cli report --sender results/sender.json --receiver results/receiver.json
//! ```

mod receiver;
mod sender;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "vajra-cli")]
#[command(about = "VAJRA Quantum-Safe Transport — Network Test CLI")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run as packet sender (traffic generator)
    Sender {
        /// Peer address (receiver) in IP:PORT format
        #[arg(long)]
        peer: String,

        /// Target throughput in Mbps
        #[arg(long, default_value = "500")]
        rate: u32,

        /// Test duration in seconds
        #[arg(long, default_value = "60")]
        duration: u64,

        /// Packet size in bytes
        #[arg(long, default_value = "1500")]
        packet_size: usize,

        /// Output JSON file for results
        #[arg(long)]
        output: Option<String>,
    },

    /// Run as packet receiver (VAJRA server)
    Receiver {
        /// Bind address in IP:PORT format
        #[arg(long, default_value = "0.0.0.0:7777")]
        bind: String,

        /// Output JSON file for results
        #[arg(long)]
        output: Option<String>,
    },

    /// Generate benchmark report from sender+receiver results
    Report {
        /// Sender results JSON file
        #[arg(long)]
        sender: String,

        /// Receiver results JSON file
        #[arg(long)]
        receiver: String,

        /// Output report file
        #[arg(long, default_value = "vajra_network_benchmark.md")]
        output: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Sender {
            peer,
            rate,
            duration,
            packet_size,
            output,
        } => {
            sender::run(peer, rate, duration, packet_size, output).await?;
        }
        Commands::Receiver { bind, output } => {
            receiver::run(bind, output).await?;
        }
        Commands::Report {
            sender,
            receiver,
            output,
        } => {
            generate_report(&sender, &receiver, &output)?;
        }
    }

    Ok(())
}

fn generate_report(
    sender_path: &str,
    receiver_path: &str,
    output_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let sender_data = std::fs::read_to_string(sender_path)?;
    let receiver_data = std::fs::read_to_string(receiver_path)?;

    let sender: serde_json::Value = serde_json::from_str(&sender_data)?;
    let receiver: serde_json::Value = serde_json::from_str(&receiver_data)?;

    let report = format!(
        r#"VAJRA Network Benchmark Results
================================
Platform: {}
Date: {}
Duration: {} seconds

Throughput:
  Packets sent:     {}
  Packets received: {}
  Achieved:         {} Mbps

Latency (milliseconds):
  P50:   {} ms
  P95:   {} ms
  P99:   {} ms

Security Properties:
  Key rotations:     {}
  Shamir splits:     {}
  Canary tokens:     {}
  Breaches detected: {}
"#,
        sender.get("platform").and_then(|v| v.as_str()).unwrap_or("unknown"),
        sender.get("date").and_then(|v| v.as_str()).unwrap_or("unknown"),
        sender.get("duration_secs").and_then(|v| v.as_u64()).unwrap_or(0),
        sender.get("packets_sent").and_then(|v| v.as_u64()).unwrap_or(0),
        receiver.get("packets_received").and_then(|v| v.as_u64()).unwrap_or(0),
        receiver.get("throughput_mbps").and_then(|v| v.as_f64()).unwrap_or(0.0),
        receiver.get("p50_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
        receiver.get("p95_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
        receiver.get("p99_ms").and_then(|v| v.as_f64()).unwrap_or(0.0),
        receiver.get("key_rotations").and_then(|v| v.as_u64()).unwrap_or(0),
        receiver.get("shamir_splits").and_then(|v| v.as_u64()).unwrap_or(0),
        receiver.get("canary_tokens").and_then(|v| v.as_u64()).unwrap_or(0),
        receiver.get("breaches_detected").and_then(|v| v.as_u64()).unwrap_or(0),
    );

    std::fs::write(output_path, &report)?;
    println!("Report written to {output_path}");
    println!("{report}");
    Ok(())
}
