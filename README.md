# VAJRA-1.0
## A Quantum-Safe Transportation Layer

VAJRA is a quantum-safe multi-path secure transport protocol featuring:
- **Living Ratchet** — Per-session key evolution using HKDF-SHA256 over ML-KEM-768
- **Phantom Channels** — 3-of-5 Shamir Secret Sharing over GF(2⁸)
- **Breach Canary** — Real-time integrity monitoring via HMAC proof chains

---

## Complete Steps to Run VAJRA on AWS and Record Benchmark

### Prerequisites

Before you begin, ensure you have:
- A GitHub Codespace or Linux machine (Ubuntu 22.04+)
- Two AWS EC2 instances (recommended: `t3.small`, 2 vCPU, 2 GB RAM) in the **same VPC/subnet**
- SSH key pair (`~/.ssh/id_ed25519`) added to both EC2 instances
- Both instances running **Ubuntu 22.04 LTS**
- Security group rules allowing:
  - SSH (port 22) from your IP
  - UDP port **7777** between the two instances (internal VPC)

---

### Step 1 — Generate SSH Key (if not already present)

```bash
ssh-keygen -t ed25519 -C vajra-aws -f ~/.ssh/id_ed25519 -N ''
cat ~/.ssh/id_ed25519.pub
# → Paste this into both EC2 instances' authorized_keys
```

---

### Step 2 — Configure AWS Instance IPs

Open [`scripts/setup_and_deploy.sh`](scripts/setup_and_deploy.sh) and [`scripts/run_benchmark.sh`](scripts/run_benchmark.sh) and update the IP addresses to match your EC2 instances:

```bash
RECEIVER_PUBLIC="<your-receiver-public-ip>"
RECEIVER_PRIVATE="<your-receiver-private-ip>"
SENDER_PUBLIC="<your-sender-public-ip>"
SENDER_PRIVATE="<your-sender-private-ip>"
```

---

### Step 3 — Verify Hardware Capabilities on Each EC2 Instance

SSH into each instance and run the hardware verification script:

```bash
# On BOTH instances
ssh -i ~/.ssh/id_ed25519 ubuntu@<instance-ip>
bash -s < vajra/scripts/hw_verify.sh
```

Expected output:
```
--- ARM Crypto Extensions / AES-NI ---
aes pmull sha2         ← REQUIRED for hardware acceleration

--- Available CPU Cores ---
2+                     ← Minimum 4 recommended for pipeline test

--- AES Speed Baseline ---
aes-256-gcm: >500 MB/s ← Confirms hardware AES acceleration
```

---

### Step 4 — Run Full Setup and Deploy (One Command)

From your **Codespace** or local machine, run:

```bash
bash scripts/setup_and_deploy.sh
```

This script automatically:

| Step | Action |
|------|--------|
| 1 | Installs Rust (via rustup) |
| 2 | Installs build dependencies (`build-essential`, `libssl-dev`, `cmake`, `iperf3`) |
| 3 | Builds `vajra-cli` binary with `RUSTFLAGS="-C target-cpu=x86-64-v2"` |
| 4 | Verifies SSH key access to both EC2 instances |
| 5 | Runs system setup on both EC2 instances |
| 6 | Deploys `vajra-cli` binary to both instances via `scp` |
| 7 | Verifies deployment with `vajra-cli --version` on both instances |
| 8 | Creates local `results/` directory |

> ⏱️ **First build takes 5–10 minutes** (Rust compilation). Subsequent builds are fast.

---

### Step 5 — Manual Verification (Optional)

Confirm the binary is deployed and working on both instances:

```bash
# Check receiver
ssh -i ~/.ssh/id_ed25519 ubuntu@<RECEIVER_PUBLIC> "./vajra-cli --version"

# Check sender
ssh -i ~/.ssh/id_ed25519 ubuntu@<SENDER_PUBLIC> "./vajra-cli --version"
```

---

### Step 6 — Run the Full Benchmark Suite

```bash
bash scripts/run_benchmark.sh
```

This script runs **4 benchmark phases**:

#### Benchmark 1 — Raw UDP Baseline (iperf3, no crypto)
```
Tests raw network throughput between EC2 instances
→ Result saved: results/iperf3_baseline_<timestamp>.json
```

#### Benchmark 2 — VAJRA Encrypted Throughput (500 Mbps target)
```
Sender: 500 pps × 1500-byte packets × 60 seconds
Full pipeline: Ratchet → AES-256-GCM → Shamir Split (3-of-5) → Canary Stamp
→ Result saved: results/vajra_sender_<timestamp>.json
               results/vajra_receiver_<timestamp>.json
```

#### Benchmark 3 — High Rate Test (1000 Mbps target)
```
Sender: 1000 pps × 1500-byte packets × 60 seconds
→ Result saved: results/vajra_sender_high_<timestamp>.json
               results/vajra_receiver_high_<timestamp>.json
```

#### Benchmark 4 — Local Criterion Microbenchmarks
```
Runs on Codespace with RUSTFLAGS="-C target-cpu=native"
Benchmarks: primitives, full_stack, shamir, ratchet, canary
→ Result saved: results/bench_primitives_<timestamp>.txt
               results/bench_fullstack_<timestamp>.txt
```

---

### Step 7 — Understand the CLI Commands

#### On the Receiver Instance
```bash
./vajra-cli receiver \
    --bind 0.0.0.0:7777 \
    --output /tmp/vajra_receiver.json
```

#### On the Sender Instance
```bash
./vajra-cli sender \
    --peer <RECEIVER_PRIVATE_IP>:7777 \
    --rate 500 \
    --duration 60 \
    --packet-size 1500 \
    --output /tmp/vajra_sender.json
```

#### Generate Report from Both Result Files
```bash
./vajra-cli report \
    --sender results/vajra_sender.json \
    --receiver results/vajra_receiver.json \
    --output vajra_network_benchmark.md
```

---

### Step 8 — View Results

Results are saved to `/workspaces/VAJRA-1.0/results/`:

```bash
ls -lh results/
```

| File | Description |
|------|-------------|
| `iperf3_baseline_<ts>.json` | Raw UDP throughput (no crypto) |
| `vajra_sender_<ts>.json` | Sender metrics (packets sent, rate, key rotations) |
| `vajra_receiver_<ts>.json` | Receiver metrics (throughput, P50/P95/P99 latency) |
| `vajra_benchmark_report_<ts>.md` | Full auto-generated summary report |
| `bench_primitives_<ts>.txt` | AES-GCM / HKDF / HMAC Criterion results |
| `bench_fullstack_<ts>.txt` | Full pipeline Criterion results |
| `receiver_hw_<ts>.txt` | Hardware capabilities of receiver instance |

---

### Step 9 — Run Local Criterion Benchmarks (Standalone)

Run individual microbenchmarks locally without AWS:

```bash
cd vajra

# AES-256-GCM, HKDF-SHA256, HMAC-SHA256
RUSTFLAGS="-C target-cpu=native" cargo bench --bench primitives

# Full pipeline: Ratchet → Encrypt → Shamir → Canary
RUSTFLAGS="-C target-cpu=native" cargo bench --bench full_stack

# Shamir Secret Sharing (Phantom Channels)
RUSTFLAGS="-C target-cpu=native" cargo bench --bench shamir

# Living Ratchet key evolution
RUSTFLAGS="-C target-cpu=native" cargo bench --bench ratchet

# Breach Canary (proof chain + timing)
RUSTFLAGS="-C target-cpu=native" cargo bench --bench canary
```

HTML benchmark reports are generated in:
```
vajra/target/criterion/
```

---

### Step 10 — Run Unit Tests

```bash
cd vajra
cargo test --all
```

Key test coverage:
- `shamir.rs` — All C(5,3)=10 share combinations, 1500B packets, cross-platform vectors
- `canary.rs` — Welford statistics, timing anomaly detection
- `primitives.rs` — AES-GCM roundtrip, HMAC tamper detection, HKDF derivation
- `tls_wrapper.rs` — Commercial session encryption roundtrip

---

### Step 11 — Launch the Security Dashboard

Visualize VAJRA's three security layers interactively:

```bash
cd vajra/vajra-dashboard
pip install streamlit plotly numpy
streamlit run app.py
```

Then open: [http://localhost:8501](http://localhost:8501)

The dashboard demonstrates:
- 🔑 **Living Ratchet Panel** — Per-session key evolution with blast-radius demo
- 📡 **Phantom Channels Panel** — 3-of-5 path compromise simulation
- 🐤 **Breach Canary Panel** — Real-time MITM timing injection demo

> **Note:** Dashboard crypto is simulated in Python for visualization only.
> All real benchmark numbers come from Rust Criterion benchmarks.

---

### Expected Benchmark Results

| Metric | Expected Value |
|--------|---------------|
| Raw UDP baseline (iperf3) | > 800 Mbps (same VPC) |
| VAJRA encrypted throughput | > 500 Mbps |
| AES-256-GCM encrypt (1500B) | < 1 µs per packet |
| Full pipeline (1500B) | < 5 µs per packet |
| Shamir split 3-of-5 (1500B) | < 2 µs per packet |
| Ratchet key rotation | < 1 µs per step |
| P99 latency | < 5 ms |

---

### Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   VAJRA Pipeline                    │
│                                                     │
│  Plaintext                                          │
│     │                                               │
│     ▼                                               │
│  Living Ratchet ──── HKDF-SHA256 ──── ML-KEM-768   │
│  (per-session key evolution)                        │
│     │                                               │
│     ▼                                               │
│  AES-256-GCM Encrypt (hardware AES-NI)             │
│     │                                               │
│     ▼                                               │
│  Phantom Channels ── 3-of-5 Shamir over GF(2⁸)     │
│  (multi-path secret splitting)                      │
│     │                                               │
│     ▼                                               │
│  Breach Canary ───── HMAC proof chain               │
│  (real-time integrity + timing anomaly detection)   │
│     │                                               │
│     ▼                                               │
│  5 encrypted shares → 5 independent paths          │
└─────────────────────────────────────────────────────┘
```

---

### Troubleshooting

| Problem | Solution |
|---------|----------|
| `SSH key not found` | Run `ssh-keygen -t ed25519 -C vajra-aws -f ~/.ssh/id_ed25519 -N ''` |
| `Cannot reach receiver` | Run `setup_and_deploy.sh` first; check security group allows UDP 7777 |
| `Binary not found after build` | Check `cargo build` errors; ensure `libssl-dev` is installed |
| `AES speed < 500 MB/s` | Instance lacks AES-NI; use a different instance type |
| `0 packets received` | Ensure receiver started before sender; check private IP is used |
| `Criterion HTML report missing` | Run with `--features html_reports` in `vajra-bench/Cargo.toml` |

---

### Committing Results

Benchmark results are automatically committed to GitHub at the end of `run_benchmark.sh`:

```bash
git add results/
git commit -m "bench: AWS ap-south-2 two-machine benchmark <timestamp>"
git push
```

---

### Project Structure

```
VAJRA-1.0/
├── scripts/
│   ├── setup_and_deploy.sh    # One-shot setup: build + deploy to AWS
│   └── run_benchmark.sh       # Full benchmark suite runner
├── results/                   # Benchmark output files
├── vajra/
│   ├── vajra-core/            # Cryptographic primitives
│   │   └── src/crypto/
│   │       ├── primitives.rs  # AES-GCM, HKDF, HMAC
│   │       ├── ratchet.rs     # Living Ratchet
│   │       ├── shamir.rs      # Phantom Channels (Shamir)
│   │       └── canary.rs      # Breach Canary
│   ├── vajra-cli/             # Network benchmark CLI
│   │   └── src/
│   │       ├── sender.rs      # Traffic generator
│   │       └── receiver.rs    # Packet receiver
│   ├── vajra-bench/           # Criterion microbenchmarks
│   ├── vajra-commercial/      # TLS 1.3 wrapper (no Shamir)
│   └── vajra-dashboard/       # Streamlit visualization dashboard
└── README.md
```

---

*VAJRA v0.1.0 — Quantum-Safe Multi-Path Secure Transport*
*All throughput numbers from Rust Criterion benchmarks on real hardware.*
