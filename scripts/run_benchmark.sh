#!/usr/bin/env bash
# VAJRA — Two-Machine Benchmark Script
# Runs sender on vajra-sender, receiver on vajra-receiver
# Collects results and saves to /workspaces/VAJRA-1.0/results/
# Usage: bash scripts/run_benchmark.sh

set -e

# ── Colors ───────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${CYAN}[BENCH]${NC} $1"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ WARN]${NC} $1"; }

# ── Config ───────────────────────────────────────────────────────────────────
RECEIVER_PUBLIC="16.112.192.184"
RECEIVER_PRIVATE="172.31.8.103"
SENDER_PUBLIC="16.112.128.168"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"
RESULTS_DIR="/workspaces/VAJRA-1.0/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
VAJRA_PORT=7777

mkdir -p "$RESULTS_DIR"

echo ""
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  VAJRA — Two-Machine Benchmark (AWS ap-south-2)      ${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# PRE-CHECK
# ─────────────────────────────────────────────────────────────────────────────
log "Pre-check: verifying connectivity..."

ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "./vajra-cli --version" > /dev/null 2>&1 && \
    ok "vajra-receiver reachable" || \
    { echo "ERROR: Cannot reach receiver. Run setup_and_deploy.sh first."; exit 1; }

ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC \
    "./vajra-cli --version" > /dev/null 2>&1 && \
    ok "vajra-sender reachable" || \
    { echo "ERROR: Cannot reach sender. Run setup_and_deploy.sh first."; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK 1 — iperf3 baseline (raw UDP throughput, no crypto)
# ─────────────────────────────────────────────────────────────────────────────
log "BENCHMARK 1 — Raw UDP throughput baseline (iperf3)..."

# Start iperf3 server on receiver
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "nohup iperf3 -s -p 5201 > /tmp/iperf3_server.log 2>&1 &"
sleep 2

# Run iperf3 client on sender → receiver private IP
ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC \
    "iperf3 -c $RECEIVER_PRIVATE -p 5201 -u -b 1G \
     -l 1472 -t 30 --json" \
    > "$RESULTS_DIR/iperf3_baseline_${TIMESTAMP}.json"

ok "iperf3 baseline saved: iperf3_baseline_${TIMESTAMP}.json"

# Kill iperf3 server
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "pkill iperf3 2>/dev/null || true"

# Extract baseline throughput
BASELINE_MBPS=$(python3 -c "
import json, sys
with open('$RESULTS_DIR/iperf3_baseline_${TIMESTAMP}.json') as f:
    d = json.load(f)
bps = d.get('end',{}).get('sum',{}).get('bits_per_second', 0)
print(f'{bps/1e6:.1f}')
" 2>/dev/null || echo "N/A")
echo "  Baseline UDP throughput: ${BASELINE_MBPS} Mbps"

# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK 2 — VAJRA encrypted throughput
# ─────────────────────────────────────────────────────────────────────────────
log "BENCHMARK 2 — VAJRA encrypted throughput (1500 byte packets)..."

# Start receiver
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "nohup ./vajra-cli receiver \
        --bind 0.0.0.0:$VAJRA_PORT \
        --output /tmp/vajra_receiver_${TIMESTAMP}.json \
    > /tmp/vajra_receiver.log 2>&1 &"
sleep 3
ok "Receiver started on port $VAJRA_PORT"

# Run sender for 60 seconds at 500 pps
ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC \
    "./vajra-cli sender \
        --peer $RECEIVER_PRIVATE:$VAJRA_PORT \
        --rate 500 \
        --duration 60 \
        --packet-size 1500 \
        --output /tmp/vajra_sender_${TIMESTAMP}.json \
    2>&1" \
    | tee "$RESULTS_DIR/vajra_sender_live_${TIMESTAMP}.txt"

ok "Sender completed 60-second run"

# Kill receiver
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "pkill -f 'vajra-cli receiver' 2>/dev/null || true"
sleep 1

# ─────────────────────────────────────────────────────────────────────────────
# BENCHMARK 3 — Higher rate (1000 pps)
# ─────────────────────────────────────────────────────────────────────────────
log "BENCHMARK 3 — High rate test (1000 pps x 1500 bytes)..."

ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "nohup ./vajra-cli receiver \
        --bind 0.0.0.0:$VAJRA_PORT \
        --output /tmp/vajra_receiver_high_${TIMESTAMP}.json \
    > /tmp/vajra_receiver_high.log 2>&1 &"
sleep 3

ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC \
    "./vajra-cli sender \
        --peer $RECEIVER_PRIVATE:$VAJRA_PORT \
        --rate 1000 \
        --duration 60 \
        --packet-size 1500 \
        --output /tmp/vajra_sender_high_${TIMESTAMP}.json \
    2>&1" \
    | tee "$RESULTS_DIR/vajra_sender_high_${TIMESTAMP}.txt"

ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "pkill -f 'vajra-cli receiver' 2>/dev/null || true"

# ─────────────────────────────────────────────────────────────────────────────
# COLLECT RESULTS
# ─────────────────────────────────────────────────────────────────────────────
log "Collecting result files from AWS instances..."

# Collect receiver results
scp $SSH_OPTS \
    ubuntu@$RECEIVER_PUBLIC:"/tmp/vajra_receiver_${TIMESTAMP}.json" \
    "$RESULTS_DIR/" 2>/dev/null || warn "Could not fetch receiver result file"

scp $SSH_OPTS \
    ubuntu@$RECEIVER_PUBLIC:"/tmp/vajra_receiver_high_${TIMESTAMP}.json" \
    "$RESULTS_DIR/" 2>/dev/null || warn "Could not fetch receiver high result file"

# Collect sender results
scp $SSH_OPTS \
    ubuntu@$SENDER_PUBLIC:"/tmp/vajra_sender_${TIMESTAMP}.json" \
    "$RESULTS_DIR/" 2>/dev/null || warn "Could not fetch sender result file"

scp $SSH_OPTS \
    ubuntu@$SENDER_PUBLIC:"/tmp/vajra_sender_high_${TIMESTAMP}.json" \
    "$RESULTS_DIR/" 2>/dev/null || warn "Could not fetch sender high result file"

# Collect system logs
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC \
    "grep -o 'aes\|avx2' /proc/cpuinfo | sort -u && \
     nproc && free -h && uname -r" \
    > "$RESULTS_DIR/receiver_hw_${TIMESTAMP}.txt"

ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC \
    "grep -o 'aes\|avx2' /proc/cpuinfo | sort -u && \
     nproc && free -h && uname -r" \
    > "$RESULTS_DIR/sender_hw_${TIMESTAMP}.txt"

ok "All results collected in $RESULTS_DIR/"

# ─────────────────────────────────────────────────────────────────────────────
# RUN LOCAL CRITERION BENCHMARKS (while instances are warm)
# ─────────────────────────────────────────────────────────────────────────────
log "Running local Criterion benchmarks on Codespace..."

source "$HOME/.cargo/env" 2>/dev/null || true
cd /workspaces/VAJRA-1.0/vajra

RUSTFLAGS="-C target-cpu=native" \
    cargo bench --bench primitives 2>&1 \
    | tee "$RESULTS_DIR/bench_primitives_${TIMESTAMP}.txt"

RUSTFLAGS="-C target-cpu=native" \
    cargo bench --bench full_stack 2>&1 \
    | tee "$RESULTS_DIR/bench_fullstack_${TIMESTAMP}.txt"

ok "Criterion benchmarks complete"

# ─────────────────────────────────────────────────────────────────────────────
# GENERATE SUMMARY REPORT
# ─────────────────────────────────────────────────────────────────────────────
log "Generating benchmark summary report..."

python3 - << PYEOF
import os, glob, json, re
from datetime import datetime

results_dir = "/workspaces/VAJRA-1.0/results"
ts = "$TIMESTAMP"

report_lines = [
    "# VAJRA Benchmark Report",
    f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}",
    f"Infrastructure: AWS EC2 ap-south-2 (Hyderabad)",
    f"Instance type: t3.small (2 vCPU, 2GB RAM)",
    "",
    "## Hardware Verification",
    "",
]

# Hardware
hw_file = f"{results_dir}/receiver_hw_{ts}.txt"
if os.path.exists(hw_file):
    with open(hw_file) as f:
        content = f.read().strip()
    report_lines += [
        "```",
        f"vajra-receiver hardware:",
        content,
        "```",
        "",
    ]

# iperf3 baseline
iperf_file = f"{results_dir}/iperf3_baseline_{ts}.json"
if os.path.exists(iperf_file):
    try:
        with open(iperf_file) as f:
            d = json.load(f)
        bps = d.get("end",{}).get("sum",{}).get("bits_per_second", 0)
        report_lines += [
            "## Network Baseline (iperf3, no crypto)",
            f"UDP throughput: **{bps/1e6:.1f} Mbps**",
            "",
        ]
    except Exception as e:
        report_lines += [f"iperf3 parse error: {e}", ""]

# VAJRA throughput from live output
vajra_file = f"{results_dir}/vajra_sender_live_{ts}.txt"
if os.path.exists(vajra_file):
    with open(vajra_file) as f:
        content = f.read()
    report_lines += [
        "## VAJRA Encrypted Throughput (500 pps, 1500B, 60s)",
        "```",
        content[-2000:] if len(content) > 2000 else content,
        "```",
        "",
    ]

# Criterion primitives
bench_file = f"{results_dir}/bench_primitives_{ts}.txt"
if os.path.exists(bench_file):
    with open(bench_file) as f:
        content = f.read()
    # Extract key lines
    key_lines = [l for l in content.split("\n")
                 if "time:" in l.lower() or "thrpt:" in l.lower()
                 or "aes" in l.lower() or "Benchmarking" in l]
    report_lines += [
        "## Criterion Benchmarks (AES-256-GCM, primitives)",
        "```",
        "\n".join(key_lines[:40]),
        "```",
        "",
    ]

report_lines += [
    "## Configuration",
    "- ML-KEM-768 (NIST PQC standard) handshake",
    "- AES-256-GCM encryption (hardware AES-NI)",
    "- HKDF-SHA256 key derivation",
    "- Living Ratchet: per-session key evolution",
    "- Phantom Channels: 3-of-5 Shamir over GF(2^8)",
    "- Breach Canary: Welford online anomaly detection",
    "",
    "---",
    "*Generated by VAJRA benchmark suite*",
]

report_path = f"{results_dir}/vajra_benchmark_report_{ts}.md"
with open(report_path, "w") as f:
    f.write("\n".join(report_lines))

print(f"Report written: {report_path}")
PYEOF

# ─────────────────────────────────────────────────────────────────────────────
# COMMIT RESULTS
# ─────────────────────────────────────────────────────────────────────────────
log "Committing results to GitHub..."

cd /workspaces/VAJRA-1.0
git add results/
git commit -m "bench: AWS ap-south-2 two-machine benchmark ${TIMESTAMP}" || \
    warn "Nothing new to commit"
git push || warn "Push failed — push manually"

# ─────────────────────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  BENCHMARK COMPLETE                                  ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "Results saved in: $RESULTS_DIR/"
ls -lh "$RESULTS_DIR/"
echo ""
echo -e "${CYAN}NEXT STEP — Deploy dashboard to Streamlit Cloud:${NC}"
echo "  https://streamlit.io/cloud"
echo "  → Sign in with GitHub (VETRICHELVA)"
echo "  → New app → VAJRA-1.0 → vajra/vajra-dashboard/app.py"
echo ""
