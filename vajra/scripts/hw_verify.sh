#!/bin/bash
# VAJRA Hardware Capability Report
# Run this on your Oracle ARM instance immediately after setup
# Save the output — paste it when reporting benchmark results

set -euo pipefail

echo "======= VAJRA HARDWARE CAPABILITY REPORT ======="
echo "Date: $(date -Iseconds)"
echo "Instance: $(hostname)"
echo ""

echo "--- CPU Architecture ---"
uname -m
grep -m1 "model name\|CPU part" /proc/cpuinfo 2>/dev/null || echo "(no model name — ARM instance)"

echo ""
echo "--- ARM Crypto Extensions (AES-NI equivalent) ---"
if [[ "$(uname -m)" == "aarch64" ]]; then
    grep -m1 "Features" /proc/cpuinfo | grep -o "aes\|pmull\|sha1\|sha2" || echo "WARNING: No crypto extensions found!"
    echo "(Need: aes pmull sha2 — if missing, AES not hardware accelerated)"
elif [[ "$(uname -m)" == "x86_64" ]]; then
    grep -m1 "flags" /proc/cpuinfo | grep -o "aes\|avx2\|sse4_2" || echo "WARNING: No AES-NI found!"
    echo "(x86_64 detected — checking for AES-NI and AVX2)"
fi

echo ""
echo "--- Kernel Version ---"
uname -r
echo "(Need: 5.15+ for threading support)"

echo ""
echo "--- Available CPU Cores ---"
nproc
echo "(Need: 4 minimum for pipeline test)"

echo ""
echo "--- Available RAM ---"
free -h | grep Mem

echo ""
echo "--- AES Speed Baseline ---"
if command -v openssl &> /dev/null; then
    openssl speed -elapsed -evp aes-256-gcm 2>&1 | grep "aes-256-gcm" || echo "openssl speed test failed"
    echo "(Need: >500 MB/s at 1024B blocks — confirms hardware acceleration)"
else
    echo "openssl not installed — install with: sudo apt install openssl"
fi

echo ""
echo "--- Network to Second Instance ---"
echo "(Run: iperf3 -s on Instance B first)"
echo "Then run: iperf3 -c <INSTANCE_B_PRIVATE_IP> -t 10"
echo "(Need: >800 Mbps internal — confirms VCN connectivity)"

echo ""
echo "--- Rust Install ---"
if command -v rustc &> /dev/null; then
    rustc --version
    cargo --version
else
    echo "Rust not installed. Run:"
    echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
fi

echo ""
echo "--- Python Install ---"
if command -v python3 &> /dev/null; then
    python3 --version
else
    echo "Python3 not installed."
fi

echo "======= END HARDWARE REPORT ======="
