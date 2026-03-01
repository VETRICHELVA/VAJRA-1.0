#!/usr/bin/env bash
# VAJRA — Full Setup & Deploy Script
# Runs on Codespace. Does everything in one shot:
#   1. Installs Rust
#   2. Installs build dependencies
#   3. Builds vajra-cli binary
#   4. Sets up both AWS instances
#   5. Deploys binary to both instances
#   6. Verifies deployment
# Usage: bash scripts/setup_and_deploy.sh

set -e  # exit on any error

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # no color

log()  { echo -e "${CYAN}[VAJRA]${NC} $1"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $1"; }
warn() { echo -e "${YELLOW}[ WARN]${NC} $1"; }
fail() { echo -e "${RED}[FAIL ]${NC} $1"; exit 1; }

# ── AWS Instance IPs ─────────────────────────────────────────────────────────
RECEIVER_PUBLIC="16.112.192.184"
RECEIVER_PRIVATE="172.31.8.103"
SENDER_PUBLIC="16.112.128.168"
SENDER_PRIVATE="172.31.0.204"
SSH_KEY="$HOME/.ssh/id_ed25519"
SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $SSH_KEY"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1 — Install Rust
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 1 — Installing Rust..."

if command -v rustc &>/dev/null; then
    ok "Rust already installed: $(rustc --version)"
else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
    ok "Rust installed: $(rustc --version)"
fi

# Ensure cargo env is loaded
source "$HOME/.cargo/env" 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2 — Install build dependencies
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 2 — Installing build dependencies..."

sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    libssl-dev \
    libclang-dev \
    cmake \
    git \
    curl \
    wget \
    iperf3

ok "Build dependencies installed"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3 — Build vajra-cli binary
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 3 — Building vajra-cli (this takes 5-10 minutes first time)..."

cd /workspaces/VAJRA-1.0/vajra

RUSTFLAGS="-C target-cpu=x86-64-v2" \
    cargo build --release -p vajra-cli 2>&1

BINARY="target/release/vajra-cli"

if [ ! -f "$BINARY" ]; then
    fail "Binary not found after build — check errors above"
fi

ok "Binary built: $(ls -lh $BINARY | awk '{print $5, $9}')"
file "$BINARY"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4 — Check SSH key exists
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 4 — Checking SSH key..."

if [ ! -f "$SSH_KEY" ]; then
    fail "SSH key not found at $SSH_KEY — run: ssh-keygen -t ed25519 -C vajra-aws -f ~/.ssh/id_ed25519 -N ''"
fi

ok "SSH key found: $SSH_KEY"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5 — Setup AWS instances
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 5 — Setting up AWS instances..."

SETUP_SCRIPT='
set -e
export DEBIAN_FRONTEND=noninteractive
echo "[setup] Updating packages..."
sudo apt-get update -qq
sudo apt-get install -y --no-install-recommends \
    build-essential pkg-config libssl-dev \
    cmake git curl wget iperf3 \
    linux-tools-common 2>/dev/null || true
echo "[setup] Checking AES-NI..."
grep -o "aes\|avx2" /proc/cpuinfo | sort -u
echo "[setup] System info:"
echo "  CPUs: $(nproc)"
echo "  RAM:  $(free -h | awk "/Mem/{print \$2}")"
echo "  OS:   $(lsb_release -ds 2>/dev/null || uname -r)"
echo "[setup] DONE on $(hostname)"
'

log "  Setting up vajra-receiver ($RECEIVER_PUBLIC)..."
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC "$SETUP_SCRIPT" || \
    warn "Receiver setup had errors — continuing"
ok "vajra-receiver setup done"

log "  Setting up vajra-sender ($SENDER_PUBLIC)..."
ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC "$SETUP_SCRIPT" || \
    warn "Sender setup had errors — continuing"
ok "vajra-sender setup done"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6 — Deploy binary to both instances
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 6 — Deploying vajra-cli binary to AWS instances..."

BINARY_PATH="/workspaces/VAJRA-1.0/vajra/target/release/vajra-cli"

log "  Copying to vajra-receiver ($RECEIVER_PUBLIC)..."
scp $SSH_OPTS "$BINARY_PATH" ubuntu@$RECEIVER_PUBLIC:~/vajra-cli
ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC "chmod +x ~/vajra-cli"
ok "Binary deployed to receiver"

log "  Copying to vajra-sender ($SENDER_PUBLIC)..."
scp $SSH_OPTS "$BINARY_PATH" ubuntu@$SENDER_PUBLIC:~/vajra-cli
ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC "chmod +x ~/vajra-cli"
ok "Binary deployed to sender"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7 — Verify deployment
# ─────────────────────────────────────────────────────────────────────────────
log "STEP 7 — Verifying deployment..."

RECEIVER_VER=$(ssh $SSH_OPTS ubuntu@$RECEIVER_PUBLIC "./vajra-cli --version" 2>&1)
SENDER_VER=$(ssh $SSH_OPTS ubuntu@$SENDER_PUBLIC "./vajra-cli --version" 2>&1)

ok "Receiver: $RECEIVER_VER"
ok "Sender:   $SENDER_VER"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 8 — Create results directory
# ─────────────────────────────────────────────────────────────────────────────
mkdir -p /workspaces/VAJRA-1.0/results
ok "Results directory created"

# ─────────────────────────────────────────────────────────────────────────────
# DONE
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  VAJRA SETUP COMPLETE — ALL SYSTEMS READY            ${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════════${NC}"
echo ""
echo "  Receiver:  ubuntu@$RECEIVER_PUBLIC  (private: $RECEIVER_PRIVATE)"
echo "  Sender:    ubuntu@$SENDER_PUBLIC  (private: $SENDER_PRIVATE)"
echo "  Binary:    ~/vajra-cli on both instances"
echo "  Results:   /workspaces/VAJRA-1.0/results/"
echo ""
echo -e "${CYAN}NEXT STEP — Run the benchmark:${NC}"
echo "  bash /workspaces/VAJRA-1.0/scripts/run_benchmark.sh"
echo ""
