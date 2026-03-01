"""
VAJRA Security Dashboard — Interactive Demo for iDEX Evaluators.

Military command center aesthetic demonstrating:
1. Living Ratchet — per-session key evolution
2. Phantom Channels — 3-of-5 Shamir secret sharing
3. Breach Canary — real-time integrity monitoring

All crypto is simulated in Python for demo purposes.
All real benchmark numbers come from Rust Criterion benchmarks.
"""

import streamlit as st
import time

from components.ratchet_panel import render_ratchet_panel
from components.shamir_panel import render_shamir_panel
from components.canary_panel import render_canary_panel

# ── Page Configuration ───────────────────────────────────────────

st.set_page_config(
    page_title="VAJRA — Quantum-Safe Transport",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Custom CSS — Military command center aesthetic ───────────────

st.markdown("""
<style>
    /* Dark navy background */
    .stApp {
        background-color: #0a0e1a;
        color: #e0e6ed;
    }

    /* Headers */
    h1, h2, h3 {
        color: #00d4ff !important;
        font-family: 'JetBrains Mono', 'Fira Code', monospace !important;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #111827;
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 12px;
    }

    [data-testid="stMetricValue"] {
        color: #00d4ff !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    [data-testid="stMetricLabel"] {
        color: #8899aa !important;
    }

    /* Buttons */
    .stButton > button {
        background-color: #1e3a5f;
        color: #00d4ff;
        border: 1px solid #00d4ff;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
        transition: all 0.3s ease;
    }

    .stButton > button:hover {
        background-color: #00d4ff;
        color: #0a0e1a;
    }

    /* Alert styling */
    .breach-alert {
        background-color: #1a0000;
        border: 2px solid #ff3030;
        border-radius: 8px;
        padding: 16px;
        color: #ff3030;
        font-family: 'JetBrains Mono', monospace;
        animation: pulse 1s infinite;
    }

    @keyframes pulse {
        0%, 100% { opacity: 1.0; }
        50% { opacity: 0.7; }
    }

    /* Status indicators */
    .status-active { color: #00ff88; }
    .status-destroyed { color: #ff3030; }
    .status-warning { color: #ff9f00; }

    /* Monospace data */
    .mono-data {
        font-family: 'JetBrains Mono', 'Fira Code', monospace;
        font-size: 0.85em;
    }

    /* Panel borders */
    .panel-container {
        border: 1px solid #1e3a5f;
        border-radius: 8px;
        padding: 16px;
        background-color: #0d1117;
    }

    /* Divider */
    hr {
        border-color: #1e3a5f;
    }

    /* Hide Streamlit branding */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    header {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ── Initialize Session State ────────────────────────────────────

if "initialized" not in st.session_state:
    st.session_state.initialized = True
    st.session_state.start_time = time.time()
    st.session_state.total_packets = 0
    st.session_state.total_rotations = 0
    st.session_state.breaches_detected = 0
    st.session_state.sessions_active = 1

# ── Header ───────────────────────────────────────────────────────

st.markdown("""
# 🛡️ VAJRA — Quantum-Safe Multi-Path Secure Transport
**Living Ratchet** · **Phantom Channels** · **Breach Canary**
""")

st.markdown("---")

# ── Three-Panel Layout ──────────────────────────────────────────

col1, col2, col3 = st.columns(3, gap="medium")

with col1:
    render_ratchet_panel()

with col2:
    render_shamir_panel()

with col3:
    render_canary_panel()

# ── Bottom Metrics Bar ──────────────────────────────────────────

st.markdown("---")

uptime = time.time() - st.session_state.start_time
hours = int(uptime // 3600)
minutes = int((uptime % 3600) // 60)
seconds = int(uptime % 60)

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Sessions Active", st.session_state.sessions_active)
m2.metric("Keys Rotated", st.session_state.total_rotations)
m3.metric("Packets Secured", f"{st.session_state.total_packets:,}")
m4.metric("Breaches Detected", st.session_state.breaches_detected)
m5.metric("Uptime", f"{hours:02d}:{minutes:02d}:{seconds:02d}")

# ── Footer ──────────────────────────────────────────────────────

st.markdown("""
<div style="text-align: center; color: #445566; font-size: 0.8em; margin-top: 20px;">
    VAJRA v0.1.0 — Quantum-Safe Multi-Path Secure Transport<br>
    All throughput numbers from Rust Criterion benchmarks on real hardware.<br>
    This demo simulates cryptographic operations for visualization only.
</div>
""", unsafe_allow_html=True)
