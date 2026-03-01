"""
Breach Canary Panel — real-time integrity monitoring visualization.

Shows:
- Inter-packet timing chart (last 50 packets)
- Anomaly detection with sigma threshold
- Demo: inject MITM delay to trigger alert
"""

import random
import time

import numpy as np
import plotly.graph_objects as go
import streamlit as st


def _init_state():
    """Initialize canary panel state."""
    if "canary_timings" not in st.session_state:
        # Generate baseline timing data (~10ms ± small jitter)
        st.session_state.canary_timings = [
            10.0 + random.gauss(0, 0.3) for _ in range(50)
        ]
        st.session_state.canary_packet_ids = list(range(50))
        st.session_state.canary_next_id = 50
        st.session_state.canary_alert_active = False
        st.session_state.canary_alert_msg = ""
        st.session_state.canary_alert_sigma = 0.0


def _compute_z_score(timings, value):
    """Compute z-score using Welford-equivalent calculation."""
    if len(timings) < 2:
        return 0.0
    mean = np.mean(timings)
    std = np.std(timings, ddof=1)
    if std == 0:
        return 0.0
    return abs(value - mean) / std


def render_canary_panel():
    """Render the Breach Canary visualization panel."""
    _init_state()

    st.markdown("### 🐤 Breach Canary")
    st.markdown("*Real-time integrity monitoring*")

    # Compute statistics
    timings = st.session_state.canary_timings
    mean_timing = np.mean(timings)
    std_timing = np.std(timings, ddof=1) if len(timings) > 1 else 0
    threshold_upper = mean_timing + 3 * std_timing
    threshold_lower = max(0, mean_timing - 3 * std_timing)

    # Create timing chart
    fig = go.Figure()

    # Normal zone (green shading)
    fig.add_hrect(
        y0=threshold_lower,
        y1=threshold_upper,
        fillcolor="rgba(0, 255, 136, 0.05)",
        line_width=0,
    )

    # Anomaly zones (red shading)
    fig.add_hrect(
        y0=threshold_upper,
        y1=max(timings) + 10,
        fillcolor="rgba(255, 48, 48, 0.1)",
        line_width=0,
    )

    # Threshold lines
    fig.add_hline(
        y=threshold_upper,
        line_dash="dash",
        line_color="#ff3030",
        annotation_text="3σ threshold",
        annotation_font_color="#ff3030",
    )

    fig.add_hline(
        y=mean_timing,
        line_dash="dot",
        line_color="#00d4ff",
        annotation_text="baseline",
        annotation_font_color="#00d4ff",
    )

    # Color points: green for normal, red for anomaly
    colors = []
    for t in timings:
        z = _compute_z_score(timings[:40], t)  # compare against early baseline
        if z > 3:
            colors.append("#ff3030")
        else:
            colors.append("#00ff88")

    # Timing line
    fig.add_trace(go.Scatter(
        x=st.session_state.canary_packet_ids,
        y=timings,
        mode="lines+markers",
        line=dict(color="#00d4ff", width=1),
        marker=dict(color=colors, size=5),
        name="Inter-packet timing",
    ))

    fig.update_layout(
        plot_bgcolor="#0d1117",
        paper_bgcolor="#0a0e1a",
        font=dict(color="#8899aa", family="JetBrains Mono, monospace"),
        xaxis=dict(
            title="Packet #",
            gridcolor="#1e3a5f",
            zerolinecolor="#1e3a5f",
        ),
        yaxis=dict(
            title="Timing (ms)",
            gridcolor="#1e3a5f",
            zerolinecolor="#1e3a5f",
        ),
        height=280,
        margin=dict(l=40, r=20, t=20, b=40),
        showlegend=False,
    )

    st.plotly_chart(fig, use_container_width=True)

    # Alert display
    if st.session_state.canary_alert_active:
        st.markdown(
            f'<div class="breach-alert">'
            f'⚠ <b>TIMING ANOMALY DETECTED</b><br>'
            f'Sigma: {st.session_state.canary_alert_sigma:.1f} | '
            f'{st.session_state.canary_alert_msg}<br>'
            f'<b>→ CHANNEL KILLED — New session establishing...</b>'
            f'</div>',
            unsafe_allow_html=True,
        )
        st.session_state.breaches_detected += 1

    # Controls
    col_a, col_b, col_c = st.columns(3)

    with col_a:
        if st.button("💉 Inject MITM +50ms", key="inject_mitm"):
            # Add anomalous timing spike
            for _ in range(3):
                spike = 60.0 + random.gauss(0, 2)
                z = _compute_z_score(
                    st.session_state.canary_timings[:40], spike
                )
                st.session_state.canary_timings.append(spike)
                st.session_state.canary_packet_ids.append(
                    st.session_state.canary_next_id
                )
                st.session_state.canary_next_id += 1

            st.session_state.canary_alert_active = True
            st.session_state.canary_alert_sigma = z
            st.session_state.canary_alert_msg = (
                f"Packet #{st.session_state.canary_next_id - 1}"
            )

            # Keep last 50 entries
            st.session_state.canary_timings = st.session_state.canary_timings[-50:]
            st.session_state.canary_packet_ids = st.session_state.canary_packet_ids[-50:]
            st.rerun()

    with col_b:
        if st.button("📈 Add Normal", key="add_normal"):
            for _ in range(5):
                normal = 10.0 + random.gauss(0, 0.3)
                st.session_state.canary_timings.append(normal)
                st.session_state.canary_packet_ids.append(
                    st.session_state.canary_next_id
                )
                st.session_state.canary_next_id += 1
                st.session_state.total_packets += 1

            st.session_state.canary_alert_active = False
            st.session_state.canary_timings = st.session_state.canary_timings[-50:]
            st.session_state.canary_packet_ids = st.session_state.canary_packet_ids[-50:]
            st.rerun()

    with col_c:
        if st.button("🔄 Reset", key="reset_canary"):
            del st.session_state["canary_timings"]
            st.rerun()

    # Stats
    st.markdown(
        f'<div style="font-family: monospace; font-size: 0.85em; color: #8899aa;">'
        f'Mean: {mean_timing:.2f}ms | '
        f'StdDev: {std_timing:.2f}ms | '
        f'3σ threshold: {threshold_upper:.2f}ms'
        f'</div>',
        unsafe_allow_html=True,
    )
