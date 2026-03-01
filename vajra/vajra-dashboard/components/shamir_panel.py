"""
Phantom Channels Panel — demonstrates 3-of-5 Shamir Secret Sharing.

Shows 5 path channels as visual indicators.
Demo triggers:
- Compromise individual paths to show threshold resilience
- 3 compromised = reconstruction fails
"""

import streamlit as st


def _init_state():
    """Initialize Shamir panel state."""
    # Ensure shared counters exist even when panel is used standalone
    st.session_state.setdefault("sessions_active", 1)

    if "shamir_paths" not in st.session_state:
        st.session_state.shamir_paths = {
            "ISP-A": "active",
            "ISP-B": "active",
            "VPN": "active",
            "Satellite": "active",
            "Mesh": "active",
        }


def render_shamir_panel():
    """Render the Phantom Channels visualization panel."""
    _init_state()

    st.markdown("### 📡 Phantom Channels")
    st.markdown("*3-of-5 Shamir Secret Sharing over GF(2⁸)*")

    # Count compromised paths
    compromised = sum(
        1 for s in st.session_state.shamir_paths.values() if s == "compromised"
    )
    active = 5 - compromised
    can_reconstruct = active >= 3

    # Path visualization
    st.markdown("**Path Status:**")

    for path_name, status in st.session_state.shamir_paths.items():
        if status == "active":
            color = "#00ff88"
            bg = "#001a0d"
            icon = "●"
            label = "ACTIVE"
        elif status == "degraded":
            color = "#ff9f00"
            bg = "#1a1400"
            icon = "◐"
            label = "DEGRADED"
        else:  # compromised
            color = "#ff3030"
            bg = "#1a0000"
            icon = "✗"
            label = "COMPROMISED"

        st.markdown(
            f'<div style="font-family: monospace; padding: 6px 10px; '
            f'margin: 3px 0; background: {bg}; border-left: 3px solid {color}; '
            f'color: {color}; display: flex; justify-content: space-between;">'
            f'<span>{icon} {path_name}</span>'
            f'<span>{label}</span>'
            f'</div>',
            unsafe_allow_html=True,
        )

    st.markdown("")

    # Reconstruction status
    if can_reconstruct:
        st.markdown(
            f'<div style="text-align: center; padding: 10px; '
            f'background: #001a0d; border: 1px solid #00ff88; border-radius: 8px; '
            f'color: #00ff88; font-family: monospace; font-size: 1.1em;">'
            f'Attacker controls {compromised}/5 paths<br>'
            f'Reconstruction: <b>POSSIBLE</b> ✓<br>'
            f'({active} active paths ≥ 3 threshold)</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div style="text-align: center; padding: 10px; '
            f'background: #1a0000; border: 2px solid #ff3030; border-radius: 8px; '
            f'color: #ff3030; font-family: monospace; font-size: 1.1em;">'
            f'Attacker controls {compromised}/5 paths<br>'
            f'Reconstruction: <b>IMPOSSIBLE</b> ✗<br>'
            f'(only {active} active paths &lt; 3 threshold)</div>',
            unsafe_allow_html=True,
        )

    st.markdown("")

    # Controls
    path_names = list(st.session_state.shamir_paths.keys())
    active_paths = [
        p for p, s in st.session_state.shamir_paths.items() if s == "active"
    ]

    col_a, col_b = st.columns(2)

    with col_a:
        if active_paths:
            target = st.selectbox(
                "Target path:",
                active_paths,
                key="shamir_target",
            )
            if st.button("💀 Compromise Path", key="compromise_path"):
                st.session_state.shamir_paths[target] = "compromised"
                st.rerun()

    with col_b:
        if st.button("🔄 Reset All Paths", key="reset_paths"):
            for p in path_names:
                st.session_state.shamir_paths[p] = "active"
            st.rerun()

    # Security explanation
    st.markdown("")
    st.info(
        "Ciphertext is split into 5 shares using Shamir's Secret Sharing "
        "over GF(2⁸). Any 3 shares can reconstruct the original. "
        "An attacker must simultaneously compromise 3+ paths — "
        "infeasible on physically separate government network paths."
    )
