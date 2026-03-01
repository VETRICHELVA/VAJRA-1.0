"""
Living Ratchet Panel — demonstrates per-session key evolution.

Shows a live scrolling table of key states with:
- Session number
- Key hash (first 8 hex characters)
- Status (ACTIVE / DESTROYED)

Demo trigger: "Simulate Key Capture" button shows blast radius.
"""

import hashlib
import os
import streamlit as st


def _generate_key():
    """Generate a random 32-byte key and return its hex hash."""
    key = os.urandom(32)
    key_hash = hashlib.sha256(key).hexdigest()[:16]
    return key_hash


def _init_state():
    """Initialize ratchet panel state."""
    # Ensure shared counter exists even when panel is used standalone
    st.session_state.setdefault("total_rotations", 0)

    if "ratchet_keys" not in st.session_state:
        st.session_state.ratchet_keys = []
        # Generate initial key chain
        for i in range(8):
            st.session_state.ratchet_keys.append({
                "session": i,
                "key_hash": _generate_key(),
                "status": "DESTROYED" if i < 7 else "ACTIVE",
            })
        st.session_state.ratchet_captured = False
        st.session_state.captured_session = None


def render_ratchet_panel():
    """Render the Living Ratchet visualization panel."""
    _init_state()

    st.markdown("### 🔑 Living Ratchet")
    st.markdown("*Per-session key evolution — forward secrecy*")

    # Key state table
    st.markdown("**Key Chain State:**")

    for entry in reversed(st.session_state.ratchet_keys):
        session = entry["session"]
        key_hash = entry["key_hash"]
        status = entry["status"]

        if st.session_state.ratchet_captured and session == st.session_state.captured_session:
            # Captured key — show in red
            st.markdown(
                f'<div style="font-family: monospace; padding: 4px 8px; '
                f'margin: 2px 0; background: #1a0000; border-left: 3px solid #ff3030; '
                f'color: #ff3030;">'
                f'Session {session:>3d} │ {key_hash}… │ ⚠ CAPTURED</div>',
                unsafe_allow_html=True,
            )
        elif status == "ACTIVE":
            st.markdown(
                f'<div style="font-family: monospace; padding: 4px 8px; '
                f'margin: 2px 0; background: #001a0d; border-left: 3px solid #00ff88; '
                f'color: #00ff88;">'
                f'Session {session:>3d} │ {key_hash}… │ ● ACTIVE</div>',
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f'<div style="font-family: monospace; padding: 4px 8px; '
                f'margin: 2px 0; background: #111827; border-left: 3px solid #334455; '
                f'color: #556677;">'
                f'Session {session:>3d} │ {key_hash}… │ ✗ DESTROYED</div>',
                unsafe_allow_html=True,
            )

    st.markdown("")

    # Controls
    col_a, col_b = st.columns(2)

    with col_a:
        if st.button("🔄 Rotate Key", key="rotate_key"):
            # Advance the ratchet
            current_max = max(e["session"] for e in st.session_state.ratchet_keys)
            # Mark current active as destroyed
            for entry in st.session_state.ratchet_keys:
                if entry["status"] == "ACTIVE":
                    entry["status"] = "DESTROYED"
            # Add new active key
            st.session_state.ratchet_keys.append({
                "session": current_max + 1,
                "key_hash": _generate_key(),
                "status": "ACTIVE",
            })
            # Keep only last 8
            st.session_state.ratchet_keys = st.session_state.ratchet_keys[-8:]
            st.session_state.total_rotations += 1
            st.session_state.ratchet_captured = False
            st.rerun()

    with col_b:
        if st.button("🎯 Capture Key", key="capture_key"):
            # Simulate attacker capturing the current active key
            for entry in st.session_state.ratchet_keys:
                if entry["status"] == "ACTIVE":
                    st.session_state.captured_session = entry["session"]
                    break
            st.session_state.ratchet_captured = True
            st.rerun()

    # Blast radius display
    if st.session_state.ratchet_captured:
        st.markdown(
            '<div class="breach-alert">'
            f'⚠ Key {st.session_state.captured_session} captured.<br>'
            '<b>Blast radius: 1 session window only.</b><br>'
            'Standard TLS: Entire connection (potentially hours).<br>'
            'VAJRA: Previous keys already destroyed — zero backward access.'
            '</div>',
            unsafe_allow_html=True,
        )
    else:
        st.info(
            "Each session gets a unique key derived via HKDF-SHA256. "
            "Previous keys are immediately zeroized. "
            "Click **Capture Key** to see the blast radius difference."
        )
