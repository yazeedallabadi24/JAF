"""UI Components for JAF Streamlit Dashboard.

Provides visual elements: WAF trace breadcrumbs, latency gauges, and the
live Attacker C2 Exfiltration Listener monitor.
"""

import streamlit as st
from typing import List, Dict, Any


def render_waf_trace(hops: List[Dict[str, Any]]):
    """Render horizontal visual cards for each defensive hop executed."""
    st.markdown("### 🛡️ JAF Multi-Hop System 1 Execution Trace")

    cols = st.columns(max(len(hops), 1))
    for idx, hop in enumerate(hops):
        with cols[idx]:
            hop_name = hop.get("hop", f"Hop {idx+1}")
            latency = hop.get("latency_ms", 0.0)
            threat = hop.get("threat_detected", False)
            action = hop.get("action", "PASS")

            bg_color = "#ffebee" if threat else "#e8f5e9"
            border_color = "#d32f2f" if threat else "#388e3c"
            status_text = "🚨 THREAT DETECTED" if threat else "✅ CLEAN / PERMITTED"

            if action == "BYPASSED_UNPROTECTED":
                bg_color = "#fff3e0"
                border_color = "#f57c00"
                status_text = "⚠️ BYPASSED (UNPROTECTED)"

            st.markdown(
                f"""
                <div style="background-color: {bg_color}; border: 2px solid {border_color}; border-radius: 8px; padding: 12px; margin-bottom: 10px;">
                    <strong style="color: #111;">{hop_name}</strong><br>
                    <span style="font-size: 0.85em; color: #555;">Action: <b>{action}</b></span><br>
                    <span style="font-size: 0.85em; color: #555;">Latency: <b>{latency} ms</b></span><br>
                    <span style="font-weight: bold; font-size: 0.8em; color: {border_color};">{status_text}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_c2_panel(packets: List[Dict[str, Any]]):
    """Render the live Attacker C2 Server monitor panel."""
    st.markdown("### 📡 Live Attacker C2 Listener (`http://127.0.0.1:8765/collect`)")

    has_breach = any(p.get("has_canary_flag") for p in packets)

    if has_breach:
        st.markdown(
            """
            <div style="background-color: #b71c1c; color: white; padding: 16px; border-radius: 8px; margin-bottom: 15px; animation: blinker 1.5s linear infinite;">
                <h3 style="margin: 0; color: white;">🚨 CRITICAL SECURITY BREACH: DATA EXFILTRATED!</h3>
                <p style="margin: 5px 0 0 0; font-size: 0.95em;">
                    The compromised agent transmitted the confidential canary flag to the attacker's listener!
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    elif packets:
        st.markdown(
            f"""
            <div style="background-color: #fff3e0; border: 2px solid #f57c00; padding: 12px; border-radius: 8px; margin-bottom: 15px;">
                <h4 style="margin: 0; color: #e65100;">⚠️ Inbound Traffic: {len(packets)} Packet(s) Received</h4>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            """
            <div style="background-color: #1b5e20; color: white; padding: 16px; border-radius: 8px; margin-bottom: 15px;">
                <h3 style="margin: 0; color: white;">🛡️ 0 PACKETS RECEIVED — ZERO DATA EXFILTRATION</h3>
                <p style="margin: 5px 0 0 0; font-size: 0.95em;">
                    All exfiltration attempts were successfully intercepted by JAF before leaving the system.
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    if packets:
        st.markdown("#### Captured Outbound Requests")
        for pkt in reversed(packets[-5:]):
            with st.expander(f"📦 Packet #{pkt['id']} [{pkt['timestamp']}] {pkt['method']} {pkt['path'][:40]}...", expanded=True):
                st.code(f"Raw Target URL: {pkt['path']}\nRaw Encoded Payload: {pkt['raw_payload']}")
                if pkt.get("has_canary_flag"):
                    st.error(f"🔓 DECODED STOLEN SECRET:\n{pkt['decoded_payload']}")
                else:
                    st.info(f"Decoded Payload:\n{pkt['decoded_payload']}")
