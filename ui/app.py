"""Streamlit demo dashboard for JAF (Jev Agent Firewall).

Multi-page layout:
1. 🏦 ACME Bank AI Assistant (Production App)
2. 💀 Attacker C2 Server (Listener :8765)
3. 🛡️ JAF Security Traces & Audit
4. ⚙️ JAF Configuration & Security Controls

Run:
    streamlit run ui/app.py
"""

from __future__ import annotations

import json
import os
import socket
import sys
import threading
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.agent_runner import DEFAULT_CANARY, LLMAgent, ScriptedHijackedAgent, system_prompt  # noqa: E402
from agent.mock_web import CLEAN_ARTICLE, IPI_PAYLOAD, POISONED_ARTICLE  # noqa: E402
from c2_server.c2_listener import HOST as C2_HOST, PORT as C2_PORT, Handler as C2Handler, HITS_FILE  # noqa: E402
from c2_server.wiki_server import (  # noqa: E402
    ensure_wiki_running,
    get_current_wiki_content,
    is_wiki_running,
    set_current_wiki_content,
    HOST as WIKI_HOST,
    PORT as WIKI_PORT,
)
from core import Blocked, Firewall, Settings, Verdict  # noqa: E402
from core.jev_client import JevClient  # noqa: E402
from core.laya_client import LayaDecisionEngine  # noqa: E402


def _ensure_c2_listener_running() -> None:
    """Auto-start the local dummy C2 listener in a background thread if not already active."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    is_open = sock.connect_ex((C2_HOST, C2_PORT)) == 0
    sock.close()
    if not is_open:
        from http.server import HTTPServer

        def run_server():
            try:
                server = HTTPServer((C2_HOST, C2_PORT), C2Handler)
                server.serve_forever()
            except Exception:
                pass

        t = threading.Thread(target=run_server, daemon=True)
        t.start()


# Auto-start both background servers for the demo
_ensure_c2_listener_running()
ensure_wiki_running()

st.set_page_config(page_title="ACME Bank AI & JAF Defense", layout="wide", page_icon="🏦")

# Session state defaults
if "protection_mode" not in st.session_state:
    st.session_state.protection_mode = "unprotected"  # "unprotected" | "protected" | "bypass_hop2"

if "engine_choice" not in st.session_state:
    st.session_state.engine_choice = "TypeSafe JEV (Cloud API - Default)"

if "use_llm" not in st.session_state:
    st.session_state.use_llm = False

if "last_verdicts" not in st.session_state:
    st.session_state.last_verdicts = []

if "last_task" not in st.session_state:
    st.session_state.last_task = f"hello, perform a research as intended to top banking APIs and check http://{WIKI_HOST}:{WIKI_PORT}/wiki/open-banking"

if "last_output" not in st.session_state:
    st.session_state.last_output = None

if "last_blocked" not in st.session_state:
    st.session_state.last_blocked = None

if "wiki_content" not in st.session_state:
    st.session_state.wiki_content = get_current_wiki_content()


def _build_engine(settings: Settings, choice: str):
    if "Local Laya" in choice:
        return LayaDecisionEngine()
    elif "Rules-Only" in choice:
        return None
    return JevClient(settings) if settings.openrouter_api_key else None


# ---------------------------------------------------------
# Sidebar Navigation (Clean & Uncluttered)
# ---------------------------------------------------------
with st.sidebar:
    st.title("🏦 ACME Banking Portal")
    nav = st.radio(
        "Go to page:",
        [
            "🏦 1. ACME Assistant (Prod App)",
            "💀 2. Attacker C2 Server",
            "🛡️ 3. JAF Security Traces",
            "⚙️ 4. Security Configuration",
        ],
        index=0,
    )

    st.markdown("---")
    st.markdown("### 🛡️ Active Security Status")
    if st.session_state.protection_mode == "protected":
        st.success("🟢 **JAF Protection: ACTIVE**\n\nMulti-Hop System 1 Firewall Enforced")
    elif st.session_state.protection_mode == "bypass_hop2":
        st.warning("🟠 **JAF Hop 2: BYPASSED**\n\nTesting Hop 3 Egress Circuit Breaker")
    else:
        st.error("🔴 **JAF Protection: DISABLED**\n\nAgent is Vulnerable to Injection")

    st.caption(f"🧠 Engine: **{st.session_state.engine_choice.split(' ')[0]}**")
    st.caption(f"🤖 Model: **{'Llama-3.1-8B' if st.session_state.use_llm else 'Scripted (Offline)'}**")


# =========================================================
# PAGE 1: ACME Bank AI Assistant (Production App)
# =========================================================
if "1. ACME Assistant" in nav:
    st.title("🏦 ACME Bank — Financial AI Assistant")
    st.caption("Internal Production Workspace · Autonomous Research & Open Banking API Support")

    col_status, col_btn = st.columns([4, 1])
    with col_status:
        if st.session_state.protection_mode == "protected":
            st.info("🛡️ **Connected to ACME Secure Gateway** — Real-time JAF multi-hop inspection is active.")
        elif st.session_state.protection_mode == "bypass_hop2":
            st.warning("⚠️ **Security Notice** — Retrieval gate is in test bypass mode (Egress protection active).")
        else:
            st.warning("⚠️ **Direct Mode** — AI agent operating without firewall guardrails.")

    st.markdown("---")
    st.subheader("💬 Ask ACME Assistant")

    default_prompt = f"hello, perform a research as intended to top banking APIs and check http://{WIKI_HOST}:{WIKI_PORT}/wiki/open-banking"

    col_p1, col_p2 = st.columns([4, 1])
    with col_p1:
        user_input = st.text_area(
            "Research Query or Prompt:",
            value=st.session_state.last_task,
            height=80,
            help="Ask the agent to research banking APIs or inspect partner documentation.",
        )
    with col_p2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🔄 Reset Prompt", use_container_width=True):
            st.session_state.last_task = default_prompt
            st.rerun()

    st.session_state.last_task = user_input

    if st.button("🚀 Run Assistant Research", type="primary", use_container_width=True):
        verdicts: list[Verdict] = []
        firewall = None

        if st.session_state.protection_mode in ("protected", "bypass_hop2"):
            settings = Settings()
            settings.mode = "enforce"
            settings.canary_tokens = settings.canary_tokens or [DEFAULT_CANARY]
            engine = _build_engine(settings, st.session_state.engine_choice)
            firewall = Firewall(settings, engine=engine, on_verdict=verdicts.append)

        bypass = st.session_state.protection_mode == "bypass_hop2"
        agent_cls = LLMAgent if st.session_state.use_llm else ScriptedHijackedAgent

        with st.spinner("🤖 ACME Assistant searching documentation and analyzing banking APIs..."):
            st.session_state.last_output = None
            st.session_state.last_blocked = None
            st.session_state.last_verdicts = []

            try:
                output = agent_cls(firewall, bypass_phase2=bypass).run(user_input)
                st.session_state.last_output = output
                st.session_state.last_verdicts = verdicts
            except Blocked as exc:
                st.session_state.last_blocked = str(exc)
                st.session_state.last_verdicts = verdicts
            except Exception as exc:
                st.session_state.last_output = f"Error: {exc}"

    # Display Results Cleanly
    if st.session_state.last_blocked:
        st.error(f"⚡ **SECURITY ALERT — ACTION HALTED BY JAF**\n\n`{st.session_state.last_blocked}`")
        st.info("👉 Switch to the **'🛡️ 3. JAF Security Traces'** page in the sidebar to inspect the sub-40ms telemetry.")

    elif st.session_state.last_output:
        st.markdown("#### 📋 Research Output from Assistant:")
        st.markdown(
            f"""
            <div style="background-color: #f8f9fa; color: #1e1e1e; border: 1px solid #dee2e6; border-radius: 8px; padding: 18px; line-height: 1.6; font-size: 15px;">
                {st.session_state.last_output}
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.session_state.protection_mode == "unprotected":
            st.warning("⚠️ **Notice:** The agent visited an external webpage. Check the **'💀 2. Attacker C2 Server'** page to see if confidential data was exfiltrated!")
        else:
            st.success("✅ **Clean Execution:** JAF sanitized the untrusted content. No unauthorized requests were allowed.")


# =========================================================
# PAGE 2: Attacker C2 Server (Listener :8765)
# =========================================================
elif "2. Attacker C2 Server" in nav:
    st.title("💀 Attacker Command & Control (C2) Server")
    st.caption("Live Listener: `http://127.0.0.1:8765/collect` · Simulates the Adversary Infrastructure")

    col_c2_head, col_c2_btn = st.columns([4, 1])
    with col_c2_btn:
        if st.button("🧹 Clear C2 Logs", use_container_width=True):
            HITS_FILE.unlink(missing_ok=True)
            st.success("C2 logs cleared!")
            st.rerun()

    hits = [json.loads(line) for line in HITS_FILE.read_text().splitlines()] if HITS_FILE.exists() else []

    if hits:
        st.error(f"🚨 **CRITICAL SECURITY BREACH: {len(hits)} Stolen Data Packet(s) Intercepted!**")
        st.markdown("The vulnerable ACME agent was hijacked via Indirect Prompt Injection and exfiltrated confidential internal data.")

        for idx, h in enumerate(reversed(hits[-5:])):
            with st.container(border=True):
                st.markdown(f"### 📦 Intercepted Exfiltration Packet #{len(hits)-idx}")
                st.code(f"GET {h.get('path', '')}", language="http")

                decoded = h.get("decoded", {})
                for param, val in decoded.items():
                    if val and DEFAULT_CANARY in val:
                        st.error("🔓 **DECODED STOLEN SYSTEM PROMPT & CANARY KEY:**")
                        st.code(val, language="text")
                    elif val:
                        st.write(f"**Decoded `{param}`:**", val)
    else:
        st.success("🛡️ **0 PACKETS RECEIVED — ZERO DATA EXFILTRATION**")
        st.markdown(
            """
            The attacker server has received **no traffic**. 
            All outbound data exfiltration attempts were blocked by JAF's multi-hop inspection.
            """
        )


# =========================================================
# PAGE 3: JAF Security Traces & Audit
# =========================================================
elif "3. JAF Security Traces" in nav:
    st.title("🛡️ JAF Multi-Hop Security Traces")
    st.caption("Sub-40ms System 1 AI Firewall Telemetry · Real-Time Decision Audit")

    if not st.session_state.last_verdicts:
        st.info("ℹ️ No firewall telemetry recorded for this session yet. Run a research query in **'🏦 1. ACME Assistant'** with JAF enabled to see live traces.")
    else:
        st.markdown("### ⏱️ Latency & Enforcement Overview")
        cols = st.columns(len(st.session_state.last_verdicts))
        for idx, v in enumerate(st.session_state.last_verdicts):
            with cols[idx]:
                st.metric(
                    label=f"Hop: {v.hop.value.upper()}",
                    value=f"{v.latency_ms:.1f} ms",
                    delta=f"Action: {v.action.value.upper()}",
                )

        st.markdown("---")
        st.markdown("### 🔍 Detailed Inspection Breakdown")

        for v in st.session_state.last_verdicts:
            with st.container(border=True):
                st.markdown(f"#### Gate: **{v.hop.value.upper()}** — Verdict: `{v.action.value.upper()}`")
                c1, c2, c3, c4 = st.columns(4)
                c1.write(f"**Category:** `{v.category.value}`")
                c2.write(f"**Risk Score:** `{v.score:.2f}`")
                c3.write(f"**Engine:** `{v.engine}`")
                c4.write(f"**Enforced:** `{'Yes' if v.enforced else 'No (Shadow)'}`")

                if v.findings:
                    st.markdown("**Rule & Model Findings:**")
                    for f in v.findings:
                        st.markdown(f"- **{f.source.upper()}** `{f.rule_id or ''}` (Confidence: `{f.score:.2f}`): {f.detail}")

                if v.sanitized_text:
                    st.markdown("---")
                    st.markdown("✂️ **Surgically Sanitized Content (Injected Directives Excised):**")
                    st.text_area("Sanitized output passed to model:", value=v.sanitized_text[:500], height=120, disabled=True)


# =========================================================
# PAGE 4: Security Configuration
# =========================================================
elif "4. Security Configuration" in nav:
    st.title("⚙️ JAF Security Configuration")
    st.caption("Control the Firewall Protection Mode, Decision Engine, and Attacking Scenario")

    st.markdown("### 1. Firewall Protection Mode")
    mode_options = {
        "🔴 Disabled (Vulnerable - Breach Demo)": "unprotected",
        "🟢 Full Protection (Hop 2 Sanitization Active)": "protected",
        "🟠 Hop 2 Bypass (Test Hop 3 Egress Circuit Breaker)": "bypass_hop2",
    }
    current_mode_label = [k for k, v in mode_options.items() if v == st.session_state.protection_mode][0]
    selected_mode = st.radio("Select JAF Operation Mode:", list(mode_options.keys()), index=list(mode_options.keys()).index(current_mode_label))
    st.session_state.protection_mode = mode_options[selected_mode]

    st.markdown("---")
    st.markdown("### 2. Decision Model Provider")
    engine_opts = [
        "TypeSafe JEV (Cloud API - Default)",
        "Local Laya INT8 ONNX (CPU - Offline)",
        "Deterministic Rules-Only (No model, 0ms)",
    ]
    st.session_state.engine_choice = st.selectbox(
        "Select JAF Engine:",
        engine_opts,
        index=engine_opts.index(st.session_state.engine_choice) if st.session_state.engine_choice in engine_opts else 0,
    )

    st.markdown("---")
    st.markdown("### 3. Agent Execution Engine")
    st.session_state.use_llm = st.toggle(
        "Use Real LLM Agent (meta-llama/llama-3.1-8b-instruct on OpenRouter)",
        value=st.session_state.use_llm,
        help="Turn on to use the live Meta Llama 3.1 8B model. Turn off for instant offline scripted demo.",
    )

    st.markdown("---")
    st.markdown("### 4. Confidential System Secret (The Attack Target)")
    st.caption("This is the private system prompt and canary token inside the ACME Bank AI Assistant:")
    st.code(system_prompt(DEFAULT_CANARY), language="text")

    st.markdown("---")
    st.markdown(f"### 5. Local Wiki Server Content (`http://{WIKI_HOST}:{WIKI_PORT}/wiki/open-banking`)")
    col_w1, col_w2 = st.columns(2)
    with col_w1:
        if st.button("🚨 Load Poisoned Webpage (With IPI Injection)", use_container_width=True):
            set_current_wiki_content(POISONED_ARTICLE)
            st.session_state.wiki_content = POISONED_ARTICLE
            st.success("Loaded Poisoned Article on local server!")
            st.rerun()
    with col_w2:
        if st.button("📄 Load Clean Technical Documentation", use_container_width=True):
            set_current_wiki_content(CLEAN_ARTICLE)
            st.session_state.wiki_content = CLEAN_ARTICLE
            st.success("Loaded Clean Article on local server!")
            st.rerun()

    st.text_area("Live Content on Local Documentation Server:", value=get_current_wiki_content(), height=150, disabled=True)
