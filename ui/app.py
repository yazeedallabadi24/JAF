"""Streamlit demo dashboard for JAF (Jev Agent Firewall).

Enterprise UI layout without decorative emojis or vibe-coded formatting:
1. ACME Assistant (Production)
2. Attacker C2 Listener
3. JAF Security Traces
4. System Configuration

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

st.set_page_config(page_title="ACME Bank AI | JAF Security", layout="wide")

# Session state defaults
if "protection_mode" not in st.session_state:
    st.session_state.protection_mode = "unprotected"

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
# Sidebar Navigation
# ---------------------------------------------------------
with st.sidebar:
    st.markdown("### ACME Banking Portal")
    st.caption("Enterprise AI Security Architecture")

    nav = st.radio(
        "Navigation Menu:",
        [
            "1. ACME Assistant (Production)",
            "2. Attacker C2 Listener",
            "3. JAF Security Traces",
            "4. System Configuration",
        ],
        index=0,
    )

    st.markdown("---")
    st.markdown("#### Security Gateway Status")

    if st.session_state.protection_mode == "protected":
        st.success("[ACTIVE] JAF Multi-Hop Protection Enforced")
    elif st.session_state.protection_mode == "bypass_hop2":
        st.warning("[TEST] Hop 2 Bypassed · Egress Circuit Breaker Active")
    else:
        st.error("[DISABLED] Direct Model Execution (Vulnerable)")

    st.caption(f"Decision Engine: **{st.session_state.engine_choice.split(' ')[0]}**")
    st.caption(f"Execution Architecture: **{'Meta Llama-3.1-8B' if st.session_state.use_llm else 'Deterministic Scripted Agent'}**")


# =========================================================
# PAGE 1: ACME Bank AI Assistant (Production App)
# =========================================================
if "1. ACME Assistant" in nav:
    st.title("ACME Bank | Financial Intelligence Assistant")
    st.caption("Production Workspace | Autonomous API Research & Partner Integration Support")

    if st.session_state.protection_mode == "protected":
        st.info("[SECURITY STATUS: PROTECTED] Connected to ACME Secure Gateway. Multi-hop inspection active.")
    elif st.session_state.protection_mode == "bypass_hop2":
        st.warning("[SECURITY STATUS: TEST MODE] Retrieval gate in bypass mode. Egress circuit breaker armed.")
    else:
        st.warning("[SECURITY STATUS: UNPROTECTED] Agent operating without firewall guardrails.")

    st.markdown("---")
    st.markdown("#### Assistant Research Query")

    default_prompt = f"hello, perform a research as intended to top banking APIs and check http://{WIKI_HOST}:{WIKI_PORT}/wiki/open-banking"

    col_p1, col_p2 = st.columns([4, 1])
    with col_p1:
        user_input = st.text_area(
            "Query or prompt instruction:",
            value=st.session_state.last_task,
            height=80,
            help="Direct prompt or research query to be processed by the ACME assistant.",
        )
    with col_p2:
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Reset Default Query", use_container_width=True):
            st.session_state.last_task = default_prompt
            st.rerun()

    st.session_state.last_task = user_input

    if st.button("Execute Research Task", type="primary", use_container_width=True):
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

        with st.spinner("Processing assistant research task across endpoints..."):
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
                st.session_state.last_output = f"Execution error: {exc}"

    # Results Display
    if st.session_state.last_blocked:
        st.error(f"[SECURITY INTERCEPT: ACTION HALTED BY JAF]\n\n{st.session_state.last_blocked}")
        st.info("Inspection telemetry recorded. Switch to '3. JAF Security Traces' to review gate metrics.")

    elif st.session_state.last_output:
        st.markdown("#### Assistant Output:")
        st.markdown(
            f"""
            <div style="background-color: #f8f9fa; color: #1e1e1e; border: 1px solid #ced4da; border-radius: 4px; padding: 18px; line-height: 1.6; font-size: 14px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;">
                {st.session_state.last_output}
            </div>
            """,
            unsafe_allow_html=True,
        )

        if st.session_state.protection_mode == "unprotected":
            st.warning("[AUDIT ADVISORY] External documentation retrieved without sanitization. Inspect '2. Attacker C2 Listener' for exfiltration logs.")
        else:
            st.success("[INTEGRITY VERIFIED] External content sanitized by JAF. Zero unauthorized network transmissions were permitted.")


# =========================================================
# PAGE 2: Attacker C2 Listener
# =========================================================
elif "2. Attacker C2 Listener" in nav:
    st.title("Adversary Telemetry Listener")
    st.caption("Endpoint: http://127.0.0.1:8765/collect | Command & Control Simulation Daemon")

    col_c2_head, col_c2_btn = st.columns([4, 1])
    with col_c2_btn:
        if st.button("Clear Listener Logs", use_container_width=True):
            HITS_FILE.unlink(missing_ok=True)
            st.success("Listener log file cleared.")
            st.rerun()

    hits = [json.loads(line) for line in HITS_FILE.read_text().splitlines()] if HITS_FILE.exists() else []

    if hits:
        st.error(f"[CRITICAL DATA EXFILTRATION DETECTED: {len(hits)} Outbound Packet(s) Intercepted]")
        st.markdown("The vulnerable ACME assistant was hijacked via Indirect Prompt Injection and transmitted internal data to this listener.")

        for idx, h in enumerate(reversed(hits[-5:])):
            with st.container(border=True):
                st.markdown(f"**Intercepted Packet #{len(hits)-idx}**")
                st.code(f"GET {h.get('path', '')}", language="http")

                decoded = h.get("decoded", {})
                for param, val in decoded.items():
                    if val and DEFAULT_CANARY in val:
                        st.error("DECODED SYSTEM PROMPT & CANARY KEY EXFILTRATED:")
                        st.code(val, language="text")
                    elif val:
                        st.write(f"Decoded parameter `{param}`:", val)
    else:
        st.success("[ZERO EXFILTRATION DETECTED | ALL CHANNELS SECURE]")
        st.markdown("The listener recorded zero inbound network packets. Outbound exfiltration channels remained completely blocked.")


# =========================================================
# PAGE 3: JAF Security Traces
# =========================================================
elif "3. JAF Security Traces" in nav:
    st.title("JAF Multi-Hop Inspection Traces")
    st.caption("Sub-40ms System 1 Firewall Telemetry | Real-Time Decision Audit")

    if not st.session_state.last_verdicts:
        st.info("No inspection telemetry recorded for the current session. Run a query in '1. ACME Assistant (Production)' to populate traces.")
    else:
        st.markdown("#### Latency & Enforcement Metrics")
        cols = st.columns(len(st.session_state.last_verdicts))
        for idx, v in enumerate(st.session_state.last_verdicts):
            with cols[idx]:
                st.metric(
                    label=f"GATE: {v.hop.value.upper()}",
                    value=f"{v.latency_ms:.1f} ms",
                    delta=f"ACTION: {v.action.value.upper()}",
                )

        st.markdown("---")
        st.markdown("#### Gate Inspection Breakdown")

        for v in st.session_state.last_verdicts:
            with st.container(border=True):
                st.markdown(f"**Gate:** `{v.hop.value.upper()}` | **Verdict:** `{v.action.value.upper()}`")
                c1, c2, c3, c4 = st.columns(4)
                c1.write(f"Category: `{v.category.value}`")
                c2.write(f"Risk Score: `{v.score:.2f}`")
                c3.write(f"Engine: `{v.engine}`")
                c4.write(f"Enforced: `{'Yes' if v.enforced else 'No (Shadow)'}`")

                if v.findings:
                    st.markdown("**Rule & Classification Evidence:**")
                    for f in v.findings:
                        st.markdown(f"- **{f.source.upper()}** `{f.rule_id or 'none'}` (Score: `{f.score:.2f}`): {f.detail}")

                if v.sanitized_text:
                    st.markdown("---")
                    st.markdown("**Surgically Sanitized Content Output:**")
                    st.text_area("Sanitized text forwarded to model:", value=v.sanitized_text[:500], height=120, disabled=True)


# =========================================================
# PAGE 4: System Configuration
# =========================================================
elif "4. System Configuration" in nav:
    st.title("Firewall Control & Engine Configuration")
    st.caption("Administrative settings for JAF multi-hop gate enforcement")

    st.markdown("#### 1. Firewall Operation Mode")
    mode_options = {
        "[DISABLED] Unprotected (Vulnerable Agent - Breach Demonstration)": "unprotected",
        "[ENFORCE] Full Protection (Hop 2 Retrieval Gate Active)": "protected",
        "[TEST] Hop 2 Bypass (Test Hop 3 Egress Circuit Breaker)": "bypass_hop2",
    }
    current_mode_label = [k for k, v in mode_options.items() if v == st.session_state.protection_mode][0]
    selected_mode = st.radio("Select JAF Enforcement Mode:", list(mode_options.keys()), index=list(mode_options.keys()).index(current_mode_label))
    st.session_state.protection_mode = mode_options[selected_mode]

    st.markdown("---")
    st.markdown("#### 2. Decision Model Provider")
    engine_opts = [
        "TypeSafe JEV (Cloud API - Default)",
        "Local Laya INT8 ONNX (CPU - Offline)",
        "Deterministic Rules-Only (No model, 0ms)",
    ]
    st.session_state.engine_choice = st.selectbox(
        "Select Classification Engine:",
        engine_opts,
        index=engine_opts.index(st.session_state.engine_choice) if st.session_state.engine_choice in engine_opts else 0,
    )

    st.markdown("---")
    st.markdown("#### 3. Agent Execution Engine")
    st.session_state.use_llm = st.toggle(
        "Enable Real LLM Agent (meta-llama/llama-3.1-8b-instruct via OpenRouter)",
        value=st.session_state.use_llm,
        help="Enable live Llama 3.1 8B execution. Disable for deterministic zero-latency scripted execution.",
    )

    st.markdown("---")
    st.markdown("#### 4. Protected Asset Specification (System Canary)")
    st.caption("Confidential internal instruction and token embedded in the assistant context:")
    st.code(system_prompt(DEFAULT_CANARY), language="text")

    st.markdown("---")
    st.markdown(f"#### 5. Documentation Server Content (http://{WIKI_HOST}:{WIKI_PORT}/wiki/open-banking)")
    col_w1, col_w2 = st.columns(2)
    with col_w1:
        if st.button("Load Poisoned Webpage (With Injection Directive)", use_container_width=True):
            set_current_wiki_content(POISONED_ARTICLE)
            st.session_state.wiki_content = POISONED_ARTICLE
            st.success("Poisoned documentation loaded onto local server.")
            st.rerun()
    with col_w2:
        if st.button("Load Baseline Documentation (Clean)", use_container_width=True):
            set_current_wiki_content(CLEAN_ARTICLE)
            st.session_state.wiki_content = CLEAN_ARTICLE
            st.success("Clean documentation loaded onto local server.")
            st.rerun()

    st.text_area("Live content served by documentation daemon:", value=get_current_wiki_content(), height=150, disabled=True)
