"""Streamlit demo dashboard.

    python -m c2_server.c2_listener     # terminal 1 (dummy attacker)
    streamlit run ui/app.py             # terminal 2
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from agent.agent_runner import DEFAULT_CANARY, LLMAgent, ScriptedHijackedAgent  # noqa: E402
from c2_server.c2_listener import HITS_FILE  # noqa: E402
from core import Blocked, Firewall, Settings, Verdict  # noqa: E402
from ui.components import render_verdict  # noqa: E402

st.set_page_config(page_title="JAF - Jev Agent Firewall", layout="wide")
st.title("JAF: Jev Agent Firewall")

MODES = {
    "0. Unprotected": ("unprotected", False),
    "1. Full protection (Phase 2 sanitizes)": ("protected", False),
    "2. Phase 2 bypassed (Phase 3 circuit breaker)": ("protected", True),
}

with st.sidebar:
    mode_label = st.radio("Protection mode", list(MODES))
    use_llm = st.toggle("Use real LLM agent (needs OPENROUTER_API_KEY)", value=False)
    st.caption("Scripted agent = deterministic hijacked model, no API key needed.")
    if st.button("Clear C2 log"):
        HITS_FILE.unlink(missing_ok=True)

tab_attack, tab_try = st.tabs(["Attack demo", "Try a prompt"])

with tab_attack:
    st.write("Task: *Research modern Open Banking API standards and summarize them.* "
             "The retrieved page contains a hidden indirect-injection payload.")
    if st.button("Run agent", type="primary"):
        mode, bypass = MODES[mode_label]
        verdicts: list[Verdict] = []
        firewall = None
        if mode == "protected":
            settings = Settings()
            settings.mode = "enforce"
            settings.canary_tokens = settings.canary_tokens or [DEFAULT_CANARY]
            firewall = Firewall(settings, on_verdict=verdicts.append)
        agent_cls = LLMAgent if use_llm else ScriptedHijackedAgent
        try:
            output = agent_cls(firewall, bypass_phase2=bypass).run(
                "Research modern Open Banking API standards and summarize them."
            )
            st.success("Agent finished")
            st.text(output)
        except Blocked as exc:
            st.error(f"Circuit breaker: {exc}")
        except Exception as exc:  # demo UI: surface any error (e.g. C2 listener not running)
            st.warning(f"Agent error: {exc}")
        for v in verdicts:
            render_verdict(v)

    st.subheader("Attacker C2 listener (127.0.0.1:8765)")
    hits = [json.loads(l) for l in HITS_FILE.read_text().splitlines()] if HITS_FILE.exists() else []
    if hits:
        st.error(f"BREACH: {len(hits)} packet(s) received")
        for h in hits[-5:]:
            st.json(h["decoded"])
    else:
        st.success("0 packets received")

with tab_try:
    hop = st.selectbox("Hop", ["ingress", "retrieval", "egress"])
    text = st.text_area("Prompt, page content, or URL", height=150)
    if st.button("Inspect") and text:
        fw = Firewall()
        if hop == "ingress":
            render_verdict(fw.inspect_ingress(text))
        elif hop == "retrieval":
            v = fw.inspect_retrieval(text)
            render_verdict(v)
            st.text_area("Sanitized output", v.sanitized_text or "", height=150)
        else:
            render_verdict(fw.inspect_egress(text))
