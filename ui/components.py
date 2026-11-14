"""Reusable Streamlit widgets."""

from __future__ import annotations

import streamlit as st

from core import Action, Verdict

_TAG = {
    Action.ALLOW: "[ALLOW]",
    Action.FLAG: "[FLAG]",
    Action.SANITIZE: "[SANITIZE]",
    Action.BLOCK: "[BLOCK]",
}


def render_verdict(v: Verdict) -> None:
    shadow = "" if v.enforced else " (shadow: not enforced)"
    with st.container(border=True):
        st.markdown(
            f"**{_TAG[v.action]} {v.hop.value.upper()}** → **{v.action.value.upper()}**{shadow} | "
            f"Category: `{v.category.value}` | Score: `{v.score:.2f}` | Engine: `{v.engine}` | "
            f"Latency: `{v.latency_ms:.1f} ms`"
        )
        for f in v.findings:
            st.caption(f"{f.source.upper()} {f.rule_id or ''} (Score: {f.score:.2f}): {f.detail}")
