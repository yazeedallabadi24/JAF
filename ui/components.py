"""Reusable Streamlit widgets."""

from __future__ import annotations

import streamlit as st

from core import Action, Verdict

_ICON = {Action.ALLOW: "🟢", Action.FLAG: "🟡", Action.SANITIZE: "🟠", Action.BLOCK: "🔴"}


def render_verdict(v: Verdict) -> None:
    shadow = "" if v.enforced else " (shadow: not enforced)"
    with st.container(border=True):
        st.markdown(
            f"{_ICON[v.action]} **{v.hop.value.upper()}** → **{v.action.value}**{shadow} · "
            f"category `{v.category.value}` · score `{v.score:.2f}` · engine `{v.engine}` · "
            f"`{v.latency_ms:.1f} ms`"
        )
        for f in v.findings:
            st.caption(f"{f.source} {f.rule_id or ''} ({f.score:.2f}): {f.detail}")
