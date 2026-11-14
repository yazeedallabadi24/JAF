"""Hop 1: direct ingress. Inspect what a user sends before the agent sees it."""

from __future__ import annotations

from .config import Settings
from .jev_client import DecisionEngine
from .policy import evaluate_text
from .verdict import Action, Hop, Verdict


def inspect_prompt(text: str, settings: Settings, engine: DecisionEngine | None) -> Verdict:
    return evaluate_text(text, Hop.INGRESS, settings, engine, malicious_action=Action.BLOCK)
