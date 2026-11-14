"""Shared fixtures. Tests never call the network: Jev is replaced by a fake engine."""

from __future__ import annotations

import pytest

from core.config import Settings
from core.jev_client import JevDecision, JevUnavailable
from core.verdict import Category, Hop

CANARY = "FLAG_BLDR_AMMAN_2026_SECRET_SYSTEM_CANARY_X99"


class FakeJev:
    """Scores text by keyword so tests are deterministic. Records every call."""

    def __init__(self, attack_words=("exfiltrate", "hidden agenda", "bypass"), p_attack=0.97):
        self.attack_words = attack_words
        self.p_attack = p_attack
        self.calls: list[tuple[str, Hop]] = []

    def classify(self, text: str, hop: Hop) -> JevDecision:
        self.calls.append((text, hop))
        if any(w in text.lower() for w in self.attack_words):
            return JevDecision(p_attack=self.p_attack, category=Category.PROMPT_INJECTION, model="fake")
        return JevDecision(p_attack=0.02, category=Category.NONE, model="fake")


class DownJev:
    def classify(self, text: str, hop: Hop) -> JevDecision:
        raise JevUnavailable("simulated outage")


@pytest.fixture
def settings() -> Settings:
    return Settings(
        openrouter_api_key="",
        mode="enforce",
        fail_mode="open",
        egress_allowlist=["api.openbanking.example", "openrouter.ai"],
        canary_tokens=[CANARY],
    )


@pytest.fixture
def fake_jev() -> FakeJev:
    return FakeJev()
