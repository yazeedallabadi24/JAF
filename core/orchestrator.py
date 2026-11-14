"""Single entry point that wires the three hops together.

    jaf = Firewall()                         # reads settings from env / .env
    jaf.check_ingress(user_prompt)           # Hop 1
    safe_text = jaf.filter_retrieval(page)   # Hop 2
    jaf.check_egress(url)                    # Hop 3, raises Blocked before the request
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable

from .config import Settings
from .jev_client import DecisionEngine, JevClient
from .phase1_direct_ingress import inspect_prompt
from .phase2_retrieval_gate import sanitize
from .phase3_egress_firewall import inspect_request
from .verdict import Action, Verdict

log = logging.getLogger("jaf")


class Blocked(Exception):
    def __init__(self, verdict: Verdict):
        self.verdict = verdict
        strongest = max(verdict.findings, key=lambda f: f.score, default=None)
        top = (strongest.rule_id or strongest.source) if strongest else verdict.category.value
        super().__init__(f"JAF blocked {verdict.hop.value} ({verdict.category.value}, {top})")


class Firewall:
    def __init__(
        self,
        settings: Settings | None = None,
        engine: DecisionEngine | None = None,
        on_verdict: Callable[[Verdict], None] | None = None,
    ):
        self.settings = settings or Settings()
        if engine is None and self.settings.jev_enabled:
            engine = JevClient(self.settings)
        self.engine = engine
        self.on_verdict = on_verdict

    def _emit(self, verdict: Verdict) -> Verdict:
        # Log decisions, never raw text: prompts may contain PII and secrets.
        log.info(
            json.dumps(
                {
                    "hop": verdict.hop.value,
                    "action": verdict.action.value,
                    "category": verdict.category.value,
                    "score": verdict.score,
                    "engine": verdict.engine,
                    "enforced": verdict.enforced,
                    "rules": [f.rule_id for f in verdict.findings if f.rule_id],
                    "latency_ms": verdict.latency_ms,
                }
            )
        )
        if self.on_verdict:
            self.on_verdict(verdict)
        return verdict

    def inspect_ingress(self, text: str) -> Verdict:
        return self._emit(inspect_prompt(text, self.settings, self.engine))

    def inspect_retrieval(self, content: str) -> Verdict:
        return self._emit(sanitize(content, self.settings, self.engine))

    def inspect_egress(self, url: str, method: str = "GET", body: str | None = None) -> Verdict:
        return self._emit(inspect_request(url, self.settings, method, body))

    # Convenience wrappers for agents: raise or return the safe value.
    def check_ingress(self, text: str) -> Verdict:
        verdict = self.inspect_ingress(text)
        if verdict.blocked:
            raise Blocked(verdict)
        return verdict

    def filter_retrieval(self, content: str) -> str:
        verdict = self.inspect_retrieval(content)
        return verdict.sanitized_text if verdict.sanitized_text is not None else content

    def check_egress(self, url: str, method: str = "GET", body: str | None = None) -> Verdict:
        verdict = self.inspect_egress(url, method, body)
        if verdict.enforced and verdict.action == Action.BLOCK:
            raise Blocked(verdict)
        return verdict
