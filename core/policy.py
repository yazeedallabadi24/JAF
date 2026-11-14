"""Turns rule findings + a Jev decision into one verdict. Shared by the ingress and retrieval gates."""

from __future__ import annotations

import time

from .config import Settings
from .jev_client import DecisionEngine, JevUnavailable
from .rules import scan
from .verdict import Action, Category, Finding, Hop, Verdict


def evaluate_text(
    text: str,
    hop: Hop,
    settings: Settings,
    engine: DecisionEngine | None,
    malicious_action: Action = Action.BLOCK,
) -> Verdict:
    """Rules first; ask Jev only when rules alone are not conclusive."""
    start = time.perf_counter()
    findings = scan(text)
    top_rule = max(findings, key=lambda f: f.score, default=None)

    def done(action: Action, category: Category, score: float, engine_name: str) -> Verdict:
        return Verdict(
            hop=hop,
            action=action,
            category=category,
            score=round(score, 4),
            findings=findings,
            engine=engine_name,
            latency_ms=round((time.perf_counter() - start) * 1000, 2),
            enforced=settings.enforce,
        )

    # 1. A high-confidence signature is enough on its own: no API call, no cost.
    if top_rule and top_rule.score >= settings.block_threshold:
        return done(malicious_action, top_rule.category, top_rule.score, "rules")

    # 2. Ask Jev.
    if engine is not None:
        try:
            decision = engine.classify(text, hop)
        except JevUnavailable as exc:
            findings.append(Finding(source="jev", detail=f"unavailable, fell back to rules: {exc}"))
        else:
            findings.append(
                Finding(
                    source="jev",
                    category=decision.category,
                    score=decision.p_attack,
                    detail=f"model={decision.model} p_attack={decision.p_attack:.3f} "
                    f"latency={decision.latency_ms:.0f}ms cost={decision.cost_usd}",
                )
            )
            # Rules and Jev vote; the stronger signal wins.
            score = max(decision.p_attack, top_rule.score if top_rule else 0.0)
            category = decision.category
            if category == Category.NONE and top_rule:
                category = top_rule.category
            if category == Category.NONE and score >= settings.flag_threshold:
                category = Category.PROMPT_INJECTION
            if score >= settings.block_threshold:
                return done(malicious_action, category, score, "jev")
            if score >= settings.flag_threshold:
                return done(Action.FLAG, category, score, "jev")
            return done(Action.ALLOW, Category.NONE, score, "jev")

    # 3. No Jev (not configured or down): decide on rules alone.
    if top_rule and top_rule.score >= settings.flag_threshold:
        return done(Action.FLAG, top_rule.category, top_rule.score, "rules-fallback")
    if engine is not None and settings.fail_mode == "closed":
        findings.append(Finding(source="policy", detail="fail-closed: Jev unavailable"))
        return done(malicious_action, Category.NONE, 1.0, "rules-fallback")
    return done(Action.ALLOW, Category.NONE, top_rule.score if top_rule else 0.0, "rules-fallback")
