"""Layer 1: deterministic signatures. Sub-millisecond, explainable, no network.

Rules catch the obvious, well-known attacks so Jev only sees the ambiguous rest.
Each rule has a stable id so blocks can be explained, tuned and appealed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .normalize import inspection_views
from .verdict import Category, Finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    category: Category
    score: float  # >= block threshold means block without asking Jev
    pattern: re.Pattern[str]


def _r(rule_id: str, category: Category, score: float, pattern: str) -> Rule:
    return Rule(rule_id, category, score, re.compile(pattern, re.IGNORECASE))


RULES: list[Rule] = [
    # Instruction override
    _r("INJ-001", Category.PROMPT_INJECTION, 0.95,
       r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|your)\b.{0,20}"
       r"\b(instructions?|rules?|directives?|prompts?|guidelines?)\b"),
    _r("INJ-002", Category.PROMPT_INJECTION, 0.9,
       r"\[\s*(system|admin|developer)\s*(directive|override|message|instruction)s?\s*[:\]]"),
    _r("INJ-003", Category.PROMPT_INJECTION, 0.7,
       r"\b(new|updated|real)\s+(instructions?|system prompt)\s*[:\-]"),
    _r("INJ-004", Category.PROMPT_INJECTION, 0.8,
       r"\bdo not (tell|disclose|inform|mention).{0,30}\b(user|anyone|human)\b"),
    # Jailbreak personas
    _r("JB-001", Category.JAILBREAK, 0.9,
       r"\b(DAN|do anything now|developer mode|jailbroken|AIM mode|unfiltered mode)\b"),
    _r("JB-002", Category.JAILBREAK, 0.6,
       r"\b(pretend|act|roleplay|role-play)\b.{0,40}\b(no|without)\b.{0,20}"
       r"\b(restrictions|rules|limits|filters|guidelines)\b"),
    # System prompt extraction
    _r("SPE-001", Category.SYSTEM_PROMPT_EXTRACTION, 0.85,
       r"\b(reveal|print|show|repeat|output|leak|tell me)\b.{0,40}\b(system prompt|initial instructions|"
       r"hidden instructions|canary|secret (key|flag|token))\b"),
    # Exfiltration instructions (typical in indirect injection)
    _r("EXF-001", Category.DATA_EXFILTRATION, 0.95,
       r"\b(base64|encode|hex)\b.{0,60}\b(system prompt|secret|canary|api key|credentials?)\b"),
    _r("EXF-002", Category.DATA_EXFILTRATION, 0.9,
       r"\b(call|send|post|request|fetch|visit)\b.{0,60}https?://\S+\?\S*=\s*<"),
    _r("INJ-005", Category.PROMPT_INJECTION, 0.85,
       r"\b(ignore|disregard)\s+(the|everything|all)\s+(above|before)\b"),
    # Content addressing the AI directly is a strong IPI signal in retrieved documents.
    _r("IPI-001", Category.PROMPT_INJECTION, 0.75,
       r"\b(to|for)\s+(any|all|the)?\s*(ai|ais|assistants?|llms?|chatbots?|language models?)\b.{0,40}"
       r"\b(reading|summari[sz]ing|processing|parsing)\b"),
    # Arabic instruction override: "تجاهل التعليمات السابقة" (ignore previous instructions)
    _r("INJ-AR-001", Category.PROMPT_INJECTION, 0.9,
       r"(تجاهل|انس|أهمل).{0,30}(التعليمات|الأوامر|القواعد)"),
    # Arabic "no restrictions / no rules" persona framing
    _r("JB-AR-001", Category.JAILBREAK, 0.7, r"(بلا|بدون)\s+(قيود|قواعد)"),
]


def scan(text: str) -> list[Finding]:
    """Run every rule against every view (normalized + decoded payloads) of the text."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for i, view in enumerate(inspection_views(text)):
        for rule in RULES:
            if rule.rule_id in seen:
                continue
            match = rule.pattern.search(view)
            if match:
                seen.add(rule.rule_id)
                where = "decoded base64 payload" if i > 0 else "text"
                findings.append(
                    Finding(
                        source="rule",
                        rule_id=rule.rule_id,
                        category=rule.category,
                        score=rule.score,
                        detail=f"matched in {where}: {match.group(0)[:80]!r}",
                    )
                )
    return findings
