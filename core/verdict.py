"""Shared verdict types returned by every JAF gate."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Action(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    SANITIZE = "sanitize"
    BLOCK = "block"


class Hop(str, Enum):
    INGRESS = "ingress"
    RETRIEVAL = "retrieval"
    EGRESS = "egress"


class Category(str, Enum):
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    DATA_EXFILTRATION = "data_exfiltration"
    HARMFUL_REQUEST = "harmful_request"


class Finding(BaseModel):
    """One reason behind a verdict (a rule hit or a model decision)."""

    source: str  # "rule", "jev", "egress"
    rule_id: str | None = None
    category: Category = Category.NONE
    score: float = 0.0
    detail: str = ""


class Verdict(BaseModel):
    hop: Hop
    action: Action
    category: Category = Category.NONE
    score: float = Field(0.0, ge=0.0, le=1.0)
    findings: list[Finding] = Field(default_factory=list)
    engine: str = "rules"  # rules | jev | rules-fallback | deterministic
    latency_ms: float = 0.0
    enforced: bool = True  # False in shadow mode: the action is logged, not applied
    sanitized_text: str | None = None  # retrieval gate output

    @property
    def blocked(self) -> bool:
        return self.enforced and self.action == Action.BLOCK
