"""Runtime configuration, loaded from environment variables (.env supported)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass


def _env_list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except ValueError:
        return default


@dataclass
class Settings:
    openrouter_api_key: str = field(default_factory=lambda: os.getenv("OPENROUTER_API_KEY", ""))
    decisions_url: str = field(
        default_factory=lambda: os.getenv(
            "JEV_DECISIONS_URL", "https://openrouter.ai/api/alpha/decisions"
        )
    )
    # Pin a dated version in production so verdicts don't drift under you.
    jev_model: str = field(default_factory=lambda: os.getenv("JEV_MODEL", "typesafe/jev-1.13"))
    jev_timeout_s: float = field(default_factory=lambda: _env_float("JEV_TIMEOUT_S", 2.0))

    # shadow: log decisions, never block. enforce: apply decisions.
    mode: str = field(default_factory=lambda: os.getenv("JAF_MODE", "shadow").lower())
    # What to do when Jev is unreachable and rules found nothing: "open" allows, "closed" blocks.
    fail_mode: str = field(default_factory=lambda: os.getenv("JAF_FAIL_MODE", "open").lower())

    block_threshold: float = field(default_factory=lambda: _env_float("JAF_BLOCK_THRESHOLD", 0.8))
    flag_threshold: float = field(default_factory=lambda: _env_float("JAF_FLAG_THRESHOLD", 0.5))

    # Egress firewall
    egress_allowlist: list[str] = field(default_factory=lambda: _env_list("JAF_EGRESS_ALLOWLIST"))
    canary_tokens: list[str] = field(
        default_factory=lambda: [
            t.strip() for t in os.getenv("JAF_CANARY_TOKENS", "").split(",") if t.strip()
        ]
    )

    @property
    def enforce(self) -> bool:
        return self.mode == "enforce"

    @property
    def jev_enabled(self) -> bool:
        return bool(self.openrouter_api_key)
