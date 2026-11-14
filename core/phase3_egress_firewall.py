"""Hop 3: egress firewall. Inspects every outbound tool call before the socket opens.

Deterministic and model-free on purpose: even if Hops 1 and 2 are bypassed, a hijacked
agent still cannot ship secrets out. Checks:
  EGR-SCHEME   non-http(s) scheme (file://, gopher://, ...)
  EGR-HOST     host not on the allowlist (when an allowlist is configured)
  EGR-PRIVATE  loopback / private / link-local address (SSRF and local C2)
  EGR-CANARY   a configured canary token appears anywhere, raw or decoded
  EGR-SECRET   API-key / private-key shaped strings
  EGR-B64      a parameter decodes from base64 into readable text
  EGR-ENTROPY  a long, high-entropy parameter value (encoded or encrypted blob)
"""

from __future__ import annotations

import ipaddress
import re
import time
from urllib.parse import parse_qsl, unquote, urlsplit

from .config import Settings
from .normalize import shannon_entropy, try_b64decode
from .rules import scan
from .verdict import Action, Category, Finding, Hop, Verdict

SECRET_PATTERNS = [
    re.compile(r"sk-or-v1-[A-Za-z0-9]{20,}"),
    re.compile(r"sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{20,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
]
ENTROPY_MIN_LEN = 24
ENTROPY_THRESHOLD = 4.5


def _host_allowed(host: str, allowlist: list[str]) -> bool:
    return any(host == a or host.endswith("." + a) for a in allowlist)


def _is_private(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved


def _values(url: str, body: str | None) -> list[str]:
    parts = urlsplit(url)
    values = [v for _, v in parse_qsl(parts.query, keep_blank_values=False)]
    values += [unquote(seg) for seg in parts.path.split("/") if seg]
    if parts.fragment:
        values.append(unquote(parts.fragment))
    if body:
        values.append(body)
        values += [v for _, v in parse_qsl(body)]
    return values


def inspect_request(
    url: str, settings: Settings, method: str = "GET", body: str | None = None
) -> Verdict:
    start = time.perf_counter()
    findings: list[Finding] = []

    def add(rule_id: str, score: float, detail: str, category=Category.DATA_EXFILTRATION):
        findings.append(Finding(source="egress", rule_id=rule_id, category=category, score=score, detail=detail))

    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    if parts.scheme not in {"http", "https"}:
        add("EGR-SCHEME", 1.0, f"scheme {parts.scheme!r} not allowed")
    allowlisted = bool(settings.egress_allowlist) and _host_allowed(host, settings.egress_allowlist)
    if settings.egress_allowlist and not allowlisted:
        add("EGR-HOST", 0.9, f"host {host!r} is not on the egress allowlist")
    if _is_private(host):
        add("EGR-PRIVATE", 0.7, f"host {host!r} is a private/loopback address")

    blob = unquote(url) + "\n" + (body or "")
    decoded_views: list[str] = []
    for value in _values(url, body):
        decoded = try_b64decode(value.strip()) if len(value) >= 16 else None
        if decoded:
            decoded_views.append(decoded)
            add("EGR-B64", 0.9, f"{method} parameter decodes from base64: {decoded[:60]!r}")
        elif not allowlisted and len(value) >= ENTROPY_MIN_LEN and shannon_entropy(value) >= ENTROPY_THRESHOLD:
            add("EGR-ENTROPY", 0.8, f"high-entropy value ({shannon_entropy(value):.2f} bits/char, len {len(value)})")

    for view in [blob, *decoded_views]:
        for token in settings.canary_tokens:
            if token and token in view:
                add("EGR-CANARY", 1.0, "canary token found in outbound request")
                break
        for pattern in SECRET_PATTERNS:
            if pattern.search(view):
                add("EGR-SECRET", 1.0, f"secret-shaped string ({pattern.pattern[:20]}...)")
                break
    for view in decoded_views:
        for f in scan(view):
            add(f"EGR-{f.rule_id}", f.score, f"decoded payload matches {f.rule_id}", f.category)

    # De-duplicate by rule id, keeping the strongest.
    best: dict[str, Finding] = {}
    for f in findings:
        if f.rule_id not in best or f.score > best[f.rule_id].score:
            best[f.rule_id] = f
    findings = sorted(best.values(), key=lambda f: f.score, reverse=True)

    score = max((f.score for f in findings), default=0.0)
    if score >= settings.block_threshold:
        action = Action.BLOCK
    elif score >= settings.flag_threshold:
        action = Action.FLAG
    else:
        action = Action.ALLOW
    top = max(findings, key=lambda f: f.score, default=None)
    return Verdict(
        hop=Hop.EGRESS,
        action=action,
        category=top.category if top and action != Action.ALLOW else Category.NONE,
        score=score,
        findings=findings,
        engine="deterministic",
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
        enforced=settings.enforce,
    )
