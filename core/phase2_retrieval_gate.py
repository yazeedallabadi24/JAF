"""Hop 2: retrieval gate. Defends against indirect prompt injection (IPI).

Untrusted content (web pages, documents, tool output) is split into chunks. Each chunk
is classified; injected chunks are cut out and replaced with a marker, so the agent keeps
the legitimate information and never reads the attacker's instructions.
"""

from __future__ import annotations

import re
import time
from concurrent.futures import ThreadPoolExecutor

from .config import Settings
from .jev_client import DecisionEngine
from .policy import evaluate_text
from .verdict import Action, Category, Finding, Hop, Verdict

REMOVED_MARKER = "[JAF: untrusted instructions removed from this content]"
MAX_CHUNK_CHARS = 2000
MAX_CHUNKS = 32
_PARAGRAPHS = re.compile(r"\n\s*\n")
# Bracketed blocks such as "[SYSTEM DIRECTIVE: ...]" are isolated so they can be cut
# without losing the paragraph around them.
_BRACKET_BLOCK = re.compile(r"(\[[^\[\]]{20,}\])", re.DOTALL)


def split_chunks(content: str) -> list[str]:
    chunks: list[str] = []
    for para in _PARAGRAPHS.split(content):
        for piece in _BRACKET_BLOCK.split(para):
            piece = piece.strip()
            while len(piece) > MAX_CHUNK_CHARS:
                chunks.append(piece[:MAX_CHUNK_CHARS])
                piece = piece[MAX_CHUNK_CHARS:]
            if piece:
                chunks.append(piece)
    return chunks


def sanitize(content: str, settings: Settings, engine: DecisionEngine | None) -> Verdict:
    start = time.perf_counter()
    chunks = split_chunks(content)
    overflow = chunks[MAX_CHUNKS:]
    chunks = chunks[:MAX_CHUNKS]

    with ThreadPoolExecutor(max_workers=8) as pool:
        verdicts = list(
            pool.map(
                lambda c: evaluate_text(c, Hop.RETRIEVAL, settings, engine, Action.SANITIZE),
                chunks,
            )
        )

    kept: list[str] = []
    findings: list[Finding] = []
    worst = None
    removed = 0
    for idx, (chunk, verdict) in enumerate(zip(chunks, verdicts)):
        for f in verdict.findings:
            findings.append(f.model_copy(update={"detail": f"chunk {idx}: {f.detail}"}))
        if worst is None or verdict.score > worst.score:
            worst = verdict
        if verdict.action == Action.SANITIZE:
            removed += 1
            kept.append(REMOVED_MARKER)
        else:
            kept.append(chunk)

    if overflow:
        # Too long to inspect fully: fail safe by dropping the uninspected tail.
        findings.append(Finding(source="policy", detail=f"{len(overflow)} chunks over limit were dropped"))

    action = Action.SANITIZE if removed else (worst.action if worst else Action.ALLOW)
    cleaned = "\n\n".join(kept)
    return Verdict(
        hop=Hop.RETRIEVAL,
        action=action,
        category=worst.category if worst and action != Action.ALLOW else Category.NONE,
        score=worst.score if worst else 0.0,
        findings=findings,
        engine=worst.engine if worst else "rules",
        latency_ms=round((time.perf_counter() - start) * 1000, 2),
        enforced=settings.enforce,
        # Shadow mode reports what would be removed but hands back the original content.
        sanitized_text=cleaned if settings.enforce else content,
    )
