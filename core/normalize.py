"""Text normalization: undo the tricks attackers use to slip past pattern matching."""

from __future__ import annotations

import base64
import binascii
import math
import re
import unicodedata
from collections import Counter

# Zero-width and bidi control characters used to split keywords ("ig​nore").
_INVISIBLE = re.compile("[​-‏‪-‮⁠-⁤﻿­]")
_B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_WS = re.compile(r"\s+")


def normalize(text: str) -> str:
    """NFKC-fold (full-width / look-alike forms), drop invisible chars, collapse whitespace."""
    text = unicodedata.normalize("NFKC", text)
    text = _INVISIBLE.sub("", text)
    return _WS.sub(" ", text).strip()


def try_b64decode(blob: str) -> str | None:
    """Decode a base64 / base64url blob into printable text, or return None."""
    padded = blob + "=" * (-len(blob) % 4)
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            raw = decoder(padded)
        except (binascii.Error, ValueError):
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(ch.isprintable() or ch.isspace() for ch in decoded)
        if decoded and printable / len(decoded) > 0.9:
            return decoded
    return None


def decoded_payloads(text: str) -> list[str]:
    """Return any readable base64 payloads hidden inside the text."""
    found = []
    for match in _B64_CANDIDATE.findall(text):
        decoded = try_b64decode(match)
        if decoded and len(decoded) >= 8:
            found.append(decoded)
    return found


def shannon_entropy(value: str) -> float:
    """Bits per character. English prose ~4.0; base64/random tokens ~5.5-6.0."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def inspection_views(text: str) -> list[str]:
    """Every view of the text a gate should scan: normalized form plus decoded payloads."""
    norm = normalize(text)
    return [norm, *decoded_payloads(norm)]
