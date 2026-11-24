"""Redaction helpers for diagnostics and report text.

Rules:

* Parser diagnostics keep positions and generic reasons but withhold every
  quoted span, because YAML/JSON/TOML error texts can echo document content.
* Names taken from the input (route names, hosts, header names) pass through
  :func:`safe_label`, which truncates them, strips control characters and
  withholds anything that looks like key material or a token.
* Credential values (API keys, secrets, password hashes, PEM bodies) are never
  passed to any of these helpers; callers count them instead.
"""

from __future__ import annotations

import re
from typing import Any

_QUOTED = re.compile(r"'[^'\n]*'|\"[^\"\n]*\"|`[^`\n]*`")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_PEM = re.compile(r"-----BEGIN [A-Z0-9 ]{1,40}-----")
_TOKENISH = re.compile(r"^[A-Za-z0-9+/=_.~-]{32,}$")


def sanitize_parser_message(message: Any, max_len: int = 160) -> str:
    """Return a parser error reason with every quoted span withheld."""
    text = "" if message is None else str(message)
    text = _QUOTED.sub("'<redacted>'", text)
    text = _CONTROL.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text or "invalid input"


def looks_secret(value: Any) -> bool:
    """Heuristic: PEM blocks and long unbroken token-like strings."""
    if not isinstance(value, str):
        return False
    if _PEM.search(value):
        return True
    if _TOKENISH.match(value):
        has_digit = any(ch.isdigit() for ch in value)
        has_alpha = any(ch.isalpha() for ch in value)
        separators = sum(value.count(ch) for ch in "-_.")
        return has_digit and has_alpha and separators <= len(value) // 16
    return False


def safe_label(value: Any, max_len: int = 96) -> str:
    """Render an input-derived name for a report or diagnostic."""
    if value is None:
        return "<unnamed>"
    text = value if isinstance(value, str) else str(value)
    if looks_secret(text):
        return "<redacted>"
    text = _CONTROL.sub("?", text)
    if len(text) > max_len:
        text = text[: max_len - 3] + "..."
    return text


def is_secret_reference(value: Any) -> bool:
    """Kong vault references (``{vault://...}``), anywhere inside the string."""
    return isinstance(value, str) and "{vault://" in value.lower()


def contains_secret_reference(obj: Any, budget: int = 200_000) -> bool:
    """True when any string inside ``obj`` is a secret reference."""
    stack = [obj]
    seen = 0
    while stack:
        seen += 1
        if seen > budget:
            return True  # fail closed on pathological structures
        item = stack.pop()
        if isinstance(item, str):
            if is_secret_reference(item):
                return True
        elif isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False
