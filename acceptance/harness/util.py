"""Shared helpers: shell-free templating, synthetic canaries, scrubbing, JWT.

Nothing in this module talks to the network or spawns processes.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import uuid
from typing import Iterable, Mapping

# ``${NAME}`` placeholders inside fixture *source* files (rendered before the
# converter or an upstream product sees them).
SOURCE_PLACEHOLDER_RE = re.compile(r"\$\{([A-Z][A-Z0-9_]*)\}")

# ``{name}`` tokens inside argv / env templates. ``{{`` and ``}}`` are literal
# braces. Each argv element is expanded independently and the result is passed
# to ``subprocess`` as a list element, never to a shell, so substituted values
# cannot introduce new arguments or shell syntax.
_ARGV_TOKEN_RE = re.compile(r"\{\{|\}\}|\{([a-z][a-z0-9_]*)\}")


class TemplateError(ValueError):
    """A template referenced an unknown placeholder or produced unsafe output."""


def render_source(text: str, values: Mapping[str, object]) -> str:
    """Replace ``${NAME}`` tokens; refuse to leave any unknown token behind."""
    missing: set[str] = set()

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in values:
            missing.add(key)
            return match.group(0)
        return str(values[key])

    rendered = SOURCE_PLACEHOLDER_RE.sub(repl, text)
    if missing:
        raise TemplateError(f"unknown source placeholder(s): {', '.join(sorted(missing))}")
    return rendered


def source_placeholders(text: str) -> set[str]:
    return set(SOURCE_PLACEHOLDER_RE.findall(text))


def expand_token_string(element: str, values: Mapping[str, object]) -> str:
    if not isinstance(element, str):
        raise TemplateError("template elements must be strings")

    def repl(match: re.Match[str]) -> str:
        whole = match.group(0)
        if whole == "{{":
            return "{"
        if whole == "}}":
            return "}"
        key = match.group(1)
        if key not in values:
            raise TemplateError(f"unknown template placeholder {{{key}}}")
        return str(values[key])

    result = _ARGV_TOKEN_RE.sub(repl, element)
    if "\x00" in result:
        raise TemplateError("NUL byte in expanded template value")
    return result


def expand_argv(template: object, values: Mapping[str, object]) -> list[str]:
    """Expand a JSON argv template (list of strings) element by element."""
    if (
        not isinstance(template, list)
        or not template
        or not all(isinstance(item, str) for item in template)
    ):
        raise TemplateError("argv template must be a non-empty list of strings")
    return [expand_token_string(item, values) for item in template]


def expand_optional_argv(template: object, values: Mapping[str, object]) -> list[str]:
    if template in (None, []):
        return []
    return expand_argv(template, values)


def expand_env(template: object, values: Mapping[str, object]) -> dict[str, str]:
    if template in (None, {}):
        return {}
    if not isinstance(template, dict):
        raise TemplateError("env template must be an object of string values")
    out: dict[str, str] = {}
    for key, value in template.items():
        if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise TemplateError("env template keys must be plain variable names")
        out[key] = expand_token_string(value, values)
    return out


def parse_key_value(items: Iterable[str], what: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for item in items:
        if "=" not in item:
            raise TemplateError(f"{what} must be KEY=VALUE")
        key, value = item.split("=", 1)
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            raise TemplateError(f"{what} key is not a plain variable name")
        out[key] = value
    return out


class SyntheticCanaries:
    """Per-run synthetic credential material.

    These values are generated locally, are not real credentials, and exist
    only so the harness can prove that converter output, reports and logs do
    not repeat credential input. They are never printed.
    """

    BASIC_USER = "synthetic-acceptance-basic"

    def __init__(self) -> None:
        self.key = "synthetic-acceptance-key-" + secrets.token_hex(12)
        self.wrong_key = "synthetic-acceptance-wrong-" + secrets.token_hex(12)
        # Shaped like the 40-hex SHA-1 digest a decK dump carries for a Kong
        # basic-auth credential. It is random, so it is nobody's password.
        self.stored_hash = secrets.token_hex(20)
        token = base64.b64encode(f"{self.BASIC_USER}:{self.stored_hash}".encode()).decode()
        self.basic_hash_as_password = "Basic " + token
        self._basic_b64 = token

    def source_values(self) -> dict[str, str]:
        return {"CANARY_KEY": self.key, "CANARY_HASH": self.stored_hash}

    def header_values(self) -> dict[str, str]:
        return {
            "CANARY_KEY": self.key,
            "WRONG_KEY": self.wrong_key,
            "BASIC_HASH_AS_PASSWORD": self.basic_hash_as_password,
        }

    def by_name(self, name: str) -> str:
        mapping = {"CANARY_KEY": self.key, "CANARY_HASH": self.stored_hash}
        if name not in mapping:
            raise KeyError(name)
        return mapping[name]

    def all_sensitive(self) -> list[str]:
        return [self.key, self.wrong_key, self.stored_hash, self._basic_b64]


def scrub(text: str, sensitive: Iterable[str]) -> str:
    for value in sensitive:
        if value:
            text = text.replace(value, "<redacted>")
    return text


def tail(text: str, lines: int = 40, max_chars: int = 6000) -> str:
    out = "\n".join(text.splitlines()[-lines:])
    if len(out) > max_chars:
        out = out[-max_chars:]
    return out


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def mint_hs256_jwt(secret: str, issuer: str, ttl_seconds: int = 300, role: str = "admin") -> str:
    """Mint a short-lived admin JWT for the harness-owned gateway instance only."""
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "iss": issuer,
        "sub": "acceptance-harness",
        "role": role,
        "iat": now,
        "nbf": now,
        "exp": now + ttl_seconds,
        "jti": uuid.uuid4().hex,
    }
    signing_input = (
        _b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + _b64url(json.dumps(claims, separators=(",", ":")).encode())
    )
    signature = hmac.new(secret.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return signing_input + "." + _b64url(signature)


_LISTEN_PORT_RE = re.compile(r"""["']?\blisten_port\b["']?\s*:\s*["']?(\d+)""")


def declared_listen_ports(resources_text: str) -> set[int]:
    """Best-effort text scan for ``listen_port`` values (YAML or JSON)."""
    return {int(value) for value in _LISTEN_PORT_RE.findall(resources_text)}
