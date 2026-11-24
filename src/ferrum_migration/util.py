"""Shared helpers: identifiers, hosts, paths, regexes, durations, sizes, URLs, CIDRs.

Validation rules mirror Ferrum Edge admission (``src/config/types.rs`` and
``docs/request_path_canonicalization.md`` at the reference commit). They are
conservative: anything this module cannot prove Ferrum accepts is reported as a
problem so the caller can refuse it instead of emitting an invalid route.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
from urllib.parse import urlsplit

VALID_HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT")
MAX_ID_LENGTH = 254
MAX_NAME_LENGTH = 255
MAX_LISTEN_PATH_LENGTH = 500
MAX_BACKEND_PATH_LENGTH = 2048
MAX_HOSTS_PER_PROXY = 100
MAX_TARGETS_PER_UPSTREAM = 1000
MAX_TARGET_WEIGHT = 65_535
MAX_TIMEOUT_MS = 86_400_000
MAX_RETRIES = 100
MAX_REGEX_LENGTH = 1024

_HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_WILDCARD_RE = re.compile(r"^\*\.[a-z0-9]([a-z0-9.-]*[a-z0-9])?$")
_SLUG_RE = re.compile(r"[^a-z0-9]+")
_PATH_EXTRA = set("-._~!$&'()*+,;=:@/")


# ---------------------------------------------------------------- identifiers

def short_hash(*parts: object) -> str:
    digest = hashlib.sha256("\x1f".join(str(part) for part in parts).encode("utf-8")).hexdigest()
    return digest[:8]


def slugify(text: object, max_len: int = 48) -> str:
    slug = _SLUG_RE.sub("-", str(text).lower()).strip("-")
    if len(slug) > max_len:
        slug = slug[:max_len].rstrip("-")
    return slug or "x"


def make_id(*parts: object) -> str:
    """Deterministic Ferrum resource id: ``^[a-zA-Z0-9][a-zA-Z0-9._-]*$``."""
    raw = "-".join(slugify(part) for part in parts if part not in (None, ""))
    if not raw:
        raw = "x"
    if len(raw) > 200:
        raw = raw[:190].rstrip("-") + "-" + short_hash(*parts)
    return raw


class IdAllocator:
    """Hands out unique ids per resource type, in call order (deterministic)."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def take(self, *parts: object) -> str:
        base = make_id(*parts)
        candidate = base
        counter = 2
        while candidate in self._used:
            candidate = f"{base}-{counter}"
            counter += 1
        self._used.add(candidate)
        return candidate


# ---------------------------------------------------------------------- hosts

def normalize_host(raw: object) -> str | None:
    """Ferrum proxy ``hosts`` entry: lowercase DNS name or ``*.suffix`` wildcard."""
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower()
    if host.endswith(".") and not host.endswith(".."):
        host = host[:-1]
    if not host or len(host) > 253 or ".." in host:
        return None
    if _WILDCARD_RE.match(host) or _HOST_RE.match(host):
        return host
    return None


def normalize_backend_host(raw: object) -> str | None:
    """Backend host: DNS name or IP literal (IPv6 without brackets)."""
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253 or ".." in host or "*" in host:
        return None
    return host if _HOST_RE.match(host) else None


def split_host_port(text: str, default_port: int) -> tuple[str, int] | None:
    """Split ``host``, ``host:port``, ``[v6]`` or ``[v6]:port``."""
    if not isinstance(text, str) or not text:
        return None
    text = text.strip()
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None
        host = text[1:end]
        rest = text[end + 1:]
        if rest == "":
            return host, default_port
        if not rest.startswith(":"):
            return None
        port = parse_port(rest[1:])
        return (host, port) if port else None
    if text.count(":") == 1:
        host, _, port_text = text.partition(":")
        port = parse_port(port_text)
        return (host, port) if port and host else None
    if ":" in text:  # bare IPv6 without brackets
        return (text, default_port)
    return (text, default_port)


def parse_port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        port = value
    elif isinstance(value, str) and value.isdigit() and len(value) <= 5:
        port = int(value)
    else:
        return None
    return port if 1 <= port <= 65535 else None


def as_int(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


# ---------------------------------------------------------------------- paths

def canonical_path_problem(path: object) -> str | None:
    """Return why ``path`` is not a canonical Ferrum literal listen path, or None."""
    if not isinstance(path, str) or not path.startswith("/"):
        return "must start with '/'"
    if len(path) > MAX_LISTEN_PATH_LENGTH:
        return "longer than 500 bytes"
    for char in path:
        code = ord(char)
        if code < 0x21 or code > 0x7E:
            return "contains whitespace, control or non-ASCII characters"
        if not (char.isalnum() or char in _PATH_EXTRA):
            return "contains characters outside the canonical path alphabet"
    if "%" in path:
        return "contains percent-escapes (Ferrum canonicalizes request paths before routing)"
    if ";" in path:
        return "contains ';' path parameters"
    segments = path.split("/")[1:]
    for index, segment in enumerate(segments):
        if segment in (".", ".."):
            return "contains dot segments"
        if segment == "" and index != len(segments) - 1:
            return "contains empty segments ('//')"
    return None


# --------------------------------------------------------------------- regex

_REGEX_UNSUPPORTED = ("(?=", "(?!", "(?<=", "(?<!", "(?>", "(?#", "(?|", "(?R", "(?&", "(?P=",
                      "\\G", "\\K", "\\Z", "\\k<", "\\k{", "\\g")
_BACKREF = re.compile(r"\\[1-9]")
_POSSESSIVE = re.compile(r"(?<!\\)[*+?}]\+")


def regex_problem(pattern: object) -> str | None:
    """Conservative check that ``pattern`` is accepted by Ferrum's Rust regex engine."""
    if not isinstance(pattern, str) or not pattern:
        return "empty regex"
    if len(pattern) > MAX_REGEX_LENGTH:
        return "regex longer than 1024 bytes"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in pattern):
        return "regex contains control characters"
    if "%" in pattern:
        return "regex contains percent-escapes, which never match canonical request paths"
    if any(token in pattern for token in _REGEX_UNSUPPORTED) or _BACKREF.search(pattern) \
            or _POSSESSIVE.search(pattern):
        return "regex uses lookaround, backreferences or other features the Rust regex engine lacks"
    try:
        re.compile(pattern)
    except re.error:
        return "regex does not compile"
    return None


def regex_literal_prefix(pattern: str) -> str:
    """Literal text every match must start with (pattern is anchored at the start)."""
    text = pattern[1:] if pattern.startswith("^") else pattern
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == "\\":
            if index + 1 < len(text) and text[index + 1] in "/.-_~:@!$&'*+,;=?#[](){}|^":
                following = text[index + 2] if index + 2 < len(text) else ""
                if following in ("*", "?", "{"):
                    break
                out.append(text[index + 1])
                index += 2
                continue
            break
        if char in ".^$*+?()[]{}|":
            if char in "*?{" and out:
                out.pop()
            break
        following = text[index + 1] if index + 1 < len(text) else ""
        if following in ("*", "?", "{"):
            break
        out.append(char)
        index += 1
    return "".join(out)


def has_top_level_alternation(pattern: str) -> bool:
    depth = 0
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "]":
                in_class = False
        elif char == "[":
            in_class = True
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


# ------------------------------------------------------------ durations/sizes

_GO_DURATION = re.compile(r"^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$")
_GO_PART = re.compile(r"(\d+(?:\.\d+)?)(ns|us|µs|ms|s|m|h)")
_GO_UNIT_MS = {"ns": 1e-6, "us": 1e-3, "µs": 1e-3, "ms": 1.0, "s": 1000.0, "m": 60_000.0, "h": 3_600_000.0}


def parse_go_duration_ms(value: object) -> int | None:
    """Go/Traefik/Istio style durations (``1m30s``, ``500ms``, ``1.5s``); bare numbers are seconds."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(round(float(value) * 1000)) if value >= 0 else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.replace(".", "", 1).isdigit():
        return int(round(float(text) * 1000))
    if not _GO_DURATION.match(text):
        return None
    total = sum(float(number) * _GO_UNIT_MS[unit] for number, unit in _GO_PART.findall(text))
    return int(round(total))


def proto_duration_ms(value: object) -> int | None:
    """protobuf JSON Duration (``"15s"``, ``"0.25s"``) or ``{seconds, nanos}``."""
    if isinstance(value, dict):
        seconds = as_int(value.get("seconds", 0)) or 0
        nanos = as_int(value.get("nanos", 0)) or 0
        return seconds * 1000 + nanos // 1_000_000
    if isinstance(value, str):
        match = re.fullmatch(r"(\d+(?:\.\d+)?)s", value.strip())
        if match:
            return int(round(float(match.group(1)) * 1000))
        return parse_go_duration_ms(value)
    return None


_NGINX_TIME = re.compile(r"^(?:\d+(?:ms|s|m|h|d|w|M|y)?)+$")
_NGINX_TIME_PART = re.compile(r"(\d+)(ms|s|m|h|d|w|M|y)?")
_NGINX_TIME_MS = {"ms": 1, "s": 1000, None: 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000,
                  "w": 604_800_000, "M": 2_592_000_000, "y": 31_536_000_000}


def parse_nginx_time_ms(value: object) -> int | None:
    if not isinstance(value, str) or not _NGINX_TIME.match(value.strip()):
        return None
    total = 0
    for number, unit in _NGINX_TIME_PART.findall(value.strip()):
        total += int(number) * _NGINX_TIME_MS[unit or None]
    return total


def parse_nginx_size(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(\d+)([kKmMgG]?)", value.strip())
    if not match:
        return None
    factor = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[match.group(2).lower()]
    return int(match.group(1)) * factor


# ----------------------------------------------------------------------- URLs

class UrlProblem(ValueError):
    """A backend URL that cannot be represented. Message is value-free."""


def split_url(url: object, default_ports: dict[str, int]) -> tuple[str, str, int, str]:
    """Return ``(scheme, host, port, path)``; rejects userinfo, query and fragment."""
    if not isinstance(url, str) or not url or any(ch.isspace() for ch in url):
        raise UrlProblem("URL is empty or contains whitespace")
    try:
        parts = urlsplit(url)
    except ValueError:
        raise UrlProblem("URL cannot be parsed") from None
    scheme = parts.scheme.lower()
    if scheme not in default_ports:
        raise UrlProblem("URL scheme is not supported")
    if "@" in parts.netloc:
        raise UrlProblem("URL embeds user credentials; refused")
    try:
        port = parts.port
    except ValueError:
        raise UrlProblem("URL port is invalid") from None
    host = parts.hostname
    if not host:
        raise UrlProblem("URL has no host")
    if parts.query or parts.fragment:
        raise UrlProblem("URL query strings and fragments are not supported")
    return scheme, host, port or default_ports[scheme], parts.path or ""


# ---------------------------------------------------------------------- CIDRs

def canonical_cidr(text: object) -> str | None:
    if not isinstance(text, str):
        return None
    value = text.strip()
    try:
        if "/" in value:
            return str(ipaddress.ip_network(value, strict=False))
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


# -------------------------------------------------------------------- weights

def scale_shares(shares: list[float]) -> tuple[list[int], bool]:
    """Integer target weights (1..1000) for traffic shares; flags lossy rounding."""
    top = max(shares)
    weights = [max(1, int(round(share / top * 1000))) for share in shares]
    total_w = sum(weights)
    total_s = sum(shares)
    approximate = any(abs(w / total_w - s / total_s) > 0.005 for w, s in zip(weights, shares))
    return weights, approximate


def clamp_timeout(value: int | None) -> tuple[int | None, bool]:
    if value is None:
        return None, False
    if value <= 0:
        return None, False
    if value > MAX_TIMEOUT_MS:
        return MAX_TIMEOUT_MS, True
    return value, False
