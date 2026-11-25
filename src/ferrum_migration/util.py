"""Shared helpers: identifiers, hosts, paths, regexes, durations, sizes, URLs, CIDRs.

Validation rules mirror Ferrum Edge admission (``src/config/types.rs`` and
``docs/request_path_canonicalization.md`` at the reference commit). They are
conservative: anything this module cannot prove Ferrum accepts is reported as a
problem so the caller can refuse it instead of emitting an invalid route.
"""

from __future__ import annotations

import hashlib
from decimal import Decimal, DecimalException
import ipaddress
import math
import re
import warnings
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
MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES = 256
MAX_BACKEND_TLS_SAN_BYTES = 2048

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
    """Ferrum proxy ``hosts`` entry: lowercase DNS name or ``*.suffix`` wildcard (RFC 1123 labels)."""
    if not isinstance(raw, str):
        return None
    host = raw.strip().lower()
    if host.endswith(".") and not host.endswith(".."):
        host = host[:-1]
    if not host or len(host) > 253 or ".." in host or not host.isascii():
        return None
    body = host[2:] if host.startswith("*.") else host
    if not body:
        return None
    for label in body.split("."):
        if not 1 <= len(label) <= 63:
            return None
        if not (label[0].isalnum() and label[-1].isalnum()):
            return None
        if any(not (ch.isalnum() or ch == "-") for ch in label):
            return None
    return host


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
    elif isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 5:
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
    if isinstance(value, str):
        stripped = value.strip()
        body = stripped[1:] if stripped.startswith("-") else stripped
        if body and body.isascii() and body.isdigit():
            try:
                return int(stripped)
            except ValueError:
                return None
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

_RUST_REGEX_FLAGS = frozenset("imsURux")
_RUST_BRACE_QUANT = re.compile(r"\{(\d+)(?:,(\d*))?\}", re.ASCII)
_POSIX_CLASS_RE = re.compile(
    r"\[:\^?(?:alnum|alpha|ascii|blank|cntrl|digit|graph|lower|print|punct|space|upper|word|xdigit):\]",
    re.ASCII,
)
_UNICODE_CLASS_ESCAPES = frozenset("wWdDsSpP")
_RUST_CLASS_LETTER_ESCAPES = frozenset("aftnrvxuUpPdDsSwW")
_RUST_OUTER_LETTER_ESCAPES = _RUST_CLASS_LETTER_ESCAPES | frozenset("AzbB")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_HEX_ESCAPE_WIDTH = {"x": 2, "u": 4, "U": 8}
MAX_REGEX_EXPANDED_COST = 10_000
MAX_REGEX_GROUP_DEPTH = 48


def _rust_regex_syntax_problem(pattern: str) -> tuple[str | None, str]:
    """Scan escapes, braces, verbose comments, inline flags, nesting depth, and expanded repetition cost linearly.

    Returns ``(error_message, python_normalized_pattern)`` where valid POSIX classes inside ``[...]`` are replaced
    with ``0`` in ``python_normalized_pattern`` so Python's ``re.compile`` validates the exact same class boundaries
    and character ranges as Rust's ``regex-syntax``.
    """
    n = len(pattern)
    i = 0
    in_class = False
    # 0 = start of class / after a completed range or class atom (next '-' is literal),
    # 1 = after a single literal atom (next '-' starts a range),
    # 2 = immediately after '<literal>-' (expecting range RHS; POSIX class here diverges from Rust).
    class_state = 0
    class_cost = 0
    flag_stack: list[tuple[bool, bool]] = [(False, True)]  # (verbose_x, unicode_u)
    cost_stack: list[list[int]] = [[0, 0]]  # [group_total_cost, last_atom_cost]
    py_parts: list[str] = []

    def _charge(atom_cost: int) -> str | None:
        frame = cost_stack[-1]
        frame[0] += atom_cost
        frame[1] = atom_cost
        if frame[0] > MAX_REGEX_EXPANDED_COST:
            return "regex expanded repetition cost exceeds safe Rust regex compilation limit"
        return None

    def _push_group(flags: tuple[bool, bool]) -> str | None:
        if len(flag_stack) > MAX_REGEX_GROUP_DEPTH:
            return "regex group nesting depth exceeds safe Rust regex AST limit"
        flag_stack.append(flags)
        cost_stack.append([0, 0])
        return None

    while i < n:
        ch = pattern[i]
        x_on, u_on = flag_stack[-1]
        if ch == "\\":
            if i + 1 >= n:
                return "regex ends with a trailing backslash", ""
            nxt = pattern[i + 1]
            if "0" <= nxt <= "9":
                return "regex uses backreferences or octal escapes unsupported by the Rust regex engine", ""
            if not nxt.isascii() or nxt in ("<", ">"):
                return "regex uses escapes unsupported or parsed differently by the Rust regex engine", ""
            if nxt.isalpha():
                allowed = _RUST_CLASS_LETTER_ESCAPES if in_class else _RUST_OUTER_LETTER_ESCAPES
                if nxt not in allowed:
                    return "regex uses escapes unsupported by the Rust regex engine", ""
            step = 2
            if nxt in _HEX_ESCAPE_WIDTH:
                width = _HEX_ESCAPE_WIDTH[nxt]
                if i + 2 + width <= n and all(c in _HEX_DIGITS for c in pattern[i + 2:i + 2 + width]):
                    step = 2 + width
                else:
                    return "regex uses hex/unicode escape syntax not portable between Python and Rust regex", ""
            esc_cost = (100 if u_on else 4) if nxt in _UNICODE_CLASS_ESCAPES else 1
            if in_class:
                class_cost += esc_cost
                if nxt in _UNICODE_CLASS_ESCAPES:
                    if class_state == 2:
                        return "regex uses a character class escape as the end of a range", ""
                    # Rust rejects `[\w-a]` / `[\d-a]` as an invalid range endpoint (unlike POSIX `[[:digit:]-a]`);
                    # keeping class_state = 1 preserves the raw '-' so Python re.compile rejects it too.
                    class_state = 1
                else:
                    class_state = 0 if class_state == 2 else 1
            else:
                err = _charge(esc_cost)
                if err:
                    return err, ""
            py_parts.append(pattern[i:i + step])
            i += step
            continue
        if in_class:
            if ch == "[":
                pm = _POSIX_CLASS_RE.match(pattern, i)
                if pm is not None:
                    if class_state == 2:
                        return "regex uses a POSIX class as the end of a character range (diverges in Rust regex)", ""
                    class_cost += 4
                    class_state = 0
                    py_parts.append(r"\d")
                    i = pm.end()
                    continue
                return "regex uses unescaped '[' inside a character class (nested class syntax differs in Rust regex)", ""
            if i + 1 < n and pattern[i:i + 2] in ("&&", "--", "~~"):
                return ("regex uses '&&', '--', or '~~' inside a character class, which Rust regex parses as a "
                        "character-class set operator rather than literal characters"), ""
            if x_on and (ch == "#" or ch.isspace() or ch in ("\u200e", "\u200f")):
                return ("regex uses unescaped '#' or whitespace inside a character class under verbose (?x) mode, "
                        "which Rust regex parses differently from PCRE/Python"), ""
            if ch == "]":
                in_class = False
                class_state = 0
                err = _charge(max(2, class_cost))
                if err:
                    return err, ""
                py_parts.append(ch)
            else:
                py_parts.append(r"\-" if (ch == "-" and class_state == 0) else ch)
                if ch == "-" and class_state == 1:
                    class_state = 2
                elif class_state == 2:
                    class_state = 0
                else:
                    class_state = 0 if ch == "-" else 1
                class_cost += 1
            i += 1
            continue
        if x_on and ch == "#":
            nl = pattern.find("\n", i + 1)
            if nl == -1:
                py_parts.append(pattern[i:])
                break
            py_parts.append(pattern[i:nl + 1])
            i = nl + 1
            continue
        if x_on and ((not ch.isascii() and ch.isspace()) or ch in ("\u200e", "\u200f")):
            return ("regex uses non-ASCII Unicode whitespace under verbose (?x) mode, which Rust regex ignores "
                    "while PCRE/Python match literally"), ""
        if x_on and ch.isspace():
            py_parts.append(ch)
            i += 1
            continue
        if ch == "[":
            in_class = True
            class_state = 0
            class_cost = 0
            start_i = i
            i += 1
            if i < n and pattern[i] == "^":
                i += 1
            if i < n and pattern[i] == "]":
                class_cost += 1
                class_state = 1
                i += 1
            py_parts.append(pattern[start_i:i])
            continue
        if ch == "{":
            qm = _RUST_BRACE_QUANT.match(pattern, i)
            if qm is None:
                return "regex contains an unescaped '{' that is not a valid counted repetition in Rust regex", ""
            lo = int(qm.group(1))
            hi_raw = qm.group(2)
            if hi_raw:
                hi = int(hi_raw)
                if hi < lo or hi > 1000:
                    return "regex counted repetition bounds are invalid or too large", ""
                rep = hi
            else:
                if lo > 1000:
                    return "regex counted repetition bound is too large", ""
                rep = lo
            frame = cost_stack[-1]
            last = max(1, frame[1])
            mult = max(1, rep)
            frame[0] += last * (mult - 1)
            frame[1] = last * mult
            if frame[0] > MAX_REGEX_EXPANDED_COST:
                return "regex expanded repetition cost exceeds safe Rust regex compilation limit", ""
            py_parts.append(pattern[i:qm.end()])
            i = qm.end()
            if i < n and pattern[i] == "+":
                return "regex uses possessive quantifiers unsupported by the Rust regex engine", ""
            continue
        if ch in "*+?":
            if i + 1 < n and pattern[i + 1] == "+":
                return "regex uses possessive quantifiers unsupported by the Rust regex engine", ""
            py_parts.append(ch)
            i += 1
            continue
        if ch == "|":
            cost_stack[-1][1] = 0
            py_parts.append(ch)
            i += 1
            continue
        if ch == ")":
            if len(flag_stack) > 1:
                flag_stack.pop()
            if len(cost_stack) > 1:
                group_total, _ = cost_stack.pop()
                err = _charge(max(1, group_total))
                if err:
                    return err, ""
            py_parts.append(ch)
            i += 1
            continue
        if ch == "(":
            if i + 1 < n and pattern[i + 1] == "?":
                if i + 2 >= n:
                    return "regex has an incomplete group", ""
                c2 = pattern[i + 2]
                if c2 in ("=", "!", ">", "#", "|", "R", "&"):
                    return "regex uses lookaround or group features unsupported by the Rust regex engine", ""
                if c2 == "<":
                    if i + 3 < n and pattern[i + 3] in ("=", "!"):
                        return "regex uses lookbehind unsupported by the Rust regex engine", ""
                    err = _push_group(flag_stack[-1])
                    if err:
                        return err, ""
                    end = pattern.find(">", i + 3)
                    nxt_i = (end + 1) if end != -1 else (i + 3)
                    py_parts.append(pattern[i:nxt_i])
                    i = nxt_i
                    continue
                if c2 == "P":
                    if i + 3 < n and pattern[i + 3] == "=":
                        return "regex uses backreferences unsupported by the Rust regex engine", ""
                    err = _push_group(flag_stack[-1])
                    if err:
                        return err, ""
                    end = pattern.find(">", i + 4) if (i + 3 < n and pattern[i + 3] == "<") else -1
                    nxt_i = (end + 1) if end != -1 else (i + 3)
                    py_parts.append(pattern[i:nxt_i])
                    i = nxt_i
                    continue
                if c2 == ":":
                    err = _push_group(flag_stack[-1])
                    if err:
                        return err, ""
                    py_parts.append(pattern[i:i + 3])
                    i += 3
                    continue
                # Inline flag group (?flags) or (?flags:...): Rust regex rejects duplicate flags and non-Rust flags.
                j = i + 2
                seen_flags: set[str] = set()
                seen_dash = False
                enable_x: bool | None = None
                enable_u: bool | None = None
                while j < n and pattern[j] not in (":", ")"):
                    flag = pattern[j]
                    if flag == "-":
                        if seen_dash:
                            return "regex inline flag group repeats '-'", ""
                        seen_dash = True
                    elif flag in _RUST_REGEX_FLAGS:
                        if flag in seen_flags:
                            return "regex inline flag group repeats a flag (rejected by Rust regex)", ""
                        seen_flags.add(flag)
                        if flag == "x":
                            enable_x = not seen_dash
                        elif flag == "u":
                            enable_u = not seen_dash
                    else:
                        return "regex uses inline flags unsupported by the Rust regex engine", ""
                    j += 1
                if j >= n:
                    return "regex has an unclosed inline flag group", ""
                new_flags = (
                    x_on if enable_x is None else enable_x,
                    u_on if enable_u is None else enable_u,
                )
                if pattern[j] == ":":
                    err = _push_group(new_flags)
                    if err:
                        return err, ""
                else:
                    flag_stack[-1] = new_flags
                py_parts.append(pattern[i:j + 1])
                i = j + 1
                continue
            err = _push_group(flag_stack[-1])
            if err:
                return err, ""
            py_parts.append(ch)
            i += 1
            continue
        err = _charge(4 if ch == "." else 1)
        if err:
            return err, ""
        py_parts.append(ch)
        i += 1
    if in_class:
        return "regex has an unclosed character class", ""
    if len(flag_stack) > 1:
        return "regex has an unclosed group", ""
    return None, "".join(py_parts)


def regex_problem(pattern: object, *, max_bytes: int = MAX_REGEX_LENGTH) -> str | None:
    """Conservative check that ``pattern`` is accepted by Ferrum's Rust regex engine."""
    if not isinstance(pattern, str) or not pattern:
        return "empty regex"
    if len(pattern.encode("utf-8")) > max_bytes:
        return f"regex longer than {max_bytes} bytes"
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in pattern):
        return "regex contains control characters"
    if "%" in pattern:
        return "regex contains percent-escapes, which never match canonical request paths"
    syntax_err, py_pattern = _rust_regex_syntax_problem(pattern)
    if syntax_err is not None:
        return syntax_err
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", FutureWarning)
            re.compile(py_pattern)
    except (re.error, OverflowError, RecursionError):
        return "regex does not compile"
    return None


def ends_with_unescaped_dollar(pattern: str) -> bool:
    """True when ``pattern`` ends with an unescaped ``$`` anchor (even number of preceding backslashes)."""
    if not pattern.endswith("$"):
        return False
    slashes = 0
    index = len(pattern) - 2
    while index >= 0 and pattern[index] == "\\":
        slashes += 1
        index -= 1
    return slashes % 2 == 0


def backend_tls_san_kind(san: object) -> str | None:
    """Return ``"IP_ADDRESS"``, ``"URI"``, or ``"DNS"`` if ``san`` passes Ferrum's SAN allow-list rules, else None.

    Mirrors Ferrum's ``validate_backend_tls_san_allow_list_entry`` and ``validate_host_entry``:
    exact DNS names (no trailing dot, no wildcards, labels 1..63 ASCII bytes starting/ending alphanumeric),
    IP addresses, or ``spiffe://<domain>/<path>`` URIs, at most 2048 UTF-8 bytes, without whitespace or controls.
    """
    if not isinstance(san, str) or not san:
        return None
    try:
        encoded = san.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_BACKEND_TLS_SAN_BYTES:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in san):
        return None
    if "%" not in san:
        try:
            ipaddress.ip_address(san)
            return "IP_ADDRESS"
        except ValueError:
            pass
    if san.lower().startswith("spiffe://"):
        rest = san[9:]
        slash = rest.find("/")
        return "URI" if (slash > 0 and slash + 1 < len(rest)) else None
    if not san.isascii() or "://" in san or "*" in san or san.endswith("."):
        return None
    lower = san.lower()
    if normalize_host(san) != lower:
        return None
    labels = lower.split(".")
    if any(not label or len(label) > 63 or not (label[0].isalnum() and label[-1].isalnum()) for label in labels):
        return None
    return "DNS"


def valid_backend_tls_san(san: object) -> bool:
    """Whether ``san`` matches Ferrum's ``backend_tls_san_allow_list`` admission rules."""
    return backend_tls_san_kind(san) is not None


def valid_backend_tls_sni(sni: object) -> bool:
    """Whether ``sni`` matches Ferrum's ``validate_backend_tls_sni`` (exact DNS hostname, not IP/wildcard)."""
    return backend_tls_san_kind(sni) == "DNS"


#: Escapes the narrow alternation grammar accepts: one ASCII punctuation character (a literal in Rust's regex
#: syntax outside a class) or a one-letter Perl class. ``\|`` is deliberately absent (escaped and raw pipes are both
#: unknown), as are multi-character escapes (``\x``, ``\p``, ``\u``...).
_NARROW_ESCAPES = frozenset("/.-_~:@!$&',;=*+?(){}[]^#\\" + "dDwWsSbB")


def _narrow_alternation_depths(pattern: str) -> list[int] | None:
    """Group depth of every ``|`` when the WHOLE pattern is in a narrow grammar; ``None`` when it is not.

    The grammar is deliberately small so the depth bookkeeping is exact under Rust's regex syntax: printable ASCII
    without whitespace, single-character escapes from ``_NARROW_ESCAPES``, plain ``(`` and non-capturing ``(?:``
    groups. Character classes (``[``/``]``: Rust nests classes and has set operators), any other ``(?`` construct
    (inline flags such as ``x`` change what ``#`` and whitespace mean; names, lookaround), escaped pipes and
    unbalanced parentheses are outside it, so nothing is proven about them.
    """
    depths: list[int] = []
    depth = 0
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            if index + 1 >= len(pattern) or pattern[index + 1] not in _NARROW_ESCAPES:
                return None
            index += 2
            continue
        if char in "[]":
            return None
        if char == "(":
            if pattern.startswith("(?", index):
                if not pattern.startswith("(?:", index):
                    return None
                index += 3
            else:
                index += 1
            depth += 1
            continue
        if char == ")":
            depth -= 1
            if depth < 0:
                return None
        elif char == "|":
            depths.append(depth)
        elif not 0x21 <= ord(char) <= 0x7E:
            return None
        index += 1
    return depths if depth == 0 else None


def regex_alternation_unproven(pattern: object) -> bool:
    """Whether a pipe in ``pattern`` may be a top-level alternation (the only shared alternation proof).

    Safety-sensitive coverage, overlap and disjointness reasoning must use this, never a hand lexer of the full
    grammar. A pattern without any ``|`` (escaped or raw) answers False. A pattern with one answers False only when
    the whole pattern is in the narrow grammar of ``_narrow_alternation_depths`` and every ``|`` sits inside a group
    (``/api/(v1|v2)/.*``); everything else, including a non-string, answers True (unknown, fail closed).
    """
    if not isinstance(pattern, str):
        return True
    if "|" not in pattern:
        return False
    depths = _narrow_alternation_depths(pattern)
    return depths is None or any(depth == 0 for depth in depths)


def regex_literal_prefix(pattern: str) -> str:
    """Literal text every match must start with (pattern is anchored at the start).

    A top-level alternation (``/a|/B``) has no literal that every branch shares, and the first branch's literal
    proves nothing about the others. The proof is then unknown: ``""`` is returned, so callers treat the pattern as
    able to match any path (overlaps everything, covered by nothing narrower). Any pipe, escaped or raw, makes the
    proof unknown unless :func:`regex_alternation_unproven` shows on its narrow grammar that it is inside a group.
    """
    text = pattern[1:] if pattern.startswith("^") else pattern
    if regex_alternation_unproven(text):
        return ""
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
    """Heuristic top-level alternation check for source-pattern translation only (NGINX location anchoring).

    Its character-class tracking follows PCRE/Python, not Rust's regex grammar (nested classes, set operators), so
    it is NOT a sound proof. Never use it for coverage, overlap or disjointness reasoning; use
    :func:`regex_alternation_unproven` instead.
    """
    depth = 0
    in_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_class:
            if char == "[":
                pm = _POSIX_CLASS_RE.match(pattern, index)
                if pm is not None:
                    index = pm.end()
                    continue
            elif char == "]":
                in_class = False
        elif char == "[":
            in_class = True
            index += 1
            if index < len(pattern) and pattern[index] == "^":
                index += 1
            if index < len(pattern) and pattern[index] == "]":
                index += 1
            continue
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
        elif char == "|" and depth == 0:
            return True
        index += 1
    return False


# ------------------------------------------------------------ durations/sizes

_GO_DURATION = re.compile(r"^[+-]?(?:(?:\d+(?:\.\d*)?|\.\d+)(?:ns|us|µs|μs|ms|s|m|h))+$", re.ASCII)
_GO_PART = re.compile(r"(\d+(?:\.\d*)?|\.\d+)(ns|us|µs|μs|ms|s|m|h)", re.ASCII)
_GO_UNIT_NS = {
    "ns": Decimal(1),
    "us": Decimal(1_000),
    "µs": Decimal(1_000),
    "μs": Decimal(1_000),
    "ms": Decimal(1_000_000),
    "s": Decimal(1_000_000_000),
    "m": Decimal(60_000_000_000),
    "h": Decimal(3_600_000_000_000),
}
_MAX_DURATION_NS = (1 << 63) - 1
_MAX_DURATION_MS = (1 << 63) - 1


def parse_go_duration_ns(value: object, *, allow_unitless_float: bool = True) -> int | None:
    """Parse a non-negative Go/Traefik/Istio duration into exact integer nanoseconds (or ``None`` if invalid).

    Matches Go ``time.ParseDuration`` truncation toward zero for fractional nanoseconds.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        if 0 <= value <= _MAX_DURATION_NS // 1_000_000_000:
            return value * 1_000_000_000
        return None
    if isinstance(value, float):
        if not allow_unitless_float or not math.isfinite(value):
            return None
        try:
            dec_f = Decimal(str(value)) * Decimal(1_000_000_000)
        except (DecimalException, ValueError, OverflowError):
            return None
        if dec_f.is_nan() or dec_f.is_infinite() or dec_f <= -1 or dec_f >= _MAX_DURATION_NS + 1:
            return None
        ns = int(dec_f)
        return ns if 0 <= ns <= _MAX_DURATION_NS else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    neg = text.startswith("-")
    unsigned = text[1:] if text[0] in "+-" else text
    if unsigned.isascii() and unsigned.isdigit():
        try:
            secs_int = int(unsigned)
        except ValueError:
            return None
        if secs_int == 0:
            return 0
        if neg or secs_int > _MAX_DURATION_NS // 1_000_000_000:
            return None
        return secs_int * 1_000_000_000
    num_body = unsigned.replace(".", "", 1)
    if allow_unitless_float and num_body and num_body.isascii() and num_body.isdigit():
        try:
            dec = Decimal(unsigned) * Decimal(1_000_000_000)
        except (DecimalException, ValueError, OverflowError):
            return None
        if dec.is_nan() or dec.is_infinite() or dec < 0 or dec >= _MAX_DURATION_NS + 1:
            return None
        ns = int(dec)
        if ns == 0:
            return 0
        if neg:
            return None
        return ns
    if not _GO_DURATION.match(text):
        return None
    total_ns = 0
    for number, unit in _GO_PART.findall(unsigned):
        try:
            part = Decimal(number) * _GO_UNIT_NS[unit]
        except (DecimalException, ValueError, OverflowError):
            return None
        if part.is_nan() or part.is_infinite() or part < 0 or part >= _MAX_DURATION_NS + 1:
            return None
        # Go time.ParseDuration truncates each component's fractional nanoseconds before summing.
        total_ns += int(part)
        if total_ns > _MAX_DURATION_NS:
            return None
    if total_ns == 0:
        return 0
    if neg:
        return None
    return total_ns


def classify_go_duration(value: object, *, allow_unitless_float: bool = True) -> str:
    """Classify a Go/Traefik/Istio duration without rounding sub-ms values to 0 or overflowing.

    Returns ``"zero"`` (unset, empty, or valid zero duration such as ``"0m"``, ``"+0s"``, ``"0μs"``),
    ``"nonzero"`` (valid positive duration, including sub-ms like ``"100us"`` or ``"750us"``), or ``"invalid"``.
    """
    if value is None or (isinstance(value, str) and not value.strip()):
        return "zero"
    ns = parse_go_duration_ns(value, allow_unitless_float=allow_unitless_float)
    if ns is None:
        return "invalid"
    return "zero" if ns == 0 else "nonzero"


def parse_go_duration_ms(value: object, *, allow_unitless_float: bool = True) -> int | None:
    """Go/Traefik/Istio style durations (``1m30s``, ``500ms``, ``1.5s``); bare numbers are seconds."""
    ns = parse_go_duration_ns(value, allow_unitless_float=allow_unitless_float)
    if ns is None:
        return None
    return (ns + 500_000) // 1_000_000


def proto_duration_ms(value: object) -> int | None:
    """protobuf JSON Duration (``"15s"``, ``"0.25s"``) or ``{seconds, nanos}`` (truncated to whole ms)."""
    if isinstance(value, dict):
        seconds = as_int(value.get("seconds", 0))
        nanos = as_int(value.get("nanos", 0))
        if seconds is None or nanos is None or not (0 <= seconds <= _MAX_DURATION_MS // 1000) \
                or not (0 <= nanos < 1_000_000_000):
            return None
        total_ms = seconds * 1000 + nanos // 1_000_000
        return total_ms if total_ms <= _MAX_DURATION_MS else None
    if isinstance(value, str):
        match = re.fullmatch(r"(\d+(?:\.\d+)?)s", value.strip(), re.ASCII)
        if match:
            try:
                dec_ms = Decimal(match.group(1)) * Decimal(1000)
            except (DecimalException, ValueError, OverflowError):
                return None
            if dec_ms.is_nan() or dec_ms.is_infinite() or dec_ms < 0 or dec_ms >= _MAX_DURATION_MS + 1:
                return None
            return int(dec_ms)
        ns = parse_go_duration_ns(value)
        return None if ns is None else ns // 1_000_000
    return None


_NGINX_TIME_PART = re.compile(r"(\d+)(ms|s|m|h|d|w|M|y)?", re.ASCII)
_NGINX_TIME_MS = {"ms": 1, "s": 1000, None: 1000, "m": 60_000, "h": 3_600_000, "d": 86_400_000,
                  "w": 604_800_000, "M": 2_592_000_000, "y": 31_536_000_000}
_NGINX_TIME_RANK = {"y": 7, "M": 6, "w": 5, "d": 4, "h": 3, "m": 2, "s": 1, None: 1, "ms": 0}


def parse_nginx_time_ms(value: object, *, allow_ms: bool = True) -> int | None:
    """Parse an NGINX time literal in linear time (ASCII space separators, descending units).

    Matches ``ngx_parse_time``: ``allow_ms=True`` (``is_sec=0``, e.g. ``proxy_*_timeout``) allows ``ms``
    through ``w`` and rejects ``M``/``y``; ``allow_ms=False`` (``is_sec=1``, e.g. ``fail_timeout``)
    allows ``s`` through ``y`` and rejects ``ms``.
    """
    if not isinstance(value, str):
        return None
    text = value.strip(" ")
    if not text:
        return None
    total = 0
    pos = 0
    prev_rank = 8
    while pos < len(text):
        while pos < len(text) and text[pos] == " ":
            pos += 1
        if pos >= len(text):
            break
        match = _NGINX_TIME_PART.match(text, pos)
        if not match:
            return None
        unit = match.group(2)
        if allow_ms and unit in ("M", "y"):
            return None
        if not allow_ms and unit == "ms":
            return None
        if unit is None:
            if match.end() != len(text):
                return None
        else:
            rank = _NGINX_TIME_RANK[unit]
            if rank >= prev_rank:
                return None
            prev_rank = rank
        try:
            total += int(match.group(1)) * _NGINX_TIME_MS[unit]
        except ValueError:
            return None
        if total > _MAX_DURATION_MS:
            return None
        pos = match.end()
    return total


def parse_nginx_size(value: object) -> int | None:
    if not isinstance(value, str):
        return None
    match = re.fullmatch(r"(\d+)([kKmMgG]?)", value.strip(), re.ASCII)
    if not match:
        return None
    factor = {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[match.group(2).lower()]
    try:
        return int(match.group(1)) * factor
    except ValueError:
        return None


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
