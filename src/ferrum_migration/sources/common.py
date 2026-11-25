"""Helpers shared by the source translators."""

from __future__ import annotations

import ipaddress
import math
import re
from dataclasses import dataclass
from typing import Any

from .. import matching, util
from ..errors import InputError
from ..limits import Limits
from ..model import RouteSpec, Target
from ..redact import contains_secret_reference, safe_label
from ..report import Report


@dataclass
class SourceContext:
    report: Report
    limits: Limits
    include_secrets: bool = False
    #: Traefik only (``--assert-traefik-input-includes-effective-controls``): the operator states, after verifying the
    #: Traefik deployment, that the input includes every effective static, dynamic and provider routing, TLS and
    #: access control within the converted scope, or that no additional control applies. The operator's scoped
    #: representation, never a validation; every other adapter ignores it.
    traefik_controls_asserted: bool = False


def expect_mapping(value: Any, what: str) -> dict:
    if not isinstance(value, dict):
        raise InputError(f"{what} must be a mapping")
    return value


def mapping(value: Any) -> dict:
    return value if isinstance(value, dict) else {}


def seq(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def str_list(value: Any) -> list[str] | None:
    """List of strings, or None when the value has another shape."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


def check_route_budget(count: int, limits: Limits) -> None:
    if count > limits.max_routes:
        raise InputError(f"input defines more than {limits.max_routes} routes")


def choose_main_port(counts: dict[int, int]) -> int | None:
    if not counts:
        return None
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]


# ------------------------------------------------------------ header rules

GATEWAY_OWNED_REQUEST_HEADERS = frozenset({
    "host", "x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port",
    "x-forwarded-prefix", "forwarded", "via", "x-real-ip", "connection", "keep-alive",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "content-length",
})
GATEWAY_OWNED_PREFIXES = ("x-consumer-", "x-path-param-", "x-ferrum-")
PROTOCOL_MANAGED_RESPONSE_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade", "content-length",
})
_SENSITIVE_WORDS = ("authorization", "cookie", "token", "secret", "password", "passwd", "apikey",
                    "api-key", "session", "credential")
_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def fold(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def header_name_ok(name: Any) -> bool:
    return isinstance(name, str) and bool(_TOKEN_RE.fullmatch(name))


def header_value_ok(value: Any, nonempty: bool = False, strict_ws: bool = False) -> bool:
    if not isinstance(value, str):
        return False
    if nonempty and not value:
        return False
    if strict_ws and value and (value[0] in (" ", "\t") or value[-1] in (" ", "\t")):
        return False
    return all(ch == "\t" or 0x20 <= ord(ch) <= 0x7E for ch in value)


def is_gateway_owned_request_header(name: str) -> bool:
    folded = fold(name)
    return folded in GATEWAY_OWNED_REQUEST_HEADERS or folded.startswith(GATEWAY_OWNED_PREFIXES)


def is_sensitive_header(name: str) -> bool:
    folded = fold(name)
    return any(word in folded for word in _SENSITIVE_WORDS)


def literal_value(value: str) -> str:
    """Escape Ferrum's ``$(`` template opener so a literal stays literal."""
    return value.replace("$(", "$$(")


_TEMPLATE_ONLY = re.compile(r"\$\((?:client_ip|request_id|header\.[a-z0-9-]+)\)")


def static_credential_problem(kind: str, name: str, value: Any) -> str | None:
    """Refuse to copy a static value for a credential-like header/query name.

    Values such as ``Authorization: Bearer ...`` or ``?apikey=...`` are
    credentials. Copying them would put secret bytes into the resources file
    without ``--include-secrets`` and without being counted, so they are never
    copied. A pure Ferrum template (``$(header.x)``) carries no secret and is
    allowed. The returned message names the header, never the value.
    """
    if not is_sensitive_header(name):
        return None
    if isinstance(value, str) and _TEMPLATE_ONLY.fullmatch(value):
        return None
    return (f"{kind} {name} sets a static credential-like value, which is never copied into the output "
            "(fail closed; configure it in Ferrum from a secret source)")


def request_header_rule(op: str, key: Any, value: Any = None, new_key: Any = None) -> tuple[dict | None, str | None]:
    if not header_name_ok(key):
        return None, "invalid header name"
    name = key.lower()
    if fold(name) == "x-ferrum-hops":
        return None, "x-ferrum-hops is Ferrum's loop guard and cannot be changed"
    if op in ("add", "update"):
        if is_gateway_owned_request_header(name):
            return None, f"header {name} is owned by Ferrum and cannot be set"
        if not header_value_ok(value):
            return None, f"header {name} has a value Ferrum cannot represent"
        problem = static_credential_problem("request header", name, value)
        if problem:
            return None, problem
        return {"operation": op, "target": "header", "key": name, "value": value}, None
    if op == "remove":
        return {"operation": "remove", "target": "header", "key": name}, None
    if op == "rename":
        if not header_name_ok(new_key):
            return None, "invalid rename destination"
        destination = new_key.lower()
        if is_gateway_owned_request_header(destination):
            return None, f"header {destination} is owned by Ferrum and cannot be a rename destination"
        return {"operation": "rename", "target": "header", "key": name, "new_key": destination}, None
    return None, f"unsupported header operation {op}"


def query_rule(op: str, key: Any, value: Any = None, new_key: Any = None) -> tuple[dict | None, str | None]:
    def ok(text: Any) -> bool:
        return isinstance(text, str) and text != "" and "\r" not in text and "\n" not in text
    if not ok(key):
        return None, "invalid query parameter name"
    if op in ("add", "update"):
        if not isinstance(value, str) or "\r" in value or "\n" in value:
            return None, "query value not representable"
        problem = static_credential_problem("query parameter", key.lower(), value)
        if problem:
            return None, problem
        return {"operation": op, "target": "query", "key": key, "value": value}, None
    if op == "remove":
        return {"operation": "remove", "target": "query", "key": key}, None
    if op == "rename":
        if not ok(new_key):
            return None, "invalid query rename destination"
        return {"operation": "rename", "target": "query", "key": key, "new_key": new_key}, None
    return None, f"unsupported query operation {op}"


def response_header_rule(op: str, key: Any, value: Any = None, new_key: Any = None) -> tuple[dict | None, str | None]:
    if not header_name_ok(key):
        return None, "invalid header name"
    name = key.lower()
    if op in ("add", "update"):
        if name in PROTOCOL_MANAGED_RESPONSE_HEADERS or fold(name).startswith("x-ferrum-") \
                or name in ("x-gateway-error", "x-gateway-upstream-status"):
            return None, f"response header {name} is managed by Ferrum"
        if not header_value_ok(value):
            return None, f"response header {name} has a value Ferrum cannot represent"
        problem = static_credential_problem("response header", name, value)
        if problem:
            return None, problem
        return {"operation": op, "target": "header", "key": name, "value": value}, None
    if op == "remove":
        return {"operation": "remove", "target": "header", "key": name}, None
    if op == "rename":
        if not header_name_ok(new_key):
            return None, "invalid rename destination"
        destination = new_key.lower()
        if "set-cookie" in (name, destination) or destination in PROTOCOL_MANAGED_RESPONSE_HEADERS:
            return None, "Set-Cookie and protocol-managed headers cannot be renamed"
        return {"operation": "rename", "target": "header", "key": name, "new_key": destination}, None
    return None, f"unsupported header operation {op}"


# ----------------------------------------------------------------- CORS

def _cors_prefix_is_effectively_universal(prefix: str) -> bool:
    if "://" not in prefix:
        return True
    scheme, authority = prefix.split("://", 1)
    if not scheme or not authority.endswith(":"):
        return True
    host = authority[:-1]
    return not host or any(c in "/?#@:" or c.isspace() for c in host)


def _cors_origin_effectively_universal(origin: Any) -> bool:
    # Under allow_credentials=true, Ferrum enforces PSL-backed host-constraint checks on wildcard suffixes
    # (`*.suffix`) and regex origins (`origin_regex_host_is_provably_constrained`). Without embedding a Public
    # Suffix List snapshot, fail closed on exact 'null', prefixes lacking a scheme://host: boundary, wildcard
    # suffixes, and regex origins so generated resources never fail Ferrum admission.
    if isinstance(origin, str):
        return origin == "null" or origin.startswith("*.")
    if isinstance(origin, dict) and len(origin) == 1:
        kind, value = next(iter(origin.items()))
        if kind == "exact":
            return value == "null"
        if kind == "prefix":
            return _cors_prefix_is_effectively_universal(value)
        if kind == "regex":
            return True
    return False


_CORS_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
_CORS_UNICODE_SHORTHANDS = frozenset("wWdDsS")
_CORS_MAX_REPEAT = 64
_CORS_MAX_TOTAL_REPEATS = 128
_CORS_MAX_UNICODE_SHORTHANDS = 4
_CORS_MAX_COMPILED_COST = 512


def _cors_regex_problem(pattern: str) -> str | None:
    """Validate that a CORS origin regex stays within Ferrum v0.9.21's Rust regex limits.

    Ferrum wraps each origin regex as ``^(?:<pattern>)$`` and compiles it with
    ``nest_limit(24)``, ``size_limit(64 KiB)``, and ``dfa_size_limit(64 KiB)``.
    In ``regex-syntax``, the wrapper itself costs up to 4 levels (outer Concat,
    wrapper Group, Alternation, branch Concat), each nested group adds up to 4
    levels (Repetition, Group, Alternation, Concat), a quantifier adds 1, and a
    character class adds up to 3 (Repetition, ClassBracketed, ClassSetUnion).
    We enforce printable ASCII, reject syntax that differs between Python ``re``
    and Rust ``regex-syntax`` (including literal ``{``), bound AST nesting
    (group ``4 + 4*g <= 24``, quantifier ``5 + 4*g <= 24``, class ``7 + 4*g <= 24``),
    and charge the expanded operand cost of bounded repetitions (including classes,
    ``.``, negated classes, and Unicode shorthands) so compiled NFA/DFA size stays
    well under 64 KiB.
    """
    problem = util.regex_problem(pattern)
    if problem:
        return problem
    if any(ord(ch) < 0x20 or ord(ch) > 0x7E for ch in pattern):
        return "an allowed origin regex must be printable ASCII"
    group_depth = 0
    class_depth = 0
    class_state = 0  # 2: right after '[', 1: right after '[^', 0: normal inside class
    class_has_unicode = False
    class_negated = False
    class_atom_count = 0
    unicode_shorthands = 0
    total_bounded_repeats = 0
    group_mult_stack = [1]
    group_unicode_stack = [False]
    group_cost_stack = [0]
    last_atom_mult = 1
    last_atom_unicode = False
    last_atom_cost = 0
    has_atom = False
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                return "an allowed origin regex has a trailing escape"
            nxt = pattern[i + 1]
            if nxt in "01234567uUN":
                return "an allowed origin regex uses an escape not portable to Rust regex"
            if nxt in "<>":
                return "an allowed origin regex uses an escape not portable to Rust regex"
            if class_depth > 0 and nxt in "bBAz":
                return "an allowed origin regex uses an assertion escape inside a character class"
            if nxt == "x":
                if i + 3 >= n or pattern[i + 2] not in _CORS_HEX_DIGITS or pattern[i + 3] not in _CORS_HEX_DIGITS:
                    return "an allowed origin regex has an invalid hex escape"
                i += 4
                if class_depth > 0:
                    class_atom_count += 1
                    class_state = 0
                else:
                    group_cost_stack[-1] += 1
                    last_atom_cost = 1
                    last_atom_mult = 1
                    last_atom_unicode = False
                    has_atom = True
                if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
                    return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
                continue
            if nxt in _CORS_UNICODE_SHORTHANDS:
                unicode_shorthands += 1
                if unicode_shorthands > _CORS_MAX_UNICODE_SHORTHANDS:
                    return "an allowed origin regex exceeds safe Rust regex size bounds"
                group_unicode_stack[-1] = True
                if class_depth > 0:
                    class_has_unicode = True
                    class_atom_count += 1
                    class_state = 0
                else:
                    group_cost_stack[-1] += 128
                    last_atom_cost = 128
                    last_atom_mult = 1
                    last_atom_unicode = True
                    has_atom = True
            else:
                if class_depth > 0:
                    class_atom_count += 1
                    class_state = 0
                else:
                    group_cost_stack[-1] += 1
                    last_atom_cost = 1
                    last_atom_mult = 1
                    last_atom_unicode = False
                    has_atom = nxt not in "bBAz"
            if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
                return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
            i += 2
            continue
        if class_depth > 0:
            if class_state == 2 and ch == "^":
                class_state = 1
                class_negated = True
                i += 1
                continue
            if ch == "]" and class_state == 0:
                class_depth = 0
                atom_cost = 128 if class_has_unicode else (64 if class_negated else max(4, class_atom_count))
                group_cost_stack[-1] += atom_cost
                if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
                    return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
                last_atom_cost = atom_cost
                last_atom_mult = 1
                last_atom_unicode = class_has_unicode
                class_has_unicode = False
                class_negated = False
                class_atom_count = 0
                has_atom = True
                i += 1
                continue
            class_state = 0
            if ch == "[":
                return "an allowed origin regex contains an unescaped '[' inside a character class"
            if i + 1 < n and pattern[i:i + 2] in ("--", "&&", "~~"):
                return "an allowed origin regex contains Rust character-class set operators"
            class_atom_count += 1
            i += 1
            continue
        if ch == "(":
            step = 1
            if i + 1 < n and pattern[i + 1] == "?":
                if pattern.startswith("(?:", i):
                    step = 3
                elif pattern.startswith("(?i:", i):
                    step = 4
                elif pattern.startswith("(?i)", i):
                    i += 4
                    last_atom_mult = 1
                    last_atom_unicode = False
                    last_atom_cost = 0
                    has_atom = False
                    continue
                else:
                    return "an allowed origin regex uses a group construct not supported for CORS migration"
            group_depth += 1
            if 4 + 4 * group_depth > 24:
                return "an allowed origin regex exceeds Ferrum nesting limits"
            # Charge capture start/end state overhead for capturing groups (step == 1) and minimal
            # wrapper overhead for non-capturing groups so repeated empty groups cannot exceed 64 KiB.
            group_overhead = 4 if step == 1 else 1
            group_mult_stack.append(1)
            group_unicode_stack.append(False)
            group_cost_stack.append(group_overhead)
            if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
                return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
            last_atom_mult = 1
            last_atom_unicode = False
            last_atom_cost = 0
            has_atom = False
            i += step
            continue
        if ch == ")":
            if group_depth > 0:
                group_depth -= 1
                child_mult = group_mult_stack.pop()
                child_unicode = group_unicode_stack.pop()
                child_cost = group_cost_stack.pop()
                group_mult_stack[-1] = max(group_mult_stack[-1], child_mult)
                group_unicode_stack[-1] = group_unicode_stack[-1] or child_unicode
                group_cost_stack[-1] += child_cost
                last_atom_mult = child_mult
                last_atom_unicode = child_unicode
                last_atom_cost = max(1, child_cost)
                has_atom = True
            else:
                last_atom_mult = 1
                last_atom_unicode = False
                last_atom_cost = 0
                has_atom = False
            i += 1
            continue
        if ch == "[":
            class_depth = 1
            class_state = 2
            class_has_unicode = False
            class_negated = False
            class_atom_count = 0
            if 7 + 4 * group_depth > 24:
                return "an allowed origin regex exceeds Ferrum nesting limits"
            last_atom_mult = 1
            last_atom_unicode = False
            last_atom_cost = 0
            has_atom = False
            i += 1
            continue
        if ch in "*+?":
            if not has_atom:
                return "an allowed origin regex has an invalid quantifier placement"
            if 5 + 4 * group_depth > 24:
                return "an allowed origin regex exceeds Ferrum nesting limits"
            group_cost_stack[-1] += 2
            if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
                return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
            i += 1
            if i < n and pattern[i] == "?":
                i += 1
            last_atom_mult = 1
            last_atom_unicode = False
            last_atom_cost = 0
            has_atom = False
            continue
        if ch == "{":
            close = pattern.find("}", i + 1)
            body = pattern[i + 1:close] if close > i + 1 else ""
            parts = body.split(",") if body else []
            valid_rep = has_atom and close > i + 1 and _is_valid_re2_repeat_body(body)
            if not valid_rep:
                return ("an allowed origin regex contains an unescaped '{' or leading-zero repeat bound that "
                        "diverges between RE2 and Rust regex (escape literal braces as \\{)")
            lo = int(parts[0])
            hi = int(parts[1]) if len(parts) == 2 and parts[1] else lo
            if len(parts) == 2 and parts[1] and hi < lo:
                return "an allowed origin regex has an inverted repetition range"
            if 5 + 4 * group_depth > 24:
                return "an allowed origin regex exceeds Ferrum nesting limits"
            factor = max(lo, hi)
            if factor > _CORS_MAX_REPEAT:
                return "an allowed origin regex repetition bound exceeds safe Ferrum size limits"
            effective = last_atom_mult * max(1, factor)
            if effective > _CORS_MAX_REPEAT:
                return "an allowed origin regex nested repetition exceeds safe Ferrum size limits"
            total_bounded_repeats += effective
            if total_bounded_repeats > _CORS_MAX_TOTAL_REPEATS:
                return "an allowed origin regex total repetition budget exceeds safe Ferrum size limits"
            if last_atom_unicode and factor > 1:
                unicode_shorthands += factor - 1
                if unicode_shorthands > _CORS_MAX_UNICODE_SHORTHANDS:
                    return "an allowed origin regex exceeds safe Rust regex size bounds"
            extra_cost = last_atom_cost * max(0, factor - 1)
            group_cost_stack[-1] += extra_cost
            if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
                return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
            group_mult_stack[-1] = max(group_mult_stack[-1], effective)
            i = close + 1
            if i < n and pattern[i] == "?":
                i += 1
            last_atom_mult = 1
            last_atom_unicode = False
            last_atom_cost = 0
            has_atom = False
            continue
        if ch in "|^$":
            last_atom_mult = 1
            last_atom_unicode = False
            last_atom_cost = 0
            has_atom = False
            i += 1
            continue
        atom_cost = 64 if ch == "." else 1
        group_cost_stack[-1] += atom_cost
        if sum(group_cost_stack) > _CORS_MAX_COMPILED_COST:
            return "an allowed origin regex exceeds safe Ferrum compiled-size limits"
        last_atom_cost = atom_cost
        last_atom_mult = 1
        last_atom_unicode = False
        has_atom = True
        i += 1
    return None


def _is_valid_re2_repeat_body(body: str) -> bool:
    """Whether ``body`` inside ``{...}`` is a valid RE2/Rust repetition bound without leading zeros."""
    if not body:
        return False
    parts = body.split(",")
    if len(parts) not in (1, 2):
        return False
    for idx, part in enumerate(parts):
        if idx == 1 and part == "":
            continue
        if not part or not (part.isascii() and part.isdigit()):
            return False
        if len(part) > 1 and part[0] == "0":
            return False
    return True


def _re2_to_python_probe(pattern: str) -> str | None:
    """Translate RE2 literal quotes (``\\Q...\\E``) and ``\\x{...}`` escapes for probing literal ``*``.

    Walks escapes left-to-right so escaped backslashes (e.g. ``[\\\\x{2a}]``) are never misread as
    RE2 escapes, and validates unescaped ``{...}`` quantifiers in the original pattern before
    translating escapes so ``\\*{01}``, ``\\*{\\x{31}}``, or ``\\*{\\Q1\\E}`` never turn into
    synthesized quantifiers. Returns ``None`` on malformed or divergent RE2 syntax.
    """
    out: list[str] = []
    in_class = False
    class_state = 0
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                return None
            nxt = pattern[i + 1]
            if not in_class and nxt == "Q":
                end = pattern.find(r"\E", i + 2)
                if end < 0:
                    return None
                out.append(re.escape(pattern[i + 2:end]))
                i = end + 2
                continue
            if nxt == "x" and i + 2 < n and pattern[i + 2] == "{":
                close = pattern.find("}", i + 3)
                if close < 0 or not (1 <= close - (i + 3) <= 6):
                    return None
                hex_digits = pattern[i + 3:close]
                if not all(c in _CORS_HEX_DIGITS for c in hex_digits):
                    return None
                code = int(hex_digits, 16)
                if code > 0x10FFFF or 0xD800 <= code <= 0xDFFF:
                    return None
                out.append(re.escape(chr(code)))
                i = close + 1
                class_state = 0
                continue
            out.append(pattern[i:i + 2])
            i += 2
            class_state = 0
            continue
        if in_class:
            if class_state == 2 and ch == "^":
                class_state = 1
            elif ch == "]" and class_state == 0:
                in_class = False
            else:
                class_state = 0
            out.append(ch)
            i += 1
            continue
        if ch == "{":
            close = pattern.find("}", i + 1)
            if close <= i + 1 or not _is_valid_re2_repeat_body(pattern[i + 1:close]):
                return None
            out.append(pattern[i:close + 1])
            i = close + 1
            continue
        if ch == "[":
            in_class = True
            class_state = 2
        out.append(ch)
        i += 1
    return "".join(out)


def _star_concat(a: tuple[bool, bool, bool], b: tuple[bool, bool, bool]) -> tuple[bool, bool, bool]:
    return (a[0] and b[0], (a[0] and b[1]) or (a[1] and b[2]), a[2] and b[2])


def _star_or(a: tuple[bool, bool, bool], b: tuple[bool, bool, bool]) -> tuple[bool, bool, bool]:
    return (a[0] or b[0], a[1] or b[1], a[2] or b[2])


def _star_repeat(e: tuple[bool, bool, bool], lo: int, hi: int | None) -> tuple[bool, bool, bool]:
    """Boolean 2x2 transition-matrix power union over the 1-character string ``"*"`` (stabilizes at k=2)."""
    res = (False, False, False)
    if lo == 0:
        res = _star_or(res, (True, False, True))
    if lo <= 1 and (hi is None or hi >= 1):
        res = _star_or(res, e)
    if hi is None or hi >= 2:
        res = _star_or(res, (e[0], e[1] and (e[0] or e[2]), e[2]))
    return res


def _regex_matches_star_linear(pattern: str) -> bool | None:
    """Decide in O(len(pattern)) time (no backtracking) whether ``pattern`` full-matches ``"*"``.

    Assumes ``pattern`` already passed ``_cors_regex_problem`` (balanced groups/classes, no backrefs
    or lookarounds, only ``(``, ``(?:``, ``(?i:``, ``(?i)`` groups, and valid ``{lo[,hi]}`` bounds).
    Each subexpression is tracked as a 3-bit reachability matrix ``(m00, m01, m11)`` over positions
    ``0`` (before ``*``) and ``1`` (after ``*``). Returns ``None`` if any unexpected token is seen.
    """
    empty = (True, False, True)
    none_val = (False, False, False)
    alt_stack: list[tuple[bool, bool, bool]] = [none_val]
    seq_stack: list[tuple[bool, bool, bool]] = [empty]
    last: tuple[bool, bool, bool] | None = None
    i = 0
    n = len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "\\":
            if i + 1 >= n:
                return None
            if last is not None:
                seq_stack[-1] = _star_concat(seq_stack[-1], last)
                last = None
            nxt = pattern[i + 1]
            if nxt == "A":
                seq_stack[-1] = _star_concat(seq_stack[-1], (True, False, False))
                i += 2
                continue
            if nxt in ("z", "Z"):
                seq_stack[-1] = _star_concat(seq_stack[-1], (False, False, True))
                i += 2
                continue
            if nxt == "b":
                seq_stack[-1] = _star_concat(seq_stack[-1], none_val)
                i += 2
                continue
            if nxt == "B":
                seq_stack[-1] = _star_concat(seq_stack[-1], empty)
                i += 2
                continue
            if nxt == "x":
                if i + 3 >= n:
                    return None
                tok = pattern[i:i + 4]
                i += 4
            else:
                tok = pattern[i:i + 2]
                i += 2
            try:
                matched = bool(re.fullmatch(tok, "*"))
            except re.error:
                return None
            last = (False, matched, False)
            continue
        if ch == "[":
            if last is not None:
                seq_stack[-1] = _star_concat(seq_stack[-1], last)
                last = None
            start = i
            i += 1
            state = 2
            closed = False
            while i < n:
                c = pattern[i]
                if c == "\\":
                    i += 2
                    state = 0
                    continue
                if state == 2 and c == "^":
                    state = 1
                    i += 1
                    continue
                if c == "]" and state == 0:
                    i += 1
                    closed = True
                    break
                state = 0
                i += 1
            if not closed:
                return None
            try:
                matched = bool(re.fullmatch(pattern[start:i], "*"))
            except re.error:
                return None
            last = (False, matched, False)
            continue
        if ch == "(":
            if last is not None:
                seq_stack[-1] = _star_concat(seq_stack[-1], last)
                last = None
            if pattern.startswith("(?i)", i):
                i += 4
                continue
            if pattern.startswith("(?:", i):
                step = 3
            elif pattern.startswith("(?i:", i):
                step = 4
            elif i + 1 < n and pattern[i + 1] == "?":
                return None
            else:
                step = 1
            alt_stack.append(none_val)
            seq_stack.append(empty)
            i += step
            continue
        if ch == ")":
            if last is not None:
                seq_stack[-1] = _star_concat(seq_stack[-1], last)
                last = None
            if len(seq_stack) <= 1:
                return None
            last = _star_or(alt_stack.pop(), seq_stack.pop())
            i += 1
            continue
        if ch == "|":
            if last is not None:
                seq_stack[-1] = _star_concat(seq_stack[-1], last)
                last = None
            alt_stack[-1] = _star_or(alt_stack[-1], seq_stack[-1])
            seq_stack[-1] = empty
            i += 1
            continue
        if ch in "^$":
            if last is not None:
                seq_stack[-1] = _star_concat(seq_stack[-1], last)
                last = None
            anchor = (True, False, False) if ch == "^" else (False, False, True)
            seq_stack[-1] = _star_concat(seq_stack[-1], anchor)
            i += 1
            continue
        if ch in "*+?":
            if last is None:
                return None
            lo, hi = (0, 1) if ch == "?" else ((0, None) if ch == "*" else (1, None))
            seq_stack[-1] = _star_concat(seq_stack[-1], _star_repeat(last, lo, hi))
            last = None
            i += 1
            if i < n and pattern[i] == "?":
                i += 1
            continue
        if ch == "{":
            if last is None:
                return None
            close = pattern.find("}", i + 1)
            if close <= i + 1 or not _is_valid_re2_repeat_body(pattern[i + 1:close]):
                return None
            parts = pattern[i + 1:close].split(",")
            lo = int(parts[0])
            hi = lo if len(parts) == 1 else (None if parts[1] == "" else int(parts[1]))
            seq_stack[-1] = _star_concat(seq_stack[-1], _star_repeat(last, lo, hi))
            last = None
            i = close + 1
            if i < n and pattern[i] == "?":
                i += 1
            continue
        if last is not None:
            seq_stack[-1] = _star_concat(seq_stack[-1], last)
        last = (False, ch in (".", "*"), False)
        i += 1
    if last is not None:
        seq_stack[-1] = _star_concat(seq_stack[-1], last)
    if len(seq_stack) != 1:
        return None
    return _star_or(alt_stack[0], seq_stack[0])[1]


def cors_origin_star_probe(origin: Any) -> str:
    """Classify an Envoy/Istio CORS origin matcher against literal ``"*"``.

    Returns ``"star"`` (Envoy treats the matcher as allow-all), ``"no_match"`` (confirmed not
    allow-all), or ``"error"`` (regex syntax diverges from RE2/Rust or exceeds safe probe bounds,
    so the caller must fail closed).
    """
    if origin == "*":
        return "star"
    if isinstance(origin, dict) and len(origin) == 1:
        kind, value = next(iter(origin.items()))
        if not isinstance(value, str):
            return "error"
        if kind == "exact":
            return "star" if value == "*" else "no_match"
        if kind == "prefix":
            return "star" if value in ("", "*") else "no_match"
        if kind == "regex":
            if not value or len(value.encode("utf-8")) > 512:
                return "error"
            translated = _re2_to_python_probe(value)
            if translated is None or _cors_regex_problem(translated) is not None:
                return "error"
            matched = _regex_matches_star_linear(translated)
            if matched is None:
                return "error"
            return "star" if matched else "no_match"
    return "error"


def is_canonical_http_origin(origin: str) -> bool:
    """Whether ``origin`` is a plain ``http(s)://host[:port]`` URL accepted by Ferrum ``cors`` string origins."""
    if not origin or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in origin):
        return False
    lower = origin.lower()
    if lower.startswith("http://"):
        authority = origin[7:]
    elif lower.startswith("https://"):
        authority = origin[8:]
    else:
        return False
    if not authority or any(ch in authority for ch in "/\\?#@%"):
        return False
    # Reject unbracketed IPv6 literals (multiple colons without '[...]') because Url::parse rejects them.
    if not authority.startswith("[") and authority.count(":") > 1:
        return False
    parsed = util.split_host_port(authority, 80)
    if parsed is None:
        return False
    host, _port = parsed
    norm_host = util.normalize_backend_host(host)
    return norm_host is not None and _is_valid_mirror_host(norm_host)


def has_explicit_default_origin_port(origin: str) -> bool:
    """Whether an ``http(s)://`` origin explicitly specifies its scheme's default port (``:80`` / ``:443``)."""
    lower = origin.lower()
    if lower.startswith("http://"):
        authority, default_port = origin[7:], 80
    elif lower.startswith("https://"):
        authority, default_port = origin[8:], 443
    else:
        return False
    if authority.startswith("["):
        end = authority.find("]")
        rest = authority[end + 1:] if end >= 0 else ""
        return rest.startswith(":") and util.parse_port(rest[1:]) == default_port
    if authority.count(":") == 1:
        _, _, port_text = authority.partition(":")
        return util.parse_port(port_text) == default_port
    return False


def has_leading_zero_origin_port(origin: str) -> bool:
    """Whether an ``http(s)://`` origin specifies a zero-padded port (such as ``:08443``)."""
    lower = origin.lower()
    if lower.startswith("http://"):
        authority = origin[7:]
    elif lower.startswith("https://"):
        authority = origin[8:]
    else:
        return False
    if authority.startswith("["):
        end = authority.find("]")
        rest = authority[end + 1:] if end >= 0 else ""
        port_text = rest[1:] if rest.startswith(":") else ""
    elif authority.count(":") == 1:
        _, _, port_text = authority.partition(":")
    else:
        port_text = ""
    return len(port_text) > 1 and port_text.startswith("0")


def cors_config(origins: Any, methods: Any = None, headers: Any = None, exposed: Any = None,
                credentials: Any = None, max_age: Any = None, preflight_continue: Any = None,
                private_network: Any = None, unmatched_preflights: str | None = None) -> tuple[dict | None, str | None]:
    if not isinstance(origins, list) or not origins:
        return None, "no allowed origins"
    if len(origins) > 64:
        return None, "more than 64 allowed origins"
    clean: list[Any] = []
    for origin in origins:
        if isinstance(origin, str):
            if not origin or len(origin.encode("utf-8")) > 512 or not header_value_ok(origin, nonempty=True, strict_ws=True):
                return None, "an allowed origin is not representable"
            if origin != "*" and not is_canonical_http_origin(origin):
                return None, "plain string allowed_origins entry must be '*' or a canonical http(s)://host[:port] origin"
            clean.append(origin)
        elif isinstance(origin, dict) and len(origin) == 1 and next(iter(origin)) in ("exact", "prefix", "regex"):
            kind, value = next(iter(origin.items()))
            if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 512:
                return None, "an allowed origin matcher is not representable"
            if kind in ("exact", "prefix") and not header_value_ok(value, nonempty=True, strict_ws=True):
                return None, "an allowed origin matcher is not representable"
            if kind == "regex":
                rx_problem = _cors_regex_problem(value)
                if rx_problem:
                    return None, rx_problem
            clean.append({kind: value})
        else:
            return None, "an allowed origin matcher is not representable"
    config: dict[str, Any] = {"allowed_origins": clean}
    for field_name, values in (("allowed_methods", methods), ("allowed_headers", headers),
                               ("exposed_headers", exposed)):
        if values is None:
            continue
        items = str_list(values)
        if items is None or len(items) > 128 or any(not item or len(item.encode("utf-8")) > 256
                                                    or item != item.strip() or not header_name_ok(item)
                                                    for item in items):
            return None, f"{field_name} is not representable"
        if items:
            config[field_name] = items
    if credentials is not None:
        creds_bool = bool(credentials)
        if creds_bool and any(_cors_origin_effectively_universal(item) for item in clean):
            return None, ("allow_credentials=true cannot be combined with an effectively universal origin matcher "
                          "(such as exact 'null', a prefix without a scheme://host: boundary, or a broad regex)")
        config["allow_credentials"] = creds_bool
    if max_age is not None:
        age = util.as_int(max_age)
        if age is None or age < 0 or age > (1 << 64) - 1:
            return None, "max_age is not representable"
        config["max_age"] = age
    if preflight_continue is not None:
        config["preflight_continue"] = bool(preflight_continue)
    if private_network is not None:
        config["allow_private_network"] = bool(private_network)
    if unmatched_preflights is not None:
        if unmatched_preflights not in ("forward", "ignore"):
            return None, "unmatched_preflights must be 'forward' or 'ignore'"
        if preflight_continue is not None:
            return None, "preflight_continue cannot be combined with unmatched_preflights"
        config["unmatched_preflights"] = unmatched_preflights
    return config, None


# ------------------------------------------- shared plugin config builders

_MEDIA_TYPE_RULE_RE = re.compile(r"^[!#$%&'+.^_`|~0-9A-Za-z-]+/(?:\*|[!#$%&'+.^_`|~0-9A-Za-z-]+)$")
_EXACT_MEDIA_TYPE_RE = re.compile(r"^[!#$%&'+.^_`|~0-9A-Za-z-]+/[!#$%&'+.^_`|~0-9A-Za-z-]+$")
_CORRELATION_ID_RESERVED_HEADERS = frozenset({
    "api-key", "authentication-info", "authorization", "connection", "content-encoding", "content-length",
    "cookie", "early-data", "expect", "forwarded", "grpc-message", "grpc-status", "grpc-status-details-bin",
    "host", "keep-alive", "proxy-authenticate", "proxy-authentication-info", "proxy-authorization",
    "proxy-connection", "sec-websocket-accept", "sec-websocket-extensions", "sec-websocket-key",
    "sec-websocket-protocol", "sec-websocket-version", "set-cookie", "te", "traceparent", "tracestate",
    "trailer", "transfer-encoding", "upgrade", "via", "www-authenticate", "x-api-key", "x-auth-token",
    "x-csrf-token", "x-ferrum-original-content-encoding", "x-forwarded-authorization", "x-forwarded-for",
    "x-forwarded-host", "x-forwarded-proto", "x-goog-api-key", "x-grpc-web-mode", "x-real-ip",
    "x-xsrf-token", "x-authenticated-identity", "x-geo-country", "x-ferrum-hops",
})
_GATEWAY_ASSERTION_HEADERS = frozenset({"x-authenticated-identity", "x-geo-country", "x-ferrum-hops"})
MAX_COMPRESSION_CONTENT_TYPES = 64
MAX_FAULT_DELAY_MS = 60_000
MAX_FAULT_MATCH_HEADERS = 16
MAX_MIRROR_BODY_BYTES = 10 * 1024 * 1024


def is_loopback_ip_literal(host: str) -> bool:
    """Whether ``host`` is an IPv4 or IPv6 loopback literal (``127.0.0.0/8`` or ``::1``)."""
    bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        return ipaddress.ip_address(bare).is_loopback
    except ValueError:
        return False


def correlation_id_header_ok(name: Any) -> bool:
    """Whether ``name`` is accepted by Ferrum v0.9.21 ``correlation_id.header_name``."""
    if not isinstance(name, str):
        return False
    trimmed = name.strip()
    if not trimmed or len(trimmed.encode("utf-8")) > 65_535 or not header_name_ok(trimmed):
        return False
    lower = trimmed.lower()
    folded = fold(lower)
    if lower in _CORRELATION_ID_RESERVED_HEADERS or folded in _CORRELATION_ID_RESERVED_HEADERS:
        return False
    return not folded.startswith(("x-consumer-", "x-ferrum-"))


def compression_config(
    algorithms: list[str] | None,
    *,
    min_content_length: int | None = None,
    content_types: list[str] | None = None,
    allow_ranges: bool = False,
    gzip_level: int | None = None,
    brotli_quality: int | None = None,
    zstd_level: int | None = None,
    decompress_request: bool | None = None,
    remove_accept_encoding: bool | None = None,
    weaken_strong_etag: bool | None = None,
) -> tuple[dict | None, str | None]:
    """Build a Ferrum v0.9.21 ``compression`` plugin config, rejecting unsupported values."""
    config: dict[str, Any] = {}
    if algorithms is not None:
        if not isinstance(algorithms, list) or not algorithms:
            return None, "compression algorithms must be a non-empty list"
        clean_algos: list[str] = []
        for raw in algorithms:
            if not isinstance(raw, str):
                return None, "compression algorithm is not a string"
            mapped = "br" if raw.lower() == "brotli" else raw.lower()
            if mapped not in ("gzip", "br", "zstd"):
                return None, f"unsupported compression algorithm {safe_label(raw, 24)}"
            if mapped not in clean_algos:
                clean_algos.append(mapped)
        config["algorithms"] = clean_algos
    if min_content_length is not None:
        if isinstance(min_content_length, bool) or not isinstance(min_content_length, int) \
                or not 0 <= min_content_length <= (1 << 64) - 1:
            return None, "min_content_length must be an integer in 0..2^64-1"
        config["min_content_length"] = min_content_length
    if content_types is not None:
        if not isinstance(content_types, list) or not content_types:
            return None, "content_types must be a non-empty list"
        ct_re = _MEDIA_TYPE_RULE_RE if allow_ranges else _EXACT_MEDIA_TYPE_RE
        clean_types: list[str] = []
        seen_types: set[str] = set()
        for raw in content_types:
            if not isinstance(raw, str) or not raw.isascii() or not ct_re.fullmatch(raw):
                return None, f"content_type {safe_label(raw, 48)} is not a valid Ferrum media type rule"
            lower = raw.lower()
            if lower not in seen_types:
                seen_types.add(lower)
                clean_types.append(lower)
                if len(clean_types) > MAX_COMPRESSION_CONTENT_TYPES:
                    return None, f"content_types exceeds Ferrum's {MAX_COMPRESSION_CONTENT_TYPES}-entry limit"
        config["content_types"] = clean_types
    if gzip_level is not None:
        if isinstance(gzip_level, bool) or not isinstance(gzip_level, int) or not 0 <= gzip_level <= 9:
            return None, "gzip_level must be 0-9"
        config["gzip_level"] = gzip_level
    if brotli_quality is not None:
        if isinstance(brotli_quality, bool) or not isinstance(brotli_quality, int) or not 0 <= brotli_quality <= 11:
            return None, "brotli_quality must be 0-11"
        config["brotli_quality"] = brotli_quality
    if zstd_level is not None:
        if isinstance(zstd_level, bool) or not isinstance(zstd_level, int) or not 1 <= zstd_level <= 19:
            return None, "zstd_level must be 1-19"
        config["zstd_level"] = zstd_level
    if decompress_request is not None:
        if not isinstance(decompress_request, bool):
            return None, "decompress_request must be a boolean"
        config["decompress_request"] = decompress_request
    if remove_accept_encoding is not None:
        if not isinstance(remove_accept_encoding, bool):
            return None, "remove_accept_encoding must be a boolean"
        config["remove_accept_encoding"] = remove_accept_encoding
    if weaken_strong_etag is not None:
        if not isinstance(weaken_strong_etag, bool):
            return None, "weaken_strong_etag must be a boolean"
        config["weaken_strong_etag"] = weaken_strong_etag
    return config, None


def parse_percentage(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if isinstance(value, int):
        if not 0 <= value <= 100:
            return None
        return float(value)
    if not math.isfinite(value) or not 0.0 <= value <= 100.0:
        return None
    return float(value)


_parse_percentage = parse_percentage


def fault_injection_config(
    *,
    abort: dict[str, Any] | None = None,
    delay: dict[str, Any] | None = None,
    match_headers: dict[str, str] | None = None,
) -> tuple[dict | None, str | None]:
    """Build a Ferrum v0.9.21 ``fault_injection`` config."""
    config: dict[str, Any] = {}
    if abort is not None:
        status = util.as_int(abort.get("status_code"))
        if status is None or not 200 <= status <= 599:
            return None, "abort.status_code must be an integer in 200-599"
        pct = _parse_percentage(abort.get("percentage"))
        if pct is None or pct <= 0.0:
            return None, "abort.percentage must be > 0 and <= 100"
        entry: dict[str, Any] = {"status_code": status, "percentage": pct}
        if abort.get("grpc_status") is not None:
            grpc = util.as_int(abort.get("grpc_status"))
            if grpc is None or not 0 <= grpc <= 16:
                return None, "abort.grpc_status must be an integer in 0-16"
            entry["grpc_status"] = grpc
        if abort.get("body") is not None:
            if not isinstance(abort["body"], str):
                return None, "abort.body must be a string"
            entry["body"] = abort["body"]
        config["abort"] = entry
    if delay is not None:
        duration_ms = util.as_int(delay.get("duration_ms"))
        if duration_ms is None or not 1 <= duration_ms <= MAX_FAULT_DELAY_MS:
            return None, f"delay.duration_ms must be 1-{MAX_FAULT_DELAY_MS}"
        pct = _parse_percentage(delay.get("percentage"))
        if pct is None or pct <= 0.0:
            return None, "delay.percentage must be > 0 and <= 100"
        config["delay"] = {"duration_ms": duration_ms, "percentage": pct}
    if not config:
        return None, "fault_injection requires at least one of abort or delay"
    if match_headers:
        if len(match_headers) > MAX_FAULT_MATCH_HEADERS:
            return None, f"match.headers exceeds Ferrum's {MAX_FAULT_MATCH_HEADERS}-header limit"
        clean_headers: dict[str, str] = {}
        for raw_name, raw_value in match_headers.items():
            if not header_name_ok(raw_name):
                return None, "match.headers contains an invalid HTTP header name"
            lower = raw_name.lower()
            folded = fold(lower)
            if lower in _GATEWAY_ASSERTION_HEADERS or folded in _GATEWAY_ASSERTION_HEADERS \
                    or folded.startswith(("x-consumer-", "x-ferrum-", "x-path-param-")):
                return None, f"match.headers cannot name gateway-asserted header {lower}"
            if is_sensitive_header(lower):
                return None, f"match.headers cannot copy credential-like header {lower} into output"
            if lower in clean_headers:
                return None, f"match.headers repeats header {lower}"
            if not header_value_ok(raw_value) or contains_secret_reference(raw_value):
                return None, f"match.headers value for {lower} is invalid or contains a secret reference"
            clean_headers[lower] = raw_value
        config["match"] = {"headers": clean_headers}
    return config, None


def _is_valid_mirror_host(norm_host: str) -> bool:
    """Mirror Ferrum v0.9.21 ``request_mirror::parse_mirror_host`` host rules.

    Accepts canonical IPv4/IPv6 literals (without IPv6 ``%`` zone identifiers) and plain ASCII DNS
    domain names whose labels avoid IDNA/Punycode (``xn--``) UTS #46 edge cases and whose final
    label does not trigger WHATWG URL IPv4 parsing (such as ``127.1`` or ``foo.0x1``).
    """
    if "%" in norm_host:
        return False
    bare = norm_host[1:-1] if norm_host.startswith("[") and norm_host.endswith("]") else norm_host
    try:
        ipaddress.ip_address(bare)
        return True
    except ValueError:
        pass
    trimmed = norm_host.rstrip(".")
    if not trimmed:
        return False
    labels = trimmed.split(".")
    if any(not label or label.lower().startswith("xn--") for label in labels):
        return False
    last = labels[-1]
    if last.isascii() and last.isdigit():
        return False
    if last.lower().startswith("0x") and all(ch in _CORS_HEX_DIGITS for ch in last[2:]):
        return False
    return True


def request_mirror_config(
    host: Any,
    port: Any,
    protocol: str = "http",
    *,
    percentage: float = 100.0,
    mirror_path: str | None = None,
    mirror_request_body: bool | None = None,
    max_body_bytes: int | None = None,
) -> tuple[dict | None, str | None]:
    """Build a Ferrum v0.9.21 ``request_mirror`` config."""
    norm_host = util.normalize_backend_host(host)
    if norm_host is None or not _is_valid_mirror_host(norm_host):
        return None, "mirror_host is not a valid hostname or IP address"
    parsed_port = util.parse_port(port)
    if parsed_port is None:
        return None, "mirror_port must be 1-65535"
    proto = str(protocol).lower()
    if proto not in ("http", "https"):
        return None, "mirror_protocol must be http or https"
    pct = _parse_percentage(percentage)
    if pct is None:
        return None, "percentage must be in 0-100"
    config: dict[str, Any] = {
        "mirror_host": norm_host,
        "mirror_port": parsed_port,
        "mirror_protocol": proto,
        "percentage": pct,
    }
    if proto == "http" and not is_loopback_ip_literal(norm_host):
        config["allow_plaintext"] = True
    if mirror_path is not None:
        if not isinstance(mirror_path, str) or not mirror_path.startswith("/") \
                or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in mirror_path):
            return None, "mirror_path must start with '/' and contain no control characters"
        config["mirror_path"] = mirror_path
    if mirror_request_body is not None:
        if not isinstance(mirror_request_body, bool):
            return None, "mirror_request_body must be a boolean"
        config["mirror_request_body"] = mirror_request_body
    if max_body_bytes is not None:
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int) or max_body_bytes <= 0:
            return None, "max_mirrored_request_body_bytes must be a positive integer"
        config["max_mirrored_request_body_bytes"] = min(max_body_bytes, MAX_MIRROR_BODY_BYTES)
    return config, None


def split_csv(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item).strip() for item in value if str(item).strip()]
    if isinstance(value, str):
        return [item.strip() for item in value.split(",") if item.strip()]
    return []


# ---------------------------------------------------------- weights/retry

def merge_weighted_targets(parts: list[tuple[int, list[Target]]]) -> tuple[list[Target], bool] | None:
    """Merge weighted destinations into one target list; None if nothing receives traffic."""
    positive = [(weight, targets) for weight, targets in parts if weight > 0]
    total = sum(weight for weight, _ in positive)
    if total <= 0:
        return None
    shares: dict[tuple[str, int], float] = {}
    order: list[tuple[str, int]] = []
    for weight, targets in positive:
        target_total = sum(t.weight for t in targets if t.weight > 0)
        if target_total <= 0:
            continue
        for target in targets:
            if target.weight <= 0:
                continue
            key = (target.host, target.port)
            if key not in shares:
                shares[key] = 0.0
                order.append(key)
            shares[key] += (weight / total) * (target.weight / target_total)
    if not order:
        return None
    weights, approximate = util.scale_shares([shares[key] for key in order])
    return [Target(host, port, weight) for (host, port), weight in zip(order, weights)], approximate


RETRY_ON_5XX = list(range(500, 600))


def retry_from_policy(retry_on: Any, attempts: Any) -> tuple[dict | None, list[str]]:
    """Envoy/Istio style ``retry_on`` list into Ferrum ``RetryConfig``."""
    notes: list[str] = []
    count = util.as_int(attempts)
    if count is None:
        count = 1
    if count <= 0:
        return None, notes
    conditions = split_csv(retry_on) if retry_on is not None else ["connect-failure"]
    statuses: set[int] = set()
    connect = False
    for condition in conditions:
        if condition in ("connect-failure", "reset", "refused-stream", "reset-before-request", "unavailable",
                         "cancelled"):
            connect = True
        elif condition == "5xx":
            statuses.update(RETRY_ON_5XX)
            connect = True
        elif condition == "gateway-error":
            statuses.update((502, 503, 504))
        elif condition == "retriable-status-codes":
            notes.append("retriable-status-codes lists are not carried over")
        elif condition.isdigit() and 100 <= int(condition) <= 599:
            statuses.add(int(condition))
        else:
            notes.append(f"retry condition {safe_label(condition, 40)} has no Ferrum equivalent")
    if not connect and not statuses:
        return None, notes
    return {
        "max_retries": min(count, util.MAX_RETRIES),
        "retry_on_connect_failure": connect,
        "retryable_status_codes": sorted(statuses),
    }, notes


# ------------------------------------------------------ frontend isolation

def frontend_conflict(first: tuple[bool, bool], second: tuple[bool, bool]) -> bool:
    """Whether two source scopes' main listeners ``(plaintext, https)`` cannot share Ferrum's listeners.

    Ferrum serves every port-agnostic route on its plaintext and its HTTPS listener. A scope the source served on
    plaintext only would therefore also answer HTTPS requests that the source sent to a scope served on HTTPS
    (with that scope's routes, client-certificate requirement or refusal). The emitter covers the opposite
    direction (HTTPS-only routes are refused, or the plaintext listener is disabled) but nothing restores the
    HTTPS scope for plaintext-only routes, so such a pair is a conflict. Scopes on the same main listeners keep
    the emitter's per-route checks, as in a single-frontend plan.
    """
    if first == second:
        return False
    plain_only = (True, False)
    return (first == plain_only and second[1]) or (second == plain_only and first[1])


def refuse_frontend_scope_conflicts(projections: list[dict], report: Report, code: str) -> None:
    """Refuse overlapping source scopes served through incompatible main listeners (fail closed).

    No longer called by any adapter: host overlap does not decide protocol exposure (Ferrum serves every route on
    every listener it opens, disjoint or unknown host names included). Translators record each route's source
    frontends in ``RouteSpec.protocols`` and the emitter enforces the listener invariant for every platform
    (``ferrum._decide_frontend``). Kept only as a stable helper; do not use it as the protocol-isolation proof.

    The same frontend isolation invariant the Istio adapter enforces for Gateway bindings
    (``istio-frontend-scope-conflict``). Each projection is one source scope on the main listeners (an Envoy
    virtual host, an NGINX server): ``scope`` identifies its source listener/server, ``frontend`` is
    ``(served on main plaintext, served on main HTTPS)``, ``hosts`` its host scope (``[]`` any host, ``None``
    unknown) and ``routes`` every route it produced. It runs on the translator's whole plan, before the emitter
    filters skipped or refused routes, decides TLS-only, or collects client CA bundles, so refused routes and
    scopes whose trust cannot be reproduced still count. When the hosts of a plaintext-only scope overlap a scope
    served on HTTPS, Ferrum cannot keep the two apart, and equivalence of the mixed plan is not provable: every
    route of both scopes is refused and reported. Different trust scopes are never combined. Plans whose scopes
    all use the same main listeners are unchanged.
    """
    conflicts: dict[int, list[str]] = {}
    for i, first in enumerate(projections):
        for j in range(i + 1, len(projections)):
            second = projections[j]
            if first["scope"] == second["scope"] or not frontend_conflict(first["frontend"], second["frontend"]):
                continue
            if not matching.hosts_overlap(first["hosts"], second["hosts"]):
                continue
            conflicts.setdefault(i, []).append(second["ref"])
            conflicts.setdefault(j, []).append(first["ref"])
    for index in sorted(conflicts):
        projection = projections[index]
        others = list(dict.fromkeys(conflicts[index]))
        names = ", ".join(others)[:400]
        reason = (f"a scope the source served through other main listeners ({names}) overlaps its hosts; Ferrum "
                  "serves port-agnostic routes on both its plaintext and HTTPS listeners, so the plaintext-only and "
                  "the HTTPS scope's routes, client-certificate requirement or refusal cannot be kept apart")
        for route in projection["routes"]:
            route.refuse(reason)
        report.error(code, projection["ref"],
                     f"This scope and {len(others)} other scope(s) serve overlapping hosts, one only over plaintext "
                     "and the other over HTTPS. Ferrum serves these routes on all of its listeners, so HTTPS requests "
                     "the source sent to one scope (with its client-certificate requirement or refusal) could reach "
                     "the other scope's routes. Every route of this scope was refused (fail closed).",
                     "Serve the plaintext and HTTPS scopes from separately configured Ferrum instances (convert a "
                     "copy of the source with only one of them), or give the hosts one scope on both listeners, "
                     "then convert again.")


# ------------------------------------------------------ first-match order

def apply_first_match_order(routes: list[RouteSpec], report: Report) -> None:
    """For sources that evaluate routes in order (Envoy, Istio) within one host scope.

    A later route fully covered by an earlier unconditional route is
    unreachable in the source and is skipped. When two routes overlap
    partially and Ferrum's specificity order would pick the later one, both
    are refused (fail closed) because the precedence cannot be reproduced.
    """
    for later_index, later in enumerate(routes):
        if later.skip:
            continue
        for earlier in routes[:later_index]:
            if earlier.skip or earlier.extra_conditions:
                continue
            if not matching.route_overlaps(earlier, later):
                continue
            if matching.route_covers(earlier, later):
                later.skip = True
                later.skip_reason = f"unreachable: {earlier.ref} matches first"
                report.warning("route-shadowed", later.ref,
                               f"Unreachable in the source because {earlier.ref} matches first; not emitted.")
                break
            preferred = matching.ferrum_prefers(earlier, later)
            if preferred is True or (preferred is None and earlier.kind == "regex" and later.kind == "regex"):
                continue
            reason = (f"the source evaluates {earlier.ref} before {later.ref} and they overlap, but Ferrum's "
                      "specificity order would pick differently")
            earlier.refuse(reason)
            later.refuse(reason)
