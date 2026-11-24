"""Helpers shared by the source translators."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .. import matching, util
from ..errors import InputError
from ..limits import Limits
from ..model import RouteSpec, Target
from ..redact import safe_label
from ..report import Report


@dataclass
class SourceContext:
    report: Report
    limits: Limits
    include_secrets: bool = False


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
    return isinstance(name, str) and bool(_TOKEN_RE.match(name))


def header_value_ok(value: Any) -> bool:
    return isinstance(value, str) and all(ch == "\t" or 0x20 <= ord(ch) <= 0x7E for ch in value)


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

def cors_config(origins: Any, methods: Any = None, headers: Any = None, exposed: Any = None,
                credentials: Any = None, max_age: Any = None, preflight_continue: Any = None,
                private_network: Any = None) -> tuple[dict | None, str | None]:
    if not isinstance(origins, list) or not origins:
        return None, "no allowed origins"
    if len(origins) > 64:
        return None, "more than 64 allowed origins"
    clean: list[Any] = []
    for origin in origins:
        if isinstance(origin, str):
            if not origin or len(origin) > 512 or not header_value_ok(origin):
                return None, "an allowed origin is not representable"
            clean.append(origin)
        elif isinstance(origin, dict) and len(origin) == 1 and next(iter(origin)) in ("exact", "prefix", "regex"):
            kind, value = next(iter(origin.items()))
            if not isinstance(value, str) or not value or len(value) > 512:
                return None, "an allowed origin matcher is not representable"
            if kind == "regex" and util.regex_problem(value):
                return None, "an allowed origin regex is not representable"
            clean.append({kind: value})
        else:
            return None, "an allowed origin matcher is not representable"
    config: dict[str, Any] = {"allowed_origins": clean}
    for field_name, values in (("allowed_methods", methods), ("allowed_headers", headers),
                               ("exposed_headers", exposed)):
        if values is None:
            continue
        items = str_list(values)
        if items is None or len(items) > 128 or any(not item or len(item) > 256 or item != item.strip()
                                                    for item in items):
            return None, f"{field_name} is not representable"
        if items:
            config[field_name] = items
    if credentials is not None:
        config["allow_credentials"] = bool(credentials)
    if max_age is not None:
        age = util.as_int(max_age)
        if age is None or age < 0:
            return None, "max_age is not representable"
        config["max_age"] = age
    if preflight_continue is not None:
        config["preflight_continue"] = bool(preflight_continue)
    if private_network is not None:
        config["allow_private_network"] = bool(private_network)
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
