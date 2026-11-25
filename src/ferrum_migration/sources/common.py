"""Helpers shared by the source translators."""

from __future__ import annotations

import base64
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

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
            if not origin or len(origin) > 512 or not header_value_ok(origin, nonempty=True, strict_ws=True):
                return None, "an allowed origin is not representable"
            clean.append(origin)
        elif isinstance(origin, dict) and len(origin) == 1 and next(iter(origin)) in ("exact", "prefix", "regex"):
            kind, value = next(iter(origin.items()))
            if not isinstance(value, str) or not value or len(value) > 512:
                return None, "an allowed origin matcher is not representable"
            if kind in ("exact", "prefix") and not header_value_ok(value, nonempty=True, strict_ws=True):
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
        if age is None or age < 0:
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
_B64URL_NO_PAD_RE = re.compile(r"^[A-Za-z0-9_-]+$")
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
_OUTPUT_CLAIM_RESERVED_HEADERS = (
    GATEWAY_OWNED_REQUEST_HEADERS
    | _CORRELATION_ID_RESERVED_HEADERS
    | frozenset({
        "a-im", "accept", "b3", "baggage", "cache-control", "cdn-loop", "date", "dnt",
        "from", "http2-settings", "max-forwards", "origin", "pragma", "prefer", "priority",
        "range", "referer", "upgrade-insecure-requests", "user-agent",
        "x-forwarded-client-cert", "x-envoy-peer-metadata", "x-envoy-peer-metadata-id",
    })
)
_OUTPUT_CLAIM_RESERVED_PREFIXES = (
    "accept-", "access-control-", "content-", "grpc-", "if-", "proxy-", "sec-",
    "x-b3-", "x-consumer-", "x-ferrum-", "x-forwarded-", "x-path-param-",
)
MAX_COMPRESSION_CONTENT_TYPES = 64
MAX_FAULT_DELAY_MS = 60_000
MAX_FAULT_MATCH_HEADERS = 16
MAX_OUTPUT_CLAIM_HEADERS = 16
MAX_OUTPUT_CLAIM_HEADER_LEN = 128
MAX_OUTPUT_CLAIM_PATH_LEN = 256
MAX_MIRROR_BODY_BYTES = 10 * 1024 * 1024
MAX_JWKS_KEYS = 256
MAX_JWKS_PROVIDERS = 64
MAX_JWKS_CANDIDATE_PROVIDERS = 8
MAX_JWK_ID_BYTES = 1024
MAX_JWK_COMPONENT_BYTES = 4096
MAX_JWK_KEY_OPS = 16
MAX_JWKS_MAX_STALE_SECONDS = 86_400


def _decode_b64url_no_pad(raw: Any) -> bytes | None:
    if not isinstance(raw, str) or not raw or len(raw.encode("utf-8")) > MAX_JWK_COMPONENT_BYTES \
            or not _B64URL_NO_PAD_RE.fullmatch(raw) or len(raw) % 4 == 1:
        return None
    pad = "=" * ((4 - len(raw) % 4) % 4)
    try:
        decoded = base64.urlsafe_b64decode(raw + pad)
    except ValueError:
        return None
    # Match Rust base64::URL_SAFE_NO_PAD (rejects non-zero trailing bits).
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != raw:
        return None
    return decoded


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
        if isinstance(min_content_length, bool) or not isinstance(min_content_length, int) or min_content_length < 0:
            return None, "min_content_length must be a non-negative integer"
        config["min_content_length"] = min_content_length
    if content_types is not None:
        if not isinstance(content_types, list) or not content_types:
            return None, "content_types must be a non-empty list"
        ct_re = _MEDIA_TYPE_RULE_RE if allow_ranges else _EXACT_MEDIA_TYPE_RE
        clean_types: list[str] = []
        for raw in content_types:
            if not isinstance(raw, str) or not raw.isascii() or not ct_re.fullmatch(raw):
                return None, f"content_type {safe_label(raw, 48)} is not a valid Ferrum media type rule"
            lower = raw.lower()
            if lower not in clean_types:
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
    return config, None


def _parse_percentage(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    val = float(value)
    if not math.isfinite(val) or not 0.0 <= val <= 100.0:
        return None
    return val


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
    if norm_host is None:
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


def jwks_provider_config(
    *,
    issuer: Any = None,
    jwks_uri: Any = None,
    jwks: Any = None,
    audiences: Any = None,
    from_headers: Any = None,
    from_params: Any = None,
    forward_original_token: Any = None,
    output_claim_headers: Any = None,
) -> tuple[dict | None, str | None]:
    """Build one validated Ferrum v0.9.21 ``jwks_auth.providers[]`` entry."""
    has_uri = jwks_uri is not None
    has_inline = jwks is not None
    if has_uri == has_inline:
        return None, "provider must specify exactly one of jwks_uri or inline jwks"
    provider: dict[str, Any] = {}
    if has_uri:
        if not isinstance(jwks_uri, str) or not jwks_uri.strip():
            return None, "jwks_uri must be a non-empty URL string"
        uri = jwks_uri.strip()
        if any(ord(ch) <= 0x20 or ord(ch) == 0x7F for ch in uri):
            return None, "jwks_uri contains whitespace or control characters"
        try:
            parts = urlsplit(uri)
            port_val = parts.port
        except ValueError:
            return None, "jwks_uri is not a valid URL"
        if parts.username is not None or parts.password is not None or not parts.hostname:
            return None, "jwks_uri must have a host and no userinfo"
        if port_val == 0:
            return None, "jwks_uri port must be 1-65535"
        if parts.query or parts.fragment:
            return None, "jwks_uri must not contain query parameters or fragments"
        scheme = parts.scheme.lower()
        if scheme == "https":
            pass
        elif scheme == "http" and is_loopback_ip_literal(parts.hostname):
            pass
        else:
            return None, "jwks_uri must use https (or http to a loopback IP literal)"
        provider["jwks_uri"] = uri
    else:
        if isinstance(jwks, str):
            raw_jwks = jwks.strip()
            if not raw_jwks:
                return None, "inline jwks must not be empty"
            try:
                parsed_jwks = json.loads(raw_jwks)
            except ValueError:
                return None, "inline jwks is not valid JSON"
        elif isinstance(jwks, dict):
            parsed_jwks = jwks
        else:
            return None, "inline jwks must be a JSON string or object"
        if not isinstance(parsed_jwks, dict) or not isinstance(parsed_jwks.get("keys"), list) \
                or not parsed_jwks["keys"] or not all(isinstance(k, dict) for k in parsed_jwks["keys"]):
            return None, "inline jwks must be a JWKS object with a non-empty keys array"
        if len(parsed_jwks["keys"]) > MAX_JWKS_KEYS:
            return None, f"inline jwks exceeds Ferrum's {MAX_JWKS_KEYS}-key limit"
        seen_kids: set[str] = set()
        clean_keys: list[dict[str, Any]] = []
        for key_entry in parsed_jwks["keys"]:
            kty = key_entry.get("kty")
            if not isinstance(kty, str) or kty not in ("RSA", "EC", "OKP") \
                    or any(secret_field in key_entry for secret_field in ("d", "p", "q", "dp", "dq", "qi", "k", "oth")):
                return None, "inline jwks contains unsupported, private, or symmetric key material"
            kid = key_entry.get("kid")
            if not isinstance(kid, str) or not kid.strip() or len(kid.encode("utf-8")) > MAX_JWK_ID_BYTES \
                    or contains_secret_reference(kid) or any(ord(c) < 0x20 or ord(c) == 0x7F for c in kid):
                return None, f"every inline jwks key must declare a safe non-empty kid <= {MAX_JWK_ID_BYTES} bytes"
            if kid in seen_kids:
                return None, "inline jwks contains duplicate kid values"
            seen_kids.add(kid)
            for comp_name in ("alg", "use", "n", "e", "crv", "x", "y"):
                comp_val = key_entry.get(comp_name)
                if comp_val is not None and (not isinstance(comp_val, str)
                                             or len(comp_val.encode("utf-8")) > MAX_JWK_COMPONENT_BYTES):
                    return None, f"inline jwks {comp_name} field is invalid or exceeds size limit"
            use = key_entry.get("use")
            if use is not None and use != "sig":
                return None, "inline jwks keys must have use 'sig' when specified"
            key_ops = key_entry.get("key_ops")
            if key_ops is not None:
                if not isinstance(key_ops, list) or len(key_ops) > MAX_JWK_KEY_OPS \
                        or not all(isinstance(op, str) and len(op.encode("utf-8")) <= MAX_JWK_COMPONENT_BYTES
                                   for op in key_ops):
                    return None, "inline jwks key_ops must be a bounded list of strings"
                if "verify" not in key_ops:
                    return None, "inline jwks key_ops must include 'verify' when specified"
                if any(op not in ("sign", "verify") for op in key_ops):
                    return None, "inline jwks key_ops may only contain 'sign' and 'verify'"
            alg = key_entry.get("alg")
            clean_key: dict[str, Any] = {"kty": kty, "kid": kid}
            if use is not None:
                clean_key["use"] = use
            if key_ops is not None:
                clean_key["key_ops"] = list(key_ops)
            if alg is not None:
                clean_key["alg"] = alg
            if kty == "RSA":
                if alg is not None and alg not in ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512"):
                    return None, "inline jwks RSA key has unsupported alg"
                n_bytes = _decode_b64url_no_pad(key_entry.get("n"))
                e_bytes = _decode_b64url_no_pad(key_entry.get("e"))
                if not n_bytes or not e_bytes:
                    return None, "inline jwks RSA key has invalid base64url n/e"
                n_int = int.from_bytes(n_bytes, "big")
                e_int = int.from_bytes(e_bytes, "big")
                if not (2048 <= n_int.bit_length() <= 8192) or e_int < 3 or e_int % 2 == 0:
                    return None, "inline jwks RSA key fails Ferrum modulus/exponent requirements"
                clean_key["n"] = key_entry["n"]
                clean_key["e"] = key_entry["e"]
            elif kty == "EC":
                crv = key_entry.get("crv")
                expected_len = {"P-256": 32, None: 32, "P-384": 48}.get(crv)
                expected_alg = "ES384" if crv == "P-384" else "ES256"
                if expected_len is None:
                    return None, "inline jwks EC key uses an unsupported curve"
                if alg is not None and alg != expected_alg:
                    return None, "inline jwks EC key alg disagrees with curve"
                x_bytes = _decode_b64url_no_pad(key_entry.get("x"))
                y_bytes = _decode_b64url_no_pad(key_entry.get("y"))
                if not x_bytes or not y_bytes or len(x_bytes) != expected_len or len(y_bytes) != expected_len:
                    return None, "inline jwks EC key has invalid x/y coordinates"
                if crv is not None:
                    clean_key["crv"] = crv
                clean_key["x"] = key_entry["x"]
                clean_key["y"] = key_entry["y"]
            else:  # OKP
                if key_entry.get("crv") != "Ed25519":
                    return None, "inline jwks OKP key must use Ed25519 curve"
                if alg is not None and alg != "EdDSA":
                    return None, "inline jwks OKP key alg must be EdDSA when specified"
                x_bytes = _decode_b64url_no_pad(key_entry.get("x"))
                if not x_bytes or len(x_bytes) != 32:
                    return None, "inline jwks OKP Ed25519 key x must decode to 32 bytes"
                clean_key["crv"] = "Ed25519"
                clean_key["x"] = key_entry["x"]
            # Rebuild strictly from validated public fields (never copies x5u URLs or arbitrary metadata).
            clean_keys.append(clean_key)
        provider["jwks"] = {"keys": clean_keys}
    if issuer is not None:
        if not isinstance(issuer, str) or not issuer or issuer != issuer.strip() \
                or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in issuer):
            return None, "issuer must be a non-empty printable string without leading or trailing whitespace"
        provider["issuer"] = issuer
    auds = str_list(audiences) if audiences is not None else None
    if not auds or any(not a or a != a.strip() or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in a) for a in auds):
        return None, ("provider must declare explicit non-empty audiences without leading or trailing whitespace "
                      "(Envoy/Istio skip audience checking when omitted, whereas Ferrum rejects tokens carrying aud)")
    provider["audiences"] = auds
    if from_headers is not None:
        if not isinstance(from_headers, list):
            return None, "from_headers must be a list"
        clean_fh: list[dict[str, str]] = []
        for item in from_headers:
            if not isinstance(item, dict):
                return None, "from_headers entry must be a mapping"
            hname = item.get("name")
            if not isinstance(hname, str) or not hname.strip() or not header_name_ok(hname.strip()):
                return None, "from_headers entry has an invalid header name"
            entry: dict[str, str] = {"name": hname.strip().lower()}
            prefix = item.get("prefix")
            if prefix is not None:
                if not isinstance(prefix, str):
                    return None, "from_headers prefix must be a string"
                if prefix:
                    entry["prefix"] = prefix
            clean_fh.append(entry)
        if clean_fh:
            provider["from_headers"] = clean_fh
    if from_params is not None:
        params = str_list(from_params)
        if params is None or any(not p.strip() or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in p)
                                 for p in params):
            return None, "from_params must be a list of valid parameter names"
        if params:
            provider["from_params"] = [p.strip() for p in params]
    if forward_original_token is not None:
        if not isinstance(forward_original_token, bool):
            return None, "forward_original_token must be a boolean"
        provider["forward_original_token"] = forward_original_token
    if output_claim_headers is not None:
        if not isinstance(output_claim_headers, list):
            return None, "output_claim_headers must be a list"
        if len(output_claim_headers) > MAX_OUTPUT_CLAIM_HEADERS:
            return None, f"output_claim_headers exceeds Ferrum's {MAX_OUTPUT_CLAIM_HEADERS}-entry limit"
        seen_dests: set[str] = set()
        clean_och: list[dict[str, str]] = []
        for item in output_claim_headers:
            if not isinstance(item, dict):
                return None, "output_claim_headers entry must be a mapping"
            claim = item.get("claim")
            header = item.get("header")
            if not isinstance(claim, str) or not claim or len(claim.encode("utf-8")) > MAX_OUTPUT_CLAIM_PATH_LEN \
                    or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in claim) \
                    or any(seg == "" for seg in claim.split(".")):
                return None, "output_claim_headers claim path is not valid"
            if not isinstance(header, str) or not header.strip() or not header_name_ok(header.strip()):
                return None, "output_claim_headers header name is not valid"
            dest = header.strip().lower()
            folded = fold(dest)
            if len(dest.encode("utf-8")) > MAX_OUTPUT_CLAIM_HEADER_LEN \
                    or dest in _OUTPUT_CLAIM_RESERVED_HEADERS or folded in _OUTPUT_CLAIM_RESERVED_HEADERS \
                    or folded.startswith(_OUTPUT_CLAIM_RESERVED_PREFIXES):
                return None, f"output_claim_headers cannot target reserved header {dest}"
            if folded in seen_dests:
                return None, f"output_claim_headers declares header {dest} more than once"
            seen_dests.add(folded)
            clean_och.append({"claim": claim, "header": dest})
        if clean_och:
            provider["output_claim_headers"] = clean_och
    return provider, None


def validate_jwks_providers(providers: list[dict[str, Any]], *, allow_missing_token: bool = False) -> str | None:
    """Enforce Ferrum v0.9.21 aggregate provider bounds and extraction equivalence."""
    if not providers:
        return "jwks_auth requires at least one provider"
    if len(providers) > MAX_JWKS_PROVIDERS:
        return f"at most {MAX_JWKS_PROVIDERS} jwks_auth providers are supported in one instance"
    open_count = 0
    per_issuer: dict[str, int] = {}
    location_sigs: set[tuple] = set()
    for prov in providers:
        iss = prov.get("issuer")
        if iss is None:
            open_count += 1
        else:
            per_issuer[iss] = per_issuer.get(iss, 0) + 1
        fh = prov.get("from_headers") or []
        fp = prov.get("from_params") or []
        if fp:
            return ("query-parameter JWT extraction (from_params) is not migrated: Envoy reads the first matching "
                    "query parameter while Ferrum reads the last")
        if len(fh) != 1:
            return ("every provider must declare exactly one explicit from_headers location; multi-location and "
                    "implicit default (Authorization + access_token) extraction cannot be proven equivalent")
        hname = fh[0]["name"]
        prefix = fh[0].get("prefix")
        if hname == "authorization" and prefix != "Bearer ":
            return "unprefixed or non-Bearer Authorization header extraction differs in Ferrum"
        if allow_missing_token and (hname == "authorization" or prefix is not None):
            return ("with allow_missing_token enabled, prefixed or Authorization header extraction differs from "
                    "Envoy/Istio (Envoy searches for prefix anywhere in the field while Ferrum uses strip_prefix, "
                    "which can treat an invalid token as missing)")
        location_sigs.add((hname, prefix))
    if open_count > MAX_JWKS_CANDIDATE_PROVIDERS:
        return f"at most {MAX_JWKS_CANDIDATE_PROVIDERS} jwks_auth providers may omit issuer"
    if any(count + open_count > MAX_JWKS_CANDIDATE_PROVIDERS for count in per_issuer.values()):
        return f"at most {MAX_JWKS_CANDIDATE_PROVIDERS} candidate jwks_auth providers may match any issuer"
    if len(location_sigs) > 1:
        return "all providers in one jwks_auth instance must share the same single explicit from_headers location"
    return None


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
