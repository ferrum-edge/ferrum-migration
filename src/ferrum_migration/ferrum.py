"""Emit Ferrum Edge file-mode resources from a :class:`~ferrum_migration.model.Plan`.

Fail-closed rules applied here (see ``docs/design.md``):

1. A route the tool cannot translate faithfully is *refused*. If its match is
   representable, a placeholder proxy with the same hosts/path/port is emitted
   whose only plugin is ``request_termination`` (HTTP 503). Ferrum runs that
   plugin before authentication, so the refused match can never fall through
   to a broader, possibly less protected, route.
2. A refused route whose match is *not* representable (header/query/SNI
   matchers, unrepresentable hosts or paths) poisons every overlapping route:
   those are refused too and replaced by placeholders.
3. Routes Ferrum would consider duplicates (same port/path, overlapping hosts)
   are all refused and replaced by one placeholder.
4. Source prefixes use plain string matching, Ferrum matches by path segment.
   Where ``/api`` and a broader route differ in policy, a ``request_termination``
   guard with ``trigger.path_prefix`` is added to the broader route so
   ``/apix`` cannot reach it. A refused string-prefix route's placeholder counts
   too, so its siblings never fall through to a broader live route (guarded even
   when the broader route serves more hosts; error ``prefix-divergence-refused``).
   A trailing-slash prefix gets an exact 404 route
   for its bare path. Routes are never widened to cover ``/apix``. For routes
   whose source matched literal string prefixes (NGINX prefix locations, Kong
   ``paths``, Traefik ``PathPrefix``, Envoy ``prefix``, Istio ``uri.prefix``),
   sibling paths that no equivalent route catches are reported as a
   ``prefix-string-siblings`` error instead of becoming silent 404s.
5. Source scopes that do not fall through between hosts (NGINX servers, Envoy
   virtual hosts, Istio hosts) get a host-only 404 route so unmatched paths do
   not reach another host tier. Only a closure for the same host names counts:
   a covering wildcard closure does not close a narrower scope (Ferrum tries all
   wildcard path routes before wildcard host-only routes). When an overlapping
   host-only route blocks the closure, a ``~/.*`` regex 404 route closes the
   scope; when neither fits, the routes that would receive its unmatched
   requests are refused (error ``scope-closure-skipped``). A wildcard scope
   covering another scope's narrower wildcard has its routes refused
   (``nested-wildcard-scope``): Ferrum's wildcard tier mixes their path routes.
6. Ferrum serves every route on each listener its profile opens, so a live
   route must have been served by the source on every opened protocol
   (``RouteSpec.protocols``; host names never prove isolation). HTTPS-only
   output (``FERRUM_PROXY_HTTP_PORT=0``) refuses plaintext-only routes; with the
   plaintext listener open, HTTPS-only routes are refused and the HTTPS listener
   is disabled explicitly (``FERRUM_PROXY_HTTPS_PORT=0``, no frontend TLS) unless
   every live route was served on both. Unknown frontend metadata refuses the
   whole plan. A final output invariant checks the emitted candidates, and the
   rendered profile is checked against the decision.
7. Backend TLS verification is never disabled. There is no opt-out: a source
   that did not verify gets verification turned on (warning), and every emitted
   ``backend_tls_verify_server_cert`` is literally ``true``.
8. Ferrum file mode has one frontend client CA bundle for its whole HTTPS
   listener. It is configured only when every migrated route that required
   client certificates named the same single bundle. Several bundles from
   separate source servers/listeners are never merged (that would let clients
   trusted by one scope reach another): the affected routes are refused and a
   ``frontend-client-ca-scope`` error asks for separately configured frontends.
9. Listener-scoped HTTP proxies (``listen_port``) are never emitted. Ferrum
   ranks host and path before it compares ports, and port-agnostic routes serve
   every HTTP frontend, so main-listener routes would answer on an extra
   listener and the extra listener's routes cannot be isolated. Routes the
   source served only on an extra plaintext listener are not migrated
   (``extra-listener-refused``); a final output invariant enforces this.
10. A route the source matched case-insensitively keeps only its exact-case
   path in Ferrum; every other route that could receive its case variants is
   refused (fail closed) instead of forwarding them.
11. Emitted proxy and upstream names are unique (compared trimmed and
   case-folded, within Ferrum's byte limit), deterministic and readable.
"""

from __future__ import annotations

import bisect
import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import matching, util
from .model import BackendRef, Plan, PluginSpec, RouteSpec, TlsSpec, UpstreamSpec
from .redact import safe_label
from .report import Report
from .sources.common import MAX_COOKIE_TTL_SECONDS, cookie_domain_ok, cookie_path_ok, hash_on_value

PLACEHOLDER_HOST = "ferrum-migration-refused.invalid"
PLACEHOLDER_PORT = 9
REFUSED_TERMINATION = {"status_code": 503, "content_type": "application/json", "message": "Route not migrated"}
NOT_FOUND_TERMINATION = {"status_code": 404, "content_type": "application/json", "message": "Not found"}
LABEL_SOURCE = "ferrum-migration/source"
LABEL_REF = "ferrum-migration/ref"
LABEL_STATUS = "ferrum-migration/status"
MIN_KEYAUTH_KEY_LENGTH = 16
MIN_JWT_SECRET_LENGTH = 32
MAX_CREDENTIAL_VALUE_LENGTH = 4096
MAX_CREDENTIALS_SIZE = 65_536
MAX_CREDENTIALS_PER_TYPE = 2
CREDENTIAL_REDACTION_PLACEHOLDER = "[REDACTED]"
MAX_PLUGIN_CONFIG_BYTES = 1_048_576
_HEADER_TOKEN_RE = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_RESERVED_TERM_HEADERS = frozenset({
    "connection", "keep-alive", "proxy-authenticate", "proxy-connection", "te", "trailer",
    "transfer-encoding", "upgrade", "content-length", "content-type",
    "authentication-info", "authorization", "proxy-authentication-info", "proxy-authorization",
    "set-cookie", "set-cookie2", "www-authenticate",
    "x-gateway-error", "x-gateway-upstream-status",
})
_NO_BODY_STATUSES = frozenset({204, 205, 304})


@dataclass
class EmitOptions:
    include_secrets: bool = False
    tls_only: bool = False


@dataclass
class EmitResult:
    config: dict[str, Any]
    stats: dict[str, Any]
    tls_only: bool
    basic_auth_used: bool
    secrets_emitted: int
    #: Ferrum listeners the profile opens: "http", "https" or "both" (also stored in ``plan.settings``).
    frontend_protocols: str = "both"


#: Protocols each frontend mode serves every emitted route on.
FRONTEND_MODES = {"both": frozenset({"http", "https"}), "http": frozenset({"http"}), "https": frozenset({"https"})}


@dataclass
class _Cand:
    route: RouteSpec
    placeholder: bool
    hosts: list[str]
    listen_path: str | None
    listen_port: int | None
    termination: dict | None = None
    guards: list[str] = field(default_factory=list)
    kind_label: str = "migrated"


def emit(plan: Plan, options: EmitOptions, report: Report) -> EmitResult:
    routes = plan.routes
    _refuse_extra_listeners(plan, routes, report)
    valid_globals: list[PluginSpec] = []
    for plugin in plan.global_plugins:
        if plugin.name == "request_termination":
            problem = validate_termination_config(plugin.config)
            if problem:
                plan.global_refusals.append(f"global request_termination: {problem}")
                report.error("global-plugin-invalid", plugin.ref or "global",
                             f"Global request_termination config is not representable ({problem}); every route is "
                             "refused (fail closed).")
                continue
        valid_globals.append(plugin)
    plan.global_plugins = valid_globals
    for reason in plan.global_refusals:
        for route in routes:
            if not route.skip:
                route.refuse(f"a global plugin could not be translated ({reason})")
    for route in routes:
        _validate_route(route, plan, options, report)
    # Decided before any candidate exists; every later step only adds refusals, so the decision stays valid.
    mode = _decide_frontend(plan, routes, options, report)
    tls_only = mode == "https"
    opened = FRONTEND_MODES[mode]
    plan.host_scopes = [
        scope for scope in plan.host_scopes
        if scope.protocols is None or bool(opened & scope.protocols)
    ]
    _poison(routes, mode)
    _poison_case_variants(plan, routes, mode)
    _resolve_frontend_client_ca(plan, routes, report, mode)
    candidates = _build_candidates(routes)
    candidates = _drop_off_protocol_slot_conflicts(plan, candidates, mode)
    candidates = _resolve_conflicts(candidates, report)
    has_deferred_redirects = any(route.https_redirect_fold is not None for route in routes)
    pre_closure_state = (
        [(route, list(route.refusals), route.placeholder_emitted) for route in routes]
        if has_deferred_redirects else None
    )
    staged_report = Report(report.platform, report.input_label)
    _add_scope_closures(plan, candidates, staged_report)
    _add_trailing_slash_placeholders(candidates, staged_report)
    _add_divergence_guards(plan, candidates, staged_report)
    candidates = _finalize_https_redirects(plan, routes, candidates, mode, options, report, staged_report,
                                           pre_closure_state)
    _assert_frontend_protocols(candidates, mode)
    builder = _Builder(plan, options, report)
    config = builder.build(candidates)
    _assert_backend_tls_verified(config)
    _assert_no_listener_scoped_proxies(config)
    _assert_unique_proxy_names(config)
    _report_routes(routes, report)
    _report_timeout_semantics(plan, routes, report)
    stats = builder.stats(routes, candidates)
    stats["tls_only"] = tls_only
    stats["frontend_protocols"] = mode
    return EmitResult(config=config, stats=stats, tls_only=tls_only,
                      basic_auth_used=builder.basic_auth_used, secrets_emitted=builder.secrets_emitted,
                      frontend_protocols=mode)


def _replay_report(target: Report, staged: Report) -> None:
    for item in staged.caveats:
        target.add(item.severity, item.code, item.ref, item.message, item.action)


def _finalize_https_redirects(plan: Plan, routes: list[RouteSpec], candidates: list[_Cand], mode: str,
                              options: EmitOptions, report: Report, staged_report: Report,
                              pre_closure_state: list[tuple[RouteSpec, list[str], bool]] | None) -> list[_Cand]:
    """Confirm deferred plaintext HTTP-to-HTTPS redirect folds only after final candidate resolution.

    A redirect candidate folds away (and emits its ``*-https-redirect`` info diagnostic) only if the final
    profile disables plaintext (``mode == "https"``) AND at least one live (non-placeholder) HTTPS candidate
    survived validation, precedence, poisoning, client-CA scope, slot conflict resolution, and scope closures.
    Otherwise, restore pre-pass route state, discard provisional closure/guard diagnostics, un-skip and validate
    the restored redirect candidates, and rebuild candidates, closures, and guards cleanly.
    """
    deferred = [route for route in routes if route.https_redirect_fold is not None]
    if not deferred:
        _replay_report(report, staged_report)
        return candidates
    has_surviving_https = mode == "https" and any(
        not cand.placeholder and "https" in (_effective_protocols(cand.route) or ())
        for cand in candidates
    )
    if has_surviving_https:
        _replay_report(report, staged_report)
        plan.settings.https_redirect_seen = True
        seen: set[tuple[str, str]] = set()
        for route in deferred:
            assert route.https_redirect_fold is not None
            code, ref = route.https_redirect_fold
            if (code, ref) not in seen:
                seen.add((code, ref))
                report.info(code, ref,
                            "HTTP-to-HTTPS redirect: not emitted; Ferrum's TLS-only profile disables the plaintext "
                            "listener instead.")
        return candidates
    if pre_closure_state is not None:
        for route, saved_refusals, saved_placeholder in pre_closure_state:
            route.refusals = saved_refusals
            route.placeholder_emitted = saved_placeholder
    for route in deferred:
        route.skip = False
        route.skip_reason = ""
        route.https_redirect_fold = None
        route.refuse("HTTP-to-HTTPS redirect cannot be folded away because no live HTTPS route survived validation")
        _validate_route(route, plan, options, report)
    _poison(routes, mode)
    _poison_case_variants(plan, routes, mode)
    rebuilt = _build_candidates(routes)
    rebuilt = _drop_off_protocol_slot_conflicts(plan, rebuilt, mode)
    rebuilt = _resolve_conflicts(rebuilt, report)
    _add_scope_closures(plan, rebuilt, report)
    _add_trailing_slash_placeholders(rebuilt, report)
    _add_divergence_guards(plan, rebuilt, report)
    return rebuilt


def _assert_frontend_protocols(candidates: list[_Cand], mode: str) -> None:
    """Hard invariant: every live (non-placeholder) route was served by the source on every listener Ferrum opens.

    Ferrum serves port-agnostic routes on each listener its profile opens, so a live route whose source frontend
    does not include one of them would be exposed there. Placeholders and synthetic 404 routes fail closed on any
    listener. A violation is a tool bug: it raises, and the CLI writes nothing.
    """
    required = FRONTEND_MODES[mode]
    for cand in candidates:
        if cand.placeholder:
            continue
        protocols = _effective_protocols(cand.route)
        if protocols is None or not required <= protocols:
            raise AssertionError("a live route would be served on a frontend protocol the source never served it on")


def _assert_backend_tls_verified(config: dict[str, Any]) -> None:
    """Hard invariant: no emitted proxy or upstream disables backend TLS verification.

    A violation is a tool bug, so it raises (the CLI reports an internal error and
    writes nothing) instead of emitting insecure output.
    """
    for kind in ("proxies", "upstreams"):
        for item in config.get(kind, []):
            if item.get("backend_tls_verify_server_cert", True) is not True:
                raise AssertionError("backend TLS verification must never be disabled in emitted output")


def _assert_no_listener_scoped_proxies(config: dict[str, Any]) -> None:
    """Hard invariant: no emitted proxy is scoped to an extra listener (see ``_refuse_extra_listeners``)."""
    for item in config.get("proxies", []):
        if item.get("listen_port") is not None:
            raise AssertionError("listener-scoped HTTP proxies must never be emitted")


def _assert_unique_proxy_names(config: dict[str, Any]) -> None:
    """Hard invariant: Ferrum admits neither duplicate proxy ids nor duplicate proxy names."""
    for kind in ("proxies", "upstreams"):
        names = [_NameAllocator.key(item["name"]) for item in config.get(kind, []) if "name" in item]
        ids = [item["id"] for item in config.get(kind, [])]
        if len(names) != len(set(names)) or len(ids) != len(set(ids)):
            raise AssertionError(f"emitted {kind} must have unique ids and names")


def _refuse_extra_listeners(plan: Plan, routes: list[RouteSpec], report: Report) -> None:
    """Never emit listener-scoped HTTP proxies; routes served only on an extra plaintext listener are not migrated.

    A Ferrum proxy with ``listen_port`` is only one candidate inside a host/path slot: the router picks the host
    tier and the longest path first and compares ports last, and a port-agnostic proxy serves every HTTP frontend.
    Main-listener routes (which every source emits port-agnostic) would therefore answer requests on the extra
    listener whenever their host/path is more specific, and the extra listener's own routes cannot be isolated
    from them. No per-listener scoping in this output can express the source's separate listeners, so these
    routes get no proxy at all (not even a placeholder, which would make Ferrum serve that port), their host scopes
    get no closure, and Ferrum does not listen on that port.
    """
    plan.host_scopes = [scope for scope in plan.host_scopes if scope.listen_port is None]
    for route in routes:
        if route.skip or route.listen_port is None:
            continue
        port = route.listen_port
        route.skip = True
        route.skip_reason = f"served only on extra plaintext listener {port}"
        report.error("extra-listener-refused", route.ref,
                     f"The source served this route only on plaintext port {port}, not on the main listeners. A "
                     "Ferrum route scoped to that port (listen_port) cannot be kept apart from the main routes: Ferrum "
                     "selects host and path before it compares ports, and port-agnostic routes serve every HTTP "
                     "listener, so the two listeners' routes would mix. The route was not migrated and no proxy is "
                     "emitted for that port, so Ferrum does not serve it (fail closed).",
                     "Serve that listener from a separately configured Ferrum instance whose main plaintext port is "
                     "that port (convert a copy of the source that contains only those servers or listeners), and "
                     "validate it separately.")


# ------------------------------------------------------------------ validation

def _validate_route(route: RouteSpec, plan: Plan, options: EmitOptions, report: Report) -> None:
    if route.skip:
        return
    if route.hosts is not None:
        normalized: list[str] = []
        seen_hosts: set[str] = set()
        for host in route.hosts:
            value = util.normalize_host(host)
            if value is None:
                route.refuse(f"host {safe_label(host)} is not representable in Ferrum")
                route.hosts = None
                route.extra_conditions = True
                break
            if value not in seen_hosts:
                seen_hosts.add(value)
                normalized.append(value)
        else:
            if len(normalized) > util.MAX_HOSTS_PER_PROXY:
                route.refuse("more than 100 hosts on one route")
            route.hosts = normalized
    if route.kind == "hostonly" and not route.hosts:
        if route.hosts == []:
            route.kind, route.path = "prefix", "/"
        else:
            route.path_ok = False
    if route.kind in ("prefix", "exact"):
        path = route.path or "/"
        if route.kind == "prefix" and path != "/" and path.endswith("/"):
            route.trailing_slash = True
            path = path[:-1]
        problem = util.canonical_path_problem(path)
        if not problem and route.kind == "exact" and len(path.encode("utf-8")) + 1 > util.MAX_LISTEN_PATH_LENGTH:
            problem = f"serialized exact listen_path exceeds {util.MAX_LISTEN_PATH_LENGTH} bytes"
        if not problem and route.kind == "prefix" and route.trailing_slash \
                and route.prefix_semantics == "string" \
                and len(path.encode("utf-8")) + 1 > util.MAX_LISTEN_PATH_LENGTH:
            problem = (f"trailing-slash prefix bare-path exact guard exceeds {util.MAX_LISTEN_PATH_LENGTH} bytes")
        if problem:
            route.refuse(f"path is not representable ({problem})")
            route.path_ok = False
            route.extra_conditions = True
        else:
            route.path = path
    elif route.kind == "regex":
        problem = util.regex_problem(route.path, max_bytes=util.MAX_LISTEN_PATH_LENGTH - 1)
        if problem:
            route.refuse(f"path regex is not representable ({problem})")
            route.path_ok = False
            route.extra_conditions = True
    elif route.kind == "hostonly":
        route.path = None
    if route.hosts and len(route.hosts) > util.MAX_HOSTS_PER_PROXY \
            and _chunk_hosts_no_prune(route.hosts, host_only=route.kind == "hostonly") is None:
        route.path_ok = False
        route.extra_conditions = True
    if route.methods is not None:
        methods: list[str] = []
        for method in route.methods:
            upper = str(method).strip().upper()
            if upper not in util.VALID_HTTP_METHODS:
                route.refuse(f"HTTP method {safe_label(method, 16)} is not supported by Ferrum")
                break
            if upper not in methods:
                methods.append(upper)
        route.methods = methods or None
    if route.termination is None:
        _validate_backend(route, plan, options, report)
    else:
        _validate_termination(route)
    if route.backend_path:
        path = route.backend_path.rstrip("/")
        if not path:
            route.backend_path = None
        else:
            problem = util.canonical_path_problem(path)
            if problem or len(path) > util.MAX_BACKEND_PATH_LENGTH:
                route.refuse(f"backend path is not representable ({problem or 'too long'})")
            else:
                route.backend_path = path
    for attr in ("connect_timeout_ms", "read_timeout_ms", "write_timeout_ms"):
        value, clamped = util.clamp_timeout(getattr(route, attr))
        setattr(route, attr, value)
        if clamped:
            report.warning("timeout-clamped", route.ref,
                           "A timeout above Ferrum's 24h maximum (or a disabled timeout) was set to 24h.")
    for plugin in route.plugins:
        if len(json.dumps(plugin.config, sort_keys=True).encode("utf-8")) > MAX_PLUGIN_CONFIG_BYTES:
            route.refuse(f"plugin {plugin.name} config exceeds Ferrum's 1 MiB limit")


def _term_header_value_ok(value: object, *, allow_outer_ws: bool = False) -> bool:
    if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
        return False
    if not allow_outer_ws and value and (value[0] in (" ", "\t") or value[-1] in (" ", "\t")):
        return False
    return all(ch == "\t" or 0x20 <= ord(ch) <= 0x7E for ch in value)


def validate_termination_config(termination: object) -> str | None:
    """Validate a Ferrum ``request_termination`` config against ``src/plugins/request_termination.rs``."""
    if not isinstance(termination, dict):
        return "termination response is not representable"
    status = termination.get("status_code")
    if isinstance(status, bool) or not isinstance(status, int) or not 200 <= status <= 599:
        return "termination status code is outside 200-599"
    content_type = termination.get("content_type")
    if content_type is not None:
        if not isinstance(content_type, str) or not content_type.strip(" \t") \
                or not _term_header_value_ok(content_type, allow_outer_ws=True):
            return "termination content_type is not representable"
    body = termination.get("body")
    if body is not None and not isinstance(body, str):
        return "termination body is not a string"
    message = termination.get("message")
    if message is not None and not isinstance(message, str):
        return "termination message is not a string"
    if status in _NO_BODY_STATUSES and body:
        return f"termination status {status} cannot carry a non-empty response body"
    headers = termination.get("headers")
    if headers is not None:
        if not isinstance(headers, dict) or len(headers) > 32:
            return "termination headers are not representable"
        seen_names: set[str] = set()
        for key, value in headers.items():
            if not isinstance(key, str) or not _HEADER_TOKEN_RE.fullmatch(key):
                return "a termination header name is invalid"
            lower = key.lower()
            if lower in _RESERVED_TERM_HEADERS or lower.startswith(("x-ferrum-", "grpc-")):
                return f"termination header {lower} is reserved by Ferrum"
            if lower in seen_names:
                return f"duplicate termination header {lower}"
            seen_names.add(lower)
            if not _term_header_value_ok(value):
                return f"termination header {lower} has an unrepresentable value"
    try:
        encoded_size = len(json.dumps(termination, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return "termination response is not JSON-serializable"
    if encoded_size > MAX_PLUGIN_CONFIG_BYTES:
        return "termination plugin config exceeds Ferrum's 1 MiB limit"
    return None


def _validate_termination(route: RouteSpec) -> None:
    problem = validate_termination_config(route.termination)
    if problem:
        route.refuse(problem)


def _validate_backend(route: RouteSpec, plan: Plan, options: EmitOptions, report: Report) -> None:
    backend = route.backend
    if backend is None:
        route.refuse("no usable backend")
        return
    if backend.scheme not in ("http", "https"):
        route.refuse("backend protocol is not HTTP(S)")
        return
    if backend.upstream_key:
        upstream = plan.upstreams.get(backend.upstream_key)
        if upstream is None or not upstream.targets:
            route.refuse("upstream has no usable targets")
            return
        if len(upstream.targets) > util.MAX_TARGETS_PER_UPSTREAM:
            route.refuse("upstream has more than 1000 targets")
            return
        for target in upstream.targets:
            host = util.normalize_backend_host(target.host)
            if host is None or util.parse_port(target.port) is None:
                route.refuse(f"upstream target {safe_label(target.host)} is not a valid host/port")
                return
            target.host = host
            target.weight = max(1, min(int(target.weight), util.MAX_TARGET_WEIGHT))
        if backend.scheme == "https":
            if upstream.tls.sni is not None and not util.valid_backend_tls_sni(upstream.tls.sni):
                route.refuse("upstream backend TLS SNI is not a valid DNS hostname")
                return
            deduped_sans = list(dict.fromkeys(upstream.tls.san_allow_list))
            if len(deduped_sans) > util.MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES:
                route.refuse(f"upstream backend TLS SAN allow-list exceeds Ferrum's "
                             f"{util.MAX_BACKEND_TLS_SAN_ALLOW_LIST_ENTRIES}-entry limit")
                return
            if any(not util.valid_backend_tls_san(san) for san in deduped_sans):
                route.refuse("upstream backend TLS SAN allow-list contains an entry Ferrum cannot represent")
                return
            upstream.tls.san_allow_list = deduped_sans
            _apply_tls_policy(upstream.tls, upstream.ref, options, report)
        return
    host = util.normalize_backend_host(backend.host)
    if host is None or util.parse_port(backend.port) is None:
        route.refuse(f"backend {safe_label(backend.host)} is not a valid host/port")
        return
    backend.host = host
    if backend.scheme == "https":
        if backend.tls.sni or backend.tls.san_allow_list:
            route.refuse("backend TLS SNI/SAN overrides are only representable on upstreams")
            return
        _apply_tls_policy(backend.tls, route.ref, options, report)


def _apply_tls_policy(tls: TlsSpec, ref: str, options: EmitOptions, report: Report) -> None:
    if tls.ca_path or tls.client_cert_path:
        report.info("backend-tls-files", ref,
                    "Backend TLS refers to CA/client certificate file paths from the source. Ferrum checks these "
                    "files when it loads the config, so `ferrum-edge validate` fails until they exist on the "
                    "Ferrum host at the same paths. The files are never read or copied by this tool.",
                    "Provide the CA bundle (and client cert/key) at those paths, or edit the paths.")
    if tls.verify:
        return
    # There is deliberately no opt-out: insecure backend TLS is never emitted.
    tls.verify = True
    report.warning("backend-tls-verify-enabled", ref,
                   "The source did not verify the backend TLS certificate; Ferrum will verify it. Requests "
                   "fail closed if the backend certificate is self-signed or does not match the host.",
                   "Provide the backend CA (backend_tls_server_ca_cert_path) if the backend uses a private CA.")


def _effective_protocols(route: RouteSpec) -> frozenset[str] | None:
    """The source main frontends of ``route`` (``None``: unknown). ``requires_tls`` never leaves plaintext in it."""
    if route.protocols is None:
        return None
    protocols = frozenset(p for p in route.protocols if p in ("http", "https"))
    return protocols - {"http"} if route.requires_tls else protocols


def _source_https_activity(plan: Plan, present: list[RouteSpec]) -> bool:
    """Whether the source had any HTTPS frontend, projected or not (settings captured from skipped listeners count)."""
    settings = plan.settings
    return bool(settings.main_https_port or settings.frontend_tls_expected or settings.frontend_cert_pairs
                or any("https" in (_effective_protocols(route) or ()) for route in present))


def _decide_frontend(plan: Plan, routes: list[RouteSpec], options: EmitOptions, report: Report) -> str:
    """Decide which Ferrum listeners the output opens; refuse every live route the source did not serve on all of them.

    Ferrum serves each emitted (port-agnostic) route on every listener its profile opens, whatever the source host
    patterns: host names that look disjoint, unknown host input or the same listener strings prove nothing, and
    neither does the absence of TLS directives (Ferrum opens HTTPS on its default port whenever frontend TLS
    material is configured). The invariant is therefore tied to the opened listeners and every live route's source
    frontends (``RouteSpec.protocols``), never to pairwise overlaps:

    * Unknown frontend metadata on a live route: the source frontends cannot be accounted for, so every route of
      the plan is refused (``frontend-protocol-unknown``) before any candidate exists.
    * HTTPS only (``--tls-only``, or no live route was served over plaintext): ``FERRUM_PROXY_HTTP_PORT=0``; live
      routes the source never served over HTTPS are refused (``frontend-protocol-scope``).
    * Otherwise the plaintext listener stays. HTTPS-only routes are refused (as before). The HTTPS listener stays
      open only when every remaining live route was also served over HTTPS; else it is disabled explicitly
      (``FERRUM_PROXY_HTTPS_PORT=0``, no frontend TLS settings) and reported (``frontend-https-disabled``).

    Refused routes become 503 placeholders, which fail closed on any listener. Later emitter steps only add
    refusals, so the decision stays valid; ``_assert_frontend_protocols`` re-checks it on the final candidates.
    """
    present = [route for route in routes if not route.skip]
    unknown = [route for route in present if not route.refusals and _effective_protocols(route) is None]
    if unknown:
        for route in present:
            route.refuse("the source frontend (plaintext or HTTPS listener) of some routes in this plan is unknown, "
                         "so no Ferrum listener set can be proven to serve only what the source served")
        report.error("frontend-protocol-unknown", "frontend listeners",
                     f"{len(unknown)} route(s) carry no source frontend information (which main plaintext or HTTPS "
                     "listener served them). Ferrum serves every route on each listener it opens, so the plan "
                     "could expose routes on a protocol the source never used. Every route was refused (fail closed).",
                     "Report this as a converter issue; convert the listeners separately in the meantime.")
    active = [route for route in present if not route.refusals]
    for route in active:
        if not _effective_protocols(route):
            route.refuse("the source served this route on no main plaintext or HTTPS listener that Ferrum provides "
                         "(for example a plaintext listener that requires TLS), so it cannot be served faithfully")
    active = [route for route in active if not route.refusals]
    plaintext = [route for route in active if "http" in _effective_protocols(route)]
    tls_only = options.tls_only or (bool(active) and not plaintext)
    if tls_only:
        if not options.tls_only:
            report.info("tls-only", "-",
                        "Every migrated route requires HTTPS in the source, so the profile disables Ferrum's "
                        "plaintext listener (FERRUM_PROXY_HTTP_PORT=0).")
        for route in active:
            if route.listen_port is not None:
                route.refuse("served on an extra plaintext port, which cannot exist in TLS-only mode")
        exposed = [route for route in active if not route.refusals and "https" not in _effective_protocols(route)]
        for route in exposed:
            route.refuse("the source served this route over plaintext only; with Ferrum's plaintext listener "
                         "disabled it would be served on the HTTPS listener, where the source never served it")
        if exposed:
            report.error("frontend-protocol-scope", "frontend listeners",
                         f"The profile disables Ferrum's plaintext listener, but {len(exposed)} route(s) were served "
                         "over plaintext only in the source. Ferrum would serve them on its HTTPS listener (whatever "
                         "their host names), so they were refused (fail closed).",
                         "Serve the plaintext routes from a separately configured Ferrum instance (convert a copy of "
                         "the source that contains only them), then validate each instance.")
        mode = "https"
    else:
        for route in active:
            if "http" not in _effective_protocols(route):
                route.refuse("the source serves this route over HTTPS only, but other routes are plaintext and "
                             "Ferrum would expose it on the plaintext listener too (re-run with --tls-only)")
        remaining = [route for route in active if not route.refusals]
        scope_protos_by_host: dict[str, set[str]] = {}
        for scope in plan.host_scopes:
            if scope.listen_port is not None or scope.protocols is None:
                continue
            for host in _scope_hosts(scope):
                scope_protos_by_host.setdefault(host, set()).update(scope.protocols)
        asymmetric_scope_hosts = [
            host for host, protos in scope_protos_by_host.items()
            if protos in ({"http"}, {"https"})
        ]
        if not remaining or (
            all("https" in _effective_protocols(route) for route in remaining)
            and not asymmetric_scope_hosts
        ):
            mode = "both"  # nothing live, or every live route and host scope covers both main listeners
            http_port = plan.settings.main_http_port or 8000
            https_port = plan.settings.main_https_port or 8443
            if (plan.settings.main_https_port or _source_https_activity(plan, present)) and http_port == https_port:
                mode = "http"
                report.error("frontend-port-conflict", "frontend listeners",
                             f"The source binds both plaintext HTTP and HTTPS on port {http_port}. Ferrum cannot "
                             "open both listeners on the same port and bind address, so the profile disables the "
                             "HTTPS listener (FERRUM_PROXY_HTTPS_PORT=0).",
                             "Serve the plaintext and HTTPS listeners on distinct ports or from separate Ferrum "
                             "instances, then convert again.")
        else:
            mode = "http"
            plaintext_only = sum(1 for route in remaining if "https" not in _effective_protocols(route))
            dual = len(remaining) - plaintext_only
            if _source_https_activity(plan, present):
                scope_note = (
                    f" ({len(asymmetric_scope_hosts)} host scope(s) also existed on only one listener)"
                    if asymmetric_scope_hosts else ""
                )
                report.error("frontend-https-disabled", "frontend listeners",
                             f"{plaintext_only} migrated route(s) were served over plaintext only in the source"
                             f"{scope_note}. Ferrum serves every route and scope closure on each listener it opens, "
                             "whatever its host names, so with HTTPS open plaintext-only routes or closures would "
                             "affect HTTPS requests the source routed differently. The profile therefore disables "
                             "Ferrum's HTTPS listener (FERRUM_PROXY_HTTPS_PORT=0) and configures no frontend TLS. "
                             f"{dual} migrated route(s) the source also served over HTTPS are served over plaintext "
                             "only, and HTTPS-only routes were refused (fail closed).",
                             "Serve the source's HTTPS listener from a separately configured Ferrum instance (convert "
                             "a copy of the source that contains only it, or re-run with --tls-only to keep only the "
                             "routes the source served over HTTPS), then validate each instance.")
            else:
                report.info("frontend-http-only", "frontend listeners",
                            "Every migrated route was served over plaintext only in the source, so the profile "
                            "disables Ferrum's HTTPS listener explicitly (FERRUM_PROXY_HTTPS_PORT=0); otherwise it "
                            "would open on its default port as soon as frontend TLS material is configured.")
    plan.settings.frontend_protocols = mode
    return mode


def _resolve_frontend_client_ca(plan: Plan, routes: list[RouteSpec], report: Report, mode: str = "both") -> None:
    """Configure the listener-wide client CA bundle only when it preserves every route's trust scope.

    Ferrum file mode verifies client certificates with one bundle
    (``FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH``) for its whole HTTPS listener. One bundle
    named by every route that required client certificates is equivalent for those routes
    (routes that required none become stricter: warning). Several bundles cannot be scoped
    per host/listener, and merging them would widen who is trusted, so none is configured and
    every route that required one is refused (fail closed). With the HTTPS listener disabled
    (``mode == "http"``) no client CA applies: the source never asked for client certificates
    over plaintext, and the profile configures no frontend TLS at all.
    """
    settings = plan.settings
    settings.client_ca_paths = []
    settings.client_ca_scope_conflict = False
    if mode == "http":
        return
    live = [route for route in routes if not route.skip and not route.refusals]
    required = sorted({ca for route in live for ca in route.client_cas})
    if not required:
        return
    if len(required) == 1:
        settings.client_ca_paths = required
        open_routes = [route for route in live if not route.client_cas]
        if open_routes:
            report.warning("frontend-client-ca-shared", "frontend client CA",
                           f"Ferrum applies one frontend client CA bundle to its whole HTTPS listener. "
                           f"{len(open_routes)} migrated route(s) that did not require client certificates in the "
                           "source will require a certificate from that CA over HTTPS in Ferrum (stricter).",
                           "If those routes must stay reachable without client certificates, serve them from a "
                           "separately configured Ferrum frontend without FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH, "
                           "and validate it separately.")
        return
    settings.client_ca_scope_conflict = True
    affected = [route for route in live if route.client_cas]
    for route in affected:
        route.refuse("the source required client certificates whose trusted CA bundle differs from other source "
                     "servers/listeners that Ferrum serves on one shared HTTPS listener; one listener-wide client CA "
                     "bundle cannot preserve this route's original trust scope")
    report.error("frontend-client-ca-scope", "frontend client CA",
                 f"The source required client certificates from {len(required)} different CA bundles on separate "
                 "servers/listeners. Ferrum file mode verifies client certificates with one bundle "
                 "(FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH) for its whole HTTPS listener, so the original "
                 "per-host/listener trust scopes cannot be established. Concatenating the bundles would let clients "
                 "trusted by one scope reach the others. No client CA bundle was configured, and the "
                 f"{len(affected)} affected route(s) were refused (fail closed).",
                 "Do not merge the CA files. Run a separately configured Ferrum frontend for each client CA trust "
                 "boundary, each with its own FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH and only that boundary's routes "
                 "(for example, convert a copy of the source that contains only those servers/listeners), then review "
                 "and validate each frontend with `ferrum-edge validate` before serving traffic.")


def _hosts_merge_in_slot(a: list[str], b: list[str], *, host_only: bool) -> bool:
    """Whether Ferrum Edge v0.9.21 rejects two proxies sharing the same slot.

    Mirrors ``hosts_overlap`` (host-only slots) and ``ambiguous_path_host_overlap`` (path slots) in
    ``src/config/types.rs``: empty ``hosts`` (catch-all) conflicts with every host list on both slot kinds;
    exact-to-wildcard overlap conflicts only in host-only slots.
    """
    if not a or not b:
        return True
    if host_only:
        return matching.hosts_overlap(a, b)
    b_exact = {h for h in b if not h.startswith("*.")}
    b_wild = [h for h in b if h.startswith("*.")]
    for h in a:
        if h.startswith("*."):
            if any(matching.host_overlap(h, w) for w in b_wild):
                return True
        elif h in b_exact:
            return True
    return False


def _poison(routes: list[RouteSpec], mode: str = "both") -> None:
    """Refuse routes that could receive traffic the source sent to an unrepresentable route.

    When the unrepresentable route's envelope (hosts + path) is itself
    representable, a placeholder is emitted for it, and Ferrum sends every
    request in that envelope to the placeholder unless the other route is
    more specific. Only such more-specific (or ambiguous) routes are refused.
    """
    opened = FRONTEND_MODES[mode]
    unrepresentable = [
        r for r in routes
        if not r.skip and r.refusals and r.extra_conditions
        and ((protos := _effective_protocols(r)) is None or bool(opened & protos))
    ]
    for bad in unrepresentable:
        envelope_ok = bad.hosts is not None and bad.path_ok
        for other in routes:
            if other is bad or other.skip:
                continue
            if not matching.route_overlaps(bad, other):
                continue
            if envelope_ok and other.path_ok and other.hosts is not None:
                if matching.ferrum_prefers(bad, other) is True:
                    continue
                if bad.kind == other.kind and bad.path == other.path and bad.listen_port == other.listen_port \
                        and _hosts_merge_in_slot(bad.hosts or [], other.hosts, host_only=bad.kind == "hostonly"):
                    continue  # identical slot and same conflict component: conflict resolution merges them
            other.refuse(f"its match overlaps {bad.ref}, whose match conditions Ferrum cannot express")


def _poison_case_variants(plan: Plan, routes: list[RouteSpec], mode: str = "both") -> None:
    """Refuse routes that could forward case variants of a path the source matched case-insensitively.

    Ferrum matches literal paths case-sensitively, so a case-insensitive source route (Envoy
    ``case_sensitive: false``, Istio ``ignoreUriCase``) only receives its exact-case path in Ferrum. A request such
    as ``/API`` that the source sent to ``/api`` would otherwise reach whichever overlapping route matches it (often
    a broader one with another policy). Every such route in the same or a more specific host tier is refused.
    A route in a less specific tier (another scope's wildcard or the catch-all tier) is spared only when the source
    route belongs to a closed host scope with exactly its host names: such a scope gets a host-only or regex 404, or
    its fallthrough targets are refused (``scope-closure-skipped``), so the variants never fall through to it.
    Without such a scope every overlapping route is refused. Unmatched variants answer 404.
    """
    opened = FRONTEND_MODES[mode]
    scopes = [set(_scope_hosts(scope)) for scope in plan.host_scopes if scope.listen_port is None]
    sources = [
        route for route in routes
        if not route.skip and route.case_insensitive
        and ((protos := _effective_protocols(route)) is None or bool(opened & protos))
    ]
    for source in sources:
        closed = bool(source.hosts) and set(source.hosts) in scopes
        for other in routes:
            if other is source or other.skip:
                continue
            if closed and other.hosts is not None:
                pairs = matching.overlapping_tier_pairs(source.hosts, other.hosts)
                if pairs and all(tb > ta for ta, tb in pairs):
                    continue
            if not matching.receives_case_variants(source, other):
                continue
            other.refuse(f"it could receive case variants of the path of {source.ref} (for example different "
                         "upper/lower case), which the source matched case-insensitively there; Ferrum matches "
                         "paths case-sensitively, so they would reach this route instead")


# ------------------------------------------------------------------ candidates

def _listen_path(route: RouteSpec) -> str | None:
    if route.kind == "hostonly":
        return None
    if route.kind == "exact":
        return "=" + (route.path or "/")
    if route.kind == "regex":
        return "~" + (route.path or "")
    return route.path or "/"


def _build_candidates(routes: list[RouteSpec]) -> list[_Cand]:
    candidates: list[_Cand] = []
    for route in routes:
        if route.skip:
            continue
        representable = route.hosts is not None and route.path_ok
        listen_path = _listen_path(route)
        if route.refusals:
            if not representable:
                continue
            hosts = list(route.hosts or [])
            if len(hosts) > util.MAX_HOSTS_PER_PROXY:
                chunks = _chunk_hosts_no_prune(hosts, host_only=listen_path is None)
                if chunks is None:
                    continue
                route.placeholder_emitted = True
                for chunk in chunks:
                    candidates.append(_Cand(route, True, chunk, listen_path, route.listen_port,
                                            termination=REFUSED_TERMINATION, kind_label="refused"))
                continue
            route.placeholder_emitted = True
            candidates.append(_Cand(route, True, hosts, listen_path, route.listen_port,
                                    termination=REFUSED_TERMINATION, kind_label="refused"))
        else:
            candidates.append(_Cand(route, False, list(route.hosts or []), listen_path, route.listen_port,
                                    termination=route.termination,
                                    kind_label="terminated" if route.termination else "migrated"))
    return candidates


def _has_sorted_prefix(paths: list[str], prefix: str) -> bool:
    idx = bisect.bisect_left(paths, prefix)
    return idx < len(paths) and paths[idx].startswith(prefix)


def _has_sorted_exact(paths: list[str], target: str) -> bool:
    idx = bisect.bisect_left(paths, target)
    return idx < len(paths) and paths[idx] == target


def _drop_off_protocol_slot_conflicts(plan: Plan, candidates: list[_Cand], mode: str) -> list[_Cand]:
    """Omit refused off-protocol placeholders that collide with or shadow live routes on the selected frontend.

    When the profile disables a listener (for example ``mode == "https"`` with plaintext disabled), a refused
    route served exclusively on the disabled listener never existed on the selected frontend. Keeping its
    placeholder when it collides in the same ``(listen_port, listen_path)`` slot with a live route would either
    conflict in Ferrum's validator or collapse the live route into a 503; keeping one that outranks a live
    same-tier route (for example plaintext ``=/extra`` over HTTPS ``/``) or shadows a lower-tier live wildcard
    or catch-all route (when the placeholder's hosts have no scope on the selected frontend) would intercept
    live HTTPS/HTTP traffic with a 503. All checks run via hash indices and sorted-path binary search in
    O(N log N) time.
    """
    opened = FRONTEND_MODES[mode]
    on_protocol_by_path: dict[str | None, _PortHostIndex] = {}
    live_prefix_by_path: dict[str, _PortHostIndex] = {}
    live_string_prefix_by_path: dict[str, _PortHostIndex] = {}
    live_literal_by_path: dict[str, _PortHostIndex] = {}
    live_hostonly_idx = _PortHostIndex()
    live_regex_idx = _PortHostIndex()
    live_ci_idx = _PortHostIndex()
    live_any_idx = _PortHostIndex()
    live_catchall_paths_set: dict[int | None, set[str]] = {}
    live_wild_paths_set: dict[int | None, dict[str, set[str]]] = {}
    on_protocol_scope_idx = _PortHostIndex()
    has_any_on_protocol = False
    for cand in candidates:
        protos = _effective_protocols(cand.route)
        is_on_protocol = (not cand.placeholder) or (protos is None) or bool(opened & protos)
        if not is_on_protocol:
            continue
        has_any_on_protocol = True
        on_protocol_by_path.setdefault(cand.listen_path, _PortHostIndex()).add(cand)
        if cand.placeholder:
            continue
        live_any_idx.add(cand)
        r = cand.route
        if r.case_insensitive:
            live_ci_idx.add(cand)
        if r.kind == "hostonly":
            live_hostonly_idx.add(cand)
        elif r.kind == "regex":
            live_regex_idx.add(cand)
        else:
            p = r.path or "/"
            live_literal_by_path.setdefault(p, _PortHostIndex()).add(cand)
            if r.kind == "prefix":
                live_prefix_by_path.setdefault(p, _PortHostIndex()).add(cand)
                if r.prefix_semantics == "string" and not r.trailing_slash:
                    live_string_prefix_by_path.setdefault(p, _PortHostIndex()).add(cand)
                if r.trailing_slash and r.prefix_semantics == "string":
                    # Reserve the bare-path exact guard slot that _add_trailing_slash_placeholders will need so
                    # an off-protocol placeholder on "=" + p cannot block the guard and force this route refused.
                    on_protocol_by_path.setdefault("=" + p, _PortHostIndex()).add(cand)
            if not cand.hosts:
                live_catchall_paths_set.setdefault(cand.listen_port, set()).add(p)
            else:
                wmap = live_wild_paths_set.setdefault(cand.listen_port, {})
                for h in cand.hosts:
                    if h.startswith("*."):
                        wmap.setdefault(h[1:], set()).add(p)
    if not has_any_on_protocol:
        return candidates
    for scope in plan.host_scopes:
        sh = _scope_hosts(scope)
        if sh:
            dummy = RouteSpec(ref=scope.ref, name=scope.ref, hosts=sh, kind="hostonly", path=None,
                              listen_port=scope.listen_port)
            on_protocol_scope_idx.add(_Cand(dummy, True, sh, None, scope.listen_port))

    sorted_catchall_paths: dict[int | None, list[str]] = {
        port: sorted(paths) for port, paths in live_catchall_paths_set.items()
    }
    sorted_wild_paths: dict[int | None, dict[str, list[str]]] = {
        port: {suf: sorted(paths) for suf, paths in smap.items()}
        for port, smap in live_wild_paths_set.items()
    }

    def _host_has_own_scope(port: int | None, host: str) -> bool:
        if host.startswith("*."):
            wmap = on_protocol_scope_idx.wild.get(port)
            return bool(wmap and host[1:] in wmap)
        emap = on_protocol_scope_idx.exact.get(port)
        return bool(emap and host in emap)

    def _shadows_same_tier(cand: _Cand) -> bool:
        port = cand.listen_port
        r = cand.route
        if r.kind in ("exact", "prefix"):
            p = r.path or "/"
            if live_hostonly_idx.has_same_tier_overlap(port, cand.hosts) \
                    or live_regex_idx.has_same_tier_overlap(port, cand.hosts) \
                    or live_ci_idx.has_same_tier_overlap(port, cand.hosts):
                return True
            limit = len(p) + 1 if r.kind == "exact" else len(p)
            for k in range(1, limit):
                anc = p[:k]
                boundary = (anc == "/" or k == len(p) or p[k] == "/")
                table = live_prefix_by_path if boundary else live_string_prefix_by_path
                idx = table.get(anc)
                if idx is not None and idx.has_same_tier_overlap(port, cand.hosts):
                    return True
            return False
        if r.kind == "regex":
            return (
                live_hostonly_idx.has_same_tier_overlap(port, cand.hosts)
                or live_regex_idx.has_same_tier_overlap(port, cand.hosts)
            )
        return False

    def _has_lower_descendant(port: int | None, hosts: list[str], r: RouteSpec, p: str) -> bool:
        seg_only = r.prefix_semantics == "segment" or r.trailing_slash
        seg_prefix = p + "/"

        def _matches_list(paths: list[str]) -> bool:
            # Emitted Ferrum prefix listen_path strips any trailing slash, so at runtime it matches bare `p` as well
            # as `p/...` and can shadow a lower-tier exact `=p` route even when `r.trailing_slash` is True.
            if not seg_only:
                return _has_sorted_prefix(paths, p)
            return _has_sorted_exact(paths, p) or _has_sorted_prefix(paths, seg_prefix)

        ca_paths = sorted_catchall_paths.get(port)
        if ca_paths and _matches_list(ca_paths):
            return True
        wmap = sorted_wild_paths.get(port)
        if wmap:
            for h in hosts:
                if h.startswith("*."):
                    suffix = h[1:]
                    dot = suffix.find(".", 1)
                    while dot != -1:
                        wpaths = wmap.get(suffix[dot:])
                        if wpaths and _matches_list(wpaths):
                            return True
                        dot = suffix.find(".", dot + 1)
                else:
                    dot = h.find(".")
                    while dot != -1:
                        wpaths = wmap.get(h[dot:])
                        if wpaths and _matches_list(wpaths):
                            return True
                        dot = h.find(".", dot + 1)
        return False

    def _shadows_lower_tier(cand: _Cand) -> bool:
        if not cand.hosts:
            return False
        port = cand.listen_port
        # Evaluate per host: a placeholder with multiple aliases (e.g. [a.example.test, b.example.test]) shadows a
        # lower-tier route if ANY alias lacks its own on-protocol scope and matches that lower-tier route.
        unscoped_hosts = [h for h in cand.hosts if not _host_has_own_scope(port, h)]
        if not unscoped_hosts:
            return False
        r = cand.route
        if r.kind in ("hostonly", "regex") or r.case_insensitive or (r.kind == "prefix" and (r.path or "/") == "/"):
            return live_any_idx.has_lower_tier_overlap(port, unscoped_hosts)
        if live_hostonly_idx.has_lower_tier_overlap(port, unscoped_hosts) \
                or live_regex_idx.has_lower_tier_overlap(port, unscoped_hosts) \
                or live_ci_idx.has_lower_tier_overlap(port, unscoped_hosts):
            return True
        p = r.path or "/"
        for k in range(1, len(p) + 1):
            anc = p[:k]
            boundary = (anc == "/" or k == len(p) or p[k] == "/")
            table = live_prefix_by_path if boundary else live_string_prefix_by_path
            idx = table.get(anc)
            if idx is not None and idx.has_lower_tier_overlap(port, unscoped_hosts):
                return True
        if r.kind == "exact":
            lit_idx = live_literal_by_path.get(p)
            return lit_idx is not None and lit_idx.has_lower_tier_overlap(port, unscoped_hosts)
        return _has_lower_descendant(port, unscoped_hosts, r, p)

    kept: list[_Cand] = []
    dropped_routes: list[RouteSpec] = []
    for cand in candidates:
        if cand.placeholder:
            protos = _effective_protocols(cand.route)
            if protos is not None and not (opened & protos):
                idx = on_protocol_by_path.get(cand.listen_path)
                same_slot = idx is not None and idx.has_conflict(
                    cand.listen_port, cand.hosts, path_slot=cand.listen_path is not None
                )
                if same_slot or _shadows_same_tier(cand) or _shadows_lower_tier(cand):
                    dropped_routes.append(cand.route)
                    continue
        kept.append(cand)
    if dropped_routes:
        remaining_ids = {id(c.route) for c in kept}
        for route in dropped_routes:
            if id(route) not in remaining_ids:
                route.placeholder_emitted = False
    return kept


def _hosts_conflict_in_ferrum(a: str, b: str, host_only: bool) -> bool:
    """Whether Ferrum rejects ``a`` and ``b`` on two separate proxies of the same slot."""
    if a == b:
        return True
    if host_only:
        return matching.host_overlap(a, b)
    return a.startswith("*.") and b.startswith("*.") and matching.host_overlap(a, b)


def _chunk_hosts_no_prune(hosts: list[str], host_only: bool) -> list[list[str]] | None:
    """Pack ``hosts`` into chunks of at most ``MAX_HOSTS_PER_PROXY`` without pruning any host.

    Hosts that Ferrum considers ambiguous across separate proxies (``hosts_overlap`` for host-only proxies,
    same-tier ``ambiguous_path_host_overlap`` for path proxies) are grouped into one connected component so
    they always stay together in a single proxy — preserving exact-tier and narrower-wildcard routing buckets.
    Returns ``None`` if any single ambiguous component exceeds ``MAX_HOSTS_PER_PROXY``.
    """
    unique = list(dict.fromkeys(hosts))
    limit = util.MAX_HOSTS_PER_PROXY
    if len(unique) <= limit:
        return [unique]
    parent = list(range(len(unique)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    wild_owner: dict[str, int] = {}
    exact_entries: list[tuple[str, int]] = []
    for idx, host in enumerate(unique):
        if host.startswith("*."):
            wild_owner[host[1:]] = idx
        elif host_only:
            exact_entries.append((host, idx))
    if wild_owner:
        for suffix, idx in wild_owner.items():
            dot = suffix.find(".", 1)
            while dot != -1:
                w = wild_owner.get(suffix[dot:])
                if w is not None:
                    union(idx, w)
                dot = suffix.find(".", dot + 1)
        if host_only:
            for host, idx in exact_entries:
                dot = host.find(".")
                while dot != -1:
                    w = wild_owner.get(host[dot:])
                    if w is not None:
                        union(idx, w)
                    dot = host.find(".", dot + 1)
    comps: dict[int, list[str]] = {}
    for idx, host in enumerate(unique):
        comps.setdefault(find(idx), []).append(host)
    ordered = sorted(comps.values(), key=len, reverse=True)
    if any(len(comp) > limit for comp in ordered):
        return None
    chunks: list[list[str]] = []
    # Bucket chunk indices by remaining capacity (1..limit) so placement scans at most `limit` buckets.
    by_rem: dict[int, list[int]] = {}
    for comp in ordered:
        size = len(comp)
        placed_idx: int | None = None
        for rem in range(size, limit + 1):
            bucket = by_rem.get(rem)
            if bucket:
                placed_idx = bucket.pop()
                if not bucket:
                    del by_rem[rem]
                break
        if placed_idx is None:
            placed_idx = len(chunks)
            chunks.append(list(comp))
            new_rem = limit - size
        else:
            chunks[placed_idx].extend(comp)
            new_rem = limit - len(chunks[placed_idx])
        if new_rem > 0:
            by_rem.setdefault(new_rem, []).append(placed_idx)
    return chunks


class _HostPathBucket:
    """Per-(port, host) path index so conflict-collapse queries touch only overlapping hosts and paths."""

    def __init__(self) -> None:
        self.all_cands: list[_Cand] = []
        self.prefix_by_path: dict[str, list[_Cand]] = {}
        self.literal_by_path: dict[str, list[_Cand]] = {}
        self.sorted_literal_paths: list[str] = []
        self.ci_prefix_by_path: dict[str, list[_Cand]] = {}
        self.ci_literal_by_path: dict[str, list[_Cand]] = {}
        self.sorted_ci_literal_paths: list[str] = []
        self.regex_by_literal_prefix: dict[str, list[_Cand]] = {}
        self.sorted_regex_prefixes: list[str] = []
        self.special: list[_Cand] = []
        self._finalized = False

    def add(self, item: _Cand) -> None:
        self.all_cands.append(item)
        r = item.route
        if r.kind == "hostonly":
            self.special.append(item)
        elif r.kind == "regex":
            lit = util.regex_literal_prefix(r.path or "") if (
                r.path and not util.regex_alternation_unproven(r.path)
            ) else ""
            if len(lit) >= 2 and lit.startswith("/"):
                self.regex_by_literal_prefix.setdefault(lit, []).append(item)
            else:
                self.special.append(item)
        elif r.case_insensitive:
            pl = (r.path or "/").lower()
            self.ci_literal_by_path.setdefault(pl, []).append(item)
            if r.kind == "prefix":
                self.ci_prefix_by_path.setdefault(pl, []).append(item)
        else:
            p = r.path or "/"
            self.literal_by_path.setdefault(p, []).append(item)
            if r.kind == "prefix":
                self.prefix_by_path.setdefault(p, []).append(item)

    def finalize(self) -> None:
        if self._finalized:
            return
        self._finalized = True
        self.sorted_literal_paths = sorted(self.literal_by_path)
        self.sorted_ci_literal_paths = sorted(self.ci_literal_by_path)
        self.sorted_regex_prefixes = sorted(self.regex_by_literal_prefix)

    def candidate_lists(self, *, needs_all: bool, literal_paths: set[str], has_prefix: bool) -> list[list[_Cand]]:
        if needs_all:
            return [self.all_cands] if self.all_cands else []
        self.finalize()
        lists: list[list[_Cand]] = []
        seen_ids: set[int] = set()

        def _add(lst: list[_Cand] | None) -> None:
            if lst and id(lst) not in seen_ids:
                seen_ids.add(id(lst))
                lists.append(lst)

        _add(self.special)
        for path_str in literal_paths:
            pl = path_str.lower()
            for k in range(1, len(path_str) + 1):
                sub = path_str[:k]
                _add(self.prefix_by_path.get(sub))
                _add(self.ci_prefix_by_path.get(pl[:k]))
                if k >= 2:
                    _add(self.regex_by_literal_prefix.get(sub))
            _add(self.literal_by_path.get(path_str))
            _add(self.ci_literal_by_path.get(pl))
            if has_prefix:
                lo = bisect.bisect_left(self.sorted_literal_paths, path_str)
                while lo < len(self.sorted_literal_paths) and self.sorted_literal_paths[lo].startswith(path_str):
                    _add(self.literal_by_path[self.sorted_literal_paths[lo]])
                    lo += 1
                clo = bisect.bisect_left(self.sorted_ci_literal_paths, pl)
                while clo < len(self.sorted_ci_literal_paths) and self.sorted_ci_literal_paths[clo].startswith(pl):
                    _add(self.ci_literal_by_path[self.sorted_ci_literal_paths[clo]])
                    clo += 1
                rlo = bisect.bisect_left(self.sorted_regex_prefixes, path_str)
                while rlo < len(self.sorted_regex_prefixes) and self.sorted_regex_prefixes[rlo].startswith(path_str):
                    _add(self.regex_by_literal_prefix[self.sorted_regex_prefixes[rlo]])
                    rlo += 1
        return lists

    def prune_all(self) -> None:
        self.all_cands[:] = [c for c in self.all_cands if not c.placeholder]
        self.special[:] = [c for c in self.special if not c.placeholder]


def _resolve_conflicts(candidates: list[_Cand], report: Report) -> list[_Cand]:
    groups: dict[tuple[int | None, str | None], list[_Cand]] = {}
    for cand in candidates:
        groups.setdefault((cand.listen_port, cand.listen_path), []).append(cand)
    replacement: dict[int, list[_Cand]] = {}
    outrank_indices: dict[str, Any] | None = None
    fully_closed_ports: set[int | None] = set()
    fully_closed_exact: dict[int | None, set[str]] = {}
    fully_closed_wild: dict[int | None, set[str]] = {}

    def _is_host_fully_closed(p: int | None, h: str) -> bool:
        if p in fully_closed_ports:
            return True
        wset = fully_closed_wild.get(p)
        if h.startswith("*."):
            if not wset:
                return False
            suffix = h[1:]
            if suffix in wset:
                return True
            dot = suffix.find(".", 1)
            while dot != -1:
                if suffix[dot:] in wset:
                    return True
                dot = suffix.find(".", dot + 1)
            return False
        eset = fully_closed_exact.get(p)
        if eset and h in eset:
            return True
        if wset:
            dot = h.find(".")
            while dot != -1:
                if h[dot:] in wset:
                    return True
                dot = h.find(".", dot + 1)
        return False

    def _mark_fully_closed(p: int | None, hosts: list[str]) -> None:
        if not hosts:
            fully_closed_ports.add(p)
            return
        eset = fully_closed_exact.setdefault(p, set())
        wset = fully_closed_wild.setdefault(p, set())
        for h in hosts:
            if h.startswith("*."):
                wset.add(h[1:])
            else:
                eset.add(h)

    def _build_outrank_indices() -> dict[str, Any]:
        # Host-first + selective suffix-subtree indexing: exact hosts look up exact + parent wildcard buckets;
        # wildcard hosts look up their own bucket + a pre-aggregated subtree _HostPathBucket + parent wildcards.
        # Only suffixes actually present as wildcard hosts across `candidates` get subtree buckets, avoiding
        # memory overhead when inputs contain no (or few) wildcard hosts.
        needed_wild_suffixes: set[str] = {
            h[1:] for cand in candidates for h in cand.hosts if h.startswith("*.")
        }
        ports_present: set[int | None] = set()
        exact_buckets: dict[int | None, dict[str, _HostPathBucket]] = {}
        wild_buckets: dict[int | None, dict[str, _HostPathBucket]] = {}
        subtree_buckets: dict[int | None, dict[str, _HostPathBucket]] = {}
        for item in candidates:
            if item.placeholder or not item.hosts:
                continue
            port = item.listen_port
            ports_present.add(port)
            ex_map = exact_buckets.setdefault(port, {})
            wi_map = wild_buckets.setdefault(port, {})
            sub_map = subtree_buckets.setdefault(port, {}) if needed_wild_suffixes else None
            seen_sub_suffixes: set[str] = set()
            for h in item.hosts:
                if h.startswith("*."):
                    suffix = h[1:]
                    bucket = wi_map.get(suffix)
                    if bucket is None:
                        bucket = _HostPathBucket()
                        wi_map[suffix] = bucket
                    bucket.add(item)
                    if sub_map is not None:
                        dot = suffix.find(".", 1)
                        while dot != -1:
                            parent_suf = suffix[dot:]
                            if parent_suf in needed_wild_suffixes and parent_suf not in seen_sub_suffixes:
                                seen_sub_suffixes.add(parent_suf)
                                sb = sub_map.get(parent_suf)
                                if sb is None:
                                    sb = _HostPathBucket()
                                    sub_map[parent_suf] = sb
                                sb.add(item)
                            dot = suffix.find(".", dot + 1)
                else:
                    bucket = ex_map.get(h)
                    if bucket is None:
                        bucket = _HostPathBucket()
                        ex_map[h] = bucket
                    bucket.add(item)
                    if sub_map is not None:
                        dot = h.find(".")
                        while dot != -1:
                            parent_suf = h[dot:]
                            if parent_suf in needed_wild_suffixes and parent_suf not in seen_sub_suffixes:
                                seen_sub_suffixes.add(parent_suf)
                                sb = sub_map.get(parent_suf)
                                if sb is None:
                                    sb = _HostPathBucket()
                                    sub_map[parent_suf] = sb
                                sb.add(item)
                            dot = h.find(".", dot + 1)
        return {
            "ports": ports_present,
            "exact": exact_buckets,
            "wild": wild_buckets,
            "subtree": subtree_buckets,
        }

    def _matching_host_buckets(port: int | None, hosts: list[str]) -> list[_HostPathBucket]:
        assert outrank_indices is not None
        ex_map: dict[str, _HostPathBucket] = outrank_indices["exact"].get(port, {})
        wi_map: dict[str, _HostPathBucket] = outrank_indices["wild"].get(port, {})
        if not hosts:
            return list(ex_map.values()) + list(wi_map.values())
        sub_map: dict[str, _HostPathBucket] = outrank_indices["subtree"].get(port, {})
        found: list[_HostPathBucket] = []
        seen_ids: set[int] = set()

        def _add_bucket(b: _HostPathBucket | None) -> None:
            if b is not None and id(b) not in seen_ids:
                seen_ids.add(id(b))
                found.append(b)

        for h in hosts:
            if h.startswith("*."):
                suffix = h[1:]
                _add_bucket(wi_map.get(suffix))
                _add_bucket(sub_map.get(suffix))
                dot = suffix.find(".", 1)
                while dot != -1:
                    _add_bucket(wi_map.get(suffix[dot:]))
                    dot = suffix.find(".", dot + 1)
            else:
                _add_bucket(ex_map.get(h))
                dot = h.find(".")
                while dot != -1:
                    _add_bucket(wi_map.get(h[dot:]))
                    dot = h.find(".", dot + 1)
        return found

    def _fail_close_outranking(named_hosts: list[str], slot_members: list[_Cand],
                               port: int | None, reason: str) -> int:
        nonlocal outrank_indices
        if outrank_indices is None:
            outrank_indices = _build_outrank_indices()
        ports_present: set[int | None] = outrank_indices["ports"]
        if not ports_present:
            return 0
        ports = (
            list(ports_present)
            if port is None
            else [p for p in (port, None) if p in ports_present]
        )
        if not ports:
            return 0
        excluded_ids = {id(m) for m in slot_members}
        probes: list[RouteSpec] = []
        seen_sigs: set[tuple[str, str | None, str, bool, bool]] = set()
        needs_all = False
        has_prefix = False
        literal_paths: set[str] = set()
        for m in slot_members:
            r = m.route
            sig = (r.kind, r.path, r.prefix_semantics, r.trailing_slash, r.case_insensitive)
            if sig in seen_sigs:
                continue
            seen_sigs.add(sig)
            if r.kind == "hostonly" or r.case_insensitive:
                needs_all = True
            elif r.kind == "regex":
                lit = util.regex_literal_prefix(r.path or "") if (
                    r.path and not util.regex_alternation_unproven(r.path)
                ) else ""
                if len(lit) >= 2 and lit.startswith("/"):
                    literal_paths.add(lit)
                    has_prefix = True
                else:
                    needs_all = True
            else:
                literal_paths.add(r.path or "/")
                if r.kind == "prefix":
                    has_prefix = True
            # Host overlap and port compatibility are already proven by `_matching_host_buckets` and `ports`, so
            # use `hosts=[]` on the path probe to keep `matching.route_overlaps` O(1) in host count.
            probes.append(RouteSpec(ref="", name="", hosts=[], kind=r.kind, path=r.path,
                                    prefix_semantics=r.prefix_semantics, trailing_slash=r.trailing_slash,
                                    case_insensitive=r.case_insensitive, listen_port=port))
        covers_all_paths = any(
            matching.path_space(probe.kind, probe.path) in (None, ("/", False), ("", False))
            for probe in probes
        )
        refused_outrank = 0
        seen_other: set[int] = set()
        for p in ports:
            if p in fully_closed_ports:
                continue
            if named_hosts:
                active_hosts = [h for h in named_hosts if not _is_host_fully_closed(p, h)]
                if not active_hosts:
                    continue
            else:
                active_hosts = []
            buckets = _matching_host_buckets(p, active_hosts)
            for bucket in buckets:
                for cand_list in bucket.candidate_lists(
                    needs_all=needs_all, literal_paths=literal_paths, has_prefix=has_prefix
                ):
                    pruned_any = False
                    for other in cand_list:
                        oid = id(other)
                        if oid in seen_other or oid in excluded_ids or oid in replacement:
                            continue
                        if other.placeholder:
                            pruned_any = True
                            continue
                        seen_other.add(oid)
                        if any(matching.route_overlaps(probe, other.route) for probe in probes):
                            _fail_close(other, reason)
                            refused_outrank += 1
                            pruned_any = True
                    if pruned_any:
                        cand_list[:] = [c for c in cand_list if not c.placeholder]
                if covers_all_paths:
                    bucket.prune_all()
            if covers_all_paths:
                _mark_fully_closed(p, active_hosts)
        return refused_outrank

    for (port, path), members in list(groups.items()):
        if len(members) < 2:
            continue
        collapsed_group = False
        for component in _components(members, host_only=path is None):
            if len(component) < 2:
                continue
            refs = [m.route.ref for m in component]
            capped_refs = [(ref, safe_label(ref)) for ref in refs[:8]]
            extra_count = len(refs) - len(capped_refs)
            for member in component:
                others = ", ".join(lbl for raw_ref, lbl in capped_refs if raw_ref != member.route.ref)
                if extra_count > 0:
                    others = f"{others}, +{extra_count} more" if others else f"+{extra_count} more"
                member.route.refuse(f"Ferrum requires one route per host/path/port and it conflicts with {others[:400]}")
                member.route.placeholder_emitted = True
            hosts: list[str] = []
            if not any(not m.hosts for m in component):
                hosts = list(dict.fromkeys(host for member in component for host in member.hosts))
            first = component[0]
            if not hosts:
                host_chunks: list[list[str]] | None = [[]]
            else:
                host_chunks = _chunk_hosts_no_prune(hosts, host_only=path is None)
            if host_chunks is None:
                if path is not None:
                    # A single ambiguous component exceeds 100 hosts: fail-close the whole (port, path) slot as one
                    # catch-all 503 placeholder, and also fail-close every overlapping live candidate that sits in a
                    # higher host tier (exact/wildcard beats catch-all in Ferrum) so no live route can outrank the
                    # replacement.
                    for member in members:
                        member.route.refuse("a merged host conflict on this path exceeds Ferrum's 100-host limit and "
                                            "cannot be split safely; the whole path slot was failed closed")
                        member.route.placeholder_emitted = True
                        replacement[id(member)] = []
                    collapse_hosts = [] if any(not m.hosts for m in members) else list(
                        dict.fromkeys(h for m in members for h in m.hosts)
                    )
                    refused_outrank = _fail_close_outranking(
                        collapse_hosts, members, port,
                        "overlaps a >100-host path conflict that collapsed to a catch-all placeholder; "
                        "its higher host tier would outrank the catch-all",
                    )
                    report.error("conflict-collapse", first.route.ref,
                                 f"A merged host conflict on path {safe_label(path, 80)} exceeds Ferrum's 100-host "
                                 "limit inside one ambiguous component and collapsed to a catch-all 503 placeholder "
                                 f"(also failing closed {refused_outrank} overlapping higher-tier route(s)); catch-all "
                                 "requests on that path for unrelated hosts will also answer 503.",
                                 "Split the overlapping wildcards/hosts into separate Ferrum frontends or fewer than "
                                 "100 hosts per proxy, then convert again.")
                    replacement[id(members[0])] = [
                        _Cand(members[0].route, True, [], path, port, termination=REFUSED_TERMINATION,
                              kind_label="refused")
                    ]
                    collapsed_group = True
                    break
                # Host-only proxy cannot have empty hosts; try chunked regex 503 placeholders if that slot is free,
                # else omit and fail-close every overlapping live candidate so no traffic escapes.
                regex_chunks = _chunk_hosts_no_prune(hosts, host_only=False)
                regex_slot = groups.get((port, REGEX_CLOSURE_PATH), [])
                regex_free = regex_chunks is not None and not any(
                    matching.hosts_overlap(other.hosts, hosts) for other in regex_slot
                )
                if regex_free and regex_chunks is not None:
                    added = [
                        _Cand(first.route, True, chunk, REGEX_CLOSURE_PATH, port,
                              termination=REFUSED_TERMINATION, kind_label="refused")
                        for chunk in regex_chunks
                    ]
                    replacement[id(first)] = added
                    groups.setdefault((port, REGEX_CLOSURE_PATH), []).extend(added)
                else:
                    for member in component:
                        member.route.placeholder_emitted = False
                    replacement[id(first)] = []
                    for other in candidates:
                        if other not in component and not other.placeholder \
                                and matching.ports_compatible(other.listen_port, port) \
                                and matching.hosts_overlap(other.hosts, hosts):
                            _fail_close(other, "overlaps a host-only route conflict whose hosts exceed Ferrum's "
                                               "100-host limit and cannot be represented safely")
            else:
                if not hosts and path is not None:
                    named_members = [m for m in component if m.hosts]
                    if named_members:
                        # Merging a named route with a catch-all into one catch-all 503 demotes those named hosts
                        # behind Ferrum's exact/wildcard tiers; fail-close any overlapping higher-tier live route
                        # so requests for those hosts cannot bypass the refused route.
                        named_hosts = list(dict.fromkeys(h for m in named_members for h in m.hosts))
                        refused_outrank = _fail_close_outranking(
                            named_hosts, named_members, port,
                            "overlaps a named route whose slot conflict with a catch-all collapsed to a catch-all "
                            "placeholder; its higher host tier would outrank the catch-all",
                        )
                        if refused_outrank:
                            report.error(
                                "conflict-collapse", first.route.ref,
                                f"A catch-all/named host conflict on path {safe_label(path, 80)} collapsed to a "
                                f"catch-all 503 placeholder and failed closed {refused_outrank} overlapping "
                                "higher-tier route(s) whose host tier would otherwise bypass the placeholder.",
                                "Avoid sharing the same listen_path between catch-all and named host routes, then "
                                "convert again.",
                            )
                replacement[id(first)] = [
                    _Cand(first.route, True, chunk, path, port, termination=REFUSED_TERMINATION, kind_label="refused")
                    for chunk in host_chunks
                ]
            for member in component[1:]:
                replacement[id(member)] = []
        if collapsed_group:
            continue
    result: list[_Cand] = []
    for cand in candidates:
        if id(cand) in replacement:
            result.extend(replacement[id(cand)])
        else:
            result.append(cand)
    return result


def _components(members: list[_Cand], *, host_only: bool = True) -> list[list[_Cand]]:
    n = len(members)
    parent = list(range(n))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    # Ferrum Edge v0.9.21 rejects any catch-all + named or catch-all + catch-all pair on the same slot
    # (both hosts_overlap and ambiguous_path_host_overlap return true when either host list is empty).
    first_catchall = next((i for i, m in enumerate(members) if not m.hosts), None)
    if first_catchall is not None:
        for i in range(n):
            union(i, first_catchall)
    else:
        exact_owner: dict[str, int] = {}
        wild_owner: dict[str, int] = {}
        for i, member in enumerate(members):
            for host in member.hosts:
                if host.startswith("*."):
                    suffix = host[1:]
                    prev = wild_owner.get(suffix)
                    if prev is None:
                        wild_owner[suffix] = i
                    else:
                        union(i, prev)
                else:
                    prev = exact_owner.get(host)
                    if prev is None:
                        exact_owner[host] = i
                    else:
                        union(i, prev)
        if wild_owner:
            # On path slots Ferrum keeps exact-host and wildcard-host proxies in separate tiers (exact beats wildcard);
            # exact-to-wildcard overlap conflicts only in the host-only slot.
            if host_only:
                for host, owner in exact_owner.items():
                    dot = host.find(".")
                    while dot != -1:
                        w = wild_owner.get(host[dot:])
                        if w is not None:
                            union(owner, w)
                        dot = host.find(".", dot + 1)
            for suffix, owner in wild_owner.items():
                dot = suffix.find(".", 1)
                while dot != -1:
                    w = wild_owner.get(suffix[dot:])
                    if w is not None:
                        union(owner, w)
                    dot = suffix.find(".", dot + 1)
    grouped: dict[int, list[_Cand]] = {}
    for index, member in enumerate(members):
        grouped.setdefault(find(index), []).append(member)
    return list(grouped.values())


REGEX_CLOSURE_PATH = "~/.*"


def _fail_close(cand: _Cand, reason: str) -> None:
    """Turn an emitted candidate into a fail-closed placeholder (same hosts/path/port, HTTP 503)."""
    cand.route.refuse(reason)
    cand.route.placeholder_emitted = True
    cand.placeholder = True
    cand.termination = REFUSED_TERMINATION
    cand.kind_label = "refused"
    cand.guards = []


def _scope_hosts(scope) -> list[str]:
    return [h for h in (util.normalize_host(x) for x in scope.hosts) if h]


def _refuse_nested_wildcard_scopes(plan: Plan, candidates: list[_Cand], report: Report) -> None:
    """Refuse the routes of a wildcard host scope that strictly covers another scope's wildcard.

    The sources pick the most specific server/virtual host for a name (``*.a.example.com`` over
    ``*.example.com``), and that scope never falls through. Ferrum's wildcard tier instead compares the
    path routes of every matching pattern, so a route of the broader scope could answer a narrower-scope
    host for a path the narrower scope does not route more specifically. No closure can prevent that, so
    every route carrying the broader pattern becomes a fail-closed placeholder.
    """
    wild_scopes: list[tuple[int, Any, set[str]]] = []
    # Map (inner_port, parent_suffix) -> up to 2 distinct witness (scope_ordinal, inner_ref, inner_wilds_set)
    # entries keyed by scope ordinal (not ref label) so colliding/truncated labels never hide a distinct scope.
    witnesses_by_port: dict[int | None, dict[str, list[tuple[int, str, set[str]]]]] = {}
    witnesses_any: dict[str, list[tuple[int, str, set[str]]]] = {}
    for scope_idx, scope in enumerate(plan.host_scopes):
        wilds = {h for h in _scope_hosts(scope) if h.startswith("*.")}
        if not wilds:
            continue
        wild_scopes.append((scope_idx, scope, wilds))
        port_map = witnesses_by_port.setdefault(scope.listen_port, {})
        for other in wilds:
            suffix = other[1:]
            dot = suffix.find(".", 1)
            while dot != -1:
                parent = suffix[dot:]
                if ("*" + parent) not in wilds:
                    # Record at most 2 distinct scope ordinals per (port, parent_suffix) and globally.
                    plist = port_map.setdefault(parent, [])
                    if len(plist) < 2 and all(oid != scope_idx for oid, _, _ in plist):
                        plist.append((scope_idx, scope.ref, wilds))
                    alist = witnesses_any.setdefault(parent, [])
                    if len(alist) < 2 and all(oid != scope_idx for oid, _, _ in alist):
                        alist.append((scope_idx, scope.ref, wilds))
                dot = suffix.find(".", dot + 1)
    if not wild_scopes:
        return
    leaky: list[tuple[int, str, int | None, str, str]] = []
    seen_outer: set[tuple[str, int | None, int]] = set()
    for outer_idx, outer, outer_wilds in wild_scopes:
        for pattern in outer_wilds:
            key = (pattern, outer.listen_port, outer_idx)
            if key in seen_outer:
                continue
            suffix = pattern[1:]
            cand_witnesses: list[tuple[int, str, set[str]]] = []
            if outer.listen_port is None:
                cand_witnesses.extend(witnesses_any.get(suffix, ()))
            else:
                cand_witnesses.extend(witnesses_by_port.get(outer.listen_port, {}).get(suffix, ()))
                cand_witnesses.extend(witnesses_by_port.get(None, {}).get(suffix, ()))
            for inner_idx, inner_ref, inner_wilds in cand_witnesses:
                if inner_idx != outer_idx and pattern not in inner_wilds:
                    seen_outer.add(key)
                    leaky.append((outer_idx, pattern, outer.listen_port, outer.ref, inner_ref))
                    break
    if not leaky:
        return
    leaky_by_pattern: dict[str, list[tuple[int | None, str, str]]] = {}
    for _outer_idx, pattern, port, outer_ref, inner_ref in leaky:
        leaky_by_pattern.setdefault(pattern, []).append((port, outer_ref, inner_ref))
    reported: set[int] = set()
    for cand in candidates:
        if cand.placeholder or not cand.hosts:
            continue
        for host in cand.hosts:
            if not host.startswith("*."):
                continue
            hit = False
            for port, _outer_ref, inner_ref in leaky_by_pattern.get(host, ()):
                if matching.ports_compatible(cand.listen_port, port):
                    _fail_close(cand, f"its wildcard host {host} covers the narrower wildcard scope {inner_ref}; "
                                      "Ferrum's wildcard tier would let this route answer that scope's hosts")
                    hit = True
                    break
            if hit:
                break
    for outer_idx, pattern, _port, outer_ref, inner_ref in leaky:
        if outer_idx in reported:
            continue
        reported.add(outer_idx)
        report.error("nested-wildcard-scope", outer_ref,
                     f"The wildcard host {pattern} covers the narrower wildcard host scope {inner_ref}. The source "
                     "sends those hosts only to the narrower scope, but Ferrum compares the path routes of every "
                     "matching wildcard pattern, so this scope's routes could answer them. Its routes were refused "
                     "(fail closed).",
                     "Serve the nested wildcard scopes from separate Ferrum frontends, or replace the broader "
                     "wildcard with explicit host names, then convert again.")


class _PortHostIndex:
    """Per-port hash index for O(|hosts| * labels) slot-conflict queries mirroring Ferrum Edge v0.9.21."""

    def __init__(self) -> None:
        self.all_by_port: dict[int | None, list[_Cand]] = {}
        self.catchall: dict[int | None, list[_Cand]] = {}
        self.exact: dict[int | None, dict[str, list[_Cand]]] = {}
        self.wild: dict[int | None, dict[str, list[_Cand]]] = {}
        self.exact_by_suffix: dict[int | None, dict[str, list[_Cand]]] = {}
        self.wild_by_parent: dict[int | None, dict[str, list[_Cand]]] = {}

    def add(self, cand: _Cand) -> None:
        port = cand.listen_port
        self.all_by_port.setdefault(port, []).append(cand)
        if not cand.hosts:
            self.catchall.setdefault(port, []).append(cand)
            return
        ex_map = self.exact.setdefault(port, {})
        wi_map = self.wild.setdefault(port, {})
        ex_suf = self.exact_by_suffix.setdefault(port, {})
        wi_par = self.wild_by_parent.setdefault(port, {})
        for h in cand.hosts:
            if h.startswith("*."):
                suffix = h[1:]
                wi_map.setdefault(suffix, []).append(cand)
                dot = suffix.find(".", 1)
                while dot != -1:
                    wi_par.setdefault(suffix[dot:], []).append(cand)
                    dot = suffix.find(".", dot + 1)
            else:
                ex_map.setdefault(h, []).append(cand)
                dot = h.find(".")
                while dot != -1:
                    ex_suf.setdefault(h[dot:], []).append(cand)
                    dot = h.find(".", dot + 1)

    def has_same_tier_overlap(self, port: int | None, scope_hosts: list[str]) -> bool:
        """Whether an indexed candidate in the same host tier overlaps ``scope_hosts``."""
        if not scope_hosts:
            return bool(self.catchall.get(port))
        ex_map = self.exact.get(port)
        wi_map = self.wild.get(port)
        wi_par = self.wild_by_parent.get(port)
        for h in scope_hosts:
            if h.startswith("*."):
                suffix = h[1:]
                if wi_map and suffix in wi_map:
                    return True
                if wi_par and suffix in wi_par:
                    return True
                if wi_map:
                    dot = suffix.find(".", 1)
                    while dot != -1:
                        if suffix[dot:] in wi_map:
                            return True
                        dot = suffix.find(".", dot + 1)
            else:
                if ex_map and h in ex_map:
                    return True
        return False

    def has_lower_tier_overlap(self, port: int | None, scope_hosts: list[str]) -> bool:
        """Whether an indexed candidate in a lower host tier (catch-all or strictly broader wildcard) overlaps."""
        if not scope_hosts:
            return False
        if self.catchall.get(port):
            return True
        wi_map = self.wild.get(port)
        if wi_map:
            for h in scope_hosts:
                if h.startswith("*."):
                    suffix = h[1:]
                    dot = suffix.find(".", 1)
                    while dot != -1:
                        if suffix[dot:] in wi_map:
                            return True
                        dot = suffix.find(".", dot + 1)
                else:
                    dot = h.find(".")
                    while dot != -1:
                        if h[dot:] in wi_map:
                            return True
                        dot = h.find(".", dot + 1)
        return False

    def has_conflict(self, port: int | None, scope_hosts: list[str], *, path_slot: bool = False) -> bool:
        """O(|scope_hosts| * labels) existence check without scanning candidate buckets."""
        if not scope_hosts:
            return bool(self.all_by_port.get(port))
        if self.catchall.get(port):
            return True
        ex_map = self.exact.get(port)
        wi_map = self.wild.get(port)
        ex_suf = self.exact_by_suffix.get(port)
        wi_par = self.wild_by_parent.get(port)
        for h in scope_hosts:
            if h.startswith("*."):
                suffix = h[1:]
                if wi_map and suffix in wi_map:
                    return True
                if not path_slot and ex_suf and suffix in ex_suf:
                    return True
                if wi_par and suffix in wi_par:
                    return True
                if wi_map:
                    dot = suffix.find(".", 1)
                    while dot != -1:
                        if suffix[dot:] in wi_map:
                            return True
                        dot = suffix.find(".", dot + 1)
            else:
                if ex_map and h in ex_map:
                    return True
                if not path_slot and wi_map:
                    dot = h.find(".")
                    while dot != -1:
                        if h[dot:] in wi_map:
                            return True
                        dot = h.find(".", dot + 1)
        return False

    def prune_placeholders(self, port: int | None, scope_hosts: list[str]) -> None:
        """Drop already-failed-closed candidates from touched buckets so later scans never revisit them."""
        def _prune(bucket: list[_Cand] | None) -> None:
            if bucket:
                bucket[:] = [c for c in bucket if not c.placeholder]

        if not scope_hosts:
            _prune(self.all_by_port.get(port))
            _prune(self.catchall.get(port))
            for m in (self.exact.get(port), self.wild.get(port),
                      self.exact_by_suffix.get(port), self.wild_by_parent.get(port)):
                if m:
                    for b in m.values():
                        _prune(b)
            return
        _prune(self.catchall.get(port))
        ex_map = self.exact.get(port, {})
        wi_map = self.wild.get(port, {})
        ex_suf = self.exact_by_suffix.get(port, {})
        wi_par = self.wild_by_parent.get(port, {})
        for h in scope_hosts:
            if h.startswith("*."):
                suffix = h[1:]
                _prune(wi_map.get(suffix))
                _prune(ex_suf.get(suffix))
                _prune(wi_par.get(suffix))
                dot = suffix.find(".", 1)
                while dot != -1:
                    _prune(wi_map.get(suffix[dot:]))
                    dot = suffix.find(".", dot + 1)
            else:
                _prune(ex_map.get(h))
                dot = h.find(".")
                while dot != -1:
                    _prune(wi_map.get(h[dot:]))
                    dot = h.find(".", dot + 1)

    def query(self, port: int | None, scope_hosts: list[str], *, path_slot: bool = False) -> list[_Cand]:
        if not scope_hosts:
            # Empty hosts (catch-all) conflicts with every proxy on the same slot in Ferrum v0.9.21.
            return list(self.all_by_port.get(port, ()))
        found: list[_Cand] = []
        seen_ids: set[int] = set()

        def _add_all(items: list[_Cand] | None) -> None:
            if not items:
                return
            for item in items:
                iid = id(item)
                if iid not in seen_ids:
                    seen_ids.add(iid)
                    found.append(item)

        _add_all(self.catchall.get(port))
        ex_map = self.exact.get(port, {})
        wi_map = self.wild.get(port, {})
        ex_suf = self.exact_by_suffix.get(port, {})
        wi_par = self.wild_by_parent.get(port, {})
        for h in scope_hosts:
            if h.startswith("*."):
                suffix = h[1:]
                _add_all(wi_map.get(suffix))
                if not path_slot:
                    _add_all(ex_suf.get(suffix))
                _add_all(wi_par.get(suffix))
                dot = suffix.find(".", 1)
                while dot != -1:
                    _add_all(wi_map.get(suffix[dot:]))
                    dot = suffix.find(".", dot + 1)
            else:
                _add_all(ex_map.get(h))
                if not path_slot:
                    dot = h.find(".")
                    while dot != -1:
                        _add_all(wi_map.get(h[dot:]))
                        dot = h.find(".", dot + 1)
        return found


def _add_regex_closure(scope, hosts: list[str], candidates: list[_Cand], regex_idx: _PortHostIndex,
                       report: Report) -> bool:
    """Close a scope whose host-only closure would overlap another host-only route with a catch-any regex 404.

    Within a host tier Ferrum tries exact, prefix and regex routes (regex in config order) before host-only
    routes. Appended last, ``~/.*`` answers 404 for every path the scope's own exact/prefix/regex routes do not
    match, and it is not a host-only route, so it does not collide with the overlapping host-only closure. If the
    regex order assumption were wrong it could only shadow other routes with a 404 (fail closed).
    """
    chunks = _chunk_hosts_no_prune(hosts, host_only=False)
    if chunks is None:
        return False
    if regex_idx.has_conflict(scope.listen_port, hosts, path_slot=True):
        return False
    for index, chunk in enumerate(chunks):
        suffix = f"-default-{index + 1}" if len(chunks) > 1 else "-default"
        synthetic = RouteSpec(ref=scope.ref, name=f"{scope.ref}{suffix}", hosts=chunk, kind="regex",
                              path=REGEX_CLOSURE_PATH[1:])
        closure = _Cand(synthetic, True, chunk, REGEX_CLOSURE_PATH, scope.listen_port,
                        termination=NOT_FOUND_TERMINATION, kind_label="scope-default")
        candidates.append(closure)
        regex_idx.add(closure)
    report.info("scope-closure-regex", scope.ref,
                "A host-only 404 route for this scope would overlap another host-only route, so a regex route "
                "matching every path (answering 404, tried after the scope's own routes) closes it instead.")
    return True


class _LiveFallthroughIndex:
    """Index live non-placeholder candidates by port and covering host pattern for O(1) fallthrough refusal."""

    def __init__(self, candidates: list[_Cand]) -> None:
        self.candidates = candidates
        self.catchall_by_port: dict[int | None, set[int]] = {}
        self.wild_by_port: dict[int | None, dict[str, set[int]]] = {}
        for idx, cand in enumerate(candidates):
            if cand.placeholder:
                continue
            if not cand.hosts:
                self.catchall_by_port.setdefault(cand.listen_port, set()).add(idx)
            else:
                wmap = self.wild_by_port.setdefault(cand.listen_port, {})
                for h in cand.hosts:
                    if h.startswith("*."):
                        wmap.setdefault(h[1:], set()).add(idx)

    def _ports_for(self, scope_port: int | None, mapping_by_port: dict[int | None, Any]) -> list[int | None]:
        if scope_port is None:
            return list(mapping_by_port)
        ports: list[int | None] = []
        if scope_port in mapping_by_port:
            ports.append(scope_port)
        if None in mapping_by_port:
            ports.append(None)
        return ports

    def refuse_targets(self, scope, hosts: list[str]) -> int:
        host_set = set(hosts)
        hit_indices: set[int] = set()
        for port in self._ports_for(scope.listen_port, self.catchall_by_port):
            bucket = self.catchall_by_port[port]
            if bucket:
                hit_indices.update(bucket)
                bucket.clear()
        parent_suffixes: set[str] = set()
        for h in hosts:
            if h.startswith("*."):
                s = h[1:]
                dot = s.find(".", 1)
                while dot != -1:
                    parent = s[dot:]
                    if ("*" + parent) not in host_set:
                        parent_suffixes.add(parent)
                    dot = s.find(".", dot + 1)
            else:
                dot = h.find(".")
                while dot != -1:
                    parent = h[dot:]
                    if ("*" + parent) not in host_set:
                        parent_suffixes.add(parent)
                    dot = h.find(".", dot + 1)
        if parent_suffixes:
            for port in self._ports_for(scope.listen_port, self.wild_by_port):
                wmap = self.wild_by_port[port]
                for suffix in parent_suffixes:
                    bucket = wmap.get(suffix)
                    if bucket:
                        hit_indices.update(bucket)
                        bucket.clear()
        count = 0
        reason = (f"unmatched requests for the hosts of {scope.ref} would fall through to it in Ferrum, "
                  "which the source never did, and that scope could not be closed")
        for idx in sorted(hit_indices):
            cand = self.candidates[idx]
            if cand.placeholder:
                continue
            _fail_close(cand, reason)
            count += 1
        return count


def _add_scope_closures(plan: Plan, candidates: list[_Cand], report: Report) -> None:
    _refuse_nested_wildcard_scopes(plan, candidates, report)
    scopes = sorted(plan.host_scopes, key=lambda s: matching.host_tier(s.hosts))
    host_only_idx = _PortHostIndex()
    regex_idx = _PortHostIndex()
    live_fallthrough_idx: _LiveFallthroughIndex | None = None
    root_hosts: dict[int | None, set[str]] = {}
    for cand in candidates:
        if cand.listen_path is None:
            host_only_idx.add(cand)
        elif cand.listen_path == "/":
            root_hosts.setdefault(cand.listen_port, set()).update(cand.hosts)
        elif cand.listen_path == REGEX_CLOSURE_PATH:
            regex_idx.add(cand)
    for scope in scopes:
        hosts = list(dict.fromkeys(h for h in (util.normalize_host(x) for x in scope.hosts) if h))
        if not hosts:
            continue
        # A prefix route for "/" on exactly these host names already catches every unmatched path in their tier.
        if all(host in root_hosts.get(scope.listen_port, set()) for host in hosts):
            continue
        overlapping = host_only_idx.query(scope.listen_port, hosts)
        # Only a closure for the very same host names closes this scope. A covering wildcard closure does not:
        # Ferrum tries every path route of every matching wildcard pattern (and of the exact tier) before any
        # wildcard host-only route, so another scope's routes would still receive these hosts' unmatched paths.
        if overlapping and all(c.route.methods is None for c in overlapping):
            covered = {h for c in overlapping for h in c.hosts}
            if all(host in covered for host in hosts):
                continue
        chunks = None if overlapping else _chunk_hosts_no_prune(hosts, host_only=True)
        if overlapping or chunks is None:
            if _add_regex_closure(scope, hosts, candidates, regex_idx, report):
                continue
            if live_fallthrough_idx is None:
                live_fallthrough_idx = _LiveFallthroughIndex(candidates)
            refused = live_fallthrough_idx.refuse_targets(scope, hosts)
            report.error("scope-closure-skipped", scope.ref,
                         "Another host-only route overlaps this scope's hosts (or its host list cannot be split within "
                         "Ferrum's 100-host limit), so no default 404 route could be added, and no regex closure fits "
                         "either. Unmatched paths for these hosts could reach other host scopes' routes in Ferrum "
                         f"(another wildcard pattern or the catch-all tier), which the source never did, so the "
                         f"{refused} route(s) that could receive them were refused (fail closed).",
                         "Add explicit routes in the source for paths these hosts must answer, or serve the "
                         "overlapping host scopes from separate Ferrum frontends, then convert again.")
            continue
        for index, chunk in enumerate(chunks):
            suffix = f"-default-{index + 1}" if len(chunks) > 1 else "-default"
            synthetic = RouteSpec(ref=scope.ref, name=f"{scope.ref}{suffix}", hosts=chunk, kind="hostonly", path=None)
            closure = _Cand(synthetic, True, chunk, None, scope.listen_port,
                            termination=NOT_FOUND_TERMINATION, kind_label="scope-default")
            candidates.append(closure)
            host_only_idx.add(closure)
        report.info("scope-closure", scope.ref,
                    "Added a host-only route answering 404 for paths this scope does not route, because the "
                    "source never falls through to other hosts' routes but Ferrum does.")


def _add_trailing_slash_placeholders(candidates: list[_Cand], report: Report) -> None:
    exact_indexes: dict[str, _PortHostIndex] = {}
    for cand in candidates:
        if cand.listen_path and cand.listen_path.startswith("="):
            exact_indexes.setdefault(cand.listen_path, _PortHostIndex()).add(cand)
    for cand in list(candidates):
        route = cand.route
        if cand.placeholder or route.kind != "prefix" or not route.trailing_slash \
                or route.prefix_semantics != "string":
            continue
        exact = "=" + (route.path or "/")
        if len(exact.encode("utf-8")) > util.MAX_LISTEN_PATH_LENGTH:
            _fail_close(cand, f"trailing-slash prefix bare-path exact guard exceeds {util.MAX_LISTEN_PATH_LENGTH} bytes")
            continue
        idx = exact_indexes.get(exact)
        port = cand.listen_port
        guard_hosts: list[str]
        if not cand.hosts:
            if idx is not None and idx.catchall.get(port):
                continue
            if idx is not None and idx.all_by_port.get(port):
                _fail_close(cand, f"a named exact route for {route.path} prevents adding a catch-all bare-path guard")
                report.error("trailing-slash-guard-conflict", route.ref,
                             f"The source prefix ends with '/', so bare {route.path} did not match it, but an "
                             f"existing named exact route on {route.path} prevents emitting a catch-all 404 guard "
                             "in Ferrum. This route was refused (fail closed).",
                             "Add an explicit bare-path route or separate the conflicting host scopes, then convert again.")
                continue
            guard_hosts = []
        else:
            if idx is not None and idx.catchall.get(port):
                _fail_close(cand, f"a catch-all exact route for {route.path} prevents adding a host-scoped bare-path guard")
                report.error("trailing-slash-guard-conflict", route.ref,
                             f"The source prefix ends with '/', so bare {route.path} did not match it, but an "
                             f"existing catch-all exact route on {route.path} prevents emitting a host-scoped 404 "
                             "guard in Ferrum (and Ferrum checks the named host tier before catch-all). This route "
                             "was refused (fail closed).",
                             "Add an explicit host-scoped bare-path route or separate the conflicting scopes, then convert again.")
                continue
            ex_map = idx.exact.get(port, {}) if idx is not None else {}
            wi_map = idx.wild.get(port, {}) if idx is not None else {}
            wi_par = idx.wild_by_parent.get(port, {}) if idx is not None else {}
            guard_hosts = []
            blocked = False
            for host in cand.hosts:
                if host.startswith("*."):
                    suffix = host[1:]
                    covered = suffix in wi_map
                    if not covered:
                        dot = suffix.find(".", 1)
                        while dot != -1:
                            if suffix[dot:] in wi_map:
                                covered = True
                                break
                            dot = suffix.find(".", dot + 1)
                    if covered:
                        continue
                    if suffix in wi_par:
                        blocked = True
                        break
                    guard_hosts.append(host)
                else:
                    if host in ex_map:
                        continue
                    guard_hosts.append(host)
            if blocked:
                _fail_close(cand, f"an overlapping narrower wildcard exact route for {route.path} prevents adding a "
                                  "valid bare-path guard")
                report.error("trailing-slash-guard-conflict", route.ref,
                             f"The source prefix ends with '/', so bare {route.path} did not match it, but a "
                             f"narrower wildcard exact route on {route.path} overlaps this route's wildcard host in "
                             "Ferrum and prevents emitting a valid bare-path 404 guard. This route was refused (fail closed).",
                             "Add explicit bare-path routes or separate the overlapping wildcard hosts, then convert again.")
                continue
            if not guard_hosts:
                continue
        synthetic = RouteSpec(ref=route.ref, name=f"{route.name}-bare", hosts=list(guard_hosts), kind="exact",
                              path=route.path)
        guard = _Cand(synthetic, True, list(guard_hosts), exact, port,
                      termination=NOT_FOUND_TERMINATION, kind_label="exact-guard")
        candidates.append(guard)
        exact_indexes.setdefault(exact, _PortHostIndex()).add(guard)
        report.info("trailing-slash-prefix", route.ref,
                    f"The source prefix ends with '/', so the bare path {route.path} did not match it. Ferrum "
                    f"matches {route.path} itself; an exact route answering 404 was added for the bare path.")


def _fingerprint(cand: _Cand) -> str:
    route = cand.route
    backend = route.backend
    data = {
        "backend": None if backend is None else [backend.scheme, backend.host, backend.port, backend.upstream_key,
                                                 backend.tls.key()],
        "backend_path": route.backend_path, "strip": route.strip, "preserve_host": route.preserve_host,
        "plugins": [[p.name, p.config, p.shared_key] for p in route.plugins],
        "termination": cand.termination, "methods": route.methods, "retry": route.retry,
        "timeouts": [route.connect_timeout_ms, route.read_timeout_ms, route.write_timeout_ms],
    }
    return json.dumps(data, sort_keys=True, default=str)


def _ancestor_paths(path: str) -> list[str]:
    """``/a/b/c`` -> ``["/", "/a", "/a/b"]`` (segment-boundary ancestors)."""
    parts = path.split("/")[1:]
    result = ["/"]
    for index in range(1, len(parts)):
        result.append("/" + "/".join(parts[:index]))
    return result


def _regex_reaches_siblings(regex: str | None, prefix: str) -> bool:
    """Whether a (Ferrum-anchored) regex route can match a string-prefix sibling of ``prefix`` (``/apix`` for ``/api``).

    Siblings start with ``prefix`` but are neither ``prefix`` itself nor under ``prefix + "/"``. Conservative:
    unknown or alternating patterns (any pipe the shared narrow-grammar proof cannot place inside a group) count as
    reaching them.
    """
    if not regex or util.regex_alternation_unproven(regex):
        return True
    literal = util.regex_literal_prefix(regex)
    return prefix.startswith(literal) or (literal.startswith(prefix) and not literal.startswith(prefix + "/"))


def _add_divergence_guards(plan: Plan, candidates: list[_Cand], report: Report) -> None:
    # A scoped request_termination guard replaces global request_termination on that proxy (plugin_cache.rs:5797).
    # If an unconditional global termination already governs the plan, do not attach scoped guards that would
    # shadow it on non-matching paths.
    if any(p.name == "request_termination" and not p.config.get("trigger") for p in plan.global_plugins):
        return
    by_path: dict[tuple[int | None, str | None], list[_Cand]] = {}
    regex_by_port: dict[int | None, list[_Cand]] = {}
    for cand in candidates:
        by_path.setdefault((cand.listen_port, cand.listen_path), []).append(cand)
        if cand.listen_path is not None and cand.listen_path.startswith("~"):
            regex_by_port.setdefault(cand.listen_port, []).append(cand)
    fingerprints: dict[int, str] = {}
    scoped_guards_added: set[tuple[int | None, tuple[str, ...], str]] = set()
    new_guard_cands: list[_Cand] = []

    def fp(item: _Cand) -> str:
        if id(item) not in fingerprints:
            fingerprints[id(item)] = _fingerprint(item)
        return fingerprints[id(item)]

    def try_scoped_regex_guard(cand: _Cand, other: _Cand, pairs: set[tuple[int, int]], regex_other: bool) -> bool:
        route = cand.route
        prefix = route.path or "/"
        guard_pattern = re.escape(prefix) + ".*"
        guard_listen = "~" + guard_pattern
        if not (
            bool(cand.hosts)
            and len(cand.hosts) <= util.MAX_HOSTS_PER_PROXY
            and other.listen_port == cand.listen_port
            and not regex_other
            and not route.methods
            and bool(pairs) and all(tb > ta for ta, tb in pairs)
            and len(guard_listen.encode("utf-8")) <= util.MAX_LISTEN_PATH_LENGTH
            and util.regex_problem(guard_pattern) is None
        ):
            return False
        guard_key = (cand.listen_port, tuple(cand.hosts), guard_listen)
        if guard_key in scoped_guards_added:
            return True
        if any(
            c.listen_port == cand.listen_port and c.listen_path == guard_listen
            and _hosts_merge_in_slot(c.hosts, cand.hosts, host_only=False)
            for c in (*candidates, *new_guard_cands)
        ):
            return False
        if any(
            not c.placeholder and matching.hosts_overlap(c.hosts, cand.hosts)
            for c in regex_by_port.get(cand.listen_port, [])
        ):
            return False
        # Avoid preempting another live lower-tier route (for example a catch-all /apix route) that sits under
        # `prefix` as a string sibling.
        for c in candidates:
            if c is cand or c is other or c.placeholder:
                continue
            if not matching.ports_compatible(c.listen_port, cand.listen_port):
                continue
            if not matching.hosts_overlap(c.hosts, cand.hosts):
                continue
            c_path = c.route.path or ""
            if c.route.kind in ("exact", "prefix") and c_path.startswith(prefix) \
                    and c_path != prefix and not c_path.startswith(prefix + "/"):
                c_pairs = matching.overlapping_tier_pairs(cand.hosts, c.hosts)
                if any(tc > ta for ta, tc in c_pairs):
                    return False
        guard_key = (cand.listen_port, tuple(cand.hosts), guard_listen)
        if guard_key not in scoped_guards_added:
            scoped_guards_added.add(guard_key)
            synthetic = RouteSpec(ref=route.ref, name=f"{route.name}-sibling-guard",
                                  hosts=list(cand.hosts), kind="regex", path=guard_pattern)
            guard_cand = _Cand(synthetic, True, list(cand.hosts), guard_listen, cand.listen_port,
                               termination=NOT_FOUND_TERMINATION, kind_label="prefix-guard")
            new_guard_cands.append(guard_cand)
            report.info("prefix-divergence-guard", route.ref,
                        f"Added a host-scoped regex 404 guard ({guard_listen}) so sibling paths like "
                        f"{prefix}x cannot reach {other.route.ref} without affecting its other hosts.")
        return True

    for cand in list(candidates):
        route = cand.route
        # A refused route's placeholder keeps its envelope too: the source sent its string-prefix siblings
        # (/apix for /api) to the refused route, so they must not fall through to a broader live route.
        refused = cand.placeholder and cand.kind_label == "refused"
        if (cand.placeholder and not refused) or route.kind != "prefix" or route.prefix_semantics != "string" \
                or route.trailing_slash or route.path in (None, "/"):
            continue
        fingerprint = fp(cand)
        # Port-agnostic routes (no listen_port) also receive requests on a port-scoped route's listener.
        ports = [cand.listen_port] if cand.listen_port is None else [cand.listen_port, None]
        closures = [o for port in ports for o in by_path.get((port, None), []) if o.placeholder]
        closed = bool(cand.hosts) and all(
            any(matching.single_host_tier(oh) <= matching.single_host_tier(h) and matching.host_cover(oh, h)
                for o in closures for oh in o.hosts)
            for h in cand.hosts
        )
        related: list[_Cand] = []
        for port in ports:
            related.extend(by_path.get((port, None), []))
            for ancestor in _ancestor_paths(route.path or "/"):
                related.extend(by_path.get((port, ancestor), []))
        # Regex routes the source's priority kept away from the siblings (an NGINX ^~ prefix stops the regex
        # search; Envoy/Istio match the earlier prefix first) still receive them in Ferrum unless an ancestor
        # prefix in each host's tier, covering every host of this route, catches them first (prefix beats regex).
        prefix_related = [o for o in related if o.listen_path is not None]
        if not cand.hosts:
            shield = any(not o.hosts for o in prefix_related)
        else:
            shield = all(
                any(matching.single_host_tier(oh) == matching.single_host_tier(h) and matching.host_cover(oh, h)
                    for o in prefix_related for oh in o.hosts)
                for h in cand.hosts
            )
        if not shield:
            for port in ports:
                related.extend(other for other in regex_by_port.get(port, [])
                               if _regex_reaches_siblings(other.route.path, route.path or "/"))
        # Where do sibling paths such as /apix (string-prefix matches the source sent to this route) land
        # in Ferrum? They are preserved only if an equivalent route (same forwarding and policy, no strip,
        # covering every host) catches them and nothing more specific intercepts them.
        equivalent = intercepted = guarded = divergence_error = False
        for other in related:
            if other is cand or other.listen_port not in ports:
                continue
            if not matching.hosts_overlap(cand.hosts, other.hosts):
                continue
            pairs = matching.overlapping_tier_pairs(cand.hosts, other.hosts)
            if closed and pairs and all(tb > ta for ta, tb in pairs):
                continue  # a host-only 404/placeholder in each overlapping host's tier intercepts first
            other_route = other.route
            regex_other = other.listen_path is not None and other.listen_path.startswith("~")
            if regex_other and pairs and all(tb < ta for ta, tb in pairs):
                continue  # strictly more specific host tier for every overlapping host: source routed those there too
            if other.listen_path is None or regex_other:
                covers = True
            elif other_route.kind == "prefix":
                covers = other_route.path == "/" or (route.path or "").startswith((other_route.path or "") + "/")
            else:
                covers = False
            if not covers:
                continue
            if other.placeholder or other.termination is not None:
                intercepted = True  # siblings get a 404/503/termination, never the source's backend
                continue
            if fp(other) == fingerprint:
                # A regex catches only some siblings, so it never proves equivalence on its own.
                if not regex_other and not route.strip and matching.hosts_cover(other.hosts, cand.hosts):
                    equivalent = True
                continue
            # A guard is exact only on a route with the same listener scope whose hosts this route covers: there,
            # every request the guard blocks is a sibling this route's source owned. A port-agnostic route also
            # serves the main listeners, where the same paths were never this route's.
            exact_scope = other.listen_port == cand.listen_port and matching.hosts_cover(cand.hosts, other.hosts)
            if regex_other and not refused and not exact_scope:
                # Competing regex coverage on more hosts or listeners: no exact guard exists. Guard anyway (fail
                # closed) so the siblings never reach a route with another policy, and report the collateral 404s.
                if route.path not in other.guards:
                    other.guards.append(route.path or "/")
                divergence_error = True
                report.error("prefix-divergence", route.ref,
                             f"The source sent paths such as {route.path}x to this route, but in Ferrum the regex "
                             f"route {other_route.ref}, which has a different policy and serves more hosts or "
                             f"listeners, would receive them. A request_termination guard (trigger.path_prefix "
                             f"{route.path}) was added to it for all of its hosts, so such paths now answer 404 there "
                             "(fail closed).",
                             "Confirm such paths are not needed on the regex route's other hosts or listeners, or add "
                             "explicit routes for them in the source, then convert again.")
                continue
            if exact_scope:
                guarded = True
                if route.path not in other.guards:
                    other.guards.append(route.path or "/")
                    report.info("prefix-divergence-guard", other_route.ref,
                                f"Added a request_termination guard (trigger.path_prefix {route.path}) so paths "
                                f"like {route.path}x, which the source routed to {route.ref}, cannot reach this "
                                f"broader route under Ferrum's segment-based prefix matching.")
            elif refused:
                if try_scoped_regex_guard(cand, other, pairs, regex_other):
                    guarded = True
                else:
                    # The guard cannot be scoped to the refused route's hosts. Letting its siblings reach this broader
                    # route would bypass the refused policy, so the guard is added anyway (fail closed) and the
                    # collateral 404s on the broader route's other hosts are a review error.
                    if route.path not in other.guards:
                        other.guards.append(route.path or "/")
                    report.error("prefix-divergence-refused", route.ref,
                                 f"The source sent paths such as {route.path}x to this refused route. Ferrum would hand "
                                 f"them to the broader route {other_route.ref}, which serves more hosts or listeners, so a "
                                 f"request_termination guard (trigger.path_prefix {route.path}) was added to it for all "
                                 f"of its hosts: such paths now answer 404 there even on hosts the source forwarded "
                                 f"(fail closed).",
                                 "Recreate the refused route in Ferrum, then remove the guard only for hosts where the "
                                 "broader route should serve those paths.")
            else:
                if try_scoped_regex_guard(cand, other, pairs, regex_other):
                    guarded = True
                else:
                    # Cannot scope strictly to this route's hosts: guard `other` anyway (fail closed) and report
                    # the collateral 404s on the broader route's other hosts.
                    if route.path not in other.guards:
                        other.guards.append(route.path or "/")
                    divergence_error = True
                    report.error("prefix-divergence", route.ref,
                                 f"The source matched any path starting with {route.path} (for example {route.path}x); "
                                 f"Ferrum matches by path segment, so on some hosts those paths would reach "
                                 f"{other_route.ref}, which has a different policy and serves more hosts or listeners. "
                                 f"A request_termination guard (trigger.path_prefix {route.path}) was added to it for "
                                 "all of its hosts so such paths answer 404 there (fail closed).",
                                 "Confirm such paths are not needed on the broader route's other hosts, or add "
                                 "explicit routes for them in the source and convert again.")
        if route.report_prefix_siblings and not refused and not divergence_error \
                and not (equivalent and not intercepted and not guarded):
            report.error("prefix-string-siblings", route.ref,
                         f"The source matched every path that starts with {route.path}, including paths such as "
                         f"{route.path}x or {route.path}.json that do not continue at a '/' boundary. Ferrum prefix "
                         f"routes match only {route.path} and {route.path}/..., and in this output those sibling "
                         f"paths do not reach the same backend, response and policy: they get a 404, a fail-closed "
                         f"response or another route's termination instead. The route was not widened.",
                         "If clients use such paths, add explicit routes for them in the source configuration and "
                         "convert again, or confirm they are unused.")
    candidates.extend(new_guard_cands)


# ------------------------------------------------------------------ building

def _fit_bytes(text: str, limit: int) -> str:
    """Truncate ``text`` to at most ``limit`` UTF-8 bytes on a character boundary (Ferrum limits are in bytes)."""
    encoded = text.encode("utf-8")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="ignore")


_COOKIE_KEYS = {"path", "ttl_seconds", "session_cookie", "domain", "http_only", "secure", "same_site"}


def _admissible_hash_policy(spec: UpstreamSpec, report: Report) -> tuple[str | None, dict | None]:
    """The upstream's ``hash_on`` and ``hash_on_cookie_config`` exactly as Ferrum admits them.

    Sources already map these within Ferrum's limits; this is the emitter's last check, so an
    unrepresentable value never reaches the resources file (Ferrum rejects the whole file). An
    invalid ``hash_on`` falls back to round robin, and an invalid cookie setting is dropped, each with
    a report finding.
    """
    hash_on = spec.hash_on
    if hash_on and hash_on != "ip":
        kind, _, name = hash_on.partition(":")
        if kind not in ("header", "cookie") or hash_on_value(kind, name) != (hash_on if kind == "cookie"
                                                                              else f"header:{name.lower()}"):
            report.warning("hash-on-not-representable", spec.ref,
                           "The consistent-hashing key is not one Ferrum accepts; round robin is used "
                           "(stickiness lost).")
            return None, None
        if kind == "header":
            hash_on = f"header:{name.lower()}"
    config = spec.hash_on_cookie_config
    if not config or not (hash_on or "").startswith("cookie:"):
        return hash_on, None
    cleaned = {key: value for key, value in config.items() if key in _COOKIE_KEYS}
    problems = [key for key in config if key not in _COOKIE_KEYS]
    if "path" in cleaned and not cookie_path_ok(cleaned["path"]):
        cleaned["path"] = "/"
        problems.append("path")
    ttl = cleaned.get("ttl_seconds")
    if "ttl_seconds" in cleaned and (isinstance(ttl, bool) or not isinstance(ttl, int)
                                     or not 0 <= ttl <= MAX_COOKIE_TTL_SECONDS):
        cleaned.pop("ttl_seconds")
        cleaned["session_cookie"] = True
        problems.append("ttl_seconds")
    if "domain" in cleaned and not cookie_domain_ok(cleaned["domain"]):
        cleaned.pop("domain")
        problems.append("domain")
    if "same_site" in cleaned and cleaned["same_site"] not in ("Strict", "Lax", "None"):
        cleaned.pop("same_site")
        problems.append("same_site")
    for key in ("session_cookie", "http_only", "secure"):
        if key in cleaned and not isinstance(cleaned[key], bool):
            cleaned.pop(key)
            problems.append(key)
    if problems:
        report.warning("hash-cookie-not-representable", spec.ref,
                       "Sticky cookie settings Ferrum would refuse were replaced or dropped: "
                       + ", ".join(sorted(set(problems))) + ".")
    return hash_on, cleaned


class _NameAllocator:
    """Deterministic, readable, unique resource names.

    Ferrum rejects duplicate proxy names. Source names repeat legitimately (one Istio route projected through two
    gateway servers, synthetic closures of one source scope, names that only differ beyond the length limit or in
    case, several names redacted to the same label). The first holder keeps the readable name; later ones get
    ``-2``, ``-3``... with the base shortened so the result stays within the byte limit. Uniqueness is decided on a
    whitespace-collapsed, case-folded key, so names stay unique after any such normalization.
    """

    def __init__(self, limit: int = util.MAX_NAME_LENGTH) -> None:
        self._limit = limit
        self._used: set[str] = set()

    @staticmethod
    def key(name: str) -> str:
        return " ".join(name.split()).casefold()

    def take(self, raw: object, fallback: str) -> str:
        base = _fit_bytes(safe_label(raw, self._limit).strip(), self._limit).strip() or fallback
        candidate, counter = base, 2
        while self.key(candidate) in self._used or not self.key(candidate):
            suffix = f"-{counter}"
            candidate = _fit_bytes(base, self._limit - len(suffix)).rstrip() + suffix
            counter += 1
        self._used.add(self.key(candidate))
        return candidate


class _Builder:
    def __init__(self, plan: Plan, options: EmitOptions, report: Report) -> None:
        self.plan = plan
        self.options = options
        self.report = report
        self.proxy_ids = util.IdAllocator()
        self.plugin_ids = util.IdAllocator()
        self.upstream_ids = util.IdAllocator()
        self.consumer_ids = util.IdAllocator()
        self.proxy_names = _NameAllocator()
        self.upstream_names = _NameAllocator()
        self.plugin_configs: list[dict[str, Any]] = []
        self.group_ids: dict[str, str] = {}
        self.upstream_id_by_key: dict[str, str] = {}
        self.basic_auth_used = False
        self.secrets_emitted = 0
        self.guard_count = 0

    def labels(self, ref: str, status: str | None = None) -> dict[str, str]:
        labels = {LABEL_SOURCE: self.plan.platform, LABEL_REF: safe_label(ref, 500)}
        if status:
            labels[LABEL_STATUS] = status
        return labels

    def build(self, candidates: list[_Cand]) -> dict[str, Any]:
        for plugin in self.plan.global_plugins:
            self._note_plugin(plugin.name)
            pid = self.plugin_ids.take(self.plan.platform, "global", plugin.name)
            self.plugin_configs.append(self._plugin_entry(pid, plugin.name, plugin.config, "global", None, plugin.ref))
        upstreams = self._build_upstreams(candidates)
        proxies = [self._build_proxy(cand) for cand in candidates]
        consumers = self._build_consumers()
        return {
            "version": "1",
            "resource_counts": {
                "proxies": len(proxies),
                "consumers": len(consumers),
                "plugin_configs": len(self.plugin_configs),
                "upstreams": len(upstreams),
            },
            "proxies": proxies,
            "upstreams": upstreams,
            "consumers": consumers,
            "plugin_configs": self.plugin_configs,
        }

    def _note_plugin(self, name: str) -> None:
        if name == "basic_auth":
            self.basic_auth_used = True

    def _plugin_entry(self, pid: str, name: str, config: dict, scope: str, proxy_id: str | None,
                      ref: str) -> dict[str, Any]:
        entry: dict[str, Any] = {"id": pid, "plugin_name": name, "scope": scope}
        if proxy_id:
            entry["proxy_id"] = proxy_id
        entry["enabled"] = True
        entry["config"] = copy.deepcopy(config)
        entry["labels"] = self.labels(ref)
        return entry

    def _build_upstreams(self, candidates: list[_Cand]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for cand in candidates:
            backend = cand.route.backend
            if cand.placeholder or backend is None or not backend.upstream_key or cand.route.termination:
                continue
            if backend.upstream_key in self.upstream_id_by_key:
                continue
            spec = self.plan.upstreams[backend.upstream_key]
            uid = self.upstream_ids.take(self.plan.platform, "up", spec.name)
            self.upstream_id_by_key[backend.upstream_key] = uid
            result.append(self._upstream_entry(uid, spec, backend.scheme == "https"))
        return result

    def _upstream_entry(self, uid: str, spec: UpstreamSpec, https: bool) -> dict[str, Any]:
        algorithm = spec.algorithm
        hash_on, cookie_config = _admissible_hash_policy(spec, self.report)
        if algorithm == "consistent_hashing" and spec.hash_on and hash_on is None:
            algorithm = "round_robin"
        weights = {t.weight for t in spec.targets}
        if algorithm == "round_robin" and len(weights) > 1:
            algorithm = "weighted_round_robin"
        entry: dict[str, Any] = {
            "id": uid,
            "name": self.upstream_names.take(spec.name, uid),
            "labels": self.labels(spec.ref),
            "targets": [{"host": t.host, "port": int(t.port), "weight": int(t.weight)} for t in spec.targets],
            "algorithm": algorithm,
        }
        if hash_on:
            entry["hash_on"] = hash_on
        if cookie_config:
            entry["hash_on_cookie_config"] = cookie_config
        if spec.health_checks:
            entry["health_checks"] = copy.deepcopy(spec.health_checks)
        if https:
            tls = spec.tls
            entry["backend_tls_verify_server_cert"] = True
            if tls.ca_path:
                entry["backend_tls_server_ca_cert_path"] = tls.ca_path
            if tls.client_cert_path and tls.client_key_path:
                entry["backend_tls_client_cert_path"] = tls.client_cert_path
                entry["backend_tls_client_key_path"] = tls.client_key_path
            if tls.sni:
                entry["backend_tls_sni"] = tls.sni
            if tls.san_allow_list:
                entry["backend_tls_san_allow_list"] = list(tls.san_allow_list)
        return entry

    def _termination_plugin(self, proxy_id: str, config: dict, ref: str, label: str) -> str:
        pid = self.plugin_ids.take(proxy_id, label)
        self.plugin_configs.append(self._plugin_entry(pid, "request_termination", config, "proxy", proxy_id, ref))
        return pid

    def _build_proxy(self, cand: _Cand) -> dict[str, Any]:
        route = cand.route
        name_suffix = {"refused": "refused", "scope-default": "", "exact-guard": ""}.get(cand.kind_label, "")
        proxy_id = self.proxy_ids.take(self.plan.platform, route.name, name_suffix)
        proxy: dict[str, Any] = {
            "id": proxy_id,
            "name": self.proxy_names.take(route.name, proxy_id),
            "labels": self.labels(route.ref, cand.kind_label),
        }
        if cand.hosts:
            proxy["hosts"] = list(cand.hosts)
        if cand.listen_path is not None:
            proxy["listen_path"] = cand.listen_path
        if cand.listen_port is not None:
            proxy["listen_port"] = cand.listen_port
        associations: list[str] = []
        if cand.placeholder or route.backend is None or route.termination is not None:
            proxy.update({"backend_scheme": "http", "backend_host": PLACEHOLDER_HOST,
                          "backend_port": PLACEHOLDER_PORT, "strip_listen_path": False})
            termination = cand.termination or REFUSED_TERMINATION
            associations.append(self._termination_plugin(proxy_id, termination, route.ref, "terminate"))
            if not cand.placeholder and route.methods:
                proxy["allowed_methods"] = list(route.methods)
            proxy["plugins"] = [{"plugin_config_id": pid} for pid in associations]
            return proxy
        if route.methods:
            proxy["allowed_methods"] = list(route.methods)
        backend: BackendRef = route.backend
        proxy["backend_scheme"] = backend.scheme
        if backend.upstream_key:
            proxy["upstream_id"] = self.upstream_id_by_key[backend.upstream_key]
        else:
            proxy["backend_host"] = backend.host
            proxy["backend_port"] = int(backend.port)
        if route.backend_path:
            proxy["backend_path"] = route.backend_path
        proxy["strip_listen_path"] = bool(route.strip)
        proxy["preserve_host_header"] = bool(route.preserve_host)
        if route.connect_timeout_ms:
            proxy["backend_connect_timeout_ms"] = route.connect_timeout_ms
        if route.read_timeout_ms:
            proxy["backend_read_timeout_ms"] = route.read_timeout_ms
        if route.write_timeout_ms:
            proxy["backend_write_timeout_ms"] = route.write_timeout_ms
        if backend.scheme == "https" and not backend.upstream_key:
            proxy["backend_tls_verify_server_cert"] = True
            if backend.tls.ca_path:
                proxy["backend_tls_server_ca_cert_path"] = backend.tls.ca_path
            if backend.tls.client_cert_path and backend.tls.client_key_path:
                proxy["backend_tls_client_cert_path"] = backend.tls.client_cert_path
                proxy["backend_tls_client_key_path"] = backend.tls.client_key_path
        if route.retry:
            proxy["retry"] = copy.deepcopy(route.retry)
        for guard in cand.guards:
            config = dict(NOT_FOUND_TERMINATION)
            config["trigger"] = {"path_prefix": guard}
            associations.append(self._termination_plugin(proxy_id, config, route.ref, "guard"))
            self.guard_count += 1
        for plugin in route.plugins:
            associations.append(self._attach_plugin(proxy_id, plugin))
        proxy["plugins"] = [{"plugin_config_id": pid} for pid in associations]
        return proxy

    def _attach_plugin(self, proxy_id: str, plugin: PluginSpec) -> str:
        self._note_plugin(plugin.name)
        if plugin.shared_key:
            key = json.dumps([plugin.shared_key, plugin.name, plugin.config], sort_keys=True)
            if key not in self.group_ids:
                pid = self.plugin_ids.take(self.plan.platform, "group", plugin.shared_key, plugin.name)
                self.group_ids[key] = pid
                self.plugin_configs.append(self._plugin_entry(pid, plugin.name, plugin.config, "proxy_group",
                                                              None, plugin.ref))
            return self.group_ids[key]
        pid = self.plugin_ids.take(proxy_id, plugin.name)
        self.plugin_configs.append(self._plugin_entry(pid, plugin.name, plugin.config, "proxy", proxy_id, plugin.ref))
        return pid

    def _build_consumers(self) -> list[dict[str, Any]]:
        consumers = self.plan.consumers
        usernames: dict[str, int] = {}
        custom_ids: dict[str, int] = {}
        for consumer in consumers:
            usernames[consumer.username] = usernames.get(consumer.username, 0) + 1
            if consumer.custom_id:
                custom_ids[consumer.custom_id] = custom_ids.get(consumer.custom_id, 0) + 1
        key_owners: dict[str, int] = {}
        jwt_owners: dict[str, int] = {}
        if self.options.include_secrets:
            for consumer in consumers:
                for key in set(consumer.keyauth):
                    key_owners[key] = key_owners.get(key, 0) + 1
                for secret in set(consumer.jwt):
                    jwt_owners[secret] = jwt_owners.get(secret, 0) + 1
        withheld = 0
        # Build validated candidates first so we can check whole-config identity uniqueness across id, username, and
        # normalized custom_id in one shared namespace (matching Ferrum's validate_unique_consumer_identities).
        staged: list[tuple[Any, dict[str, Any], set[str]]] = []
        identity_owners: dict[str, int] = {}
        for consumer in consumers:
            if usernames[consumer.username] > 1:
                consumer.quarantined.append("its username is not unique")
            if consumer.custom_id and custom_ids[consumer.custom_id] > 1:
                consumer.quarantined.append("its custom_id is not unique")
            username = consumer.username
            if not username or not username.strip() or len(username.encode("utf-8")) > util.MAX_NAME_LENGTH \
                    or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in username):
                self.report.error("consumer-invalid", consumer.ref, "Consumer username is not representable; skipped.")
                continue
            custom_id = consumer.custom_id
            if custom_id is not None and not custom_id.strip():
                custom_id = None
            if custom_id is not None and (
                    len(custom_id.encode("utf-8")) > util.MAX_NAME_LENGTH
                    or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in custom_id)):
                self.report.error("consumer-invalid", consumer.ref, "Consumer custom_id is not representable; skipped.")
                continue
            cid = self.consumer_ids.take(self.plan.platform, "consumer", consumer.key)
            labels = dict(consumer.labels)
            labels.update(self.labels(consumer.ref))
            entry: dict[str, Any] = {
                "id": cid,
                "username": username,
                "labels": labels,
            }
            if custom_id:
                entry["custom_id"] = custom_id
            groups = [g for g in consumer.acl_groups if isinstance(g, str) and g.strip()
                      and len(g.encode("utf-8")) <= 255
                      and not any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in g)]
            if len(groups) != len(consumer.acl_groups) or len(groups) > 500:
                self.report.error("consumer-acl-groups", consumer.ref,
                                  "Some ACL group names were not representable or exceeded 500 entries and were "
                                  "dropped; the consumer is quarantined (credentials withheld) so dropping a group "
                                  "cannot bypass a deny-list rule (fail closed).")
                consumer.quarantined.append("some ACL group names were dropped or truncated")
                groups = groups[:500]
            if groups:
                entry["acl_groups"] = groups
            own_identities = {cid, username} | ({custom_id} if custom_id else set())
            for ident in own_identities:
                identity_owners[ident] = identity_owners.get(ident, 0) + 1
            staged.append((consumer, entry, own_identities))
        result: list[dict[str, Any]] = []
        for consumer, entry, own_identities in staged:
            if any(identity_owners[ident] > 1 for ident in own_identities):
                self.report.error("consumer-identity-conflict", consumer.ref,
                                  "Consumer id, username or custom_id collides with another consumer's identity in "
                                  "Ferrum's shared identity namespace; omitted (fail closed).",
                                  "Give every consumer a unique id, username and custom_id across all consumers.")
                continue
            secret_count = len(consumer.keyauth) + len(consumer.jwt) + consumer.withheld_secrets
            if consumer.quarantined:
                if secret_count:
                    self.report.error("consumer-quarantined", consumer.ref,
                                      "Credentials withheld (fail closed) because " + "; ".join(consumer.quarantined) + ".",
                                      "Recreate this consumer's policy in Ferrum, then issue new credentials.")
            elif self.options.include_secrets:
                credentials = self._credentials(consumer, key_owners, jwt_owners)
                if credentials:
                    entry["credentials"] = credentials
            else:
                withheld += secret_count
            result.append(entry)
        if withheld:
            self.report.warning("credentials-withheld", "consumers",
                                f"{withheld} migratable credential(s) were not written because plaintext secrets are "
                                "only emitted with explicit --include-secrets. Authentication on migrated routes "
                                "fails closed until credentials exist.",
                                "Re-run with --include-secrets into a private directory, or issue new credentials "
                                "in Ferrum.")
        return result

    def _credentials(self, consumer, key_owners: dict[str, int], jwt_owners: dict[str, int]) -> dict[str, Any]:
        credentials: dict[str, Any] = {}
        keys = []
        for key in consumer.keyauth:
            stripped = sum(1 for ch in key if not ch.isspace())
            if key_owners.get(key, 0) > 1:
                self.report.error("keyauth-duplicate", consumer.ref,
                                  "An API key is shared with another consumer; it was not migrated (fail closed).")
            elif stripped < MIN_KEYAUTH_KEY_LENGTH or len(key) > MAX_CREDENTIAL_VALUE_LENGTH \
                    or key == CREDENTIAL_REDACTION_PLACEHOLDER \
                    or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in key):
                self.report.error("keyauth-weak", consumer.ref,
                                  "An API key is shorter than Ferrum's 16-character minimum or not representable; "
                                  "it was not migrated (fail closed).",
                                  "Issue a new random key of at least 16 characters.")
            elif key not in keys:
                keys.append(key)
        if len(keys) > MAX_CREDENTIALS_PER_TYPE:
            self.report.error("keyauth-limit", consumer.ref,
                              f"{len(keys)} API keys exceed Ferrum's default limit of {MAX_CREDENTIALS_PER_TYPE} "
                              "credentials per type; none was migrated (fail closed).",
                              "Reduce the consumer to at most 2 keys or raise FERRUM_MAX_CREDENTIALS_PER_TYPE and "
                              "provision keys in Ferrum.")
            keys = []
        if keys:
            credentials["keyauth"] = [{"key": key} for key in keys]
        secrets = []
        for secret in consumer.jwt:
            stripped = sum(1 for ch in secret if not ch.isspace())
            if jwt_owners.get(secret, 0) > 1:
                self.report.error("jwt-secret-duplicate", consumer.ref,
                                  "A JWT secret is shared with another consumer; Ferrum refuses shared secrets, so it "
                                  "was not migrated (fail closed).")
            elif stripped < MIN_JWT_SECRET_LENGTH or len(secret) > MAX_CREDENTIAL_VALUE_LENGTH \
                    or secret == CREDENTIAL_REDACTION_PLACEHOLDER \
                    or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in secret):
                self.report.error("jwt-secret-weak", consumer.ref,
                                  "A JWT secret is shorter than Ferrum's 32-character minimum; it was not migrated "
                                  "(fail closed).", "Rotate to a random secret of at least 32 characters.")
            elif secret not in secrets:
                secrets.append(secret)
        if len(secrets) > 1:
            # Ferrum's jwt_auth accepts a signature from any of the resolved consumer's JWT secrets, so several
            # secrets on one consumer would no longer be bound to the key claim of their own source credential.
            self.report.error("jwt-multiple-secrets", consumer.ref,
                              f"{len(secrets)} JWT secrets would be attached to one consumer; Ferrum cannot bind each "
                              "to its own key claim, so none was migrated (fail closed).",
                              "Issue one new random secret of at least 32 characters for this consumer in Ferrum.")
            secrets = []
        if secrets:
            credentials["jwt"] = [{"secret": secret} for secret in secrets]
        if credentials:
            size = len(json.dumps(credentials, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
            if size > MAX_CREDENTIALS_SIZE:
                self.report.error("consumer-credentials-size", consumer.ref,
                                  f"Consumer credentials JSON ({size} bytes) exceeds Ferrum's {MAX_CREDENTIALS_SIZE}-byte "
                                  "limit; credentials withheld (fail closed).",
                                  "Reduce credential count/length and provision credentials in Ferrum.")
                return {}
            self.secrets_emitted += len(keys) + len(secrets)
        return credentials

    def stats(self, routes: list[RouteSpec], candidates: list[_Cand]) -> dict[str, Any]:
        source_routes = [r for r in routes if not r.skip]
        scoped_prefix_guards = sum(1 for c in candidates if c.kind_label == "prefix-guard")
        return {
            "source_routes": len(source_routes),
            "migrated_routes": sum(1 for c in candidates if not c.placeholder),
            "refused_routes": sum(1 for r in source_routes if r.refusals),
            "fail_closed_placeholders": sum(1 for c in candidates if c.placeholder and c.kind_label == "refused"),
            "synthetic_404_routes": sum(1 for c in candidates
                                        if c.kind_label in ("scope-default", "exact-guard", "prefix-guard")),
            "prefix_guards": self.guard_count + scoped_prefix_guards,
            "skipped_source_routes": sum(1 for r in routes if r.skip),
            "proxies": len(candidates),
            "upstreams": len(self.upstream_id_by_key),
            "consumers": len(self.plan.consumers),
            "plugin_configs": len(self.plugin_configs),
            "credentials_emitted": self.secrets_emitted,
        }


def _report_routes(routes: list[RouteSpec], report: Report) -> None:
    for route in routes:
        if route.skip:
            continue
        if route.refusals:
            outcome = ("A fail-closed placeholder answering HTTP 503 was emitted for its match."
                       if route.placeholder_emitted else
                       "No route was emitted; overlapping routes were refused with it.")
            reasons = "; ".join(route.refusals[:6])
            if len(route.refusals) > 6:
                reasons += f"; and {len(route.refusals) - 6} more"
            report.error("route-refused", route.ref, f"Not migrated: {reasons}. {outcome}",
                         "Recreate this route manually in Ferrum after reviewing the reasons.")


# What each source's projected read timeout meant there (only values the translators actually copy).
_SOURCE_READ_TIMEOUT = {
    "nginx": "proxy_read_timeout/grpc_read_timeout only bound the idle time between two successive reads from the "
             "upstream",
    "kong": "a service read_timeout only bounds the idle time between two successive reads from the upstream",
    "traefik": "forwardingTimeouts.responseHeaderTimeout only bounds the wait for response headers after the request "
               "has been written",
    "envoy": "the route timeout (15s when unset) bounds the complete upstream response; Ferrum's value is not a "
             "total deadline, so a response that keeps streaming can outlive it",
    "istio": "the VirtualService http timeout bounds the complete upstream response; Ferrum's value is not a total "
             "deadline, so a response that keeps streaming can outlive it",
}
_EDGE_READ_TIMEOUT = ("In Ferrum Edge v0.9.21, backend_read_timeout_ms is one budget covering the wait for response "
                      "headers, idle time between streamed response frames, and the total time to send a buffered "
                      "client request body to the backend.")


def _report_timeout_semantics(plan: Plan, routes: list[RouteSpec], report: Report) -> None:
    """Label projected backend timeouts as approximations: equal units do not mean equal semantics."""
    live = [r for r in routes if not r.skip and not r.refusals and r.termination is None and r.backend is not None]
    has_read = any(r.read_timeout_ms for r in live)
    has_other = any(r.connect_timeout_ms or r.write_timeout_ms for r in live)
    if not (has_read or has_other):
        return
    parts: list[str] = []
    if has_read:
        source = _SOURCE_READ_TIMEOUT.get(plan.platform, "the source's read timeout has its own semantics")
        parts.append(f"Source read timeouts were copied into backend_read_timeout_ms, but {source}. "
                     f"{_EDGE_READ_TIMEOUT}")
    if has_other:
        parts.append("Source connect and write timeouts were copied by name into backend_connect_timeout_ms and "
                     "backend_write_timeout_ms; their exact timing points in Ferrum were not runtime-verified.")
    parts.append("The numbers carry over, but the timing behavior is only an approximation: long pauses in "
                 "streamed responses, slow uploads or long-running responses can time out differently than in the "
                 "source.")
    report.warning("timeout-approximate", "backend timeouts", " ".join(parts),
                   "Review backend_*_timeout_ms on routes with streaming, long-polling or large uploads.")
