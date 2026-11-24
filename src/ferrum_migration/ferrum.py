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

import copy
import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import matching, util
from .model import BackendRef, Plan, PluginSpec, RouteSpec, TlsSpec, UpstreamSpec
from .redact import safe_label
from .report import Report

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
    _poison(routes)
    _poison_case_variants(plan, routes)
    _resolve_frontend_client_ca(plan, routes, report, mode)
    candidates = _build_candidates(routes)
    candidates = _resolve_conflicts(candidates, report)
    _add_scope_closures(plan, candidates, report)
    _add_trailing_slash_placeholders(candidates, report)
    _add_divergence_guards(plan, candidates, report)
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
        for host in route.hosts:
            value = util.normalize_host(host)
            if value is None:
                route.refuse(f"host {safe_label(host)} is not representable in Ferrum")
                route.hosts = None
                route.extra_conditions = True
                break
            if value not in normalized:
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
        if problem:
            route.refuse(f"path is not representable ({problem})")
            route.path_ok = False
            route.extra_conditions = True
        else:
            route.path = path
    elif route.kind == "regex":
        problem = util.regex_problem(route.path)
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
        if not remaining or all("https" in _effective_protocols(route) for route in remaining):
            mode = "both"  # nothing live, or every live route was served on both main listeners
        else:
            mode = "http"
            plaintext_only = sum(1 for route in remaining if "https" not in _effective_protocols(route))
            dual = len(remaining) - plaintext_only
            if _source_https_activity(plan, present):
                report.error("frontend-https-disabled", "frontend listeners",
                             f"{plaintext_only} migrated route(s) were served over plaintext only in the source. Ferrum "
                             "serves every route on each listener it opens, whatever its host names, so with HTTPS "
                             "open they would also answer HTTPS requests the source never sent to them. The profile "
                             "therefore disables Ferrum's HTTPS listener (FERRUM_PROXY_HTTPS_PORT=0) and configures no "
                             f"frontend TLS. {dual} migrated route(s) the source also served over HTTPS are served "
                             "over plaintext only, and HTTPS-only routes were refused (fail closed).",
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


def _poison(routes: list[RouteSpec]) -> None:
    """Refuse routes that could receive traffic the source sent to an unrepresentable route.

    When the unrepresentable route's envelope (hosts + path) is itself
    representable, a placeholder is emitted for it, and Ferrum sends every
    request in that envelope to the placeholder unless the other route is
    more specific. Only such more-specific (or ambiguous) routes are refused.
    """
    unrepresentable = [r for r in routes if not r.skip and r.refusals and r.extra_conditions]
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
                if bad.kind == other.kind and bad.path == other.path and bad.listen_port == other.listen_port:
                    continue  # identical slot: conflict resolution merges them into one placeholder
            other.refuse(f"its match overlaps {bad.ref}, whose match conditions Ferrum cannot express")


def _poison_case_variants(plan: Plan, routes: list[RouteSpec]) -> None:
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
    scopes = [set(_scope_hosts(scope)) for scope in plan.host_scopes if scope.listen_port is None]
    sources = [route for route in routes if not route.skip and route.case_insensitive]
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

    for i in range(len(unique)):
        for j in range(i + 1, len(unique)):
            if _hosts_conflict_in_ferrum(unique[i], unique[j], host_only):
                parent[find(i)] = find(j)
    comps: dict[int, list[str]] = {}
    for idx, host in enumerate(unique):
        comps.setdefault(find(idx), []).append(host)
    ordered = sorted(comps.values(), key=len, reverse=True)
    if any(len(comp) > limit for comp in ordered):
        return None
    chunks: list[list[str]] = []
    for comp in ordered:
        placed = False
        for chunk in chunks:
            if len(chunk) + len(comp) <= limit:
                chunk.extend(comp)
                placed = True
                break
        if not placed:
            chunks.append(list(comp))
    return chunks


def _resolve_conflicts(candidates: list[_Cand], report: Report) -> list[_Cand]:
    groups: dict[tuple[int | None, str | None], list[_Cand]] = {}
    for cand in candidates:
        groups.setdefault((cand.listen_port, cand.listen_path), []).append(cand)
    replacement: dict[int, list[_Cand]] = {}
    for (port, path), members in list(groups.items()):
        if len(members) < 2:
            continue
        collapsed_group = False
        for component in _components(members):
            if len(component) < 2:
                continue
            refs = [m.route.ref for m in component]
            for member in component:
                others = ", ".join(safe_label(ref) for ref in refs if ref != member.route.ref)[:400]
                member.route.refuse(f"Ferrum requires one route per host/path/port and it conflicts with {others}")
                member.route.placeholder_emitted = True
            hosts: list[str] = []
            if not any(not m.hosts for m in component):
                for member in component:
                    for host in member.hosts:
                        if host not in hosts:
                            hosts.append(host)
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
                    refused_outrank = 0
                    for other in candidates:
                        if other in members or other.placeholder:
                            continue
                        if not matching.ports_compatible(other.listen_port, port):
                            continue
                        if not other.hosts or not matching.hosts_overlap(other.hosts, hosts):
                            continue
                        if matching.route_overlaps(first.route, other.route):
                            _fail_close(other, "overlaps a >100-host path conflict that collapsed to a catch-all "
                                               "placeholder; its higher host tier would outrank the catch-all")
                            refused_outrank += 1
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


def _components(members: list[_Cand]) -> list[list[_Cand]]:
    parent = list(range(len(members)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    for i in range(len(members)):
        for j in range(i + 1, len(members)):
            if matching.hosts_overlap(members[i].hosts, members[j].hosts):
                parent[find(i)] = find(j)
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
    scopes = [(scope, _scope_hosts(scope)) for scope in plan.host_scopes]
    leaky: list[tuple[str, int | None, str, str]] = []
    for outer, outer_hosts in scopes:
        for inner, inner_hosts in scopes:
            # Scopes with the same ref come from one source scope (an Istio VirtualService bound through a plaintext
            # and an HTTPS server) and carry the same route set, so nesting between them changes nothing.
            if outer is inner or outer.ref == inner.ref \
                    or not matching.ports_compatible(outer.listen_port, inner.listen_port):
                continue
            for pattern in outer_hosts:
                if not pattern.startswith("*.") or pattern in inner_hosts:
                    continue
                if any(other.startswith("*.") and other != pattern and matching.host_cover(pattern, other)
                       for other in inner_hosts):
                    leaky.append((pattern, outer.listen_port, outer.ref, inner.ref))
    if not leaky:
        return
    reported: set[str] = set()
    for cand in candidates:
        if cand.placeholder:
            continue
        for pattern, port, outer_ref, inner_ref in leaky:
            if pattern in cand.hosts and matching.ports_compatible(cand.listen_port, port):
                _fail_close(cand, f"its wildcard host {pattern} covers the narrower wildcard scope {inner_ref}; "
                                  "Ferrum's wildcard tier would let this route answer that scope's hosts")
                break
    for pattern, _port, outer_ref, inner_ref in leaky:
        if outer_ref in reported:
            continue
        reported.add(outer_ref)
        report.error("nested-wildcard-scope", outer_ref,
                     f"The wildcard host {pattern} covers the narrower wildcard host scope {inner_ref}. The source "
                     "sends those hosts only to the narrower scope, but Ferrum compares the path routes of every "
                     "matching wildcard pattern, so this scope's routes could answer them. Its routes were refused "
                     "(fail closed).",
                     "Serve the nested wildcard scopes from separate Ferrum frontends, or replace the broader "
                     "wildcard with explicit host names, then convert again.")


def _add_regex_closure(scope, hosts: list[str], candidates: list[_Cand], report: Report) -> bool:
    """Close a scope whose host-only closure would overlap another host-only route with a catch-any regex 404.

    Within a host tier Ferrum tries exact, prefix and regex routes (regex in config order) before host-only
    routes. Appended last, ``~/.*`` answers 404 for every path the scope's own exact/prefix/regex routes do not
    match, and it is not a host-only route, so it does not collide with the overlapping host-only closure. If the
    regex order assumption were wrong it could only shadow other routes with a 404 (fail closed).
    """
    chunks = _chunk_hosts_no_prune(hosts, host_only=False)
    if chunks is None:
        return False
    for cand in candidates:
        if cand.listen_port == scope.listen_port and cand.listen_path == REGEX_CLOSURE_PATH \
                and matching.hosts_overlap(cand.hosts, hosts):
            return False
    for index, chunk in enumerate(chunks):
        suffix = f"-default-{index + 1}" if len(chunks) > 1 else "-default"
        synthetic = RouteSpec(ref=scope.ref, name=f"{scope.ref}{suffix}", hosts=chunk, kind="regex",
                              path=REGEX_CLOSURE_PATH[1:])
        candidates.append(_Cand(synthetic, True, chunk, REGEX_CLOSURE_PATH, scope.listen_port,
                                termination=NOT_FOUND_TERMINATION, kind_label="scope-default"))
    report.info("scope-closure-regex", scope.ref,
                "A host-only 404 route for this scope would overlap another host-only route, so a regex route "
                "matching every path (answering 404, tried after the scope's own routes) closes it instead.")
    return True


def _refuse_fallthrough_targets(scope, hosts: list[str], candidates: list[_Cand]) -> int:
    """Refuse emitted routes that would receive an unclosed scope's unmatched requests from outside its names."""
    count = 0
    for cand in candidates:
        if cand.placeholder or not matching.ports_compatible(cand.listen_port, scope.listen_port):
            continue
        if cand.hosts and not any(pattern not in hosts and matching.host_cover(pattern, host)
                                  for pattern in cand.hosts for host in hosts):
            continue
        _fail_close(cand, f"unmatched requests for the hosts of {scope.ref} would fall through to it in Ferrum, "
                          "which the source never did, and that scope could not be closed")
        count += 1
    return count


def _add_scope_closures(plan: Plan, candidates: list[_Cand], report: Report) -> None:
    _refuse_nested_wildcard_scopes(plan, candidates, report)
    scopes = sorted(plan.host_scopes, key=lambda s: matching.host_tier(s.hosts))
    host_only: dict[int | None, list[_Cand]] = {}
    root_hosts: dict[int | None, set[str]] = {}
    for cand in candidates:
        if cand.listen_path is None:
            host_only.setdefault(cand.listen_port, []).append(cand)
        elif cand.listen_path == "/":
            root_hosts.setdefault(cand.listen_port, set()).update(cand.hosts)
    for scope in scopes:
        hosts = list(dict.fromkeys(h for h in (util.normalize_host(x) for x in scope.hosts) if h))
        if not hosts:
            continue
        # A prefix route for "/" on exactly these host names already catches every unmatched path in their tier.
        if all(host in root_hosts.get(scope.listen_port, set()) for host in hosts):
            continue
        overlapping = [c for c in host_only.get(scope.listen_port, []) if matching.hosts_overlap(c.hosts, hosts)]
        # Only a closure for the very same host names closes this scope. A covering wildcard closure does not:
        # Ferrum tries every path route of every matching wildcard pattern (and of the exact tier) before any
        # wildcard host-only route, so another scope's routes would still receive these hosts' unmatched paths.
        if overlapping and all(c.kind_label == "scope-default" for c in overlapping) and \
                all(any(host in c.hosts for c in overlapping) for host in hosts):
            continue
        chunks = None if overlapping else _chunk_hosts_no_prune(hosts, host_only=True)
        if overlapping or chunks is None:
            if _add_regex_closure(scope, hosts, candidates, report):
                continue
            refused = _refuse_fallthrough_targets(scope, hosts, candidates)
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
            host_only.setdefault(scope.listen_port, []).append(closure)
        report.info("scope-closure", scope.ref,
                    "Added a host-only route answering 404 for paths this scope does not route, because the "
                    "source never falls through to other hosts' routes but Ferrum does.")


def _add_trailing_slash_placeholders(candidates: list[_Cand], report: Report) -> None:
    slots: dict[tuple[int | None, str | None], list[_Cand]] = {}
    for cand in candidates:
        slots.setdefault((cand.listen_port, cand.listen_path), []).append(cand)
    for cand in list(candidates):
        route = cand.route
        if cand.placeholder or route.kind != "prefix" or not route.trailing_slash \
                or route.prefix_semantics != "string":
            continue
        exact = "=" + (route.path or "/")
        if any(matching.hosts_overlap(o.hosts, cand.hosts) for o in slots.get((cand.listen_port, exact), [])):
            continue
        synthetic = RouteSpec(ref=route.ref, name=f"{route.name}-bare", hosts=list(cand.hosts), kind="exact",
                              path=route.path)
        guard = _Cand(synthetic, True, list(cand.hosts), exact, cand.listen_port,
                      termination=NOT_FOUND_TERMINATION, kind_label="exact-guard")
        candidates.append(guard)
        slots.setdefault((cand.listen_port, exact), []).append(guard)
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
                # If this route is strictly in a more specific host tier than `other` on every overlapping host,
                # emit a host-scoped regex 404 guard in this route's own tier so siblings like /apix are blocked on
                # these hosts without returning 404 for `other`'s unrelated hosts.
                guard_pattern = re.escape(route.path or "/") + ".*"
                guard_listen = "~" + guard_pattern
                can_scope_regex = (
                    bool(cand.hosts)
                    and len(cand.hosts) <= util.MAX_HOSTS_PER_PROXY
                    and other.listen_port == cand.listen_port
                    and not regex_other
                    and bool(pairs) and all(tb > ta for ta, tb in pairs)
                    and util.regex_problem(guard_pattern) is None
                    and not any(
                        c.listen_port == cand.listen_port and c.listen_path == guard_listen
                        and matching.hosts_overlap(c.hosts, cand.hosts)
                        for c in candidates
                    )
                    and not any(
                        not c.placeholder and matching.hosts_overlap(c.hosts, cand.hosts)
                        for c in regex_by_port.get(cand.listen_port, [])
                    )
                )
                if can_scope_regex:
                    guarded = True
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
                                    f"{route.path}x cannot reach {other_route.ref} without affecting its other hosts.")
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
        if spec.hash_on:
            entry["hash_on"] = spec.hash_on
        if spec.hash_on_cookie_config:
            entry["hash_on_cookie_config"] = copy.deepcopy(spec.hash_on_cookie_config)
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
            entry: dict[str, Any] = {
                "id": cid,
                "username": username,
                "labels": self.labels(consumer.ref),
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
