"""Traefik OSS dynamic configuration (file provider, YAML/TOML/JSON) ``http`` section to the IR.

Router rules are parsed (v2 and v3 syntax) and expanded to disjunctive normal
form; ``Host``/``Path``/``PathPrefix``/``Method`` are representable, anything
else (headers, queries, client IPs, regex matchers, negation) refuses the router
and poisons overlapping routes. Router priorities are compared against Ferrum's
specificity order; shadowed routes are dropped and contradictory pairs refused.

The file provider input is dynamic configuration only. Controls outside it can change how the source served a
router: the static entryPoints it is attached to (named in ``entryPoints``, or Traefik's default entryPoints) can add
TLS, client certificate options, prepended middlewares, HTTP redirections, forwarded-header trust and bind
restrictions; TLS options defined elsewhere (a ``default`` set by another provider applies to TLS routers that name
none) and routers of other providers (competing for the same hosts and paths, or mapping them to other TLS options)
are not in the input either. A missing router ``tls`` block therefore does not prove plaintext, and a ``tls`` block
does not prove that nothing else applied. Without the operator's explicit statement
(``--assert-traefik-input-includes-effective-controls``: after verification, the input includes every effective
routing, TLS and access control within the converted scope, or no additional control applies; it is the operator's
scoped representation, never verified here) every route that would forward traffic is refused. With it, the routers
are translated from the dynamic input alone, and everything the input does state (router ``tls`` and TLS options,
middlewares, explicit ``entryPoints`` lists) still applies or refuses; unresolved references and controls Ferrum
cannot reproduce (such as enabled ``sniStrict``) refuse their routes whatever the operator states.

HTTPS is translated only under one global handshake policy: the ``default`` TLS options (or Traefik's built-in
default) used by every TLS router. Traefik chooses TLS options per handshake from the SNI, for every path of the
frontend at once, and Ferrum's HTTPS listener applies one policy to every connection, so per-route SNI selection is
not reconstructed: any other TLS options in the input refuse every HTTPS route (see ``_handshake_scope``). Traefik
stores the special ``default`` options globally, without a provider qualifier, so only an unset or empty router
reference, or exactly ``default``, uses them; a qualified reference such as ``default@file`` is a different name.

Typed fields must be spelled canonically. Traefik's file provider decodes into typed structs and matches field names
case-insensitively, so ``TLS`` or ``clientauth`` select the same controls as ``tls`` and ``clientAuth``, while this
translator reads the canonical spelling only. Any typed field at the structural boundaries listed in
``_TYPED_FIELDS`` that is spelled in another letter case, or given more than once in different letter case, rejects
the whole input before any route or profile is built (``_canonical_schema_gate``). Keys that name resources
(routers, services, middlewares, serversTransports, TLS options, certificate stores) are case-sensitive identifiers
in Traefik and are never checked or folded.

Router ``parentRefs`` (Traefik v3.6 multi-layer routing) is not translated. A router with parent references is a
child: Traefik runs it inside its parents' muxer, after the parents' middlewares, under the parents' entryPoint and
TLS constraints, so it is not an independent root route and must never be projected as one. Inherited routing is not
reconstructed. A router whose ``parentRefs`` is absent or exactly an empty list is an ordinary root; any other value
on any router of the input as written (a nonempty list, an explicit null, or any other shape) rejects the whole input
before any route or profile is built, whatever the operator states (``_parent_refs_preflight``).
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .. import matching, util
from ..errors import InputError
from ..model import BackendRef, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from ..safe_load import load_structured
from .common import (SourceContext, check_route_budget, compression_config, cors_config, literal_value, mapping,
                     merge_weighted_targets, request_header_rule, request_mirror_config, response_header_rule, seq,
                     str_list)

PLATFORM = "traefik"
REPRESENTABLE_MATCHERS = {"Host", "HostHeader", "Path", "PathPrefix", "Method"}
# Traefik TLS options name applied to TLS routers that do not reference one.
DEFAULT_TLS_OPTIONS = "default"
# clientAuthType values that verify client certificates against caFiles (Traefik: required, or only if given).
VERIFYING_CLIENT_AUTH = ("RequireAndVerifyClientCert", "VerifyClientCertIfGiven")
# clientAuthType values that ask for client certificates without verifying them against a CA.
UNVERIFIED_CLIENT_AUTH = ("RequestClientCert", "RequireAnyClientCert")
#: The one CLI opt-in (Traefik only). With it the operator states, after verifying the Traefik deployment, that the
#: input includes every effective routing, TLS and access control within the converted scope (static entryPoints,
#: this dynamic configuration and every other provider), or that no additional control applies. It is the operator's
#: scoped representation; the converter cannot check it and never treats it as a validation.
CONTROLS_ASSERTION_FLAG = "--assert-traefik-input-includes-effective-controls"
#: What the operator states with that flag (shared by the report and refusal texts).
CONTROLS_ASSERTION_STATEMENT = (
    "the input includes every effective routing, TLS and access control that applies within the converted scope, "
    "whether it is set in the static configuration, in this dynamic configuration or by another provider, or no "
    "additional control applies")
#: The operator checklist behind that statement (action of the default refusal; mirrored in the docs).
CONTROLS_CHECKLIST = (
    "Verify for every router in the input: (1) static entryPoints: the entryPoints it uses (named in entryPoints, or "
    "the default entryPoints of routers that name none) add no http.tls, http.middlewares, http.redirections, "
    "forwardedHeaders, proxyProtocol or address restriction, and routers naming no entryPoints share the entryPoint "
    "the other routers of their protocol use; (2) omitted TLS options: no TLS options from another provider or file "
    "apply, in particular no 'default' TLS options defined outside the input (Traefik applies them to TLS routers "
    "that name no options and to connections whose SNI no router claims); (3) SNI option conflicts: no router "
    "outside the input maps the same host names to other TLS options (Traefik then falls back to the default "
    "options); (4) competing routers: no router outside the input (another provider or file) matches the same hosts "
    "and paths on those entryPoints; (5) no middleware, service or serversTransport outside the input applies.")
#: Refusal reason for routes that would forward traffic without that statement.
CONTROLS_UNVERIFIED_REASON = (
    "controls outside the input (the static entryPoints this router is attached to, TLS options such as a 'default' "
    "set by another provider, competing routers of other providers) may add TLS, client certificate options, SNI "
    "checks, middlewares, redirections, forwarded-header trust, bind restrictions or other routing, so how the "
    f"source served it is unknown (see traefik-controls-unverified; {CONTROLS_ASSERTION_FLAG} only after verifying "
    "that the input includes every effective control)")

#: Canonical typed field names (the json/yaml/toml tags of Traefik v3.6's dynamic configuration structs) at the
#: structural boundaries that select routing, TLS and access controls. Traefik's file provider (paerser) matches
#: field names case-insensitively; this translator reads the canonical spelling only, so any other spelling is
#: refused (see ``_canonical_schema_gate``). Each field maps to None (not descended), the name of a nested typed
#: struct, ("list", struct) or ("map", struct). The keys of a "map" are resource names (routers, services,
#: middlewares, serversTransports, TLS options, certificate stores): case-sensitive identifiers that are never
#: checked or folded; only the typed fields of each entry are.
_TYPED_FIELDS: dict[str, dict[str, Any]] = {
    "configuration": {"http": "http", "tcp": None, "udp": None, "tls": "tls"},
    "http": {"routers": ("map", "router"), "services": ("map", "service"), "middlewares": ("map", "middleware"),
             "models": None, "serversTransports": ("map", "serversTransport")},
    "router": {"entryPoints": None, "middlewares": None, "service": None, "rule": None, "ruleSyntax": None,
               "priority": None, "tls": "routerTls", "observability": None, "parentRefs": None},
    "routerTls": {"options": None, "certResolver": None, "domains": ("list", "domain")},
    "domain": {"main": None, "sans": None},
    "tls": {"certificates": ("list", "certAndStores"), "options": ("map", "tlsOptions"),
            "stores": ("map", "tlsStore")},
    "certAndStores": {"certFile": None, "keyFile": None, "stores": None},
    "tlsStore": {"defaultCertificate": "certificate", "defaultGeneratedCert": "generatedCert"},
    "certificate": {"certFile": None, "keyFile": None},
    "generatedCert": {"resolver": None, "domain": "domain"},
    "tlsOptions": {"minVersion": None, "maxVersion": None, "cipherSuites": None, "curvePreferences": None,
                   "clientAuth": "clientAuth", "sniStrict": None, "alpnProtocols": None,
                   "disableSessionTickets": None, "preferServerCipherSuites": None},
    "clientAuth": {"caFiles": None, "clientAuthType": None},
    "service": {"loadBalancer": "loadBalancer", "weighted": "weighted", "mirroring": "mirroring", "failover": None,
                "highestRandomWeight": None},
    "loadBalancer": {"sticky": "sticky", "servers": ("list", "server"), "strategy": None, "healthCheck": "healthCheck",
                     "passiveHealthCheck": None, "passHostHeader": None, "responseForwarding": None,
                     "serversTransport": None},
    "server": {"url": None, "weight": None, "preservePath": None},
    "sticky": {"cookie": "cookie"},
    "cookie": {"name": None, "secure": None, "httpOnly": None, "sameSite": None, "maxAge": None, "path": None,
               "domain": None},
    "healthCheck": {"scheme": None, "mode": None, "path": None, "method": None, "status": None, "port": None,
                    "interval": None, "unhealthyInterval": None, "timeout": None, "hostname": None,
                    "followRedirects": None, "headers": None},
    "weighted": {"services": ("list", "weightedService"), "sticky": "sticky", "healthCheck": None},
    "weightedService": {"name": None, "weight": None},
    "mirroring": {"service": None, "mirrorBody": None, "maxBodySize": None, "mirrors": ("list", "mirror"),
                  "healthCheck": None},
    "mirror": {"name": None, "percent": None},
    "serversTransport": {"serverName": None, "insecureSkipVerify": None, "rootCAs": None,
                         "certificates": ("list", "certificate"), "maxIdleConnsPerHost": None,
                         "forwardingTimeouts": "forwardingTimeouts", "disableHTTP2": None, "peerCertURI": None,
                         "spiffe": None},
    "forwardingTimeouts": {"dialTimeout": None, "responseHeaderTimeout": None, "idleConnTimeout": None,
                           "readIdleTimeout": None, "pingTimeout": None},
    # The middleware envelope: its one key names the middleware type. Types this translator reads get their config
    # checked; the others are refused or omitted by type and their configs are not read.
    "middleware": {"addPrefix": "addPrefix", "stripPrefix": "stripPrefix", "stripPrefixRegex": None,
                   "replacePath": None, "replacePathRegex": None, "chain": "chain", "ipWhiteList": "ipAllowList",
                   "ipAllowList": "ipAllowList", "headers": "headers", "errors": None, "rateLimit": "rateLimit",
                   "redirectRegex": None, "redirectScheme": "redirectScheme", "basicAuth": "basicAuth",
                   "digestAuth": None, "forwardAuth": None, "inFlightReq": None, "buffering": "buffering",
                   "circuitBreaker": None, "compress": "compress", "passTLSClientCert": None, "retry": "retry",
                   "contentType": None, "grpcWeb": "grpcWeb", "plugin": None},
    "compress": {"excludedContentTypes": None, "includedContentTypes": None, "minResponseBodyBytes": None,
                 "defaultEncoding": None, "encodings": None},
    "grpcWeb": {"allowOrigins": None},
    "addPrefix": {"prefix": None},
    "stripPrefix": {"prefixes": None, "forceSlash": None},
    "chain": {"middlewares": None},
    "ipAllowList": {"sourceRange": None, "ipStrategy": "ipStrategy", "rejectStatusCode": None},
    "ipStrategy": {"depth": None, "excludedIPs": None, "ipv6Subnet": None},
    "headers": {"customRequestHeaders": None, "customResponseHeaders": None, "accessControlAllowCredentials": None,
                "accessControlAllowHeaders": None, "accessControlAllowMethods": None,
                "accessControlAllowOriginList": None, "accessControlAllowOriginListRegex": None,
                "accessControlExposeHeaders": None, "accessControlMaxAge": None, "addVaryHeader": None,
                "allowedHosts": None, "hostsProxyHeaders": None, "sslProxyHeaders": None, "stsSeconds": None,
                "stsIncludeSubdomains": None, "stsPreload": None, "forceSTSHeader": None, "frameDeny": None,
                "customFrameOptionsValue": None, "contentTypeNosniff": None, "browserXssFilter": None,
                "customBrowserXSSValue": None, "contentSecurityPolicy": None,
                "contentSecurityPolicyReportOnly": None, "publicKey": None, "referrerPolicy": None,
                "permissionsPolicy": None, "isDevelopment": None, "featurePolicy": None, "sslRedirect": None,
                "sslTemporaryRedirect": None, "sslHost": None, "sslForceHost": None},
    "basicAuth": {"users": None, "usersFile": None, "realm": None, "removeHeader": None, "headerField": None},
    "rateLimit": {"average": None, "period": None, "burst": None, "sourceCriterion": "sourceCriterion",
                  "redis": None},
    "sourceCriterion": {"ipStrategy": "ipStrategy", "requestHeaderName": None, "requestHost": None},
    "buffering": {"maxRequestBodyBytes": None, "memRequestBodyBytes": None, "maxResponseBodyBytes": None,
                  "memResponseBodyBytes": None, "retryExpression": None},
    "redirectScheme": {"scheme": None, "port": None, "permanent": None},
    "retry": {"attempts": None, "initialInterval": None},
}
# Case-folded field name -> canonical field name, per typed struct. str.casefold() folds at least every pair Go's
# strings.EqualFold treats as equal for these ASCII names (including the Kelvin sign and the long s), so every
# spelling Traefik would accept is caught; anything it folds beyond that is refused too (stricter).
_TYPED_FOLDS: dict[str, dict[str, str]] = {
    struct: {name.casefold(): name for name in fields} for struct, fields in _TYPED_FIELDS.items()}


def typed_field_problems(value: Any, struct: str = "configuration", path: str = "") -> list[str]:
    """Value-free paths of typed fields spelled other than canonically, or given in several letter cases.

    Only the typed fields of ``struct`` and its nested typed structs (``_TYPED_FIELDS``) are checked, and only
    beneath canonically spelled parents (a non-canonical parent already rejects the input). Map keys that name
    resources are case-sensitive identifiers and are never compared or folded. Values that are not mappings are left
    to the translator, which refuses them where it reads them. Paths use canonical names, ``<name>`` for resource
    names and ``[]`` for list items, so they never echo input.
    """
    problems: list[str] = []
    if not isinstance(value, dict):
        return problems
    fields, folds = _TYPED_FIELDS[struct], _TYPED_FOLDS[struct]
    spellings: dict[str, list[Any]] = {}
    for key in value:
        canonical = folds.get(key.casefold()) if isinstance(key, str) else None
        if canonical is not None:
            spellings.setdefault(canonical, []).append(key)
    for canonical, keys in spellings.items():
        where = f"{path}.{canonical}" if path else canonical
        if keys != [canonical]:
            problems.append(where)
            continue
        child = fields[canonical]
        item = value[canonical]
        if child is None:
            continue
        if isinstance(child, str):
            problems.extend(typed_field_problems(item, child, where))
        elif child[0] == "map":
            for entry in mapping(item).values():  # keys are resource names: never folded
                problems.extend(typed_field_problems(entry, child[1], f"{where}.<name>"))
        else:
            for entry in seq(item):
                problems.extend(typed_field_problems(entry, child[1], f"{where}[]"))
    return problems


#: Canonical name of the router field that makes a router a child of other routers (Traefik v3.6).
PARENT_REFS_FIELD = "parentRefs"


def parent_refs_violations(root: Any) -> int:
    """Number of routers in the original ``http.routers`` whose ``parentRefs`` is not absent or exactly ``[]``.

    Read-only and value-free: only a count is returned. Every router mapping of the input as written is checked,
    including routers that later translation would skip (no rule, unparseable or unsatisfiable rule, shadowed). A
    nonempty list makes the router a child that Traefik runs inside its parents (after their middlewares, under their
    entryPoint and TLS constraints); an explicit null or any other shape leaves its role unknown. Both count, so the
    caller can refuse. The key is matched case-insensitively here as well, although the canonical schema gate already
    rejects other spellings before this check runs. Router entries that are not mappings carry no readable field and
    are refused by the translator itself (``traefik-router-invalid``).
    """
    http = root.get("http") if isinstance(root, dict) else None
    routers = http.get("routers") if isinstance(http, dict) else None
    if not isinstance(routers, dict):
        return 0
    folded = PARENT_REFS_FIELD.casefold()
    count = 0
    for router in routers.values():
        if not isinstance(router, dict):
            continue
        for key, value in router.items():
            if isinstance(key, str) and key.casefold() == folded and not (isinstance(value, list) and not value):
                count += 1
                break
    return count


class RuleError(Exception):
    """Unparseable router rule (message is value-free)."""


_RULE_TOKEN = re.compile(r"\s*(?:(&&|\|\||!|\(|\)|,)|(`[^`]*`|\"(?:[^\"\\]|\\.)*\"|'[^']*')|([A-Za-z][A-Za-z0-9]*))")


def tokenize_rule(rule: str) -> list[tuple[str, str]]:
    tokens: list[tuple[str, str]] = []
    position = 0
    while position < len(rule):
        if not rule[position:].strip():
            break
        match = _RULE_TOKEN.match(rule, position)
        if not match:
            raise RuleError(f"unexpected character at offset {position}")
        if match.group(1):
            tokens.append(("op", match.group(1)))
        elif match.group(2):
            raw = match.group(2)
            value = raw[1:-1]
            if raw.startswith('"'):
                value = re.sub(r"\\(.)", r"\1", value)
            tokens.append(("str", value))
        else:
            tokens.append(("ident", match.group(3)))
        position = match.end()
    return tokens


class _RuleParser:
    def __init__(self, tokens: list[tuple[str, str]]) -> None:
        self.tokens = tokens
        self.index = 0
        self.depth = 0

    def peek(self) -> tuple[str | None, str | None]:
        return self.tokens[self.index] if self.index < len(self.tokens) else (None, None)

    def expect(self, kind: str, value: str | None = None) -> str:
        token = self.peek()
        if token[0] != kind or (value is not None and token[1] != value):
            raise RuleError("unexpected token in rule")
        self.index += 1
        return token[1] or ""

    def parse(self) -> tuple:
        node = self.parse_or()
        if self.index != len(self.tokens):
            raise RuleError("trailing tokens in rule")
        return node

    def parse_or(self) -> tuple:
        nodes = [self.parse_and()]
        while self.peek() == ("op", "||"):
            self.index += 1
            nodes.append(self.parse_and())
        return nodes[0] if len(nodes) == 1 else ("or", nodes)

    def parse_and(self) -> tuple:
        nodes = [self.parse_unary()]
        while self.peek() == ("op", "&&"):
            self.index += 1
            nodes.append(self.parse_unary())
        return nodes[0] if len(nodes) == 1 else ("and", nodes)

    def parse_unary(self) -> tuple:
        self.depth += 1
        if self.depth > 32:
            raise RuleError("rule nesting too deep")
        kind, value = self.peek()
        if (kind, value) == ("op", "!"):
            self.index += 1
            node: tuple = ("not", self.parse_unary())
        elif (kind, value) == ("op", "("):
            self.index += 1
            node = self.parse_or()
            self.expect("op", ")")
        elif kind == "ident":
            self.index += 1
            self.expect("op", "(")
            args: list[str] = []
            if self.peek() != ("op", ")"):
                args.append(self.expect("str"))
                while self.peek() == ("op", ","):
                    self.index += 1
                    args.append(self.expect("str"))
            self.expect("op", ")")
            node = ("call", value, args)
        else:
            raise RuleError("unexpected token in rule")
        self.depth -= 1
        return node


def rule_to_dnf(rule: str, cap: int) -> list[list[tuple]]:
    node = _RuleParser(tokenize_rule(rule)).parse()

    def dnf(item: tuple) -> list[list[tuple]]:
        kind = item[0]
        if kind == "call":
            name, args = item[1], item[2]
            if name in REPRESENTABLE_MATCHERS and len(args) > 1:
                return [[("call", name, [arg])] for arg in args]
            return [[item]]
        if kind == "not":
            return [[("unsupported", "negation")]]
        if kind == "or":
            result: list[list[tuple]] = []
            for child in item[1]:
                result.extend(dnf(child))
                if len(result) > cap:
                    raise RuleError("rule expands to too many alternatives")
            return result
        result = [[]]
        for child in item[1]:
            part = dnf(child)
            result = [left + right for left in result for right in part]
            if len(result) > cap:
                raise RuleError("rule expands to too many alternatives")
        return result

    return dnf(node)


def evaluate_term(term: list[tuple]) -> dict | None:
    """Collapse one conjunction; None if it can never match."""
    hosts: set[str] | None = None
    kind = path = None
    methods: set[str] | None = None
    extra: list[str] = []
    for atom in term:
        if atom[0] == "unsupported":
            extra.append(atom[1])
            continue
        name, args = atom[1], atom[2]
        if name not in REPRESENTABLE_MATCHERS or len(args) != 1:
            extra.append(f"{name} matcher")
            continue
        value = args[0]
        if name in ("Host", "HostHeader"):
            host = value.lower()
            if hosts is None:
                hosts = {host}
            elif host not in hosts:
                return None
        elif name in ("Path", "PathPrefix"):
            if "{" in value:
                extra.append("path template variables")
                continue
            this = ("exact" if name == "Path" else "prefix", value)
            if kind is None:
                kind, path = this
            elif (kind, path) != this:
                extra.append("several path matchers in one conjunction")
        else:
            method = value.upper()
            if methods is None:
                methods = {method}
            elif method not in methods:
                return None
    return {"hosts": hosts, "kind": kind, "path": path, "methods": methods, "extra": extra}


@dataclass
class _Acc:
    plugins: list[PluginSpec] = field(default_factory=list)
    refusals: list[str] = field(default_factory=list)
    strip_prefixes: list[list[str]] = field(default_factory=list)
    add_prefixes: list[str] = field(default_factory=list)
    path_ops: list[str] = field(default_factory=list)
    https_redirect: bool = False
    retry: dict | None = None
    allowed_hosts: list[str] | None = None
    resp_size_limited: bool = False


class _Traefik:
    def __init__(self, root: dict, ctx: SourceContext) -> None:
        self.root = root
        self.ctx = ctx
        self.report = ctx.report
        self.plan = Plan(platform=PLATFORM)
        http = mapping(root.get("http"))
        self.routers = mapping(http.get("routers"))
        self.services = mapping(http.get("services"))
        self.middlewares = mapping(http.get("middlewares"))
        self.transports = mapping(http.get("serversTransports"))
        self.priority: dict[int, tuple[int, str]] = {}
        self.builtin_default_tls_used = False
        # Per route spec (by id): the sorted entryPoint names its router lists, or None when it lists none (Traefik
        # then attaches it to its default entryPoints, which only the static configuration defines).
        self.entrypoints_of: dict[int, tuple[str, ...] | None] = {}
        self.controls_asserted = ctx.traefik_controls_asserted

    def run(self) -> Plan:
        # Before anything else: no section, route or profile setting is built from an input whose typed fields
        # Traefik would read differently from this translator.
        self._canonical_schema_gate()
        # Then: no child router (parentRefs) is ever projected as an independent root route.
        self._parent_refs_preflight()
        for key in self.root:
            if key in ("tcp", "udp"):
                self.report.error("traefik-l4", f"traefik {key}", "TCP/UDP routers are not migrated (HTTP only).",
                                  "Configure Ferrum stream proxies manually.")
            elif key not in ("http", "tls"):
                self.report.warning("traefik-unknown-section", f"traefik {safe_label(key, 40)}",
                                    "Unknown top-level section ignored (static configuration is not read).")
        self._tls_section()
        check_route_budget(len(self.routers), self.ctx.limits)
        # Decided on every router of the input as written: before rule parsing, early exits (invalid, unparseable,
        # unsatisfiable or redirect routers) and shadowing, none of which changes which handshakes Traefik admitted.
        handshake_scope_problems = self._handshake_scope()
        for name, router in self.routers.items():
            self._router(str(name), router)
        self._https_handshake_policy(handshake_scope_problems)
        if self.builtin_default_tls_used:
            self.report.info("traefik-tls-default-options", "traefik tls options",
                             "The input defines no 'default' TLS options, so HTTPS routers that use the default were "
                             "translated with Traefik's built-in default (no client certificates, no sniStrict). That "
                             "rests on the operator's statement "
                             f"({CONTROLS_ASSERTION_FLAG}) that no other provider or file defines 'default' TLS "
                             "options; without it these routes are refused.",
                             "If another provider or file defines default TLS options, add them to the input and "
                             "convert again; the statement would otherwise be wrong.")
        self._precedence()
        self._outside_controls()
        check_route_budget(len(self.plan.routes), self.ctx.limits)
        return self.plan

    # ------------------------------------------------- canonical typed fields

    def _canonical_schema_gate(self) -> None:
        """Reject the whole input when a typed field is spelled other than canonically (fail closed, exit 3).

        Traefik's file provider decodes into typed structs and matches field names case-insensitively (paerser,
        ``strings.EqualFold``): ``TLS``, ``Options`` or ``clientauth`` select the same TLS, routing and access
        controls as ``tls``, ``options`` and ``clientAuth``. This translator reads the canonical spelling only, so a
        control under another spelling would be missed (an HTTPS router taken for plaintext, a dropped client
        certificate requirement or middleware). Rather than guessing which of several case-equivalent keys Traefik
        used, any such spelling, at any checked level (parent sections included), refuses the entire plan before
        any route or profile is built, whatever the operator states. Resource names are never folded.
        """
        problems = list(dict.fromkeys(typed_field_problems(self.root)))
        if not problems:
            return
        shown = ", ".join(problems[:6]) + (f" and {len(problems) - 6} more" if len(problems) > 6 else "")
        raise InputError(
            "Traefik typed field(s) spelled in another letter case than Traefik's canonical name, or given more than "
            f"once in different letter case: {shown}. Traefik matches these field names case-insensitively, so they "
            "can select routing, TLS or access controls that this converter reads only under the canonical spelling; "
            "nothing was converted (fail closed). Spell each field exactly as Traefik documents it (for example "
            "'tls', 'options', 'clientAuth', 'middlewares') and convert again. Names of routers, services, "
            "middlewares, serversTransports, TLS options and stores are case-sensitive and are not affected.")

    # ------------------------------------------------- multi-layer routing (parentRefs)

    def _parent_refs_preflight(self) -> None:
        """Reject the whole input when any router has ``parentRefs`` other than absent or ``[]`` (fail closed, exit 3).

        Traefik v3.6 runs a router that names parent routers inside the parents' muxer: after the parents'
        middlewares, and only for requests admitted by the parents' entryPoints and TLS settings. This translator
        does not reconstruct that inheritance, and projecting the child as an independent root route would drop
        the parents' controls (authentication or allow-list middlewares, TLS, entryPoint scope). The parents'
        controls are stated in the input itself, so the operator statement does not lift this. An explicit null
        or any other shape is refused too: the router's role cannot be read with certainty. Read-only: runs on the
        input as written, after the canonical schema gate and before any section, route, report entry or profile
        setting is built. The message carries the canonical field path and a count only, never input values or
        router names.
        """
        count = parent_refs_violations(self.root)
        if not count:
            return
        raise InputError(
            f"Traefik router field http.routers.<name>.{PARENT_REFS_FIELD} is set to something other than an empty "
            f"list on {count} router(s) (a nonempty list, an explicit null or another shape). A router with parent "
            "references runs inside its parent routers in Traefik, after their middlewares and under their "
            "entryPoint and TLS constraints, and this converter does not translate that inheritance, so it cannot "
            "be migrated as an independent route; nothing was converted (fail closed), whatever "
            f"{CONTROLS_ASSERTION_FLAG} states. Convert only routers without parent references (the field absent or "
            "an empty list) and configure the multi-layer routes in Ferrum by hand.")

    # ------------------------------------------------- controls outside the input

    def _outside_controls(self) -> None:
        """Account for controls the dynamic input does not contain (fail closed).

        Without the operator's statement nothing proves how the source served a router: its static entryPoints may
        add TLS (a router without ``tls`` is then served over HTTPS), client certificate options, prepended
        middlewares, redirections, forwarded-header trust or bind restrictions; a ``default`` TLS options set by
        another provider may apply to it; routers of other providers may compete for its hosts and paths or map
        them to other TLS options. An explicit router ``tls`` does not rule any of those out either. Every route
        that would forward traffic is refused (503 placeholder). Routes already refused stay placeholders, and
        redirect routers are never emitted, so nothing forwards.

        With the statement the routers keep the translation of the dynamic input. Explicit restrictions in the
        input still apply, including ``entryPoints`` lists: Ferrum serves every route of one protocol on one
        listener, so routers of that protocol whose lists leave out the entryPoint the others share are refused
        instead of being served where the source never served them. Refusals for unresolved or unreproducible
        controls (made earlier) are never lifted by the statement.
        """
        present = [spec for spec in self.plan.routes if not spec.skip]
        if not present:
            return
        if self.controls_asserted and any(str(key).lower() == "entrypoints" for key in self.root):
            # Static entryPoint definitions in the input are explicit source settings this translator does not read;
            # the operator's statement never overrides what the input itself states.
            forwarding = [spec for spec in present if not spec.refusals]
            for spec in forwarding:
                spec.refuse("the input itself defines static entryPoints, which are not translated, and the operator "
                            "statement does not override settings stated in the input")
            if forwarding:
                self.report.error(
                    "traefik-entrypoints-in-input", "traefik entryPoints",
                    f"The input contains a static entryPoints section, which this converter does not translate. "
                    f"{CONTROLS_ASSERTION_FLAG} cannot override settings the input states, so {len(forwarding)} "
                    "route(s) that would forward traffic were refused (fail closed).",
                    "Convert the dynamic configuration on its own, and state that it includes every effective "
                    "control only after verifying that those entryPoints add no TLS, client certificate options, "
                    "middlewares, redirections, forwarded-header trust or bind restrictions; otherwise configure the "
                    "equivalent controls in Ferrum by hand.")
            return
        if not self.controls_asserted:
            forwarding = [spec for spec in present if not spec.refusals]
            for spec in forwarding:
                spec.refuse(CONTROLS_UNVERIFIED_REASON)
            if forwarding:
                self.report.error(
                    "traefik-controls-unverified", "traefik input scope",
                    "The input is Traefik dynamic configuration only. Controls outside it can change how the source "
                    "served its routers: the static entryPoints they are attached to (named in entryPoints, or "
                    "Traefik's default entryPoints) can add TLS, client certificate options, prepended middlewares, "
                    "HTTP redirections, forwarded-header trust and bind restrictions; TLS options defined elsewhere "
                    "(a 'default' set by another provider applies to TLS routers that name none) and routers of other "
                    "providers (competing for the same hosts and paths, or mapping them to other TLS options) are not "
                    "in the input either. Neither a missing router tls block (plaintext) nor a present one proves how "
                    f"the source served a route. {len(forwarding)} route(s) that would forward traffic were refused "
                    "(fail closed); they answer 503.",
                    f"{CONTROLS_CHECKLIST} Only if every such control is in the input or none applies, convert again "
                    f"with {CONTROLS_ASSERTION_FLAG}. That is your scoped statement; the tool cannot verify it. "
                    "Otherwise add the missing dynamic configuration to the input, configure the equivalent controls "
                    "in Ferrum by hand, or keep the routes refused.")
            return
        self.report.warning(
            "traefik-controls-asserted", "traefik input scope",
            f"Translated on the operator's statement ({CONTROLS_ASSERTION_FLAG}) that {CONTROLS_ASSERTION_STATEMENT} "
            "(checked by the operator: static entryPoints, TLS options of other providers including 'default', SNI "
            "option conflicts and competing routers). It is the operator's representation for the converted scope; "
            "the tool did not and cannot verify it. Routers with a tls block are HTTPS-only, the rest "
            "plaintext-only, routers that name no entryPoints are taken to share the entryPoint the other routers of "
            "their protocol use, and every control the input states still applies or refuses its routes.",
            "Re-verify whenever the static configuration, another provider or this input changes; a wrong statement "
            "can expose routes on a protocol or without a control the source applied.")
        for tls in (False, True):
            kind = "HTTPS" if tls else "plaintext"
            group = [spec for spec in present if spec.requires_tls is tls and id(spec) in self.entrypoints_of]
            named = [self.entrypoints_of[id(spec)] for spec in group if self.entrypoints_of[id(spec)]]
            if not named:
                continue
            counts = Counter(name for names in named for name in names)
            main = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[0][0]
            outside = [spec for spec in group
                       if self.entrypoints_of[id(spec)] and main not in self.entrypoints_of[id(spec)]]
            for spec in outside:
                spec.refuse(f"the router's entryPoints leave out {safe_label(main, 48)}, which the other {kind} "
                            f"routers share; Ferrum serves every {kind} route on one listener, so this router would "
                            "answer on an entryPoint the source never served it on")
            if outside:
                self.report.error(
                    "traefik-entrypoint-scope", "traefik entryPoints",
                    f"{len(outside)} {kind} route(s) name entryPoints that do not include "
                    f"{safe_label(main, 48)}, the entryPoint the other {kind} routers share. Ferrum serves all "
                    f"{kind} routes on one listener and cannot keep separate entryPoints apart, so they were refused "
                    "(fail closed).",
                    "Convert the routers of each entryPoint separately (a copy of the input with only those "
                    "routers) for separately configured Ferrum instances.")

    def _tls_section(self) -> None:
        tls = mapping(self.root.get("tls"))
        for cert in seq(tls.get("certificates")):
            if isinstance(cert, dict) and isinstance(cert.get("certFile"), str) and isinstance(cert.get("keyFile"), str):
                if "BEGIN" in cert["certFile"] or "BEGIN" in cert["keyFile"]:
                    self.report.error("traefik-inline-cert", "traefik tls", "Inline certificate material is never "
                                      "migrated or echoed; write it to files instead.")
                    continue
                self.plan.settings.frontend_cert_pairs.append((cert["certFile"], cert["keyFile"]))
        stores = mapping(tls.get("stores"))
        default = mapping(mapping(stores.get("default")).get("defaultCertificate"))
        if isinstance(default.get("certFile"), str) and isinstance(default.get("keyFile"), str) \
                and "BEGIN" not in default["certFile"] + default["keyFile"]:
            self.plan.settings.frontend_cert_pairs.append((default["certFile"], default["keyFile"]))
        if tls.get("options"):
            # clientAuth and sniStrict are not part of this note: both are admission controls of the one global
            # handshake policy (see _https_handshake_policy), carried over or refusing every HTTPS route, never dropped.
            self.report.info("traefik-tls-options", "traefik tls", "TLS option settings other than clientAuth and "
                             "sniStrict (versions, ciphers, curves, ALPN) are not migrated; set FERRUM_TLS_* settings "
                             "manually. HTTPS routers are translated only under the 'default' TLS options: their "
                             "clientAuth is applied to every HTTPS route or refuses them all, enabled sniStrict refuses "
                             "them all, and any other TLS options refuse them all (traefik-tls-options-scope).")

    # ---------------------------------------------------------------- routers

    def _router(self, name: str, router: Any) -> None:
        ref = f"traefik router '{safe_label(name)}'"
        if not isinstance(router, dict) or not isinstance(router.get("rule"), str):
            self.report.error("traefik-router-invalid", ref, "Router without a rule; skipped.")
            return
        rule = router["rule"]
        priority = util.as_int(router.get("priority"))
        priority = priority if priority and priority > 0 else len(rule)
        requires_tls = router.get("tls") is not None
        # A Traefik router matches TLS requests only with a tls block and plaintext requests only without one, so
        # each router has exactly one frontend. entryPoint-level TLS (and everything else an entryPoint adds) lives
        # in the static configuration, which is not part of the input: without the operator's statement these
        # routes are refused in _outside_controls, with it the frontend below is taken as stated.
        frontends = frozenset({"https" if requires_tls else "http"})
        listed = str_list(router.get("entryPoints"))
        entrypoints_problem = None
        if listed is None or any(not item.strip() for item in listed):
            entrypoints_problem = ("router entryPoints has unexpected types or empty names, so the listeners that "
                                   "served it are unknown")
            entrypoints: tuple[str, ...] | None = None
        else:
            entrypoints = tuple(sorted(set(listed))) or None
        if requires_tls and mapping(router.get("tls")).get("certResolver"):
            self.report.warning("traefik-cert-resolver", ref, "ACME certResolver is not migrated; provide a "
                                "certificate or configure Ferrum's ACME settings.")
        # The router's tls.options reference is not resolved here: the handshake policy is decided once for every
        # HTTPS route (_handshake_scope on the input as written, applied in _https_handshake_policy).
        try:
            if len(rule) > 4096:
                raise RuleError("rule too long")
            terms = rule_to_dnf(rule, self.ctx.limits.max_rule_terms)
        except RuleError as exc:
            spec = RouteSpec(ref=ref, name=name, hosts=None, kind="prefix", path="/", requires_tls=requires_tls,
                             protocols=frontends)
            spec.path_ok = False
            spec.extra_conditions = True
            spec.refuse(f"rule cannot be parsed ({exc})")
            if entrypoints_problem:
                spec.refuse(entrypoints_problem)
            self.entrypoints_of[id(spec)] = entrypoints
            self.plan.routes.append(spec)
            return
        service_name = router.get("service")
        backend_info = self._service_ref(service_name, ref)
        middleware_names = str_list(router.get("middlewares"))
        acc = _Acc()
        if middleware_names is None:
            acc.refusals.append("middlewares list has unexpected types")
        else:
            for mw_name, mw_type, mw_config in self._resolve_middlewares(middleware_names, acc, 0, set()):
                self._apply_middleware(mw_name, mw_type, mw_config, acc, ref)
        groups: dict[tuple, dict] = {}
        for term in terms:
            evaluated = evaluate_term(term)
            if evaluated is None:
                continue
            methods = tuple(sorted(evaluated["methods"])) if evaluated["methods"] is not None else None
            key = (evaluated["kind"], evaluated["path"], methods, tuple(evaluated["extra"]))
            group = groups.setdefault(key, {"hosts": set(), "any_host": False})
            if evaluated["hosts"] is None:
                group["any_host"] = True
            else:
                group["hosts"].update(evaluated["hosts"])
        if not groups:
            self.report.warning("traefik-rule-unsatisfiable", ref, "Rule can never match; not emitted.")
            return
        if acc.https_redirect and not requires_tls:
            self.plan.settings.https_redirect_seen = True
            self.report.info("traefik-https-redirect", ref, "HTTP-to-HTTPS redirect router: not emitted; Ferrum's "
                             "TLS-only profile disables the plaintext listener instead.")
            return
        for number, ((kind, path, methods, extra), group) in enumerate(groups.items()):
            spec = RouteSpec(ref=ref if len(groups) == 1 else f"{ref} alternative #{number + 1}",
                             name=name if number == 0 else f"{name}-{number + 1}")
            spec.hosts = [] if group["any_host"] else sorted(group["hosts"])
            if kind is None:
                spec.kind, spec.path = ("hostonly", None) if spec.hosts else ("prefix", "/")
            else:
                spec.kind, spec.path = kind, path
                # PathPrefix is a plain string prefix (/api also matches /apix); Path is exact. Ferrum matches
                # prefixes by segment, so the emitter reports siblings it cannot route equivalently.
                spec.report_prefix_siblings = kind == "prefix"
            spec.methods = list(methods) if methods else None
            spec.requires_tls = requires_tls
            spec.protocols = frontends
            if entrypoints_problem:
                spec.refuse(entrypoints_problem)
            self.entrypoints_of[id(spec)] = entrypoints
            for condition in extra:
                spec.refuse(f"rule uses {condition}, which Ferrum cannot express")
                spec.extra_conditions = True
            if acc.allowed_hosts is not None and not (spec.hosts and set(spec.hosts) <= set(acc.allowed_hosts)):
                spec.refuse("headers.allowedHosts restricts hosts beyond the router rule")
            for refusal in acc.refusals:
                spec.refuse(refusal)
            for problem in backend_info["problems"]:
                spec.refuse(problem)
            spec.backend = backend_info.get("backend")
            spec.preserve_host = backend_info.get("preserve_host", True)
            spec.connect_timeout_ms = backend_info.get("connect")
            spec.read_timeout_ms = backend_info.get("read")
            spec.retry = acc.retry
            spec.plugins = [PluginSpec(p.name, p.config, p.ref, p.shared_key) for p in acc.plugins]
            for extra_plugin in backend_info.get("plugins", []):
                spec.plugins.append(PluginSpec(extra_plugin.name, extra_plugin.config, extra_plugin.ref,
                                               extra_plugin.shared_key))
            self._apply_paths(spec, acc)
            if (spec.strip or spec.backend_path) \
                    and any(p.name == "request_mirror" for p in spec.plugins):
                spec.plugins = [p for p in spec.plugins if p.name != "request_mirror"]
                self.report.warning("traefik-mirroring", ref,
                                    "Mirror target(s) dropped on path-rewriting route (stripPrefix/addPrefix): "
                                    "Traefik mirrors the rewritten path, whereas Ferrum file-mode request_mirror "
                                    "mirrors the original request path.")
            self.priority[id(spec)] = (priority, name)
            self.plan.routes.append(spec)

    def _apply_paths(self, spec: RouteSpec, acc: _Acc) -> None:
        if len(acc.strip_prefixes) > 1:
            spec.refuse("several stripPrefix middlewares cannot be combined")
            return
        if len(acc.add_prefixes) > 1:
            spec.refuse("several addPrefix middlewares cannot be combined")
            return
        if "add" in acc.path_ops and "strip" in acc.path_ops and acc.path_ops.index("add") < acc.path_ops.index("strip"):
            spec.refuse("addPrefix before stripPrefix cannot be reproduced in Ferrum")
            return
        if acc.strip_prefixes:
            prefixes = acc.strip_prefixes[0]
            path = spec.path if spec.kind in ("prefix", "exact") else None
            chosen = None
            for prefix in prefixes:
                if path is not None and path.startswith(prefix):
                    chosen = prefix
                    break
                if path is None or prefix.startswith(path):
                    spec.refuse("stripPrefix only applies to some requests of this route")
                    return
            if chosen is not None:
                spec.strip = True
                remainder = (path or "")[len(chosen):]
                if remainder and not remainder.startswith("/"):
                    spec.refuse("stripPrefix splits a path segment")
                    return
                spec.backend_path = remainder if remainder not in ("", "/") else None
        if acc.add_prefixes:
            spec.backend_path = acc.add_prefixes[0].rstrip("/") + (spec.backend_path or "")

    # ------------------------------------------------- TLS handshake policy

    def _handshake_scope(self) -> list[str]:
        """Reasons why HTTPS cannot be translated under one global default handshake policy (empty: it can).

        Traefik admits a TLS handshake before any HTTP router runs, choosing the TLS options (clientAuth, sniStrict,
        versions...) from the connection's SNI for every path of that frontend at once, and Ferrum's HTTPS listener
        applies one policy to every connection. So the only policy translated is the ``default`` TLS options (or
        Traefik's built-in default, on the operator's statement), used by every TLS router. The check runs on every
        router of the input as written, whatever its rule, and on every TLS options definition, used or not:

        * a ``tls.options`` section that cannot be read;
        * any TLS options definition other than ``default`` (whether a router reaches it is not analysed);
        * a router that is not a mapping, or whose ``tls`` block or ``tls.options`` reference cannot be read;
        * a TLS router whose reference is anything other than unset, empty or exactly ``default`` (named options,
          any provider-qualified name, ``default@file`` and a malformed ``default@`` included, undefined names).

        Traefik stores the special ``default`` options globally, without a provider qualifier, and resolves a router
        reference to them only when it is unset, empty or exactly ``default``; any other reference is qualified by
        provider and looked up by that name, so ``default@file`` does not name the global default. Any of the above
        refuses every HTTPS route, whatever the hosts or paths and whatever the operator states. Reasons are
        value-free.
        """
        problems: list[str] = []
        tls_root = self.root.get("tls")
        options = tls_root.get("options") if isinstance(tls_root, dict) else None
        if (tls_root is not None and not isinstance(tls_root, dict)) or \
                (options is not None and not isinstance(options, dict)):
            problems.append("the tls.options section cannot be read")
        elif options and any(name != DEFAULT_TLS_OPTIONS for name in options):
            problems.append("the input defines TLS options other than 'default'")
        unreadable = other = False
        for router in self.routers.values():
            if not isinstance(router, dict):
                unreadable = True  # whether it is a TLS router, and which options it uses, is unknown
                continue
            tls = router.get("tls")
            if tls is None:
                continue  # not a TLS router (see _router); it references no TLS options
            if not isinstance(tls, dict):
                unreadable = True
                continue
            reference = tls.get("options")
            if reference is None or reference == "":
                continue  # unset: Traefik applies the global 'default' options
            if not isinstance(reference, str):
                unreadable = True
                continue
            if reference != DEFAULT_TLS_OPTIONS:
                # Only the exact unqualified literal names the global default. Any '@' qualifier (default@file, an
                # empty suffix, another provider) or any other name is a different, possibly undefined, set.
                other = True
        if unreadable:
            problems.append("a router or its tls block or tls.options reference cannot be read")
        if other:
            problems.append("a TLS router references TLS options other than the unqualified 'default' (named, "
                            "provider-qualified such as default@file, malformed or undefined)")
        return problems

    def _https_handshake_policy(self, scope_problems: list[str]) -> None:
        """Apply the one global handshake policy to every HTTPS route, or refuse them all.

        Plaintext routes are not affected. Refused HTTPS routes stay HTTPS-only placeholders; they are never served
        on the plaintext listener instead.
        """
        https = [spec for spec in self.plan.routes if spec.requires_tls]
        if not https:
            return
        if scope_problems:
            for spec in https:
                spec.refuse("Traefik HTTPS routes are translated only under one global 'default' TLS handshake "
                            f"policy, and the input does not establish one ({'; '.join(scope_problems)})")
            self.report.error(
                "traefik-tls-options-scope", "traefik tls options",
                "Traefik selects TLS options during the handshake, by SNI, for every path of an entryPoint at once; "
                "Ferrum's HTTPS listener applies one policy to every connection. HTTPS routes are therefore "
                "translated only when every TLS router uses the 'default' TLS options and no other TLS options "
                f"exist in the input, which does not hold here ({'; '.join(scope_problems)}). All {len(https)} "
                "HTTPS route(s) were refused (fail closed), whatever their hosts or paths; plaintext routes are not "
                "affected.",
                "Keep these HTTPS routes on the source proxy, or move the handshake requirements into one 'default' "
                "TLS options entry used by every TLS router (naming no options, or exactly 'default' without a "
                "provider qualifier), remove the other TLS options and references, and convert again. For separate handshake policies, convert each policy's routers separately for "
                "separately configured Ferrum frontends.")
            return
        cas, client_auth_problem = self._default_client_auth()
        strict_problem = self._default_sni_strict()
        for spec in https:
            spec.client_cas = list(cas)
            if client_auth_problem:
                spec.refuse(client_auth_problem)
            if strict_problem:
                spec.refuse("the default TLS options enable sniStrict (or state it unreadably), an admission control "
                            "Ferrum's HTTPS listener cannot reproduce")

    def _default_client_auth(self) -> tuple[tuple[str, ...], str | None]:
        """Client CA bundle the default TLS options require (empty: none), or a refusal reason.

        clientAuth is never dropped: a requirement that cannot be reproduced exactly (or more strictly) as one
        frontend client CA bundle file refuses every HTTPS route. The emitter decides whether one listener-wide
        bundle preserves all routes' trust scopes.
        """
        verdict = self._classify_default_client_auth()
        if verdict[1]:
            self.report.error("traefik-client-auth", f"traefik tls options '{DEFAULT_TLS_OPTIONS}'",
                              f"Client certificate requirements cannot be reproduced ({verdict[1]}). Every HTTPS "
                              "router uses these TLS options, so every HTTPS route was refused (fail closed); "
                              "clientAuth is never dropped.",
                              "Use clientAuthType RequireAndVerifyClientCert with exactly one caFiles file path, "
                              "or configure a dedicated Ferrum frontend with "
                              "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH manually and validate it.")
        return verdict

    def _classify_default_client_auth(self) -> tuple[tuple[str, ...], str | None]:
        # Only called when _handshake_scope found a readable tls.options section with no entry besides 'default'.
        options = mapping(mapping(self.root.get("tls")).get("options"))
        name = DEFAULT_TLS_OPTIONS
        if name not in options:
            self.builtin_default_tls_used = True  # Traefik's built-in default requests no client certificates
            return (), None
        option = options[name] if options[name] is not None else {}
        if not isinstance(option, dict):
            return (), "the TLS options entry is malformed"
        client_auth = option.get("clientAuth")
        if client_auth is None:
            return (), None
        if not isinstance(client_auth, dict):
            return (), "clientAuth is malformed"
        cas = str_list(client_auth.get("caFiles"))
        if cas is None:
            return (), "clientAuth caFiles has unexpected types"
        auth_type = client_auth.get("clientAuthType")
        if auth_type is None or auth_type == "":
            # Traefik requires and verifies client certificates whenever caFiles are set without a clientAuthType.
            auth_type = "RequireAndVerifyClientCert" if cas else "NoClientCert"
        if auth_type == "NoClientCert":
            return (), None
        if auth_type in UNVERIFIED_CLIENT_AUTH:
            return (), (f"clientAuthType {auth_type} asks for client certificates without verifying them against a "
                        "CA, which Ferrum's frontend client CA cannot express")
        if auth_type not in VERIFYING_CLIENT_AUTH:
            return (), "clientAuthType is not a known Traefik value"
        if len(cas) != 1 or not cas[0].strip() or "BEGIN" in cas[0]:
            # Inline material is never copied, and several bundles are never concatenated by this tool.
            return (), "clientAuth needs exactly one caFiles file path; missing, inline or several CA bundles"
        if auth_type == "VerifyClientCertIfGiven":
            self.report.warning("traefik-mtls-optional", f"traefik tls options '{safe_label(name)}'",
                                "Optional client certificates (VerifyClientCertIfGiven) become mandatory under "
                                "Ferrum's frontend client CA (stricter).")
        return (cas[0],), None

    def _default_sni_strict(self) -> str | None:
        """Refusal reason when the default TLS options enable sniStrict (or state it unreadably), else None.

        Traefik's sniStrict rejects TLS handshakes without SNI, or for names that match no configured certificate,
        before any router runs. Ferrum's HTTPS listener completes every handshake with its frontend certificate, so
        this admission control cannot be reproduced. It is never dropped: every HTTPS route is refused, whatever
        the operator states about the scope of the input.
        """
        problem = self._classify_default_sni_strict()
        if problem:
            self.report.error("traefik-sni-strict", f"traefik tls options '{DEFAULT_TLS_OPTIONS}'",
                              f"Strict SNI checking cannot be reproduced ({problem}). Every HTTPS router uses these TLS "
                              "options, so every HTTPS route was refused (fail closed); sniStrict is never dropped.",
                              "Keep these routes on the source proxy, or remove sniStrict from the source TLS "
                              "options only if accepting handshakes without a matching SNI is acceptable there, "
                              "and convert again.")
        return problem

    def _classify_default_sni_strict(self) -> str | None:
        option = mapping(mapping(self.root.get("tls")).get("options")).get(DEFAULT_TLS_OPTIONS)
        if not isinstance(option, dict):
            # A malformed entry already refuses every HTTPS route (_default_client_auth). Traefik's built-in default
            # (no 'default' entry in the input, covered by the operator's statement) does not enable sniStrict.
            return None
        value = option.get("sniStrict")
        if value is None or value is False:
            return None
        if value is True:
            return ("sniStrict is enabled, so the source rejected handshakes without SNI or for names matching no "
                    "certificate")
        return "sniStrict is not a boolean, so whether the source rejected handshakes by SNI is unknown"

    # ------------------------------------------------------------ middleware

    def _resolve_middlewares(self, names: list[str], acc: _Acc, depth: int, seen: set[str]) -> list[tuple]:
        result = []
        if depth > 10:
            acc.refusals.append("middleware chains nested too deeply")
            return result
        for raw_name in names:
            base, _, provider = raw_name.partition("@")
            if provider not in ("", "file"):
                acc.refusals.append(f"middleware from provider {safe_label(provider, 32)} is not in the input")
                continue
            if base in seen:
                acc.refusals.append("middleware chain cycle")
                continue
            definition = self.middlewares.get(base)
            if not isinstance(definition, dict) or len(definition) != 1:
                acc.refusals.append(f"middleware {safe_label(base, 48)} is undefined or ambiguous")
                continue
            mw_type, config = next(iter(definition.items()))
            if mw_type == "chain":
                if not isinstance(config, dict):
                    acc.refusals.append(f"middleware chain {safe_label(base, 48)} config is malformed")
                    continue
                children = str_list(config.get("middlewares"))
                if children is None:
                    acc.refusals.append(f"middleware chain {safe_label(base, 48)} middlewares list has unexpected types")
                    continue
                result.extend(self._resolve_middlewares(children, acc, depth + 1, seen | {base}))
            else:
                result.append((base, mw_type, mapping(config) if config is not None else {}))
        return result

    def _apply_middleware(self, name: str, mw_type: str, config: dict, acc: _Acc, router_ref: str) -> None:
        ref = f"traefik middleware '{safe_label(name)}'"
        if mw_type == "stripPrefix":
            prefixes = str_list(config.get("prefixes"))
            if not prefixes:
                acc.refusals.append("stripPrefix without prefixes")
            else:
                acc.strip_prefixes.append(prefixes)
                acc.path_ops.append("strip")
        elif mw_type == "addPrefix":
            prefix = config.get("prefix")
            if not isinstance(prefix, str) or not prefix.startswith("/"):
                acc.refusals.append("addPrefix prefix must start with '/'")
            else:
                acc.add_prefixes.append(prefix)
                acc.path_ops.append("add")
        elif mw_type == "headers":
            self._headers(config, acc, ref)
        elif mw_type == "basicAuth":
            if config.get("headerField"):
                acc.refusals.append("basicAuth headerField forwards the user to the backend, which is not reproduced")
                return
            acc.plugins.append(PluginSpec("basic_auth", {"hide_credentials": config.get("removeHeader") is True}, ref))
            self.report.error("traefik-basic-auth", ref, "basicAuth is emitted fail-closed: htpasswd hashes are never "
                              "migrated or echoed, so nobody can authenticate until Ferrum credentials exist.",
                              "Create consumers with hmac_sha256 Basic credentials and export "
                              "FERRUM_BASIC_AUTH_HMAC_SECRET_FILE.")
        elif mw_type in ("ipAllowList", "ipWhiteList"):
            if config.get("ipStrategy"):
                acc.refusals.append("ipStrategy reads client IPs from X-Forwarded-For differently than Ferrum's "
                                    "trusted-proxy walk")
                return
            ranges = str_list(config.get("sourceRange")) or []
            cidrs = [util.canonical_cidr(item) for item in ranges]
            if not cidrs or any(cidr is None for cidr in cidrs):
                acc.refusals.append("ipAllowList sourceRange is empty or invalid")
                return
            acc.plugins.append(PluginSpec("ip_restriction", {"allow": cidrs}, ref))
        elif mw_type == "rateLimit":
            self._rate_limit(config, acc, ref)
        elif mw_type == "buffering":
            req_size = util.as_int(config.get("maxRequestBodyBytes"))
            if req_size and req_size > 0:
                acc.refusals.append("buffering.maxRequestBodyBytes buffers and rejects oversized chunked uploads "
                                    "before contacting the backend, whereas Ferrum request_size_limiting streams "
                                    "chunked bodies up to max_bytes")
            resp_size = util.as_int(config.get("maxResponseBodyBytes"))
            if resp_size and resp_size > 0:
                acc.plugins.append(PluginSpec("response_size_limiting",
                                              {"max_bytes": resp_size, "require_buffered_check": True}, ref))
                acc.resp_size_limited = True
            if any(config.get(k) for k in ("memRequestBodyBytes", "memResponseBodyBytes", "retryExpression")) \
                    or not ((req_size and req_size > 0) or (resp_size and resp_size > 0)):
                self.report.info("traefik-buffering", ref,
                                 "Only maxResponseBodyBytes is migrated from buffering.")
        elif mw_type == "compress":
            if acc.resp_size_limited:
                acc.refusals.append("buffering.maxResponseBodyBytes ordered before compress measures compressed "
                                    "response size in Traefik, whereas Ferrum response_size_limiting checks the "
                                    "uncompressed backend Content-Length")
            else:
                self._compress(config, acc, ref)
        elif mw_type == "grpcWeb":
            acc.refusals.append("grpcWeb enforces local CORS preflight handling and allowOrigins (including an empty "
                                "allow-list), whereas Ferrum grpc_web forwards unhandled preflights upstream; "
                                "configure grpc_web and cors manually in Ferrum")
        elif mw_type == "redirectScheme":
            if config.get("scheme") == "https":
                acc.https_redirect = True
            else:
                acc.refusals.append("redirectScheme to a scheme other than https")
        elif mw_type == "retry":
            attempts = util.as_int(config.get("attempts"))
            if attempts and attempts > 0:
                acc.retry = {"max_retries": min(attempts, util.MAX_RETRIES), "retry_on_connect_failure": True,
                             "retryable_status_codes": []}
        elif mw_type == "contentType":
            self.report.info("traefik-middleware-omitted", ref, f"{mw_type} is not migrated (no security impact).")
        elif mw_type in ("circuitBreaker", "errors", "passTLSClientCert"):
            self.report.warning("traefik-middleware-omitted", ref, f"{mw_type} is not migrated.")
        else:
            acc.refusals.append(f"middleware type {safe_label(mw_type, 40)} has no safe Ferrum equivalent")

    def _compress(self, config: dict, acc: _Acc, ref: str) -> None:
        if config.get("excludedContentTypes"):
            self.report.warning("traefik-compress", ref,
                                "compress omitted: excludedContentTypes has no Ferrum equivalent (Ferrum uses an "
                                "allow-list and cannot exclude specific response media types).")
            return
        raw_enc = config.get("encodings")
        encodings = str_list(raw_enc) if raw_enc is not None else ["gzip", "br"]
        if raw_enc is not None and (encodings is None or not encodings):
            self.report.warning("traefik-compress", ref, "compress omitted: encodings has unexpected types.")
            return
        raw_min = config.get("minResponseBodyBytes")
        # Traefik compress defaults minResponseBodyBytes to 1024 (whereas Ferrum defaults to 256).
        min_len: int = 1024
        if raw_min is not None:
            parsed_min = util.as_int(raw_min)
            if parsed_min is None or parsed_min < 0:
                self.report.warning("traefik-compress", ref, "compress omitted: invalid minResponseBodyBytes.")
                return
            min_len = parsed_min
        raw_inc = config.get("includedContentTypes")
        inc: list[str] | None = None
        if raw_inc is not None:
            inc = str_list(raw_inc)
            if not inc:
                self.report.warning("traefik-compress", ref, "compress omitted: invalid includedContentTypes.")
                return
            # Traefik matches media types literally via mime.ParseMediaType; wildcard entries like 'text/*' never match
            # in Traefik but would widen compression as a range in Ferrum. Drop wildcard entries and omit if none stay.
            exact_inc = [ct for ct in inc if "*" not in ct]
            if len(exact_inc) != len(inc):
                self.report.warning("traefik-compress", ref,
                                    "compress.includedContentTypes wildcard entries ('*' or 'type/*') were dropped "
                                    "(Traefik matches media types literally whereas Ferrum treats 'type/*' as a range).")
            if not exact_inc:
                return
            inc = exact_inc
        built, problem = compression_config(encodings, min_content_length=min_len, content_types=inc, allow_ranges=False)
        if built is None:
            self.report.warning("traefik-compress", ref, f"compress omitted ({problem}).")
            return
        if config.get("defaultEncoding"):
            self.report.warning("traefik-compress", ref,
                                "compress.defaultEncoding is not migrated; Ferrum negotiates via Accept-Encoding.")
        acc.plugins.append(PluginSpec("compression", built, ref))

    def _headers(self, config: dict, acc: _Acc, ref: str) -> None:
        for key in ("sslRedirect", "sslTemporaryRedirect", "sslHost", "sslForceHost", "sslProxyHeaders"):
            if config.get(key):
                acc.refusals.append(f"headers.{key} is not supported")
                return
        request_rules, response_rules = [], []
        for header, value in mapping(config.get("customRequestHeaders")).items():
            if value == "":
                rule, problem = request_header_rule("remove", header)
            else:
                rule, problem = request_header_rule("update", header, literal_value(str(value)))
            if problem:
                acc.refusals.append(problem)
            else:
                request_rules.append(rule)
        for header, value in mapping(config.get("customResponseHeaders")).items():
            if value == "":
                rule, problem = response_header_rule("remove", header)
            else:
                rule, problem = response_header_rule("update", header, literal_value(str(value)))
            if rule:
                response_rules.append(rule)
            else:
                self.report.warning("traefik-response-header", ref, f"Response header not migrated ({problem}).")
        security: list[tuple[str, str]] = []
        sts = util.as_int(config.get("stsSeconds"))
        if sts and sts > 0:
            value = f"max-age={sts}"
            if config.get("stsIncludeSubdomains"):
                value += "; includeSubDomains"
            if config.get("stsPreload"):
                value += "; preload"
            security.append(("strict-transport-security", value))
        if config.get("customFrameOptionsValue"):
            security.append(("x-frame-options", str(config["customFrameOptionsValue"])))
        elif config.get("frameDeny"):
            security.append(("x-frame-options", "DENY"))
        if config.get("contentTypeNosniff"):
            security.append(("x-content-type-options", "nosniff"))
        if config.get("customBrowserXSSValue"):
            security.append(("x-xss-protection", str(config["customBrowserXSSValue"])))
        elif config.get("browserXssFilter"):
            security.append(("x-xss-protection", "1; mode=block"))
        for key, header in (("contentSecurityPolicy", "content-security-policy"),
                            ("contentSecurityPolicyReportOnly", "content-security-policy-report-only"),
                            ("referrerPolicy", "referrer-policy"), ("permissionsPolicy", "permissions-policy")):
            if isinstance(config.get(key), str) and config[key]:
                security.append((header, config[key]))
        for header, value in security:
            rule, problem = response_header_rule("update", header, literal_value(value))
            if rule:
                response_rules.append(rule)
            else:
                acc.refusals.append(f"security header {header} not representable ({problem})")
        if security and not config.get("forceSTSHeader") and sts:
            self.report.warning("traefik-sts", ref, "Traefik only sent HSTS over HTTPS; Ferrum sets it on every response.")
        if any(key.startswith("accessControl") for key in config):
            if config.get("accessControlAllowOriginListRegex"):
                self.report.warning("traefik-cors-regex", ref, "Regex CORS origins are not translated; CORS omitted "
                                    "(browsers block cross-origin calls).")
            else:
                built, problem = cors_config(str_list(config.get("accessControlAllowOriginList")) or [],
                                             config.get("accessControlAllowMethods"),
                                             config.get("accessControlAllowHeaders"),
                                             config.get("accessControlExposeHeaders"),
                                             config.get("accessControlAllowCredentials"),
                                             config.get("accessControlMaxAge"))
                if built:
                    acc.plugins.append(PluginSpec("cors", built, ref))
                else:
                    self.report.warning("traefik-cors", ref, f"CORS omitted ({problem}).")
        if config.get("allowedHosts"):
            hosts = [host.lower() for host in (str_list(config.get("allowedHosts")) or [])]
            # Every headers middleware in the chain checks its own list, so a request must pass all of them:
            # keep the intersection, never let a later (broader) list replace an earlier one.
            acc.allowed_hosts = hosts if acc.allowed_hosts is None else \
                [host for host in acc.allowed_hosts if host in hosts]
            if config.get("hostsProxyHeaders"):
                # allowedHosts is then also checked against these request headers (for example X-Forwarded-Host),
                # a restriction beyond the router's Host match that Ferrum cannot enforce.
                acc.refusals.append("headers.allowedHosts is also checked against hostsProxyHeaders, which Ferrum "
                                    "cannot enforce")
        elif config.get("hostsProxyHeaders"):
            self.report.info("traefik-hosts-proxy-headers", ref, "hostsProxyHeaders only affects allowedHosts and SSL "
                             "redirect host checks, which this middleware does not configure; ignored.")
        if request_rules:
            acc.plugins.append(PluginSpec("request_transformer", {"rules": request_rules}, ref))
        if response_rules:
            acc.plugins.append(PluginSpec("response_transformer", {"rules": response_rules}, ref))

    def _rate_limit(self, config: dict, acc: _Acc, ref: str) -> None:
        criterion = mapping(config.get("sourceCriterion"))
        if criterion.get("ipStrategy") or criterion.get("requestHeaderName") or criterion.get("requestHost"):
            acc.refusals.append("rateLimit sourceCriterion has no Ferrum equivalent")
            return
        average = util.as_int(config.get("average"))
        if not average or average <= 0:
            self.report.info("traefik-rate-limit-off", ref, "rateLimit with average 0 means no limit; omitted.")
            return
        period_ms = util.parse_go_duration_ms(config.get("period", "1s"))
        if not period_ms or period_ms % 1000:
            acc.refusals.append("rateLimit period is not a whole number of seconds")
            return
        seconds = period_ms // 1000
        presets = {1: "requests_per_second", 60: "requests_per_minute", 3600: "requests_per_hour"}
        if seconds in presets:
            limit = {"scope": "default", presets[seconds]: average}
        elif seconds <= 86_400:
            limit = {"scope": "default", "window_seconds": seconds, "max_requests": average}
        else:
            acc.refusals.append("rateLimit period longer than a day")
            return
        acc.plugins.append(PluginSpec("rate_limiting", {"limit_by": "ip", "limits": [limit]}, ref))
        self.report.warning("traefik-rate-limit", ref, "rateLimit burst semantics differ; Ferrum enforces the same "
                            "average rate per client IP.")

    # --------------------------------------------------------------- services

    def _service_ref(self, service_name: Any, ref: str) -> dict:
        if not isinstance(service_name, str):
            return {"problems": ["router has no service"]}
        base, _, provider = service_name.partition("@")
        if provider == "internal":
            return {"problems": [f"internal service {safe_label(base, 32)} (dashboard/API) is not migrated"]}
        if provider not in ("", "file"):
            return {"problems": [f"service from provider {safe_label(provider, 32)} is not in the input"]}
        return self._service(base, 0)

    def _service(self, name: str, depth: int) -> dict:
        raw = self.services.get(name)
        ref = f"traefik service '{safe_label(name)}'"
        if not isinstance(raw, dict):
            return {"problems": [f"service {safe_label(name, 48)} is undefined"]}
        if "loadBalancer" in raw:
            return self._load_balancer(name, mapping(raw["loadBalancer"]), ref)
        if "weighted" in raw and depth == 0:
            return self._weighted(name, mapping(raw["weighted"]), ref)
        if "mirroring" in raw and depth == 0:
            mirroring = mapping(raw["mirroring"])
            main = mirroring.get("service")
            if not isinstance(main, str) or not main:
                return {"problems": ["mirroring without service"]}
            main_base, _, main_provider = main.partition("@")
            if main_provider == "internal":
                return {"problems": [f"internal service {safe_label(main_base, 32)} (dashboard/API) is not migrated"]}
            if main_provider not in ("", "file"):
                return {"problems": [f"service from provider {safe_label(main_provider, 32)} is not in the input"]}
            main_result = self._service(main_base, depth + 1)
            if main_result.get("problems"):
                return main_result
            mirror_plugins, dropped = self._mirror_plugins(mirroring, ref)
            if mirror_plugins:
                main_result = dict(main_result)
                main_result["plugins"] = list(main_result.get("plugins", [])) + mirror_plugins
                self.report.warning("traefik-mirroring", ref,
                                    f"Migrated {len(mirror_plugins)} mirror target(s) to request_mirror; Ferrum "
                                    "redacts credential-like headers and query parameters on mirrored requests by "
                                    "default (stricter).")
            if dropped:
                self.report.warning("traefik-mirroring", ref,
                                    f"{dropped} mirror target(s) could not be represented as a single static "
                                    "request_mirror target and were dropped.")
            return main_result
        return {"problems": ["service type (failover or nested weighted) is not supported"]}

    def _mirror_plugins(self, mirroring: dict, ref: str) -> tuple[list[PluginSpec], int]:
        plugins: list[PluginSpec] = []
        dropped = 0
        raw_mirrors = seq(mirroring.get("mirrors"))
        raw_body = mirroring.get("mirrorBody")
        if raw_body is not None and not isinstance(raw_body, bool):
            return [], len(raw_mirrors)
        mirror_body = True if raw_body is None else raw_body
        if mirror_body:
            # Traefik forwards oversized bodies to the primary service unmirrored, whereas Ferrum's body-mirroring
            # ceiling is applied during request collection and can return 413 on sampled chunked uploads. Only
            # header-only mirrors (mirrorBody: false) preserve primary-route availability identically.
            return [], len(raw_mirrors)
        max_body: int | None = None
        for entry in raw_mirrors:
            if not isinstance(entry, dict) or not isinstance(entry.get("name"), str):
                dropped += 1
                continue
            raw_pct = entry.get("percent")
            if isinstance(raw_pct, bool) or not isinstance(raw_pct, (int, float)):
                dropped += 1
                continue
            pct = float(raw_pct)
            if pct == 0.0:
                continue
            base, _, provider = entry["name"].partition("@")
            if provider not in ("", "file"):
                dropped += 1
                continue
            target_raw = mapping(self.services.get(base))
            lb = mapping(target_raw.get("loadBalancer"))
            if not lb or lb.get("passHostHeader") is not False:
                # Traefik's loadBalancer defaults passHostHeader to true (preserving client Host), whereas Ferrum
                # file-mode request_mirror strips Host to the mirror target's authority. Only mirror when
                # passHostHeader is explicitly false so the virtual-host boundary matches.
                dropped += 1
                continue
            scheme, targets, problems = self._servers(lb, ref)
            tls, _timeouts, transport_problems = self._transport(lb.get("serversTransport"), ref)
            if problems or transport_problems or scheme is None or len(targets) != 1 \
                    or (scheme == "https" and (not tls.verify or tls.ca_path or tls.client_cert_path
                                               or tls.sni or tls.san_allow_list)):
                dropped += 1
                continue
            built, problem = request_mirror_config(
                targets[0].host, targets[0].port, scheme,
                percentage=pct, mirror_request_body=mirror_body, max_body_bytes=max_body,
            )
            if built is None:
                dropped += 1
                continue
            plugins.append(PluginSpec("request_mirror", built, ref))
        return plugins, dropped

    def _transport(self, name: Any, ref: str) -> tuple[TlsSpec, dict, list[str]]:
        """Backend TLS, forwarding timeouts and refusal reasons for one ``serversTransport`` reference.

        Used for direct load balancers and for every weighted child alike. A transport that cannot be
        found, or whose identity controls cannot be reproduced, is a refusal reason, never a silent default.
        """
        tls = TlsSpec(verify=True)
        timeouts: dict = {}
        problems: list[str] = []
        if not name:
            return tls, timeouts, problems
        base, _, provider = str(name).partition("@")
        if provider not in ("", "file"):
            return tls, timeouts, [f"serversTransport from provider {safe_label(provider, 32)} is not in the input"]
        transport = mapping(self.transports.get(base))
        if not transport:
            return tls, timeouts, ["serversTransport is undefined"]
        if transport.get("insecureSkipVerify"):
            tls.verify = False
        cas = str_list(transport.get("rootCAs"))
        if cas is None:
            problems.append("serversTransport rootCAs has unexpected types")
        elif len(cas) == 1 and "BEGIN" not in cas[0]:
            tls.ca_path = cas[0]
        elif cas:
            # Traefik trusts only the listed roots; falling back to Ferrum's default trust store would trust more.
            problems.append("serversTransport rootCAs are inline or several; provide one CA bundle file path")
        certs = seq(transport.get("certificates"))
        if certs:
            first = mapping(certs[0])
            cert, key = first.get("certFile"), first.get("keyFile")
            if len(certs) == 1 and isinstance(cert, str) and isinstance(key, str) and "BEGIN" not in cert + key:
                tls.client_cert_path, tls.client_key_path = cert, key
            else:
                # Inline material is never copied, and Ferrum presents exactly one client certificate from file
                # paths; dropping the identity silently would change who the backend sees.
                problems.append("serversTransport client certificates are inline, malformed or several; the backend "
                                "client identity cannot be migrated")
        for key_name, label in (("spiffe", "spiffe workload identity"),
                                ("peerCertURI", "peerCertURI backend certificate pinning")):
            if transport.get(key_name):
                problems.append(f"serversTransport {label} has no Ferrum equivalent")
        if isinstance(transport.get("serverName"), str):
            tls.sni = transport["serverName"]
        forwarding = mapping(transport.get("forwardingTimeouts"))
        dial = util.parse_go_duration_ms(forwarding.get("dialTimeout"))
        header = util.parse_go_duration_ms(forwarding.get("responseHeaderTimeout"))
        if dial:
            timeouts["connect"] = dial
        if header:
            timeouts["read"] = header
        return tls, timeouts, problems

    def _servers(self, lb: dict, ref: str) -> tuple[str | None, list[Target], list[str]]:
        problems: list[str] = []
        scheme = None
        targets: list[Target] = []
        for server in seq(lb.get("servers")):
            url = server.get("url") if isinstance(server, dict) else None
            try:
                server_scheme, host, port, path = util.split_url(url, {"http": 80, "https": 443, "h2c": 80})
            except util.UrlProblem as exc:
                problems.append(f"server url: {exc}")
                continue
            if path not in ("", "/"):
                problems.append("server URLs with paths are not supported")
                continue
            server_scheme = "http" if server_scheme == "h2c" else server_scheme
            if scheme and scheme != server_scheme:
                problems.append("servers mix http and https")
                continue
            scheme = server_scheme
            weight = util.as_int(server.get("weight")) if isinstance(server, dict) else None
            weight = 1 if weight is None else weight
            if weight > 0:
                targets.append(Target(host, port, weight))
        if not targets and not problems:
            problems.append("load balancer has no servers")
        return scheme, targets, problems

    def _load_balancer(self, name: str, lb: dict, ref: str) -> dict:
        scheme, targets, problems = self._servers(lb, ref)
        result: dict[str, Any] = {"problems": problems, "preserve_host": lb.get("passHostHeader", True) is not False}
        tls, timeouts, transport_problems = self._transport(lb.get("serversTransport"), ref)
        result["problems"].extend(transport_problems)  # same list object as `problems`
        result.update(timeouts)
        if problems or scheme is None:
            return result
        health = self._health(mapping(lb.get("healthCheck")), ref)
        sticky = mapping(mapping(lb.get("sticky")).get("cookie"))
        if len(targets) == 1 and not health and not sticky and not (scheme == "https" and (tls.sni or tls.san_allow_list)):
            result["backend"] = BackendRef(scheme=scheme, host=targets[0].host, port=targets[0].port, tls=tls)
            return result
        key = f"{name}|{scheme}|{tls.key()}"
        if key not in self.plan.upstreams:
            spec = UpstreamSpec(key=key, name=name, ref=ref, targets=targets, tls=tls, health_checks=health)
            if lb.get("sticky") is not None:
                cookie_name = sticky.get("name") or f"traefik-{util.slugify(name)}"
                spec.algorithm = "consistent_hashing"
                spec.hash_on = f"cookie:{cookie_name}"
                cookie = {"path": sticky.get("path") or "/", "http_only": sticky.get("httpOnly", False) is True,
                          "secure": sticky.get("secure", False) is True}
                max_age = util.as_int(sticky.get("maxAge"))
                if max_age:
                    cookie["ttl_seconds"] = max_age
                else:
                    cookie["session_cookie"] = True
                if sticky.get("sameSite") in ("none", "lax", "strict"):
                    cookie["same_site"] = str(sticky["sameSite"]).capitalize()
                spec.hash_on_cookie_config = cookie
                self.report.warning("traefik-sticky", ref, "Sticky cookies map to consistent hashing on the cookie; "
                                    "the cookie value format differs.")
            self.plan.upstreams[key] = spec
        result["backend"] = BackendRef(scheme=scheme, upstream_key=key)
        return result

    def _health(self, health: dict, ref: str) -> dict | None:
        if not health or not isinstance(health.get("path"), str):
            return None
        entry: dict[str, Any] = {"http_path": health["path"]}
        interval = util.parse_go_duration_ms(health.get("interval", "30s"))
        timeout = util.parse_go_duration_ms(health.get("timeout", "5s"))
        if interval:
            entry["interval_seconds"] = max(1, interval // 1000)
        if timeout:
            entry["timeout_ms"] = timeout
        if health.get("scheme") == "https":
            entry["use_tls"] = True
        if health.get("port") or health.get("hostname") or health.get("headers"):
            self.report.warning("traefik-health", ref, "Health-check port/hostname/headers are not migrated.")
        return {"active": entry}

    def _weighted(self, name: str, weighted: dict, ref: str) -> dict:
        parts: list[tuple[int, list[Target]]] = []
        schemes = set()
        preserve = set()
        tls_keys = set()
        timeout_keys: set[tuple] = set()
        tls_value = TlsSpec()
        problems: list[str] = []
        dropped_lb_options = any(weighted.get(key) is not None for key in ("healthCheck", "sticky"))
        for child in seq(weighted.get("services")):
            if not isinstance(child, dict) or not isinstance(child.get("name"), str):
                problems.append("weighted child without a name")
                continue
            base, _, provider = child["name"].partition("@")
            if provider not in ("", "file"):
                problems.append(f"weighted child from provider {safe_label(provider, 32)} is not in the input")
                continue
            child_raw = mapping(self.services.get(base))
            lb = mapping(child_raw.get("loadBalancer"))
            if not lb:
                problems.append("weighted children must be load balancers")
                continue
            scheme, targets, child_problems = self._servers(lb, ref)
            problems.extend(child_problems)
            # Each child's serversTransport is resolved exactly like a direct load balancer's: an undefined
            # transport or unmigratable identity control refuses the route instead of falling back to defaults.
            tls_value, timeouts, transport_problems = self._transport(lb.get("serversTransport"), ref)
            problems.extend(transport_problems)
            schemes.add(scheme)
            preserve.add(lb.get("passHostHeader", True) is not False)
            tls_keys.add(tls_value.key())
            timeout_keys.add((timeouts.get("connect"), timeouts.get("read")))
            dropped_lb_options = dropped_lb_options or any(lb.get(key) is not None for key in ("healthCheck", "sticky"))
            parts.append((util.as_int(child.get("weight")) or 0, targets))
        if len(schemes) > 1 or len(preserve) > 1 or len(tls_keys) > 1:
            problems.append("weighted children differ in scheme, passHostHeader or transport")
        if len(timeout_keys) > 1:
            problems.append("weighted children differ in serversTransport forwardingTimeouts (dialTimeout/"
                            "responseHeaderTimeout), and Ferrum applies one timeout per route")
        if problems:
            return {"problems": problems}
        if dropped_lb_options:
            self.report.warning("traefik-weighted-lb-options", ref, "healthCheck/sticky settings of a weighted service "
                                "or its child load balancers are not migrated: the merged upstream uses weighted "
                                "round robin without health checks or session stickiness.",
                                "Configure Ferrum upstream health_checks or hash_on manually if needed.")
        merged = merge_weighted_targets(parts)
        if merged is None:
            return {"problems": ["weighted service sends no traffic anywhere"]}
        targets, approximate = merged
        if approximate:
            self.report.warning("traefik-weights", ref, "Weighted split was rounded to integer target weights.")
        key = f"weighted:{name}"
        self.plan.upstreams[key] = UpstreamSpec(key=key, name=name, ref=ref, targets=targets, tls=tls_value,
                                                algorithm="weighted_round_robin")
        connect, read = next(iter(timeout_keys))
        return {"problems": [], "backend": BackendRef(scheme=next(iter(schemes)), upstream_key=key),
                "preserve_host": next(iter(preserve)), "connect": connect, "read": read}

    # ------------------------------------------------------------- priorities

    def _precedence(self) -> None:
        items = [(spec, *self.priority[id(spec)]) for spec in self.plan.routes
                 if id(spec) in self.priority and not spec.skip]
        if len(items) > self.ctx.limits.max_precedence_routes:
            raise InputError(f"more than {self.ctx.limits.max_precedence_routes} Traefik routes for precedence analysis")
        for index, (a, priority_a, router_a) in enumerate(items):
            for b, priority_b, router_b in items[index + 1:]:
                if router_a == router_b or a.skip or b.skip or a.extra_conditions or b.extra_conditions:
                    continue
                if not matching.route_overlaps(a, b):
                    continue
                prefers = matching.ferrum_prefers(a, b)
                ferrum_winner = None if prefers is None else (a if prefers else b)
                if priority_a == priority_b:
                    reason = f"overlaps {b.ref if a is not b else a.ref} with equal Traefik priority (ambiguous order)"
                    a.refuse(reason)
                    b.refuse(f"overlaps {a.ref} with equal Traefik priority (ambiguous order)")
                    continue
                traefik_winner = a if priority_a > priority_b else b
                if ferrum_winner is traefik_winner:
                    continue
                loser = b if traefik_winner is a else a
                if matching.route_covers(traefik_winner, loser):
                    loser.skip = True
                    loser.skip_reason = f"shadowed by higher-priority {traefik_winner.ref}"
                    self.report.warning("route-shadowed", loser.ref,
                                        f"Unreachable in Traefik because {traefik_winner.ref} has higher priority; "
                                        "not emitted.")
                else:
                    reason = "Traefik priority and Ferrum's specificity order disagree for overlapping routes"
                    a.refuse(reason)
                    b.refuse(reason)


def translate(text: str, fmt: str, ctx: SourceContext) -> Plan:
    documents = load_structured(text, fmt, ctx.limits, allow_multi=False)
    if not documents or not isinstance(documents[0], dict):
        raise InputError("Traefik dynamic configuration must be a mapping at the top level")
    return _Traefik(documents[0], ctx).run()
