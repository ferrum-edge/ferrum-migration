"""Traefik OSS dynamic configuration (file provider, YAML/TOML/JSON) ``http`` section to the IR.

Router rules are parsed (v2 and v3 syntax) and expanded to disjunctive normal
form; ``Host``/``Path``/``PathPrefix``/``Method`` are representable, anything
else (headers, queries, client IPs, regex matchers, negation) refuses the router
and poisons overlapping routes. Router priorities are compared against Ferrum's
specificity order; shadowed routes are dropped and contradictory pairs refused.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .. import matching, util
from ..errors import InputError
from ..model import BackendRef, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from ..safe_load import load_structured
from .common import (SourceContext, check_route_budget, cors_config, literal_value, mapping,
                     merge_weighted_targets, request_header_rule, response_header_rule, seq, str_list)

PLATFORM = "traefik"
REPRESENTABLE_MATCHERS = {"Host", "HostHeader", "Path", "PathPrefix", "Method"}
# Traefik TLS options name applied to TLS routers that do not reference one.
DEFAULT_TLS_OPTIONS = "default"
# clientAuthType values that verify client certificates against caFiles (Traefik: required, or only if given).
VERIFYING_CLIENT_AUTH = ("RequireAndVerifyClientCert", "VerifyClientCertIfGiven")
# clientAuthType values that ask for client certificates without verifying them against a CA.
UNVERIFIED_CLIENT_AUTH = ("RequestClientCert", "RequireAnyClientCert")


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
    add_prefix: str | None = None
    https_redirect: bool = False
    retry: dict | None = None
    allowed_hosts: list[str] | None = None


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
        # Per HTTPS route spec (by id): effective TLS options name and the host names Traefik maps those options to
        # for SNI selection (empty when selection depends on the SNI). Plus the per-name client auth verdicts.
        self.tls_option_of: dict[int, tuple[str, list[str]]] = {}
        self.client_auth_cache: dict[str, tuple[tuple[str, ...], str | None]] = {}
        self.builtin_default_tls_used = False

    def run(self) -> Plan:
        for key in self.root:
            if key in ("tcp", "udp"):
                self.report.error("traefik-l4", f"traefik {key}", "TCP/UDP routers are not migrated (HTTP only).",
                                  "Configure Ferrum stream proxies manually.")
            elif key not in ("http", "tls"):
                self.report.warning("traefik-unknown-section", f"traefik {safe_label(key, 40)}",
                                    "Unknown top-level section ignored (static configuration is not read).")
        self._tls_section()
        check_route_budget(len(self.routers), self.ctx.limits)
        entrypoints_seen = False
        for name, router in self.routers.items():
            if isinstance(router, dict) and router.get("entryPoints"):
                entrypoints_seen = True
            self._router(str(name), router)
        if entrypoints_seen:
            self.report.info("traefik-entrypoints", "traefik routers", "EntryPoints live in Traefik's static "
                             "configuration, which is not read: routers with a tls block are treated as HTTPS-only, "
                             "the rest as plaintext.")
        self._client_auth_scopes()
        if self.builtin_default_tls_used:
            self.report.info("traefik-tls-default-options", "traefik tls options",
                             "The input defines no 'default' TLS options, so HTTPS routers that use the default were "
                             "translated with Traefik's built-in default (no client certificates). A default TLS "
                             "option defined by another provider is not part of the input.",
                             "If another provider defines default TLS options with clientAuth, add them to the input "
                             "and convert again.")
        self._precedence()
        check_route_budget(len(self.plan.routes), self.ctx.limits)
        return self.plan

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
            # clientAuth is not part of this note: it is resolved per HTTPS router (see _client_auth) and either
            # carried over as the route's frontend client CA or refuses the route.
            self.report.info("traefik-tls-options", "traefik tls", "TLS options other than clientAuth (versions, "
                             "ciphers, curves, sniStrict, ALPN) are not migrated; set FERRUM_TLS_* settings manually. "
                             "clientAuth is applied per HTTPS router or refuses it.")

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
        if requires_tls and mapping(router.get("tls")).get("certResolver"):
            self.report.warning("traefik-cert-resolver", ref, "ACME certResolver is not migrated; provide a "
                                "certificate or configure Ferrum's ACME settings.")
        tls_option, tls_option_problem = self._router_tls_option(router) if requires_tls else (None, None)
        try:
            if len(rule) > 4096:
                raise RuleError("rule too long")
            terms = rule_to_dnf(rule, self.ctx.limits.max_rule_terms)
        except RuleError as exc:
            spec = RouteSpec(ref=ref, name=name, hosts=None, kind="prefix", path="/", requires_tls=requires_tls)
            spec.path_ok = False
            spec.extra_conditions = True
            spec.refuse(f"rule cannot be parsed ({exc})")
            self.plan.routes.append(spec)
            return
        # Traefik maps TLS options to SNI names from Host matchers only; HostHeader does not take part, so such
        # routers get the options selected by each connection's SNI.
        sni_mapped = not any(kind == "ident" and value == "HostHeader" for kind, value in tokenize_rule(rule))
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
            if tls_option_problem:
                spec.refuse(tls_option_problem)
            elif tls_option is not None:
                client_cas, client_auth_problem = self._client_auth(tls_option)
                spec.client_cas = list(client_cas)
                if client_auth_problem:
                    spec.refuse(client_auth_problem)
                self.tls_option_of[id(spec)] = (tls_option, list(spec.hosts) if sni_mapped else [])
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
            self._apply_paths(spec, acc)
            self.priority[id(spec)] = (priority, name)
            self.plan.routes.append(spec)

    def _apply_paths(self, spec: RouteSpec, acc: _Acc) -> None:
        if len(acc.strip_prefixes) > 1:
            spec.refuse("several stripPrefix middlewares cannot be combined")
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
        if acc.add_prefix:
            spec.backend_path = acc.add_prefix.rstrip("/") + (spec.backend_path or "")

    # ------------------------------------------------------ TLS client auth

    def _router_tls_option(self, router: dict) -> tuple[str | None, str | None]:
        """Name of the TLS options an HTTPS router uses, or a refusal reason when they cannot be known."""
        raw = mapping(router.get("tls")).get("options")
        if raw is None or raw == "":
            return DEFAULT_TLS_OPTIONS, None
        if not isinstance(raw, str):
            return None, ("router tls.options is not a TLS options name, so its client certificate requirements are "
                          "unknown")
        base, _, provider = raw.partition("@")
        if provider not in ("", "file"):
            return None, (f"TLS options from provider {safe_label(provider, 32)} are not in the input, so the router's "
                          "client certificate requirements (clientAuth) are unknown")
        return base, None

    def _client_auth(self, name: str) -> tuple[tuple[str, ...], str | None]:
        """Client CA bundle a TLS options entry requires (empty: none), or a refusal reason.

        clientAuth is never dropped: a requirement that cannot be reproduced exactly (or more strictly) as one
        frontend client CA bundle file refuses every route that uses it. The emitter decides whether one
        listener-wide bundle preserves all routes' trust scopes.
        """
        if name not in self.client_auth_cache:
            verdict = self._classify_client_auth(name)
            self.client_auth_cache[name] = verdict
            if verdict[1]:
                self.report.error("traefik-client-auth", f"traefik tls options '{safe_label(name)}'",
                                  f"Client certificate requirements cannot be reproduced ({verdict[1]}). Every HTTPS "
                                  "router using these TLS options was refused (fail closed); clientAuth is never "
                                  "dropped.",
                                  "Use clientAuthType RequireAndVerifyClientCert with exactly one caFiles file path, "
                                  "or configure a dedicated Ferrum frontend with "
                                  "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH manually and validate it.")
        return self.client_auth_cache[name]

    def _classify_client_auth(self, name: str) -> tuple[tuple[str, ...], str | None]:
        tls_root = self.root.get("tls")
        options = mapping(tls_root).get("options")
        if (tls_root is not None and not isinstance(tls_root, dict)) or \
                (options is not None and not isinstance(options, dict)):
            return (), "the tls.options section is malformed"
        options = options or {}
        if name not in options:
            if name == DEFAULT_TLS_OPTIONS:
                self.builtin_default_tls_used = True  # Traefik's built-in default requests no client certificates
                return (), None
            return (), f"TLS options {safe_label(name, 48)} are undefined"
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

    def _client_auth_scopes(self) -> None:
        """Refuse HTTPS routes whose client certificate requirement depends on the connection's SNI.

        Traefik selects TLS options during the handshake by SNI host name, not per router. A router without a
        Host matcher gets whatever options the SNI selects (the default options for names no router claims), and
        a host name that routers map to different TLS options falls back to the default options. When the
        candidate options disagree on clientAuth, the requirement cannot be reproduced, so the route is refused.
        """
        specs = [spec for spec in self.plan.routes if id(spec) in self.tls_option_of and not spec.skip]
        options_by_host: dict[str, set[str]] = {}
        for spec in specs:
            name, sni_hosts = self.tls_option_of[id(spec)]
            for host in sni_hosts:
                options_by_host.setdefault(host, set()).add(name)
        for spec in specs:
            name, sni_hosts = self.tls_option_of[id(spec)]
            candidates = {name}
            if not sni_hosts:
                candidates.add(DEFAULT_TLS_OPTIONS)
                reason = ("the router has no Host matcher, so Traefik applied the TLS options selected by each "
                          "connection's SNI (the default options for unclaimed names)")
            else:
                conflicting = [host for host in sni_hosts if len(options_by_host.get(host, ())) > 1]
                if not conflicting:
                    continue
                for host in conflicting:
                    candidates |= options_by_host[host]
                candidates.add(DEFAULT_TLS_OPTIONS)
                reason = ("routers for the same host reference different TLS options, so Traefik fell back to the "
                          "default TLS options for that host")
            verdicts = set()
            for name in sorted(candidates):
                cas, problem = self._client_auth(name)
                verdicts.add((cas, problem is not None))
            if len(verdicts) > 1:
                spec.refuse(f"{reason}, and those TLS options differ in client certificate requirements "
                            "(clientAuth), so the requirement for this route cannot be reproduced")

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
                children = str_list(mapping(config).get("middlewares")) or []
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
        elif mw_type == "addPrefix":
            prefix = config.get("prefix")
            if not isinstance(prefix, str) or not prefix.startswith("/"):
                acc.refusals.append("addPrefix prefix must start with '/'")
            else:
                acc.add_prefix = prefix
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
            size = util.as_int(config.get("maxRequestBodyBytes"))
            if size and size > 0:
                acc.plugins.append(PluginSpec("request_size_limiting", {"max_bytes": size}, ref))
            self.report.info("traefik-buffering", ref, "Only maxRequestBodyBytes is migrated from buffering.")
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
        elif mw_type in ("compress", "contentType"):
            self.report.info("traefik-middleware-omitted", ref, f"{mw_type} is not migrated (no security impact).")
        elif mw_type in ("circuitBreaker", "errors", "passTLSClientCert"):
            self.report.warning("traefik-middleware-omitted", ref, f"{mw_type} is not migrated.")
        else:
            acc.refusals.append(f"middleware type {safe_label(mw_type, 40)} has no safe Ferrum equivalent")

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
            self.report.warning("traefik-mirroring", ref, "Mirrors are dropped; only the main service is migrated.")
            main = mapping(raw["mirroring"]).get("service")
            return self._service(str(main).partition("@")[0], depth + 1) if main else {"problems": ["mirroring without service"]}
        return {"problems": ["service type (failover or nested weighted) is not supported"]}

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
        if len(targets) == 1 and not health and not sticky:
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
