"""Kong Gateway declarative config (DB-less ``kong.yml`` / decK dump) to the IR.

The input is treated as data. Supported: services, routes (nested or
top-level), upstreams/targets, consumers with key-auth / JWT (HMAC) / ACL
credentials, and global/service/route plugins listed in ``docs/mappings.md``.
Live Kong databases are never contacted; export with ``deck gateway dump``
first.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any

from .. import util
from ..errors import InputError
from ..model import BackendRef, ConsumerSpec, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import contains_secret_reference, safe_label
from ..safe_load import load_structured
from .common import (SourceContext, check_route_budget, cors_config, mapping, query_rule, request_header_rule,
                     response_header_rule, seq, str_list)

PLATFORM = "kong"
HTTP_PROTOCOLS = {"http", "https", "grpc", "grpcs", "ws", "wss"}
TLS_PROTOCOLS = {"https", "grpcs", "wss"}
SERVICE_SCHEMES = {"http": "http", "grpc": "http", "ws": "http", "https": "https", "grpcs": "https", "wss": "https"}
OBSERVABILITY_PLUGINS = {
    "prometheus", "datadog", "statsd", "statsd-advanced", "file-log", "http-log", "tcp-log", "udp-log",
    "syslog", "loggly", "zipkin", "opentelemetry", "kafka-log", "splunk", "app-dynamics",
}
COSMETIC_PLUGINS = {
    "correlation-id": "Ferrum has a correlation_id plugin; configure it manually if needed",
    "proxy-cache": "response caching is not migrated; Ferrum has a response_caching plugin",
    "acme": "certificate automation is not migrated; Ferrum supports ACME via FERRUM_ACME_* settings",
    "response-ratelimiting": None,
}
KNOWN_TOP_LEVEL = {"_format_version", "_transform", "_info", "_workspace", "_konnect", "services", "routes",
                   "upstreams", "consumers", "plugins", "certificates", "ca_certificates", "snis", "vaults",
                   "consumer_groups"}
_REGEX_HINT = re.compile(r"[\\^$*+?()\[\]{}|]")
_KEY_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
# Ferrum authentication plugins this translator can emit (from key-auth, basic-auth and jwt).
AUTH_PLUGINS = frozenset({"key_auth", "basic_auth", "jwt_auth"})


def translate(text: str, fmt: str, ctx: SourceContext) -> Plan:
    documents = load_structured(text, fmt, ctx.limits, allow_multi=False)
    if not documents or not isinstance(documents[0], dict):
        raise InputError("Kong declarative config must be a mapping at the top level")
    return _Kong(documents[0], ctx).run()


def _ref_key(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("name", "id", "username", "custom_id"):
            if isinstance(value.get(key), str):
                return value[key]
    return None


class _Plugin:
    __slots__ = ("raw", "name", "level", "owner")

    def __init__(self, raw: dict, level: str, owner: str | None) -> None:
        self.raw = raw
        self.name = str(raw.get("name", ""))
        self.level = level
        self.owner = owner


class _Kong:
    def __init__(self, root: dict, ctx: SourceContext) -> None:
        self.root = root
        self.ctx = ctx
        self.report = ctx.report
        self.plan = Plan(platform=PLATFORM)
        self.services: list[tuple[str, dict]] = []
        self.service_map: dict[str, dict] = {}
        self.service_index: dict[str, str] = {}
        self.routes: list[tuple[dict, str | None, str]] = []
        self.route_index: dict[str, int] = {}
        self.upstreams: dict[str, dict] = {}
        self.plugins: list[_Plugin] = []
        self.plugins_by_owner: dict[tuple[str, str | None], list[_Plugin]] = {}
        self.consumer_quarantine: dict[str, list[str]] = {}
        self.jwt_algorithm = "HS256"
        self.format_version = "3.0"
        self.pretransformed = False

    # ------------------------------------------------------------ indexing

    def run(self) -> Plan:
        root = self.root
        version = root.get("_format_version")
        if version is None:
            self.report.info("kong-format-version", "-", "No _format_version; assuming Kong 3.x semantics.")
        elif str(version) not in ("1.1", "2.1", "3.0"):
            self.report.warning("kong-format-version", "-",
                                f"Unrecognized _format_version {safe_label(version, 16)}; assuming 3.x semantics.")
        else:
            self.format_version = str(version)
        for key in root:
            if key not in KNOWN_TOP_LEVEL:
                self.report.error("kong-entity-unsupported", f"kong {safe_label(key, 40)}",
                                  "This entity type is not migrated.", "Recreate it manually in Ferrum if needed.")
        if root.get("vaults"):
            self.report.error("kong-vaults", "kong vaults",
                              "Vault definitions are not migrated; any {vault://...} reference is refused.",
                              "Store secrets in Ferrum's supported secret sources (*_FILE, Vault, cloud managers).")
        for key in ("_workspace", "_konnect", "_info"):
            if key in root:
                self.report.info("kong-metadata", f"kong {key}", "Kong workspace/Konnect metadata is safely ignored.")
        if any(key in root for key in ("_info", "_konnect", "_workspace")):
            self.report.info("kong-input-flavor", "-",
                             "Input carries decK metadata (_info/_konnect/_workspace): treated as a decK dump. decK "
                             "dumps and DB-less kong.yml share one schema, so --from kong handles both; no extra "
                             "flag is needed.")
        else:
            self.report.info("kong-input-flavor", "-",
                             "No decK metadata found: treated as Kong declarative config (DB-less kong.yml or a decK "
                             "dump without metadata; both share one schema and are handled identically).")
        self.pretransformed = root.get("_transform") is False
        withheld_kinds = sum(len(seq(consumer.get(kind))) for consumer in seq(root.get("consumers"))
                             if isinstance(consumer, dict) for kind in ("keyauth_credentials", "jwt_secrets"))
        if self.pretransformed and not withheld_kinds:
            self.report.info("kong-transform", "-", "_transform: false (credential fields pre-transformed); this "
                             "input has no key-auth or JWT credentials.")
        elif self.pretransformed:
            self.report.error("kong-transform", "-",
                              "_transform: false declares credential fields as already transformed (stored values, "
                              "not what clients send). Key-auth keys and JWT secrets from this input are therefore "
                              "not migrated, even with --include-secrets (fail closed).",
                              "Issue new credentials in Ferrum.")
        self._index_upstreams()
        self._index_services()
        self._index_top_routes()
        consumers = self._index_consumers()
        self._index_top_plugins()
        self._decide_jwt_algorithm(consumers)
        self._translate_globals()
        check_route_budget(len(self.routes), self.ctx.limits)
        for index, (route, service_key, ref) in enumerate(self.routes):
            self._build_route(route, service_key, ref, index)
        check_route_budget(len(self.plan.routes), self.ctx.limits)
        self._check_regex_overlaps()
        self._build_consumers(consumers)
        self._note_certificates()
        return self.plan

    def _index_upstreams(self) -> None:
        for index, upstream in enumerate(seq(self.root.get("upstreams"))):
            if isinstance(upstream, dict) and isinstance(upstream.get("name"), str):
                self.upstreams[upstream["name"]] = upstream
            else:
                self.report.error("kong-upstream-invalid", f"kong upstream #{index + 1}", "Upstream without a name; skipped.")

    def _index_services(self) -> None:
        for index, service in enumerate(seq(self.root.get("services"))):
            if not isinstance(service, dict):
                raise InputError("every Kong service must be a mapping")
            name = service.get("name") or service.get("id") or f"service-{index + 1}"
            key = str(name)
            if key in self.service_map:
                raise InputError("duplicate Kong service name/id")
            self.services.append((key, service))
            self.service_map[key] = service
            for ident in (service.get("name"), service.get("id")):
                if isinstance(ident, str):
                    self.service_index[ident] = key
            for plugin in seq(service.get("plugins")):
                if isinstance(plugin, dict):
                    self._register_plugin(plugin, "service", key)
            for route in seq(service.get("routes")):
                if isinstance(route, dict):
                    self._register_route(route, key)

    def _register_route(self, route: dict, service_key: str | None) -> None:
        index = len(self.routes)
        label = route.get("name") or route.get("id") or f"route-{index + 1}"
        ref = f"kong route '{safe_label(label)}'"
        self.routes.append((route, service_key, ref))
        for ident in (route.get("name"), route.get("id")):
            if isinstance(ident, str):
                self.route_index[ident] = index
        for plugin in seq(route.get("plugins")):
            if isinstance(plugin, dict):
                self._register_plugin(plugin, "route", str(index))

    def _index_top_routes(self) -> None:
        for route in seq(self.root.get("routes")):
            if not isinstance(route, dict):
                raise InputError("every Kong route must be a mapping")
            service_ref = _ref_key(route.get("service"))
            service_key = self.service_index.get(service_ref) if service_ref else None
            self._register_route(route, service_key)

    def _register_plugin(self, raw: dict, level: str, owner: str | None) -> None:
        consumer = _ref_key(raw.get("consumer"))
        if consumer or raw.get("consumer_group"):
            target = consumer or "?"
            self.consumer_quarantine.setdefault(target, []).append(
                f"plugin {safe_label(raw.get('name'), 40)} is scoped to this consumer and has no Ferrum equivalent")
            return
        plugin = _Plugin(raw, level, owner)
        self.plugins.append(plugin)
        self.plugins_by_owner.setdefault((level, owner), []).append(plugin)

    def _index_top_plugins(self) -> None:
        for raw in seq(self.root.get("plugins")):
            if not isinstance(raw, dict):
                raise InputError("every Kong plugin must be a mapping")
            route_ref = _ref_key(raw.get("route"))
            service_ref = _ref_key(raw.get("service"))
            if raw.get("consumer") or raw.get("consumer_group"):
                self._register_plugin(raw, "consumer", None)
            elif route_ref is not None:
                if route_ref not in self.route_index:
                    self.report.error("kong-plugin-orphan", f"kong plugin {safe_label(raw.get('name'), 40)}",
                                      "Plugin references an unknown route; ignored.")
                    continue
                self._register_plugin(raw, "route", str(self.route_index[route_ref]))
            elif service_ref is not None:
                if service_ref not in self.service_index:
                    self.report.error("kong-plugin-orphan", f"kong plugin {safe_label(raw.get('name'), 40)}",
                                      "Plugin references an unknown service; ignored.")
                    continue
                self._register_plugin(raw, "service", self.service_index[service_ref])
            else:
                self._register_plugin(raw, "global", None)

    # ------------------------------------------------------------ consumers

    def _index_consumers(self) -> list[dict]:
        consumers = []
        for index, consumer in enumerate(seq(self.root.get("consumers"))):
            if not isinstance(consumer, dict):
                raise InputError("every Kong consumer must be a mapping")
            consumers.append(consumer)
            for plugin in seq(consumer.get("plugins")):
                if isinstance(plugin, dict):
                    key = consumer.get("username") or consumer.get("custom_id") or str(index)
                    self.consumer_quarantine.setdefault(str(key), []).append(
                        f"plugin {safe_label(plugin.get('name'), 40)} is scoped to this consumer and has no Ferrum "
                        "equivalent")
        for group in seq(self.root.get("consumer_groups")):
            if not isinstance(group, dict):
                continue
            name = safe_label(group.get("name"))
            if group.get("plugins"):
                for member in seq(group.get("consumers")):
                    key = _ref_key(member)
                    if key:
                        self.consumer_quarantine.setdefault(key, []).append(
                            f"consumer group {name} carries plugin overrides")
            self.report.error("kong-consumer-group", f"kong consumer_group {name}",
                              "Consumer groups are not migrated; members with group plugin overrides are "
                              "quarantined (credentials withheld).")
        for consumer in consumers:
            for group in seq(consumer.get("groups")):
                key = consumer.get("username") or consumer.get("custom_id")
                if key:
                    self.consumer_quarantine.setdefault(str(key), []).append(
                        f"member of consumer group {safe_label(_ref_key(group))}")
        return consumers

    def _decide_jwt_algorithm(self, consumers: list[dict]) -> None:
        algorithms = Counter()
        for consumer in consumers:
            for cred in seq(consumer.get("jwt_secrets")):
                if isinstance(cred, dict):
                    algorithm = str(cred.get("algorithm") or "HS256")
                    if algorithm in ("HS256", "HS384", "HS512"):
                        algorithms[algorithm] += 1
        if algorithms:
            self.jwt_algorithm = sorted(algorithms.items(), key=lambda item: (-item[1], item[0]))[0][0]

    def _build_consumers(self, consumers: list[dict]) -> None:
        identities: Counter = Counter()
        for consumer in consumers:
            for key in ("username", "custom_id", "id"):
                if isinstance(consumer.get(key), str):
                    identities[consumer[key]] += 1
        for index, consumer in enumerate(consumers):
            username = consumer.get("username")
            custom_id = consumer.get("custom_id")
            if not isinstance(username, str) and not isinstance(custom_id, str):
                self.report.error("kong-consumer-invalid", f"kong consumer #{index + 1}",
                                  "Consumer without username or custom_id; skipped.")
                continue
            key = username if isinstance(username, str) else custom_id
            ref = f"kong consumer '{safe_label(key)}'"
            spec = ConsumerSpec(ref=ref, key=key, username=key,
                                custom_id=custom_id if isinstance(custom_id, str) else None)
            for acl in seq(consumer.get("acls")):
                group = acl.get("group") if isinstance(acl, dict) else None
                if isinstance(group, str):
                    spec.acl_groups.append(group)
            for marker in (username, custom_id, consumer.get("id")):
                if isinstance(marker, str) and marker in self.consumer_quarantine:
                    spec.quarantined.extend(self.consumer_quarantine[marker])
            for cred in seq(consumer.get("keyauth_credentials")):
                value = cred.get("key") if isinstance(cred, dict) else None
                if self.pretransformed:
                    continue  # reported once by run(); stored values are never reused as credentials
                if not isinstance(value, str) or contains_secret_reference(value):
                    self.report.error("kong-keyauth-unreadable", ref,
                                      "A key-auth credential has no plaintext key (hashed or vault reference); "
                                      "not migrated.", "Issue a new key in Ferrum.")
                    continue
                if isinstance(cred, dict) and cred.get("ttl"):
                    self.report.warning("kong-keyauth-ttl", ref,
                                        "Key-auth credential TTLs are not supported; the key does not expire in Ferrum.")
                if self.ctx.include_secrets:
                    spec.keyauth.append(value)
                else:
                    spec.withheld_secrets += 1
            self._consumer_jwt(consumer, spec, identities)
            if seq(consumer.get("basicauth_credentials")):
                self.report.error("kong-basicauth-credentials", ref,
                                  f"{len(seq(consumer.get('basicauth_credentials')))} basic-auth credential(s) not "
                                  "migrated: Kong password hashes cannot be converted to Ferrum's hmac_sha256 format.",
                                  "Set new passwords as hmac_sha256 hashes keyed by FERRUM_BASIC_AUTH_HMAC_SECRET.")
            for kind, label in (("hmacauth_credentials", "HMAC"), ("oauth2_credentials", "OAuth2"),
                                ("mtls_auth_credentials", "mTLS")):
                if seq(consumer.get(kind)):
                    self.report.error("kong-credentials-unsupported", ref,
                                      f"{label} credentials are not migrated (semantics differ in Ferrum).",
                                      "Recreate this authentication method manually.")
            if spec.quarantined:
                self.report.error("kong-consumer-quarantined", ref,
                                  "Consumer quarantined: " + "; ".join(spec.quarantined) + ". Its credentials are "
                                  "withheld so it cannot authenticate with weaker policy.")
            self.plan.consumers.append(spec)

    def _consumer_jwt(self, consumer: dict, spec: ConsumerSpec, identities: Counter) -> None:
        if self.pretransformed:
            return  # reported once by run(); stored values are never reused as credentials
        # Kong binds each credential's key (the token's key claim) to that credential's own secret. Ferrum's
        # jwt_auth resolves the consumer from the claim and then accepts a signature from ANY of that consumer's
        # JWT secrets, so it cannot bind a key to one individual credential. Collect first, decide below.
        candidates: list[tuple[str, str]] = []
        for cred in seq(consumer.get("jwt_secrets")):
            if not isinstance(cred, dict):
                continue
            algorithm = str(cred.get("algorithm") or "HS256")
            secret = cred.get("secret")
            key = cred.get("key")
            if algorithm not in ("HS256", "HS384", "HS512") or not isinstance(secret, str) \
                    or contains_secret_reference(secret):
                self.report.error("kong-jwt-credential", spec.ref,
                                  "A JWT credential uses an asymmetric algorithm or has no plaintext secret; "
                                  "Ferrum jwt_auth verifies HMAC secrets only.",
                                  "Use Ferrum's jwks_auth plugin for asymmetric tokens.")
                continue
            if algorithm != self.jwt_algorithm:
                self.report.error("kong-jwt-algorithm", spec.ref,
                                  f"A JWT credential uses {algorithm} but the migrated jwt_auth plugin pins "
                                  f"{self.jwt_algorithm}; not migrated.")
                continue
            if not isinstance(key, str):
                self.report.error("kong-jwt-credential", spec.ref, "A JWT credential has no key; not migrated.")
                continue
            candidates.append((key, secret))
        if len(candidates) > 1:
            self.report.error("kong-jwt-multiple-credentials", spec.ref,
                              f"The consumer has {len(candidates)} HMAC JWT credentials. Kong only accepts a token "
                              "signed with the secret of the credential its key claim names; Ferrum would accept a "
                              "signature from any of the consumer's secrets for every key, merging the credentials' "
                              "scopes. None of them was migrated (fail closed).",
                              "Issue one new random HMAC secret (at least 32 characters) for this consumer in Ferrum, "
                              "or split the credentials into separate consumers in the source and convert again. "
                              "Do not reuse the old secrets, and keep the old credentials active in the source until "
                              "clients have switched.")
            return
        if not candidates:
            return
        # Even a single credential is not portable. Kong selects the credential by its own `key` (read from the
        # configured claim, or the token header), so only that exact value verifies against this secret. Ferrum
        # resolves the claim value against every consumer alias it indexes (username, id and custom_id) and then
        # accepts the consumer-wide JWT secret, so tokens naming another alias of the consumer would verify too.
        # No one-to-one selector contract between a Kong credential key and a Ferrum secret is verified, so the
        # secret is never written (not even with --include-secrets) and the consumer is not re-keyed for it.
        # The consumer, its other credentials and the route's jwt_auth protection are still migrated, so JWT
        # authentication fails closed until a new secret is issued in Ferrum.
        self.report.error("kong-jwt-credential-withheld", spec.ref,
                          "The consumer's HMAC JWT credential was not migrated. Kong only accepts a token whose key "
                          "claim equals this credential's key, while Ferrum resolves the claim against every alias "
                          "of a consumer (username, id, custom_id) and accepts the consumer-wide secret, so the "
                          "credential's selector cannot be reproduced one-to-one. Routes keep jwt_auth, so JWT "
                          "authentication for this consumer fails closed (fail closed).",
                          "Issue a new random HMAC secret (at least 32 characters) for this consumer in Ferrum and "
                          "have clients sign tokens whose configured identity claim names exactly this consumer. "
                          "Do not reuse the old secret, and keep the Kong credential active until clients have "
                          "switched.")

    # -------------------------------------------------------------- plugins

    def _translate_globals(self) -> None:
        for plugin in self.plugins:
            if plugin.level != "global" or plugin.raw.get("enabled") is False:
                continue
            ref = f"kong global plugin {safe_label(plugin.name, 40)}"
            outcome = self._translate_plugin(plugin, ref)
            if outcome[0] == "plugin":
                self.plan.global_plugins.append(outcome[1])
            elif outcome[0] == "termination":
                self.plan.global_plugins.append(PluginSpec("request_termination", outcome[1], ref))
            elif outcome[0] == "refuse":
                self.plan.global_refusals.append(f"{plugin.name}: {outcome[1]}")
                self.report.error("kong-plugin-refused", ref, f"Not translatable: {outcome[1]}. Every route is "
                                  "refused because this plugin applied globally.")

    def _translate_plugin(self, plugin: _Plugin, ref: str) -> tuple:
        raw = plugin.raw
        name = plugin.name
        config = raw.get("config") or {}
        if not isinstance(config, dict):
            return ("refuse", "plugin config is not a mapping")
        if contains_secret_reference(config):
            return ("refuse", "plugin config references a vault secret")
        if raw.get("ordering"):
            self.report.warning("kong-plugin-ordering", ref, "Dynamic plugin ordering is not migrated; Ferrum "
                                "uses its fixed priority order.")
        if name in OBSERVABILITY_PLUGINS:
            self.report.info("kong-plugin-observability", ref,
                             "Observability plugin omitted; configure Ferrum logging/metrics plugins separately.")
            return ("omit",)
        handler = _PLUGIN_HANDLERS.get(name)
        if handler is None:
            if name in COSMETIC_PLUGINS and COSMETIC_PLUGINS[name]:
                self.report.warning("kong-plugin-omitted", ref, f"Omitted: {COSMETIC_PLUGINS[name]}.")
                return ("omit",)
            return ("refuse", f"plugin {safe_label(name, 40)} has no safe Ferrum equivalent")
        return handler(self, config, ref)

    def _effective_plugins(self, route_index: int, service_key: str | None) -> tuple[list[PluginSpec], dict | None, list[str]]:
        by_name: dict[str, tuple[_Plugin, str]] = {}
        if service_key is not None:
            for plugin in self.plugins_by_owner.get(("service", service_key), []):
                if plugin.raw.get("enabled") is not False:
                    by_name.setdefault(plugin.name, (plugin, "service"))
        for plugin in self.plugins_by_owner.get(("route", str(route_index)), []):
            if plugin.raw.get("enabled") is not False:
                by_name[plugin.name] = (plugin, "route")
        plugins: list[PluginSpec] = []
        refusals: list[str] = []
        termination = None
        for name, (plugin, level) in by_name.items():
            ref = f"kong {level} plugin {safe_label(name, 40)}"
            outcome = self._translate_plugin(plugin, ref)
            if outcome[0] == "plugin":
                spec = outcome[1]
                if level == "service":
                    spec.shared_key = f"service-{service_key}"
                plugins.append(spec)
            elif outcome[0] == "termination":
                termination = outcome[1]
            elif outcome[0] == "refuse":
                refusals.append(f"{level} plugin {safe_label(name, 40)}: {outcome[1]}")
        return plugins, termination, refusals

    def _auth_composition(self, plugins: list[PluginSpec], ref: str) -> str | None:
        """Refusal reason when a route's effective policy combines several authentication methods.

        The effective Ferrum chain is the route/service plugins plus every global plugin whose name no scoped
        plugin replaces (Ferrum: scoped plugins replace global plugins of the same name; Kong: the most specific
        plugin of a name wins). One method is supported as before. Several methods are not: Kong requires all of
        them (or accepts any one when ``anonymous`` is set) and authenticates the consumer of the plugin that runs
        last, while Ferrum's default single auth mode commits the first accepted principal (and its multi mode is
        first-success), so the consumer that later policy (ACL, consumer rate limits) sees, and which methods are
        actually required, are not proven equivalent. Withholding one method's credentials does not make the
        composition safe while another method still migrates, so the route is refused before it becomes live.
        """
        methods = sorted(({plugin.name for plugin in plugins} | {plugin.name for plugin in self.plan.global_plugins})
                         & AUTH_PLUGINS)
        if len(methods) < 2:
            return None
        self.report.error("kong-auth-composition", ref,
                          f"The route's effective policy (global, service and route plugins together) combines "
                          f"{len(methods)} authentication methods ({', '.join(methods)}). Kong requires every one of "
                          "them (or any one when anonymous is configured) and identifies the consumer of the plugin "
                          "that runs last, while Ferrum commits the first accepted principal, so the required methods "
                          "and the consumer seen by later policy cannot be proven equivalent. The route was refused "
                          "(fail closed).",
                          "Recreate the route in Ferrum with one authentication method (or an explicitly reviewed "
                          "auth_mode), then validate it before serving traffic.")
        return ("the effective policy combines several authentication methods (" + ", ".join(methods) + "), whose "
                "composition and consumer selection cannot be proven equivalent in Ferrum")

    # --------------------------------------------------------------- routes

    def _service_backend(self, service_key: str, ref: str) -> dict:
        service = self.service_map[service_key]
        result: dict[str, Any] = {"problems": []}
        url = service.get("url")
        defaults = {"http": 80, "https": 443, "grpc": 80, "grpcs": 443, "ws": 80, "wss": 443}
        if isinstance(url, str):
            try:
                protocol, host, port, path = util.split_url(url, defaults)
            except util.UrlProblem as exc:
                result["problems"].append(f"service url: {exc}")
                return result
        else:
            protocol = str(service.get("protocol") or "http")
            host = service.get("host")
            port = util.parse_port(service.get("port")) or (443 if protocol in TLS_PROTOCOLS else 80)
            path = service.get("path") or ""
        scheme = SERVICE_SCHEMES.get(protocol)
        if scheme is None:
            result["problems"].append(f"service protocol {safe_label(protocol, 16)} is not HTTP")
            return result
        if not isinstance(host, str):
            result["problems"].append("service has no host")
            return result
        if contains_secret_reference(host):
            result["problems"].append("service host is a vault reference")
            return result
        tls = TlsSpec(verify=service.get("tls_verify") is True)
        if scheme == "https" and service.get("ca_certificates"):
            # The service names a restricted backend trust set. Its PEM material is never copied, so the only
            # emittable alternative would be Ferrum's default system trust store, which trusts more issuers.
            # Refuse instead of silently widening backend trust.
            result["problems"].append("service ca_certificates restrict backend TLS trust to specific CAs that are "
                                      "not copied; Ferrum would fall back to its default trust store")
            self.report.error("kong-ca-certificates", ref,
                              "The service restricts backend TLS trust to its ca_certificates. CA certificate "
                              "material is never copied, and falling back to Ferrum's default system trust store "
                              "would trust more issuers than the source, so routes using this service were refused "
                              "(fail closed).",
                              "Provision those CA certificates manually as a PEM file on the Ferrum host, set "
                              "backend_tls_server_ca_cert_path on the recreated proxy or upstream, and validate before "
                              "serving traffic.")
        if service.get("client_certificate"):
            self.report.error("kong-client-certificate", ref,
                              "The service presented a client certificate (mTLS); key material is never migrated, "
                              "so backend requests fail closed until a client cert/key path is configured.")
        if host in self.upstreams:
            result["backend"] = BackendRef(scheme=scheme, upstream_key=self._upstream_key(host, tls))
        else:
            result["backend"] = BackendRef(scheme=scheme, host=host, port=port, tls=tls)
        result["path"] = path if isinstance(path, str) and path not in ("", "/") else None
        for field_name, attr in (("connect_timeout", "connect"), ("read_timeout", "read"), ("write_timeout", "write")):
            value = util.as_int(service.get(field_name))
            if value is not None:
                result[attr] = value
        retries = util.as_int(service.get("retries"))
        if retries:
            result["retry"] = {"max_retries": min(retries, util.MAX_RETRIES), "retry_on_connect_failure": True,
                               "retryable_status_codes": []}
        return result

    def _upstream_key(self, name: str, tls: TlsSpec) -> str:
        key = f"{name}|{tls.key()}"
        if key in self.plan.upstreams:
            return key
        raw = self.upstreams[name]
        ref = f"kong upstream '{safe_label(name)}'"
        spec = UpstreamSpec(key=key, name=name, ref=ref, tls=tls)
        for target in seq(raw.get("targets")):
            if not isinstance(target, dict):
                continue
            weight = util.as_int(target.get("weight"))
            weight = 100 if weight is None else weight
            if weight <= 0:
                continue
            parsed = util.split_host_port(str(target.get("target", "")), 8000)
            if parsed is None:
                self.report.error("kong-target-invalid", ref, "A target is not host[:port]; skipped.")
                continue
            spec.targets.append(Target(parsed[0], parsed[1], weight))
        algorithm = str(raw.get("algorithm") or "round-robin")
        mapped = {"round-robin": "round_robin", "consistent-hashing": "consistent_hashing",
                  "least-connections": "least_connections", "latency": "least_latency"}.get(algorithm)
        if mapped is None:
            self.report.warning("kong-lb-algorithm", ref, "Load-balancing algorithm has no equivalent; using round robin.")
            mapped = "round_robin"
        spec.algorithm = mapped
        if mapped == "consistent_hashing":
            hash_on = raw.get("hash_on") or "none"
            if hash_on == "ip":
                spec.hash_on = "ip"
            elif hash_on == "header" and isinstance(raw.get("hash_on_header"), str):
                spec.hash_on = f"header:{raw['hash_on_header'].lower()}"
            elif hash_on == "cookie" and isinstance(raw.get("hash_on_cookie"), str):
                spec.hash_on = f"cookie:{raw['hash_on_cookie']}"
                spec.hash_on_cookie_config = {"path": raw.get("hash_on_cookie_path") or "/"}
            else:
                self.report.warning("kong-hash-on", ref,
                                    "hash_on source has no equivalent; using round robin (stickiness lost).")
                spec.algorithm = "round_robin"
        if raw.get("host_header"):
            self.report.warning("kong-host-header", ref, "Upstream host_header is not migrated; Ferrum sends the "
                                "selected target's authority.")
        spec.health_checks = self._health_checks(raw, ref)
        self.plan.upstreams[key] = spec
        return key

    def _health_checks(self, raw: dict, ref: str) -> dict | None:
        checks = mapping(raw.get("healthchecks"))
        result: dict[str, Any] = {}
        active = mapping(checks.get("active"))
        healthy = mapping(active.get("healthy"))
        unhealthy = mapping(active.get("unhealthy"))
        interval = util.as_int(healthy.get("interval")) or util.as_int(unhealthy.get("interval")) or 0
        if interval > 0:
            probe = {"http": "http", "https": "http", "tcp": "tcp", "grpc": "grpc", "grpcs": "grpc"}.get(
                str(active.get("type") or "http"), "http")
            entry: dict[str, Any] = {
                "http_path": active.get("http_path") if isinstance(active.get("http_path"), str) else "/",
                "interval_seconds": interval,
                "timeout_ms": int(float(active.get("timeout", 1) or 1) * 1000),
                "healthy_threshold": max(1, util.as_int(healthy.get("successes")) or 1),
                "unhealthy_threshold": max(1, util.as_int(unhealthy.get("http_failures"))
                                           or util.as_int(unhealthy.get("tcp_failures")) or 1),
                "probe_type": probe,
            }
            if str(active.get("type")) in ("https", "grpcs"):
                entry["use_tls"] = True
            statuses = healthy.get("http_statuses")
            if isinstance(statuses, list) and all(isinstance(code, int) for code in statuses) and statuses:
                entry["healthy_status_codes"] = statuses
            result["active"] = entry
        passive = mapping(mapping(checks.get("passive")).get("unhealthy"))
        failures = max(util.as_int(passive.get("http_failures")) or 0, util.as_int(passive.get("tcp_failures")) or 0,
                       util.as_int(passive.get("timeouts")) or 0)
        if failures > 0:
            entry = {"unhealthy_threshold": min(failures, 1000)}
            statuses = passive.get("http_statuses")
            if isinstance(statuses, list) and all(isinstance(code, int) for code in statuses) and statuses:
                entry["unhealthy_status_codes"] = statuses
            result["passive"] = entry
        if result:
            self.report.warning("kong-health-checks", ref, "Health checks were mapped approximately (thresholds, "
                                "intervals and status lists); ejection timing differs from Kong.")
        return result or None

    def _build_route(self, route: dict, service_key: str | None, ref: str, index: int) -> None:
        name = str(route.get("name") or route.get("id") or f"route-{index + 1}")
        protocols = str_list(route.get("protocols")) or ["http", "https"]
        if not all(protocol in HTTP_PROTOCOLS for protocol in protocols):
            skipped = RouteSpec(ref=ref, name=name, skip=True, skip_reason="stream route")
            self.plan.routes.append(skipped)
            self.report.error("kong-stream-route", ref, "TCP/TLS/UDP routes are not migrated (HTTP only).",
                              "Configure a Ferrum stream proxy (tcp/tcps/udp/dtls) manually.")
            return
        requires_tls = all(protocol in TLS_PROTOCOLS for protocol in protocols)
        # Kong matches one route set on its plaintext and its TLS proxy listeners, filtered by the route's protocols.
        frontends = frozenset(("https" if protocol in TLS_PROTOCOLS else "http") for protocol in protocols)
        hosts = str_list(route.get("hosts"))
        methods = str_list(route.get("methods"))
        paths = str_list(route.get("paths"))
        extra = []
        if route.get("headers"):
            extra.append("header matchers")
        if route.get("snis"):
            extra.append("SNI matchers")
        if route.get("expression"):
            extra.append("an expressions-router expression")
        if route.get("sources") or route.get("destinations"):
            extra.append("source/destination matchers")
        if hosts is None or methods is None or paths is None:
            extra.append("hosts/methods/paths with unexpected types")
            hosts, methods, paths = hosts or [], methods or [], paths or []
        plugins, termination, plugin_refusals = self._effective_plugins(index, service_key)
        auth_composition = None if termination is not None else self._auth_composition(plugins, ref)
        backend_info: dict[str, Any] = {"problems": []}
        if termination is None:
            if service_key is None:
                backend_info["problems"].append("route has no service")
            else:
                backend_info = self._service_backend(service_key, f"kong service '{safe_label(service_key)}'")
        strip = route.get("strip_path", True) is not False
        preserve = route.get("preserve_host") is True
        if route.get("path_handling") == "v1":
            self.report.info("kong-path-handling", ref, "path_handling v1 slash-joining is approximated by Ferrum's "
                             "backend_path composition; verify forwarded paths.")
        entries: list[str | None] = list(paths) if paths else [None]
        for number, path in enumerate(entries):
            spec = RouteSpec(ref=ref if len(entries) == 1 else f"{ref} path #{number + 1}",
                             name=name if number == 0 else f"{name}-{number + 1}")
            spec.hosts = list(hosts)
            spec.methods = list(methods) or None
            spec.requires_tls = requires_tls
            spec.protocols = frontends
            spec.strip = strip
            spec.preserve_host = preserve
            if path is None:
                if hosts:
                    spec.kind, spec.path = "hostonly", None
                else:
                    spec.kind, spec.path = "prefix", "/"
            elif path.startswith("~"):
                pattern = path[1:]
                if pattern.startswith("^"):
                    pattern = pattern[1:]
                if pattern.endswith("$") and not pattern.endswith("\\$"):
                    pattern = pattern[:-1]
                else:
                    pattern += ".*"
                spec.kind, spec.path = "regex", pattern
                if strip:
                    spec.refuse("regex path with strip_path=true: Ferrum strips the whole regex match")
            elif self.format_version != "3.0" and _REGEX_HINT.search(path):
                spec.kind, spec.path = "prefix", path
                spec.refuse("pre-3.0 implicit regex path is ambiguous")
                spec.extra_conditions = True
            else:
                spec.kind, spec.path = "prefix", path
                # Kong's traditional and traditional_compatible routers match literal paths as plain string
                # prefixes (/api also matches /apix); `expression` routes are refused above. Ferrum matches by
                # path segment, so the emitter reports siblings it cannot route equivalently.
                spec.report_prefix_siblings = True
            for condition in extra:
                spec.refuse(f"matches on {condition}, which Ferrum cannot express")
                spec.extra_conditions = True
            for refusal in plugin_refusals:
                spec.refuse(refusal)
            if auth_composition:
                spec.refuse(auth_composition)
            if termination is not None:
                spec.termination = termination
                if plugins:
                    self.report.warning("kong-termination-order", spec.ref,
                                        "Ferrum's request_termination runs before authentication, so callers get the "
                                        "termination response without authenticating first.")
            else:
                for problem in backend_info["problems"]:
                    spec.refuse(problem)
                spec.backend = backend_info.get("backend")
                spec.backend_path = backend_info.get("path")
                spec.connect_timeout_ms = backend_info.get("connect")
                spec.read_timeout_ms = backend_info.get("read")
                spec.write_timeout_ms = backend_info.get("write")
                spec.retry = backend_info.get("retry")
                spec.plugins = [PluginSpec(p.name, p.config, p.ref, p.shared_key) for p in plugins]
            self.plan.routes.append(spec)

    def _check_regex_overlaps(self) -> None:
        """Kong and Ferrum order regex vs prefix paths differently: refuse overlapping pairs."""
        from .. import matching
        regexes = [r for r in self.plan.routes if r.kind == "regex" and not r.skip]
        prefixes = [r for r in self.plan.routes if r.kind in ("prefix", "exact", "hostonly") and not r.skip]
        for regex in regexes:
            for other in prefixes:
                if matching.route_overlaps(regex, other):
                    reason = f"regex path overlaps {other.ref}; Kong and Ferrum order regex and prefix paths differently"
                    regex.refuse(reason)
                    regex.extra_conditions = True

    def _note_certificates(self) -> None:
        certificates = seq(self.root.get("certificates"))
        if certificates:
            names = []
            for cert in certificates:
                for sni in seq(cert.get("snis") if isinstance(cert, dict) else None):
                    label = sni.get("name") if isinstance(sni, dict) else sni
                    if isinstance(label, str):
                        names.append(safe_label(label, 64))
            self.plan.settings.frontend_tls_expected = True
            self.report.warning("kong-certificates", "kong certificates",
                                f"{len(certificates)} certificate(s) found (SNIs: {', '.join(names[:10]) or 'none'}). "
                                "Certificates and private keys are never copied or echoed.",
                                "Write the certificate/key to files and set FERRUM_FRONTEND_TLS_CERT_PATH/KEY_PATH.")
        if seq(self.root.get("ca_certificates")):
            self.report.info("kong-ca-certificates", "kong ca_certificates", "CA certificates are not copied.")


# ------------------------------------------------------------------ plugins

def _kong_key_auth(self: _Kong, config: dict, ref: str) -> tuple:
    names = str_list(config.get("key_names")) or ["apikey"]
    in_header = config.get("key_in_header", True) is not False
    in_query = config.get("key_in_query", True) is not False
    locations = []
    for name in names:
        if not _KEY_NAME.match(name):
            return ("refuse", "a key name is not a valid header/query token")
        if in_header:
            locations.append(f"header:{name}")
        if in_query:
            locations.append(f"query:{name}")
    if not locations:
        return ("refuse", "no key location is enabled")
    if len(locations) > 8:
        return ("refuse", "more than 8 key locations")
    if config.get("key_in_body"):
        self.report.warning("kong-key-in-body", ref, "Keys in request bodies are no longer accepted (stricter).")
    if config.get("anonymous"):
        self.report.warning("kong-anonymous", ref, "Anonymous fallback is not supported: requests without a valid "
                            "key are rejected instead of proceeding as the anonymous consumer (stricter).")
    value: Any = locations if len(locations) > 1 else locations[0]
    return ("plugin", PluginSpec("key_auth", {"key_location": value,
                                              "hide_credentials": config.get("hide_credentials") is True}, ref))


def _kong_basic_auth(self: _Kong, config: dict, ref: str) -> tuple:
    if config.get("anonymous"):
        self.report.warning("kong-anonymous", ref, "Anonymous fallback is not supported (stricter).")
    self.report.error("kong-basic-auth", ref, "basic_auth is emitted fail-closed: no Kong password can be "
                      "converted, so nobody can authenticate until new hmac_sha256 credentials exist.",
                      "Export FERRUM_BASIC_AUTH_HMAC_SECRET_FILE and create credentials in Ferrum.")
    return ("plugin", PluginSpec("basic_auth", {"hide_credentials": config.get("hide_credentials") is True}, ref))


def _kong_jwt(self: _Kong, config: dict, ref: str) -> tuple:
    if config.get("secret_is_base64"):
        return ("refuse", "secret_is_base64 is not supported")
    if util.as_int(config.get("maximum_expiration")):
        return ("refuse", "maximum_expiration (token lifetime cap) has no Ferrum equivalent")
    headers = [h.lower() for h in (str_list(config.get("header_names")) or ["authorization"])]
    if len(headers) != 1:
        return ("refuse", "several token headers cannot be expressed as one token_lookup")
    if config.get("uri_param_names", ["jwt"]) or config.get("cookie_names"):
        self.report.warning("kong-jwt-locations", ref, "Only the header token location is migrated; tokens in "
                            "query parameters or cookies are rejected (stricter).")
    claims = str_list(config.get("claims_to_verify")) or []
    plugin_config: dict[str, Any] = {
        "token_lookup": f"header:{'Authorization' if headers[0] == 'authorization' else headers[0]}",
        "consumer_claim_field": str(config.get("key_claim_name") or "iss"),
        "algorithm": self.jwt_algorithm,
        "require_exp": "exp" in claims,
    }
    if "nbf" in claims:
        plugin_config["require_nbf"] = True
    if config.get("anonymous"):
        self.report.warning("kong-anonymous", ref, "Anonymous fallback is not supported (stricter).")
    self.report.info("kong-jwt", ref, "Ferrum validates exp/nbf whenever present, even if Kong did not verify them.")
    return ("plugin", PluginSpec("jwt_auth", plugin_config, ref))


def _kong_acl(self: _Kong, config: dict, ref: str) -> tuple:
    allow = str_list(config.get("allow") or config.get("whitelist"))
    deny = str_list(config.get("deny") or config.get("blacklist"))
    if allow is None or deny is None:
        return ("refuse", "allow/deny lists have unexpected types")
    if config.get("include_consumer_groups"):
        return ("refuse", "include_consumer_groups relies on consumer groups, which are not migrated")
    plugin_config: dict[str, Any] = {}
    if allow:
        plugin_config["allowed_groups"] = allow
    if deny:
        plugin_config["disallowed_groups"] = deny
    if not plugin_config:
        return ("refuse", "ACL without allow or deny groups")
    if config.get("hide_groups_header") is False:
        self.report.info("kong-acl-header", ref, "Kong's X-Consumer-Groups upstream header is not reproduced.")
    return ("plugin", PluginSpec("access_control", plugin_config, ref))


def _kong_rate_limiting(self: _Kong, config: dict, ref: str) -> tuple:
    windows: dict[str, int] = {}
    for unit, field_name in (("second", "requests_per_second"), ("minute", "requests_per_minute"),
                             ("hour", "requests_per_hour")):
        value = config.get(unit)
        if value is None:
            continue
        number = util.as_int(value)
        if number is None or number <= 0:
            return ("refuse", f"{unit} limit is not a positive integer")
        windows[field_name] = number
    for unit in ("day", "month", "year"):
        if config.get(unit) is not None:
            return ("refuse", f"{unit} windows cannot be combined with Ferrum's preset windows")
    if not windows:
        return ("refuse", "no rate-limit window configured")
    limit_by = {"consumer": "consumer", "ip": "ip", "service": "service"}.get(str(config.get("limit_by") or "consumer"))
    if limit_by is None:
        return ("refuse", "limit_by credential/header/path/consumer-group has no Ferrum equivalent")
    policy = str(config.get("policy") or "local")
    if policy in ("cluster", "redis"):
        self.report.error("kong-rate-limit-policy", ref,
                          f"Kong '{policy}' policy counts across nodes; Ferrum enforces the limit per node unless "
                          "sync_mode: redis is configured (Redis settings and passwords are not migrated).",
                          "Run a single Ferrum node or configure rate_limiting sync_mode: redis.")
    plugin_config = {"limit_by": limit_by, "limits": [dict(scope="default", **windows)],
                     "expose_headers": config.get("hide_client_headers") is not True}
    return ("plugin", PluginSpec("rate_limiting", plugin_config, ref))


def _kong_cors(self: _Kong, config: dict, ref: str) -> tuple:
    origins = str_list(config.get("origins")) or ["*"]
    for origin in origins:
        if origin != "*" and _REGEX_HINT.search(origin.replace(".", "")):
            self.report.warning("kong-cors-regex", ref, "Regex CORS origins are not translated; CORS omitted, so "
                                "browsers block cross-origin calls (fail closed).")
            return ("omit",)
    if config.get("headers") is None:
        self.report.warning("kong-cors-headers", ref, "Kong reflected requested headers; Ferrum allows its default "
                            "header list (stricter).")
    built, problem = cors_config(origins, config.get("methods"), config.get("headers"), config.get("exposed_headers"),
                                 config.get("credentials"), config.get("max_age"), config.get("preflight_continue"),
                                 config.get("private_network"))
    if built is None:
        self.report.warning("kong-cors", ref, f"CORS omitted ({problem}); browsers block cross-origin calls.")
        return ("omit",)
    if origins == ["*"] and config.get("credentials"):
        self.report.warning("kong-cors-credentials", ref, "Wildcard origins with credentials: Ferrum drops credentials "
                            "instead of reflecting every origin (stricter).")
    return ("plugin", PluginSpec("cors", built, ref))


def _kong_ip_restriction(self: _Kong, config: dict, ref: str) -> tuple:
    plugin_config: dict[str, Any] = {}
    for source_keys, target in ((("allow", "whitelist"), "allow"), (("deny", "blacklist"), "deny")):
        values = None
        for key in source_keys:
            if config.get(key):
                values = str_list(config.get(key))
                break
        if values is None:
            if any(config.get(key) for key in source_keys):
                return ("refuse", f"{target} list has unexpected types")
            continue
        cidrs = []
        for value in values:
            cidr = util.canonical_cidr(value)
            if cidr is None:
                return ("refuse", "an IP/CIDR entry is not valid")
            cidrs.append(cidr)
        if cidrs:
            plugin_config[target] = cidrs
    if not plugin_config:
        return ("refuse", "no allow or deny entries")
    return ("plugin", PluginSpec("ip_restriction", plugin_config, ref))


def _kong_request_size(self: _Kong, config: dict, ref: str) -> tuple:
    size = config.get("allowed_payload_size", 128)
    number = util.as_int(size)
    if number is None or number <= 0:
        return ("refuse", "allowed_payload_size is not a positive integer")
    unit = str(config.get("size_unit") or "megabytes")
    factor = {"megabytes": 1024 * 1024, "kilobytes": 1024, "bytes": 1}.get(unit)
    if factor is None:
        return ("refuse", "unknown size_unit")
    return ("plugin", PluginSpec("request_size_limiting", {"max_bytes": number * factor}, ref))


def _split_pair(entry: Any) -> tuple[str, str] | None:
    if not isinstance(entry, str) or ":" not in entry:
        return None
    name, _, value = entry.partition(":")
    return name, value


def _kong_request_transformer(self: _Kong, config: dict, ref: str) -> tuple:
    rules: list[dict] = []
    if config.get("http_method"):
        return ("refuse", "changing the HTTP method is not supported")
    for section in ("replace", "append"):
        block = mapping(config.get(section))
        if any(block.get(sub) for sub in ("headers", "querystring", "body", "uri")):
            return ("refuse", f"'{section}' operations have no exact Ferrum equivalent")
    for section in ("remove", "rename", "add"):
        if mapping(config.get(section)).get("body"):
            return ("refuse", "body transformations are not translated")
    for name in str_list(mapping(config.get("remove")).get("headers")) or []:
        rule, problem = request_header_rule("remove", name)
        if problem:
            return ("refuse", problem)
        rules.append(rule)
    for name in str_list(mapping(config.get("remove")).get("querystring")) or []:
        rule, problem = query_rule("remove", name)
        if problem:
            return ("refuse", problem)
        rules.append(rule)
    for target in ("headers", "querystring"):
        for entry in seq(mapping(config.get("rename")).get(target)):
            pair = _split_pair(entry)
            if pair is None:
                return ("refuse", "malformed rename entry")
            builder = request_header_rule if target == "headers" else query_rule
            rule, problem = builder("rename", pair[0], None, pair[1])
            if problem:
                return ("refuse", problem)
            rules.append(rule)
    for target in ("headers", "querystring"):
        for entry in seq(mapping(config.get("add")).get(target)):
            pair = _split_pair(entry)
            if pair is None:
                return ("refuse", "malformed add entry")
            if "$(" in pair[1]:
                return ("refuse", "Kong template values are not translated")
            builder = request_header_rule if target == "headers" else query_rule
            rule, problem = builder("add", pair[0], pair[1])
            if problem:
                return ("refuse", problem)
            rules.append(rule)
    if not rules:
        self.report.info("kong-transformer-empty", ref, "Request transformer had no effective rules; omitted.")
        return ("omit",)
    return ("plugin", PluginSpec("request_transformer", {"rules": rules}, ref))


def _kong_response_transformer(self: _Kong, config: dict, ref: str) -> tuple:
    rules: list[dict] = []
    dropped = []
    for section in ("replace", "append"):
        if any(mapping(config.get(section)).get(sub) for sub in ("headers", "json")):
            dropped.append(section)
    if any(mapping(config.get(section)).get("json") for section in ("remove", "rename", "add")):
        dropped.append("json body")
    for name in str_list(mapping(config.get("remove")).get("headers")) or []:
        rule, problem = response_header_rule("remove", name)
        if rule:
            rules.append(rule)
    for entry in seq(mapping(config.get("rename")).get("headers")):
        pair = _split_pair(entry)
        rule, problem = response_header_rule("rename", pair[0], None, pair[1]) if pair else (None, "bad")
        if rule:
            rules.append(rule)
        else:
            dropped.append("rename")
    for entry in seq(mapping(config.get("add")).get("headers")):
        pair = _split_pair(entry)
        rule, problem = response_header_rule("add", pair[0], pair[1]) if pair else (None, "bad")
        if rule and "$(" not in pair[1]:
            rules.append(rule)
        else:
            dropped.append("add")
    if dropped:
        self.report.warning("kong-response-transformer", ref,
                            "Some response transformations were not translated: " + ", ".join(sorted(set(dropped))) + ".")
    if not rules:
        return ("omit",)
    return ("plugin", PluginSpec("response_transformer", {"rules": rules}, ref))


def _kong_request_termination(self: _Kong, config: dict, ref: str) -> tuple:
    if config.get("trigger") or config.get("echo"):
        return ("refuse", "trigger/echo modes are not translated")
    status = util.as_int(config.get("status_code", 503)) or 503
    if not 200 <= status <= 599:
        return ("refuse", "status code outside 200-599")
    termination: dict[str, Any] = {"status_code": status}
    if isinstance(config.get("body"), str):
        termination["content_type"] = str(config.get("content_type") or "application/json")
        termination["body"] = config["body"]
    else:
        termination["content_type"] = "application/json"
        termination["message"] = str(config.get("message") or "Service unavailable")
    return ("termination", termination)


def _kong_redirect(self: _Kong, config: dict, ref: str) -> tuple:
    location = config.get("location")
    if config.get("keep_incoming_path") or not isinstance(location, str) or "$" in location:
        return ("refuse", "only static redirects are translated")
    status = util.as_int(config.get("status_code", 301)) or 301
    return ("termination", {"status_code": status, "headers": {"location": location}, "body": ""})


_PLUGIN_HANDLERS = {
    "key-auth": _kong_key_auth,
    "basic-auth": _kong_basic_auth,
    "jwt": _kong_jwt,
    "acl": _kong_acl,
    "rate-limiting": _kong_rate_limiting,
    "cors": _kong_cors,
    "ip-restriction": _kong_ip_restriction,
    "request-size-limiting": _kong_request_size,
    "request-transformer": _kong_request_transformer,
    "response-transformer": _kong_response_transformer,
    "request-termination": _kong_request_termination,
    "redirect": _kong_redirect,
}
