"""Envoy v3 static bootstrap (``static_resources``) HTTP proxying to the IR.

Supported: listeners with one filter chain and an inline ``route_config`` in the
HTTP connection manager, virtual hosts (domains), ordered routes (prefix, path,
safe_regex, path_separated_prefix), clusters with static/DNS endpoints, upstream
TLS from file paths, weighted clusters, prefix rewrites, timeouts, retries,
header add/remove, CORS and direct responses. Dynamic xDS (RDS/EDS/ADS) is not
read. HTTP filters other than router/cors/grpc_stats/health_check refuse every
route of their connection manager (fail closed).
"""

from __future__ import annotations

import re
from typing import Any

from .. import util
from ..errors import InputError
from ..model import BackendRef, HostScope, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from ..safe_load import load_structured
from .common import (SourceContext, apply_first_match_order, check_route_budget, choose_main_port, cors_config,
                     literal_value, mapping, merge_weighted_targets, request_header_rule, response_header_rule,
                     retry_from_policy, seq, split_csv, str_list)

PLATFORM = "envoy"
_REDIRECT_CODES = {"MOVED_PERMANENTLY": 301, "FOUND": 302, "SEE_OTHER": 303, "TEMPORARY_REDIRECT": 307,
                   "PERMANENT_REDIRECT": 308}


def _kind(item: Any) -> str:
    """Normalize a filter/transport identity from ``name`` or ``typed_config['@type']``."""
    item = mapping(item)
    type_url = str(mapping(item.get("typed_config")).get("@type", ""))
    name = str(item.get("name", ""))
    text = (type_url + " " + name).lower()
    for token, kind in (("http_connection_manager", "hcm"), ("filters.http.router", "router"),
                        ("router.v3.router", "router"), ("filters.http.cors", "cors"), ("cors.v3.cors", "cors"),
                        ("grpc_stats", "grpc_stats"), ("health_check", "health_check"),
                        ("filters.http.buffer", "buffer"), ("buffer.v3.buffer", "buffer"),
                        ("downstreamtlscontext", "tls"), ("upstreamtlscontext", "tls"),
                        ("transport_sockets.tls", "tls"), ("proxy_protocol", "proxy_protocol"),
                        ("tls_inspector", "tls_inspector"), ("http_inspector", "http_inspector"),
                        ("original_dst", "original_dst")):
        if token in text:
            return kind
    return name or type_url or "unknown"


class _Envoy:
    def __init__(self, root: dict, ctx: SourceContext) -> None:
        self.root = root
        self.ctx = ctx
        self.report = ctx.report
        self.plan = Plan(platform=PLATFORM)
        self.clusters: dict[str, dict] = {}

    def run(self) -> Plan:
        if self.root.get("dynamic_resources"):
            self.report.error("envoy-xds", "envoy dynamic_resources", "Dynamic xDS configuration is not read; only "
                              "static_resources are migrated.", "Export the effective configuration statically.")
        if "admin" in self.root:
            self.report.info("envoy-admin", "envoy admin", "The Envoy admin interface is not migrated; Ferrum's admin "
                             "API stays on loopback.")
        static = mapping(self.root.get("static_resources"))
        for cluster in seq(static.get("clusters")):
            if isinstance(cluster, dict) and isinstance(cluster.get("name"), str):
                if cluster["name"] in self.clusters:
                    raise InputError("duplicate Envoy cluster name")
                self.clusters[cluster["name"]] = cluster
        listeners = [l for l in seq(static.get("listeners")) if isinstance(l, dict)]
        infos = [self._listener_info(listener, index) for index, listener in enumerate(listeners)]
        self._elect_ports(infos)
        for info in infos:
            self._listener(info)
        check_route_budget(len(self.plan.routes), self.ctx.limits)
        return self.plan

    # -------------------------------------------------------------- listeners

    def _listener_info(self, listener: dict, index: int) -> dict:
        name = listener.get("name") or f"listener-{index + 1}"
        ref = f"envoy listener '{safe_label(name)}'"
        address = mapping(mapping(listener.get("address")).get("socket_address"))
        port = util.parse_port(address.get("port_value"))
        chains = [c for c in seq(listener.get("filter_chains")) if isinstance(c, dict)]
        tls = len(chains) == 1 and _kind(chains[0].get("transport_socket")) == "tls"
        addr = address.get("address")
        addr = None if addr in (None, "0.0.0.0", "::", "") else str(addr)
        return {"listener": listener, "ref": ref, "port": port, "tls": tls, "chains": chains, "addr": addr,
                "udp": str(address.get("protocol", "TCP")).upper() == "UDP"}

    def _elect_ports(self, infos: list[dict]) -> None:
        plain: dict[int, int] = {}
        tls: dict[int, int] = {}
        for info in infos:
            if info["port"] and not info["udp"]:
                bucket = tls if info["tls"] else plain
                bucket[info["port"]] = bucket.get(info["port"], 0) + 1
        self.plan.settings.main_http_port = choose_main_port(plain)
        self.plan.settings.main_https_port = choose_main_port(tls)
        addresses = {info["addr"] for info in infos}
        specific = {a for a in addresses if a}
        if specific and None not in addresses and len(specific) == 1:
            self.plan.settings.bind_address = next(iter(specific))
        self.bind_conflict = bool(specific) and (None in addresses or len(specific) > 1)

    def _listener(self, info: dict) -> None:
        ref, listener = info["ref"], info["listener"]
        settings = self.plan.settings
        if info["udp"] or info["port"] is None:
            self.report.error("envoy-listener-unsupported", ref, "UDP or port-less listeners are not migrated.")
            return
        if self.bind_conflict and info["addr"]:
            self.report.error("envoy-bind-address", ref, "Listener binds a specific address while others differ; "
                              "Ferrum binds one address and would expose it more widely. Skipped.")
            return
        for listener_filter in seq(listener.get("listener_filters")):
            kind = _kind(listener_filter)
            if kind == "proxy_protocol":
                settings.proxy_protocol = True
                self.report.warning("envoy-proxy-protocol", ref, "PROXY protocol is only suggested in ferrum.conf.")
            elif kind == "original_dst":
                self.report.error("envoy-original-dst", ref, "original_dst listeners are not migrated.")
                return
        if len(info["chains"]) != 1:
            self.report.error("envoy-filter-chains", ref, "Only listeners with exactly one filter chain are migrated.")
            return
        chain = info["chains"][0]
        if chain.get("filter_chain_match"):
            self.report.error("envoy-filter-chain-match", ref, "filter_chain_match (SNI/ALPN selection) is not "
                              "migrated; listener skipped.")
            return
        listen_port = None
        client_cas: list[str] = []
        client_ca_problem = None
        if info["tls"]:
            if info["port"] != settings.main_https_port:
                self.report.error("envoy-tls-port", ref, "TLS on a non-main port cannot be scoped reliably; skipped.")
                return
            # Only a listener that is actually migrated may contribute its client CA trust scope.
            client_cas, client_ca_problem = self._downstream_tls(
                mapping(mapping(chain.get("transport_socket")).get("typed_config")), ref)
        elif info["port"] != settings.main_http_port:
            listen_port = info["port"]
        filters = [f for f in seq(chain.get("filters")) if isinstance(f, dict)]
        hcms = [f for f in filters if _kind(f) == "hcm"]
        if len(hcms) != 1 or len(filters) != 1:
            self.report.error("envoy-network-filters", ref, "Only a single HTTP connection manager filter is "
                              "migrated (TCP proxying and other network filters are not).")
            return
        config = mapping(hcms[0].get("typed_config"))
        start = len(self.plan.routes)
        self._hcm(config, ref, listen_port, info["tls"])
        for route in self.plan.routes[start:]:
            route.client_cas = list(client_cas)
            if client_ca_problem:
                route.refuse(client_ca_problem)

    def _downstream_tls(self, config: dict, ref: str) -> tuple[list[str], str | None]:
        """Record frontend cert paths; return this listener's client CA scope or a refusal reason."""
        common = mapping(config.get("common_tls_context"))
        certs = seq(common.get("tls_certificates"))
        if certs:
            cert = mapping(mapping(certs[0]).get("certificate_chain"))
            key = mapping(mapping(certs[0]).get("private_key"))
            if isinstance(cert.get("filename"), str) and isinstance(key.get("filename"), str):
                self.plan.settings.frontend_cert_pairs.append((cert["filename"], key["filename"]))
            else:
                self.report.error("envoy-inline-tls", ref, "Inline or SDS certificate material is never migrated or "
                                  "echoed; write it to files and set FERRUM_FRONTEND_TLS_CERT_PATH/KEY_PATH.")
        elif common.get("tls_certificate_sds_secret_configs"):
            self.report.error("envoy-sds", ref, "SDS certificates are not migrated.")
        self.plan.settings.frontend_tls_expected = True
        validation = mapping(common.get("validation_context"))
        if not config.get("require_client_certificate"):
            return [], None
        ca = mapping(validation.get("trusted_ca"))
        # Only a bare file-path trusted_ca is reproducible: SAN/hash/SPKI pins, CRLs or custom validators
        # narrow who is trusted, and Ferrum's listener-wide bundle would accept every client of that CA.
        constraints = [key for key in validation if key != "trusted_ca"]
        if isinstance(ca.get("filename"), str) and not constraints:
            return [ca["filename"]], None
        self.report.error("envoy-client-ca", ref,
                          "The listener required client certificates, but its trust (inline, SDS or missing CA, or "
                          "extra validation constraints such as SAN, hash or SPKI pinning) cannot be reproduced by "
                          "Ferrum's frontend client CA bundle. Its routes were refused (fail closed).",
                          "Configure a Ferrum frontend dedicated to this trust boundary with a client CA file "
                          "(FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH), review the dropped constraints, and validate "
                          "it before serving traffic.")
        return [], "the listener's client certificate trust cannot be reproduced by Ferrum's frontend client CA bundle"

    # -------------------------------------------------------------------- HCM

    def _hcm(self, config: dict, ref: str, listen_port: int | None, tls: bool) -> None:
        if config.get("rds") or config.get("scoped_routes"):
            self.report.error("envoy-rds", ref, "RDS/scoped routes are dynamic and not migrated.")
            return
        if config.get("use_remote_address") or config.get("xff_num_trusted_hops"):
            self.report.warning("envoy-xff", ref, "Client-IP trust settings (use_remote_address/xff_num_trusted_hops) "
                                "are not migrated; configure FERRUM_TRUSTED_PROXIES.")
        cors_enabled = False
        filter_refusal = None
        buffer_limit = None
        for http_filter in seq(config.get("http_filters")):
            kind = _kind(http_filter)
            if mapping(http_filter).get("disabled"):
                continue
            if kind == "router":
                continue
            if kind == "cors":
                cors_enabled = True
            elif kind in ("grpc_stats", "health_check"):
                self.report.warning("envoy-http-filter-omitted", ref, f"HTTP filter {kind} is not migrated.")
            elif kind == "buffer":
                buffer_limit = util.as_int(mapping(mapping(http_filter).get("typed_config")).get("max_request_bytes"))
            else:
                filter_refusal = f"HTTP filter {safe_label(kind, 80)} has no safe Ferrum equivalent"
        route_config = mapping(config.get("route_config"))
        shared = {"request_add": seq(route_config.get("request_headers_to_add")),
                  "request_remove": seq(route_config.get("request_headers_to_remove")),
                  "response_add": seq(route_config.get("response_headers_to_add")),
                  "response_remove": seq(route_config.get("response_headers_to_remove")),
                  "typed_per_filter_config": mapping(route_config.get("typed_per_filter_config"))}
        for index, vhost in enumerate(seq(route_config.get("virtual_hosts"))):
            if isinstance(vhost, dict):
                self._vhost(vhost, index, ref, listen_port, tls, cors_enabled, filter_refusal, buffer_limit, shared)

    def _vhost(self, vhost: dict, index: int, listener_ref: str, listen_port: int | None, tls: bool,
               cors_enabled: bool, filter_refusal: str | None, buffer_limit: int | None, shared: dict) -> None:
        name = str(vhost.get("name") or f"vhost-{index + 1}")
        ref = f"envoy virtual_host '{safe_label(name)}' on {listener_ref}"
        domains = str_list(vhost.get("domains")) or []
        hosts: list[str] | None = []
        host_problem = None
        if "*" not in domains:
            for domain in domains:
                host = domain.lower()
                if ":" in host:
                    base, _, port_text = host.rpartition(":")
                    if util.parse_port(port_text) is None:
                        host_problem = "domain with an invalid port"
                        break
                    host = base
                if host.endswith("*") or ("*" in host and not host.startswith("*.")):
                    host_problem = "prefix/embedded wildcard domain"
                    break
                if host not in hosts:
                    hosts.append(host)
        if host_problem:
            self.report.error("envoy-domains", ref, f"Domains not representable ({host_problem}).")
            hosts = None
        requires_tls = tls or str(vhost.get("require_tls", "NONE")).upper() == "ALL"
        if not tls and str(vhost.get("require_tls", "NONE")).upper() == "EXTERNAL_ONLY":
            requires_tls = True
            self.report.warning("envoy-require-tls", ref, "require_tls EXTERNAL_ONLY is treated as HTTPS-only.")
        routes: list[RouteSpec] = []
        for route_index, raw in enumerate(seq(vhost.get("routes"))):
            if not isinstance(raw, dict):
                continue
            spec = self._route(raw, route_index, name, ref, hosts, listen_port, requires_tls, tls, cors_enabled,
                               vhost, shared)
            if filter_refusal:
                spec.refuse(filter_refusal)
            if buffer_limit and buffer_limit > 0 and not spec.termination:
                spec.plugins.append(PluginSpec("request_size_limiting", {"max_bytes": buffer_limit}, ref))
            routes.append(spec)
        if not tls and routes and all(getattr(r, "https_redirect", False) for r in routes):
            self.plan.settings.https_redirect_seen = True
            self.report.info("envoy-https-redirect", ref, "HTTP-to-HTTPS redirect virtual host: not emitted.")
            return
        for route in routes:
            if getattr(route, "https_redirect", False):
                # Keep it as a fail-closed placeholder so its traffic cannot fall through.
                route.skip = False
                route.skip_reason = ""
                route.refuse("https_redirect on a route mixed with forwarding routes")
        apply_first_match_order(routes, self.report)
        self.plan.routes.extend(routes)
        if hosts:
            self.plan.host_scopes.append(HostScope(ref, list(hosts), listen_port))

    # ------------------------------------------------------------------ routes

    def _route(self, raw: dict, index: int, vhost_name: str, vhost_ref: str, hosts: list[str] | None,
               listen_port: int | None, requires_tls: bool, tls: bool, cors_enabled: bool, vhost: dict,
               shared: dict) -> RouteSpec:
        name = str(raw.get("name") or f"{vhost_name}-route-{index + 1}")
        ref = f"envoy route '{safe_label(name)}' in {vhost_ref}"
        spec = RouteSpec(ref=ref, name=name, hosts=None if hosts is None else list(hosts),
                         listen_port=listen_port, requires_tls=requires_tls)
        if hosts is None:
            spec.extra_conditions = True
            spec.refuse("virtual host domains are not representable")
        match = mapping(raw.get("match"))
        if "prefix" in match:
            spec.kind, spec.path = "prefix", match.get("prefix") or "/"
            # `prefix` is a plain string prefix (/api also matches /apix); `path_separated_prefix` below is
            # segment-based like Ferrum and needs no sibling report.
            spec.report_prefix_siblings = True
        elif "path" in match:
            spec.kind, spec.path = "exact", match.get("path")
        elif "safe_regex" in match:
            spec.kind, spec.path = "regex", mapping(match.get("safe_regex")).get("regex")
        elif "path_separated_prefix" in match:
            spec.kind, spec.path = "prefix", match.get("path_separated_prefix")
            spec.prefix_semantics = "segment"
        else:
            spec.kind, spec.path = "prefix", "/"
            spec.path_ok = False
            spec.extra_conditions = True
            spec.refuse("route match type is not supported")
        if match.get("case_sensitive") is False:
            self.report.warning("envoy-case-insensitive", ref, "Case-insensitive matching becomes case-sensitive "
                                "(stricter).")
        for key in ("headers", "query_parameters", "grpc", "runtime_fraction", "tls_context", "dynamic_metadata",
                    "filter_state", "cel_expr"):
            if match.get(key):
                spec.extra_conditions = True
                spec.refuse(f"matches on {key}, which Ferrum cannot express")
        # Per-route/vhost filter config can re-enable an HCM filter marked `disabled: true` (for example an
        # authentication filter turned on for this route only). Migrating the route without it would skip
        # that policy, so any non-CORS per-filter config refuses the route.
        for source, label in ((raw, "route"), (vhost, "virtual host"), (shared, "route configuration")):
            per_filter = mapping(source.get("typed_per_filter_config"))
            others = [str(key) for key in per_filter if "cors" not in str(key).lower()]
            if others:
                names = ", ".join(safe_label(key, 80) for key in others[:3])
                spec.refuse(f"{label} typed_per_filter_config for HTTP filter(s) {names} can enable or change a "
                            "filter for this route, which is not migrated")
        if raw.get("direct_response") is not None:
            self._direct_response(spec, mapping(raw.get("direct_response")))
            return spec
        if raw.get("redirect") is not None:
            self._redirect(spec, mapping(raw.get("redirect")), tls)
            return spec
        action = raw.get("route")
        if not isinstance(action, dict):
            spec.refuse("route action is not a forwarding route")
            return spec
        self._action(spec, action, vhost, ref)
        self._headers(spec, raw, vhost, shared, ref)
        self._cors(spec, raw, vhost, cors_enabled, ref)
        return spec

    def _direct_response(self, spec: RouteSpec, response: dict) -> None:
        status = util.as_int(response.get("status"))
        body = mapping(response.get("body"))
        if status is None or not 200 <= status <= 599:
            spec.refuse("direct response status outside 200-599")
            return
        if body.get("filename") or body.get("inline_bytes"):
            spec.refuse("direct response bodies from files or bytes are not migrated")
            return
        text = body.get("inline_string", "")
        spec.termination = {"status_code": status, "content_type": "text/plain", "body": str(text)} \
            if status not in (204, 304) else {"status_code": status, "body": ""}

    def _redirect(self, spec: RouteSpec, redirect: dict, tls: bool) -> None:
        if redirect.get("https_redirect") or redirect.get("scheme_redirect") == "https":
            if not tls and not redirect.get("host_redirect") and not redirect.get("path_redirect"):
                spec.https_redirect = True  # type: ignore[attr-defined]
                spec.skip = True
                spec.skip_reason = "HTTPS redirect"
                return
        code = _REDIRECT_CODES.get(str(redirect.get("response_code", "MOVED_PERMANENTLY")))
        scheme = redirect.get("scheme_redirect") or ("https" if redirect.get("https_redirect") else None)
        host = redirect.get("host_redirect")
        path = redirect.get("path_redirect")
        if code is None or not (scheme and host and path):
            spec.refuse("only fully static redirects (scheme, host and path) are migrated")
            return
        spec.termination = {"status_code": code, "headers": {"location": f"{scheme}://{host}{path}"}, "body": ""}

    def _action(self, spec: RouteSpec, action: dict, vhost: dict, ref: str) -> None:
        hash_on = None
        for policy in seq(action.get("hash_policy")):
            policy = mapping(policy)
            if mapping(policy.get("header")).get("header_name"):
                hash_on = f"header:{str(policy['header']['header_name']).lower()}"
            elif mapping(policy.get("cookie")).get("name"):
                hash_on = f"cookie:{policy['cookie']['name']}"
            elif mapping(policy.get("connection_properties")).get("source_ip"):
                hash_on = "ip"
            break
        if isinstance(action.get("cluster"), str):
            backend = self._cluster(action["cluster"], hash_on)
        elif action.get("weighted_clusters"):
            backend = self._weighted(mapping(action["weighted_clusters"]), spec, hash_on)
        else:
            spec.refuse("route has no static cluster (cluster_header and others are not supported)")
            return
        for problem in backend["problems"]:
            spec.refuse(problem)
        spec.backend = backend.get("backend")
        spec.connect_timeout_ms = backend.get("connect")
        rewrite = action.get("prefix_rewrite")
        if isinstance(rewrite, str):
            if spec.kind == "regex":
                spec.refuse("prefix_rewrite on a regex route")
            else:
                spec.strip = True
                spec.backend_path = rewrite if rewrite not in ("", "/") else None
                if spec.kind == "exact":
                    self.report.warning("envoy-exact-rewrite", ref, "prefix_rewrite on an exact path: verify the "
                                        "forwarded path.")
        if action.get("regex_rewrite") or action.get("path_rewrite_policy"):
            spec.refuse("regex/path rewrite policies are not supported")
        if action.get("host_rewrite_header") or action.get("host_rewrite_path_regex"):
            spec.refuse("dynamic host rewrites are not supported")
        if action.get("auto_host_rewrite"):
            spec.preserve_host = False
        elif action.get("host_rewrite_literal"):
            spec.preserve_host = False
            self.report.warning("envoy-host-rewrite", ref, "A literal Host rewrite is not representable; Ferrum sends "
                                "the selected target's authority.")
        else:
            spec.preserve_host = True
        timeout = action.get("timeout")
        timeout_ms = 15_000 if timeout is None else util.proto_duration_ms(timeout)
        if timeout_ms == 0:
            timeout_ms = util.MAX_TIMEOUT_MS + 1
        spec.read_timeout_ms = timeout_ms
        retry = action.get("retry_policy") or vhost.get("retry_policy")
        if isinstance(retry, dict):
            config, notes = retry_from_policy(retry.get("retry_on"), retry.get("num_retries", 1))
            spec.retry = config
            for note in notes:
                self.report.warning("envoy-retry", ref, note)
        if action.get("request_mirror_policies"):
            self.report.warning("envoy-mirror", ref, "Request mirroring is dropped.")

    def _headers(self, spec: RouteSpec, raw: dict, vhost: dict, shared: dict, ref: str) -> None:
        request_rules: list[dict] = []
        response_rules: list[dict] = []
        sources = (shared, vhost, raw)
        for source in sources:
            for name in seq(source.get("request_remove") if source is shared else source.get("request_headers_to_remove")):
                rule, problem = request_header_rule("remove", name)
                request_rules.append(rule) if rule else spec.refuse(problem or "invalid header")
            for entry in seq(source.get("request_add") if source is shared else source.get("request_headers_to_add")):
                rule, problem = self._header_entry(entry, True)
                request_rules.append(rule) if rule else spec.refuse(problem or "invalid header")
            for name in seq(source.get("response_remove") if source is shared else source.get("response_headers_to_remove")):
                rule, _ = response_header_rule("remove", name)
                if rule:
                    response_rules.append(rule)
            for entry in seq(source.get("response_add") if source is shared else source.get("response_headers_to_add")):
                rule, problem = self._header_entry(entry, False)
                if rule:
                    response_rules.append(rule)
                else:
                    self.report.warning("envoy-response-header", ref, f"Response header not migrated ({problem}).")
        if request_rules:
            spec.plugins.append(PluginSpec("request_transformer", {"rules": request_rules}, ref))
        if response_rules:
            spec.plugins.append(PluginSpec("response_transformer", {"rules": response_rules}, ref))

    def _header_entry(self, entry: Any, request: bool) -> tuple[dict | None, str | None]:
        entry = mapping(entry)
        header = mapping(entry.get("header"))
        key, value = header.get("key"), header.get("value", "")
        action = entry.get("append_action")
        if action is None:
            append = entry.get("append")
            action = "APPEND_IF_EXISTS_OR_ADD" if append is None or append is True else "OVERWRITE_IF_EXISTS_OR_ADD"
        if not isinstance(value, str):
            return None, "header value is not a string"
        translated = _envoy_value(value)
        if translated is None:
            return None, "header value uses Envoy format specifiers Ferrum cannot reproduce"
        if action == "OVERWRITE_IF_EXISTS_OR_ADD":
            op = "update"
        elif action == "ADD_IF_ABSENT":
            op = "add"
        elif action == "APPEND_IF_EXISTS_OR_ADD" and not request:
            op = "add"
        else:
            return None, f"header action {safe_label(action, 40)} has no exact Ferrum equivalent"
        builder = request_header_rule if request else response_header_rule
        return builder(op, key, translated)

    def _cors(self, spec: RouteSpec, raw: dict, vhost: dict, enabled: bool, ref: str) -> None:
        policy = None
        for source in (raw, vhost):
            per_filter = mapping(source.get("typed_per_filter_config"))
            candidate = next((mapping(v) for k, v in per_filter.items() if "cors" in str(k).lower()), None)
            if candidate:
                policy = candidate
                break
            if mapping(source.get("cors")):
                policy = mapping(source.get("cors"))
                break
        if not policy:
            return
        if not enabled:
            self.report.info("envoy-cors-inactive", ref, "CORS policy present without the cors HTTP filter; ignored "
                             "(it had no effect in Envoy).")
            return
        origins = []
        for matcher in seq(policy.get("allow_origin_string_match")):
            matcher = mapping(matcher)
            if "exact" in matcher:
                origins.append({"exact": matcher["exact"]})
            elif "prefix" in matcher:
                origins.append({"prefix": matcher["prefix"]})
            elif "safe_regex" in matcher:
                origins.append({"regex": mapping(matcher["safe_regex"]).get("regex")})
            else:
                origins = []
                break
        max_age = policy.get("max_age")
        built, problem = cors_config(origins, split_csv(policy.get("allow_methods")) or None,
                                     split_csv(policy.get("allow_headers")) or None,
                                     split_csv(policy.get("expose_headers")) or None,
                                     policy.get("allow_credentials"), util.as_int(max_age) if max_age else None)
        if built:
            spec.plugins.append(PluginSpec("cors", built, ref))
        else:
            self.report.warning("envoy-cors", ref, f"CORS omitted ({problem}); browsers block cross-origin calls.")

    # ---------------------------------------------------------------- clusters

    def _cluster(self, name: str, hash_on: str | None) -> dict:
        raw = self.clusters.get(name)
        ref = f"envoy cluster '{safe_label(name)}'"
        if raw is None:
            return {"problems": [f"cluster {safe_label(name, 48)} is undefined"]}
        cluster_type = str(raw.get("type", "STATIC")).upper()
        if raw.get("cluster_type") or cluster_type not in ("STATIC", "STRICT_DNS", "LOGICAL_DNS"):
            return {"problems": [f"cluster {safe_label(name, 48)} uses dynamic or custom discovery"]}
        targets, problems = self._endpoints(raw, ref)
        tls, scheme, tls_problems = self._upstream_tls(raw, ref)
        problems += tls_problems
        result: dict[str, Any] = {"problems": problems}
        connect = util.proto_duration_ms(raw.get("connect_timeout")) if raw.get("connect_timeout") else 5_000
        result["connect"] = connect
        if problems:
            return result
        key = f"{name}|{hash_on}"
        if key not in self.plan.upstreams:
            spec = UpstreamSpec(key=key, name=name, ref=ref, targets=targets, tls=tls)
            policy = str(raw.get("lb_policy", "ROUND_ROBIN")).upper()
            spec.algorithm = {"ROUND_ROBIN": "round_robin", "LEAST_REQUEST": "least_connections",
                              "RANDOM": "random"}.get(policy, "round_robin")
            if policy in ("RING_HASH", "MAGLEV"):
                if hash_on:
                    spec.algorithm, spec.hash_on = "consistent_hashing", hash_on
                else:
                    self.report.warning("envoy-hash", ref, "Ring-hash without a route hash policy; using round robin.")
            elif policy not in ("ROUND_ROBIN", "LEAST_REQUEST", "RANDOM"):
                self.report.warning("envoy-lb-policy", ref, "Load-balancing policy has no equivalent; round robin.")
            spec.health_checks = self._health(raw, ref)
            if raw.get("outlier_detection") or raw.get("circuit_breakers"):
                self.report.warning("envoy-resilience", ref, "Outlier detection and circuit breakers are not migrated.")
            self.plan.upstreams[key] = spec
        result["backend"] = BackendRef(scheme=scheme, upstream_key=key)
        result["tls_key"] = tls.key() + scheme
        result["targets"] = targets
        return result

    def _endpoints(self, raw: dict, ref: str) -> tuple[list[Target], list[str]]:
        targets: list[Target] = []
        problems: list[str] = []
        if raw.get("hosts"):
            problems.append("v2 'hosts' clusters are not supported (use load_assignment)")
        assignment = mapping(raw.get("load_assignment"))
        for locality in seq(assignment.get("endpoints")):
            locality = mapping(locality)
            if util.as_int(locality.get("priority", 0)):
                self.report.warning("envoy-priority", ref, "Failover-priority endpoints are not migrated (Ferrum has "
                                    "no standby tiers).")
                continue
            for endpoint in seq(locality.get("lb_endpoints")):
                endpoint = mapping(endpoint)
                socket = mapping(mapping(mapping(endpoint.get("endpoint")).get("address")).get("socket_address"))
                port = util.parse_port(socket.get("port_value"))
                if not isinstance(socket.get("address"), str) or port is None:
                    problems.append("an endpoint has no socket address/port")
                    continue
                weight = util.as_int(endpoint.get("load_balancing_weight")) or 1
                targets.append(Target(socket["address"], port, weight))
        if not targets and not problems:
            problems.append("cluster has no endpoints")
        return targets, problems

    def _upstream_tls(self, raw: dict, ref: str) -> tuple[TlsSpec, str, list[str]]:
        socket = mapping(raw.get("transport_socket"))
        if not socket or _kind(socket) != "tls":
            return TlsSpec(), "http", []
        config = mapping(socket.get("typed_config"))
        common = mapping(config.get("common_tls_context"))
        problems: list[str] = []
        tls = TlsSpec(verify=False)
        validation = mapping(common.get("validation_context"))
        if common.get("validation_context_sds_secret_config") or common.get("tls_certificate_sds_secret_configs"):
            problems.append("SDS TLS material is not migrated")
        if validation:
            ca = mapping(validation.get("trusted_ca"))
            if ca.get("filename"):
                tls.verify = True
                tls.ca_path = str(ca["filename"])
            elif ca:
                problems.append("inline trusted CA material is not migrated")
            sans = []
            for matcher in seq(validation.get("match_subject_alt_names")) + \
                    [mapping(m).get("matcher") for m in seq(validation.get("match_typed_subject_alt_names"))]:
                matcher = mapping(matcher)
                if "exact" in matcher:
                    sans.append(str(matcher["exact"]))
                elif matcher:
                    problems.append("non-exact SAN matchers are not supported")
            tls.san_allow_list = sans
            if sans:
                tls.verify = True
        for cert in seq(common.get("tls_certificates"))[:1]:
            chain = mapping(mapping(cert).get("certificate_chain"))
            key = mapping(mapping(cert).get("private_key"))
            if chain.get("filename") and key.get("filename"):
                tls.client_cert_path, tls.client_key_path = str(chain["filename"]), str(key["filename"])
            else:
                problems.append("inline client certificate material is never migrated")
        if isinstance(config.get("sni"), str):
            tls.sni = config["sni"]
        return tls, "https", problems

    def _health(self, raw: dict, ref: str) -> dict | None:
        for check in seq(raw.get("health_checks")):
            check = mapping(check)
            http = mapping(check.get("http_health_check"))
            if not isinstance(http.get("path"), str):
                continue
            entry = {"http_path": http["path"],
                     "interval_seconds": max(1, (util.proto_duration_ms(check.get("interval")) or 10_000) // 1000),
                     "timeout_ms": util.proto_duration_ms(check.get("timeout")) or 5_000,
                     "healthy_threshold": max(1, util.as_int(check.get("healthy_threshold")) or 1),
                     "unhealthy_threshold": max(1, util.as_int(check.get("unhealthy_threshold")) or 1)}
            self.report.warning("envoy-health", ref, "Active health checks mapped approximately.")
            return {"active": entry}
        return None

    def _weighted(self, weighted: dict, spec: RouteSpec, hash_on: str | None) -> dict:
        parts: list[tuple[int, list[Target]]] = []
        keys = set()
        problems: list[str] = []
        first = None
        for child in seq(weighted.get("clusters")):
            child = mapping(child)
            if child.get("request_headers_to_add") or child.get("typed_per_filter_config"):
                problems.append("per-cluster header or filter overrides in weighted clusters")
            result = self._cluster(str(child.get("name")), hash_on)
            problems += result["problems"]
            if result.get("backend") is None:
                continue
            first = first or result
            keys.add(result["tls_key"])
            parts.append((util.as_int(child.get("weight")) or 0, result["targets"]))
        if len(keys) > 1:
            problems.append("weighted clusters differ in TLS settings")
        if problems or first is None:
            return {"problems": problems or ["weighted clusters are empty"]}
        merged = merge_weighted_targets(parts)
        if merged is None:
            return {"problems": ["weighted clusters send no traffic anywhere"]}
        targets, approximate = merged
        if approximate:
            self.report.warning("envoy-weights", spec.ref, "Weighted split was rounded to integer target weights.")
        base = self.plan.upstreams[first["backend"].upstream_key]
        key = f"weighted:{spec.ref}"
        self.plan.upstreams[key] = UpstreamSpec(key=key, name=f"{spec.name}-weighted", ref=spec.ref, targets=targets,
                                                tls=base.tls, algorithm="weighted_round_robin")
        return {"problems": [], "backend": BackendRef(scheme=first["backend"].scheme, upstream_key=key),
                "connect": first.get("connect")}


def _envoy_value(value: str) -> str | None:
    if "%" not in value:
        return literal_value(value)
    if value in ("%DOWNSTREAM_REMOTE_ADDRESS_WITHOUT_PORT%", "%DOWNSTREAM_DIRECT_REMOTE_ADDRESS_WITHOUT_PORT%"):
        return "$(client_ip)"
    match = re.fullmatch(r"%REQ\(([A-Za-z0-9-]+)\)%", value)
    if match and not any(word in match.group(1).lower() for word in ("authorization", "cookie", "token", "key")):
        return f"$(header.{match.group(1).lower()})"
    return None


def translate(text: str, fmt: str, ctx: SourceContext) -> Plan:
    documents = load_structured(text, fmt, ctx.limits, allow_multi=False)
    if not documents or not isinstance(documents[0], dict):
        raise InputError("Envoy bootstrap must be a mapping at the top level")
    return _Envoy(documents[0], ctx).run()
