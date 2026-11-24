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
from urllib.parse import urlsplit

from .. import util
from ..errors import InputError
from ..model import BackendRef, HostScope, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import contains_secret_reference, safe_label
from ..safe_load import load_structured
from .common import (SourceContext, apply_first_match_order, check_route_budget, choose_main_port, compression_config,
                     cors_config, fault_injection_config, fold, header_value_ok, jwks_provider_config, literal_value,
                     mapping, merge_weighted_targets, request_header_rule, request_mirror_config, response_header_rule,
                     retry_from_policy, seq, split_csv, str_list, validate_jwks_providers)

PLATFORM = "envoy"
_REDIRECT_CODES = {"MOVED_PERMANENTLY": 301, "FOUND": 302, "SEE_OTHER": 303, "TEMPORARY_REDIRECT": 307,
                   "PERMANENT_REDIRECT": 308}


def _proto_bool(value: Any) -> bool | None:
    """Read a protobuf BoolValue in either JSON bool or ``{value: bool}`` shape."""
    if isinstance(value, bool):
        return value
    if isinstance(value, dict) and isinstance(value.get("value"), bool):
        return value["value"]
    return None


def _kind(item: Any) -> str:
    """Normalize a filter/transport identity from ``typed_config['@type']`` (authoritative) or ``name``."""
    item = mapping(item)
    raw_type = mapping(item.get("typed_config")).get("@type")
    type_url = raw_type.strip() if isinstance(raw_type, str) else ""
    name = str(item.get("name", ""))
    # Envoy selects extensions strictly by typed_config['@type'] when present; never let a free-form filter name
    # masquerade as a harmless filter when typed_config names a different extension.
    text = type_url.lower() if type_url else name.lower()
    for token, kind in (("http_connection_manager", "hcm"), ("filters.http.router", "router"),
                        ("router.v3.router", "router"), ("filters.http.cors", "cors"), ("cors.v3.cors", "cors"),
                        ("filters.http.grpc_web", "grpc_web"), ("grpc_web.v3.grpcweb", "grpc_web"),
                        ("filters.http.compressor", "compressor"), ("compressor.v3.compressor", "compressor"),
                        ("filters.http.fault", "fault"), ("fault.v3.httpfault", "fault"),
                        ("filters.http.jwt_authn", "jwt_authn"), ("jwt_authn.v3.jwtauthentication", "jwt_authn"),
                        ("grpc_stats", "grpc_stats"), ("health_check", "health_check"),
                        ("filters.http.buffer", "buffer"), ("buffer.v3.buffer", "buffer"),
                        ("downstreamtlscontext", "tls"), ("upstreamtlscontext", "tls"),
                        ("transport_sockets.tls", "tls"), ("proxy_protocol", "proxy_protocol"),
                        ("tls_inspector", "tls_inspector"), ("http_inspector", "http_inspector"),
                        ("original_dst", "original_dst")):
        if token in text:
            return kind
    return type_url or name or "unknown"


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
        # Each route records its one source frontend (RouteSpec.protocols). The emitter keeps a plaintext
        # listener's routes off Ferrum's HTTPS listener (and vice versa) for every host, which also covers TLS
        # listeners that were skipped (RDS, filter_chain_match) after their port and certificate were recorded.
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
        raw_required = config.get("require_client_certificate")
        parsed_required = _proto_bool(raw_required)
        if raw_required is not None and parsed_required is None:
            self.report.error("envoy-client-ca", ref,
                              "require_client_certificate has an invalid non-boolean value, so client certificate "
                              "enforcement cannot be determined. Its routes were refused (fail closed).",
                              "Set require_client_certificate to a boolean or BoolValue ({value: true/false}) and "
                              "convert again.")
            return [], "require_client_certificate has an invalid non-boolean value"
        required = parsed_required is True
        has_sds_or_combined = bool(common.get("validation_context_sds_secret_config")
                                   or common.get("combined_validation_context"))
        has_validation = bool(validation) or has_sds_or_combined
        if not required and not has_validation:
            return [], None
        ca = mapping(validation.get("trusted_ca"))
        # Only a bare file-path trusted_ca is reproducible: SAN/hash/SPKI pins, CRLs, SDS or custom validators
        # narrow who is trusted, and Ferrum's listener-wide bundle would accept every client of that CA.
        constraints = [key for key in validation if key != "trusted_ca"]
        if not has_sds_or_combined and isinstance(ca.get("filename"), str) and ca["filename"].strip() \
                and not constraints:
            if not required:
                self.report.warning("envoy-mtls-optional", ref,
                                    "Optional client certificate verification (validation_context without "
                                    "require_client_certificate) becomes mandatory under Ferrum's frontend client CA "
                                    "(stricter).")
            return [ca["filename"]], None
        self.report.error("envoy-client-ca", ref,
                          "The listener configured client certificate verification, but its trust (inline, SDS, "
                          "combined or missing CA, or extra validation constraints such as SAN, hash, SPKI or CRL) "
                          "cannot be reproduced by Ferrum's frontend client CA bundle. Its routes were refused "
                          "(fail closed).",
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
        hcm_plugins: list[PluginSpec] = []
        hcm_fault: PluginSpec | None = None
        hcm_jwt: PluginSpec | None = None
        hcm_filter_kinds: dict[str, str] = {}
        for http_filter in seq(config.get("http_filters")):
            kind = _kind(http_filter)
            raw_filter = mapping(http_filter)
            fname = raw_filter.get("name")
            if isinstance(fname, str) and fname:
                hcm_filter_kinds[fname] = kind
            if raw_filter.get("disabled"):
                continue
            typed = mapping(raw_filter.get("typed_config"))
            if kind == "router":
                continue
            if kind == "cors":
                cors_enabled = True
            elif kind in ("grpc_stats", "health_check"):
                self.report.warning("envoy-http-filter-omitted", ref, f"HTTP filter {kind} is not migrated.")
            elif kind == "buffer":
                buffer_limit = util.as_int(typed.get("max_request_bytes"))
            elif kind == "grpc_web":
                if set(typed) - {"@type"}:
                    filter_refusal = "HTTP filter grpc_web has unsupported configuration fields"
                else:
                    hcm_plugins.append(PluginSpec("grpc_web", {}, ref))
            elif kind == "compressor":
                comp_status, comp_val = _parse_envoy_compressor(typed)
                if comp_status == "plugin":
                    hcm_plugins.append(PluginSpec("compression", comp_val, ref))
                elif comp_status == "omit":
                    self.report.info("envoy-compressor-disabled", ref,
                                     "Envoy compressor filter has response compression disabled; omitted.")
                else:
                    filter_refusal = f"HTTP filter compressor cannot be migrated ({comp_val})"
            elif kind == "fault":
                fault_cfg, fault_err = _parse_envoy_fault(typed)
                if fault_cfg is not None:
                    hcm_fault = PluginSpec("fault_injection", fault_cfg, ref)
                else:
                    filter_refusal = f"HTTP filter fault cannot be migrated ({fault_err})"
            elif kind == "jwt_authn":
                jwt_cfg, jwt_err = self._parse_jwt_authn(typed, ref)
                if jwt_cfg is not None:
                    if hcm_jwt is not None:
                        filter_refusal = "multiple jwt_authn HTTP filters in one connection manager are not supported"
                    else:
                        hcm_jwt = PluginSpec("jwks_auth", jwt_cfg, ref)
                else:
                    filter_refusal = f"HTTP filter jwt_authn cannot be migrated ({jwt_err})"
            else:
                filter_refusal = f"HTTP filter {safe_label(kind, 80)} has no safe Ferrum equivalent"
        route_config = mapping(config.get("route_config"))
        shared = {"request_add": seq(route_config.get("request_headers_to_add")),
                  "request_remove": seq(route_config.get("request_headers_to_remove")),
                  "response_add": seq(route_config.get("response_headers_to_add")),
                  "response_remove": seq(route_config.get("response_headers_to_remove")),
                  "typed_per_filter_config": mapping(route_config.get("typed_per_filter_config")),
                  "hcm_filter_kinds": hcm_filter_kinds,
                  "hcm_plugins": hcm_plugins,
                  "hcm_fault": hcm_fault,
                  "hcm_jwt": hcm_jwt}
        for index, vhost in enumerate(seq(route_config.get("virtual_hosts"))):
            if isinstance(vhost, dict):
                self._vhost(vhost, index, ref, listen_port, tls, cors_enabled, filter_refusal, buffer_limit, shared)

    def _vhost(self, vhost: dict, index: int, listener_ref: str, listen_port: int | None, tls: bool,
               cors_enabled: bool, filter_refusal: str | None, buffer_limit: int | None, shared: dict) -> None:
        name = str(vhost.get("name") or f"vhost-{index + 1}")
        ref = f"envoy virtual_host '{safe_label(name)}' on {listener_ref}"
        raw_domains = str_list(vhost.get("domains"))
        hosts: list[str] | None = []
        host_problem = None
        if raw_domains is None or not raw_domains:
            host_problem = "domains missing or invalid"
        elif "*" not in raw_domains:
            for domain in raw_domains:
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
            if shared.get("hcm_jwt") is not None:
                if spec.termination is not None:
                    spec.refuse("jwt_authn runs before direct_response/redirect in Envoy, whereas Ferrum "
                                "request_termination answers before authentication")
                else:
                    jwt_p = shared["hcm_jwt"]
                    spec.plugins.append(PluginSpec(jwt_p.name, jwt_p.config, jwt_p.ref))
            if not spec.termination:
                for hp in shared.get("hcm_plugins", []):
                    spec.plugins.append(PluginSpec(hp.name, hp.config, hp.ref))
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
        # An Envoy listener is either plaintext or TLS, and its virtual hosts are its own: each route was served on
        # exactly one source frontend. require_tls on a plaintext listener only redirects (requires_tls removes it).
        spec = RouteSpec(ref=ref, name=name, hosts=None if hosts is None else list(hosts),
                         listen_port=listen_port, requires_tls=requires_tls,
                         protocols=frozenset({"https" if tls else "http"}))
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
        raw_case = match.get("case_sensitive")
        parsed_case = _proto_bool(raw_case)
        if raw_case is not None and parsed_case is None:
            spec.extra_conditions = True
            spec.refuse("case_sensitive has an invalid non-boolean value")
        elif parsed_case is False and spec.kind in ("prefix", "exact") and spec.path_ok:
            # Envoy ignores case_sensitive for safe_regex. Ferrum matches literal paths case-sensitively: the route
            # keeps its exact-case path and the emitter refuses every route that could receive the case variants
            # (fail closed), instead of letting them reach an overlapping route with another policy.
            spec.case_insensitive = True
            self.report.warning("envoy-case-insensitive", ref,
                                "case_sensitive: false: Ferrum matches this path case-sensitively. Only the "
                                "exact-case path is routed here; other case variants answer 404 or a fail-closed "
                                "response, and routes that could receive them were refused.")
        for key in ("headers", "query_parameters", "grpc", "runtime_fraction", "tls_context", "dynamic_metadata",
                    "filter_state", "cel_expr"):
            if match.get(key):
                spec.extra_conditions = True
                spec.refuse(f"matches on {key}, which Ferrum cannot express")
        # Per-route/vhost filter config is keyed by the exact HCM filter name (including disabled filters) and can
        # re-enable an authentication filter for this route only. Resolve every key against hcm_filter_kinds and its
        # override @type rather than matching substrings on the filter name.
        hcm_filter_kinds: dict[str, str] = shared.get("hcm_filter_kinds", {})
        effective_fault: PluginSpec | None = shared.get("hcm_fault")
        for source, label in ((shared, "route configuration"), (vhost, "virtual host"), (raw, "route")):
            per_filter = mapping(source.get("typed_per_filter_config"))
            others = []
            for key, raw_override in per_filter.items():
                key_str = str(key)
                override = mapping(raw_override)
                override_type = str(override.get("@type", "")).lower()
                filter_kind = hcm_filter_kinds.get(key_str)
                is_filter_config = "filterconfig" in override_type
                if filter_kind == "cors" and not is_filter_config \
                        and (not override_type or "cors.v3.cors" in override_type):
                    continue
                if filter_kind == "fault":
                    if override.get("disabled") is True and (not override_type or is_filter_config):
                        effective_fault = None
                        continue
                    if not is_filter_config and (not override_type or "fault.v3.httpfault" in override_type):
                        parsed_fault, fault_err = _parse_envoy_fault(override)
                        if parsed_fault is not None:
                            effective_fault = PluginSpec("fault_injection", parsed_fault, ref)
                        else:
                            spec.refuse(f"{label} typed_per_filter_config for fault cannot be migrated ({fault_err})")
                        continue
                others.append(key_str)
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
        if effective_fault is not None:
            spec.plugins.append(PluginSpec(effective_fault.name, effective_fault.config, effective_fault.ref))
        self._headers(spec, raw, vhost, shared, ref)
        self._cors(spec, raw, vhost, cors_enabled, hcm_filter_kinds, ref)
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
        if status in (204, 205, 304):
            spec.termination = {"status_code": status, "body": str(text)}
        else:
            spec.termination = {"status_code": status, "content_type": "text/plain", "body": str(text)}

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
        location = f"{scheme}://{host}{path}"
        if not header_value_ok(location, nonempty=True, strict_ws=True):
            spec.refuse("redirect location is not a valid header value")
            return
        spec.termination = {"status_code": code, "headers": {"location": location}, "body": ""}

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
        if _proto_bool(action.get("auto_host_rewrite")) is True:
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
            self._mirror_policies(spec, seq(action.get("request_mirror_policies")), ref)

    def _mirror_policies(self, spec: RouteSpec, policies: list, ref: str) -> None:
        migrated = 0
        dropped = 0
        for policy in policies:
            if not isinstance(policy, dict) or not isinstance(policy.get("cluster"), str):
                dropped += 1
                continue
            if set(policy) - {"cluster", "runtime_fraction"}:
                # Mirror policies with header mutations, cluster_header, or other controls cannot be preserved faithfully.
                dropped += 1
                continue
            cluster_raw = self.clusters.get(policy["cluster"])
            if cluster_raw is None:
                dropped += 1
                continue
            cluster_type = str(cluster_raw.get("type", "STATIC")).upper()
            if cluster_raw.get("cluster_type") or cluster_type not in ("STATIC", "STRICT_DNS", "LOGICAL_DNS"):
                dropped += 1
                continue
            targets, ep_problems = self._endpoints(cluster_raw, ref)
            tls, scheme, tls_problems = self._upstream_tls(cluster_raw, ref)
            if ep_problems or tls_problems or len(targets) != 1 \
                    or (scheme == "https" and (tls.ca_path or tls.client_cert_path or tls.sni or tls.san_allow_list)):
                dropped += 1
                continue
            pct = 100.0
            rf = policy.get("runtime_fraction")
            if rf is not None:
                if not isinstance(rf, dict) or rf.get("runtime_key"):
                    dropped += 1
                    continue
                default_val = rf.get("default_value")
                if default_val is not None:
                    parsed_pct = _envoy_fractional_percent(default_val)
                    if parsed_pct is None:
                        dropped += 1
                        continue
                    pct = parsed_pct
            if pct == 0.0:
                continue
            built, _problem = request_mirror_config(targets[0].host, targets[0].port, scheme, percentage=pct)
            if built is None:
                dropped += 1
                continue
            spec.plugins.append(PluginSpec("request_mirror", built, ref))
            migrated += 1
        if migrated:
            self.report.warning("envoy-mirror", ref,
                                f"Migrated {migrated} request_mirror_policies target(s) to request_mirror; Ferrum "
                                "redacts credential-like headers and query parameters on mirrored requests by default "
                                "(stricter).")
        if dropped:
            self.report.warning("envoy-mirror", ref,
                                f"{dropped} request_mirror_policies entry(ies) could not be represented faithfully "
                                "(dynamic runtime_key, header mutations, multi-endpoint or custom-TLS cluster) and "
                                "were dropped.")

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

    def _cors(self, spec: RouteSpec, raw: dict, vhost: dict, enabled: bool, hcm_filter_kinds: dict[str, str],
              ref: str) -> None:
        policy = None
        for source in (raw, vhost):
            per_filter = mapping(source.get("typed_per_filter_config"))
            candidate = next(
                (mapping(v) for k, v in per_filter.items()
                 if hcm_filter_kinds.get(str(k)) == "cors"
                 and "filterconfig" not in str(mapping(v).get("@type", "")).lower()),
                None,
            )
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
        raw_creds = policy.get("allow_credentials")
        creds: bool | None = None
        if raw_creds is not None:
            creds = _proto_bool(raw_creds)
            if creds is None:
                self.report.warning("envoy-cors", ref,
                                    "CORS omitted (allow_credentials has an invalid non-boolean value); browsers block "
                                    "cross-origin calls.")
                return
        built, problem = cors_config(origins, split_csv(policy.get("allow_methods")) or None,
                                     split_csv(policy.get("allow_headers")) or None,
                                     split_csv(policy.get("expose_headers")) or None,
                                     creds, util.as_int(max_age) if max_age else None)
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
        if raw.get("transport_socket_matches"):
            return TlsSpec(), "http", ["cluster transport_socket_matches is not migrated"]
        socket = mapping(raw.get("transport_socket"))
        if not socket:
            return TlsSpec(), "http", []
        typed_cfg = mapping(socket.get("typed_config"))
        if "@type" in typed_cfg:
            type_url = typed_cfg.get("@type")
            msg_type = type_url.rsplit("/", 1)[-1] if isinstance(type_url, str) and "/" in type_url else ""
            if msg_type in (
                "envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer",
                "envoy.api.v2.core.RawBuffer",
            ):
                return TlsSpec(), "http", []
            if msg_type not in (
                "envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "envoy.api.v2.auth.UpstreamTlsContext",
            ):
                return TlsSpec(), "http", [
                    f"upstream transport_socket {safe_label(msg_type or type_url, 48)} is not supported"
                ]
        else:
            kind = _kind(socket)
            if kind != "tls":
                if str(socket.get("name", "")) in (
                    "envoy.transport_sockets.raw_buffer",
                    "raw_buffer",
                ):
                    return TlsSpec(), "http", []
                return TlsSpec(), "http", [f"upstream transport_socket {safe_label(kind, 48)} is not supported"]
        config = mapping(socket.get("typed_config"))
        common = mapping(config.get("common_tls_context"))
        problems: list[str] = []
        tls = TlsSpec(verify=False)
        validation = mapping(common.get("validation_context"))
        if common.get("validation_context_sds_secret_config") or common.get("tls_certificate_sds_secret_configs") \
                or common.get("combined_validation_context"):
            problems.append("SDS or combined TLS validation material is not migrated")
        if validation:
            extra_validation = [k for k in validation
                                if k not in ("trusted_ca", "match_subject_alt_names", "match_typed_subject_alt_names")
                                and validation.get(k)]
            if extra_validation:
                problems.append("upstream TLS validation constraints beyond trusted_ca and exact SANs "
                                f"({', '.join(sorted(extra_validation)[:4])}) are not supported")
            ca = mapping(validation.get("trusted_ca"))
            if isinstance(ca.get("filename"), str) and ca["filename"].strip():
                tls.verify = True
                tls.ca_path = str(ca["filename"])
            elif ca:
                problems.append("inline or invalid trusted CA material is not migrated")
            sans: list[str] = []
            raw_typed = validation.get("match_typed_subject_alt_names")
            raw_legacy = validation.get("match_subject_alt_names")
            if raw_typed is not None and not isinstance(raw_typed, list):
                problems.append("match_typed_subject_alt_names has unexpected shape")
                typed_sans: list = []
            else:
                typed_sans = list(raw_typed or [])
            if typed_sans:
                # Envoy ignores deprecated match_subject_alt_names whenever match_typed_subject_alt_names is populated.
                for typed_matcher in typed_sans:
                    if not isinstance(typed_matcher, dict):
                        problems.append("malformed typed SAN matcher")
                        continue
                    san_type = str(typed_matcher.get("san_type", "")).upper()
                    matcher = typed_matcher.get("matcher")
                    if san_type not in ("DNS", "IP_ADDRESS"):
                        if san_type == "URI":
                            problems.append("Envoy exact URI SAN matchers are case-sensitive, whereas Ferrum compares "
                                            "SPIFFE trust domains case-insensitively")
                        else:
                            problems.append(f"SAN matcher type {safe_label(san_type, 24)} is not supported")
                        continue
                    if not isinstance(matcher, dict) or not isinstance(matcher.get("exact"), str) \
                            or any(k != "exact" and not (k == "ignore_case" and matcher[k] is False) for k in matcher):
                        problems.append("non-exact or option-bearing SAN matchers are not supported")
                        continue
                    san = matcher["exact"]
                    if util.backend_tls_san_kind(san) == san_type:
                        sans.append(san)
                    else:
                        problems.append("upstream TLS SAN entry does not match declared SAN type or is not "
                                        "representable in Ferrum")
            elif raw_legacy is not None:
                if not isinstance(raw_legacy, list):
                    problems.append("match_subject_alt_names has unexpected shape")
                else:
                    for matcher in raw_legacy:
                        if not isinstance(matcher, dict) or not isinstance(matcher.get("exact"), str) \
                                or any(k != "exact" and not (k == "ignore_case" and matcher[k] is False)
                                       for k in matcher):
                            problems.append("non-exact or option-bearing SAN matchers are not supported")
                            continue
                        san = matcher["exact"]
                        san_kind = util.backend_tls_san_kind(san)
                        if san_kind in ("DNS", "IP_ADDRESS"):
                            sans.append(san)
                        elif san_kind == "URI":
                            problems.append("Envoy exact URI SAN matchers are case-sensitive, whereas Ferrum compares "
                                            "SPIFFE trust domains case-insensitively")
                        else:
                            problems.append("upstream TLS SAN entry is not representable in Ferrum")
            tls.san_allow_list = sans
            if sans:
                tls.verify = True
        for cert in seq(common.get("tls_certificates"))[:1]:
            chain = mapping(mapping(cert).get("certificate_chain"))
            key = mapping(mapping(cert).get("private_key"))
            if isinstance(chain.get("filename"), str) and chain["filename"].strip() \
                    and isinstance(key.get("filename"), str) and key["filename"].strip():
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
            path = http.get("path")
            if not isinstance(path, str):
                continue
            if not path.startswith("/") or len(path.encode("utf-8")) > util.MAX_BACKEND_PATH_LENGTH \
                    or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
                self.report.warning("envoy-health", ref, "Active health check path is not representable; omitted.")
                continue
            entry = {"http_path": path,
                     "interval_seconds": max(1, min((util.proto_duration_ms(check.get("interval")) or 10_000) // 1000, 3600)),
                     "timeout_ms": max(1, min(util.proto_duration_ms(check.get("timeout")) or 5_000, util.MAX_TIMEOUT_MS)),
                     "healthy_threshold": max(1, min(util.as_int(check.get("healthy_threshold")) or 1, 10_000)),
                     "unhealthy_threshold": max(1, min(util.as_int(check.get("unhealthy_threshold")) or 1, 10_000))}
            self.report.warning("envoy-health", ref, "Active health checks mapped approximately.")
            return {"active": entry}
        return None

    def _weighted(self, weighted: dict, spec: RouteSpec, hash_on: str | None) -> dict:
        parts: list[tuple[int, list[Target]]] = []
        keys = set()
        connects = set()
        problems: list[str] = []
        first = None
        for child in seq(weighted.get("clusters")):
            child = mapping(child)
            if any(child.get(k) for k in ("request_headers_to_add", "request_headers_to_remove",
                                          "response_headers_to_add", "response_headers_to_remove",
                                          "typed_per_filter_config", "host_rewrite_literal")):
                problems.append("per-cluster header, host-rewrite or filter overrides in weighted clusters")
            result = self._cluster(str(child.get("name")), hash_on)
            problems += result["problems"]
            if result.get("backend") is None:
                continue
            first = first or result
            keys.add(result["tls_key"])
            connects.add(result.get("connect"))
            parts.append((util.as_int(child.get("weight")) or 0, result["targets"]))
        if len(keys) > 1:
            problems.append("weighted clusters differ in TLS settings")
        if len(connects) > 1:
            problems.append("weighted clusters differ in connect_timeout")
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


    def _verify_jwks_cluster(self, cluster_name: Any, uri: str, ref: str) -> str | None:
        """Ensure Envoy's remote_jwks cluster has no custom endpoint/TLS trust that Ferrum's direct fetch would bypass."""
        if not isinstance(cluster_name, str) or not cluster_name:
            return "remote_jwks.http_uri.cluster is missing"
        cluster_raw = self.clusters.get(cluster_name)
        if cluster_raw is None:
            return f"remote_jwks cluster {safe_label(cluster_name, 48)} is undefined"
        cluster_type = str(cluster_raw.get("type", "STATIC")).upper()
        if cluster_raw.get("cluster_type") or cluster_type not in ("STATIC", "STRICT_DNS", "LOGICAL_DNS"):
            return "remote_jwks cluster uses dynamic or custom discovery"
        targets, ep_problems = self._endpoints(cluster_raw, ref)
        if ep_problems or len(targets) != 1:
            return "remote_jwks cluster must resolve to a single endpoint matching jwks_uri"
        tls, scheme, tls_problems = self._upstream_tls(cluster_raw, ref)
        if tls_problems:
            return "remote_jwks cluster has unsupported upstream TLS settings"
        parts = urlsplit(uri)
        uri_scheme = parts.scheme.lower()
        uri_host = (parts.hostname or "").lower()
        uri_port = parts.port or (443 if uri_scheme == "https" else 80)
        if scheme != uri_scheme:
            return "remote_jwks cluster transport scheme disagrees with jwks_uri"
        if targets[0].host.strip("[]").lower() != uri_host or targets[0].port != uri_port:
            return "remote_jwks cluster endpoint disagrees with jwks_uri host/port"
        if scheme == "https":
            if tls.ca_path or tls.client_cert_path or tls.san_allow_list:
                return "remote_jwks cluster pins custom CA, SANs, or client certificates that jwks_auth cannot reproduce"
            if tls.sni and tls.sni.lower() != uri_host:
                return "remote_jwks cluster SNI overrides jwks_uri hostname"
        return None

    def _parse_jwt_authn(self, typed: dict, ref: str) -> tuple[dict | None, str | None]:
        if contains_secret_reference(typed):
            return None, "jwt_authn contains a secret/vault reference"
        unknown_root = [str(k) for k in typed if k not in _ENVOY_JWT_ROOT_KEYS]
        if unknown_root:
            return None, f"unsupported jwt_authn field(s): {', '.join(sorted(unknown_root)[:4])}"
        raw_providers = typed.get("providers")
        if not isinstance(raw_providers, dict) or not raw_providers:
            return None, "jwt_authn requires a non-empty providers map"
        parsed_providers: dict[str, dict[str, Any]] = {}
        all_claim_dests: dict[str, set[str]] = {}
        for pname, praw in raw_providers.items():
            if not isinstance(pname, str) or not isinstance(praw, dict):
                return None, "jwt_authn provider entry is malformed"
            unknown_p = [str(k) for k in praw if k not in _ENVOY_JWT_PROVIDER_KEYS]
            if unknown_p:
                return None, f"unsupported provider field(s): {', '.join(sorted(unknown_p)[:4])}"
            jwks_uri = None
            inline_jwks = None
            cluster_name = None
            if praw.get("remote_jwks") is not None:
                rjwks = mapping(praw["remote_jwks"])
                http_uri = mapping(rjwks.get("http_uri"))
                uri = http_uri.get("uri")
                if not isinstance(uri, str) or not uri.strip():
                    return None, "remote_jwks.http_uri.uri is missing or invalid"
                jwks_uri = uri.strip()
                cluster_name = http_uri.get("cluster")
            if praw.get("local_jwks") is not None:
                ljwks = mapping(praw["local_jwks"])
                if set(ljwks) - {"inline_string"} or not isinstance(ljwks.get("inline_string"), str):
                    return None, "only local_jwks.inline_string is supported"
                inline_jwks = ljwks["inline_string"]
            raw_fh = praw.get("from_headers")
            fh: list[dict[str, Any]] | None = None
            if raw_fh is not None:
                if not isinstance(raw_fh, list):
                    return None, "from_headers must be a list"
                fh = []
                for entry in raw_fh:
                    if not isinstance(entry, dict) or set(entry) - {"name", "value_prefix"}:
                        return None, "from_headers entry has unsupported fields"
                    item: dict[str, Any] = {"name": entry.get("name")}
                    if entry.get("value_prefix") is not None:
                        item["prefix"] = entry["value_prefix"]
                    fh.append(item)
            raw_cth = praw.get("claim_to_headers")
            och: list[dict[str, Any]] | None = None
            if raw_cth is not None:
                if not isinstance(raw_cth, list):
                    return None, "claim_to_headers must be a list"
                och = []
                for entry in raw_cth:
                    if not isinstance(entry, dict) or set(entry) - {"header_name", "claim_name"}:
                        return None, "claim_to_headers entry has unsupported fields"
                    och.append({"claim": entry.get("claim_name"), "header": entry.get("header_name")})
            # Envoy defaults `forward` to false (strips the original token); Ferrum defaults to true.
            raw_forward = praw.get("forward", False)
            prov_cfg, problem = jwks_provider_config(
                issuer=praw.get("issuer"),
                jwks_uri=jwks_uri,
                jwks=inline_jwks,
                audiences=praw.get("audiences"),
                from_headers=fh,
                from_params=praw.get("from_params"),
                forward_original_token=raw_forward,
                output_claim_headers=och,
            )
            if prov_cfg is None:
                return None, problem
            if jwks_uri is not None:
                cluster_err = self._verify_jwks_cluster(cluster_name, jwks_uri, ref)
                if cluster_err is not None:
                    return None, cluster_err
            if praw.get("clock_skew_seconds") is not None:
                skew = util.as_int(praw.get("clock_skew_seconds"))
                if skew is None or not 0 <= skew <= 300:
                    return None, "clock_skew_seconds must be 0-300"
                prov_cfg["clock_skew_seconds"] = skew
            parsed_providers[pname] = prov_cfg
            all_claim_dests[pname] = {fold(entry["header"]) for entry in prov_cfg.get("output_claim_headers", [])}
        raw_rules = typed.get("rules")
        if not isinstance(raw_rules, list) or len(raw_rules) != 1 or not isinstance(raw_rules[0], dict):
            return None, "only a single unconditional catch-all jwt_authn rule (prefix: '/') is supported"
        rule = raw_rules[0]
        if set(rule) - {"match", "requires"}:
            return None, "jwt_authn rule contains unsupported fields"
        match = mapping(rule.get("match"))
        if set(match) - {"prefix"} or match.get("prefix", "/") not in ("", "/"):
            return None, "jwt_authn rule match must be catch-all (prefix: '/')"
        requires = rule.get("requires")
        if not isinstance(requires, dict) or len(requires) != 1:
            return None, "jwt_authn rule requires must specify provider_name or requires_any"
        allow_missing = False
        selected_names: list[str] = []
        if isinstance(requires.get("provider_name"), str):
            selected_names.append(requires["provider_name"])
        elif isinstance(requires.get("requires_any"), dict):
            reqs = seq(requires["requires_any"].get("requirements"))
            if not reqs:
                return None, "requires_any.requirements must not be empty"
            for sub in reqs:
                if not isinstance(sub, dict) or len(sub) != 1:
                    return None, "unsupported nested jwt_authn requirement"
                if isinstance(sub.get("provider_name"), str):
                    selected_names.append(sub["provider_name"])
                elif "allow_missing" in sub:
                    allow_missing = True
                else:
                    return None, "only provider_name and allow_missing are supported inside requires_any"
        else:
            return None, "only provider_name or requires_any requirements are supported"
        if not selected_names:
            return None, "jwt_authn rule selects no providers"
        deduped_names = list(dict.fromkeys(selected_names))
        providers_out: list[dict[str, Any]] = []
        emitted_dests: set[str] = set()
        for pname in deduped_names:
            if pname not in parsed_providers:
                return None, f"jwt_authn rule references undefined provider {safe_label(pname, 40)}"
            providers_out.append(parsed_providers[pname])
            emitted_dests.update(all_claim_dests[pname])
        # Envoy sanitizes claim_to_headers destinations across ALL configured providers, even unselected ones.
        for pname, dests in all_claim_dests.items():
            if pname not in deduped_names and not dests <= emitted_dests:
                return None, (f"unselected provider {safe_label(pname, 40)} declares claim_to_headers destinations "
                              "absent from selected providers (sanitization would be dropped)")
        bound_err = validate_jwks_providers(providers_out)
        if bound_err is not None:
            return None, bound_err
        result: dict[str, Any] = {"providers": providers_out}
        if allow_missing:
            result["allow_missing_token"] = True
        return result, None


def _envoy_fractional_percent(value: Any) -> float | None:
    if not isinstance(value, dict):
        return None
    numerator = util.as_int(value.get("numerator"))
    if numerator is None or numerator < 0:
        return None
    denom = str(value.get("denominator", "HUNDRED")).upper()
    scale = {"HUNDRED": 1.0, "TEN_THOUSAND": 100.0, "MILLION": 10_000.0}.get(denom)
    if scale is None:
        return None
    pct = numerator / scale
    return pct if 0.0 <= pct <= 100.0 else None


def _parse_envoy_compressor(typed: dict) -> tuple[str, Any]:
    unknown_root = [str(k) for k in typed
                    if k not in ("@type", "compressor_library", "response_direction_config",
                                 "request_direction_config", "choose_first")]
    if unknown_root:
        return "refuse", f"unsupported compressor field(s): {', '.join(sorted(unknown_root)[:4])}"
    lib = mapping(typed.get("compressor_library"))
    lib_type = str(mapping(lib.get("typed_config")).get("@type", "")).lower()
    lib_text = lib_type if lib_type else str(lib.get("name", "")).lower()
    algo = None
    for token, name in (("gzip", "gzip"), ("brotli", "br"), ("zstd", "zstd")):
        if token in lib_text:
            algo = name
            break
    if algo is None:
        return "refuse", "unknown or missing compressor_library"
    # Envoy request_direction_config compresses outbound requests (NOT decompression); Ferrum has no equivalent.
    raw_req = typed.get("request_direction_config")
    if raw_req is not None:
        if not isinstance(raw_req, dict):
            return "refuse", "request_direction_config is malformed"
        req_common = mapping(raw_req.get("common_config"))
        req_enabled = req_common.get("enabled")
        explicitly_off = (isinstance(req_enabled, dict) and not req_enabled.get("runtime_key")
                          and _proto_bool(req_enabled.get("default_value")) is False)
        if not explicitly_off:
            return "refuse", "request_direction_config (outbound request compression) has no Ferrum equivalent"
    resp = mapping(typed.get("response_direction_config"))
    unknown_resp = [str(k) for k in resp if k not in ("common_config", "remove_accept_encoding_header")]
    if unknown_resp:
        return "refuse", f"unsupported response_direction_config field(s): {', '.join(sorted(unknown_resp)[:4])}"
    common = mapping(resp.get("common_config"))
    unknown_common = [str(k) for k in common if k not in ("enabled", "min_content_length", "content_type")]
    if unknown_common:
        return "refuse", f"unsupported compressor common_config field(s): {', '.join(sorted(unknown_common)[:4])}"
    resp_enabled = common.get("enabled")
    if resp_enabled is not None:
        if not isinstance(resp_enabled, dict) or resp_enabled.get("runtime_key"):
            return "refuse", "response_direction_config.common_config.enabled with runtime_key is not supported"
        default_enabled = _proto_bool(resp_enabled.get("default_value"))
        if resp_enabled.get("default_value") is not None and default_enabled is None:
            return "refuse", "response_direction_config.common_config.enabled.default_value is invalid"
        if default_enabled is False:
            return "omit", None
    min_len = util.as_int(common.get("min_content_length")) if common.get("min_content_length") is not None else None
    if common.get("min_content_length") is not None and min_len is None:
        return "refuse", "response_direction_config.common_config.min_content_length is invalid"
    raw_types = common.get("content_type")
    content_types = str_list(raw_types) if raw_types is not None else None
    if raw_types is not None and not content_types:
        return "refuse", "response_direction_config.common_config.content_type is invalid"
    remove_ae = resp.get("remove_accept_encoding_header")
    if remove_ae is not None and not isinstance(remove_ae, bool):
        return "refuse", "remove_accept_encoding_header must be a boolean"
    cfg, err = compression_config([algo], min_content_length=min_len, content_types=content_types,
                                  remove_accept_encoding=remove_ae)
    return ("plugin", cfg) if cfg is not None else ("refuse", err)


def _parse_envoy_fault(typed: dict) -> tuple[dict | None, str | None]:
    for unsupported in ("response_rate_limit", "max_active_faults", "downstream_nodes", "upstream_cluster"):
        if typed.get(unsupported):
            return None, f"{unsupported} is not supported"
    delay_cfg: dict[str, Any] | None = None
    abort_cfg: dict[str, Any] | None = None
    raw_delay = typed.get("delay")
    if raw_delay is not None:
        if not isinstance(raw_delay, dict):
            return None, "delay must be a mapping"
        if raw_delay.get("header_delay") is not None:
            return None, "header_delay is not supported"
        duration_ms = util.proto_duration_ms(raw_delay.get("fixed_delay"))
        if duration_ms is None:
            return None, "delay.fixed_delay is missing or invalid"
        pct = _envoy_fractional_percent(raw_delay.get("percentage")) if raw_delay.get("percentage") is not None else 0.0
        if pct is None:
            return None, "delay.percentage is invalid"
        delay_cfg = {"duration_ms": duration_ms, "percentage": pct}
    raw_abort = typed.get("abort")
    if raw_abort is not None:
        if not isinstance(raw_abort, dict):
            return None, "abort must be a mapping"
        if raw_abort.get("header_abort") is not None:
            return None, "header_abort is not supported"
        http_status = util.as_int(raw_abort.get("http_status"))
        grpc_status = util.as_int(raw_abort.get("grpc_status")) if raw_abort.get("grpc_status") is not None else None
        if raw_abort.get("grpc_status") is not None and grpc_status is None:
            return None, "abort.grpc_status is invalid"
        if http_status is None and grpc_status is not None:
            http_status = 503
        if http_status is None:
            return None, "abort.http_status is missing or invalid"
        pct = _envoy_fractional_percent(raw_abort.get("percentage")) if raw_abort.get("percentage") is not None else 0.0
        if pct is None:
            return None, "abort.percentage is invalid"
        abort_cfg = {"status_code": http_status, "percentage": pct}
        if grpc_status is not None:
            abort_cfg["grpc_status"] = grpc_status
    match_headers: dict[str, str] | None = None
    raw_headers = typed.get("headers")
    if raw_headers is not None:
        if not isinstance(raw_headers, list):
            return None, "fault headers matcher must be a list"
        if raw_headers:
            match_headers = {}
            for hm in raw_headers:
                if not isinstance(hm, dict) or not isinstance(hm.get("name"), str):
                    return None, "fault header matcher is malformed"
                if hm.get("invert_match"):
                    return None, "inverted fault header matchers are not supported"
                unsupported_hm = [k for k in hm if k not in ("name", "exact_match", "string_match", "invert_match")]
                if unsupported_hm:
                    return None, f"fault header matcher field {unsupported_hm[0]} is not supported"
                if isinstance(hm.get("exact_match"), str):
                    val = hm["exact_match"]
                elif isinstance(hm.get("string_match"), dict) \
                        and isinstance(hm["string_match"].get("exact"), str) \
                        and not any(k != "exact" and not (k == "ignore_case" and hm["string_match"][k] is False)
                                    for k in hm["string_match"]):
                    val = hm["string_match"]["exact"]
                else:
                    return None, "only exact fault header matchers are supported"
                lower_name = hm["name"].lower()
                if lower_name in match_headers:
                    return None, f"duplicate fault header matcher for {lower_name} is not supported"
                match_headers[lower_name] = val
    return fault_injection_config(abort=abort_cfg, delay=delay_cfg, match_headers=match_headers)


_ENVOY_JWT_PROVIDER_KEYS = frozenset({
    "issuer", "audiences", "remote_jwks", "local_jwks", "from_headers", "from_params",
    "forward", "claim_to_headers", "jwt_cache_config", "clock_skew_seconds",
})
_ENVOY_JWT_ROOT_KEYS = frozenset({"@type", "providers", "rules"})


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
