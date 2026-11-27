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

import json
import re
from typing import Any

from .. import util
from ..errors import InputError
from ..model import BackendRef, HostScope, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from ..safe_load import load_structured
from .common import (SourceContext, apply_first_match_order, check_route_budget, choose_main_port, compression_config,
                     cors_config, cors_origin_star_probe, envoy_cookie_hash, envoy_outlier_passive,
                     fault_injection_config, hash_on_value,
                     header_value_ok, literal_value, mapping, merge_weighted_targets, replaced_prefix_backend_path,
                     request_header_rule, response_header_rule, retry_from_policy, seq, split_csv, str_list)

PLATFORM = "envoy"
_REDIRECT_CODES = {"MOVED_PERMANENTLY": 301, "FOUND": 302, "SEE_OTHER": 303, "TEMPORARY_REDIRECT": 307,
                   "PERMANENT_REDIRECT": 308}


# Map fields whose direct keys are user-chosen identifiers while their values are protobuf messages.
_ENVOY_TYPED_MAP_FIELDS = frozenset({
    "typed_per_filter_config", "per_filter_config", "typed_filter_metadata", "providers", "requirement_map",
})
# Fields whose values are opaque protobuf Structs or arbitrary label maps (left untouched recursively).
_ENVOY_OPAQUE_FIELDS = frozenset({
    "filter_metadata", "static_layer", "dynamic_metadata", "labels",
})
# Protobuf Any @type message names whose 'value' payload is an opaque Struct/Value/ListValue.
_ENVOY_OPAQUE_ANY_TYPES = frozenset({
    "google.protobuf.struct", "google.protobuf.value", "google.protobuf.listvalue",
})
_CAMEL_BOUNDARY_RE = re.compile(r"([a-z0-9])([A-Z])")


def _proto_snake(key: str) -> str:
    """Convert a protobuf canonical JSON camelCase field name to snake_case."""
    if not key or key.startswith("@") or key.islower():
        return key
    return _CAMEL_BOUNDARY_RE.sub(r"\1_\2", key).lower()


def _normalize_envoy_proto(obj: Any, *, preserve_map_keys: bool = False, parent_key: str | None = None) -> Any:
    """Normalize protobuf JSON camelCase field aliases to snake_case, rejecting duplicate spellings."""
    if isinstance(obj, list):
        return [_normalize_envoy_proto(item, preserve_map_keys=False, parent_key=parent_key) for item in obj]
    if not isinstance(obj, dict):
        return obj
    raw_type = obj.get("@type")
    is_opaque_any = (
        isinstance(raw_type, str)
        and raw_type.strip().rsplit("/", 1)[-1].lower() in _ENVOY_OPAQUE_ANY_TYPES
    )
    out: dict[Any, Any] = {}
    for raw_key, raw_val in obj.items():
        if preserve_map_keys or not isinstance(raw_key, str):
            out[raw_key] = _normalize_envoy_proto(raw_val, preserve_map_keys=False, parent_key=None)
            continue
        norm_key = _proto_snake(raw_key)
        if norm_key in out:
            raise InputError(f"Envoy config contains duplicate protobuf field spelling for '{safe_label(norm_key, 60)}'")
        # Node.metadata and google.protobuf.Struct/Value/ListValue Any payloads are opaque JSON.
        if norm_key in _ENVOY_OPAQUE_FIELDS or (parent_key == "node" and norm_key == "metadata") \
                or (is_opaque_any and norm_key == "value"):
            out[norm_key] = raw_val
        else:
            out[norm_key] = _normalize_envoy_proto(
                raw_val,
                preserve_map_keys=norm_key in _ENVOY_TYPED_MAP_FIELDS,
                parent_key=norm_key,
            )
    return out


def _proto_bool(value: Any) -> bool | None:
    """Read a protobuf BoolValue in either JSON bool or ``{value: bool}`` shape."""
    if isinstance(value, bool):
        return value
    if isinstance(value, dict) and isinstance(value.get("value"), bool):
        return value["value"]
    return None


def _proto_uint32(value: Any) -> int | None:
    """Read a protobuf UInt32Value in either JSON int or ``{value: int}`` shape."""
    if isinstance(value, dict):
        if set(value) != {"value"}:
            return None
        value = value.get("value")
    parsed = util.as_int(value)
    return parsed if parsed is not None and 0 <= parsed <= 0xFFFFFFFF else None


_EXACT_TYPE_KINDS = {
    "envoy.extensions.filters.network.http_connection_manager.v3.httpconnectionmanager": "hcm",
    "envoy.config.filter.network.http_connection_manager.v2.httpconnectionmanager": "hcm",
    "envoy.extensions.filters.http.router.v3.router": "router",
    "envoy.config.filter.http.router.v2.router": "router",
    "envoy.extensions.filters.http.cors.v3.cors": "cors",
    "envoy.config.filter.http.cors.v2.cors": "cors",
    "envoy.extensions.filters.http.grpc_web.v3.grpcweb": "grpc_web",
    "envoy.config.filter.http.grpc_web.v2.grpcweb": "grpc_web",
    "envoy.extensions.filters.http.compressor.v3.compressor": "compressor",
    "envoy.extensions.filters.http.fault.v3.httpfault": "fault",
    "envoy.config.filter.http.fault.v2.httpfault": "fault",
    "envoy.extensions.filters.http.jwt_authn.v3.jwtauthentication": "jwt_authn",
    "envoy.config.filter.http.jwt_authn.v2alpha.jwtauthentication": "jwt_authn",
    "envoy.extensions.filters.http.buffer.v3.buffer": "buffer",
    "envoy.config.filter.http.buffer.v2.buffer": "buffer",
    "envoy.extensions.filters.http.grpc_stats.v3.filterconfig": "grpc_stats",
    "envoy.extensions.filters.http.health_check.v3.healthcheck": "health_check",
    "envoy.config.filter.http.health_check.v2.healthcheck": "health_check",
    "envoy.extensions.transport_sockets.tls.v3.downstreamtlscontext": "tls",
    "envoy.extensions.transport_sockets.tls.v3.upstreamtlscontext": "tls",
    "envoy.api.v2.auth.downstreamtlscontext": "tls",
    "envoy.api.v2.auth.upstreamtlscontext": "tls",
    "envoy.extensions.filters.listener.proxy_protocol.v3.proxyprotocol": "proxy_protocol",
    "envoy.extensions.filters.listener.tls_inspector.v3.tlsinspector": "tls_inspector",
    "envoy.extensions.filters.listener.http_inspector.v3.httpinspector": "http_inspector",
    "envoy.extensions.filters.listener.original_dst.v3.originaldst": "original_dst",
}
_EXACT_NAME_KINDS = {
    "envoy.filters.network.http_connection_manager": "hcm",
    "envoy.http_connection_manager": "hcm",
    "envoy.filters.http.router": "router",
    "envoy.router": "router",
    "envoy.filters.http.cors": "cors",
    "envoy.cors": "cors",
    "envoy.filters.http.grpc_web": "grpc_web",
    "envoy.grpc_web": "grpc_web",
    "envoy.filters.http.compressor": "compressor",
    "envoy.filters.http.fault": "fault",
    "envoy.fault": "fault",
    "envoy.filters.http.jwt_authn": "jwt_authn",
    "envoy.filters.http.buffer": "buffer",
    "envoy.buffer": "buffer",
    "envoy.filters.http.grpc_stats": "grpc_stats",
    "envoy.filters.http.health_check": "health_check",
    "envoy.health_check": "health_check",
    "envoy.transport_sockets.tls": "tls",
    "envoy.filters.listener.proxy_protocol": "proxy_protocol",
    "envoy.listener.proxy_protocol": "proxy_protocol",
    "envoy.filters.listener.tls_inspector": "tls_inspector",
    "envoy.listener.tls_inspector": "tls_inspector",
    "envoy.filters.listener.http_inspector": "http_inspector",
    "envoy.listener.http_inspector": "http_inspector",
    "envoy.filters.listener.original_dst": "original_dst",
    "envoy.listener.original_dst": "original_dst",
}


def _kind(item: Any) -> str:
    """Normalize a filter/transport identity using exact ``@type`` message names or canonical filter aliases."""
    item = mapping(item)
    raw_type = mapping(item.get("typed_config")).get("@type")
    type_url = raw_type.strip() if isinstance(raw_type, str) else ""
    name = str(item.get("name", "")).strip()
    if type_url:
        msg_type = type_url.rsplit("/", 1)[-1].lower()
        return _EXACT_TYPE_KINDS.get(msg_type, type_url)
    return _EXACT_NAME_KINDS.get(name.lower(), name or "unknown")


class _Envoy:
    def __init__(self, root: dict, ctx: SourceContext) -> None:
        self.root = root
        self.ctx = ctx
        self.report = ctx.report
        self.plan = Plan(platform=PLATFORM)
        self.clusters: dict[str, dict] = {}
        self.has_runtime = bool(root.get("layered_runtime") or root.get("runtime"))
        self.redirect_vhosts: list[tuple[str, list[str] | None, int | None, list[RouteSpec]]] = []
        self._cors_origin_cache: dict[int, tuple[Any, list[Any], str | None, str]] = {}
        self._cors_config_cache: dict[tuple, tuple[Any, dict | None, str | None]] = {}
        # Hash policy key (as passed to _cluster and part of the upstream key) -> (hash_on, cookie config).
        self._hash_policies: dict[str, tuple[str, dict | None]] = {}

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
        self._resolve_https_redirects()
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

    def _proxy_protocol(self, config: dict, ref: str) -> None:
        """The proxy_protocol listener filter into Ferrum's PROXY protocol suggestion, where it is representable.

        Envoy (``envoy.extensions.filters.listener.proxy_protocol.v3.ProxyProtocol``) accepts v1 and v2 unless
        ``disallowed_versions`` excludes one, and requires the header unless
        ``allow_requests_without_proxy_protocol`` is true. Ferrum's ``FERRUM_FRONTEND_PROXY_PROTOCOL_*``
        (``off|v1|v2|auto``) always requires the header once enabled, so an optional header is reported and
        not suggested.
        """
        settings = self.plan.settings
        disallowed = {str(v).upper() for v in seq(config.get("disallowed_versions"))}
        if _proto_bool(config.get("allow_requests_without_proxy_protocol")) is True:
            version = None
            self.report.warning("envoy-proxy-protocol-optional", ref,
                                "The listener accepts connections with or without a PROXY header; Ferrum requires "
                                "the header once PROXY protocol is enabled, so it is not suggested. Configure it "
                                "manually if every connection carries the header.")
        elif {"V1", "V2"} <= disallowed:
            version = None
            self.report.warning("envoy-proxy-protocol", ref, "The listener disallows both PROXY versions; nothing is "
                                "suggested.")
        else:
            version = "v2" if "V1" in disallowed else "v1" if "V2" in disallowed else "auto"
            self.report.warning("envoy-proxy-protocol", ref, "PROXY protocol is only suggested in ferrum.conf.")
        if config.get("rules") or config.get("pass_through_tlvs"):
            self.report.warning("envoy-proxy-protocol", ref, "PROXY protocol TLV rules are not migrated.")
        if settings.proxy_protocol and settings.proxy_protocol_version != version:
            settings.proxy_protocol_version = None  # listeners disagree: suggest nothing
        else:
            settings.proxy_protocol_version = version
        settings.proxy_protocol = True

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
                self._proxy_protocol(mapping(mapping(listener_filter).get("typed_config")), ref)
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
        hcm_compressors: list[dict[str, Any]] = []
        compressor_filter_count = 0
        active_compressor_count = 0
        hcm_fault: PluginSpec | None = None
        hcm_fault_error: str | None = None
        hcm_filter_kinds: dict[str, str] = {}
        fault_filter_count = 0
        cors_filter_count = 0
        fault_index: int | None = None
        cors_index: int | None = None
        grpc_web_index: int | None = None
        for idx, http_filter in enumerate(seq(config.get("http_filters"))):
            raw_filter = mapping(http_filter)
            if raw_filter.get("config_discovery") is not None:
                filter_refusal = "HTTP filter uses dynamic config_discovery, which is not migrated"
                continue
            kind = _kind(http_filter)
            fname = raw_filter.get("name")
            if isinstance(fname, str) and fname:
                hcm_filter_kinds[fname] = kind
            if kind == "fault":
                fault_filter_count += 1
                if fault_index is None:
                    fault_index = idx
                if fault_filter_count > 1:
                    filter_refusal = "multiple fault HTTP filters in one connection manager are not supported"
            elif kind == "cors":
                cors_filter_count += 1
                if cors_index is None:
                    cors_index = idx
                if cors_filter_count > 1:
                    filter_refusal = "multiple cors HTTP filters in one connection manager are not supported"
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
                # Envoy's buffer filter buffers the entire request body before forwarding or running local replies
                # (returning HTTP 413 on oversized chunked uploads), whereas Ferrum request_size_limiting streams
                # unknown-length chunked bodies upstream. Refuse fail-closed like Traefik buffering.maxRequestBodyBytes.
                filter_refusal = ("HTTP filter buffer buffers and rejects oversized chunked uploads before "
                                  "forwarding or local replies, whereas Ferrum request_size_limiting streams "
                                  "chunked bodies up to max_bytes")
            elif kind == "grpc_web":
                if set(typed) - {"@type"}:
                    filter_refusal = "HTTP filter grpc_web has unsupported configuration fields"
                else:
                    if grpc_web_index is None:
                        grpc_web_index = idx
                    hcm_plugins.append(PluginSpec("grpc_web", {}, ref))
            elif kind == "compressor":
                compressor_filter_count += 1
                comp_status, comp_val = _parse_envoy_compressor(typed)
                if comp_status == "disabled":
                    self.report.info("envoy-compressor-disabled", ref,
                                     "Envoy compressor filter has response compression disabled; omitted.")
                elif comp_status == "plugin":
                    active_compressor_count += 1
                    comp_cfg, dropped_wild = comp_val
                    if dropped_wild:
                        self.report.warning("envoy-compressor", ref,
                                            "Envoy compressor content_type wildcard entries ('*' or 'type/*') were "
                                            "dropped (Envoy matches literally whereas Ferrum treats 'type/*' as a range).")
                    hcm_compressors.append(comp_cfg)
                else:
                    active_compressor_count += 1
                    filter_refusal = f"HTTP filter compressor cannot be migrated ({comp_val})"
            elif kind == "fault":
                fault_status, fault_val = _parse_envoy_fault(typed, has_runtime=self.has_runtime)
                if fault_status == "plugin":
                    hcm_fault = PluginSpec("fault_injection", fault_val, ref)
                elif fault_status == "omit":
                    self.report.info("envoy-fault-noop", ref,
                                     "Envoy fault filter has 0% abort/delay probability (inert); omitted.")
                else:
                    hcm_fault_error = f"HTTP filter fault cannot be migrated ({fault_val})"
            elif kind == "jwt_authn":
                filter_refusal = ("HTTP filter jwt_authn is not auto-migrated: Ferrum jwks_auth requires every JWT "
                                  "header to include a matching kid (whereas Envoy verifies kid-less tokens) and "
                                  "omits non-integer float claim headers; configure jwks_auth manually after "
                                  "confirming IdP token format")
            else:
                filter_refusal = f"HTTP filter {safe_label(kind, 80)} has no safe Ferrum equivalent"
        if compressor_filter_count > 1 and active_compressor_count >= 1:
            filter_refusal = ("multiple compressor HTTP filters (including disabled entries registered in Envoy's "
                              "Accept-Encoding negotiation registry) cannot be proven equivalent to one Ferrum "
                              "compression plugin")
        elif len(hcm_compressors) == 1 and compressor_filter_count == 1:
            hcm_plugins.append(PluginSpec("compression", hcm_compressors[0], ref))
            self.report.warning("envoy-compressor", ref,
                                "Envoy compresses responses without a Content-Type header and strips strong ETag "
                                "validators when compressing, whereas Ferrum v0.9.21 requires a matching Content-Type "
                                "and skips strong-ETag responses by default.")
        route_config = mapping(config.get("route_config"))
        has_local_reply = bool(config.get("local_reply_config"))
        if has_local_reply:
            self.report.warning("envoy-local-reply", ref,
                                "HCM local_reply_config is not migrated; direct_response, redirect, and active fault "
                                "aborts are refused, while gateway-generated errors on forwarding routes (such as "
                                "upstream timeouts) will use Ferrum's default status and body.")
        shared = {"request_add": seq(route_config.get("request_headers_to_add")),
                  "request_remove": seq(route_config.get("request_headers_to_remove")),
                  "response_add": seq(route_config.get("response_headers_to_add")),
                  "response_remove": seq(route_config.get("response_headers_to_remove")),
                  "typed_per_filter_config": mapping(route_config.get("typed_per_filter_config")),
                  "request_mirror_policies": seq(route_config.get("request_mirror_policies")),
                  "hcm_filter_kinds": hcm_filter_kinds,
                  "hcm_plugins": hcm_plugins,
                  "hcm_fault": hcm_fault,
                  "hcm_fault_error": hcm_fault_error,
                  "fault_index": fault_index,
                  "cors_index": cors_index,
                  "grpc_web_index": grpc_web_index,
                  "has_local_reply": has_local_reply}
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
            seen_hosts: set[str] = set()
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
                if host not in seen_hosts:
                    seen_hosts.add(host)
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
            if buffer_limit and buffer_limit > 0:
                if spec.termination is not None:
                    spec.refuse("active Envoy buffer filter can return HTTP 413 before a direct_response or static "
                                "redirect runs, which Ferrum request_termination cannot reproduce")
                else:
                    spec.plugins.append(PluginSpec("request_size_limiting", {"max_bytes": buffer_limit}, ref))
            if not spec.termination and not getattr(spec, "https_redirect", False):
                for hp in shared.get("hcm_plugins", []):
                    spec.plugins.append(PluginSpec(hp.name, hp.config, hp.ref))
            routes.append(spec)
        if not tls and routes and all(getattr(r, "https_redirect", False) for r in routes):
            self.redirect_vhosts.append((ref, hosts, listen_port, routes))
            return
        for route in routes:
            if getattr(route, "https_redirect", False):
                # Keep it as a fail-closed placeholder so its traffic cannot fall through.
                route.skip = False
                route.skip_reason = ""
                if not route.refusals:
                    route.refuse("https_redirect on a route mixed with forwarding routes")
        apply_first_match_order(routes, self.report)
        self.plan.routes.extend(routes)
        if hosts:
            self.plan.host_scopes.append(
                HostScope(ref, list(hosts), listen_port, protocols=frozenset({"https" if tls else "http"}))
            )

    def _resolve_https_redirects(self) -> None:
        """Fold plaintext HTTP-to-HTTPS redirect virtual hosts away only when live HTTPS exists and no other plain routes do."""
        if not self.redirect_vhosts:
            return
        local_plugins = {"cors", "basic_auth", "key_auth", "jwt_auth", "ip_restriction", "rate_limiting",
                         "request_termination", "fault_injection", "request_size_limiting"}
        has_live_https = any(not r.skip and not r.refusals and "https" in (r.protocols or ())
                             for r in self.plan.routes)
        has_other_plain = any(not r.skip and not r.requires_tls and r.listen_port is None for r in self.plan.routes)
        can_fold = (
            has_live_https
            and not has_other_plain
            and all(
                listen_port is None
                and all(not r.refusals and not any(p.name in local_plugins for p in r.plugins) for r in routes)
                for _, _, listen_port, routes in self.redirect_vhosts
            )
        )
        if can_fold:
            for ref, hosts, _listen_port, routes in self.redirect_vhosts:
                for route in routes:
                    if hosts and route.kind == "prefix" and route.path == "/" and route.methods is None:
                        route.kind, route.path = "hostonly", None
                    route.skip = True
                    route.skip_reason = "HTTPS redirect"
                    route.https_redirect_fold = ("envoy-https-redirect", ref)
                self.plan.routes.extend(routes)
            return
        for ref, hosts, listen_port, routes in self.redirect_vhosts:
            for route in routes:
                route.skip = False
                route.skip_reason = ""
                if hosts and route.kind == "prefix" and route.path == "/" and route.methods is None:
                    route.kind, route.path = "hostonly", None
                route.refuse("HTTP-to-HTTPS redirect virtual host cannot be folded away alongside other plaintext "
                             "routes, without a live HTTPS listener, or with local filters/errors")
            apply_first_match_order(routes, self.report)
            self.plan.routes.extend(routes)
            if hosts:
                self.plan.host_scopes.append(
                    HostScope(ref, list(hosts), listen_port, protocols=frozenset({"http"}))
                )

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
            spec.empty_source_prefix = match.get("prefix") == ""
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
        # Resolve the winning fault configuration (most-specific of route > vhost > route_config > HCM)
        # before translating or refusing it, so disabling fault on a route clears an untranslatable parent fault.
        winning_fault: tuple[str, Any] = (
            ("hcm_error", shared["hcm_fault_error"]) if shared.get("hcm_fault_error")
            else ("hcm_plugin", shared.get("hcm_fault"))
        )
        for source, label in ((shared, "route configuration"), (vhost, "virtual host"), (raw, "route")):
            per_filter = mapping(source.get("typed_per_filter_config"))
            others = []
            for key, raw_override in per_filter.items():
                key_str = str(key)
                override = mapping(raw_override)
                override_type = str(override.get("@type", "")).strip().lower()
                override_msg = override_type.rsplit("/", 1)[-1] if override_type else ""
                filter_kind = hcm_filter_kinds.get(key_str)
                is_filter_config = override_msg in (
                    "envoy.config.route.v3.filterconfig",
                    "envoy.api.v2.route.filterconfig",
                )
                if filter_kind == "cors":
                    if override.get("disabled") is True and (not override_msg or is_filter_config):
                        continue
                    if not is_filter_config and (
                        not override_msg or override_msg in (
                            "envoy.extensions.filters.http.cors.v3.corspolicy",
                            "envoy.extensions.filters.http.cors.v3.cors",
                            "envoy.config.filter.http.cors.v2.corspolicy",
                            "envoy.config.filter.http.cors.v2.cors",
                        )
                    ):
                        continue
                if filter_kind == "fault":
                    if override.get("disabled") is True and (not override_msg or is_filter_config):
                        winning_fault = ("disabled", None)
                    elif is_filter_config:
                        winning_fault = ("wrapped", (label, override))
                    elif not override_msg or override_msg in (
                        "envoy.extensions.filters.http.fault.v3.httpfault",
                        "envoy.config.filter.http.fault.v2.httpfault",
                    ):
                        winning_fault = ("override", (label, override))
                    else:
                        winning_fault = ("unsupported", (label, key_str))
                    continue
                others.append(key_str)
            if others:
                names = ", ".join(safe_label(key, 80) for key in others[:3])
                spec.refuse(f"{label} typed_per_filter_config for HTTP filter(s) {names} can enable or change a "
                            "filter for this route, which is not migrated")
        effective_fault: PluginSpec | None = None
        if winning_fault[0] == "hcm_plugin":
            effective_fault = winning_fault[1]
        elif winning_fault[0] == "hcm_error":
            spec.refuse(winning_fault[1])
        elif winning_fault[0] == "wrapped":
            fault_label, wrapper = winning_fault[1]
            inner = wrapper.get("config")
            inner_type = str(mapping(inner).get("@type", "")).strip().lower()
            inner_msg = inner_type.rsplit("/", 1)[-1] if inner_type else ""
            if set(wrapper) <= {"@type", "config", "disabled", "is_optional"} and isinstance(inner, dict) \
                    and (not inner_msg or inner_msg in (
                        "envoy.extensions.filters.http.fault.v3.httpfault",
                        "envoy.config.filter.http.fault.v2.httpfault",
                    )):
                fault_status, fault_val = _parse_envoy_fault(inner, has_runtime=self.has_runtime)
                if fault_status == "plugin":
                    effective_fault = PluginSpec("fault_injection", fault_val, ref)
                elif fault_status == "omit":
                    effective_fault = None
                else:
                    spec.refuse(f"{fault_label} typed_per_filter_config for fault cannot be migrated ({fault_val})")
            else:
                spec.refuse(f"{fault_label} typed_per_filter_config FilterConfig wrapper for fault is not supported")
        elif winning_fault[0] == "override":
            fault_label, fault_override = winning_fault[1]
            fault_status, fault_val = _parse_envoy_fault(fault_override, has_runtime=self.has_runtime)
            if fault_status == "plugin":
                effective_fault = PluginSpec("fault_injection", fault_val, ref)
            elif fault_status == "omit":
                effective_fault = None
            else:
                spec.refuse(f"{fault_label} typed_per_filter_config for fault cannot be migrated ({fault_val})")
        elif winning_fault[0] == "unsupported":
            fault_label, fault_key = winning_fault[1]
            spec.refuse(f"{fault_label} typed_per_filter_config for HTTP filter(s) {safe_label(fault_key, 80)} "
                        "can enable or change a filter for this route, which is not migrated")
        if raw.get("direct_response") is not None:
            self._direct_response(spec, mapping(raw.get("direct_response")))
            if shared.get("has_local_reply"):
                spec.refuse("direct_response under HCM local_reply_config cannot be proven equivalent "
                            "(local_reply_config can rewrite status, body, or content type)")
            if effective_fault is not None:
                spec.refuse("fault filter runs before direct_response in Envoy, whereas Ferrum request_termination "
                            "answers before fault_injection")
            return spec
        if raw.get("redirect") is not None:
            self._redirect(spec, mapping(raw.get("redirect")), tls)
            if shared.get("has_local_reply"):
                spec.refuse("redirect under HCM local_reply_config cannot be proven equivalent "
                            "(local_reply_config can rewrite status, body, or content type)")
            if effective_fault is not None:
                spec.refuse("fault filter runs before redirect in Envoy, whereas Ferrum request_termination "
                            "answers before fault_injection")
            return spec
        action = raw.get("route")
        if not isinstance(action, dict):
            spec.refuse("route action is not a forwarding route")
            return spec
        self._action(spec, action, vhost, shared, ref)
        if effective_fault is not None:
            if shared.get("has_local_reply") and effective_fault.config.get("abort") is not None:
                spec.refuse("fault abort under HCM local_reply_config cannot be proven equivalent "
                            "(local_reply_config can rewrite abort status, body, or content type)")
            gw_idx = shared.get("grpc_web_index")
            f_idx = shared.get("fault_index")
            if gw_idx is not None and f_idx is not None and gw_idx < f_idx \
                    and effective_fault.config.get("abort", {}).get("grpc_status") is not None:
                spec.refuse("grpc_web precedes fault with explicit grpc_status in Envoy http_filters, whereas "
                            "Ferrum fault_injection emits grpc_status only for client-native gRPC (gRPC-Web falls "
                            "back to HTTP 503 / gRPC UNAVAILABLE)")
            spec.plugins.append(PluginSpec(effective_fault.name, effective_fault.config, effective_fault.ref))
        self._headers(spec, raw, vhost, shared, ref)
        cors_active = self._cors(spec, raw, vhost, shared, cors_enabled, hcm_filter_kinds, ref)
        if effective_fault is not None and cors_active:
            f_idx = shared.get("fault_index")
            c_idx = shared.get("cors_index")
            if f_idx is not None and c_idx is not None and f_idx < c_idx:
                spec.refuse("fault filter precedes cors in Envoy http_filters (aborting preflights before CORS), "
                            "whereas Ferrum cors answers preflights in on_request_received before fault_injection "
                            "runs in before_proxy")
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
        raw_port = redirect.get("port_redirect")
        port_redir: int | None = None
        if raw_port is not None:
            parsed_port = util.as_int(raw_port)
            if parsed_port is None or not 0 <= parsed_port <= 65535:
                spec.refuse("redirect port_redirect is invalid")
                return
            port_redir = None if parsed_port == 0 else parsed_port
        if (redirect.get("https_redirect") or redirect.get("scheme_redirect") == "https") \
                and port_redir in (None, 443):
            if not tls and not redirect.get("host_redirect") and not redirect.get("path_redirect"):
                spec.https_redirect = True  # type: ignore[attr-defined]
                spec.skip = True
                spec.skip_reason = "HTTPS redirect"
                return
        code = _REDIRECT_CODES.get(str(redirect.get("response_code", "MOVED_PERMANENTLY")))
        scheme = redirect.get("scheme_redirect") or ("https" if redirect.get("https_redirect") else None)
        host = redirect.get("host_redirect")
        path = redirect.get("path_redirect")
        if code is None or not (scheme and host and isinstance(path, str) and path):
            spec.refuse("only fully static redirects (scheme, host and path) are migrated")
            return
        if "?" not in path and redirect.get("strip_query") is not True:
            spec.refuse("static redirect preserves incoming query strings unless strip_query: true or path_redirect "
                        "sets a fixed query, which Ferrum request_termination cannot reproduce dynamically")
            return
        norm_path = path if path.startswith("/") else "/" + path
        host_str = str(host)
        if port_redir is not None:
            if ":" in host_str and not (host_str.startswith("[") and host_str.endswith("]")):
                spec.refuse("redirect specifies both host_redirect port and port_redirect")
                return
            authority = f"{host_str}:{port_redir}"
        else:
            authority = host_str
        location = f"{scheme}://{authority}{norm_path}"
        if not header_value_ok(location, nonempty=True, strict_ws=True):
            spec.refuse("redirect location is not a valid header value")
            return
        spec.termination = {"status_code": code, "headers": {"location": location}, "body": ""}

    def _action(self, spec: RouteSpec, action: dict, vhost: dict, shared: dict, ref: str) -> None:
        hash_on = None
        for policy in seq(action.get("hash_policy")):
            policy = mapping(policy)
            if mapping(policy.get("header")).get("header_name"):
                hash_on = hash_on_value("header", policy["header"]["header_name"])
                if hash_on is None:
                    self.report.warning("envoy-hash", ref, "The hash header name is not an HTTP token Ferrum accepts; "
                                        "round robin is used (stickiness lost).")
            elif mapping(policy.get("cookie")).get("name"):
                cookie_hash, cookie_config = envoy_cookie_hash(mapping(policy["cookie"]), self.report, "envoy-hash", ref)
                if cookie_hash is not None:
                    hash_on = json.dumps([cookie_hash, cookie_config], sort_keys=True)
                    self._hash_policies[hash_on] = (cookie_hash, cookie_config)
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
        # Envoy treats an empty prefix_rewrite as unset (router config_impl.cc): the path is forwarded unchanged.
        if isinstance(rewrite, str) and rewrite:
            if spec.kind == "regex":
                spec.refuse("prefix_rewrite on a regex route")
            elif spec.empty_source_prefix:
                # An empty matched prefix is replaced by the rewrite: rewrite + the whole path, no stripping.
                spec.strip = False
                spec.backend_path = rewrite
            else:
                spec.strip = True
                spec.backend_path, exact = replaced_prefix_backend_path(spec.kind, spec.path, rewrite)
                if not exact:
                    self.report.warning("envoy-rewrite-slash", ref, "The prefix ends with '/' but prefix_rewrite does "
                                        "not: Envoy joins the rest of the path without a slash (/v1 + x = /v1x), "
                                        "whereas Ferrum inserts one (/v1/x).")
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
        # Envoy resolves request_mirror_policies by most-specific non-empty list across route, vhost, route_config.
        raw_mirrors = (seq(action.get("request_mirror_policies"))
                       or seq(vhost.get("request_mirror_policies"))
                       or shared.get("request_mirror_policies")
                       or [])
        if raw_mirrors:
            self._mirror_policies(spec, raw_mirrors, ref)

    def _mirror_policies(self, spec: RouteSpec, policies: list, ref: str) -> None:
        # Envoy mirrors rewrite :authority (appending '-shadow' by default, or keeping client :authority when
        # disable_shadow_host_suffix_append is true), whereas Ferrum file-mode request_mirror strips Host so the
        # mirror target receives its own dial authority. Drop active Envoy mirror policies with a warning instead of
        # replaying traffic to a different virtual host.
        dropped = 0
        for policy in policies:
            if not isinstance(policy, dict):
                dropped += 1
                continue
            rf = policy.get("runtime_fraction")
            if rf is not None:
                # In Envoy protobuf, an explicit runtime_fraction wrapper without runtime_key and without default_value
                # (or numerator 0) is 0% (disabled), not 100%.
                if isinstance(rf, dict) and not rf.get("runtime_key") and not self.has_runtime:
                    dv = rf.get("default_value")
                    if dv is None:
                        continue
                    parsed_pct = _envoy_fractional_percent(dv)
                    if parsed_pct == 0.0:
                        continue
            dropped += 1
        if dropped:
            self.report.warning("envoy-mirror", ref,
                                f"{dropped} request_mirror_policies entry(ies) were dropped: Envoy mirrors preserve "
                                "or append '-shadow' to :authority, whereas Ferrum file-mode request_mirror strips "
                                "Host to the mirror endpoint's authority. Configure request_mirror manually if the "
                                "shadow destination accepts its own endpoint Host.")

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

    def _resolve_cors_origins(self, merged_origins: Any) -> tuple[list[Any], str | None, str]:
        """Parse, bound (<= 64), and star-probe one CORS origin list once per shared source object."""
        if merged_origins is None:
            return [], None, "no_match"
        cache_key = id(merged_origins)
        cached = self._cors_origin_cache.get(cache_key)
        if cached is not None and cached[0] is merged_origins:
            return list(cached[1]), cached[2], cached[3]
        raw_list = seq(merged_origins)
        if len(raw_list) > 64:
            res: tuple[list[Any], str | None, str] = ([], "more than 64 allowed origins", "no_match")
            self._cors_origin_cache[cache_key] = (merged_origins, *res)
            return list(res[0]), res[1], res[2]
        origins: list[Any] = []
        matcher_problem: str | None = None
        for matcher in raw_list:
            matcher = mapping(matcher)
            extra_keys = set(matcher) - {"exact", "prefix", "safe_regex", "ignore_case"}
            raw_ignore = matcher.get("ignore_case")
            if extra_keys or (raw_ignore is not None and raw_ignore is not False):
                origins = []
                matcher_problem = "origin matcher uses ignore_case or unsupported StringMatcher options"
                break
            present = [k for k in ("exact", "prefix", "safe_regex") if k in matcher]
            if len(present) != 1:
                origins = []
                matcher_problem = "origin matcher is invalid or ambiguous"
                break
            kind = present[0]
            if kind == "exact":
                origins.append({"exact": matcher["exact"]})
            elif kind == "prefix":
                origins.append({"prefix": matcher["prefix"]})
            else:
                origins.append({"regex": mapping(matcher["safe_regex"]).get("regex")})
        star_state = "no_match"
        if matcher_problem is None:
            for o in origins:
                probe = cors_origin_star_probe(o)
                if probe == "error":
                    star_state = "error"
                    break
                if probe == "star":
                    star_state = "star"
        self._cors_origin_cache[cache_key] = (merged_origins, list(origins), matcher_problem, star_state)
        return origins, matcher_problem, star_state

    def _cors(self, spec: RouteSpec, raw: dict, vhost: dict, shared: dict, enabled: bool,
              hcm_filter_kinds: dict[str, str], ref: str) -> bool:
        # Match Envoy cors_filter.cc initializeCorsPolicies precedence:
        # 1) Walk route -> vhost -> route_config typed_per_filter_config for cors-kind entries. If the most
        #    specific cors entry is FilterConfig{disabled: true}, the filter is disabled (legacy route.cors/vhost.cors
        #    cannot re-enable it).
        # 2) Collect all non-FilterConfig typed CorsPolicy entries (most specific first).
        # 3) Read legacy route.cors / vhost.cors ONLY when no typed CorsPolicy exists at any level.
        # 4) Enablement (enabled / filter_enabled / shadow_enabled) comes from policies[0]; other fields inherit
        #    from the first policy in policies that sets each field.
        typed_policies: list[dict] = []
        saw_cors_override = False
        for per_filter in (mapping(raw.get("typed_per_filter_config")),
                           mapping(vhost.get("typed_per_filter_config")),
                           mapping(shared.get("typed_per_filter_config"))):
            for k, v in per_filter.items():
                if hcm_filter_kinds.get(str(k)) != "cors":
                    continue
                override = mapping(v)
                otype = str(override.get("@type", "")).strip().lower()
                omsg = otype.rsplit("/", 1)[-1] if otype else ""
                is_fc = omsg in ("envoy.config.route.v3.filterconfig", "envoy.api.v2.route.filterconfig")
                if not saw_cors_override:
                    saw_cors_override = True
                    if override.get("disabled") is True and (not omsg or is_fc):
                        self.report.info("envoy-cors-inactive", ref,
                                         "CORS filter disabled via typed_per_filter_config; omitted.")
                        return False
                if not is_fc:
                    typed_policies.append(override)
                break
        route_action = mapping(raw.get("route"))
        if typed_policies:
            policies = typed_policies
        else:
            legacy_route = route_action.get("cors") if route_action.get("cors") is not None else raw.get("cors")
            policies = [p for p in (legacy_route, vhost.get("cors")) if isinstance(p, dict)]
        if not policies:
            return False
        if not enabled and not typed_policies:
            self.report.info("envoy-cors-inactive", ref, "CORS policy present without the cors HTTP filter; ignored "
                             "(it had no effect in Envoy).")
            return False
        # Check Envoy enablement/shadow controls on the most specific policy so 0% / shadow-only CORS never activates.
        top_policy = policies[0]
        raw_legacy_enabled = top_policy.get("enabled")
        if raw_legacy_enabled is not None:
            legacy_bool = _proto_bool(raw_legacy_enabled)
            if legacy_bool is False:
                self.report.info("envoy-cors-inactive", ref, "CORS policy has enabled: false; omitted.")
                return False
            if legacy_bool is None:
                spec.refuse("CORS policy has an invalid enabled value")
                return False
        raw_fe = top_policy.get("filter_enabled")
        if raw_fe is not None:
            if not isinstance(raw_fe, dict) or raw_fe.get("runtime_key"):
                spec.refuse("CORS policy uses dynamic or malformed filter_enabled that cannot be preserved statically")
                return False
            dv = raw_fe.get("default_value")
            fe_pct = 0.0 if dv is None else _envoy_fractional_percent(dv)
            if fe_pct is None or fe_pct not in (0.0, 100.0):
                spec.refuse("CORS policy uses fractional or invalid filter_enabled that cannot be preserved statically")
                return False
            if fe_pct == 0.0:
                self.report.info("envoy-cors-inactive", ref,
                                 "CORS policy has filter_enabled 0% (inactive or shadow-only); omitted.")
                return False
        elif top_policy.get("shadow_enabled") is not None:
            spec.refuse("CORS policy sets shadow_enabled without an explicit filter_enabled; review manually")
            return False
        # Merge CORS fields most-specific-first matching Envoy's cors_filter.cc field fallback across policy layers.
        merged_origins = next((p["allow_origin_string_match"] for p in policies
                               if seq(p.get("allow_origin_string_match"))), None)
        merged_methods = next((p["allow_methods"] for p in policies
                               if isinstance(p.get("allow_methods"), str) and p["allow_methods"]), None)
        merged_headers = next((p["allow_headers"] for p in policies
                               if isinstance(p.get("allow_headers"), str) and p["allow_headers"]), None)
        merged_expose = next((p["expose_headers"] for p in policies
                              if isinstance(p.get("expose_headers"), str) and p["expose_headers"]), None)
        merged_max_age = next((p["max_age"] for p in policies
                               if p.get("max_age") is not None and p.get("max_age") != ""), None)
        raw_creds = next((p["allow_credentials"] for p in policies if p.get("allow_credentials") is not None), None)
        origins, matcher_problem, star_state = self._resolve_cors_origins(merged_origins)
        creds: bool | None = None
        if raw_creds is not None:
            creds = _proto_bool(raw_creds)
            if creds is None:
                spec.refuse("CORS policy has an invalid non-boolean allow_credentials value")
                return False
        if matcher_problem:
            spec.refuse(f"CORS policy cannot be safely migrated ({matcher_problem})")
            return False
        raw_fnmp = next((p["forward_not_matching_preflights"] for p in policies
                         if p.get("forward_not_matching_preflights") is not None), None)
        unmatched_mode = "forward"
        if raw_fnmp is not None:
            fnmp_bool = _proto_bool(raw_fnmp)
            if fnmp_bool is None:
                spec.refuse("CORS policy has an invalid forward_not_matching_preflights value")
                return False
            unmatched_mode = "forward" if fnmp_bool else "ignore"
        raw_pna = next((p["allow_private_network_access"] for p in policies
                        if p.get("allow_private_network_access") is not None), None)
        pna: bool | None = None
        if raw_pna is not None:
            pna = _proto_bool(raw_pna)
            if pna is None:
                spec.refuse("CORS policy has an invalid non-boolean allow_private_network_access value")
                return False
        parsed_methods = split_csv(merged_methods) or None
        parsed_headers = split_csv(merged_headers) or None
        parsed_expose = split_csv(merged_expose) or None
        # Envoy treats any origin matcher matching literal "*" (exact, prefix, or safe_regex) as allow-all.
        if star_state == "error":
            spec.refuse("active CORS policy contains an origin regex that cannot be safely verified or admitted")
            return False
        if star_state == "star":
            if creds is True:
                spec.refuse("CORS policy combines allow_credentials=true with a wildcard '*' origin matcher, "
                            "which Ferrum downgrades by disabling credentials")
                return False
            origins = ["*"]
        if creds is True and any("*" in (lst or []) for lst in (parsed_methods, parsed_headers, parsed_expose)):
            spec.refuse("CORS policy combines allow_credentials=true with wildcard '*' in "
                        "allow_methods/allow_headers/expose_headers, which Ferrum returns literally; specify "
                        "explicit method and header lists")
            return False
        if creds is not True and merged_headers == "*":
            # Envoy's header-reflection branch triggers only for the exact string "*"; padded (" * ") or mixed
            # lists ("*, X-Trace") are returned literally. Without credentials, emit ["*", "authorization"] for
            # exact "*" so Fetch preflights for bearer-token requests match Envoy's reflection behavior.
            parsed_headers = ["*", "authorization"]
        # Use Ferrum's unmatched_preflights mode so omitted allow_methods/allow_headers stay empty and omitted
        # max_age stays absent (matching Envoy cors_filter.cc instead of inheriting Ferrum's permissive defaults).
        # Pass raw merged_max_age so invalid or >u64 values fail cors_config rather than silently becoming None.
        # Cache validated CORS config by shared origin object and effective fields, and emit as a shared
        # proxy_group plugin so thousands of routes inheriting one large regex origin list emit one config entry.
        cacheable_age = merged_max_age if isinstance(merged_max_age, (str, int, float, type(None))) else None
        cfg_key = (
            id(merged_origins),
            star_state,
            tuple(parsed_methods) if parsed_methods is not None else None,
            tuple(parsed_headers) if parsed_headers is not None else None,
            tuple(parsed_expose) if parsed_expose is not None else None,
            creds,
            type(merged_max_age).__name__,
            cacheable_age,
            pna,
            unmatched_mode,
        ) if isinstance(merged_max_age, (str, int, float, type(None))) else None
        cached_cfg = self._cors_config_cache.get(cfg_key) if cfg_key is not None else None
        if cached_cfg is not None and cached_cfg[0] is merged_origins:
            built, problem = cached_cfg[1], cached_cfg[2]
        else:
            built, problem = cors_config(origins, parsed_methods, parsed_headers, parsed_expose,
                                         creds, merged_max_age, private_network=pna,
                                         unmatched_preflights=unmatched_mode)
            if cfg_key is not None:
                self._cors_config_cache[cfg_key] = (merged_origins, built, problem)
        if built:
            spec.plugins.append(PluginSpec("cors", built, ref, shared_key="envoy-cors"))
            return True
        spec.refuse(f"active CORS policy cannot be admitted by Ferrum ({problem})")
        return False

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
        hash_key, cookie_config = self._hash_policies.get(hash_on, (hash_on, None)) if hash_on else (None, None)
        # One upstream per cluster and hashing key: routes that hash the same cookie into one cluster share
        # Envoy's affinity, so they must share one Ferrum upstream (its bindings are per upstream). The first
        # route's cookie policy is kept and a differing one is reported.
        key = f"{name}|{hash_key}"
        existing = self.plan.upstreams.get(key)
        if existing is not None and existing.hash_on_cookie_config is not None and cookie_config is not None \
                and existing.hash_on_cookie_config != cookie_config:
            self.report.warning("envoy-hash-cookie-conflict", ref,
                                "Routes hash the same cookie into this cluster with different cookie settings (ttl or "
                                "path). Ferrum keeps one upstream with the first route's settings so the affinity "
                                "stays shared; reconcile the cookie settings manually.")
        if key not in self.plan.upstreams:
            spec = UpstreamSpec(key=key, name=name, ref=ref, targets=targets, tls=tls,
                                source_destinations={f"envoy:{name}"})
            policy = str(raw.get("lb_policy", "ROUND_ROBIN")).upper()
            spec.algorithm = {"ROUND_ROBIN": "round_robin", "LEAST_REQUEST": "least_connections",
                              "RANDOM": "random"}.get(policy, "round_robin")
            if policy in ("RING_HASH", "MAGLEV"):
                if hash_key:
                    spec.algorithm = "consistent_hashing"
                    spec.hash_on, spec.hash_on_cookie_config = hash_key, cookie_config
                else:
                    self.report.warning("envoy-hash", ref, "Ring-hash without a route hash policy; using round robin.")
            elif policy not in ("ROUND_ROBIN", "LEAST_REQUEST", "RANDOM"):
                self.report.warning("envoy-lb-policy", ref, "Load-balancing policy has no equivalent; round robin.")
            spec.health_checks = self._health(raw, ref)
            if isinstance(raw.get("outlier_detection"), dict):
                passive = envoy_outlier_passive(raw["outlier_detection"], targets, cluster_type == "LOGICAL_DNS",
                                                self.report, ref)
                if passive:
                    spec.health_checks = {**(spec.health_checks or {}), "passive": passive}
                    spec.outlier_scoped = True
            self._circuit_breakers(raw.get("circuit_breakers"), ref)
            self.plan.upstreams[key] = spec
        result["backend"] = BackendRef(scheme=scheme, upstream_key=key)
        result["tls_key"] = tls.key() + scheme
        result["targets"] = targets
        return result

    def _circuit_breakers(self, raw: Any, ref: str) -> None:
        """Envoy cluster ``circuit_breakers`` thresholds are concurrency limits on the cluster (connections,
        pending requests, active requests, outstanding retries). Ferrum Edge enforces the comparable limits only
        for mesh-projected destinations (``src/backend_active_request_limit.rs``); file-mode proxies and upstreams
        have no such fields, so every threshold the source sets is reported. Ferrum's own ``circuit_breaker`` is a
        failure-rate breaker, not a concurrency limit, and is not used for them."""
        fields = set()
        for threshold in seq(mapping(raw).get("thresholds")):
            fields |= {key for key in ("max_connections", "max_pending_requests", "max_requests", "max_retries",
                                        "retry_budget", "max_connection_pools") if mapping(threshold).get(key) is not None}
        if fields or seq(mapping(raw).get("per_host_thresholds")):
            self.report.warning("envoy-circuit-breakers", ref,
                                "circuit_breakers " + (", ".join(sorted(fields)) or "per_host_thresholds") +
                                " are not migrated: Ferrum file mode has no per-upstream connection, pending-request, "
                                "active-request or retry concurrency limits.")

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
        live: list[dict] = []  # clusters that receive traffic
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
            weight = util.as_int(child.get("weight")) or 0
            parts.append((weight, result["targets"]))
            if weight > 0:
                live.append(result)
        if len(keys) > 1:
            problems.append("weighted clusters differ in TLS settings")
        if len(connects) > 1:
            problems.append("weighted clusters differ in connect_timeout")
        if problems or first is None:
            return {"problems": problems or ["weighted clusters are empty"]}
        if len(live) == 1:
            # Only one cluster receives traffic: route to it as it is, with its own upstream policy.
            return {"problems": [], "backend": live[0]["backend"], "connect": live[0].get("connect")}
        merged = merge_weighted_targets(parts)
        if merged is None:
            return {"problems": ["weighted clusters send no traffic anywhere"]}
        if any((self.plan.upstreams[r["backend"].upstream_key].health_checks or {}).get("passive") for r in live):
            self.report.warning("envoy-outlier-weighted", spec.ref,
                                "The weighted clusters' outlier detection applies to each cluster's own hosts; Ferrum "
                                "serves the split from one merged upstream, so it was not migrated for this route.")
        targets, approximate = merged
        if approximate:
            self.report.warning("envoy-weights", spec.ref, "Weighted split was rounded to integer target weights.")
        base = self.plan.upstreams[first["backend"].upstream_key]
        key = f"weighted:{spec.ref}"
        destinations = set().union(*(self.plan.upstreams[r["backend"].upstream_key].source_destinations for r in live))
        self.plan.upstreams[key] = UpstreamSpec(key=key, name=f"{spec.name}-weighted", ref=spec.ref, targets=targets,
                                                tls=base.tls, algorithm="weighted_round_robin",
                                                source_destinations=destinations)
        return {"problems": [], "backend": BackendRef(scheme=first["backend"].scheme, upstream_key=key),
                "connect": first.get("connect")}


_DENOMINATOR_MAX = {
    "HUNDRED": 100,
    "TEN_THOUSAND": 10_000,
    "MILLION": 1_000_000,
}
_DENOMINATOR_ENUM = {0: 100, 1: 10_000, 2: 1_000_000}


def _envoy_fractional_percent(value: Any) -> float | None:
    if not isinstance(value, dict):
        return None
    if "numerator" not in value or value.get("numerator") is None:
        numerator = 0
    else:
        numerator = util.as_int(value.get("numerator"))
    if numerator is None or numerator < 0:
        return None
    raw_denom = value.get("denominator")
    if raw_denom is None:
        denom_max = 100
    elif isinstance(raw_denom, int) and not isinstance(raw_denom, bool):
        denom_max = _DENOMINATOR_ENUM.get(raw_denom)
    elif isinstance(raw_denom, str):
        denom_max = _DENOMINATOR_MAX.get(raw_denom.upper())
    else:
        denom_max = None
    if denom_max is None or numerator > denom_max:
        return None
    return (numerator * 100.0) / denom_max


# Default MIME types from Envoy compressor_filter.cc (defaultContentEncoding()) when content_type is unset/empty.
_ENVOY_DEFAULT_COMPRESSOR_CONTENT_TYPES = [
    "text/html",
    "text/plain",
    "text/css",
    "application/javascript",
    "application/x-javascript",
    "text/javascript",
    "text/x-javascript",
    "text/ecmascript",
    "text/js",
    "text/jscript",
    "text/x-js",
    "application/ecmascript",
    "application/x-json",
    "application/xml",
    "application/json",
    "image/svg+xml",
    "text/xml",
    "application/xhtml+xml",
    "application/grpc-web",
    "application/grpc-web+proto",
]


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
            return "disabled", None
    raw_min = common.get("min_content_length")
    if raw_min is None:
        # Envoy CommonDirectionConfig resolves omitted or 0 min_content_length to 30 bytes (Ferrum defaults to 256).
        min_len: int | None = 30
    else:
        min_len = _proto_uint32(raw_min)
        if min_len is None:
            return "refuse", "response_direction_config.common_config.min_content_length is invalid"
        if min_len == 0:
            min_len = 30
    raw_types = common.get("content_type")
    content_types = str_list(raw_types) if raw_types is not None else None
    if raw_types is not None and content_types is None:
        return "refuse", "response_direction_config.common_config.content_type is invalid"
    dropped_wild = False
    if not content_types:
        # Protobuf repeated content_type defaults (when omitted or empty) to Envoy's defaultContentEncoding() list
        # rather than inheriting Ferrum's smaller default MIME allow-list.
        content_types = list(_ENVOY_DEFAULT_COMPRESSOR_CONTENT_TYPES)
    else:
        # Envoy matches content_type literally; entries containing '*' never match real responses in Envoy,
        # whereas Ferrum treats 'type/*' as a range. Drop wildcard entries and omit if none remain.
        exact_types = [ct for ct in content_types if "*" not in ct]
        dropped_wild = len(exact_types) != len(content_types)
        if not exact_types:
            return "refuse", ("content_type contains only wildcard entries (literal in Envoy, which still compresses "
                              "responses without Content-Type and can strip Accept-Encoding)")
        content_types = exact_types
    remove_ae = resp.get("remove_accept_encoding_header")
    if remove_ae is None:
        # Envoy ResponseDirectionConfig defaults remove_accept_encoding_header to false (Ferrum defaults to true).
        remove_ae = False
    elif not isinstance(remove_ae, bool):
        return "refuse", "remove_accept_encoding_header must be a boolean"
    raw_choose_first = typed.get("choose_first")
    if raw_choose_first is not None and not isinstance(raw_choose_first, bool):
        return "refuse", "choose_first must be a boolean"
    cfg, err = compression_config([algo], min_content_length=min_len, content_types=content_types,
                                  allow_ranges=False, remove_accept_encoding=remove_ae)
    return ("plugin", (cfg, dropped_wild)) if cfg is not None else ("refuse", err)


def _parse_envoy_fault(typed: dict, *, has_runtime: bool = False) -> tuple[str, Any]:
    if has_runtime:
        return "refuse", ("fault filter is runtime-backed when Envoy layered_runtime/runtime is configured and "
                          "cannot be proven static")
    unknown_root = [str(k) for k in typed if k not in ("@type", "delay", "abort", "headers")]
    if unknown_root:
        return "refuse", f"unsupported fault field(s): {', '.join(sorted(unknown_root)[:4])}"
    delay_cfg: dict[str, Any] | None = None
    abort_cfg: dict[str, Any] | None = None
    raw_delay = typed.get("delay")
    if raw_delay is not None:
        if not isinstance(raw_delay, dict):
            return "refuse", "delay must be a mapping"
        unknown_d = [str(k) for k in raw_delay if k not in ("fixed_delay", "percentage")]
        if unknown_d:
            return "refuse", f"unsupported fault delay field(s): {', '.join(sorted(unknown_d)[:4])}"
        duration_ms = util.proto_duration_ms(raw_delay.get("fixed_delay"))
        if duration_ms is None:
            return "refuse", "delay.fixed_delay is missing or invalid"
        pct = _envoy_fractional_percent(raw_delay.get("percentage")) if raw_delay.get("percentage") is not None else 0.0
        if pct is None:
            return "refuse", "delay.percentage is invalid"
        if pct > 0.0:
            delay_cfg = {"duration_ms": duration_ms, "percentage": pct}
    raw_abort = typed.get("abort")
    if raw_abort is not None:
        if not isinstance(raw_abort, dict):
            return "refuse", "abort must be a mapping"
        unknown_a = [str(k) for k in raw_abort if k not in ("http_status", "grpc_status", "percentage")]
        if unknown_a:
            return "refuse", f"unsupported fault abort field(s): {', '.join(sorted(unknown_a)[:4])}"
        http_raw = raw_abort.get("http_status")
        grpc_raw = raw_abort.get("grpc_status")
        if http_raw is not None and grpc_raw is not None:
            return "refuse", "abort cannot set both http_status and grpc_status"
        http_status = util.as_int(http_raw) if http_raw is not None else None
        grpc_status = util.as_int(grpc_raw) if grpc_raw is not None else None
        if grpc_raw is not None and grpc_status is None:
            return "refuse", "abort.grpc_status is invalid"
        if http_raw is not None and http_status is None:
            return "refuse", "abort.http_status is invalid"
        if http_status is None and grpc_status is not None:
            # Envoy fault_filter.cc responds with HTTP 200 for gRPC-status aborts; Ferrum uses status_code directly.
            http_status = 200
        if http_status is None:
            return "refuse", "abort.http_status is missing or invalid"
        pct = _envoy_fractional_percent(raw_abort.get("percentage")) if raw_abort.get("percentage") is not None else 0.0
        if pct is None:
            return "refuse", "abort.percentage is invalid"
        if pct > 0.0:
            abort_cfg = {"status_code": http_status, "percentage": pct, "body": "fault filter abort"}
            if grpc_status is not None:
                abort_cfg["grpc_status"] = grpc_status
    if delay_cfg is None and abort_cfg is None:
        return "omit", None
    raw_headers = typed.get("headers")
    if raw_headers is not None:
        if not isinstance(raw_headers, list):
            return "refuse", "fault headers matcher must be a list"
        if raw_headers:
            return "refuse", ("fault headers matchers are not migrated (Envoy compares comma-joined header values "
                              "whereas Ferrum matches any individual header line)")
    cfg, err = fault_injection_config(abort=abort_cfg, delay=delay_cfg)
    return ("plugin", cfg) if cfg is not None else ("refuse", err)


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
    return _Envoy(_normalize_envoy_proto(documents[0]), ctx).run()
