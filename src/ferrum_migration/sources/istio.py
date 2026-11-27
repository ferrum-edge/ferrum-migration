"""Istio networking CRDs (multi-document YAML or a ``kind: List``) to the IR.

This is an *ingress projection*: Gateway-bound VirtualServices are translated
into Ferrum edge routes using the Gateway servers' hosts/ports/TLS,
DestinationRules (TLS mode, load balancer) and ServiceEntries (static
endpoints). Service-discovery hosts (``*.svc.cluster.local``) are emitted as
plain DNS targets. Mesh-internal routing (``gateways: [mesh]``), workload mTLS
and sidecar behavior are reported, not translated or claimed.
AuthorizationPolicy/RequestAuthentication/EnvoyFilter/WasmPlugin resources that
(may) apply to a Gateway's workloads refuse that Gateway's routes. Kubernetes
Secrets are never read.
"""

from __future__ import annotations

import ipaddress
import json
import math
from typing import Any

from .. import matching, util
from ..errors import InputError
from ..model import BackendRef, HostScope, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from ..safe_load import load_structured
from .common import (SourceContext, apply_first_match_order, check_route_budget, choose_main_port, cors_config,
                     cors_origin_star_probe, envoy_cookie_hash, fault_injection_config, hash_on_value,
                     endpoints_are_hosts, header_value_ok, istio_connection_pool, istio_outlier_passive,
                     literal_value, mapping,
                     merge_weighted_targets, parse_percentage, replaced_prefix_backend_path, request_header_rule,
                     response_header_rule, retry_from_policy, seq, str_list)

PLATFORM = "istio"
ROOT_NAMESPACE = "istio-system"
ISTIO_GROUPS = ("networking.istio.io/", "security.istio.io/", "extensions.istio.io/", "telemetry.istio.io/")
POLICY_KINDS = ("AuthorizationPolicy", "RequestAuthentication", "EnvoyFilter", "WasmPlugin")
DEFAULT_RETRY_ON = "connect-failure,refused-stream,unavailable,cancelled,retriable-status-codes"
# ServerTLSSettings fields that restrict which client certificates a MUTUAL/OPTIONAL_MUTUAL server accepts.
CLIENT_CERT_CONSTRAINTS = ("subjectAltNames", "verifyCertificateSpki", "verifyCertificateHash", "caCrl")


def _meta(obj: dict) -> tuple[str, str]:
    metadata = mapping(obj.get("metadata"))
    return str(metadata.get("namespace") or "default"), str(metadata.get("name") or "unnamed")


class _Istio:
    def __init__(self, objects: list[dict], ctx: SourceContext) -> None:
        self.ctx = ctx
        self.report = ctx.report
        self.plan = Plan(platform=PLATFORM)
        self.gateways: dict[tuple[str, str], dict] = {}
        self.virtual_services: list[dict] = []
        self.destination_rules: list[dict] = []
        self.service_entries: list[dict] = []
        self.policies: list[dict] = []
        self.no_dr_warned = False
        # internal.istio.io/route-semantics of the VirtualService being translated ("ingress", "gateway" or None).
        self.route_semantics: str | None = None
        self.resilience_cache: dict[tuple, tuple[dict | None, dict]] = {}
        # --kubernetes-service-discovery: Kubernetes Service objects from the input, by (namespace, name).
        self.services: dict[tuple[str, str], dict] = {}
        self.discovery_namespaces: set[str] = set()
        self.discovery_reported: set[tuple[str, str]] = set()
        self.shared_bind: str | None = None
        # One entry per emitted projection (VirtualService x Gateway binding x frontend group), checked together
        # once every binding is known (see _check_frontend_scopes).
        self.projections: list[dict] = []
        for obj in objects:
            self._classify(obj)

    def _classify(self, obj: dict) -> None:
        kind = str(obj.get("kind", ""))
        api = str(obj.get("apiVersion", ""))
        namespace, name = _meta(obj)
        ref = f"{kind or 'object'} {safe_label(namespace)}/{safe_label(name)}"
        if kind == "Secret":
            self.report.warning("istio-secret-ignored", ref, "Kubernetes Secret objects are never read or copied.")
            return
        if kind == "Service" and api == "v1" and self.ctx.kubernetes_service_discovery:
            self.services[(namespace, name)] = obj  # selects the EndpointSlice port (--kubernetes-service-discovery)
            return
        if not api.startswith(ISTIO_GROUPS):
            self.report.info("istio-object-ignored", ref, "Non-Istio object ignored.")
            return
        if kind == "Gateway":
            if (namespace, name) in self.gateways:
                raise InputError("duplicate Istio Gateway")
            self.gateways[(namespace, name)] = obj
        elif kind == "VirtualService":
            self.virtual_services.append(obj)
        elif kind == "DestinationRule":
            self.destination_rules.append(obj)
        elif kind == "ServiceEntry":
            self.service_entries.append(obj)
        elif kind in POLICY_KINDS:
            self.policies.append(obj)
        elif kind == "PeerAuthentication":
            self.report.warning("istio-peer-authentication", ref, "PeerAuthentication governs workload mTLS; Ferrum in "
                                "file mode talks to backends without mesh identity, so STRICT workloads reject it "
                                "(fail closed).", "Use Ferrum mesh mode or DestinationRule TLS with file paths.")
        else:
            self.report.info("istio-kind-ignored", ref, f"{safe_label(kind, 40)} is not migrated.")

    def run(self) -> Plan:
        self._elect_ports()
        check_route_budget(sum(len(seq(mapping(v.get("spec")).get("http"))) for v in self.virtual_services),
                           self.ctx.limits)
        for vs in self.virtual_services:
            self._virtual_service(vs)
        self._check_frontend_scopes()
        self._resolve_https_redirects()
        check_route_budget(len(self.plan.routes), self.ctx.limits)
        if self.discovery_namespaces:
            self.report.warning("istio-k8s-sd", "istio destinations",
                                "Destinations use Ferrum's Kubernetes service discovery: run Ferrum inside the cluster "
                                "(it reads the in-cluster API address and service-account token) with permission to "
                                "list discovery.k8s.io EndpointSlices in namespace(s) "
                                + ", ".join(sorted(safe_label(ns) for ns in self.discovery_namespaces)) + ".")
        return self.plan

    # ---------------------------------------------------------------- gateways

    def _servers(self, gateway: dict) -> list[dict]:
        namespace, name = _meta(gateway)
        servers = []
        for index, raw in enumerate(seq(mapping(gateway.get("spec")).get("servers"))):
            raw = mapping(raw)
            port = mapping(raw.get("port"))
            tls = mapping(raw.get("tls"))
            protocol = str(port.get("protocol", "HTTP")).upper()
            servers.append({
                "ref": f"istio Gateway '{safe_label(namespace)}/{safe_label(name)}' server #{index + 1}",
                "port": util.parse_port(port.get("number")),
                "protocol": protocol,
                "tls": protocol == "HTTPS",
                "tls_mode": str(tls.get("mode", "SIMPLE")).upper() if protocol == "HTTPS" else None,
                "redirect": tls.get("httpsRedirect") is True and protocol != "HTTPS",
                "hosts": str_list(raw.get("hosts")) or [],
                "tls_config": tls,
                "bind": _bind_address(raw.get("bind")),
            })
        return servers

    def _elect_ports(self) -> None:
        plain: dict[int, int] = {}
        tls: dict[int, int] = {}
        binds: set[str | None] = set()
        for gateway in self.gateways.values():
            for server in self._servers(gateway):
                if server["port"] and server["protocol"] in ("HTTP", "HTTP2", "GRPC", "HTTPS"):
                    bucket = tls if server["tls"] else plain
                    bucket[server["port"]] = bucket.get(server["port"], 0) + 1
                    binds.add(server["bind"])
        self.plan.settings.main_http_port = choose_main_port(plain)
        self.plan.settings.main_https_port = choose_main_port(tls)
        # Server.bind restricts a listener to one address (or a Unix socket). Ferrum binds one proxy address for
        # all routes, so a restricted bind is only reproduced when every HTTP(S) server shares the same IP literal.
        specific = {bind for bind in binds if bind}
        self.shared_bind = None
        if len(specific) == 1 and None not in binds and _is_ip_literal(next(iter(specific))):
            self.shared_bind = next(iter(specific))
            self.plan.settings.bind_address = self.shared_bind

    def _server_tls(self, server: dict) -> str | None:
        mode = server["tls_mode"]
        tls = server["tls_config"]
        if mode in ("PASSTHROUGH", "AUTO_PASSTHROUGH", "ISTIO_MUTUAL"):
            return f"TLS mode {mode} is not migrated"
        cert, key = tls.get("serverCertificate"), tls.get("privateKey")
        if isinstance(cert, str) and isinstance(key, str):
            self.plan.settings.frontend_cert_pairs.append((cert, key))
        elif tls.get("credentialName"):
            self.report.warning("istio-credential-name", server["ref"], "credentialName refers to a Kubernetes Secret, "
                                "which is never read.", "Export the certificate/key to files and set "
                                "FERRUM_FRONTEND_TLS_CERT_PATH/KEY_PATH.")
        self.plan.settings.frontend_tls_expected = True
        if mode in ("MUTUAL", "OPTIONAL_MUTUAL"):
            # These ServerTLSSettings fields narrow which client certificates the CA bundle admits (SAN, SPKI or
            # certificate-hash pins, a CRL). Ferrum's listener-wide client CA bundle would admit every client
            # certificate that CA issued, so the trust boundary cannot be reproduced.
            constraints = [key for key in CLIENT_CERT_CONSTRAINTS if tls.get(key)]
            if constraints:
                self.report.error("istio-client-ca", server["ref"],
                                  "The server requires client certificates with extra constraints ("
                                  + ", ".join(constraints) + ") that Ferrum's frontend client CA bundle cannot "
                                  "reproduce.", "Configure a Ferrum frontend dedicated to this trust boundary and "
                                  "review the dropped constraints before serving traffic.")
                return "client certificate constraints beyond the CA bundle (" + ", ".join(constraints) + \
                    ") cannot be reproduced"
            ca = tls.get("caCertificates")
            if isinstance(ca, str) and ca.strip():
                # Recorded per server; the emitter decides whether one listener-wide bundle preserves every scope.
                server["client_ca"] = ca
            else:
                return "mutual TLS without a caCertificates file path"
            if mode == "OPTIONAL_MUTUAL":
                self.report.warning("istio-optional-mutual", server["ref"], "OPTIONAL_MUTUAL becomes mandatory client "
                                    "certificates (stricter).")
        return None

    def _gateway_policies(self, gateway: dict, ref: str) -> list[str]:
        """Policies that (may) apply to the gateway workloads and cannot be safely translated.

        Neither the namespace the ingress gateway *pods* run in nor the cluster's
        ``meshConfig.rootNamespace`` is part of a static Istio CRD bundle. A workload
        selector is therefore treated as applying in any namespace unless it is provably
        disjoint from the Gateway's selector: a label key both selectors pin to different
        values. Extra or different label keys are no proof, because one pod can carry all
        of them. A namespace-wide policy (no selector) also applies in any namespace
        (fail closed); outside the Gateway's and the default root namespace it is also
        reported, because it only matters if the gateway pods run there.
        ``RequestAuthentication`` is refused fail-closed alongside ``AuthorizationPolicy``,
        ``EnvoyFilter``, and ``WasmPlugin`` because static CRDs cannot prove root-namespace
        or workload-namespace scope without authoritative MeshConfig.
        """
        gw_ns, gw_name = _meta(gateway)
        selector = mapping(mapping(gateway.get("spec")).get("selector"))
        reasons: list[str] = []
        for policy in self.policies:
            ns, name = _meta(policy)
            spec = mapping(policy.get("spec"))
            kind = str(policy.get("kind"))
            refs = [mapping(r) for r in seq(spec.get("targetRefs")) + seq(spec.get("targetRef"))]
            labels = mapping(mapping(spec.get("selector")).get("matchLabels")) or \
                mapping(mapping(spec.get("workloadSelector")).get("labels"))
            label = f"{kind} {safe_label(ns)}/{safe_label(name)}"
            if refs:
                applies = any(_target_ref_may_apply(r, ns, gw_ns, gw_name, selector) for r in refs)
            elif labels:
                applies = not _selectors_disjoint(selector, labels)
            else:
                applies = True
                if ns not in (gw_ns, ROOT_NAMESPACE):
                    self.report.error("istio-policy-scope-unknown", ref,
                                      f"{label} has no workload selector, so it applies to every workload in its "
                                      "namespace. The gateway pods' namespace is not part of the input, so it may "
                                      "apply to them; this gateway's routes were refused (fail closed).",
                                      "Confirm the gateway pods' namespace. If the policy does not apply to them, "
                                      "convert again without it; otherwise recreate its policy in Ferrum first.")
            if applies:
                reasons.append(f"{label} applies to this gateway's workloads and cannot be translated")
        return reasons

    # --------------------------------------------------------- virtualservices

    def _virtual_service(self, vs: dict) -> None:
        namespace, name = _meta(vs)
        ref = f"istio VirtualService '{safe_label(namespace)}/{safe_label(name)}'"
        spec = mapping(vs.get("spec"))
        # Istio marks the VirtualServices it generates from Kubernetes Ingress and Gateway API resources with
        # internal.istio.io/route-semantics: ingress|gateway. For those, a uri.prefix other than "/" is a
        # path-separated prefix with one trailing "/" trimmed, and under "gateway" a rewrite to "/" drops the
        # prefix and keeps a leading "/" (pilot/pkg/networking/core/route/route.go, translateRouteMatch and
        # the RegexRewrite for UseGatewaySemantics).
        semantics = mapping(mapping(vs.get("metadata")).get("annotations")).get("internal.istio.io/route-semantics")
        self.route_semantics = semantics if semantics in ("ingress", "gateway") else None
        if spec.get("tls") or spec.get("tcp"):
            self.report.error("istio-l4-routes", ref, "tls/tcp routes are not migrated (HTTP only).")
        raw_gateways = spec.get("gateways")
        if raw_gateways is None:
            gateways = ["mesh"]
        else:
            parsed_gateways = str_list(raw_gateways)
            if parsed_gateways is None:
                self.report.error("istio-gateways-invalid", ref,
                                  "VirtualService spec.gateways has unexpected types; its routes were not migrated.")
                return
            gateways = parsed_gateways or ["mesh"]
        vs_hosts = [h.lower() for h in (str_list(spec.get("hosts")) or [])]
        for host in vs_hosts:
            if host != "*" and "." not in host:
                self.report.error("istio-short-host", ref, "Short (namespace-relative) hosts are not routable at the "
                                  "edge; use fully qualified host names.")
        vs_hosts = [h for h in vs_hosts if h == "*" or "." in h]
        for gateway_ref in gateways:
            if gateway_ref == "mesh":
                self.report.info("istio-mesh-routes", ref, "Mesh-internal routing (gateways: mesh) is not translated: "
                                 "this tool only projects Gateway-bound routes onto Ferrum's edge proxy. Ferrum "
                                 "documents separate mesh/Istio CRD support, which this tool does not exercise.")
                continue
            gw_ns, _, gw_name = gateway_ref.rpartition("/")
            gw_ns = gw_ns or namespace
            gateway = self.gateways.get((gw_ns, gw_name))
            if gateway is None:
                self.report.error("istio-gateway-missing", ref, f"Gateway {safe_label(gateway_ref)} is not in the "
                                  "input; its routes are not migrated.")
                continue
            self._bind(vs, spec, namespace, name, ref, vs_hosts, gateway, gw_ns, gateway_ref)

    def _bind(self, vs: dict, spec: dict, namespace: str, name: str, ref: str, vs_hosts: list[str],
              gateway: dict, gw_ns: str, gateway_ref: str) -> None:
        settings = self.plan.settings
        # One group per Ferrum projection: (listen_port, requires_tls, client CA, TLS refusal). HTTPS servers with
        # different client trust stay apart, so one server's trust requirement never covers another's hosts.
        groups: dict[tuple, dict] = {}
        refusals = self._gateway_policies(gateway, f"{ref} via {safe_label(gateway_ref)}")
        for server in self._servers(gateway):
            hosts = _bind_hosts(vs_hosts, namespace, gw_ns, server["hosts"])
            if hosts is None:
                continue
            if server["protocol"] not in ("HTTP", "HTTP2", "GRPC", "HTTPS"):
                self.report.error("istio-server-protocol", server["ref"], "Non-HTTP gateway servers are not migrated.")
                continue
            if server["bind"] and server["bind"] != self.shared_bind:
                # A listener restricted to one address (or a Unix socket) must not become reachable on Ferrum's
                # shared proxy address. Requests on the other addresses never reached this server in the source.
                self.report.error("istio-server-bind", server["ref"],
                                  "The server binds a specific address or Unix socket that Ferrum cannot reproduce "
                                  "(other servers listen elsewhere, or it is not an IP address). Ferrum binds one "
                                  "proxy address for all routes, which would expose it more widely; skipped.",
                                  "Run a separate Ferrum instance bound to that address for these routes.")
                continue
            if server["redirect"]:
                continue
            refusal = None
            client_ca = None
            if server["tls"]:
                problem = self._server_tls(server)
                if server["port"] != settings.main_https_port:
                    if problem:
                        self.report.error("istio-server-tls", server["ref"], f"{problem}; server skipped.")
                    else:
                        self.report.error("istio-tls-port", server["ref"], "TLS on a non-main port is not migrated.")
                    continue
                if problem:
                    # Skipping the server would let a plaintext server's routes for the same hosts serve its
                    # HTTPS traffic without its TLS requirements; refuse its routes instead (fail closed).
                    self.report.error("istio-server-tls", server["ref"], f"{problem}; the routes bound to this "
                                      "server are refused (fail closed).")
                    refusal = f"the HTTPS gateway server's TLS settings cannot be reproduced ({problem})"
                client_ca = server.get("client_ca")
                key: tuple = (None, True, client_ca, refusal)
            else:
                key = (None if server["port"] == settings.main_http_port else server["port"], False, None, None)
            group = groups.setdefault(key, {"hosts": [], "any": False, "port": server["port"], "listen_port": key[0],
                                            "requires_tls": key[1], "client_cas": [client_ca] if client_ca else [],
                                            "refusals": [refusal] if refusal else []})
            if hosts == []:
                group["any"] = True
            for host in hosts:
                if host not in group["hosts"]:
                    group["hosts"].append(host)
        # match.port selects routes per gateway server port; a shared projection must not pick one port's view.
        port_specific = any(mapping(match).get("port") for entry in seq(spec.get("http"))
                            for match in seq(mapping(entry).get("match")))
        # Hosts this binding served on the main HTTPS listener, taken before the merge below folds HTTPS groups into
        # plaintext ones. Only these count as an HTTPS source frontend for a merged plaintext route set.
        https_any = any(group["any"] for key, group in groups.items() if key[1] is True)
        https_hosts = {host for key, group in groups.items() if key[1] is True for host in group["hosts"]}
        self._merge_shared_hosts(groups, ref, port_specific)
        for group in groups.values():
            listen_port, requires_tls = group["listen_port"], group["requires_tls"]
            if requires_tls:
                frontends = frozenset({"https"})
            elif listen_port is not None:
                frontends = frozenset()  # extra plaintext listener: never emitted (extra-listener-refused)
            elif https_any or (not group["any"] and group["hosts"]
                               and all(host in https_hosts for host in group["hosts"])):
                frontends = frozenset({"http", "https"})  # every host is also bound on the main HTTPS server
            else:
                frontends = frozenset({"http"})
            hosts = [] if group["any"] else group["hosts"]
            server_ports = group.get("shared_ports") or [group["port"]]
            routes: list[RouteSpec] = []
            for index, entry in enumerate(seq(spec.get("http"))):
                routes.extend(self._http_route(mapping(entry), index, namespace, name, ref, hosts, listen_port,
                                               requires_tls, gw_ns, gateway_ref, server_ports))
            for route in routes:
                route.client_cas = list(group["client_cas"])
                route.protocols = frontends
                for reason in group["refusals"] + refusals:
                    route.refuse(reason)
            apply_first_match_order(routes, self.report)
            self.plan.routes.extend(routes)
            self.projections.append({
                "binding": (ref, gateway_ref), "ref": f"{ref} via {safe_label(gateway_ref)}",
                "hosts": list(hosts), "listen_port": listen_port, "routes": routes,
                # What a request for these hosts gets from the source frontend before any route matches: the
                # protocol, the client-certificate trust, and whether the frontend itself is refused (TLS settings,
                # shared-scope conflict, or a gateway policy).
                "frontend": (bool(requires_tls), tuple(sorted(group["client_cas"])),
                             bool(group["refusals"] or refusals)),
            })
            if hosts:
                self.plan.host_scopes.append(
                    HostScope(f"{ref} via {safe_label(gateway_ref)}", list(hosts), listen_port, protocols=frontends)
                )

    def _resolve_https_redirects(self) -> None:
        """Fold main-port Gateway ``httpsRedirect`` servers away only when live HTTPS exists and no other main plain routes do.

        Extra-port ``httpsRedirect`` servers always emit extra-listener placeholders and never block main-port
        folding. When main-port redirects cannot fold, emit a fail-closed refused placeholder for each redirect
        server's host scope and refuse only plaintext main-port projections that can tie with or outrank a
        redirect placeholder in Ferrum's host-tier order (exact > wildcard > catch-all).
        """
        settings = self.plan.settings
        main_redirects: list[tuple[tuple[str, str], int, dict, list[str]]] = []
        extra_redirects: list[tuple[tuple[str, str], int, dict, list[str]]] = []
        max_hosts = self.ctx.limits.max_precedence_routes
        total_hosts = 0
        for (gw_ns, gw_name), gateway in self.gateways.items():
            for srv_idx, server in enumerate(self._servers(gateway), start=1):
                if not server["redirect"]:
                    continue
                if server["protocol"] not in ("HTTP", "HTTP2", "GRPC"):
                    continue
                if server["bind"] and server["bind"] != self.shared_bind:
                    continue
                seen_hosts: set[str] = set()
                stripped: list[str] = []
                any_host = False
                for entry in server["hosts"]:
                    _, _, raw_host = entry.rpartition("/")
                    host = raw_host.lower().strip()
                    if host == "*":
                        if not any_host:
                            any_host = True
                            total_hosts += 1
                            if total_hosts > max_hosts:
                                raise InputError(f"more than {max_hosts} hosts across Istio httpsRedirect servers")
                    elif host:
                        norm_host = util.normalize_host(host) or host.rstrip(".")
                        if norm_host and norm_host not in seen_hosts:
                            seen_hosts.add(norm_host)
                            stripped.append(norm_host)
                            total_hosts += 1
                            if total_hosts > max_hosts:
                                raise InputError(f"more than {max_hosts} hosts across Istio httpsRedirect servers")
                if not any_host and not stripped:
                    continue
                bucket = main_redirects if server["port"] == settings.main_http_port else extra_redirects
                bucket.append(((gw_ns, gw_name), srv_idx, server, [] if any_host else stripped))
        seen_extra_scopes: set[tuple[int | None, frozenset[str]]] = set()
        for (gw_ns, gw_name), srv_idx, server, hosts in extra_redirects:
            scope_key = (server["port"], frozenset(hosts))
            if scope_key in seen_extra_scopes:
                continue
            seen_extra_scopes.add(scope_key)
            route = RouteSpec(
                ref=server["ref"],
                name=f"{gw_ns}-{gw_name}-https-redirect-{srv_idx}",
                hosts=list(hosts),
                kind="prefix",
                path="/",
                listen_port=server["port"],
                requires_tls=False,
                protocols=frozenset(),
            )
            route.refuse("Gateway httpsRedirect server on a non-main HTTP port is not migrated")
            self.plan.routes.append(route)
            if hosts:
                self.plan.host_scopes.append(
                    HostScope(server["ref"], list(hosts), server["port"], protocols=frozenset())
                )
        if not main_redirects:
            return
        has_live_https = any(not r.skip and not r.refusals and "https" in (r.protocols or ())
                             for r in self.plan.routes)
        has_other_plain = any(not r.skip and not r.requires_tls and r.listen_port is None for r in self.plan.routes)
        seen_main_scopes: set[frozenset[str]] = set()
        if has_live_https and not has_other_plain:
            for (gw_ns, gw_name), srv_idx, server, hosts in main_redirects:
                scope_key_m = frozenset(hosts)
                if scope_key_m in seen_main_scopes:
                    continue
                seen_main_scopes.add(scope_key_m)
                route = RouteSpec(
                    ref=server["ref"],
                    name=f"{gw_ns}-{gw_name}-https-redirect-{srv_idx}",
                    hosts=list(hosts),
                    kind="hostonly" if hosts else "prefix",
                    path=None if hosts else "/",
                    listen_port=None,
                    requires_tls=False,
                    protocols=frozenset({"http"}),
                    skip=True,
                    skip_reason="HTTPS redirect",
                    https_redirect_fold=("istio-https-redirect", server["ref"]),
                )
                self.plan.routes.append(route)
            return
        any_redir_ref: str | None = None
        exact_redir: dict[str, str] = {}
        wild_redir: dict[str, str] = {}
        for (gw_ns, gw_name), srv_idx, server, hosts in main_redirects:
            scope_key_m = frozenset(hosts)
            if scope_key_m in seen_main_scopes:
                continue
            seen_main_scopes.add(scope_key_m)
            route = RouteSpec(
                ref=server["ref"],
                name=f"{gw_ns}-{gw_name}-https-redirect-{srv_idx}",
                hosts=list(hosts),
                kind="hostonly" if hosts else "prefix",
                path=None if hosts else "/",
                listen_port=None,
                requires_tls=False,
                protocols=frozenset({"http"}),
            )
            route.refuse("Gateway httpsRedirect server cannot be folded away alongside other plaintext routes or "
                         "without a live HTTPS server")
            self.plan.routes.append(route)
            if hosts:
                self.plan.host_scopes.append(
                    HostScope(server["ref"], list(hosts), None, protocols=frozenset({"http"}))
                )
                for host in hosts:
                    if host.startswith("*."):
                        wild_redir.setdefault(host[1:], server["ref"])
                    else:
                        exact_redir.setdefault(host, server["ref"])
            elif any_redir_ref is None:
                any_redir_ref = server["ref"]
        # Index-backed check against plaintext main-port projections only: refuse a projection only when its host
        # scope can tie with or outrank a redirect placeholder in Ferrum (exact > wildcard > catch-all).
        for proj in self.projections:
            if proj["listen_port"] is not None or proj["frontend"][0]:
                continue
            matched_ref: str | None = any_redir_ref
            if matched_ref is None and proj["hosts"]:
                for raw_host in proj["hosts"]:
                    host = util.normalize_host(raw_host) or raw_host.strip().lower().rstrip(".")
                    if host.startswith("*."):
                        # A wildcard plaintext host ties with an identical wildcard redirect or is covered by a
                        # broader wildcard redirect.
                        suffix = host[1:]
                        if suffix in wild_redir:
                            matched_ref = wild_redir[suffix]
                            break
                        dot = suffix.find(".", 1)
                        while dot != -1:
                            parent = suffix[dot:]
                            if parent in wild_redir:
                                matched_ref = wild_redir[parent]
                                break
                            dot = suffix.find(".", dot + 1)
                        if matched_ref is not None:
                            break
                    else:
                        if host in exact_redir:
                            matched_ref = exact_redir[host]
                            break
                        dot = host.find(".")
                        while dot != -1:
                            parent = host[dot:]
                            if parent in wild_redir:
                                matched_ref = wild_redir[parent]
                                break
                            dot = host.find(".", dot + 1)
                        if matched_ref is not None:
                            break
            if matched_ref is not None:
                reason = (f"{matched_ref} enforces Gateway-level httpsRedirect for overlapping hosts; "
                          "Ferrum cannot keep the redirect and plaintext routes apart on the same listener")
                for proj_route in proj["routes"]:
                    proj_route.refuse(reason)
                self.report.error("istio-frontend-scope-conflict", proj["ref"],
                                  f"This projection overlaps {matched_ref} (httpsRedirect) while plaintext "
                                  "routes remain active. Every route of this projection was refused (fail closed).",
                                  "Serve redirected hosts and plaintext hosts on separate Ferrum instances, or "
                                  "remove plaintext routes so Ferrum can run TLS-only.")

    def _check_frontend_scopes(self) -> None:
        """Refuse overlapping projections from different bindings whose source frontends differ.

        ``_merge_shared_hosts`` reconciles the plaintext and HTTPS servers of one VirtualService-to-Gateway binding.
        Separate bindings (another VirtualService, or the same one through another Gateway) are only compared here,
        on the final set of projections, refused ones included. Ferrum serves every port-agnostic route on its
        plaintext and its HTTPS listener and has one client CA bundle, so for an overlapping host it would answer
        one binding's HTTPS (or plaintext) requests with another binding's routes: routes the source only exposed
        over plaintext become reachable over HTTPS next to a stricter or refused HTTPS frontend, or a refused
        frontend's hosts reach another binding's live routes. Equivalence of such mixed plans is not provable, so
        every projection in a conflicting pair is refused (fail closed). Projections with the same frontend (same
        protocol, client CA and refusal state) are left to the emitter's per-route checks; extra-listener
        projections are never emitted (``extra-listener-refused``).
        """
        projections = [p for p in self.projections if p["listen_port"] is None]
        conflicts: dict[int, list[str]] = {}
        for i, first in enumerate(projections):
            for j in range(i + 1, len(projections)):
                second = projections[j]
                if first["binding"] == second["binding"] or first["frontend"] == second["frontend"]:
                    continue
                if not matching.hosts_overlap(first["hosts"], second["hosts"]):
                    continue
                conflicts.setdefault(i, []).append(second["ref"])
                conflicts.setdefault(j, []).append(first["ref"])
        for index, others in conflicts.items():
            projection = projections[index]
            names = ", ".join(dict.fromkeys(others))[:400]
            reason = (f"another Gateway binding with a different frontend ({names}) serves overlapping hosts; Ferrum "
                      "serves port-agnostic routes on both its plaintext and HTTPS listeners, so the two frontends' "
                      "protocol, client-certificate requirement or refusal cannot be kept apart")
            for route in projection["routes"]:
                route.refuse(reason)
            self.report.error("istio-frontend-scope-conflict", projection["ref"],
                              f"This projection and {len(dict.fromkeys(others))} projection(s) of other Gateway "
                              "bindings serve overlapping hosts through different frontends (plaintext vs HTTPS, "
                              "different client-certificate trust, or a refused frontend). Ferrum serves these "
                              "routes on all of its listeners, so requests for one binding's frontend could reach "
                              "the other binding's routes. Every route of this projection was refused (fail closed).",
                              "Bind such hosts through one Gateway with the same servers, or serve each frontend "
                              "from a separately configured Ferrum instance, then convert again.")

    def _merge_shared_hosts(self, groups: dict, ref: str, port_specific: bool) -> None:
        """Keep an HTTPS server's requirements for hosts a plaintext main-port server also binds.

        Ferrum serves port-agnostic routes on its plaintext and its HTTPS listener, so such hosts get one route
        set. It must carry the HTTPS server's client CA (Ferrum checks the client CA bundle on the HTTPS listener
        only, so plaintext access stays as in the source) or its refusal; dropping the HTTPS group would serve
        HTTPS without them.

        Overlap is decided on actual host scopes (wildcards included), not on equal strings. A merge is only made
        where the contract is proven: the same host names, or a catch-all on one side. When the scopes overlap
        through different names (``*.example.com`` vs ``a.example.com``) and the HTTPS server is stricter or the
        VirtualService selects routes by ``match.port``, Ferrum would answer some HTTPS requests from the
        plaintext projection; both projections are refused instead. A shared projection keeps both server ports,
        so a port-specific match in it is refused rather than silently resolved for one port.
        """
        plain_key = (None, False, None, None)
        for key in [k for k in groups if k[1] is True]:
            plain = groups.get(plain_key)
            if plain is None:
                return
            secure = groups[key]
            strict = bool(secure["client_cas"] or secure["refusals"])
            ports = sorted({port for port in (plain["port"], secure["port"]) if port is not None})
            if not plain["any"] and not secure["any"]:
                pairs = [(s, p) for s in secure["hosts"] for p in plain["hosts"] if matching.host_overlap(s, p)]
                if not pairs:
                    continue
                if (strict or port_specific) and any(s != p for s, p in pairs):
                    self._refuse_shared_scope(plain, secure, ref)
                    continue
            if plain["any"]:
                # The plaintext catch-all routes already serve every host this HTTPS server binds.
                del groups[key]
                if strict:
                    self._carry_tls(plain, secure, ref, whole_catch_all=not secure["any"])
                if port_specific:
                    plain["shared_ports"] = ports
                continue
            if secure["any"]:
                if plain["hosts"]:  # every plaintext host is shared
                    if strict:
                        self._carry_tls(plain, secure, ref, whole_catch_all=False)
                    if port_specific:
                        plain["shared_ports"] = ports
                continue
            shared = [host for host in secure["hosts"] if host in plain["hosts"]]
            secure["hosts"] = [host for host in secure["hosts"] if host not in shared]
            if not secure["hosts"]:
                del groups[key]
            if not shared or not (strict or port_specific):
                continue
            plain["hosts"] = [host for host in plain["hosts"] if host not in shared]
            split = {"hosts": shared, "any": False, "port": plain["port"], "listen_port": None, "requires_tls": False,
                     "client_cas": [], "refusals": [], "shared_ports": ports if port_specific else None}
            if strict:
                self._carry_tls(split, secure, ref, whole_catch_all=False)
            groups[("shared",) + key] = split
            if not plain["hosts"]:
                del groups[plain_key]

    def _refuse_shared_scope(self, plain: dict, secure: dict, ref: str) -> None:
        reason = ("a plaintext and an HTTPS gateway server bind overlapping but different host scopes; Ferrum serves "
                  "these port-agnostic routes on both listeners, so the HTTPS server's client-certificate requirement, "
                  "refusal or port-specific routes cannot be proven to apply to every overlapping host")
        for group in (plain, secure):
            if reason not in group["refusals"]:
                group["refusals"].append(reason)
        self.report.error("istio-shared-host-scope", ref,
                          "A plaintext and an HTTPS gateway server bind overlapping host scopes through different "
                          "names (for example a wildcard and a host it covers). The HTTPS server requires client "
                          "certificates, is refused, or the VirtualService selects routes by match.port, and Ferrum "
                          "would answer some HTTPS requests from the plaintext projection. Both projections were "
                          "refused (fail closed).",
                          "Bind the same host names on both servers (or split them into separate Gateways/Ferrum "
                          "frontends), then convert again.")

    def _carry_tls(self, target: dict, secure: dict, ref: str, whole_catch_all: bool) -> None:
        for ca in secure["client_cas"]:
            if ca not in target["client_cas"]:
                target["client_cas"].append(ca)
        for reason in secure["refusals"]:
            if reason not in target["refusals"]:
                target["refusals"].append(reason)
        message = ("A plaintext and an HTTPS gateway server bind the same hosts. Ferrum serves one route set for "
                   "them on both listeners, so the HTTPS server's client certificate requirement or refusal is kept "
                   "on those routes (Ferrum checks client certificates on its HTTPS listener only).")
        if whole_catch_all:
            message += (" The plaintext server matches any host, so this applies to every host it serves over "
                        "HTTPS (stricter or refused).")
        self.report.warning("istio-shared-host-tls", ref, message)

    def _http_route(self, entry: dict, index: int, namespace: str, vs_name: str, vs_ref: str, hosts: list[str],
                    listen_port: int | None, requires_tls: bool, gw_ns: str, gateway_ref: str,
                    server_ports: list[int | None]) -> list[RouteSpec]:
        name = str(entry.get("name") or f"{vs_name}-http-{index + 1}")
        base_ref = f"istio route '{safe_label(name)}' in {vs_ref}"
        blocks: dict[tuple, dict] = {}
        for match in seq(entry.get("match")) or [{}]:
            match = mapping(match)
            port_condition = False
            if match.get("port"):
                if util.as_int(match.get("port")) not in server_ports:
                    continue
                # One projection serves several gateway server ports (plaintext and HTTPS share these hosts):
                # Ferrum cannot keep a match that only applied on one of them.
                port_condition = len(server_ports) > 1
            match_gateways = str_list(match.get("gateways"))
            if match.get("gateways") is not None and match_gateways is None:
                extra = ["gateways matcher with unexpected types"]
            else:
                gw_ns_ref, gw_sep, gw_name_ref = gateway_ref.rpartition("/")
                gw_key = (gw_ns_ref if gw_sep else namespace, gw_name_ref)
                if match_gateways and not any(
                    ((g.rpartition("/")[0] if "/" in g else namespace), g.rpartition("/")[2]) == gw_key
                    for g in match_gateways
                ):
                    continue
                extra = []
            uri = mapping(match.get("uri"))
            extra.extend(key for key in ("headers", "queryParams", "authority", "scheme", "sourceLabels",
                                         "sourceNamespace", "withoutHeaders") if match.get(key))
            if port_condition:
                extra.append("one gateway server port (match.port) while Ferrum serves these hosts on both its "
                             "plaintext and HTTPS listeners")
            if "exact" in uri:
                kind, path = "exact", uri["exact"]
            elif "prefix" in uri:
                # A VirtualService uri.prefix is a plain string prefix (/api also matches /apix); flagged for the
                # emitter's sibling report below. exact and regex matches are not prefixes. Istio-generated
                # (route-semantics) VirtualServices use path-separated prefixes instead.
                kind, path = "prefix", uri["prefix"] or "/"
                if self.route_semantics and isinstance(path, str) and path != "/":
                    kind, path = "segment", (path[:-1] if path.endswith("/") else path) or "/"
            elif "regex" in uri:
                kind, path = "regex", uri["regex"]
            elif uri:
                kind, path = "prefix", "/"
                extra.append("uri matcher")
            else:
                kind, path = "prefix", "/"
            # ignoreUriCase applies to exact and prefix URI matches only. Ferrum matches paths case-sensitively:
            # the route keeps its exact-case path and the emitter refuses every route that could receive the case
            # variants (fail closed), instead of letting them reach an overlapping route.
            ignore_case = bool(match.get("ignoreUriCase")) and kind in ("exact", "prefix", "segment")
            if ignore_case:
                self.report.warning("istio-ignore-case", base_ref,
                                    "ignoreUriCase: Ferrum matches this path case-sensitively. Only the exact-case "
                                    "path is routed here; other case variants answer 404 or a fail-closed response, "
                                    "and routes that could receive them were refused.")
            method = mapping(match.get("method"))
            methods = None
            if method:
                if "exact" in method:
                    methods = [str(method["exact"]).upper()]
                else:
                    extra.append("non-exact method matcher")
            key = (kind, path, tuple(extra), ignore_case)
            block = blocks.setdefault(key, {"methods": [], "all": False})
            if methods is None:
                block["all"] = True
            else:
                block["methods"].extend(m for m in methods if m not in block["methods"])
        routes = []
        for number, ((kind, path, extra, ignore_case), block) in enumerate(blocks.items()):
            spec = RouteSpec(ref=base_ref if len(blocks) == 1 else f"{base_ref} match #{number + 1}",
                             name=name if number == 0 else f"{name}-{number + 1}",
                             hosts=list(hosts), kind=kind, path=path, listen_port=listen_port,
                             requires_tls=requires_tls)
            if kind == "segment":
                spec.kind, spec.prefix_semantics = "prefix", "segment"
            spec.case_insensitive = ignore_case
            spec.methods = None if block["all"] else list(block["methods"])
            spec.report_prefix_siblings = kind == "prefix"
            for condition in extra:
                spec.extra_conditions = True
                spec.refuse(f"matches on {condition}, which Ferrum cannot express")
            self._route_action(spec, entry, namespace, gw_ns, requires_tls)
            routes.append(spec)
        return routes

    def _route_action(self, spec: RouteSpec, entry: dict, namespace: str, gw_ns: str, requires_tls: bool) -> None:
        ref = spec.ref
        if entry.get("delegate"):
            spec.refuse("delegate VirtualServices are not migrated")
            return
        if entry.get("directResponse"):
            response = mapping(entry["directResponse"])
            status = util.as_int(response.get("status"))
            body = mapping(response.get("body"))
            if status is None or not 200 <= status <= 599 or body.get("bytes"):
                spec.refuse("directResponse is not representable")
            elif status in (204, 205, 304):
                spec.termination = {"status_code": status, "body": str(body.get("string", ""))}
            else:
                spec.termination = {"status_code": status, "content_type": "text/plain",
                                    "body": str(body.get("string", ""))}
            return
        if entry.get("redirect"):
            redirect = mapping(entry["redirect"])
            scheme = redirect.get("scheme") or ("https" if requires_tls else None)
            authority, uri = redirect.get("authority"), redirect.get("uri")
            code = util.as_int(redirect.get("redirectCode")) or 301
            location = f"{scheme}://{authority}{uri}" if (scheme and authority and uri) else ""
            if not (scheme and authority and uri) or redirect.get("derivePort") or redirect.get("port") \
                    or not 200 <= code <= 599 or not header_value_ok(location, nonempty=True, strict_ws=True):
                spec.refuse("only fully static redirects (scheme, authority and uri without custom port) are migrated")
            else:
                spec.termination = {"status_code": code, "headers": {"location": location},
                                    "body": ""}
            return
        destinations = [mapping(d) for d in seq(entry.get("route"))]
        if not destinations:
            spec.refuse("route has no destination")
            return
        self._destinations(spec, destinations, namespace, gw_ns)
        rewrite = mapping(entry.get("rewrite"))
        if rewrite.get("uriRegexRewrite"):
            spec.refuse("uriRegexRewrite is not supported")
        # Istio builds a URI rewrite only for a nonempty uri (route.go): "" leaves the path unchanged.
        if isinstance(rewrite.get("uri"), str) and rewrite["uri"] != "":
            if spec.kind == "regex":
                spec.refuse("uri rewrite on a regex match is not supported")
            else:
                spec.strip = True
                if self.route_semantics == "gateway" and spec.prefix_semantics == "segment" \
                        and rewrite["uri"] == "/":
                    # Istio's regex rewrite keeps "/" + the rest after the prefix: Ferrum's remainder exactly.
                    spec.backend_path = None
                else:
                    spec.backend_path, exact = replaced_prefix_backend_path(spec.kind, spec.path, rewrite["uri"])
                    if not exact:
                        self.report.warning("istio-rewrite-slash", ref, "The uri prefix ends with '/' but the "
                                            "rewrite does not: Envoy joins the rest of the path without a slash "
                                            "(/v1 + x = /v1x), whereas Ferrum inserts one (/v1/x).")
        spec.preserve_host = True
        if rewrite.get("authority"):
            spec.preserve_host = False
            self.report.warning("istio-authority-rewrite", ref, "authority rewrite: Ferrum sends the selected target's "
                                "authority instead of the configured value.")
        if entry.get("timeout"):
            timeout = util.parse_go_duration_ms(entry["timeout"])
            spec.read_timeout_ms = util.MAX_TIMEOUT_MS + 1 if timeout == 0 else timeout
        retries = entry.get("retries")
        if isinstance(retries, dict):
            config, notes = retry_from_policy(retries.get("retryOn", DEFAULT_RETRY_ON), retries.get("attempts", 0))
            spec.retry = config
            for note in notes:
                self.report.warning("istio-retry", ref, note)
        else:
            self.report.info("istio-default-retries", ref, "Istio's implicit default retry policy is not reproduced.")
        if entry.get("fault"):
            fault_status, fault_val = _translate_istio_fault(entry["fault"])
            if fault_status == "plugin":
                spec.plugins.append(PluginSpec("fault_injection", fault_val, ref))
            elif fault_status == "omit":
                self.report.info("istio-fault-noop", ref,
                                 "fault injection has 0% abort/delay probability (inert); omitted.")
            else:
                self.report.warning("istio-dropped", ref, f"fault injection is dropped ({fault_val}).")
        if entry.get("mirror") or entry.get("mirrors"):
            self._mirrors(spec, entry, namespace, gw_ns, ref)
        self._cors(spec, mapping(entry.get("corsPolicy")))
        raw_headers = entry.get("headers")
        if raw_headers is not None and not isinstance(raw_headers, dict):
            spec.refuse("route headers section is not a mapping")
        elif isinstance(raw_headers, dict):
            self._headers(spec, raw_headers)

    def _mirrors(self, spec: RouteSpec, entry: dict, namespace: str, gw_ns: str, ref: str) -> None:
        # Istio mirrors rewrite :authority with '-shadow' and apply mesh Auto mTLS / DestinationRule namespace
        # precedence, whereas Ferrum file-mode request_mirror strips Host to the mirror endpoint's authority.
        # Ignore explicitly 0%-percentage (inert) mirrors (including empty percentage wrappers, which default to 0.0
        # in protobuf) and drop active mirrors with a warning.
        dropped = 0
        if entry.get("mirror") is not None:
            if "mirrorPercentage" in entry and entry["mirrorPercentage"] is not None:
                pct_obj = entry["mirrorPercentage"]
                raw_pct = pct_obj.get("value", 0.0) if isinstance(pct_obj, dict) else None
            elif "mirrorPercent" in entry and entry["mirrorPercent"] is not None:
                raw_pct = entry["mirrorPercent"]
            else:
                raw_pct = 100.0
            if isinstance(raw_pct, bool) or not isinstance(raw_pct, (int, float)) \
                    or (isinstance(raw_pct, float) and not math.isfinite(raw_pct)) or raw_pct != 0:
                dropped += 1
        for item in seq(entry.get("mirrors")):
            if not isinstance(item, dict):
                dropped += 1
                continue
            if "percentage" in item and item["percentage"] is not None:
                pct_obj = item["percentage"]
                raw_pct = pct_obj.get("value", 0.0) if isinstance(pct_obj, dict) else None
            else:
                raw_pct = 100.0
            if isinstance(raw_pct, bool) or not isinstance(raw_pct, (int, float)) \
                    or (isinstance(raw_pct, float) and not math.isfinite(raw_pct)) or raw_pct != 0:
                dropped += 1
        if dropped:
            self.report.warning("istio-dropped", ref,
                                f"{dropped} mirror destination(s) were dropped: Istio mirrors append '-shadow' to "
                                ":authority and apply mesh mTLS/DestinationRule precedence, whereas Ferrum file-mode "
                                "request_mirror strips Host to the mirror endpoint's authority. Configure "
                                "request_mirror manually if the shadow destination accepts its own endpoint Host.")

    def _cors(self, spec: RouteSpec, policy: dict) -> None:
        if not policy:
            return
        raw_creds = policy.get("allowCredentials")
        if raw_creds is not None and not isinstance(raw_creds, bool):
            spec.refuse("CORS policy has an invalid allowCredentials value")
            return
        creds = raw_creds if isinstance(raw_creds, bool) else None
        raw_unmatched = policy.get("unmatchedPreflights")
        unmatched_mode = "forward"
        if raw_unmatched is not None:
            if isinstance(raw_unmatched, str) and raw_unmatched in ("UNSPECIFIED", "FORWARD"):
                unmatched_mode = "forward"
            elif isinstance(raw_unmatched, str) and raw_unmatched == "IGNORE":
                unmatched_mode = "ignore"
            else:
                spec.refuse("CORS policy has an unsupported unmatchedPreflights value")
                return
        # Istio treats allowOrigins as authoritative whenever the key is present (even if empty []);
        # fall back to deprecated allowOrigin only when allowOrigins is omitted or null.
        origins = []
        matcher_problem: str | None = None
        if "allowOrigins" in policy and policy.get("allowOrigins") is not None:
            raw_modern = policy["allowOrigins"]
            if not isinstance(raw_modern, list):
                matcher_problem = "allowOrigins must be a list"
            else:
                for raw_m in raw_modern:
                    matcher = mapping(raw_m)
                    extra_keys = set(matcher) - {"exact", "prefix", "regex"}
                    present = [k for k in ("exact", "prefix", "regex") if k in matcher]
                    if extra_keys or len(present) != 1:
                        origins = []
                        matcher_problem = "allowOrigins entry uses unsupported or ambiguous matcher fields"
                        break
                    key = present[0]
                    origins.append({key: matcher[key]})
        else:
            for origin in seq(policy.get("allowOrigin")):
                origins.append({"exact": origin})
        if matcher_problem:
            spec.refuse(f"active CORS policy cannot be safely migrated ({matcher_problem})")
            return
        if len(origins) > 64:
            spec.refuse("active CORS policy cannot be safely migrated (more than 64 allowed origins)")
            return
        # Istio/Envoy treats any origin matcher matching literal "*" (exact, prefix, or regex) as allow-all.
        star_probes = [cors_origin_star_probe(o) for o in origins]
        if "error" in star_probes:
            spec.refuse("active CORS policy contains an origin regex that cannot be safely verified or admitted")
            return
        if "star" in star_probes:
            if creds is True:
                spec.refuse("CORS policy combines allowCredentials=true with a wildcard '*' origin matcher, "
                            "which Ferrum downgrades by disabling credentials")
                return
            origins = ["*"]
        if creds is True and any("*" in (str_list(policy.get(k)) or [])
                                 for k in ("allowMethods", "allowHeaders", "exposeHeaders")):
            spec.refuse("CORS policy combines allowCredentials=true with wildcard '*' in "
                        "allowMethods/allowHeaders/exposeHeaders, which Ferrum returns literally; specify explicit lists")
            return
        raw_headers = policy.get("allowHeaders")
        parsed_headers = str_list(raw_headers) if raw_headers is not None else None
        if creds is not True and parsed_headers == ["*"]:
            # Istio forwards allowHeaders: ["*"] to Envoy as "*", which reflects requested headers including
            # Authorization; Fetch excludes Authorization from literal "*", so emit ["*", "authorization"].
            effective_headers: Any = ["*", "authorization"]
        else:
            effective_headers = raw_headers
        raw_max_age = policy.get("maxAge")
        max_age = util.parse_go_duration_ms(raw_max_age) if raw_max_age is not None else None
        if raw_max_age is not None and max_age is None:
            spec.refuse("active CORS policy has an invalid maxAge")
            return
        # Pass unmatched_preflights explicitly so Ferrum preserves omitted allowMethods/allowHeaders/maxAge
        # rather than supplying permissive defaults that could broaden credentialed CORS.
        built, problem = cors_config(origins, policy.get("allowMethods"), effective_headers,
                                     policy.get("exposeHeaders"), creds,
                                     max_age // 1000 if max_age is not None else None,
                                     unmatched_preflights=unmatched_mode)
        if built:
            spec.plugins.append(PluginSpec("cors", built, spec.ref))
        else:
            spec.refuse(f"active CORS policy cannot be safely migrated ({problem})")

    def _headers(self, spec: RouteSpec, headers: dict) -> None:
        raw_req = headers.get("request")
        raw_resp = headers.get("response")
        request_rules: list[dict] = []
        response_rules: list[dict] = []
        if raw_req is not None and not isinstance(raw_req, dict):
            spec.refuse("request headers section is not a mapping")
            request: dict = {}
        else:
            request = mapping(raw_req)
        if request.get("add"):
            spec.refuse("request header 'add' appends in Istio but only adds when absent in Ferrum")
        raw_req_set = request.get("set")
        if raw_req_set is not None and not isinstance(raw_req_set, dict):
            spec.refuse("request header 'set' section is not a mapping")
        else:
            for key, value in mapping(raw_req_set).items():
                rule, problem = request_header_rule("update", key, literal_value(str(value)))
                request_rules.append(rule) if rule else spec.refuse(problem or "invalid header")
        remove_req = str_list(request.get("remove"))
        if request.get("remove") is not None and remove_req is None:
            spec.refuse("request header 'remove' list has unexpected types")
        for key in remove_req or []:
            rule, problem = request_header_rule("remove", key)
            request_rules.append(rule) if rule else spec.refuse(problem or "invalid header")
        if raw_resp is not None and not isinstance(raw_resp, dict):
            self.report.warning("istio-response-header", spec.ref,
                                "Response headers section is not a mapping; omitted.")
            response: dict = {}
        else:
            response = mapping(raw_resp)
        for op, section in (("update", "set"), ("add", "add")):
            raw_section = response.get(section)
            if raw_section is not None and not isinstance(raw_section, dict):
                self.report.warning("istio-response-header", spec.ref,
                                    f"Response header '{section}' section is not a mapping; omitted.")
                continue
            for key, value in mapping(raw_section).items():
                rule, problem = response_header_rule(op, key, literal_value(str(value)))
                if rule:
                    response_rules.append(rule)
                else:
                    self.report.warning("istio-response-header", spec.ref, f"Response header not migrated ({problem}).")
        remove_resp = str_list(response.get("remove"))
        if response.get("remove") is not None and remove_resp is None:
            self.report.warning("istio-response-header", spec.ref,
                                "Response header 'remove' list has unexpected types; omitted.")
        for key in remove_resp or []:
            rule, _ = response_header_rule("remove", key)
            if rule:
                response_rules.append(rule)
        if isinstance(response.get("add"), dict) and response.get("add"):
            self.report.warning("istio-response-add", spec.ref, "Response header 'add' only adds when absent in Ferrum.")
        if request_rules:
            spec.plugins.append(PluginSpec("request_transformer", {"rules": request_rules}, spec.ref))
        if response_rules:
            spec.plugins.append(PluginSpec("response_transformer", {"rules": response_rules}, spec.ref))

    # ------------------------------------------------------------ destinations

    def _destinations(self, spec: RouteSpec, destinations: list[dict], namespace: str, gw_ns: str) -> None:
        resolved = []
        live_count = sum(1 for raw in destinations
                         if (util.as_int(mapping(raw).get("weight")) or (100 if len(destinations) == 1 else 0)) > 0)
        for raw in destinations:
            if raw.get("headers"):
                spec.refuse("per-destination header operations are not migrated")
                return
            destination = mapping(raw.get("destination"))
            host = destination.get("host")
            if not isinstance(host, str):
                spec.refuse("destination without host")
                return
            if destination.get("subset"):
                spec.refuse("subset routing needs pod labels; use Ferrum's native Istio support in Kubernetes")
                return
            fqdn = _fqdn(host.lower(), namespace)
            port = util.parse_port(mapping(destination.get("port")).get("number"))
            result = self._backend(fqdn, port, gw_ns, spec.ref, allow_discovery=live_count <= 1)
            if result.get("problem"):
                spec.refuse(result["problem"])
                return
            weight = util.as_int(raw.get("weight"))
            resolved.append((100 if weight is None and len(destinations) == 1 else (weight or 0), result))
        live = [item for item in resolved if item[0] > 0]
        if len(resolved) == 1 or len(live) == 1:
            # One destination receives all the traffic: route to it as it is, with its own policy.
            spec.backend = (live or resolved)[0][1]["backend"]
            return
        keys = {item[1]["tls_key"] for item in resolved}
        if len(keys) > 1:
            spec.refuse("weighted destinations differ in TLS settings")
            return
        merged = merge_weighted_targets([(weight, item["targets"]) for weight, item in resolved])
        if merged is None:
            spec.refuse("weighted destinations send no traffic anywhere")
            return
        targets, approximate = merged
        if approximate:
            self.report.warning("istio-weights", spec.ref, "Weighted split was rounded to integer target weights.")
        first = self.plan.upstreams[resolved[0][1]["backend"].upstream_key]
        members = [self.plan.upstreams[item[1]["backend"].upstream_key] for item in live]
        settings = members[0].proxy_settings
        if any(m.proxy_settings != settings for m in members):
            self.report.warning("istio-resilience-weighted", spec.ref,
                                "Weighted destinations have different connectionPool settings; Ferrum serves them "
                                "from one merged upstream, so they were not migrated for this route.")
            settings = {}
        # Outlier detection applies to each destination's own endpoints (its ejection cap included); one merged
        # upstream would pool them, even when the settings match.
        health = None
        if any((m.health_checks or {}).get("passive") for m in members):
            self.report.warning("istio-outlier-weighted", spec.ref,
                                "Each weighted destination's outlierDetection applies to its own endpoints; Ferrum "
                                "serves the split from one merged upstream, so it was not migrated for this route.")
        key = f"weighted:{spec.ref}"
        self.plan.upstreams[key] = UpstreamSpec(key=key, name=f"{spec.name}-weighted", ref=spec.ref, targets=targets,
                                                tls=first.tls, algorithm="weighted_round_robin",
                                                health_checks=dict(health) if health else None,
                                                proxy_settings=dict(settings))
        spec.backend = BackendRef(scheme=resolved[0][1]["backend"].scheme, upstream_key=key)

    def _backend(self, fqdn: str, port: int | None, gw_ns: str, ref: str, allow_discovery: bool = True) -> dict:
        if port is None and self.ctx.kubernetes_service_discovery and fqdn.endswith(".svc.cluster.local") \
                and not self._has_service_entry(fqdn):
            # Istio takes the port of a single-port Service; the Service object in the input supplies it.
            labels = fqdn.split(".")
            service = self.services.get((labels[1], labels[0])) if len(labels) == 5 else None
            ports = [mapping(p) for p in seq(mapping((service or {}).get("spec")).get("ports"))]
            if len(ports) == 1:
                port = util.parse_port(ports[0].get("port"))
        targets, port, se_sans, problem = self._service_entry_targets(fqdn, port)
        if problem:
            return {"problem": problem}
        discovery = None
        if self.ctx.kubernetes_service_discovery and fqdn.endswith(".svc.cluster.local") \
                and not self._has_service_entry(fqdn):
            if allow_discovery:
                discovery, port = self._kubernetes_discovery(fqdn, port, ref)
            elif (fqdn, "weighted") not in self.discovery_reported:
                self.discovery_reported.add((fqdn, "weighted"))
                self.report.warning("istio-k8s-sd-weighted", ref,
                                    "A weighted split over several destinations is served from one merged Ferrum "
                                    "upstream, which cannot combine service-discovery providers; "
                                    f"{safe_label(fqdn)} keeps its Service DNS name for this route.")
        rule = self._destination_rule(fqdn, gw_ns)
        tls, scheme, algorithm, hash_policy, problem = self._traffic_policy(rule, port, ref, se_sans)
        if problem:
            return {"problem": problem}
        if discovery is not None:
            targets = []
            if scheme == "https" and not tls.sni:
                # Discovered targets are pod addresses: keep verifying the backend certificate against the Service
                # name, as the DNS target did.
                tls.sni = fqdn
        hash_on, cookie_config = hash_policy if hash_policy else (None, None)
        passive, pool_settings = self._resilience(rule, port, f"istio destination {safe_label(fqdn)}:{port}", targets,
                                                  discovered=discovery is not None)
        if rule is None and not self.no_dr_warned:
            self.no_dr_warned = True
            self.report.warning("istio-no-destination-rule", ref, "Destinations without a DestinationRule are reached "
                                "over plaintext HTTP; workloads requiring mesh mTLS reject these requests (fail closed).")
        key = (f"{fqdn}:{port}|{scheme}|{tls.key()}|{algorithm}|{hash_on}|"
               f"{json.dumps([cookie_config, passive, pool_settings, discovery], sort_keys=True)}")
        if key not in self.plan.upstreams:
            self.plan.upstreams[key] = UpstreamSpec(key=key, name=f"{fqdn}-{port}", ref=f"istio destination {fqdn}:{port}",
                                                    targets=targets, tls=tls, algorithm=algorithm, hash_on=hash_on,
                                                    hash_on_cookie_config=cookie_config,
                                                    health_checks={"passive": passive} if passive else None,
                                                    proxy_settings=dict(pool_settings), outlier_scoped=bool(passive),
                                                    service_discovery=discovery)
        return {"backend": BackendRef(scheme=scheme, upstream_key=key), "targets": targets,
                "tls_key": scheme + tls.key()}

    def _has_service_entry(self, fqdn: str) -> bool:
        return any(matching.host_cover(h, fqdn) for entry in self.service_entries
                   for h in [h.lower() for h in (str_list(mapping(entry.get("spec")).get("hosts")) or [])])

    def _kubernetes_discovery(self, fqdn: str, port: int | None, ref: str) -> tuple[dict | None, int | None]:
        """Ferrum Kubernetes service discovery for ``<name>.<namespace>.svc.cluster.local``, or (None, port).

        Ferrum's provider (Edge ``src/service_discovery/kubernetes.rs``) lists the EndpointSlices labelled
        ``kubernetes.io/service-name=<name>`` and takes each ready endpoint with the slice port named
        ``port_name`` (the first port when unset). Slice ports carry the Service port names, so the Service
        object (in the input) maps the destination's Service port number to that name; without it the port
        cannot be chosen safely and the destination keeps its DNS name.
        """
        labels = fqdn.split(".")
        if len(labels) != 5:
            return None, port
        name, namespace = labels[0], labels[1]
        reported = (fqdn, str(port))

        def keep_dns(message: str) -> tuple[None, int | None]:
            if reported not in self.discovery_reported:
                self.discovery_reported.add(reported)
                self.report.warning("istio-k8s-sd-port", ref, message + f" {safe_label(fqdn)} keeps its Service DNS "
                                    "name (the Service's cluster IP).")
            return None, port

        service = self.services.get((namespace, name))
        if service is None:
            return keep_dns("The Kubernetes Service object is not in the input, so the EndpointSlice port cannot be "
                            "selected.")
        spec = mapping(service.get("spec"))
        if str(spec.get("type", "ClusterIP")) == "ExternalName":
            return keep_dns("The Service is an ExternalName alias with no endpoints.")
        ports = [mapping(p) for p in seq(spec.get("ports"))]
        if port is None and len(ports) == 1:
            port = util.parse_port(ports[0].get("port"))
        matched = [p for p in ports if util.parse_port(p.get("port")) == port]
        if port is None or len(matched) != 1:
            return keep_dns("The destination port is not exactly one of the Service's ports.")
        port_name = matched[0].get("name")
        kubernetes: dict[str, Any] = {"namespace": namespace, "service_name": name}
        if isinstance(port_name, str) and port_name:
            kubernetes["port_name"] = port_name
        elif len(ports) != 1:
            return keep_dns("The Service port is unnamed in a multi-port Service.")
        self.discovery_namespaces.add(namespace)
        return {"provider": "kubernetes", "kubernetes": kubernetes}, port

    def _service_entry_targets(
        self, fqdn: str, port: int | None
    ) -> tuple[list[Target], int | None, list[str] | None, str | None]:
        for entry in self.service_entries:
            spec = mapping(entry.get("spec"))
            hosts = [h.lower() for h in (str_list(spec.get("hosts")) or [])]
            if not any(matching.host_cover(h, fqdn) for h in hosts):
                continue
            raw_se_sans = spec.get("subjectAltNames")
            se_sans: list[str] | None = [] if raw_se_sans is None else str_list(raw_se_sans)
            ports = [mapping(p) for p in seq(spec.get("ports"))]
            if port is None and len(ports) == 1:
                port = util.parse_port(ports[0].get("number"))
            if port is None:
                return [], None, se_sans, "destination port is required (ServiceEntry has several ports)"
            port_entry = next((p for p in ports if util.parse_port(p.get("number")) == port), {})
            resolution = str(spec.get("resolution", "NONE")).upper()
            if resolution == "NONE":
                return [], port, se_sans, "ServiceEntry with resolution NONE (passthrough) is not migrated"
            endpoints = [mapping(e) for e in seq(spec.get("endpoints"))]
            if not endpoints:
                return [Target(fqdn, util.parse_port(port_entry.get("targetPort")) or port, 1)], port, se_sans, None
            targets = []
            for endpoint in endpoints:
                address = endpoint.get("address")
                if not isinstance(address, str) or address.startswith("unix://"):
                    return [], port, se_sans, "ServiceEntry endpoint address is not representable"
                endpoint_port = util.parse_port(mapping(endpoint.get("ports")).get(str(port_entry.get("name", "")))) \
                    or util.parse_port(port_entry.get("targetPort")) or port
                targets.append(Target(address, endpoint_port, util.as_int(endpoint.get("weight")) or 1))
            return targets, port, se_sans, None
        if port is None:
            return [], None, [], "destination port is required (no ServiceEntry describes the service ports)"
        return [Target(fqdn, port, 1)], port, [], None

    def _destination_rule(self, fqdn: str, gw_ns: str) -> dict | None:
        best = None
        best_rank = None
        for rule in self.destination_rules:
            ns, _name = _meta(rule)
            host = str(mapping(rule.get("spec")).get("host", "")).lower()
            host = _fqdn(host, ns) if host and "*" not in host else host
            if not host or not matching.host_cover(host, fqdn):
                continue
            namespace_rank = 0 if ns == gw_ns else (1 if fqdn.split(".")[1:2] == [ns] else 2)
            rank = (0 if host == fqdn else 1, namespace_rank)
            if best_rank is None or rank < best_rank:
                best, best_rank = rule, rank
        return best

    @staticmethod
    def _effective_policy(rule: dict, port: int | None) -> dict:
        """The DestinationRule trafficPolicy for one port. A matching portLevelSettings entry replaces the whole
        destination-level policy: settings it omits take their defaults, they are not inherited (Istio
        ``GetPortLevelTrafficPolicy`` in pilot/pkg/networking/util/util.go)."""
        policy = mapping(mapping(rule.get("spec")).get("trafficPolicy"))
        for level in seq(policy.get("portLevelSettings")):
            level = mapping(level)
            if util.parse_port(mapping(level.get("port")).get("number")) == port:
                return {k: v for k, v in level.items() if k != "port"}
        return policy

    def _resilience(self, rule: dict | None, port: int | None, ref: str, targets: list,
                    discovered: bool = False) -> tuple[dict | None, dict]:
        """(passive health check, per-proxy pool settings) from outlierDetection and connectionPool.

        Discovered targets are individual pods, the hosts Istio's outlier detection ejects."""
        if rule is None:
            return None, {}
        cache_key = (id(rule), port, discovered)
        if cache_key in self.resilience_cache:  # one report per destination, however many routes use it
            return self.resilience_cache[cache_key]
        policy = self._effective_policy(rule, port)
        passive = None
        if isinstance(policy.get("outlierDetection"), dict):
            passive = istio_outlier_passive(policy["outlierDetection"], discovered or endpoints_are_hosts(targets),
                                            self.report, ref)
        settings = {}
        if isinstance(policy.get("connectionPool"), dict):
            settings = istio_connection_pool(policy["connectionPool"], self.report, ref)
        self.resilience_cache[cache_key] = (passive, settings)
        return passive, settings

    def _traffic_policy(self, rule: dict | None, port: int | None, ref: str, se_sans: list[str] | None = None):
        tls = TlsSpec()
        if rule is None:
            return tls, "http", "round_robin", None, None
        policy = self._effective_policy(rule, port)
        tls_policy = mapping(policy.get("tls"))
        mode = str(tls_policy.get("mode", "DISABLE")).upper()
        scheme = "http"
        if mode in ("SIMPLE", "MUTUAL"):
            scheme = "https"
            tls.verify = not tls_policy.get("insecureSkipVerify")
            if tls_policy.get("credentialName") or tls_policy.get("caCertCredentialName"):
                return tls, scheme, "round_robin", None, (
                    "DestinationRule credentialName/caCertCredentialName (Kubernetes Secret) is never read")
            extra_tls = [k for k in ("caCrl", "verifyCertificateSpki", "verifyCertificateHash") if tls_policy.get(k)]
            if extra_tls:
                return tls, scheme, "round_robin", None, (
                    "DestinationRule TLS validation constraints (" + ", ".join(extra_tls) + ") are not supported")
            if isinstance(tls_policy.get("caCertificates"), str):
                tls.ca_path = tls_policy["caCertificates"]
            if isinstance(tls_policy.get("sni"), str):
                tls.sni = tls_policy["sni"]
            raw_dr_sans = tls_policy.get("subjectAltNames")
            if raw_dr_sans is not None:
                parsed_dr_sans = str_list(raw_dr_sans)
                if parsed_dr_sans is None:
                    return tls, scheme, "round_robin", None, "DestinationRule subjectAltNames has unexpected types"
                sans = parsed_dr_sans
            else:
                sans = []
            if not sans:
                if se_sans is None:
                    return tls, scheme, "round_robin", None, "ServiceEntry subjectAltNames has unexpected types"
                sans = list(se_sans)
            if any(not util.valid_backend_tls_san(s) for s in sans):
                return tls, scheme, "round_robin", None, "DestinationRule/ServiceEntry subjectAltNames entry is not representable"
            tls.san_allow_list = sans
            if mode == "MUTUAL":
                cert, key = tls_policy.get("clientCertificate"), tls_policy.get("privateKey")
                if not (isinstance(cert, str) and cert.strip() and isinstance(key, str) and key.strip()):
                    return tls, scheme, "round_robin", None, "MUTUAL TLS without client certificate file paths"
                tls.client_cert_path, tls.client_key_path = cert, key
        elif mode == "ISTIO_MUTUAL":
            return tls, scheme, "round_robin", None, "ISTIO_MUTUAL needs mesh identity; use Ferrum mesh mode"
        elif mode != "DISABLE":
            return tls, scheme, "round_robin", None, f"DestinationRule TLS mode {safe_label(mode, 32)} is not supported"
        balancer = mapping(policy.get("loadBalancer"))
        algorithm, hash_on = "round_robin", None
        simple = str(balancer.get("simple", "ROUND_ROBIN")).upper()
        algorithm = {"ROUND_ROBIN": "round_robin", "LEAST_REQUEST": "least_connections", "LEAST_CONN": "least_connections",
                     "RANDOM": "random", "PASSTHROUGH": "round_robin"}.get(simple, "round_robin")
        consistent = mapping(balancer.get("consistentHash"))
        if consistent:
            if consistent.get("httpHeaderName"):
                header_key = hash_on_value("header", consistent["httpHeaderName"])
                if header_key is None:
                    self.report.warning("istio-hash", ref, "consistentHash httpHeaderName is not an HTTP token Ferrum "
                                        "accepts; round robin.")
                else:
                    algorithm, hash_on = "consistent_hashing", header_key
            elif mapping(consistent.get("httpCookie")).get("name"):
                cookie_hash, cookie_config = envoy_cookie_hash(mapping(consistent["httpCookie"]), self.report,
                                                               "istio-hash", ref)
                if cookie_hash is not None:
                    algorithm, hash_on = "consistent_hashing", (cookie_hash, cookie_config)
            elif consistent.get("useSourceIp"):
                algorithm, hash_on = "consistent_hashing", "ip"
            else:
                self.report.warning("istio-hash", ref, "consistentHash source has no equivalent; round robin.")
        # (hash_on, hash_on_cookie_config), or None without consistent hashing.
        hash_policy = hash_on if isinstance(hash_on, tuple) else ((hash_on, None) if hash_on else None)
        return tls, scheme, algorithm, hash_policy, None


_GRPC_STATUS_NAMES = {
    "OK": 0, "CANCELLED": 1, "UNKNOWN": 2, "INVALID_ARGUMENT": 3, "DEADLINE_EXCEEDED": 4,
    "NOT_FOUND": 5, "ALREADY_EXISTS": 6, "PERMISSION_DENIED": 7, "RESOURCE_EXHAUSTED": 8,
    "FAILED_PRECONDITION": 9, "ABORTED": 10, "OUT_OF_RANGE": 11, "UNIMPLEMENTED": 12,
    "INTERNAL": 13, "UNAVAILABLE": 14, "DATA_LOSS": 15, "UNAUTHENTICATED": 16,
}


def _translate_istio_fault(raw: Any) -> tuple[str, Any]:
    if not isinstance(raw, dict):
        return "drop", "fault must be a mapping"
    delay_cfg: dict[str, Any] | None = None
    abort_cfg: dict[str, Any] | None = None
    if raw.get("delay") is not None:
        delay = raw.get("delay")
        if not isinstance(delay, dict) or delay.get("exponentialDelay") is not None:
            return "drop", "unsupported fault delay shape"
        duration_ms = util.parse_go_duration_ms(delay.get("fixedDelay"))
        if duration_ms is None:
            return "drop", "delay.fixedDelay is missing or invalid"
        pct_obj = delay.get("percentage")
        if isinstance(pct_obj, dict) and pct_obj.get("value") is not None:
            raw_pct = pct_obj["value"]
        elif delay.get("percent") is not None:
            raw_pct = delay["percent"]
        else:
            return "drop", "delay requires an explicit percentage"
        pct = parse_percentage(raw_pct)
        if pct is None:
            return "drop", "delay percentage is invalid"
        if pct > 0.0:
            delay_cfg = {"duration_ms": duration_ms, "percentage": pct}
    if raw.get("abort") is not None:
        abort = raw.get("abort")
        if not isinstance(abort, dict) or abort.get("http2Error") is not None:
            return "drop", "unsupported fault abort shape"
        pct_obj = abort.get("percentage")
        if not isinstance(pct_obj, dict) or pct_obj.get("value") is None:
            return "drop", "abort requires an explicit percentage"
        pct = parse_percentage(pct_obj["value"])
        if pct is None:
            return "drop", "abort percentage is invalid"
        http_raw = abort.get("httpStatus")
        grpc_raw = abort.get("grpcStatus")
        if http_raw is not None and grpc_raw is not None:
            return "drop", "abort cannot set both httpStatus and grpcStatus (mutually exclusive in Istio)"
        http_status = util.as_int(http_raw) if http_raw is not None else None
        grpc_code: int | None = None
        if grpc_raw is not None:
            if isinstance(grpc_raw, str) and grpc_raw.upper() in _GRPC_STATUS_NAMES:
                grpc_code = _GRPC_STATUS_NAMES[grpc_raw.upper()]
            else:
                grpc_code = util.as_int(grpc_raw)
            if grpc_code is None:
                return "drop", "abort.grpcStatus is not representable"
            # Envoy/Istio send HTTP 200 for gRPC-status aborts; Ferrum uses status_code directly on HTTP requests.
            http_status = 200
        if http_status is None:
            return "drop", "abort.httpStatus is missing or invalid"
        if pct > 0.0:
            abort_cfg = {"status_code": http_status, "percentage": pct, "body": "fault filter abort"}
            if grpc_code is not None:
                abort_cfg["grpc_status"] = grpc_code
    if delay_cfg is None and abort_cfg is None:
        return "omit", None
    cfg, err = fault_injection_config(abort=abort_cfg, delay=delay_cfg)
    return ("plugin", cfg) if cfg is not None else ("drop", err)


def _bind_address(value: Any) -> str | None:
    """A Gateway Server ``bind``: None for unset or a wildcard address, else the restricted address/socket."""
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "0.0.0.0", "::", "[::]"):
        return None
    return text


def _selectors_disjoint(gateway_selector: dict, policy_labels: dict) -> bool:
    """Whether no pod can match both label selectors: some key is pinned to different values.

    An empty Gateway selector, or labels the Gateway selector does not mention, prove nothing: one pod can
    carry every label of both selectors.
    """
    return any(key in gateway_selector and str(gateway_selector[key]) != str(value)
               for key, value in policy_labels.items())


def _target_ref_may_apply(ref: dict, policy_ns: str, gw_ns: str, gw_name: str, gateway_selector: dict) -> bool:
    """Whether a policy ``targetRef`` entry may apply to the legacy Gateway's workloads (fail closed).

    A Kubernetes Gateway API ``targetRef`` (``kind: Gateway``) attaches to gateway pods carrying either
    ``gateway.networking.k8s.io/gateway-name: <name>`` or legacy ``istio.io/gateway-name: <name>``. Under the
    same disjointness invariant as workload selectors, a ``kind: Gateway`` targetRef is provably unrelated only
    when it is well-formed, does not name this Gateway, AND ``gateway_selector`` pins BOTH gateway-name label
    keys to values different from the referenced Gateway name. Malformed refs (non-string namespace/group),
    ``kind: GatewayClass``, and unrecognized kind/group combinations always apply.
    """
    raw_kind = ref.get("kind")
    raw_name = ref.get("name")
    raw_ns = ref.get("namespace")
    raw_group = ref.get("group")
    if not (isinstance(raw_kind, str) and raw_kind and raw_kind == raw_kind.strip()
            and isinstance(raw_name, str) and raw_name and raw_name == raw_name.strip()):
        return True
    if raw_ns is not None and (not isinstance(raw_ns, str) or not raw_ns or raw_ns != raw_ns.strip()):
        return True
    if raw_group is not None and (not isinstance(raw_group, str) or raw_group != raw_group.strip()):
        return True
    ref_kind = raw_kind
    ref_name = raw_name
    ref_ns = raw_ns if isinstance(raw_ns, str) else policy_ns
    ref_group = raw_group if isinstance(raw_group, str) else ""
    # Istio targetRef attachment is strictly same-namespace; cross-namespace targetRefs are invalid and fail closed.
    if ref_ns != policy_ns:
        return True
    if (ref_kind == "Service" and ref_group == "") or (ref_kind == "ServiceEntry" and ref_group == "networking.istio.io"):
        return False
    if ref_kind == "Gateway" and ref_group == "gateway.networking.k8s.io":
        if ref_name == gw_name and ref_ns == gw_ns:
            return True
        return not (
            _selectors_disjoint(gateway_selector, {"gateway.networking.k8s.io/gateway-name": ref_name})
            and _selectors_disjoint(gateway_selector, {"istio.io/gateway-name": ref_name})
        )
    return True


def _is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _fqdn(host: str, namespace: str) -> str:
    if host.endswith(".svc.cluster.local") or "*" in host:
        return host
    parts = host.split(".")
    if len(parts) == 1:
        return f"{host}.{namespace}.svc.cluster.local"
    if len(parts) == 2:
        return f"{host}.svc.cluster.local"
    return host


def _bind_hosts(vs_hosts: list[str], vs_ns: str, gw_ns: str, server_hosts: list[str]) -> list[str] | None:
    """Hosts a VirtualService serves through one Gateway server; ``[]`` = any; None = not bound."""
    result: list[str] = []
    any_host = False
    for entry in server_hosts:
        ns_filter, _, host = entry.rpartition("/")
        ns_filter = ns_filter or "*"
        if ns_filter not in ("*", vs_ns) and not (ns_filter == "." and vs_ns == gw_ns):
            continue
        host = host.lower()
        for vs_host in vs_hosts:
            if vs_host == "*" and host == "*":
                any_host = True
            elif vs_host == "*":
                result.append(host)
            elif host == "*" or matching.host_cover(host, vs_host):
                result.append(vs_host)
            elif matching.host_cover(vs_host, host):
                result.append(host)
    if any_host:
        return []
    deduped = []
    for host in result:
        if host not in deduped:
            deduped.append(host)
    return deduped or None


def translate(text: str, fmt: str, ctx: SourceContext) -> Plan:
    documents = load_structured(text, fmt, ctx.limits, allow_multi=True)
    objects: list[dict] = []
    for document in documents:
        if not isinstance(document, dict):
            raise InputError("every YAML document must be a Kubernetes object")
        if document.get("kind") == "List":
            for item in seq(document.get("items")):
                if not isinstance(item, dict):
                    raise InputError("every List item must be a Kubernetes object")
                objects.append(item)
        else:
            objects.append(document)
    return _Istio(objects, ctx).run()
