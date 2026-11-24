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
from typing import Any

from .. import matching, util
from ..errors import InputError
from ..model import BackendRef, HostScope, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from ..safe_load import load_structured
from .common import (SourceContext, apply_first_match_order, check_route_budget, choose_main_port, cors_config,
                     literal_value, mapping, merge_weighted_targets, request_header_rule, response_header_rule,
                     retry_from_policy, seq, str_list)

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
        self.shared_bind: str | None = None
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
        check_route_budget(len(self.plan.routes), self.ctx.limits)
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
            if isinstance(ca, str):
                # Recorded per server; the emitter decides whether one listener-wide bundle preserves every scope.
                server["client_ca"] = ca
            else:
                return "mutual TLS without a caCertificates file path"
            if mode == "OPTIONAL_MUTUAL":
                self.report.warning("istio-optional-mutual", server["ref"], "OPTIONAL_MUTUAL becomes mandatory client "
                                    "certificates (stricter).")
        return None

    def _gateway_refusals(self, gateway: dict, ref: str) -> list[str]:
        """Policies that (may) apply to the gateway workloads refuse that gateway's routes.

        The namespace the ingress gateway *pods* run in is not part of the input (it is
        often ``istio-system`` or ``istio-ingress``, not the Gateway resource's
        namespace). A workload selector that matches the Gateway's selector is
        therefore treated as applying in any namespace (fail closed). A namespace-wide
        policy (no selector) applies when it lives in the Gateway's or the root
        namespace; one in another namespace is reported for review, because it applies
        only if the gateway pods run there.
        """
        gw_ns, gw_name = _meta(gateway)
        selector = mapping(mapping(gateway.get("spec")).get("selector"))
        reasons = []
        for policy in self.policies:
            ns, name = _meta(policy)
            spec = mapping(policy.get("spec"))
            kind = str(policy.get("kind"))
            refs = [mapping(r) for r in seq(spec.get("targetRefs")) + seq(spec.get("targetRef"))]
            targeted = any(r.get("kind") == "Gateway" and r.get("name") == gw_name and
                           (r.get("namespace") or ns) == gw_ns for r in refs)
            labels = mapping(mapping(spec.get("selector")).get("matchLabels")) or \
                mapping(mapping(spec.get("workloadSelector")).get("labels"))
            label = f"{kind} {safe_label(ns)}/{safe_label(name)}"
            if targeted:
                applies = True
            elif refs:
                applies = False
            elif labels:
                applies = bool(selector) and all(selector.get(k) == v for k, v in labels.items())
            elif ns in (gw_ns, ROOT_NAMESPACE):
                applies = True
            else:
                applies = False
                self.report.error("istio-policy-scope-unknown", ref,
                                  f"{label} has no workload selector, so it applies to every workload in its "
                                  "namespace. If the ingress gateway pods run in that namespace, its policy is not "
                                  "migrated and these routes would be less protected.",
                                  "Confirm the gateway pods' namespace; if it matches, recreate the policy in Ferrum "
                                  "before serving traffic.")
            if applies:
                reasons.append(f"{label} applies to this gateway's workloads and cannot be translated")
        return reasons

    # --------------------------------------------------------- virtualservices

    def _virtual_service(self, vs: dict) -> None:
        namespace, name = _meta(vs)
        ref = f"istio VirtualService '{safe_label(namespace)}/{safe_label(name)}'"
        spec = mapping(vs.get("spec"))
        if spec.get("tls") or spec.get("tcp"):
            self.report.error("istio-l4-routes", ref, "tls/tcp routes are not migrated (HTTP only).")
        gateways = str_list(spec.get("gateways")) or ["mesh"]
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
        refusals = self._gateway_refusals(gateway, f"{ref} via {safe_label(gateway_ref)}")
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
                settings.https_redirect_seen = True
                self.report.info("istio-https-redirect", server["ref"], "httpsRedirect server: not emitted; the "
                                 "TLS-only profile disables the plaintext listener instead.")
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
        self._merge_shared_hosts(groups, ref)
        for group in groups.values():
            listen_port, requires_tls = group["listen_port"], group["requires_tls"]
            hosts = [] if group["any"] else group["hosts"]
            routes: list[RouteSpec] = []
            for index, entry in enumerate(seq(spec.get("http"))):
                routes.extend(self._http_route(mapping(entry), index, namespace, name, ref, hosts, listen_port,
                                               requires_tls, gw_ns, gateway_ref, group["port"]))
            for route in routes:
                route.client_cas = list(group["client_cas"])
                for reason in group["refusals"] + refusals:
                    route.refuse(reason)
            apply_first_match_order(routes, self.report)
            self.plan.routes.extend(routes)
            if hosts:
                self.plan.host_scopes.append(HostScope(f"{ref} via {safe_label(gateway_ref)}", list(hosts), listen_port))

    def _merge_shared_hosts(self, groups: dict, ref: str) -> None:
        """Keep an HTTPS server's requirements for hosts a plaintext main-port server also binds.

        Ferrum serves port-agnostic routes on its plaintext and its HTTPS listener, so such hosts get one route
        set. It must carry the HTTPS server's client CA (Ferrum checks the client CA bundle on the HTTPS listener
        only, so plaintext access stays as in the source) or its refusal; dropping the HTTPS group would serve
        HTTPS without them.
        """
        plain_key = (None, False, None, None)
        for key in [k for k in groups if k[1] is True]:
            plain = groups.get(plain_key)
            if plain is None:
                return
            secure = groups[key]
            strict = bool(secure["client_cas"] or secure["refusals"])
            if plain["any"]:
                # The plaintext catch-all routes already serve every host this HTTPS server binds.
                del groups[key]
                if strict:
                    self._carry_tls(plain, secure, ref, whole_catch_all=not secure["any"])
                continue
            if secure["any"]:
                if strict and plain["hosts"]:
                    self._carry_tls(plain, secure, ref, whole_catch_all=False)  # every plaintext host is shared
                continue
            shared = [host for host in secure["hosts"] if host in plain["hosts"]]
            secure["hosts"] = [host for host in secure["hosts"] if host not in shared]
            if not secure["hosts"]:
                del groups[key]
            if not shared or not strict:
                continue
            plain["hosts"] = [host for host in plain["hosts"] if host not in shared]
            split = {"hosts": shared, "any": False, "port": plain["port"], "listen_port": None, "requires_tls": False,
                     "client_cas": [], "refusals": []}
            self._carry_tls(split, secure, ref, whole_catch_all=False)
            groups[("shared",) + key] = split
            if not plain["hosts"]:
                del groups[plain_key]

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
                    server_port: int | None) -> list[RouteSpec]:
        name = str(entry.get("name") or f"{vs_name}-http-{index + 1}")
        base_ref = f"istio route '{safe_label(name)}' in {vs_ref}"
        blocks: dict[tuple, dict] = {}
        for match in seq(entry.get("match")) or [{}]:
            match = mapping(match)
            if match.get("port") and util.as_int(match.get("port")) != server_port:
                continue
            match_gateways = str_list(match.get("gateways"))
            if match_gateways and gateway_ref not in match_gateways:
                continue
            uri = mapping(match.get("uri"))
            extra = [key for key in ("headers", "queryParams", "authority", "scheme", "sourceLabels",
                                     "sourceNamespace", "withoutHeaders") if match.get(key)]
            if "exact" in uri:
                kind, path = "exact", uri["exact"]
            elif "prefix" in uri:
                # A VirtualService uri.prefix is a plain string prefix (/api also matches /apix); flagged for the
                # emitter's sibling report below. exact and regex matches are not prefixes.
                kind, path = "prefix", uri["prefix"] or "/"
            elif "regex" in uri:
                kind, path = "regex", uri["regex"]
            elif uri:
                kind, path = "prefix", "/"
                extra.append("uri matcher")
            else:
                kind, path = "prefix", "/"
            if match.get("ignoreUriCase"):
                self.report.warning("istio-ignore-case", base_ref, "ignoreUriCase becomes case-sensitive (stricter).")
            method = mapping(match.get("method"))
            methods = None
            if method:
                if "exact" in method:
                    methods = [str(method["exact"]).upper()]
                else:
                    extra.append("non-exact method matcher")
            key = (kind, path, tuple(extra))
            block = blocks.setdefault(key, {"methods": [], "all": False})
            if methods is None:
                block["all"] = True
            else:
                block["methods"].extend(m for m in methods if m not in block["methods"])
        routes = []
        for number, ((kind, path, extra), block) in enumerate(blocks.items()):
            spec = RouteSpec(ref=base_ref if len(blocks) == 1 else f"{base_ref} match #{number + 1}",
                             name=name if number == 0 else f"{name}-{number + 1}",
                             hosts=list(hosts), kind=kind, path=path, listen_port=listen_port,
                             requires_tls=requires_tls)
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
            else:
                spec.termination = {"status_code": status, "content_type": "text/plain",
                                    "body": str(body.get("string", ""))} if status not in (204, 304) else \
                    {"status_code": status, "body": ""}
            return
        if entry.get("redirect"):
            redirect = mapping(entry["redirect"])
            scheme = redirect.get("scheme") or ("https" if requires_tls else None)
            authority, uri = redirect.get("authority"), redirect.get("uri")
            code = util.as_int(redirect.get("redirectCode")) or 301
            if not (scheme and authority and uri) or redirect.get("derivePort"):
                spec.refuse("only fully static redirects (scheme, authority and uri) are migrated")
            else:
                spec.termination = {"status_code": code, "headers": {"location": f"{scheme}://{authority}{uri}"},
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
        if isinstance(rewrite.get("uri"), str):
            if spec.kind == "regex":
                spec.refuse("uri rewrite on a regex match is not supported")
            else:
                spec.strip = True
                spec.backend_path = rewrite["uri"] if rewrite["uri"] not in ("", "/") else None
                if spec.kind == "exact":
                    self.report.warning("istio-exact-rewrite", ref, "uri rewrite on an exact match: verify the "
                                        "forwarded path.")
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
        for key, label in (("fault", "fault injection"), ("mirror", "mirroring"), ("mirrors", "mirroring")):
            if entry.get(key):
                self.report.warning("istio-dropped", ref, f"{label} is dropped.")
        self._cors(spec, mapping(entry.get("corsPolicy")))
        self._headers(spec, mapping(entry.get("headers")))

    def _cors(self, spec: RouteSpec, policy: dict) -> None:
        if not policy:
            return
        origins = []
        for matcher in seq(policy.get("allowOrigins")):
            matcher = mapping(matcher)
            key = next((k for k in ("exact", "prefix", "regex") if k in matcher), None)
            if key is None:
                origins = []
                break
            origins.append({key: matcher[key]})
        for origin in seq(policy.get("allowOrigin")):
            origins.append({"exact": origin})
        max_age = util.parse_go_duration_ms(policy.get("maxAge")) if policy.get("maxAge") else None
        built, problem = cors_config(origins, policy.get("allowMethods"), policy.get("allowHeaders"),
                                     policy.get("exposeHeaders"), policy.get("allowCredentials"),
                                     max_age // 1000 if max_age is not None else None)
        if built:
            spec.plugins.append(PluginSpec("cors", built, spec.ref))
        else:
            self.report.warning("istio-cors", spec.ref, f"CORS omitted ({problem}); browsers block cross-origin calls.")

    def _headers(self, spec: RouteSpec, headers: dict) -> None:
        request = mapping(headers.get("request"))
        response = mapping(headers.get("response"))
        request_rules: list[dict] = []
        response_rules: list[dict] = []
        if request.get("add"):
            spec.refuse("request header 'add' appends in Istio but only adds when absent in Ferrum")
        for key, value in mapping(request.get("set")).items():
            rule, problem = request_header_rule("update", key, literal_value(str(value)))
            request_rules.append(rule) if rule else spec.refuse(problem or "invalid header")
        for key in str_list(request.get("remove")) or []:
            rule, problem = request_header_rule("remove", key)
            request_rules.append(rule) if rule else spec.refuse(problem or "invalid header")
        for op, section in (("update", "set"), ("add", "add")):
            for key, value in mapping(response.get(section)).items():
                rule, problem = response_header_rule(op, key, literal_value(str(value)))
                if rule:
                    response_rules.append(rule)
                else:
                    self.report.warning("istio-response-header", spec.ref, f"Response header not migrated ({problem}).")
        for key in str_list(response.get("remove")) or []:
            rule, _ = response_header_rule("remove", key)
            if rule:
                response_rules.append(rule)
        if response.get("add"):
            self.report.warning("istio-response-add", spec.ref, "Response header 'add' only adds when absent in Ferrum.")
        if request_rules:
            spec.plugins.append(PluginSpec("request_transformer", {"rules": request_rules}, spec.ref))
        if response_rules:
            spec.plugins.append(PluginSpec("response_transformer", {"rules": response_rules}, spec.ref))

    # ------------------------------------------------------------ destinations

    def _destinations(self, spec: RouteSpec, destinations: list[dict], namespace: str, gw_ns: str) -> None:
        resolved = []
        for raw in destinations:
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
            result = self._backend(fqdn, port, gw_ns, spec.ref)
            if result.get("problem"):
                spec.refuse(result["problem"])
                return
            weight = util.as_int(raw.get("weight"))
            resolved.append((100 if weight is None and len(destinations) == 1 else (weight or 0), result))
        if len(resolved) == 1:
            spec.backend = resolved[0][1]["backend"]
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
        key = f"weighted:{spec.ref}"
        self.plan.upstreams[key] = UpstreamSpec(key=key, name=f"{spec.name}-weighted", ref=spec.ref, targets=targets,
                                                tls=first.tls, algorithm="weighted_round_robin")
        spec.backend = BackendRef(scheme=resolved[0][1]["backend"].scheme, upstream_key=key)

    def _backend(self, fqdn: str, port: int | None, gw_ns: str, ref: str) -> dict:
        targets, port, problem = self._service_entry_targets(fqdn, port)
        if problem:
            return {"problem": problem}
        rule = self._destination_rule(fqdn, gw_ns)
        tls, scheme, algorithm, hash_on, problem = self._traffic_policy(rule, port, ref)
        if problem:
            return {"problem": problem}
        if rule is None and not self.no_dr_warned:
            self.no_dr_warned = True
            self.report.warning("istio-no-destination-rule", ref, "Destinations without a DestinationRule are reached "
                                "over plaintext HTTP; workloads requiring mesh mTLS reject these requests (fail closed).")
        key = f"{fqdn}:{port}|{scheme}|{tls.key()}|{algorithm}|{hash_on}"
        if key not in self.plan.upstreams:
            self.plan.upstreams[key] = UpstreamSpec(key=key, name=f"{fqdn}-{port}", ref=f"istio destination {fqdn}:{port}",
                                                    targets=targets, tls=tls, algorithm=algorithm, hash_on=hash_on)
        return {"backend": BackendRef(scheme=scheme, upstream_key=key), "targets": targets,
                "tls_key": scheme + tls.key()}

    def _service_entry_targets(self, fqdn: str, port: int | None) -> tuple[list[Target], int | None, str | None]:
        for entry in self.service_entries:
            spec = mapping(entry.get("spec"))
            hosts = [h.lower() for h in (str_list(spec.get("hosts")) or [])]
            if not any(matching.host_cover(h, fqdn) for h in hosts):
                continue
            ports = [mapping(p) for p in seq(spec.get("ports"))]
            if port is None and len(ports) == 1:
                port = util.parse_port(ports[0].get("number"))
            if port is None:
                return [], None, "destination port is required (ServiceEntry has several ports)"
            port_entry = next((p for p in ports if util.parse_port(p.get("number")) == port), {})
            resolution = str(spec.get("resolution", "NONE")).upper()
            if resolution == "NONE":
                return [], port, "ServiceEntry with resolution NONE (passthrough) is not migrated"
            endpoints = [mapping(e) for e in seq(spec.get("endpoints"))]
            if not endpoints:
                return [Target(fqdn, util.parse_port(port_entry.get("targetPort")) or port, 1)], port, None
            targets = []
            for endpoint in endpoints:
                address = endpoint.get("address")
                if not isinstance(address, str) or address.startswith("unix://"):
                    return [], port, "ServiceEntry endpoint address is not representable"
                endpoint_port = util.parse_port(mapping(endpoint.get("ports")).get(str(port_entry.get("name", "")))) \
                    or util.parse_port(port_entry.get("targetPort")) or port
                targets.append(Target(address, endpoint_port, util.as_int(endpoint.get("weight")) or 1))
            return targets, port, None
        if port is None:
            return [], None, "destination port is required (no ServiceEntry describes the service ports)"
        return [Target(fqdn, port, 1)], port, None

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

    def _traffic_policy(self, rule: dict | None, port: int | None, ref: str):
        tls = TlsSpec()
        if rule is None:
            return tls, "http", "round_robin", None, None
        policy = mapping(mapping(rule.get("spec")).get("trafficPolicy"))
        for level in seq(policy.get("portLevelSettings")):
            level = mapping(level)
            if util.parse_port(mapping(level.get("port")).get("number")) == port:
                policy = {**policy, **{k: v for k, v in level.items() if k != "port"}}
        tls_policy = mapping(policy.get("tls"))
        mode = str(tls_policy.get("mode", "DISABLE")).upper()
        scheme = "http"
        if mode in ("SIMPLE", "MUTUAL"):
            scheme = "https"
            tls.verify = not tls_policy.get("insecureSkipVerify")
            if tls_policy.get("credentialName"):
                return tls, scheme, "round_robin", None, "DestinationRule credentialName (Kubernetes Secret) is never read"
            if isinstance(tls_policy.get("caCertificates"), str):
                tls.ca_path = tls_policy["caCertificates"]
            if isinstance(tls_policy.get("sni"), str):
                tls.sni = tls_policy["sni"]
            tls.san_allow_list = [str(s) for s in seq(tls_policy.get("subjectAltNames"))]
            if mode == "MUTUAL":
                cert, key = tls_policy.get("clientCertificate"), tls_policy.get("privateKey")
                if not (isinstance(cert, str) and isinstance(key, str)):
                    return tls, scheme, "round_robin", None, "MUTUAL TLS without client certificate file paths"
                tls.client_cert_path, tls.client_key_path = cert, key
        elif mode == "ISTIO_MUTUAL":
            return tls, scheme, "round_robin", None, "ISTIO_MUTUAL needs mesh identity; use Ferrum mesh mode"
        balancer = mapping(policy.get("loadBalancer"))
        algorithm, hash_on = "round_robin", None
        simple = str(balancer.get("simple", "ROUND_ROBIN")).upper()
        algorithm = {"ROUND_ROBIN": "round_robin", "LEAST_REQUEST": "least_connections", "LEAST_CONN": "least_connections",
                     "RANDOM": "random", "PASSTHROUGH": "round_robin"}.get(simple, "round_robin")
        consistent = mapping(balancer.get("consistentHash"))
        if consistent:
            if consistent.get("httpHeaderName"):
                algorithm, hash_on = "consistent_hashing", f"header:{str(consistent['httpHeaderName']).lower()}"
            elif mapping(consistent.get("httpCookie")).get("name"):
                algorithm, hash_on = "consistent_hashing", f"cookie:{consistent['httpCookie']['name']}"
            elif consistent.get("useSourceIp"):
                algorithm, hash_on = "consistent_hashing", "ip"
            else:
                self.report.warning("istio-hash", ref, "consistentHash source has no equivalent; round robin.")
        if policy.get("outlierDetection") or policy.get("connectionPool"):
            self.report.warning("istio-resilience", ref, "outlierDetection/connectionPool are not migrated.")
        return tls, scheme, algorithm, hash_on, None


def _bind_address(value: Any) -> str | None:
    """A Gateway Server ``bind``: None for unset or a wildcard address, else the restricted address/socket."""
    if value is None:
        return None
    text = str(value).strip()
    if text in ("", "0.0.0.0", "::", "[::]"):
        return None
    return text


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
