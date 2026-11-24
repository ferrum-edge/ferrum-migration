import json
import textwrap
import unittest

from helpers import assert_structurally_valid, codes, migrate, one_proxy, plugin, plugins_of, proxies, read_fixture, \
    upstream_of

from ferrum_migration.errors import InputError


class IstioFixtureTest(unittest.TestCase):
    def setUp(self):
        self.text = read_fixture("istio", "istio.yaml")
        self.result, self.report, self.plan = migrate("istio", self.text)
        self.config = self.result.config

    def test_structure_and_tls(self):
        assert_structurally_valid(self, self.config)
        self.assertTrue(self.result.tls_only)
        self.assertIn(("/etc/istio/certs/tls.crt", "/etc/istio/certs/tls.key"), self.plan.settings.frontend_cert_pairs)
        self.assertIn("istio-https-redirect", codes(self.report, "info"))

    def test_weighted_destinations_timeout_and_retries(self):
        proxy = one_proxy(self, self.config, "/cart", "shop.example.com")
        self.assertTrue(proxy["preserve_host_header"])
        self.assertEqual(proxy["backend_read_timeout_ms"], 5000)
        self.assertEqual(proxy["retry"]["max_retries"], 3)
        upstream = upstream_of(self.config, proxy)
        self.assertEqual([(t["host"], t["port"], t["weight"]) for t in upstream["targets"]],
                         [("cart.shop.svc.cluster.local", 8080, 1000), ("cart-next.shop.svc.cluster.local", 8080, 111)])

    def test_destination_rule_tls_lb_rewrite_and_cors(self):
        proxy = one_proxy(self, self.config, "/catalog", "shop.example.com")
        self.assertEqual(proxy["allowed_methods"], ["GET"])
        self.assertEqual(proxy["backend_scheme"], "https")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertEqual(proxy["backend_path"], "/v1/catalog")
        upstream = upstream_of(self.config, proxy)
        self.assertEqual(upstream["algorithm"], "least_connections")
        self.assertTrue(upstream["backend_tls_verify_server_cert"])
        self.assertEqual(upstream["backend_tls_server_ca_cert_path"], "/etc/certs/internal-ca.pem")
        cors = plugin(self, self.config, proxy, "cors")["config"]
        self.assertEqual(cors["allowed_origins"], [{"exact": "https://shop.example.com"}])
        self.assertEqual(cors["max_age"], 86400)

    def test_subset_refused_service_entry_and_headers(self):
        reviews = one_proxy(self, self.config, "/reviews", "shop.example.com")
        self.assertEqual(reviews["labels"]["ferrum-migration/status"], "refused")
        billing = one_proxy(self, self.config, "/billing", "shop.example.com")
        targets = upstream_of(self.config, billing)["targets"]
        self.assertEqual([(t["host"], t["port"]) for t in targets], [("192.0.2.10", 8080), ("192.0.2.11", 8080)])
        root = one_proxy(self, self.config, "/", "shop.example.com")
        rules = plugin(self, self.config, root, "request_transformer")["config"]["rules"]
        self.assertIn({"operation": "update", "target": "header", "key": "x-gateway", "value": "ferrum"}, rules)
        self.assertIn({"operation": "remove", "target": "header", "key": "x-internal-debug"}, rules)
        guards = sorted(p["config"]["trigger"]["path_prefix"] for p in plugins_of(self.config, root)
                        if p["plugin_name"] == "request_termination")
        # /reviews is refused (subset); Istio sent /reviewsx to it, so it must not reach the "/" route either.
        self.assertEqual(guards, ["/billing", "/cart", "/catalog", "/reviews"])

    def test_mesh_routes_and_secrets_not_translated(self):
        self.assertIn("istio-mesh-routes", codes(self.report, "info"))
        self.assertIn("istio-secret-ignored", codes(self.report, "warning"))
        everything = json.dumps(self.config) + json.dumps([c.to_dict() for c in self.report.caveats])
        self.assertNotIn("dGVzdC1vbmx5", everything)
        self.assertNotIn("ratings", json.dumps(self.config))


class IstioSecurityTest(unittest.TestCase):
    def test_authorization_policy_on_gateway_refuses_its_routes(self):
        text = read_fixture("istio", "istio.yaml") + textwrap.dedent("""
            ---
            apiVersion: security.istio.io/v1
            kind: AuthorizationPolicy
            metadata:
              name: gw-allow-office
              namespace: edge
            spec:
              selector:
                matchLabels:
                  istio: ingressgateway
              action: ALLOW
              rules:
                - from:
                    - source:
                        ipBlocks: ["192.0.2.0/24"]
        """)
        result, report, _ = migrate("istio", text)
        statuses = {p["labels"]["ferrum-migration/status"] for p in result.config["proxies"]
                    if "listen_path" in p}
        self.assertEqual(statuses, {"refused"})

    def test_policy_for_other_workloads_does_not_affect_gateway(self):
        # Provably disjoint: the policy pins the Gateway selector's own label key to another value, so no pod
        # can match both. A targetRef naming another Gateway is unrelated too.
        text = read_fixture("istio", "istio.yaml") + textwrap.dedent("""
            ---
            apiVersion: security.istio.io/v1
            kind: AuthorizationPolicy
            metadata:
              name: egress-only
              namespace: shop
            spec:
              selector:
                matchLabels: {istio: egressgateway, app: cart}
            ---
            apiVersion: security.istio.io/v1
            kind: AuthorizationPolicy
            metadata:
              name: other-gateway
              namespace: edge
            spec:
              targetRefs:
                - {kind: Gateway, group: gateway.networking.k8s.io, name: other-gw}
        """)
        result, report, _ = migrate("istio", text)
        self.assertEqual(one_proxy(self, result.config, "/cart", "shop.example.com")["labels"]["ferrum-migration/status"],
                         "migrated")
        self.assertNotIn("istio-policy-scope-unknown", codes(report))

    def _policy_statuses(self, policy_yaml):
        result, report, _ = migrate("istio", read_fixture("istio", "istio.yaml") + textwrap.dedent(policy_yaml))
        statuses = {p["labels"]["ferrum-migration/status"] for p in result.config["proxies"] if "listen_path" in p}
        return statuses, report

    def test_policy_selector_not_provably_disjoint_refuses_gateway_routes(self):
        # Other or extra label keys are no proof of disjointness: one gateway pod can carry all of them.
        for labels in ("{app: cart}", "{istio: ingressgateway, version: canary}"):
            statuses, _report = self._policy_statuses("""
                ---
                apiVersion: security.istio.io/v1
                kind: AuthorizationPolicy
                metadata: {name: maybe-gateway, namespace: shop}
                spec:
                  selector:
                    matchLabels: LABELS
            """.replace("LABELS", labels))
            self.assertEqual(statuses, {"refused"}, labels)

    def test_namespace_wide_policy_in_unknown_namespace_refuses_gateway_routes(self):
        statuses, report = self._policy_statuses("""
            ---
            apiVersion: security.istio.io/v1
            kind: RequestAuthentication
            metadata: {name: namespace-wide, namespace: payments}
            spec: {}
        """)
        self.assertEqual(statuses, {"refused"})
        self.assertIn("istio-policy-scope-unknown", codes(report, "error"))

    def test_header_match_poisons_only_more_specific_routes(self):
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["app.example.com"]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [app.example.com]
              gateways: [gw]
              http:
                - match: [{uri: {prefix: /api}, headers: {x-canary: {exact: "1"}}}]
                  route: [{destination: {host: canary, port: {number: 80}}}]
                - match: [{uri: {prefix: /api/v1}}]
                  route: [{destination: {host: api, port: {number: 80}}}]
                - route: [{destination: {host: web, port: {number: 80}}}]
        """)
        result, _report, _ = migrate("istio", text)
        self.assertEqual(one_proxy(self, result.config, "/api", "app.example.com")["labels"]["ferrum-migration/status"],
                         "refused")
        self.assertEqual(one_proxy(self, result.config, "/api/v1", "app.example.com")["labels"]["ferrum-migration/status"],
                         "refused")
        self.assertEqual(one_proxy(self, result.config, "/", "app.example.com")["labels"]["ferrum-migration/status"],
                         "migrated")

    def test_istio_mutual_refused(self):
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["app.example.com"]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [app.example.com]
              gateways: [gw]
              http:
                - route: [{destination: {host: web, port: {number: 80}}}]
            ---
            apiVersion: networking.istio.io/v1
            kind: DestinationRule
            metadata: {name: web, namespace: default}
            spec:
              host: web
              trafficPolicy: {tls: {mode: ISTIO_MUTUAL}}
        """)
        result, _report, _ = migrate("istio", text)
        self.assertEqual(one_proxy(self, result.config, "/", "app.example.com")["labels"]["ferrum-migration/status"],
                         "refused")

    def test_mutual_servers_with_different_client_cas_are_refused_not_concatenated(self):
        # Synthetic paths only; no certificate material.
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 443, name: https-a, protocol: HTTPS}
                  hosts: ["a.example.test"]
                  tls:
                    mode: MUTUAL
                    serverCertificate: /etc/synthetic/server.crt
                    privateKey: /etc/synthetic/server.key
                    caCertificates: /etc/synthetic/client-ca-a.pem
                - port: {number: 443, name: https-b, protocol: HTTPS}
                  hosts: ["b.example.test"]
                  tls:
                    mode: MUTUAL
                    serverCertificate: /etc/synthetic/server.crt
                    privateKey: /etc/synthetic/server.key
                    caCertificates: /etc/synthetic/client-ca-b.pem
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: a, namespace: default}
            spec:
              hosts: [a.example.test]
              gateways: [gw]
              http:
                - route: [{destination: {host: web-a, port: {number: 80}}}]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: b, namespace: default}
            spec:
              hosts: [b.example.test]
              gateways: [gw]
              http:
                - route: [{destination: {host: web-b, port: {number: 80}}}]
        """)
        result, report, plan = migrate("istio", text)
        for host in ("a.example.test", "b.example.test"):
            self.assertEqual(one_proxy(self, result.config, "/", host)["labels"]["ferrum-migration/status"],
                             "refused", host)
        self.assertIn("frontend-client-ca-scope", codes(report, "error"))
        self.assertEqual(plan.settings.client_ca_paths, [])

    # Synthetic paths only; no certificate material is read or needed.
    SHARED_HOST = textwrap.dedent("""
        apiVersion: networking.istio.io/v1
        kind: Gateway
        metadata: {name: gw, namespace: default}
        spec:
          servers:
            - port: {number: 80, name: http, protocol: HTTP}
              hosts: ["app.example.test"]
            - port: {number: 443, name: https, protocol: HTTPS}
              hosts: ["app.example.test"]
              tls:
                mode: MUTUAL
                serverCertificate: /etc/synthetic/server.crt
                privateKey: /etc/synthetic/server.key
                caCertificates: /etc/synthetic/client-ca.pem
        EXTRA_TLS
        ---
        apiVersion: networking.istio.io/v1
        kind: VirtualService
        metadata: {name: app, namespace: default}
        spec:
          hosts: [app.example.test]
          gateways: [gw]
          http:
            - route: [{destination: {host: web, port: {number: 80}}}]
    """)

    def test_shared_http_https_host_keeps_https_client_ca(self):
        result, report, plan = migrate("istio", self.SHARED_HOST.replace("EXTRA_TLS", ""))
        self.assertEqual(one_proxy(self, result.config, "/", "app.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")
        self.assertEqual(plan.settings.client_ca_paths, ["/etc/synthetic/client-ca.pem"])
        self.assertIn("istio-shared-host-tls", codes(report, "warning"))

    def test_client_certificate_constraints_refuse_shared_host_routes(self):
        constrained = "        subjectAltNames: [client.example.test]"
        result, report, plan = migrate("istio", self.SHARED_HOST.replace("EXTRA_TLS", constrained))
        self.assertEqual(one_proxy(self, result.config, "/", "app.example.test")["labels"]["ferrum-migration/status"],
                         "refused")
        self.assertIn("istio-client-ca", codes(report, "error"))
        self.assertEqual(plan.settings.client_ca_paths, [])

    def test_overlapping_but_different_shared_host_scopes_are_refused_not_merged(self):
        # The HTTPS server's wildcard covers the plaintext server's host. Ferrum would answer HTTPS requests for
        # that host from the plaintext projection, without the HTTPS server's client certificate requirement.
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["a.example.test"]
                - port: {number: 443, name: https, protocol: HTTPS}
                  hosts: ["*.example.test"]
                  tls:
                    mode: MUTUAL
                    serverCertificate: /etc/synthetic/server.crt
                    privateKey: /etc/synthetic/server.key
                    caCertificates: /etc/synthetic/client-ca.pem
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: ["*.example.test"]
              gateways: [gw]
              http:
                - route: [{destination: {host: web, port: {number: 80}}}]
        """)
        result, report, _plan = migrate("istio", text)
        statuses = {p["labels"]["ferrum-migration/status"] for p in result.config["proxies"] if "listen_path" in p}
        self.assertEqual(statuses, {"refused"})
        self.assertEqual(one_proxy(self, result.config, "/", "a.example.test")["labels"]["ferrum-migration/status"],
                         "refused")
        self.assertIn("istio-shared-host-scope", codes(report, "error"))

    def test_port_specific_match_is_not_resolved_for_one_shared_listener(self):
        # The /admin match applies on the HTTPS server port only. The shared projection serves both listeners, so
        # it is refused (fail closed) instead of being silently dropped for HTTPS or exposed over plaintext.
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["app.example.test"]
                - port: {number: 443, name: https, protocol: HTTPS}
                  hosts: ["app.example.test"]
                  tls: {mode: SIMPLE, serverCertificate: /etc/synthetic/server.crt, privateKey: /etc/synthetic/server.key}
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [app.example.test]
              gateways: [gw]
              http:
                - name: admin-tls-port
                  match: [{port: 443, uri: {prefix: /admin}}]
                  route: [{destination: {host: admin, port: {number: 80}}}]
                - route: [{destination: {host: web, port: {number: 80}}}]
        """)
        result, report, _plan = migrate("istio", text)
        self.assertEqual(one_proxy(self, result.config, "/admin", "app.example.test")["labels"]["ferrum-migration/status"],
                         "refused")
        self.assertEqual(one_proxy(self, result.config, "/", "app.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")
        self.assertIn("route-refused", codes(report, "error"))

    def test_restricted_server_bind_is_not_exposed_on_shared_address(self):
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["public.example.test"]
                  BIND_PUBLIC
                - port: {number: 80, name: http-local, protocol: HTTP}
                  bind: 127.0.0.1
                  hosts: ["local.example.test"]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [public.example.test, local.example.test]
              gateways: [gw]
              http:
                - route: [{destination: {host: web, port: {number: 80}}}]
        """)
        result, report, plan = migrate("istio", text.replace("BIND_PUBLIC", ""))
        self.assertEqual(proxies(result.config, host="local.example.test"), [])
        self.assertIn("istio-server-bind", codes(report, "error"))
        self.assertEqual(one_proxy(self, result.config, "/", "public.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")
        self.assertIsNone(plan.settings.bind_address)
        # Every HTTP server shares the same restricted address: Ferrum binds that address instead.
        result, report, plan = migrate("istio", text.replace("BIND_PUBLIC", "bind: 127.0.0.1"))
        self.assertNotIn("istio-server-bind", codes(report))
        self.assertEqual(plan.settings.bind_address, "127.0.0.1")
        self.assertEqual(len(proxies(result.config, "/", host="local.example.test")), 1)

    def test_uri_prefix_siblings_reported_but_not_exact_matches(self):
        # uri.prefix /api also matches /apix through an Istio gateway; uri.exact has no siblings.
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["app.example.com"]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [app.example.com]
              gateways: [gw]
              http:
                - name: api
                  match: [{uri: {prefix: /api}}]
                  route: [{destination: {host: api, port: {number: 80}}}]
                - name: status
                  match: [{uri: {exact: /status}}]
                  route: [{destination: {host: status, port: {number: 80}}}]
        """)
        result, report, _ = migrate("istio", text)
        self.assertEqual(one_proxy(self, result.config, "/api", "app.example.com")["labels"]["ferrum-migration/status"],
                         "migrated")
        sources = [c.ref for c in report.caveats if c.code == "prefix-string-siblings"]
        self.assertEqual(len(sources), 1)
        self.assertIn("'api'", sources[0])

    def test_non_mapping_document_rejected(self):
        with self.assertRaises(InputError):
            migrate("istio", "- just\n- a list\n")


def routed_statuses(config):
    return {p["labels"]["ferrum-migration/status"] for p in config["proxies"] if "listen_path" in p}


class IstioFrontendScopeTest(unittest.TestCase):
    # Synthetic hosts and file paths only; no certificate material is read or needed.
    TWO_GATEWAYS = textwrap.dedent("""
        apiVersion: networking.istio.io/v1
        kind: Gateway
        metadata: {name: gw-plain, namespace: default}
        spec:
          selector: {app: gw-plain}
          servers:
            - port: {number: 80, name: http, protocol: HTTP}
              hosts: ["PLAIN_HOST"]
        ---
        apiVersion: networking.istio.io/v1
        kind: Gateway
        metadata: {name: gw-tls, namespace: default}
        spec:
          selector: {app: gw-tls}
          servers:
            - port: {number: 443, name: https, protocol: HTTPS}
              hosts: ["TLS_HOST"]
              tls:
                mode: MUTUAL
                serverCertificate: /etc/synthetic/server.crt
                privateKey: /etc/synthetic/server.key
                caCertificates: /etc/synthetic/client-ca.pem
        ---
        apiVersion: networking.istio.io/v1
        kind: VirtualService
        metadata: {name: plain-app, namespace: default}
        spec:
          hosts: ["PLAIN_HOST"]
          gateways: [gw-plain]
          http:
            - name: public
              match: [{uri: {exact: /public}}]
              route: [{destination: {host: public, port: {number: 80}}}]
        ---
        apiVersion: networking.istio.io/v1
        kind: VirtualService
        metadata: {name: tls-app, namespace: default}
        spec:
          hosts: ["TLS_HOST"]
          gateways: [gw-tls]
          http:
            - name: secure
              route: [{destination: {host: secure, port: {number: 80}}}]
    """)

    def two_gateways(self, plain_host, tls_host, **kwargs):
        text = self.TWO_GATEWAYS.replace("PLAIN_HOST", plain_host).replace("TLS_HOST", tls_host)
        return migrate("istio", text, **kwargs)

    def test_plaintext_and_mutual_bindings_on_overlapping_hosts_are_refused(self):
        # Separate Gateway bindings: Ferrum would serve the plaintext binding's /public route on its HTTPS listener
        # for a host whose HTTPS frontend required client certificates. Both projections are refused.
        for plain_host, tls_host in (("app.example.test", "app.example.test"), ("app.example.test", "*.example.test")):
            with self.subTest(plain=plain_host, tls=tls_host):
                result, report, _plan = self.two_gateways(plain_host, tls_host, tls_only=True)
                assert_structurally_valid(self, result.config)
                self.assertEqual(routed_statuses(result.config), {"refused"})
                conflicts = sorted(c.ref for c in report.caveats if c.code == "istio-frontend-scope-conflict")
                self.assertEqual(len(conflicts), 2)

    def test_disjoint_hosts_across_bindings_are_not_a_frontend_conflict(self):
        result, report, _plan = self.two_gateways("www.example.test", "app.example.test", tls_only=True)
        self.assertNotIn("istio-frontend-scope-conflict", codes(report))
        self.assertEqual(one_proxy(self, result.config, "=/public", "www.example.test")["labels"]
                         ["ferrum-migration/status"], "migrated")
        self.assertEqual(one_proxy(self, result.config, "/", "app.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")

    def test_same_frontend_bindings_on_one_host_stay_migrated(self):
        # Two plaintext Gateways and two VirtualServices for one host: the same frontend, no trust to mix.
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw-one, namespace: default}
            spec:
              servers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: [app.example.test]}]
            ---
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw-two, namespace: default}
            spec:
              servers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: [app.example.test]}]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: one, namespace: default}
            spec:
              hosts: [app.example.test]
              gateways: [gw-one]
              http: [{match: [{uri: {exact: /one}}], route: [{destination: {host: one, port: {number: 80}}}]}]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: two, namespace: default}
            spec:
              hosts: [app.example.test]
              gateways: [gw-two]
              http: [{match: [{uri: {exact: /two}}], route: [{destination: {host: two, port: {number: 80}}}]}]
        """)
        result, report, _plan = migrate("istio", text)
        assert_structurally_valid(self, result.config)
        self.assertNotIn("istio-frontend-scope-conflict", codes(report))
        for path in ("=/one", "=/two"):
            self.assertEqual(one_proxy(self, result.config, path, "app.example.test")["labels"]
                             ["ferrum-migration/status"], "migrated", path)

    def test_refused_frontend_of_another_binding_refuses_overlapping_live_binding(self):
        # Both bindings are HTTPS without client certificates; a policy selects only gw-tls's workloads, so its
        # binding is refused. The other Gateway's live routes for an overlapping host would answer those requests
        # in Ferrum, so they are refused as well (the refused candidate counts).
        text = self.TWO_GATEWAYS.replace("PLAIN_HOST", "app.example.test").replace("TLS_HOST", "*.example.test")
        text = text.replace("    - port: {number: 80, name: http, protocol: HTTP}\n",
                            "    - port: {number: 443, name: https-other, protocol: HTTPS}\n"
                            "      tls: {mode: SIMPLE, serverCertificate: /etc/synthetic/server.crt, "
                            "privateKey: /etc/synthetic/server.key}\n")
        text = text.replace("mode: MUTUAL", "mode: SIMPLE").replace(
            "        caCertificates: /etc/synthetic/client-ca.pem\n", "")
        self.assertNotIn("protocol: HTTP}", text)
        self.assertNotIn("caCertificates", text)
        text += textwrap.dedent("""
            ---
            apiVersion: security.istio.io/v1
            kind: AuthorizationPolicy
            metadata: {name: tls-only-policy, namespace: default}
            spec:
              selector:
                matchLabels: {app: gw-tls}
              action: ALLOW
              rules: [{from: [{source: {ipBlocks: ["192.0.2.0/24"]}}]}]
        """)
        result, report, _plan = migrate("istio", text)
        self.assertEqual(routed_statuses(result.config), {"refused"})
        self.assertIn("istio-frontend-scope-conflict", codes(report, "error"))

    def test_extra_plaintext_listener_is_not_emitted(self):
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: [www.example.test]
                - port: {number: 8080, name: http-ops, protocol: HTTP}
                  hosts: [ops.example.test]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: web, namespace: default}
            spec:
              hosts: [www.example.test]
              gateways: [gw]
              http: [{route: [{destination: {host: web, port: {number: 80}}}]}]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: ops, namespace: default}
            spec:
              hosts: [ops.example.test]
              gateways: [gw]
              http: [{route: [{destination: {host: ops, port: {number: 80}}}]}]
        """)
        result, report, _plan = migrate("istio", text)
        assert_structurally_valid(self, result.config)
        self.assertEqual(proxies(result.config, host="ops.example.test"), [])
        self.assertEqual(one_proxy(self, result.config, "/", "www.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")
        self.assertIn("extra-listener-refused", codes(report, "error"))


class IstioCaseAndNamesTest(unittest.TestCase):
    IGNORE_CASE = textwrap.dedent("""
        apiVersion: networking.istio.io/v1
        kind: Gateway
        metadata: {name: gw, namespace: default}
        spec:
          servers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: [app.example.test]}]
        ---
        apiVersion: networking.istio.io/v1
        kind: VirtualService
        metadata: {name: app, namespace: default}
        spec:
          hosts: [app.example.test]
          gateways: [gw]
          http:
            - name: admin
              match: [{uri: {prefix: /admin/}IGNORE}]
              route: [{destination: {host: admin, port: {number: 80}}}]
            - name: status
              match: [{uri: {exact: /status}}]
              route: [{destination: {host: status, port: {number: 80}}}]
            - name: web
              route: [{destination: {host: web, port: {number: 80}}}]
    """)

    def status(self, result, path):
        return one_proxy(self, result.config, path, "app.example.test")["labels"]["ferrum-migration/status"]

    def test_ignore_uri_case_refuses_routes_that_would_receive_case_variants(self):
        # Istio sent /ADMIN/x to the admin route; in Ferrum it would reach the "/" route instead. That route is
        # refused (fail closed); admin keeps its exact-case path, and the unrelated exact /status route stays.
        result, report, _plan = migrate("istio", self.IGNORE_CASE.replace("IGNORE", ", ignoreUriCase: true"))
        assert_structurally_valid(self, result.config)
        self.assertEqual(self.status(result, "/admin"), "migrated")
        self.assertEqual(self.status(result, "=/status"), "migrated")
        self.assertEqual(self.status(result, "/"), "refused")
        self.assertIn("istio-ignore-case", codes(report, "warning"))
        self.assertIn("route-refused", codes(report, "error"))

    def test_case_sensitive_match_keeps_expected_behavior(self):
        result, report, _plan = migrate("istio", self.IGNORE_CASE.replace("IGNORE", ""))
        for path in ("/admin", "=/status", "/"):
            self.assertEqual(self.status(result, path), "migrated", path)
        self.assertNotIn("istio-ignore-case", codes(report))
        self.assertNotIn("route-refused", codes(report))

    def test_route_projected_through_two_servers_gets_unique_names(self):
        # One direct-response route bound through a plaintext and an HTTPS server with disjoint hosts becomes two
        # proxies (and two closures) from the same source names. Ferrum rejects duplicate proxy names.
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: [a.example.test]
                - port: {number: 443, name: https, protocol: HTTPS}
                  hosts: [b.example.test]
                  tls: {mode: SIMPLE, serverCertificate: /etc/synthetic/server.crt, privateKey: /etc/synthetic/server.key}
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [a.example.test, b.example.test]
              gateways: [gw]
              http:
                - name: maintenance
                  match: [{uri: {exact: /maintenance}}]
                  directResponse: {status: 503, body: {string: maintenance}}
        """)
        for tls_only in (False, True):
            with self.subTest(tls_only=tls_only):
                result, _report, _plan = migrate("istio", text, tls_only=tls_only)
                assert_structurally_valid(self, result.config)
                names = [p["name"] for p in result.config["proxies"]]
                self.assertEqual(len(names), len(set(names)))
                self.assertEqual(len(result.config["proxies"]), 4)  # two routes, two closures
                self.assertIn("maintenance", names)
                again, _report, _plan = migrate("istio", text, tls_only=tls_only)
                self.assertEqual(names, [p["name"] for p in again.config["proxies"]])


if __name__ == "__main__":
    unittest.main()
