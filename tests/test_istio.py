import json
import textwrap
import unittest

from helpers import assert_structurally_valid, codes, migrate, one_proxy, plugin, plugins_of, read_fixture, upstream_of

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
        self.assertEqual(guards, ["/billing", "/cart", "/catalog"])

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
        text = read_fixture("istio", "istio.yaml") + textwrap.dedent("""
            ---
            apiVersion: security.istio.io/v1
            kind: AuthorizationPolicy
            metadata:
              name: cart-only
              namespace: shop
            spec:
              selector:
                matchLabels: {app: cart}
        """)
        result, _report, _ = migrate("istio", text)
        self.assertEqual(one_proxy(self, result.config, "/cart", "shop.example.com")["labels"]["ferrum-migration/status"],
                         "migrated")

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

    def test_non_mapping_document_rejected(self):
        with self.assertRaises(InputError):
            migrate("istio", "- just\n- a list\n")


if __name__ == "__main__":
    unittest.main()
