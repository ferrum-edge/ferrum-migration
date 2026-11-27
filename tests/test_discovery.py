"""--kubernetes-service-discovery: Istio Service destinations through Ferrum's Kubernetes service discovery.

Ferrum's provider (Edge ``src/service_discovery/kubernetes.rs``) lists the EndpointSlices labelled
``kubernetes.io/service-name`` and uses the slice port named ``port_name`` (the first port when unset); slice
ports carry the Service port names, so the Service object in the input selects the port.
"""

import contextlib
import io
import unittest

from helpers import codes, fixture_path, migrate, read_fixture

from ferrum_migration.cli import main
from ferrum_migration.errors import InputError

GATEWAY = """apiVersion: networking.istio.io/v1
kind: Gateway
metadata: {name: gw, namespace: edge}
spec:
  selector: {istio: ingressgateway}
  servers:
    - port: {number: 80, name: http, protocol: HTTP}
      hosts: ["*/d.example.test"]
"""


def convert(http_routes: str, *documents: str):
    vs = ("---\napiVersion: networking.istio.io/v1\nkind: VirtualService\nmetadata: {name: d, namespace: shop}\n"
          "spec:\n  hosts: [d.example.test]\n  gateways: [edge/gw]\n  http:\n" + http_routes)
    text = GATEWAY + vs + "".join("---\n" + doc for doc in documents)
    return migrate("istio", text, kubernetes_service_discovery=True)


def service(name: str, ports: str, extra: str = "") -> str:
    return (f"apiVersion: v1\nkind: Service\nmetadata: {{name: {name}, namespace: shop}}\nspec:\n"
            f"  selector: {{app: {name}}}\n  ports: {ports}\n{extra}")


def route(path: str, host: str, port: str = "8080") -> str:
    return (f"    - name: r{path.strip('/').replace('/', '-')}\n      match: [{{uri: {{prefix: {path}}}}}]\n"
            f"      route: [{{destination: {{host: {host}, port: {{number: {port}}}}}}}]\n")


def upstream_of_path(config: dict, listen_path: str) -> dict:
    proxy = [p for p in config["proxies"] if p.get("listen_path") == listen_path and p.get("upstream_id")]
    assert len(proxy) == 1, listen_path
    return next(u for u in config["upstreams"] if u["id"] == proxy[0]["upstream_id"])


class KubernetesDiscoveryTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _plan = migrate("istio", read_fixture("discovery", "istio.yaml"),
                                                  kubernetes_service_discovery=True)

    def test_named_port_of_a_multi_port_service(self):
        orders = upstream_of_path(self.result.config, "/orders")
        self.assertEqual(orders["targets"], [])
        self.assertEqual(orders["service_discovery"], {"provider": "kubernetes", "kubernetes": {
            "namespace": "shop", "service_name": "orders", "port_name": "http"}})

    def test_single_unnamed_port_uses_the_first_slice_port(self):
        payments = upstream_of_path(self.result.config, "/payments")
        # An unnamed port is selected by its (empty) name, never as the first slice port (Edge matches a slice
        # port without a name against "").
        self.assertEqual(payments["service_discovery"]["kubernetes"],
                         {"namespace": "shop", "service_name": "payments", "port_name": ""})

    def test_https_keeps_verifying_the_service_name(self):
        secure = upstream_of_path(self.result.config, "/secure")
        self.assertEqual(secure["service_discovery"]["kubernetes"]["port_name"], "https")
        self.assertEqual(secure["backend_tls_sni"], "secure.shop.svc.cluster.local")
        self.assertTrue(secure["backend_tls_verify_server_cert"])

    def test_missing_service_keeps_the_dns_name(self):
        missing = upstream_of_path(self.result.config, "/missing")
        self.assertNotIn("service_discovery", missing)
        self.assertEqual(missing["targets"][0]["host"], "missing.shop.svc.cluster.local")
        self.assertIn("istio-k8s-sd-port", codes(self.report))

    def test_weighted_split_keeps_dns_names(self):
        split = upstream_of_path(self.result.config, "/split")
        self.assertNotIn("service_discovery", split)
        self.assertEqual(sorted(t["host"] for t in split["targets"]),
                         ["orders.shop.svc.cluster.local", "payments.shop.svc.cluster.local"])
        self.assertIn("istio-k8s-sd-weighted", codes(self.report))

    def test_deployment_requirement_is_reported(self):  # F1
        text = " ".join(c.message for c in self.report.caveats if c.code == "kubernetes-service-discovery")
        for needle in ("EndpointSlices", "shop", "KUBERNETES_SERVICE_HOST", "ca.crt", "FERRUM_TLS_CA_BUNDLE_PATH",
                       "FERRUM_BACKEND_ALLOW_IPS"):
            self.assertIn(needle, text)


class ExactOrReportedTest(unittest.TestCase):
    def test_node_local_and_unready_policies_keep_dns(self):  # F2
        for extra in ("  internalTrafficPolicy: Local\n", "  publishNotReadyAddresses: true\n"):
            with self.subTest(extra=extra.strip()):
                result, report, _plan = convert(route("/a", "a"), service("a", "[{name: http, port: 8080}]", extra))
                self.assertNotIn("service_discovery", upstream_of_path(result.config, "/a"))
                self.assertIn("istio-k8s-sd-port", codes(report))

    def test_non_tcp_port_refuses_the_route(self):  # F3
        result, _report, _plan = convert(route("/a", "a"),
                                         service("a", "[{name: dns, port: 8080, protocol: UDP}]"))
        proxy = [p for p in result.config["proxies"] if p.get("listen_path") == "/a"][0]
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")

    def test_invalid_explicit_port_is_refused_not_inferred(self):  # F6
        result, _report, _plan = convert(route("/a", "a", "65536"), service("a", "[{name: http, port: 8080}]"))
        proxy = [p for p in result.config["proxies"] if p.get("listen_path") == "/a"][0]
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")

    def test_invalid_kubernetes_names_keep_dns(self):  # F7
        result, report, _plan = convert(route("/a", "a"), service("a", "[{name: " + "x" * 64 + ", port: 8080}]"))
        self.assertNotIn("service_discovery", upstream_of_path(result.config, "/a"))
        self.assertIn("istio-k8s-sd-port", codes(report))

    def test_duplicate_service_is_rejected(self):  # F8
        doc = service("a", "[{name: http, port: 8080}]")
        with self.assertRaises(InputError):
            convert(route("/a", "a"), doc, doc)

    def test_report_names_only_emitted_discovery(self):  # F9
        dr = ("apiVersion: networking.istio.io/v1\nkind: DestinationRule\nmetadata: {name: a, namespace: shop}\n"
              "spec:\n  host: a.shop.svc.cluster.local\n  trafficPolicy: {tls: {mode: ISTIO_MUTUAL}}\n")
        result, report, _plan = convert(route("/a", "a"), service("a", "[{name: http, port: 8080}]"), dr)
        self.assertFalse([u for u in result.config["upstreams"] if "service_discovery" in u])
        self.assertNotIn("kubernetes-service-discovery", codes(report))

    def test_weighted_use_of_a_destination_shares_its_outlier_detector(self):  # F5
        outlier = ("apiVersion: networking.istio.io/v1\nkind: DestinationRule\nmetadata: {name: a, namespace: shop}\n"
                   "spec:\n  host: a.shop.svc.cluster.local\n"
                   "  trafficPolicy: {outlierDetection: {consecutive5xxErrors: 3, baseEjectionTime: 300s}}\n")
        split = ("    - name: split\n      match: [{uri: {prefix: /split}}]\n      route:\n"
                 "        - {destination: {host: a, port: {number: 8080}}, weight: 50}\n"
                 "        - {destination: {host: b, port: {number: 8080}}, weight: 50}\n")
        docs = (service("a", "[{name: http, port: 8080}]"), service("b", "[{name: http, port: 8080}]"), outlier)
        alone, report, _plan = convert(route("/a", "a"), *docs)
        self.assertIn("passive", upstream_of_path(alone.config, "/a")["health_checks"])  # discovered pods: exact
        shared, report, _plan = convert(route("/a", "a") + split, *docs)
        self.assertNotIn("health_checks", upstream_of_path(shared.config, "/a"))
        self.assertIn("outlier-detection-scope", codes(report))


class WithoutFlagTest(unittest.TestCase):
    def test_default_keeps_service_dns_names(self):
        result, report, _plan = migrate("istio", read_fixture("discovery", "istio.yaml"))
        orders = upstream_of_path(result.config, "/orders")
        self.assertNotIn("service_discovery", orders)
        self.assertEqual(orders["targets"][0]["host"], "orders.shop.svc.cluster.local")
        self.assertIn("istio-object-ignored", codes(report))

    def test_flag_is_refused_for_other_sources(self):
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            code = main(["check", fixture_path("kong", "kong.yaml"), "--from", "kong",
                         "--kubernetes-service-discovery"])
        self.assertEqual(code, 2)
        self.assertIn("--from istio", err.getvalue())


if __name__ == "__main__":
    unittest.main()
