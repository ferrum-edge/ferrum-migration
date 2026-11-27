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
        self.assertEqual(payments["service_discovery"]["kubernetes"],
                         {"namespace": "shop", "service_name": "payments"})

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

    def test_deployment_requirement_is_reported(self):
        text = " ".join(c.message for c in self.report.caveats if c.code == "istio-k8s-sd")
        self.assertIn("EndpointSlices", text)
        self.assertIn("shop", text)


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
