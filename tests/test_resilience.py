"""Outlier detection, circuit breakers and connection pools (Envoy clusters, Istio DestinationRules).

Mapped only where Ferrum Edge applies the same control to file-mode resources, following Edge's own
DestinationRule projection (``apply_outlier_detection_to_passive`` in Edge ``src/modes/mesh/mod.rs``,
``translate_outlier_detection`` / ``translate_traffic_policy`` in ``src/config_sources/k8s/istio.rs``);
everything else is reported, never approximated silently.
"""

import unittest

from helpers import codes, migrate, read_fixture

from ferrum_migration.report import Report
from ferrum_migration.sources.common import FIVE_XX, envoy_outlier_passive, istio_connection_pool, \
    istio_outlier_passive


def upstream_for(config: dict, target_host: str) -> dict:
    found = [u for u in config["upstreams"] if any(t["host"] == target_host for t in u["targets"])]
    assert len(found) == 1, target_host
    return found[0]


def proxies_to(config: dict, upstream: dict) -> list[dict]:
    return [p for p in config["proxies"] if p.get("upstream_id") == upstream["id"]]


class EnvoyResilienceTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _plan = migrate("envoy", read_fixture("resilience", "envoy.yaml"))

    def test_consecutive_5xx_becomes_a_passive_streak(self):
        upstream = upstream_for(self.result.config, "ejecting-1.internal")
        self.assertEqual(upstream["health_checks"]["passive"], {
            "unhealthy_status_codes": FIVE_XX, "consecutive_error_mode": True, "unhealthy_threshold": 3,
            "unhealthy_window_seconds": 5, "healthy_after_seconds": 60, "max_ejection_percent": 50})
        self.assertIn("envoy-outlier", codes(self.report))

    def test_circuit_breakers_are_reported_not_mapped(self):
        self.assertIn("envoy-circuit-breakers", codes(self.report))
        upstream = upstream_for(self.result.config, "ejecting-1.internal")
        for proxy in proxies_to(self.result.config, upstream):
            self.assertNotIn("circuit_breaker", proxy)

    def test_partial_enforcement_and_disabled_detector_emit_nothing(self):
        for host in ("partial-1.internal", "disabled-1.internal"):
            with self.subTest(host=host):
                self.assertNotIn("health_checks", upstream_for(self.result.config, host))

    def test_success_rate_default_is_reported_with_enough_hosts(self):
        report = Report("envoy", "input")
        envoy_outlier_passive({}, 5, report, "cluster")
        self.assertIn("envoy-outlier-unsupported", codes(report))
        report = Report("envoy", "input")
        passive = envoy_outlier_passive({}, 2, report, "cluster")
        self.assertNotIn("envoy-outlier-unsupported", codes(report))
        # Envoy defaults: 5 consecutive, 10s interval, 30s base ejection, 10% cap.
        self.assertEqual((passive["unhealthy_threshold"], passive["unhealthy_window_seconds"],
                          passive["healthy_after_seconds"], passive["max_ejection_percent"]), (5, 10, 30, 10))


class IstioResilienceTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _plan = migrate("istio", read_fixture("resilience", "istio.yaml"))
        self.upstream = upstream_for(self.result.config, "orders.shop.svc.cluster.local")

    def test_outlier_detection_follows_edge_projection(self):
        self.assertEqual(self.upstream["health_checks"]["passive"], {
            "unhealthy_status_codes": FIVE_XX, "consecutive_error_mode": True, "unhealthy_threshold": 7,
            "unhealthy_window_seconds": 5, "healthy_after_seconds": 45, "max_ejection_percent": 30})

    def test_deferred_outlier_fields_are_reported(self):
        messages = " ".join(c.message for c in self.report.caveats if c.code == "istio-outlier-unsupported")
        self.assertIn("minHealthPercent", messages)

    def test_connection_pool_maps_only_file_mode_controls(self):
        proxies = proxies_to(self.result.config, self.upstream)
        self.assertTrue(proxies)
        for proxy in proxies:
            self.assertEqual(proxy["backend_connect_timeout_ms"], 2000)
            self.assertEqual(proxy["pool_idle_timeout_seconds"], 90)
            self.assertEqual(proxy["pool_http2_max_concurrent_streams"], 50)
            self.assertEqual(proxy["pool_tcp_keepalive_seconds"], 600)
        messages = " ".join(c.message for c in self.report.caveats if c.code == "istio-connection-pool")
        for field in ("tcp.maxConnections", "http.http2MaxRequests", "tcp.tcpKeepalive.probes"):
            self.assertIn(field, messages)

    def test_disabled_and_invalid_outlier_detection(self):
        report = Report("istio", "input")
        self.assertIsNone(istio_outlier_passive({"consecutive5xxErrors": 0}, report, "dr"))
        self.assertIsNone(istio_outlier_passive({"maxEjectionPercent": 150}, report, "dr"))
        self.assertIn("istio-outlier", codes(report))
        # An omitted threshold is Istio's default of 5 consecutive errors.
        passive = istio_outlier_passive({"interval": "1m"}, Report("istio", "input"), "dr")
        self.assertEqual((passive["unhealthy_threshold"], passive["unhealthy_window_seconds"]), (5, 60))

    def test_connection_pool_rounding(self):
        report = Report("istio", "input")
        settings = istio_connection_pool({"http": {"idleTimeout": "2h"}, "tcp": {"tcpKeepalive": {"time": "1.5s"}}},
                                         report, "dr")
        self.assertEqual(settings, {"pool_idle_timeout_seconds": 3600})
        self.assertIn("istio-connection-pool", codes(report))

    def test_weighted_destinations_with_different_policies_are_reported(self):
        text = read_fixture("resilience", "istio.yaml").replace(
            "      route: [{destination: {host: orders.shop.svc.cluster.local, port: {number: 8080}}}]",
            "      route:\n"
            "        - {destination: {host: orders.shop.svc.cluster.local, port: {number: 8080}}, weight: 50}\n"
            "        - {destination: {host: other.shop.svc.cluster.local, port: {number: 8080}}, weight: 50}")
        result, report, _plan = migrate("istio", text)
        self.assertIn("istio-resilience-weighted", codes(report))
        weighted = [u for u in result.config["upstreams"] if len(u["targets"]) == 2]
        self.assertEqual(len(weighted), 1)
        self.assertNotIn("health_checks", weighted[0])


if __name__ == "__main__":
    unittest.main()
