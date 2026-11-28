"""Outlier detection, circuit breakers and connection pools (Envoy clusters, Istio DestinationRules).

A source control is migrated only where Ferrum Edge reproduces it exactly, following Edge's own DestinationRule
projection (``apply_outlier_detection_to_passive`` in Edge ``src/modes/mesh/mod.rs``) and Envoy's ejection
rules (``source/common/upstream/outlier_detection_impl.cc``); every other case is reported with its own code and
nothing approximate is emitted.
"""

import unittest

from helpers import codes, migrate, read_fixture

from ferrum_migration.model import Target
from ferrum_migration.report import Report
from ferrum_migration.sources.common import FIVE_XX, endpoints_are_hosts, envoy_outlier_passive, \
    istio_connection_pool, istio_outlier_passive

IPS = [Target("10.0.0.1", 80, 1), Target("10.0.0.2", 80, 1)]
EXACT = {"base_ejection_time": "300s", "max_ejection_time": "300s", "enforcing_success_rate": 0}


def upstream_for(config: dict, target_host: str) -> dict:
    found = [u for u in config["upstreams"] if any(t["host"] == target_host for t in u["targets"])
             and len(u["targets"]) <= 2 and not u["name"].endswith("-weighted")]
    assert len(found) == 1, (target_host, [u["name"] for u in found])
    return found[0]


def messages(report: Report, code: str) -> str:
    return " ".join(c.message for c in report.caveats if c.code == code)


class EnvoyOutlierTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _plan = migrate("envoy", read_fixture("resilience", "envoy.yaml"))

    def test_exact_detector_becomes_a_passive_streak(self):
        import yaml

        envoy = yaml.safe_load(read_fixture("resilience", "envoy.yaml"))
        vhost = envoy["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0][
            "typed_config"]["route_config"]["virtual_hosts"][0]
        routes = vhost["routes"]
        filtered = [route for route in routes if route.get("name") != "split"]
        self.assertEqual(len(filtered), len(routes) - 1)
        vhost["routes"] = filtered

        result, _report, _plan = migrate("envoy", yaml.safe_dump(envoy))
        upstream = upstream_for(result.config, "10.0.0.1")
        self.assertEqual(upstream["health_checks"]["passive"], {
            "unhealthy_status_codes": FIVE_XX, "consecutive_error_mode": True, "unhealthy_threshold": 3,
            "unhealthy_window_seconds": 5, "healthy_after_seconds": 300, "max_ejection_percent": 50})

    def test_shared_direct_and_weighted_cluster_skips_health_checks_and_warns(self):
        upstream = upstream_for(self.result.config, "10.0.0.1")
        self.assertNotIn("health_checks", upstream)
        warnings = [
            c for c in self.report.caveats
            if c.code == "outlier-detection-scope"
            and c.severity == "warning"
            and c.ref == "envoy cluster 'ejecting'"
        ]
        self.assertEqual(len(warnings), 1)

    def test_growing_ejection_time_is_reported_not_approximated(self):  # base 60s < max_ejection_time 300s
        self.assertNotIn("health_checks", upstream_for(self.result.config, "10.0.1.1"))
        self.assertIn("envoy-outlier-ejection-growth", codes(self.report))

    def test_dns_names_are_not_individual_hosts(self):  # F4
        self.assertNotIn("health_checks", upstream_for(self.result.config, "named-1.internal"))
        self.assertIn("envoy-outlier-endpoints", codes(self.report))
        report = Report("envoy", "input")
        envoy_outlier_passive({}, [Target("n.internal", 80, 1)], False, report, "cluster")
        self.assertIn("success-rate", messages(report, "envoy-outlier-unsupported"))  # host count unknown

    def test_routes_sharing_a_cluster_do_not_share_a_streak(self):  # F6
        self.assertNotIn("health_checks", upstream_for(self.result.config, "10.0.4.1"))
        self.assertIn("outlier-detection-scope", codes(self.report))

    def test_weighted_routes_report_the_lost_detector(self):  # F2
        self.assertIn("envoy-outlier-weighted", codes(self.report))
        weighted = [u for u in self.result.config["upstreams"] if u["name"].endswith("-weighted")]
        self.assertTrue(weighted)
        self.assertTrue(all("health_checks" not in u for u in weighted))

    def test_only_live_cluster_of_a_weighted_route_keeps_its_policy(self):  # F9 (Envoy)
        solo = upstream_for(self.result.config, "10.0.5.1")
        self.assertIn("passive", solo["health_checks"])

    def test_partial_enforcement_and_disabled_detector_emit_nothing(self):
        for host in ("10.0.2.1", "10.0.3.1"):
            with self.subTest(host=host):
                self.assertNotIn("health_checks", upstream_for(self.result.config, host))

    def test_circuit_breakers_are_reported_not_mapped(self):
        self.assertIn("envoy-circuit-breakers", codes(self.report))
        self.assertFalse([p for p in self.result.config["proxies"] if "circuit_breaker" in p])

    def test_split_origin_counting_is_not_reproduced(self):  # F5
        report = Report("envoy", "input")
        self.assertIsNone(envoy_outlier_passive(dict(EXACT, split_external_local_origin_errors=True), IPS, False,
                                                report, "cluster"))
        self.assertIn("envoy-outlier-split", codes(report))

    def test_unknown_and_override_fields_are_reported(self):  # F10
        report = Report("envoy", "input")
        self.assertIsNone(envoy_outlier_passive(dict(EXACT, always_eject_one_host=True), IPS, False, report, "c"))
        report = Report("envoy", "input")
        envoy_outlier_passive(dict(EXACT, some_future_field=1), IPS, False, report, "c")
        self.assertIn("some_future_field", messages(report, "envoy-outlier-unsupported"))

    def test_endpoint_granularity(self):
        self.assertTrue(endpoints_are_hosts(IPS))
        self.assertFalse(endpoints_are_hosts([Target("n.internal", 80, 1)]))
        self.assertTrue(endpoints_are_hosts([Target("n.internal", 80, 1)], logical_dns=True))


class IstioResilienceTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _plan = migrate("istio", read_fixture("resilience", "istio.yaml"))

    def test_exact_outlier_detection_follows_edge_projection(self):
        pay = upstream_for(self.result.config, "10.2.0.1")
        self.assertEqual(pay["health_checks"]["passive"], {
            "unhealthy_status_codes": FIVE_XX, "consecutive_error_mode": True, "unhealthy_threshold": 7,
            "unhealthy_window_seconds": 5, "healthy_after_seconds": 300, "max_ejection_percent": 50})
        self.assertIn("minHealthPercent", messages(self.report, "istio-outlier-unsupported"))

    def test_service_names_and_growing_ejection_are_not_approximated(self):
        orders = upstream_for(self.result.config, "orders.shop.svc.cluster.local")
        self.assertNotIn("health_checks", orders)
        self.assertIn("istio-outlier-ejection-growth", codes(self.report))  # 45s < Envoy's 300s max

    def test_connection_pool_maps_only_exact_controls(self):  # F1, F7, F10
        orders = upstream_for(self.result.config, "orders.shop.svc.cluster.local")
        proxies = [p for p in self.result.config["proxies"] if p.get("upstream_id") == orders["id"]]
        self.assertTrue(proxies)
        for proxy in proxies:
            self.assertEqual(proxy["backend_connect_timeout_ms"], 2000)
            for key in ("pool_idle_timeout_seconds", "pool_http2_max_concurrent_streams",
                        "pool_tcp_keepalive_seconds"):
                self.assertNotIn(key, proxy)
        text = messages(self.report, "istio-connection-pool")
        for field in ("http.maxConcurrentStreams", "http.idleTimeout", "tcp.tcpKeepalive.time", "tcp.maxConnections",
                      "http.http2MaxRequests", "tcp.tcpKeepalive.probes", "http.http2KeepAlive"):
            self.assertIn(field, text)

    def test_port_level_settings_replace_the_destination_policy(self):  # F3
        ported = upstream_for(self.result.config, "ported.shop.svc.cluster.local")
        self.assertNotIn("health_checks", ported)
        self.assertEqual(ported["algorithm"], "least_connections")
        for proxy in self.result.config["proxies"]:
            if proxy.get("upstream_id") == ported["id"]:
                self.assertNotIn("backend_connect_timeout_ms", proxy)

    def test_weighted_destinations_never_pool_outlier_detection(self):  # F8
        text = read_fixture("resilience", "istio.yaml").replace(
            "      route: [{destination: {host: pay.external.test, port: {number: 8080}}}]",
            "      route:\n"
            "        - {destination: {host: pay.external.test, port: {number: 8080}}, weight: 50}\n"
            "        - {destination: {host: pay.external.test, port: {number: 8080}}, weight: 50}")
        result, report, _plan = migrate("istio", text)
        self.assertIn("istio-outlier-weighted", codes(report))
        weighted = [u for u in result.config["upstreams"] if u["name"].endswith("-weighted")]
        self.assertTrue(weighted and all("health_checks" not in u for u in weighted))

    def test_zero_weight_destination_keeps_the_live_policy(self):  # F9
        text = read_fixture("resilience", "istio.yaml").replace(
            "      route: [{destination: {host: orders.shop.svc.cluster.local, port: {number: 8080}}}]",
            "      route:\n"
            "        - {destination: {host: orders.shop.svc.cluster.local, port: {number: 8080}}, weight: 100}\n"
            "        - {destination: {host: canary.shop.svc.cluster.local, port: {number: 8080}}, weight: 0}")
        result, _report, _plan = migrate("istio", text)
        self.assertFalse([u for u in result.config["upstreams"] if u["name"].endswith("-weighted")])
        orders = upstream_for(result.config, "orders.shop.svc.cluster.local")
        proxies = [p for p in result.config["proxies"] if p.get("upstream_id") == orders["id"]]
        self.assertTrue(proxies and all(p["backend_connect_timeout_ms"] == 2000 for p in proxies))

    def test_disabled_and_invalid_outlier_detection(self):
        report = Report("istio", "input")
        self.assertIsNone(istio_outlier_passive({"consecutive5xxErrors": 0}, True, report, "dr"))
        self.assertIsNone(istio_outlier_passive({"maxEjectionPercent": 150}, True, report, "dr"))
        self.assertIsNone(istio_outlier_passive({"baseEjectionTime": "300s", "splitExternalLocalOriginErrors": True},
                                                True, report, "dr"))
        self.assertIn("istio-outlier-split", codes(report))
        passive = istio_outlier_passive({"baseEjectionTime": "5m", "interval": "1m"}, True, Report("i", "x"), "dr")
        self.assertEqual((passive["unhealthy_threshold"], passive["unhealthy_window_seconds"],
                          passive["healthy_after_seconds"]), (5, 60, 300))

    def test_connection_pool_invalid_connect_timeout(self):
        report = Report("istio", "input")
        self.assertEqual(istio_connection_pool({"tcp": {"connectTimeout": 5}}, report, "dr"), {})
        self.assertIn("istio-connection-pool", codes(report))


if __name__ == "__main__":
    unittest.main()
