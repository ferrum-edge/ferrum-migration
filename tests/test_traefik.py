import json
import textwrap
import unittest

import yaml

from helpers import assert_structurally_valid, codes, migrate, one_proxy, plugin, plugins_of, proxies, read_fixture, \
    upstream_of

from ferrum_migration.sources.traefik import RuleError, evaluate_term, rule_to_dnf


class TraefikRuleTest(unittest.TestCase):
    def test_dnf_expansion_and_v2_multi_args(self):
        terms = rule_to_dnf("Host(`a.example.com`, `b.example.com`) && (PathPrefix(`/x`) || Path(`/y`))", 32)
        self.assertEqual(len(terms), 4)
        evaluated = [evaluate_term(term) for term in terms]
        self.assertIn({"hosts": {"a.example.com"}, "kind": "prefix", "path": "/x", "methods": None, "extra": []},
                      evaluated)

    def test_negation_and_header_are_extra_conditions(self):
        term = rule_to_dnf("!Host(`a.example.com`) && Header(`X`, `1`)", 32)[0]
        self.assertEqual(sorted(evaluate_term(term)["extra"]), ["Header matcher", "negation"])

    def test_contradictory_hosts_are_unsatisfiable(self):
        term = rule_to_dnf("Host(`a.example.com`) && Host(`b.example.com`)", 32)[0]
        self.assertIsNone(evaluate_term(term))

    def test_bad_rules_raise(self):
        for rule in ("Host(`a`", "Host(a)", "&& Host(`a`)", "(" * 40 + "Host(`a`)" + ")" * 40):
            with self.assertRaises(RuleError):
                rule_to_dnf(rule, 32)

    def test_expansion_cap(self):
        rule = " && ".join(f"(PathPrefix(`/a{i}`) || PathPrefix(`/b{i}`))" for i in range(8))
        with self.assertRaises(RuleError):
            rule_to_dnf(rule, 32)


class TraefikFixtureTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _ = migrate("traefik", read_fixture("traefik", "dynamic.yaml"))
        self.config = self.result.config

    def test_structure(self):
        assert_structurally_valid(self, self.config)
        self.assertTrue(self.result.tls_only)
        self.assertIn("traefik-https-redirect", codes(self.report, "info"))

    def test_strip_prefix_headers_and_rate_limit(self):
        proxy = one_proxy(self, self.config, "/api", "app.example.com")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertTrue(proxy["preserve_host_header"])
        upstream = upstream_of(self.config, proxy)
        self.assertEqual(len(upstream["targets"]), 2)
        self.assertEqual(upstream["health_checks"]["active"],
                         {"http_path": "/health", "interval_seconds": 10, "timeout_ms": 3000})
        request_rules = plugin(self, self.config, proxy, "request_transformer")["config"]["rules"]
        self.assertIn({"operation": "update", "target": "header", "key": "x-gateway", "value": "ferrum"}, request_rules)
        self.assertIn({"operation": "remove", "target": "header", "key": "x-debug"}, request_rules)
        response_rules = plugin(self, self.config, proxy, "response_transformer")["config"]["rules"]
        keys = {rule["key"]: rule.get("value") for rule in response_rules}
        self.assertEqual(keys["strict-transport-security"], "max-age=31536000; includeSubDomains")
        self.assertEqual(keys["x-frame-options"], "DENY")
        self.assertEqual(keys["x-content-type-options"], "nosniff")
        rate = plugin(self, self.config, proxy, "rate_limiting")["config"]
        self.assertEqual(rate, {"limit_by": "ip", "limits": [{"scope": "default", "requests_per_minute": 50}]})

    def test_host_only_root_with_guards(self):
        root = [p for p in proxies(self.config, host="app.example.com") if "listen_path" not in p]
        self.assertEqual(len(root), 1)
        self.assertEqual(root[0]["backend_host"], "frontend.internal")
        self.assertFalse(root[0]["preserve_host_header"])
        guards = sorted(p["config"]["trigger"]["path_prefix"] for p in plugins_of(self.config, root[0])
                        if p["plugin_name"] == "request_termination")
        self.assertEqual(guards, ["/api", "/beta", "/v2"])

    def test_weighted_canary_shares_one_upstream(self):
        v2 = one_proxy(self, self.config, "/v2", "app.example.com")
        beta = one_proxy(self, self.config, "/beta", "app.example.com")
        self.assertEqual(v2["upstream_id"], beta["upstream_id"])
        upstream = upstream_of(self.config, v2)
        self.assertEqual(upstream["algorithm"], "weighted_round_robin")
        self.assertEqual([t["weight"] for t in upstream["targets"]], [1000, 111])

    def test_header_matcher_and_internal_service_refused(self):
        admin = one_proxy(self, self.config, "/admin", "app.example.com")
        self.assertEqual(admin["labels"]["ferrum-migration/status"], "refused")
        dashboard = proxies(self.config, host="traefik.example.com")
        self.assertEqual(len(dashboard), 1)
        self.assertEqual(dashboard[0]["labels"]["ferrum-migration/status"], "refused")


class TraefikSemanticsTest(unittest.TestCase):
    def test_toml_v2_hosts_and_ip_allow_list(self):
        result, report, _ = migrate("traefik", read_fixture("traefik", "dynamic.toml"), fmt="toml")
        proxy = one_proxy(self, result.config, "/api")
        self.assertEqual(proxy["hosts"], ["a.example.com", "b.example.com"])
        self.assertFalse(proxy["strip_listen_path"])
        self.assertEqual(plugin(self, result.config, proxy, "ip_restriction")["config"],
                         {"allow": ["192.0.2.0/24", "2001:db8::/32"]})
        self.assertFalse(report.has_errors)

    def _doc(self, routers, middlewares=None):
        return yaml.safe_dump({"http": {
            "routers": routers,
            "middlewares": middlewares or {},
            "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}},
        }})

    def test_higher_priority_catch_all_shadows_specific_router(self):
        result, report, _ = migrate("traefik", self._doc({
            "catchall": {"rule": "PathPrefix(`/`)", "priority": 1000, "service": "s"},
            "api": {"rule": "PathPrefix(`/api`)", "service": "s"},
        }))
        self.assertEqual(proxies(result.config, "/api"), [])
        self.assertIn("route-shadowed", codes(report, "warning"))

    def test_equal_priority_overlap_is_refused(self):
        result, _report, _ = migrate("traefik", self._doc({
            "a": {"rule": "PathPrefix(`/a`)", "priority": 10, "service": "s"},
            "b": {"rule": "PathPrefix(`/a/b`)", "priority": 10, "service": "s"},
        }))
        for proxy in result.config["proxies"]:
            self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")

    def test_forward_auth_is_refused(self):
        result, _report, _ = migrate("traefik", self._doc(
            {"r": {"rule": "PathPrefix(`/p`)", "service": "s", "middlewares": ["auth"]}},
            {"auth": {"forwardAuth": {"address": "http://auth.internal/check"}}}))
        self.assertEqual(one_proxy(self, result.config, "/p")["labels"]["ferrum-migration/status"], "refused")

    def test_basic_auth_users_never_echoed(self):
        fake_hash = "test:$apr1$fakefake$0123456789abcdefghijkl"
        result, report, _ = migrate("traefik", self._doc(
            {"r": {"rule": "PathPrefix(`/b`)", "service": "s", "middlewares": ["ba"]}},
            {"ba": {"basicAuth": {"users": [fake_hash], "removeHeader": True}}}))
        proxy = one_proxy(self, result.config, "/b")
        self.assertEqual(plugin(self, result.config, proxy, "basic_auth")["config"], {"hide_credentials": True})
        self.assertNotIn("fakefake", json.dumps(result.config))
        self.assertNotIn("fakefake", json.dumps([c.to_dict() for c in report.caveats]))

    def test_ip_strategy_refused(self):
        result, _report, _ = migrate("traefik", self._doc(
            {"r": {"rule": "PathPrefix(`/i`)", "service": "s", "middlewares": ["ip"]}},
            {"ip": {"ipAllowList": {"sourceRange": ["10.0.0.0/8"], "ipStrategy": {"depth": 1}}}}))
        self.assertEqual(one_proxy(self, result.config, "/i")["labels"]["ferrum-migration/status"], "refused")

    def test_conditional_strip_prefix_refused(self):
        result, _report, _ = migrate("traefik", self._doc(
            {"r": {"rule": "PathPrefix(`/api`)", "service": "s", "middlewares": ["strip"]}},
            {"strip": {"stripPrefix": {"prefixes": ["/api/v1"]}}}))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "refused")

    def test_strip_prefix_shorter_than_route_uses_backend_path(self):
        result, _report, _ = migrate("traefik", self._doc(
            {"r": {"rule": "PathPrefix(`/api/v1`)", "service": "s", "middlewares": ["strip"]}},
            {"strip": {"stripPrefix": {"prefixes": ["/api"]}}}))
        proxy = one_proxy(self, result.config, "/api/v1")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertEqual(proxy["backend_path"], "/v1")


if __name__ == "__main__":
    unittest.main()
