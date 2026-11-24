import unittest

import yaml

from helpers import assert_structurally_valid, codes, plugins_of

from ferrum_migration import matching, util
from ferrum_migration.ferrum import EmitOptions, emit
from ferrum_migration.model import BackendRef, Plan, PluginSpec, RouteSpec, TlsSpec
from ferrum_migration.report import Report


def route(name, path="/", kind="prefix", hosts=None, **kwargs):
    spec = RouteSpec(ref=f"test route {name}", name=name, hosts=list(hosts or []), kind=kind, path=path)
    spec.backend = kwargs.pop("backend", BackendRef(scheme="http", host=f"{name}.internal", port=8080))
    for key, value in kwargs.items():
        setattr(spec, key, value)
    return spec


def run(routes, **options):
    plan = Plan(platform="test", routes=routes)
    report = Report("test", "synthetic")
    result = emit(plan, EmitOptions(**options), report)
    return result, report


class EmitterTest(unittest.TestCase):
    def test_conflicting_routes_become_one_placeholder(self):
        result, report = run([route("a", "/x", hosts=["a.example.com"]),
                              route("b", "/x", hosts=["a.example.com", "b.example.com"])])
        assert_structurally_valid(self, result.config)
        self.assertEqual(len(result.config["proxies"]), 1)
        proxy = result.config["proxies"][0]
        self.assertEqual(proxy["hosts"], ["a.example.com", "b.example.com"])
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(sum(1 for c in report.caveats if c.code == "route-refused"), 2)

    def test_disjoint_hosts_do_not_conflict(self):
        result, _ = run([route("a", "/x", hosts=["a.example.com"]), route("b", "/x", hosts=["b.example.com"])])
        self.assertEqual({p["labels"]["ferrum-migration/status"] for p in result.config["proxies"]}, {"migrated"})

    def test_unrepresentable_host_poisons_catch_all_overlap(self):
        bad = route("bad", "/x", hosts=["www.example.*"])
        catch_all = route("all", "/")
        result, _ = run([bad, catch_all])
        self.assertEqual(len(result.config["proxies"]), 1)
        self.assertEqual(result.config["proxies"][0]["labels"]["ferrum-migration/status"], "refused")

    def test_invalid_path_is_refused_not_emitted(self):
        result, report = run([route("enc", "/a%2Fb"), route("other", "/other")])
        self.assertEqual([p["listen_path"] for p in result.config["proxies"]], ["/other"])
        self.assertIn("route-refused", codes(report, "error"))

    def test_tls_only_decision(self):
        secure = route("s", "/s", requires_tls=True)
        plain = route("p", "/p")
        result, _ = run([secure, plain])
        statuses = {p["listen_path"]: p["labels"]["ferrum-migration/status"] for p in result.config["proxies"]}
        self.assertEqual(statuses, {"/s": "refused", "/p": "migrated"})
        result, _ = run([route("s", "/s", requires_tls=True), route("p", "/p")], tls_only=True)
        self.assertEqual({p["labels"]["ferrum-migration/status"] for p in result.config["proxies"]}, {"migrated"})

    def test_backend_tls_verification_policy(self):
        tls = TlsSpec(verify=False)
        result, report = run([route("t", "/t", backend=BackendRef(scheme="https", host="t.internal", port=443, tls=tls))])
        self.assertTrue(result.config["proxies"][0]["backend_tls_verify_server_cert"])
        self.assertIn("backend-tls-verify-enabled", codes(report, "warning"))

    def test_guard_added_only_when_policies_differ(self):
        auth = PluginSpec("key_auth", {"key_location": "header:x-api-key"})
        result, _ = run([route("api", "/api", plugins=[auth]), route("root", "/", plugins=[])])
        root = next(p for p in result.config["proxies"] if p["listen_path"] == "/")
        self.assertEqual([p["config"]["trigger"]["path_prefix"] for p in plugins_of(result.config, root)
                          if p["plugin_name"] == "request_termination"], ["/api"])
        same = BackendRef(scheme="http", host="same.internal", port=80)
        result, _ = run([route("api", "/api", backend=same), route("root", "/", backend=BackendRef(
            scheme="http", host="same.internal", port=80))])
        root = next(p for p in result.config["proxies"] if p["listen_path"] == "/")
        self.assertEqual(plugins_of(result.config, root), [])

    def test_segment_semantics_need_no_guard(self):
        auth = PluginSpec("key_auth", {})
        result, _ = run([route("api", "/api", plugins=[auth], prefix_semantics="segment"), route("root", "/")])
        root = next(p for p in result.config["proxies"] if p["listen_path"] == "/")
        self.assertEqual(plugins_of(result.config, root), [])

    def test_output_is_deterministic(self):
        def build():
            result, _ = run([route("a", "/a", hosts=["x.example.com"]), route("b", "/b/"),
                             route("c", "/c/[0-9]+", kind="regex")])
            return yaml.safe_dump(result.config, sort_keys=False)
        self.assertEqual(build(), build())

    def test_ids_are_valid_and_unique_for_odd_names(self):
        routes = [route("Ünïcode name!!", f"/r{i}") for i in range(3)] + [route("x" * 400, "/long")]
        result, _ = run(routes)
        assert_structurally_valid(self, result.config)

    def test_timeouts_are_clamped(self):
        result, report = run([route("t", "/t", read_timeout_ms=util.MAX_TIMEOUT_MS * 2)])
        self.assertEqual(result.config["proxies"][0]["backend_read_timeout_ms"], util.MAX_TIMEOUT_MS)
        self.assertIn("timeout-clamped", codes(report, "warning"))

    def test_projected_timeouts_are_labelled_approximate(self):
        _result, report = run([route("t", "/t", read_timeout_ms=60_000)])
        self.assertIn("timeout-approximate", codes(report, "warning"))
        _result, report = run([route("n", "/n")])
        self.assertNotIn("timeout-approximate", codes(report))


class MatchingTest(unittest.TestCase):
    def test_host_semantics(self):
        self.assertTrue(matching.host_cover("*.example.com", "a.b.example.com"))
        self.assertFalse(matching.host_cover("*.example.com", "example.com"))
        self.assertTrue(matching.hosts_overlap([], ["a.example.com"]))
        self.assertFalse(matching.hosts_overlap(None, ["a.example.com"]))
        self.assertTrue(matching.hosts_overlap(None, []))

    def test_paths(self):
        self.assertIsNone(util.canonical_path_problem("/api/v1"))
        for bad in ("api", "/a//b", "/a/../b", "/a%20b", "/a;b", "/a b", "/é"):
            self.assertIsNotNone(util.canonical_path_problem(bad), bad)
        self.assertEqual(util.regex_literal_prefix("/users/[0-9]+"), "/users/")
        self.assertEqual(util.regex_literal_prefix("/files?/x"), "/file")
        self.assertIsNotNone(util.regex_problem("/(?=x)y"))
        self.assertIsNone(util.regex_problem("/users/(?P<id>[0-9]+)"))

    def test_durations_and_sizes(self):
        self.assertEqual(util.parse_go_duration_ms("1m30s"), 90_000)
        self.assertEqual(util.parse_nginx_time_ms("60s"), 60_000)
        self.assertEqual(util.parse_nginx_time_ms("5"), 5_000)
        self.assertEqual(util.parse_nginx_size("10m"), 10 * 1024 * 1024)
        self.assertEqual(util.proto_duration_ms("0.25s"), 250)
        self.assertEqual(util.canonical_cidr("10.1.2.3/8"), "10.0.0.0/8")

    def test_url_userinfo_refused(self):
        with self.assertRaises(util.UrlProblem):
            util.split_url("http://user:pass@host:80/", {"http": 80})


if __name__ == "__main__":
    unittest.main()
