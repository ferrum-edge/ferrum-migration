import unittest

import yaml

from helpers import assert_structurally_valid, codes, plugins_of

from ferrum_migration import matching, util
from ferrum_migration.ferrum import EmitOptions, emit
from ferrum_migration.model import BackendRef, ConsumerSpec, HostScope, Plan, PluginSpec, RouteSpec, TlsSpec
from ferrum_migration.report import Report
from ferrum_migration.sources.common import apply_first_match_order


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

    def test_proxy_names_are_unique_readable_and_stable(self):
        # Ferrum admits neither duplicate proxy ids nor duplicate names. Names repeat after truncation, differ only
        # in case, or exceed the byte limit with multi-byte characters; each must still be unique and readable.
        same = BackendRef(scheme="http", host="names.internal", port=80)
        raw = ["x" * 300 + "a", "x" * 300 + "b", "Api", "api", "é" * 200, "é" * 200]

        def build():
            result, _ = run([route(name, f"/r{index}", backend=BackendRef(scheme="http", host=same.host, port=same.port))
                             for index, name in enumerate(raw)])
            return result

        result = build()
        assert_structurally_valid(self, result.config)
        names = [p["name"] for p in result.config["proxies"]]
        self.assertEqual(len(names), len(raw))
        self.assertEqual(names[2:4], ["Api", "api-2"])
        self.assertTrue(names[1].endswith("-2") and names[5].endswith("-2"))
        self.assertTrue(all(len(name.encode("utf-8")) <= util.MAX_NAME_LENGTH for name in names))
        self.assertEqual(names, [p["name"] for p in build().config["proxies"]])

    def test_extra_listener_routes_are_never_emitted(self):
        # A listen_port route cannot be isolated from port-agnostic main routes in Ferrum's router, so neither a live
        # route nor a placeholder is emitted for an extra listener; the main route is unchanged.
        result, report = run([route("main", "/"), route("ops", "/ops", listen_port=8081),
                              route("ops-refused", "/ops-admin", listen_port=8081, refusals=["synthetic"])])
        assert_structurally_valid(self, result.config)
        self.assertEqual([(p.get("listen_path"), p["labels"]["ferrum-migration/status"])
                          for p in result.config["proxies"]], [("/", "migrated")])
        self.assertEqual(sum(1 for c in report.caveats if c.code == "extra-listener-refused"), 2)
        self.assertEqual(result.stats["skipped_source_routes"], 2)

    def test_timeouts_are_clamped(self):
        result, report = run([route("t", "/t", read_timeout_ms=util.MAX_TIMEOUT_MS * 2)])
        self.assertEqual(result.config["proxies"][0]["backend_read_timeout_ms"], util.MAX_TIMEOUT_MS)
        self.assertIn("timeout-clamped", codes(report, "warning"))

    def test_projected_timeouts_are_labelled_approximate(self):
        _result, report = run([route("t", "/t", read_timeout_ms=60_000)])
        self.assertIn("timeout-approximate", codes(report, "warning"))
        _result, report = run([route("n", "/n")])
        self.assertNotIn("timeout-approximate", codes(report))

    def test_refused_string_prefix_siblings_cannot_reach_broader_route(self):
        # The source sent /adminx to the refused string-prefix route /admin; Ferrum's segment prefix would hand it
        # to the broader live "/" route, skipping the refused policy. A guard must close that path.
        def guards(result):
            root = next(p for p in result.config["proxies"] if p["listen_path"] == "/")
            return [p["config"]["trigger"]["path_prefix"] for p in plugins_of(result.config, root)
                    if p["plugin_name"] == "request_termination"]

        result, report = run([route("admin", "/admin", refusals=["synthetic untranslatable policy"]), route("root", "/")])
        self.assertEqual(guards(result), ["/admin"])
        self.assertNotIn("prefix-divergence-refused", codes(report))
        # The refused route covers fewer hosts than the broader route: still guarded (fail closed), reported.
        result, report = run([route("admin", "/admin", hosts=["a.example.test"], refusals=["synthetic"]),
                              route("root", "/", hosts=["a.example.test", "b.example.test"])])
        self.assertEqual(guards(result), ["/admin"])
        self.assertIn("prefix-divergence-refused", codes(report, "error"))

    def test_covering_wildcard_closure_does_not_close_narrower_wildcard_scope(self):
        # Ferrum tries every matching wildcard pattern's path routes before any wildcard host-only route, so the
        # *.example.test closure does not keep *.a.example.test's unmatched paths away from other scopes' routes.
        plan = Plan(platform="test", routes=[route("w", "/w", hosts=["*.example.test"]),
                                             route("n", "/n", hosts=["*.a.example.test"])])
        plan.host_scopes = [HostScope("scope wide", ["*.example.test"]), HostScope("scope narrow", ["*.a.example.test"])]
        report = Report("test", "synthetic")
        result = emit(plan, EmitOptions(), report)
        assert_structurally_valid(self, result.config)
        by_path = {p.get("listen_path"): p for p in result.config["proxies"]}
        self.assertEqual(sorted(by_path, key=str), ["/n", "/w", None, "~/.*"])

        def status(path):
            return by_path[path]["labels"]["ferrum-migration/status"]

        def termination(path):
            return [p["config"]["status_code"] for p in plugins_of(result.config, by_path[path])
                    if p["plugin_name"] == "request_termination"]

        # The *.example.test closure is the only host-only route; it does not count as closing *.a.example.test.
        self.assertEqual(by_path[None]["hosts"], ["*.example.test"])
        # The narrower scope is closed by its own catch-any regex 404 instead (no scope left unclosed).
        self.assertEqual(by_path["~/.*"]["hosts"], ["*.a.example.test"])
        self.assertEqual((status("~/.*"), termination("~/.*")), ("scope-default", [404]))
        self.assertIn("scope-closure-regex", codes(report, "info"))
        self.assertNotIn("scope-closure-skipped", codes(report))
        # The broader wildcard's route could still answer narrower-scope hosts in Ferrum's wildcard tier, so it is
        # a fail-closed placeholder rather than live.
        self.assertEqual((status("/w"), termination("/w")), ("refused", [503]))
        self.assertIn("nested-wildcard-scope", codes(report, "error"))
        self.assertIn("route-refused", codes(report, "error"))
        # The only forwarding proxy that matches narrower-scope hosts is that scope's own route.
        live = [p for p in result.config["proxies"] if p["labels"]["ferrum-migration/status"] == "migrated"]
        self.assertEqual([(p["listen_path"], p["hosts"]) for p in live], [("/n", ["*.a.example.test"])])

    def test_one_consumer_never_receives_several_jwt_secrets(self):
        consumer = ConsumerSpec(ref="test consumer", key="c", username="c",
                                jwt=["synthetic-jwt-secret-one-0000000000000001",
                                     "synthetic-jwt-secret-two-0000000000000002"])
        plan = Plan(platform="test", routes=[route("r", "/r")], consumers=[consumer])
        report = Report("test", "synthetic")
        result = emit(plan, EmitOptions(include_secrets=True), report)
        self.assertNotIn("credentials", result.config["consumers"][0])
        self.assertEqual(result.secrets_emitted, 0)
        self.assertIn("jwt-multiple-secrets", codes(report, "error"))


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

    def test_segment_prefix_shadows_only_segment_descendants(self):
        # A segment prefix /api (Envoy path_separated_prefix) never matches /apix, so a later /apix route is
        # reachable in the source and must not be dropped as shadowed; /api/v1 really is shadowed.
        seg = RouteSpec(ref="seg", name="seg", kind="prefix", path="/api", prefix_semantics="segment")
        sibling = RouteSpec(ref="sibling", name="sibling", kind="prefix", path="/apix")
        nested = RouteSpec(ref="nested", name="nested", kind="prefix", path="/api/v1")
        exact = RouteSpec(ref="exact", name="exact", kind="exact", path="/api")
        apply_first_match_order([seg, sibling, nested, exact], Report("test", "synthetic"))
        self.assertFalse(sibling.skip)
        self.assertTrue(nested.skip)
        self.assertTrue(exact.skip)
        self.assertFalse(matching.route_covers(seg, sibling))
        string = RouteSpec(ref="string", name="string", kind="prefix", path="/api")
        self.assertTrue(matching.route_covers(string, sibling))

    def test_case_insensitive_matching_is_folded_and_variants_detected(self):
        ci = RouteSpec(ref="ci", name="ci", kind="prefix", path="/admin", case_insensitive=True)

        def other(kind, path, **kwargs):
            return RouteSpec(ref=f"other {path}", name="other", kind=kind, path=path, **kwargs)

        # Routes that would match a case variant (/ADMIN...) of the case-insensitive route's path.
        for kind, path in (("prefix", "/"), ("exact", "/ADMIN"), ("prefix", "/Adm"), ("regex", "(?i)/admin")):
            self.assertTrue(matching.receives_case_variants(ci, other(kind, path)), path)
        # Routes that only match its exact-case paths, or unrelated paths, receive no variants.
        for kind, path in (("prefix", "/admin/v1"), ("exact", "/status"), ("prefix", "/other")):
            self.assertFalse(matching.receives_case_variants(ci, other(kind, path)), path)
        letterless = RouteSpec(ref="n", name="n", kind="prefix", path="/1/2", case_insensitive=True)
        self.assertFalse(matching.receives_case_variants(letterless, other("prefix", "/")))
        # The segment/exact disjointness proof is not applied across case semantics; it still holds without.
        seg_ci = RouteSpec(ref="s", name="s", kind="prefix", path="/api", prefix_semantics="segment",
                           case_insensitive=True)
        self.assertTrue(matching.route_overlaps(seg_ci, other("exact", "/API")))
        seg = RouteSpec(ref="s2", name="s2", kind="prefix", path="/api", prefix_semantics="segment")
        self.assertFalse(matching.route_overlaps(seg, other("exact", "/apix")))
        # A case-sensitive route covers a case-insensitive one only when its own literal has no letters.
        self.assertFalse(matching.route_covers(other("prefix", "/admin"), RouteSpec(
            ref="i", name="i", kind="prefix", path="/admin/x", case_insensitive=True)))
        self.assertTrue(matching.route_covers(other("prefix", "/"), ci))

    def test_url_userinfo_refused(self):
        with self.assertRaises(util.UrlProblem):
            util.split_url("http://user:pass@host:80/", {"http": 80})


if __name__ == "__main__":
    unittest.main()
