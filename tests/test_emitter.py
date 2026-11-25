import unittest

import yaml

from helpers import assert_structurally_valid, codes, plugins_of

from ferrum_migration import matching, util
from ferrum_migration.ferrum import EmitOptions, emit
from ferrum_migration.model import BackendRef, ConsumerSpec, HostScope, Plan, PluginSpec, RouteSpec, TlsSpec
from ferrum_migration.report import Report
from ferrum_migration.sources.common import apply_first_match_order

#: Source frontend metadata (RouteSpec.protocols) as adapters record it. Hand-built routes default to a source that
#: served them on both main listeners (a Kong route with default protocols, an NGINX server listening on 80 and
#: 443 ssl). Unknown metadata (None) refuses the whole plan; see test_frontend_protocols.FrontendAccountingTest.
BOTH = frozenset({"http", "https"})
PLAINTEXT = frozenset({"http"})
HTTPS = frozenset({"https"})


def route(name, path="/", kind="prefix", hosts=None, **kwargs):
    spec = RouteSpec(ref=f"test route {name}", name=name, hosts=list(hosts or []), kind=kind, path=path)
    spec.backend = kwargs.pop("backend", BackendRef(scheme="http", host=f"{name}.internal", port=8080))
    kwargs.setdefault("protocols", BOTH)
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
        def statuses(result):
            return {p["listen_path"]: p["labels"]["ferrum-migration/status"] for p in result.config["proxies"]}

        # An HTTPS-only route next to a route served on both listeners: by default the plaintext listener stays, the
        # HTTPS-only route is refused and HTTPS stays open (every live route was also served over HTTPS).
        result, report = run([route("s", "/s", requires_tls=True, protocols=HTTPS), route("p", "/p")])
        self.assertEqual(statuses(result), {"/s": "refused", "/p": "migrated"})
        self.assertEqual(result.frontend_protocols, "both")
        self.assertNotIn("frontend-https-disabled", codes(report))
        # --tls-only: both routes were served over HTTPS, so both are live on the HTTPS listener alone.
        result, report = run([route("s", "/s", requires_tls=True, protocols=HTTPS), route("p", "/p")], tls_only=True)
        self.assertEqual(set(statuses(result).values()), {"migrated"})
        self.assertEqual(result.frontend_protocols, "https")
        self.assertNotIn("frontend-protocol-scope", codes(report))

        # A route the source served over plaintext only. Default: it stays live and HTTPS is disabled, so it is never
        # served over HTTPS. --tls-only: it is refused instead of being exposed on the HTTPS listener.
        def mixed():
            return [route("s", "/s", requires_tls=True, protocols=HTTPS), route("p", "/p", protocols=PLAINTEXT)]

        result, report = run(mixed())
        self.assertEqual(statuses(result), {"/s": "refused", "/p": "migrated"})
        self.assertEqual(result.frontend_protocols, "http")
        self.assertIn("frontend-https-disabled", codes(report, "error"))
        result, report = run(mixed(), tls_only=True)
        self.assertEqual(statuses(result), {"/s": "migrated", "/p": "refused"})
        self.assertEqual(result.frontend_protocols, "https")
        self.assertIn("frontend-protocol-scope", codes(report, "error"))

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
        self.assertIsNotNone(util.regex_problem(r"\057api"))
        self.assertIsNotNone(util.regex_problem(r"^/api(?xx:[ab])$"))
        self.assertIsNotNone(util.regex_problem(r"^/api{foo$"))
        self.assertIsNone(util.regex_problem(r"^/api[\\0]$"))
        self.assertIsNone(util.regex_problem(r"(?x)^/api$ # (?xx:[ab])"))
        self.assertIsNone(util.regex_problem("/users/(?P<id>[0-9]+)"))
        self.assertIsNone(util.normalize_host("api.-team.example.test"))
        self.assertIsNone(util.normalize_host("a" * 64 + ".example.test"))
        self.assertEqual(util.normalize_host("Api.Example.Test."), "api.example.test")

    def test_durations_and_sizes(self):
        self.assertEqual(util.parse_go_duration_ms("1m30s"), 90_000)
        self.assertEqual(util.parse_go_duration_ns("9223372036854775807.1ns"), 9_223_372_036_854_775_807)
        self.assertEqual(util.parse_go_duration_ns("-0.1ns"), 0)
        self.assertEqual(util.parse_go_duration_ns(-1e-10), 0)
        self.assertIsNone(util.parse_go_duration_ns("-1ns"))
        self.assertIsNone(util.parse_go_duration_ns(-1e-9))
        self.assertEqual(util.parse_nginx_time_ms("60s"), 60_000)
        self.assertEqual(util.parse_nginx_time_ms("5"), 5_000)
        self.assertEqual(util.parse_nginx_time_ms("1m 500ms"), 60_500)
        self.assertEqual(util.parse_nginx_time_ms("1s2"), 3_000)
        self.assertIsNone(util.parse_nginx_time_ms("1m\t500ms"))
        self.assertIsNone(util.parse_nginx_time_ms("500ms 1m"))
        self.assertIsNone(util.parse_nginx_time_ms("1y", allow_ms=True))
        self.assertEqual(util.parse_nginx_time_ms("1y", allow_ms=False), 31_536_000_000)
        self.assertIsNone(util.parse_nginx_time_ms("500ms", allow_ms=False))
        self.assertIsNone(util.parse_nginx_time_ms("1m" + " " * 20_000 + "x"))
        self.assertEqual(util.parse_nginx_size("10m"), 10 * 1024 * 1024)
        self.assertEqual(util.proto_duration_ms("0.25s"), 250)
        self.assertEqual(util.proto_duration_ms("0.0009s"), 0)
        self.assertEqual(util.proto_duration_ms({"seconds": 0, "nanos": 900_000}), 0)
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

    def test_top_level_alternation_has_no_literal_prefix_proof(self):
        # The first branch's literal says nothing about the other branches: the proof is unknown ("").
        for pattern in ("/other|/ADMIN/.*", "^/a|^/b", "/a/(x)|/b"):
            self.assertEqual(util.regex_literal_prefix(pattern), "", pattern)
        # Alternation inside a group keeps the literal every match starts with (the narrow grammar proves it).
        self.assertEqual(util.regex_literal_prefix("/api/(v1|v2)/x"), "/api/")
        # A pipe next to a character class is outside that grammar (Rust nests classes and has set operators), so
        # nothing is proven about it: unknown (""), fail closed. Without a pipe, a class still ends the literal only.
        self.assertEqual(util.regex_literal_prefix("/a[|]b"), "")
        self.assertTrue(util.regex_alternation_unproven("/a[|]b"))
        self.assertEqual(util.regex_literal_prefix("/a[0-9]b"), "/a")
        ci = RouteSpec(ref="ci", name="ci", kind="prefix", path="/admin", case_insensitive=True)
        alternation = RouteSpec(ref="alt", name="alt", kind="regex", path="/other|/ADMIN/.*")
        self.assertTrue(matching.receives_case_variants(ci, alternation))
        self.assertTrue(matching.route_overlaps(ci, alternation))
        grouped = RouteSpec(ref="grp", name="grp", kind="regex", path="/other/(a|B)")
        self.assertFalse(matching.receives_case_variants(ci, grouped))

    def test_url_userinfo_refused(self):
        with self.assertRaises(util.UrlProblem):
            util.split_url("http://user:pass@host:80/", {"http": 80})

    def test_mixed_exact_and_wildcard_hosts_per_tier_preference_and_poisoning(self):
        exact = RouteSpec(ref="exact", name="exact", hosts=["example.com"], kind="prefix", path="/api",
                          protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
        mixed_longer = RouteSpec(ref="mixed", name="mixed", hosts=["example.com", "*.example.com"], kind="prefix",
                                 path="/api/admin", protocols=frozenset({"http"}),
                                 backend=BackendRef("http", "b.internal", 80))
        # On example.com both sit in tier 0 so /api/admin wins over /api; ferrum_prefers must not claim exact wins.
        self.assertIs(matching.ferrum_prefers(exact, mixed_longer), False)
        self.assertIs(matching.ferrum_prefers(mixed_longer, exact), True)
        # Across example.com (both tier 0 -> a wins on longer path) and sub.example.com (b tier 0 > a tier 1 -> b wins),
        # preference differs by host, so ferrum_prefers must report None (ambiguous).
        mixed_a = RouteSpec(ref="ma", name="ma", hosts=["example.com", "*.example.com"], kind="prefix", path="/api/v1")
        mixed_b = RouteSpec(ref="mb", name="mb", hosts=["example.com", "sub.example.com"], kind="prefix", path="/api")
        self.assertIsNone(matching.ferrum_prefers(mixed_a, mixed_b))
        # Poisoning: unrepresentable exact /api must refuse mixed /api/admin because mixed wins in tier 0 on example.com.
        exact.refuse("header match")
        exact.extra_conditions = True
        plan = Plan(platform="test", routes=[exact, mixed_longer])
        result = emit(plan, EmitOptions(), Report("test", "synthetic"))
        self.assertTrue(mixed_longer.refusals)
        self.assertFalse([p for p in result.config["proxies"] if p["labels"].get("ferrum-migration/status") == "migrated"])

    def test_mixed_hosts_case_variant_poisoning_and_divergence_guards(self):
        from ferrum_migration.model import HostScope
        # Case-insensitive exact /api on closed example.com must still refuse mixed ["example.com", "*.example.com"] "/"
        # because the mixed route sits in exact_hosts["example.com"] (tier 0) before the host-only closure.
        ci = RouteSpec(ref="ci", name="ci", hosts=["example.com"], kind="prefix", path="/api",
                       case_insensitive=True, protocols=frozenset({"http"}),
                       backend=BackendRef("http", "a.internal", 80))
        mixed_root = RouteSpec(ref="mr", name="mr", hosts=["example.com", "*.example.com"], kind="prefix", path="/",
                               protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        plan = Plan(platform="test", routes=[ci, mixed_root], host_scopes=[HostScope("s", ["example.com"])])
        emit(plan, EmitOptions(), Report("test", "synthetic"))
        self.assertTrue(mixed_root.refusals)
        # String-prefix divergence: closed exact /api must still guard/report mixed ["example.com", "*.example.com"] "/".
        api = RouteSpec(ref="api", name="api", hosts=["example.com"], kind="prefix", path="/api",
                        prefix_semantics="string", protocols=frozenset({"http"}),
                        backend=BackendRef("http", "a.internal", 80))
        mixed_broad = RouteSpec(ref="mb", name="mb", hosts=["example.com", "*.example.com"], kind="prefix", path="/",
                                protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        report = Report("test", "synthetic")
        emit(Plan(platform="test", routes=[api, mixed_broad], host_scopes=[HostScope("s", ["example.com"])]),
             EmitOptions(), report)
        self.assertIn("prefix-divergence", {c.code for c in report.caveats})
        # Mixed string-prefix /api must guard exact regex /api.* on example.com (both share tier 0 on example.com).
        mixed_api = RouteSpec(ref="mapi", name="mapi", hosts=["example.com", "*.example.com"], kind="prefix",
                              path="/api", prefix_semantics="string", protocols=frozenset({"http"}),
                              backend=BackendRef("http", "a.internal", 80))
        exact_rx = RouteSpec(ref="rx", name="rx", hosts=["example.com"], kind="regex", path="/api.*",
                             protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        report2 = Report("test", "synthetic")
        result2 = emit(Plan(platform="test", routes=[mixed_api, exact_rx]), EmitOptions(), report2)
        self.assertGreaterEqual(result2.stats["prefix_guards"], 1)

    def test_over_100_hosts_route_chunks_cleanly_and_unchunkable_poisons(self):
        from ferrum_migration.model import HostScope

        # Chunkable 105 exact hosts with a HostScope: refused placeholders and scope closures stay <= 100 hosts each,
        # without poisoning an unrelated catch-all or a more-specific route.
        many = [f"h{i}.example.test" for i in range(105)]
        bad = RouteSpec(ref="many", name="many", hosts=many, kind="prefix", path="/api",
                        protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
        sub = RouteSpec(ref="one", name="one", hosts=["h0.example.test"], kind="prefix", path="/api/sub",
                        protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        catch_all = RouteSpec(ref="root", name="root", hosts=[], kind="prefix", path="/",
                              protocols=frozenset({"http"}), backend=BackendRef("http", "c.internal", 80))
        plan = Plan(platform="test", routes=[bad, sub, catch_all], host_scopes=[HostScope("many-scope", many, None)])
        result = emit(plan, EmitOptions(), Report("test", "synthetic"))
        self.assertTrue(bad.refusals)
        self.assertFalse(sub.refusals)
        self.assertFalse(catch_all.refusals)
        for proxy in result.config["proxies"]:
            self.assertLessEqual(len(proxy.get("hosts", [])), util.MAX_HOSTS_PER_PROXY)

        # Unchunkable single ambiguous wildcard component (>100 mutually overlapping wildcards): poisons overlapping route
        # instead of emitting an invalid >100-host proxy.
        nested = ["*.example.test"] + [f"*.s{i}.example.test" for i in range(101)]
        bad_nested = RouteSpec(ref="nested", name="nested", hosts=nested, kind="prefix", path="/api",
                               protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
        overlap = RouteSpec(ref="ov", name="ov", hosts=["a.s0.example.test"], kind="prefix", path="/api/sub",
                            protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        result2 = emit(Plan(platform="test", routes=[bad_nested, overlap]), EmitOptions(), Report("test", "synthetic"))
        self.assertTrue(bad_nested.refusals)
        self.assertTrue(overlap.refusals)
        for proxy in result2.config["proxies"]:
            self.assertLessEqual(len(proxy.get("hosts", [])), util.MAX_HOSTS_PER_PROXY)

    def test_identical_mixed_hosts_and_wildcard_suffix_precedence(self):
        # Identical mixed exact + wildcard hosts: witness-based tiers must not produce impossible (0, 1)/(1, 0) pairs.
        mixed = ["api.example.com", "*.example.com"]
        self.assertEqual(matching.overlapping_tier_pairs(mixed, mixed), {(0, 0), (1, 1)})
        exact_api = RouteSpec(ref="a", name="a", hosts=mixed, kind="exact", path="/api")
        root = RouteSpec(ref="b", name="b", hosts=mixed, kind="prefix", path="/")
        self.assertIs(matching.ferrum_prefers(exact_api, root), True)
        # Within wildcard prefix class, longer wildcard suffix wins over longer path prefix (router_cache.rs:2146).
        broad_long = RouteSpec(ref="bl", name="bl", hosts=["*.example.test"], kind="prefix", path="/api/private")
        narrow_short = RouteSpec(ref="ns", name="ns", hosts=["*.sub.example.test"], kind="prefix", path="/api")
        self.assertIs(matching.ferrum_prefers(broad_long, narrow_short), False)
        self.assertIs(matching.ferrum_prefers(narrow_short, broad_long), True)

    def test_wildcard_conflict_chunking_preserves_narrower_wildcard_without_pruning(self):
        # Opus P1-3: merging conflicting wildcards (>100 total hosts) must NOT drop *.a.example.test, because a live
        # route on *.a.example.test / would otherwise beat a *.example.test /api placeholder in Ferrum.
        hosts_1 = ["*.example.test"] + [f"a{i}.other.test" for i in range(60)]
        hosts_2 = ["*.a.example.test"] + [f"b{i}.other.test" for i in range(60)]
        r1 = RouteSpec(ref="r1", name="r1", hosts=hosts_1, kind="prefix", path="/api",
                       protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
        r2 = RouteSpec(ref="r2", name="r2", hosts=hosts_2, kind="prefix", path="/api",
                       protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        live = RouteSpec(ref="live", name="live", hosts=hosts_2, kind="prefix", path="/",
                         protocols=frozenset({"http"}), backend=BackendRef("http", "c.internal", 80))
        result = emit(Plan(platform="test", routes=[r1, r2, live]), EmitOptions(), Report("test", "synthetic"))
        refused_api = [p for p in result.config["proxies"]
                       if p.get("listen_path") == "/api" and p["labels"].get("ferrum-migration/status") == "refused"]
        all_refused_hosts = [h for p in refused_api for h in p.get("hosts", [])]
        self.assertIn("*.example.test", all_refused_hosts)
        self.assertIn("*.a.example.test", all_refused_hosts)
        # Both overlapping wildcards must stay in the same chunk so Ferrum does not reject them as ambiguous.
        same_chunk = any("*.example.test" in p.get("hosts", []) and "*.a.example.test" in p.get("hosts", [])
                         for p in refused_api)
        self.assertTrue(same_chunk)
        for proxy in result.config["proxies"]:
            self.assertLessEqual(len(proxy.get("hosts", [])), util.MAX_HOSTS_PER_PROXY)

    def test_host_only_conflict_chunking_preserves_exact_under_wildcard(self):
        hosts_1 = ["*.example.test"] + [f"a{i}.other.test" for i in range(60)]
        hosts_2 = ["api.example.test"] + [f"b{i}.other.test" for i in range(60)]
        r1 = RouteSpec(ref="r1", name="r1", hosts=hosts_1, kind="hostonly", path=None,
                       protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
        r2 = RouteSpec(ref="r2", name="r2", hosts=hosts_2, kind="hostonly", path=None,
                       protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        result = emit(Plan(platform="test", routes=[r1, r2]), EmitOptions(), Report("test", "synthetic"))
        host_only_proxies = [p for p in result.config["proxies"] if "listen_path" not in p]
        self.assertTrue(any("*.example.test" in p["hosts"] and "api.example.test" in p["hosts"]
                            for p in host_only_proxies))
        for proxy in result.config["proxies"]:
            self.assertLessEqual(len(proxy.get("hosts", [])), util.MAX_HOSTS_PER_PROXY)

    def test_string_prefix_divergence_scoped_guard_and_global_termination(self):
        # Opus P1 #2 + Sol P1 #2: a live string-prefix route (a.example.test /api with auth) next to a broader
        # catch-all / gets a host-scoped regex 404 guard on a.example.test without breaking other hosts on /.
        from ferrum_migration.model import PluginSpec
        auth_api = RouteSpec(ref="api", name="api", hosts=["a.example.test"], kind="prefix", path="/api",
                             protocols=frozenset({"http"}), backend=BackendRef("http", "api.internal", 80),
                             plugins=[PluginSpec("key_auth", {"key_location": ["header:apikey"]}, "api")],
                             report_prefix_siblings=True)
        pub_root = RouteSpec(ref="root", name="root", hosts=[], kind="prefix", path="/",
                             protocols=frozenset({"http"}), backend=BackendRef("http", "pub.internal", 80))
        report = Report("test", "synthetic")
        result = emit(Plan(platform="test", routes=[auth_api, pub_root]), EmitOptions(), report)
        self.assertGreaterEqual(result.stats["prefix_guards"], 1)
        root_proxy = [p for p in result.config["proxies"] if p.get("listen_path") == "/"][0]
        self.assertEqual(root_proxy["plugins"], [])
        guard_proxies = [p for p in result.config["proxies"]
                         if p["labels"].get("ferrum-migration/status") == "prefix-guard"]
        self.assertEqual(len(guard_proxies), 1)
        self.assertEqual(guard_proxies[0]["hosts"], ["a.example.test"])
        self.assertEqual(guard_proxies[0]["listen_path"], "~/api.*")

        # Sol P1 #2: when an unconditional global request_termination governs the plan, do NOT attach scoped
        # divergence guards (a scoped request_termination would shadow the global termination in Ferrum).
        g_api = RouteSpec(ref="api", name="api", hosts=[], kind="prefix", path="/api",
                          protocols=frozenset({"http"}), backend=BackendRef("http", "api.internal", 80),
                          plugins=[PluginSpec("key_auth", {"key_location": ["header:apikey"]}, "api")])
        g_root = RouteSpec(ref="root", name="root", hosts=[], kind="prefix", path="/",
                           protocols=frozenset({"http"}), backend=BackendRef("http", "pub.internal", 80))
        g_term = PluginSpec("request_termination", {"status_code": 403, "message": "Closed"}, "global-403")
        g_res = emit(Plan(platform="test", routes=[g_api, g_root], global_plugins=[g_term]),
                     EmitOptions(), Report("test", "synthetic"))
        g_root_proxy = [p for p in g_res.config["proxies"] if p.get("listen_path") == "/"][0]
        self.assertEqual(g_root_proxy["plugins"], [])

    def test_oversized_conflict_collapse_also_refuses_outranking_higher_tier_live_route(self):
        # Sol P1 #1 + Opus P1 #1: when two conflicting routes at =/api form a >100-host ambiguous wildcard
        # component and collapse to a catch-all 503 placeholder, overlapping higher-tier live routes for ANY
        # member of the collapsed group (regardless of order or component) must also be failed closed.
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                r_a = RouteSpec(ref="ra", name="ra",
                                hosts=["*.example.test"] + [f"*.s{i}.example.test" for i in range(60)],
                                kind="exact", path="/api", protocols=frozenset({"http"}),
                                backend=BackendRef("http", "a.internal", 80))
                r_b = RouteSpec(ref="rb", name="rb",
                                hosts=[f"*.s{i}.example.test" for i in range(60, 120)],
                                kind="exact", path="/api", protocols=frozenset({"http"}),
                                backend=BackendRef("http", "b.internal", 80))
                r_c = RouteSpec(ref="rc", name="rc", hosts=["q.example.org"],
                                kind="exact", path="/api", protocols=frozenset({"http"}),
                                backend=BackendRef("http", "c.internal", 80))
                live_wild = RouteSpec(ref="live-wild", name="live-wild", hosts=["*.s0.example.test"],
                                      kind="prefix", path="/", protocols=frozenset({"http"}),
                                      backend=BackendRef("http", "pub1.internal", 80))
                live_exact = RouteSpec(ref="live-exact", name="live-exact", hosts=["q.example.org"],
                                       kind="prefix", path="/", protocols=frozenset({"http"}),
                                       backend=BackendRef("http", "pub2.internal", 80))
                routes = [r_b, r_a, r_c, live_wild, live_exact] if reverse else [r_a, r_b, r_c, live_wild, live_exact]
                report = Report("test", "synthetic")
                result = emit(Plan(platform="test", routes=routes), EmitOptions(), report)
                self.assertTrue(live_wild.refusals)
                self.assertTrue(live_exact.refusals)
                self.assertIn("conflict-collapse", {c.code for c in report.caveats})
                for proxy in result.config["proxies"]:
                    self.assertLessEqual(len(proxy.get("hosts", [])), util.MAX_HOSTS_PER_PROXY)

    def test_500_byte_prefix_guard_falls_back_and_cors_rejects_padded_origin(self):
        from ferrum_migration.sources.common import cors_config

        long_prefix = "/" + "a" * 499  # 500 bytes: ~/aaa...* would be 503 bytes > 500
        long_route = RouteSpec(ref="long", name="long", hosts=["a.example.test"], kind="prefix", path=long_prefix,
                               protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80),
                               report_prefix_siblings=True)
        root = RouteSpec(ref="root", name="root", hosts=[], kind="prefix", path="/",
                         protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        res = emit(Plan(platform="test", routes=[long_route, root]), EmitOptions(), Report("test", "synthetic"))
        for proxy in res.config["proxies"]:
            lp = proxy.get("listen_path")
            if lp is not None:
                self.assertLessEqual(len(lp.encode("utf-8")), util.MAX_LISTEN_PATH_LENGTH)
        built, problem = cors_config([" https://example.test "])
        self.assertIsNone(built)
        self.assertIsNotNone(problem)

    def test_termination_validation_global_and_edge_cases(self):
        from ferrum_migration.model import PluginSpec
        # 205 with non-empty body, reserved header, trailing whitespace, whitespace-only content_type,
        # newline in header name, and >1 MiB body all refused.
        for label, term in (
            ("205-body", {"status_code": 205, "body": "nonempty"}),
            ("reserved-hdr", {"status_code": 200, "headers": {"Set-Cookie": "a=b"}, "body": ""}),
            ("ferrum-hdr", {"status_code": 200, "headers": {"X-Ferrum-Debug": "1"}, "body": ""}),
            ("dup-hdr", {"status_code": 200, "headers": {"X-A": "1", "x-a": "2"}, "body": ""}),
            ("newline-hdr", {"status_code": 200, "headers": {"X-Demo\n": "1"}, "body": ""}),
            ("trailing-ws", {"status_code": 302, "headers": {"location": "https://a.test/ "}, "body": ""}),
            ("blank-ct", {"status_code": 200, "content_type": "   ", "body": "ok"}),
            ("oversized-1mib", {"status_code": 200, "content_type": "text/plain", "body": "a" * (1024 * 1024)}),
        ):
            with self.subTest(case=label):
                r = RouteSpec(ref=label, name=label, hosts=["a.example.test"], kind="prefix", path="/r",
                              protocols=frozenset({"http"}), termination=term)
                emit(Plan(platform="test", routes=[r]), EmitOptions(), Report("test", "synthetic"))
                self.assertTrue(r.refusals)
        # Surrounding spaces on content_type are accepted (Ferrum trims OWS).
        ws_ct = RouteSpec(ref="ws-ct", name="ws-ct", hosts=["a.example.test"], kind="prefix", path="/ok",
                          protocols=frozenset({"http"}),
                          termination={"status_code": 200, "content_type": " text/plain ", "body": "ok"})
        emit(Plan(platform="test", routes=[ws_ct]), EmitOptions(), Report("test", "synthetic"))
        self.assertFalse(ws_ct.refusals)
        # Invalid global request_termination (including >1 MiB body) fails closed on all routes.
        for bad_global in (
            PluginSpec("request_termination", {"status_code": 205, "body": "nope"}, "global-term"),
            PluginSpec("request_termination", {"status_code": 200, "body": "a" * (1024 * 1024)}, "global-big"),
        ):
            route = RouteSpec(ref="ok", name="ok", hosts=["a.example.test"], kind="prefix", path="/ok",
                              protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
            report = Report("test", "synthetic")
            result = emit(Plan(platform="test", routes=[route], global_plugins=[bad_global]), EmitOptions(), report)
            self.assertTrue(route.refusals)
            self.assertIn("global-plugin-invalid", {c.code for c in report.caveats})
            self.assertFalse([p for p in result.config["plugin_configs"] if p["scope"] == "global"])

    def test_san_limits_and_dns_syntax_and_lone_surrogate_rejected(self):
        from ferrum_migration.errors import InputError
        from ferrum_migration.model import Target, TlsSpec, UpstreamSpec
        from ferrum_migration.safe_load import Limits, load_structured

        self.assertFalse(util.valid_backend_tls_san("api.example.com."))
        self.assertFalse(util.valid_backend_tls_san("-bad.example.com"))
        self.assertFalse(util.valid_backend_tls_san("a" * 64 + ".example.com"))
        self.assertFalse(util.valid_backend_tls_san("fe80::1%eth0"))
        self.assertFalse(util.valid_backend_tls_san("\u212a.internal"))  # Kelvin sign
        self.assertFalse(util.valid_backend_tls_sni("\u212a.internal"))
        self.assertEqual(util.backend_tls_san_kind("spiffe://trust.domain/ns/default/sa/app"), "URI")
        self.assertEqual(util.backend_tls_san_kind("10.0.0.1"), "IP_ADDRESS")
        self.assertEqual(util.backend_tls_san_kind("api.example.com"), "DNS")
        # 257 distinct SANs refused.
        up = UpstreamSpec(key="u", name="u", ref="u", targets=[Target("b.internal", 443, 1)],
                          tls=TlsSpec(verify=True, san_allow_list=[f"s{i}.example.test" for i in range(257)]))
        r = RouteSpec(ref="s", name="s", hosts=["b.example.test"], kind="prefix", path="/s",
                      protocols=frozenset({"http"}), backend=BackendRef("https", upstream_key="u"))
        emit(Plan(platform="test", routes=[r], upstreams={"u": up}), EmitOptions(), Report("test", "synthetic"))
        self.assertTrue(r.refusals)
        # Lone surrogate in JSON raises InputError instead of UnicodeEncodeError.
        with self.assertRaises(InputError):
            load_structured('{"key": "\\ud800"}', "json", Limits())

    def test_acl_drop_quarantines_consumer_and_cross_field_identity_collision_omitted(self):
        from ferrum_migration.model import ConsumerSpec
        # Dropping a >255-byte ACL group must quarantine the consumer so it cannot bypass a deny-list.
        c_acl = ConsumerSpec(ref="c-acl", key="c-acl", username="alice",
                             acl_groups=["é" * 130, "ok"], keyauth=["secret-key-at-least-16-chars"])
        # Cross-field identity collision: c2's custom_id equals c1's username.
        c1 = ConsumerSpec(ref="c1", key="c1", username="shared-id", keyauth=["key-one-at-least-16-chars"])
        c2 = ConsumerSpec(ref="c2", key="c2", username="bob", custom_id="shared-id",
                          keyauth=["key-two-at-least-16-chars"])
        # Consumer with >2 keys exceeds Ferrum's default per-type limit; keys withheld fail closed.
        c_many = ConsumerSpec(ref="c-many", key="c-many", username="carol",
                              keyauth=[f"synthetic-key-{i:04d}-long" for i in range(17)])
        # Consumer with a 3000-character multibyte key (<=4096 chars even though >4096 UTF-8 bytes) succeeds.
        c_mb = ConsumerSpec(ref="c-mb", key="c-mb", username="dave", keyauth=["é" * 3000])
        report = Report("test", "synthetic")
        result = emit(Plan(platform="test", consumers=[c_acl, c1, c2, c_many, c_mb]),
                      EmitOptions(include_secrets=True), report)
        by_name = {c["username"]: c for c in result.config["consumers"]}
        self.assertEqual(sorted(by_name), ["alice", "carol", "dave"])
        self.assertNotIn("credentials", by_name["alice"])
        self.assertNotIn("credentials", by_name["carol"])
        self.assertIn("credentials", by_name["dave"])
        self.assertIn("consumer-acl-groups", {c.code for c in report.caveats})
        self.assertIn("consumer-quarantined", {c.code for c in report.caveats})
        self.assertIn("consumer-identity-conflict", {c.code for c in report.caveats})
        self.assertIn("keyauth-limit", {c.code for c in report.caveats})

    def test_conflict_merging_over_100_hosts_chunks_without_colliding_with_sibling(self):
        hosts_a = ["shared.example.test"] + [f"a{i}.example.test" for i in range(60)]
        hosts_b = ["shared.example.test"] + [f"b{i}.example.test" for i in range(60)]
        r1 = RouteSpec(ref="r1", name="r1", hosts=hosts_a, kind="prefix", path="/api",
                       protocols=frozenset({"http"}), backend=BackendRef("http", "a.internal", 80))
        r2 = RouteSpec(ref="r2", name="r2", hosts=hosts_b, kind="prefix", path="/api",
                       protocols=frozenset({"http"}), backend=BackendRef("http", "b.internal", 80))
        sibling = RouteSpec(ref="sib", name="sib", hosts=["other.example.test"], kind="prefix", path="/api",
                            protocols=frozenset({"http"}), backend=BackendRef("http", "c.internal", 80))
        result = emit(Plan(platform="test", routes=[r1, r2, sibling]), EmitOptions(), Report("test", "synthetic"))
        self.assertFalse(sibling.refusals)
        placeholders = [p for p in result.config["proxies"] if p["labels"].get("ferrum-migration/status") == "refused"]
        self.assertEqual(len(placeholders), 2)
        for proxy in result.config["proxies"]:
            self.assertLessEqual(len(proxy.get("hosts", [])), util.MAX_HOSTS_PER_PROXY)
            self.assertTrue(proxy.get("hosts"))

    def test_termination_header_crlf_and_invalid_backend_san_refused(self):
        from ferrum_migration.model import Target, TlsSpec, UpstreamSpec
        bad_term = RouteSpec(ref="t", name="t", hosts=["a.example.test"], kind="prefix", path="/r",
                             protocols=frozenset({"http"}),
                             termination={"status_code": 302, "headers": {"location": "https://x\r\nBad: 1"}, "body": ""})
        up = UpstreamSpec(key="u", name="u", ref="u", targets=[Target("b.internal", 443, 1)],
                          tls=TlsSpec(verify=True, san_allow_list=["https://not-spiffe.example/id"]))
        bad_san = RouteSpec(ref="s", name="s", hosts=["b.example.test"], kind="prefix", path="/s",
                            protocols=frozenset({"http"}), backend=BackendRef("https", upstream_key="u"))
        emit(Plan(platform="test", routes=[bad_term, bad_san], upstreams={"u": up}), EmitOptions(),
             Report("test", "synthetic"))
        self.assertTrue(bad_term.refusals)
        self.assertTrue(bad_san.refusals)

    def test_consumer_byte_length_and_control_char_validation(self):
        from ferrum_migration.model import ConsumerSpec
        bad_cid = ConsumerSpec(ref="c1", key="c1", username="alice", custom_id="bad\nid")
        bad_utf8 = ConsumerSpec(ref="c2", key="c2", username="é" * 130)  # 260 UTF-8 bytes > 255
        blank_acl = ConsumerSpec(ref="c3", key="c3", username="bob", custom_id="   ", acl_groups=["   ", "ok"])
        report = Report("test", "synthetic")
        result = emit(Plan(platform="test", consumers=[bad_cid, bad_utf8, blank_acl]), EmitOptions(), report)
        self.assertEqual([c["username"] for c in result.config["consumers"]], ["bob"])
        self.assertNotIn("custom_id", result.config["consumers"][0])
        self.assertEqual(result.config["consumers"][0]["acl_groups"], ["ok"])


if __name__ == "__main__":
    unittest.main()
