import json
import textwrap
import unittest

import yaml

from helpers import assert_structurally_valid, codes, live_routes, migrate, one_proxy, plugin, plugins_of, proxies, \
    read_fixture, upstream_of

from ferrum_migration.sources.traefik import ENTRYPOINTS_ASSERTION_FLAG, RuleError, evaluate_term, rule_to_dnf


def asserted(text, **kwargs):
    """Convert with the operator's entryPoint assertion (``--assert-traefik-entrypoints-add-no-controls``).

    Used for the mapping tests below: their synthetic inputs stand for sources whose static entryPoints (named, or
    the defaults) add no TLS, client options, middlewares, redirections, forwarded-header trust or bind restriction.
    Default behavior without the assertion is covered by TraefikEntryPointsTest.
    """
    return migrate("traefik", text, traefik_entrypoints_asserted=True, **kwargs)


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
        self.result, self.report, _ = asserted(read_fixture("traefik", "dynamic.yaml"))
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
        # /admin is refused (Header matcher); its string-prefix siblings must not reach the host-only root.
        self.assertEqual(guards, ["/admin", "/api", "/beta", "/v2"])

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
        result, report, _ = asserted(read_fixture("traefik", "dynamic.toml"), fmt="toml")
        proxy = one_proxy(self, result.config, "/api")
        self.assertEqual(proxy["hosts"], ["a.example.com", "b.example.com"])
        self.assertFalse(proxy["strip_listen_path"])
        self.assertEqual(plugin(self, result.config, proxy, "ip_restriction")["config"],
                         {"allow": ["192.0.2.0/24", "2001:db8::/32"]})
        # The only review item is the string-prefix sibling report: Traefik's PathPrefix(`/api`) also forwarded
        # /apix, which this output answers with 404.
        self.assertEqual({c.code for c in report.caveats if c.severity == "error"}, {"prefix-string-siblings"})

    def _doc(self, routers, middlewares=None):
        return yaml.safe_dump({"http": {
            "routers": routers,
            "middlewares": middlewares or {},
            "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}},
        }})

    def test_allowed_hosts_from_several_middlewares_never_broaden(self):
        # Each headers middleware checks its own allowedHosts; the later, broader list must not replace the
        # earlier one that rejects a.example.test.
        router = {"r": {"rule": "Host(`a.example.test`) && Path(`/x`)", "service": "s",
                        "middlewares": ["narrow", "broad"]}}
        middlewares = {"narrow": {"headers": {"allowedHosts": ["b.example.test"]}},
                       "broad": {"headers": {"allowedHosts": ["a.example.test", "b.example.test"]}}}
        result, _report, _ = asserted(self._doc(router, middlewares))
        self.assertEqual(one_proxy(self, result.config, "=/x", "a.example.test")["labels"]["ferrum-migration/status"],
                         "refused")
        # One list covering the router host is a no-op, unless hostsProxyHeaders also subjects other headers to it.
        result, _report, _ = asserted(self._doc(router, {
            "narrow": {"headers": {"allowedHosts": ["a.example.test"]}}, "broad": {"headers": {}}}))
        self.assertEqual(one_proxy(self, result.config, "=/x", "a.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")
        result, _report, _ = asserted(self._doc(router, {
            "narrow": {"headers": {"allowedHosts": ["a.example.test"], "hostsProxyHeaders": ["X-Forwarded-Host"]}},
            "broad": {"headers": {}}}))
        self.assertEqual(one_proxy(self, result.config, "=/x", "a.example.test")["labels"]["ferrum-migration/status"],
                         "refused")

    def test_higher_priority_catch_all_shadows_specific_router(self):
        result, report, _ = asserted(self._doc({
            "catchall": {"rule": "PathPrefix(`/`)", "priority": 1000, "service": "s"},
            "api": {"rule": "PathPrefix(`/api`)", "service": "s"},
        }))
        self.assertEqual(proxies(result.config, "/api"), [])
        self.assertIn("route-shadowed", codes(report, "warning"))

    def test_equal_priority_overlap_is_refused(self):
        result, _report, _ = asserted(self._doc({
            "a": {"rule": "PathPrefix(`/a`)", "priority": 10, "service": "s"},
            "b": {"rule": "PathPrefix(`/a/b`)", "priority": 10, "service": "s"},
        }))
        for proxy in result.config["proxies"]:
            self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")

    def test_forward_auth_is_refused(self):
        result, _report, _ = asserted(self._doc(
            {"r": {"rule": "PathPrefix(`/p`)", "service": "s", "middlewares": ["auth"]}},
            {"auth": {"forwardAuth": {"address": "http://auth.internal/check"}}}))
        self.assertEqual(one_proxy(self, result.config, "/p")["labels"]["ferrum-migration/status"], "refused")

    def test_basic_auth_users_never_echoed(self):
        fake_hash = "test:$apr1$fakefake$0123456789abcdefghijkl"
        result, report, _ = asserted(self._doc(
            {"r": {"rule": "PathPrefix(`/b`)", "service": "s", "middlewares": ["ba"]}},
            {"ba": {"basicAuth": {"users": [fake_hash], "removeHeader": True}}}))
        proxy = one_proxy(self, result.config, "/b")
        self.assertEqual(plugin(self, result.config, proxy, "basic_auth")["config"], {"hide_credentials": True})
        self.assertNotIn("fakefake", json.dumps(result.config))
        self.assertNotIn("fakefake", json.dumps([c.to_dict() for c in report.caveats]))

    def test_ip_strategy_refused(self):
        result, _report, _ = asserted(self._doc(
            {"r": {"rule": "PathPrefix(`/i`)", "service": "s", "middlewares": ["ip"]}},
            {"ip": {"ipAllowList": {"sourceRange": ["10.0.0.0/8"], "ipStrategy": {"depth": 1}}}}))
        self.assertEqual(one_proxy(self, result.config, "/i")["labels"]["ferrum-migration/status"], "refused")

    def test_conditional_strip_prefix_refused(self):
        result, _report, _ = asserted(self._doc(
            {"r": {"rule": "PathPrefix(`/api`)", "service": "s", "middlewares": ["strip"]}},
            {"strip": {"stripPrefix": {"prefixes": ["/api/v1"]}}}))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "refused")

    def test_strip_prefix_shorter_than_route_uses_backend_path(self):
        result, _report, _ = asserted(self._doc(
            {"r": {"rule": "PathPrefix(`/api/v1`)", "service": "s", "middlewares": ["strip"]}},
            {"strip": {"stripPrefix": {"prefixes": ["/api"]}}}))
        proxy = one_proxy(self, result.config, "/api/v1")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertEqual(proxy["backend_path"], "/v1")

    def test_path_prefix_siblings_are_reported_not_widened(self):
        result, report, _ = asserted(self._doc({"r": {"rule": "PathPrefix(`/api`)", "service": "s"}}))
        self.assertEqual([p.get("listen_path") for p in result.config["proxies"]], ["/api"])
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertIn("prefix-string-siblings", codes(report, "error"))

    def test_exact_path_and_trailing_slash_prefix_have_no_sibling_report(self):
        # Path(`/status`) is exact; PathPrefix(`/api/`) siblings all continue at a '/' boundary.
        _result, report, _ = asserted(self._doc({
            "status": {"rule": "Path(`/status`)", "service": "s"},
            "api": {"rule": "PathPrefix(`/api/`)", "service": "s"},
        }))
        self.assertNotIn("prefix-string-siblings", codes(report))


class TraefikServersTransportTest(unittest.TestCase):
    def _doc(self, services, transports, router_service="split"):
        return yaml.safe_dump({"http": {
            "routers": {"r": {"rule": "PathPrefix(`/w`)", "service": router_service}},
            "services": services,
            "serversTransports": transports,
        }})

    def _weighted(self, transport_a, transport_b):
        services = {
            "split": {"weighted": {"services": [{"name": "a", "weight": 3}, {"name": "b", "weight": 1}]}},
            "a": {"loadBalancer": {"servers": [{"url": "http://a.internal:80"}]}},
            "b": {"loadBalancer": {"servers": [{"url": "http://b.internal:80"}]}},
        }
        if transport_a:
            services["a"]["loadBalancer"]["serversTransport"] = transport_a
        if transport_b:
            services["b"]["loadBalancer"]["serversTransport"] = transport_b
        return services

    TIMEOUTS = {"forwardingTimeouts": {"dialTimeout": "2s", "responseHeaderTimeout": "7s"}}

    def test_weighted_children_keep_agreeing_forwarding_timeouts(self):
        result, report, _ = asserted(self._doc(self._weighted("t", "t"), {"t": self.TIMEOUTS}))
        proxy = one_proxy(self, result.config, "/w")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual((proxy["backend_connect_timeout_ms"], proxy["backend_read_timeout_ms"]), (2000, 7000))
        self.assertIn("timeout-approximate", codes(report, "warning"))

    def test_weighted_children_with_different_timeouts_are_refused(self):
        result, report, _ = asserted(self._doc(self._weighted("t", None), {"t": self.TIMEOUTS}))
        self.assertEqual(one_proxy(self, result.config, "/w")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("route-refused", codes(report, "error"))

    def test_weighted_child_with_undefined_transport_is_refused(self):
        result, _report, _ = asserted(self._doc(self._weighted("missing", "missing"), {}))
        self.assertEqual(one_proxy(self, result.config, "/w")["labels"]["ferrum-migration/status"], "refused")

    def test_identity_controls_are_refused_for_direct_and_weighted_backends(self):
        direct = {"d": {"loadBalancer": {"servers": [{"url": "https://d.internal:443"}], "serversTransport": "pin"}}}
        result, _report, _ = asserted(self._doc(
            direct, {"pin": {"peerCertURI": "spiffe://example.test/backend"}}, router_service="d"))
        self.assertEqual(one_proxy(self, result.config, "/w")["labels"]["ferrum-migration/status"], "refused")
        result, _report, _ = asserted(self._doc(
            self._weighted("id", "id"), {"id": {"spiffe": {"ids": ["spiffe://example.test/backend"]}}}))
        self.assertEqual(one_proxy(self, result.config, "/w")["labels"]["ferrum-migration/status"], "refused")
        # Several pinned roots cannot be expressed; Ferrum's default trust store would trust more CAs.
        result, _report, _ = asserted(self._doc(
            direct, {"pin": {"rootCAs": ["/etc/test-only/ca-a.pem", "/etc/test-only/ca-b.pem"]}}, router_service="d"))
        self.assertEqual(one_proxy(self, result.config, "/w")["labels"]["ferrum-migration/status"], "refused")


class TraefikClientAuthTest(unittest.TestCase):
    """tls.options clientAuth becomes the frontend client CA or refuses the route; it is never dropped."""

    CA = "/etc/test-only/client-ca.pem"  # synthetic path; never read by the tool

    def _doc(self, routers, options=None):
        doc = {"http": {"routers": routers,
                        "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}}}
        if options is not None:
            doc["tls"] = {"options": options}
        return yaml.safe_dump(doc)

    def _status(self, result, path, host=None):
        return one_proxy(self, result.config, path, host)["labels"]["ferrum-migration/status"]

    def test_referenced_client_auth_is_preserved_as_frontend_client_ca(self):
        router = {"r": {"rule": "Host(`m.example.test`) && Path(`/m`)", "service": "s",
                        "tls": {"options": "mtls@file"}}}
        result, report, plan = asserted(self._doc(router, {"mtls": {"clientAuth": {
            "caFiles": [self.CA], "clientAuthType": "RequireAndVerifyClientCert"}}}))
        self.assertEqual(self._status(result, "=/m", "m.example.test"), "migrated")
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])
        self.assertNotIn("traefik-client-auth", codes(report))
        # Optional verification becomes mandatory (stricter), with a warning.
        _result, report, plan = asserted(self._doc(router, {"mtls": {"clientAuth": {
            "caFiles": [self.CA], "clientAuthType": "VerifyClientCertIfGiven"}}}))
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])
        self.assertIn("traefik-mtls-optional", codes(report, "warning"))

    def test_default_option_client_auth_applies_to_routers_without_options(self):
        # caFiles without clientAuthType: Traefik requires and verifies client certificates.
        result, _report, plan = asserted(self._doc(
            {"r": {"rule": "Host(`d.example.test`)", "service": "s", "tls": {}}},
            {"default": {"clientAuth": {"caFiles": [self.CA]}}}))
        self.assertEqual(self._status(result, None, "d.example.test"), "migrated")
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])

    def test_unknown_or_unreproducible_client_auth_refuses_the_route(self):
        cases = {
            "other provider": ({"options": "mtls@kubernetescrd"}, {}),
            "undefined": ({"options": "missing"}, {}),
            "several CA files": ({"options": "m"}, {"m": {"clientAuth": {
                "caFiles": [self.CA, "/etc/test-only/other-ca.pem"]}}}),
            "unverified certificates": ({"options": "m"}, {"m": {"clientAuth": {
                "clientAuthType": "RequireAnyClientCert"}}}),
            "malformed default": ({}, {"default": {"clientAuth": "yes"}}),
        }
        for label, (router_tls, options) in cases.items():
            with self.subTest(label):
                result, report, plan = asserted(self._doc(
                    {"r": {"rule": "Host(`u.example.test`) && Path(`/u`)", "service": "s", "tls": router_tls}},
                    options))
                self.assertEqual(self._status(result, "=/u", "u.example.test"), "refused")
                self.assertEqual(plan.settings.client_ca_paths, [])
                self.assertIn("route-refused", codes(report, "error"))

    def test_sni_dependent_client_auth_is_refused(self):
        options = {"mtls": {"clientAuth": {"caFiles": [self.CA]}}}
        # No Host matcher: Traefik applies the options selected by SNI (the default ones for unclaimed names).
        result, _report, _plan = asserted(self._doc(
            {"r": {"rule": "Path(`/h`)", "service": "s", "tls": {"options": "mtls"}}}, options))
        self.assertEqual(self._status(result, "=/h"), "refused")
        # One host mapped to different TLS options: Traefik falls back to the default options for that host.
        result, _report, _plan = asserted(self._doc({
            "a": {"rule": "Host(`c.example.test`) && Path(`/a`)", "service": "s", "tls": {"options": "mtls"}},
            "b": {"rule": "Host(`c.example.test`) && Path(`/b`)", "service": "s", "tls": {}},
        }, options))
        for path in ("=/a", "=/b"):
            self.assertEqual(self._status(result, path, "c.example.test"), "refused")

    def test_plaintext_and_tls_routers_without_client_auth_are_unaffected(self):
        options = {"default": {"minVersion": "VersionTLS12"}, "mtls": {"clientAuth": {"caFiles": [self.CA]}}}
        for router_tls in (None, {}):
            with self.subTest(tls=router_tls):
                router = {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s"}
                if router_tls is not None:
                    router["tls"] = router_tls
                result, report, plan = asserted(self._doc({"r": router}, options))
                self.assertEqual(self._status(result, "=/p", "p.example.test"), "migrated")
                self.assertEqual(plan.settings.client_ca_paths, [])
                self.assertNotIn("traefik-client-auth", codes(report))


class TraefikEntryPointsTest(unittest.TestCase):
    """Static entryPoints are not in the dynamic input: no forwarding without the operator's explicit assertion."""

    SERVICE = {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}
    ROUTERS = {
        "plaintext, no entryPoints": {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s"},
        "plaintext, named entryPoint": {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s",
                                        "entryPoints": ["web"]},
        "explicit tls": {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s", "tls": {},
                         "entryPoints": ["websecure"]},
    }

    def _doc(self, routers, middlewares=None):
        http = {"routers": routers, "services": self.SERVICE}
        if middlewares:
            http["middlewares"] = middlewares
        return yaml.safe_dump({"http": http})

    @staticmethod
    def _status(proxy):
        return proxy["labels"]["ferrum-migration/status"]

    def test_default_refuses_every_forwarding_router(self):
        for label, router in self.ROUTERS.items():
            with self.subTest(label):
                result, report, plan = migrate("traefik", self._doc({"r": router}))
                proxy = one_proxy(self, result.config, "=/p", "p.example.test")
                self.assertEqual(self._status(proxy), "refused")
                self.assertEqual([(p["plugin_name"], p["config"]["status_code"])
                                  for p in plugins_of(result.config, proxy)], [("request_termination", 503)])
                self.assertEqual(live_routes(result.config), [])
                self.assertEqual(result.stats["migrated_routes"], 0)
                self.assertIn("traefik-entrypoints-unverified", codes(report, "error"))
                self.assertNotIn("traefik-entrypoints-asserted", codes(report))
                self.assertTrue(any("static entryPoints" in reason for reason in plan.routes[0].refusals))

    def test_default_refusal_names_the_remediation_without_calling_it_validation(self):
        _result, report, _plan = migrate("traefik", self._doc({"r": self.ROUTERS["plaintext, no entryPoints"]}))
        [caveat] = [c for c in report.caveats if c.code == "traefik-entrypoints-unverified"]
        self.assertEqual(caveat.severity, "error")
        self.assertIn(ENTRYPOINTS_ASSERTION_FLAG, caveat.action)
        self.assertIn("Inspect the static configuration", caveat.action)
        self.assertIn("cannot verify", caveat.action)
        self.assertNotIn("p.example.test", caveat.message + caveat.action)

    def test_default_refuses_the_real_fixtures(self):
        for name, fmt in (("dynamic.yaml", "yaml"), ("dynamic.toml", "toml")):
            with self.subTest(name):
                result, report, _plan = migrate("traefik", read_fixture("traefik", name), fmt=fmt)
                assert_structurally_valid(self, result.config)
                self.assertEqual(live_routes(result.config), [])
                self.assertEqual(result.config["upstreams"], [])
                self.assertIn("traefik-entrypoints-unverified", codes(report, "error"))

    def test_assertion_restores_the_dynamic_mapping(self):
        for label, router in self.ROUTERS.items():
            with self.subTest(label):
                result, report, _plan = asserted(self._doc({"r": router}))
                self.assertEqual(self._status(one_proxy(self, result.config, "=/p", "p.example.test")), "migrated")
                self.assertNotIn("traefik-entrypoints-unverified", codes(report))
                self.assertIn("traefik-entrypoints-asserted", codes(report, "warning"))
                # The router's own tls block still decides the frontend: HTTPS-only output for the tls router.
                self.assertEqual(result.tls_only, "tls" in router)

    def test_assertion_is_reported_as_unverified(self):
        _result, report, _plan = asserted(self._doc({"r": self.ROUTERS["plaintext, no entryPoints"]}))
        [caveat] = [c for c in report.caveats if c.code == "traefik-entrypoints-asserted"]
        self.assertIn(ENTRYPOINTS_ASSERTION_FLAG, caveat.message)
        self.assertIn("cannot verify", caveat.message)

    def test_assertion_never_overrides_restrictions_stated_in_the_input(self):
        base = {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s"}
        cases = {
            "TLS options from another provider": ({**base, "tls": {"options": "mtls@kubernetescrd"}}, None),
            "untranslatable middleware": ({**base, "middlewares": ["auth"]},
                                          {"auth": {"forwardAuth": {"address": "http://auth.internal/check"}}}),
            "malformed entryPoints": ({**base, "entryPoints": [""]}, None),
            "non-string entryPoints": ({**base, "entryPoints": [{"name": "web"}]}, None),
        }
        for label, (router, middlewares) in cases.items():
            with self.subTest(label):
                result, report, _plan = asserted(self._doc({"r": router}, middlewares))
                self.assertEqual(self._status(one_proxy(self, result.config, "=/p", "p.example.test")), "refused")
                self.assertEqual(live_routes(result.config), [])
                self.assertIn("route-refused", codes(report, "error"))

    def test_assertion_never_overrides_static_entrypoints_stated_in_the_input(self):
        # A static entryPoints section in the input is not translated; the assertion cannot speak over it.
        text = yaml.safe_dump({
            "entryPoints": {"web": {"address": ":80", "http": {"redirections": {"entryPoint": {"to": "websecure"}}}}},
            "http": {"routers": {"r": self.ROUTERS["plaintext, named entryPoint"]}, "services": self.SERVICE},
        })
        result, report, _plan = asserted(text)
        self.assertEqual(self._status(one_proxy(self, result.config, "=/p", "p.example.test")), "refused")
        self.assertEqual(live_routes(result.config), [])
        self.assertIn("traefik-entrypoints-in-input", codes(report, "error"))
        self.assertNotIn("traefik-entrypoints-asserted", codes(report))

    def test_assertion_keeps_router_tls_as_https_only(self):
        result, report, _plan = asserted(self._doc({
            "plain": {"rule": "Host(`p.example.test`) && Path(`/plain`)", "service": "s", "entryPoints": ["web"]},
            "secure": {"rule": "Host(`p.example.test`) && Path(`/secure`)", "service": "s", "tls": {},
                       "entryPoints": ["websecure"]},
        }))
        self.assertEqual(self._status(one_proxy(self, result.config, "=/plain", "p.example.test")), "migrated")
        # Never exposed on the plaintext listener; the separate HTTPS entryPoint is not an entryPoint-scope conflict.
        self.assertEqual(self._status(one_proxy(self, result.config, "=/secure", "p.example.test")), "refused")
        self.assertEqual(result.frontend_protocols, "http")
        self.assertNotIn("traefik-entrypoint-scope", codes(report))

    def test_assertion_keeps_explicit_entrypoint_lists(self):
        def router(path, entrypoints=None):
            spec = {"rule": f"Host(`e.example.test`) && Path(`{path}`)", "service": "s"}
            if entrypoints is not None:
                spec["entryPoints"] = entrypoints
            return spec

        result, report, plan = asserted(self._doc({
            "a": router("/a", ["web"]),
            "b": router("/b", ["web", "metrics"]),
            "c": router("/c", ["admin"]),
            "d": router("/d"),
        }))
        statuses = {path: self._status(one_proxy(self, result.config, f"={path}", "e.example.test"))
                    for path in ("/a", "/b", "/c", "/d")}
        # web is the entryPoint the plaintext routers share; admin-only router c was never served there.
        self.assertEqual(statuses, {"/a": "migrated", "/b": "migrated", "/c": "refused", "/d": "migrated"})
        self.assertIn("traefik-entrypoint-scope", codes(report, "error"))
        refused = next(spec for spec in plan.routes if spec.name == "c")
        self.assertTrue(any("leave out web" in reason for reason in refused.refusals))


if __name__ == "__main__":
    unittest.main()
