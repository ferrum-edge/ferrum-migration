import json
import textwrap
import unittest

import yaml

from helpers import assert_structurally_valid, codes, live_routes, migrate, one_proxy, plugin, plugins_of, proxies, \
    read_fixture, upstream_of

from ferrum_migration.errors import InputError
from ferrum_migration.limits import Limits
from ferrum_migration.report import Report
from ferrum_migration.sources.common import SourceContext
from ferrum_migration.sources.traefik import CONTROLS_ASSERTION_FLAG, RuleError, evaluate_term, \
    parent_refs_violations, rule_to_dnf, translate, typed_field_problems


def asserted(text, **kwargs):
    """Convert with the operator's statement (``--assert-traefik-input-includes-effective-controls``).

    Used for the mapping tests below: their synthetic inputs stand for deployments whose every effective routing, TLS
    and access control within the converted scope is in the input: static entryPoints (named, or the defaults) add
    no TLS, client options, middlewares, redirections, forwarded-header trust or bind restriction, and no other
    provider adds TLS options (no 'default' outside the input), SNI option conflicts or competing routers. Default
    behavior without the statement is covered by TraefikInputControlsTest.
    """
    return migrate("traefik", text, traefik_controls_asserted=True, **kwargs)


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
    """The default TLS options' clientAuth becomes the frontend client CA of every HTTPS route, or refuses them all;
    it is never dropped. (Other TLS options refuse HTTPS through the handshake scope; see TraefikHandshakeScopeTest.)"""

    CA = "/etc/test-only/client-ca.pem"  # synthetic path; never read by the tool

    def _doc(self, routers, options=None):
        doc = {"http": {"routers": routers,
                        "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}}}
        if options is not None:
            doc["tls"] = {"options": options}
        return yaml.safe_dump(doc)

    def _status(self, result, path, host=None):
        return one_proxy(self, result.config, path, host)["labels"]["ferrum-migration/status"]

    def test_default_client_auth_is_preserved_for_every_https_route(self):
        # One homogeneous handshake policy: routers naming no options, an empty reference (Traefik treats it as
        # unset) and routers naming exactly 'default', on different hosts and paths, all get the default options'
        # client CA. (A qualified 'default@file' is a different name: see TraefikHandshakeScopeTest.)
        routers = {
            "implicit": {"rule": "Host(`m.example.test`) && Path(`/m`)", "service": "s", "tls": {}},
            "explicit": {"rule": "Host(`n.example.test`) && Path(`/n`)", "service": "s",
                         "tls": {"options": "default"}},
            "empty": {"rule": "Host(`o.example.test`) && Path(`/o`)", "service": "s",
                      "tls": {"options": ""}},
        }
        result, report, plan = asserted(self._doc(routers, {"default": {"clientAuth": {
            "caFiles": [self.CA], "clientAuthType": "RequireAndVerifyClientCert"}}}))
        for path, host in (("=/m", "m.example.test"), ("=/n", "n.example.test"), ("=/o", "o.example.test")):
            self.assertEqual(self._status(result, path, host), "migrated", path)
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])
        self.assertTrue(result.tls_only)
        self.assertNotIn("traefik-client-auth", codes(report))
        self.assertNotIn("traefik-tls-options-scope", codes(report))
        # Optional verification becomes mandatory (stricter), with a warning.
        _result, report, plan = asserted(self._doc(routers, {"default": {"clientAuth": {
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

    def test_unreproducible_default_client_auth_refuses_every_https_route(self):
        cases = {
            "several CA files": {"clientAuth": {"caFiles": [self.CA, "/etc/test-only/other-ca.pem"]}},
            "unverified certificates": {"clientAuth": {"clientAuthType": "RequireAnyClientCert"}},
            "malformed clientAuth": {"clientAuth": "yes"},
            "malformed entry": "yes",
        }
        for label, default in cases.items():
            with self.subTest(label):
                result, report, plan = asserted(self._doc({
                    "u": {"rule": "Host(`u.example.test`) && Path(`/u`)", "service": "s", "tls": {}},
                    "v": {"rule": "Host(`v.example.test`) && Path(`/v`)", "service": "s",
                          "tls": {"options": "default"}},
                }, {"default": default}))
                self.assertEqual(self._status(result, "=/u", "u.example.test"), "refused")
                self.assertEqual(self._status(result, "=/v", "v.example.test"), "refused")
                self.assertEqual(plan.settings.client_ca_paths, [])
                self.assertIn("traefik-client-auth", codes(report, "error"))
                self.assertIn("route-refused", codes(report, "error"))

    def test_plaintext_and_tls_routers_without_client_auth_are_unaffected(self):
        options = {"default": {"minVersion": "VersionTLS12"}}
        for router_tls in (None, {}):
            with self.subTest(tls=router_tls):
                router = {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s"}
                if router_tls is not None:
                    router["tls"] = router_tls
                result, report, plan = asserted(self._doc({"r": router}, options))
                self.assertEqual(self._status(result, "=/p", "p.example.test"), "migrated")
                self.assertEqual(plan.settings.client_ca_paths, [])
                self.assertNotIn("traefik-client-auth", codes(report))
                self.assertNotIn("traefik-tls-options-scope", codes(report))


class TraefikSniStrictTest(unittest.TestCase):
    """Enabled sniStrict in the default TLS options is an admission control: every HTTPS route is refused, with or
    without the operator's statement; it is never dropped as a TLS tuning setting. (sniStrict in any other TLS options
    refuses HTTPS through the handshake scope; see TraefikHandshakeScopeTest.)"""

    SERVICE = {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}

    def _doc(self, routers, options):
        return yaml.safe_dump({"http": {"routers": routers, "services": self.SERVICE}, "tls": {"options": options}})

    def _status(self, result, path, host):
        return one_proxy(self, result.config, path, host)["labels"]["ferrum-migration/status"]

    @staticmethod
    def _router(host, path, tls):
        return {"rule": f"Host(`{host}`) && Path(`{path}`)", "service": "s", "tls": tls}

    def test_explicit_reference_to_strict_default_refuses_the_route_even_with_the_statement(self):
        # Only the exact unqualified reference reaches the strict default; 'default@file' refuses through the
        # handshake scope instead (TraefikHandshakeScopeTest).
        for reference in ("default",):
            with self.subTest(reference=reference):
                result, report, plan = asserted(self._doc(
                    {"r": self._router("s.example.test", "/s", {"options": reference})},
                    {"default": {"sniStrict": True, "minVersion": "VersionTLS12"}}))
                self.assertEqual(self._status(result, "=/s", "s.example.test"), "refused")
                self.assertEqual(live_routes(result.config), [])
                self.assertIn("traefik-sni-strict", codes(report, "error"))
                self.assertIn("route-refused", codes(report, "error"))
                self.assertNotIn("traefik-tls-options-scope", codes(report))
                self.assertTrue(any("sniStrict" in reason for reason in plan.routes[0].refusals))

    def test_strict_default_options_refuse_every_https_route(self):
        # Routers naming no options and routers referencing 'default' explicitly, on different hosts, all use it.
        result, report, _plan = asserted(self._doc({
            "implicit": self._router("d.example.test", "/implicit", {}),
            "explicit": self._router("d.example.test", "/explicit", {"options": "default"}),
            "other-host": self._router("o.example.test", "/other", {}),
        }, {"default": {"sniStrict": True}}))
        for path, host in (("=/implicit", "d.example.test"), ("=/explicit", "d.example.test"),
                           ("=/other", "o.example.test")):
            self.assertEqual(self._status(result, path, host), "refused", path)
        self.assertEqual(live_routes(result.config), [])
        self.assertIn("traefik-sni-strict", codes(report, "error"))

    def test_unreadable_sni_strict_is_refused(self):
        result, report, _plan = asserted(self._doc({"r": self._router("u.example.test", "/u", {})},
                                                   {"default": {"sniStrict": "yes"}}))
        self.assertEqual(self._status(result, "=/u", "u.example.test"), "refused")
        self.assertIn("traefik-sni-strict", codes(report, "error"))

    def test_ordinary_tls_options_without_strict_sni_stay_migrated(self):
        options_cases = {
            "sniStrict false": {"default": {"sniStrict": False, "minVersion": "VersionTLS12"}},
            "sniStrict absent": {"default": {"minVersion": "VersionTLS12"}},
            "empty default entry": {"default": None},
        }
        for label, options in options_cases.items():
            with self.subTest(label):
                result, report, _plan = asserted(self._doc({"r": self._router("t.example.test", "/t", {})}, options))
                self.assertEqual(self._status(result, "=/t", "t.example.test"), "migrated")
                self.assertNotIn("traefik-sni-strict", codes(report))
                self.assertNotIn("traefik-tls-options-scope", codes(report))

    def test_plaintext_routers_are_not_subject_to_sni_strict(self):
        router = {"rule": "Host(`p.example.test`) && Path(`/p`)", "service": "s"}
        result, report, _plan = asserted(self._doc({"r": router}, {"default": {"sniStrict": True}}))
        self.assertEqual(self._status(result, "=/p", "p.example.test"), "migrated")
        self.assertNotIn("traefik-sni-strict", codes(report))


class TraefikHandshakeScopeTest(unittest.TestCase):
    """HTTPS is translated only under one global 'default' handshake policy. Any other TLS options in the input (a
    definition, used or not, or a named, provider-scoped, undefined or unreadable reference on any router as written)
    refuse every HTTPS route, whatever the hosts or paths and with or without the operator's statement. Plaintext
    routes are unaffected, and refused HTTPS routes are never moved to the plaintext listener."""

    SERVICE = {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}

    def _doc(self, routers, options=None):
        doc = {"http": {"routers": routers, "services": self.SERVICE}}
        if options is not None:
            doc["tls"] = {"options": options}
        return yaml.safe_dump(doc)

    def _status(self, result, path, host):
        return one_proxy(self, result.config, path, host)["labels"]["ferrum-migration/status"]

    @staticmethod
    def _router(host, path, tls=None):
        router = {"rule": f"Host(`{host}`) && Path(`{path}`)", "service": "s"}
        if tls is not None:
            router["tls"] = tls
        return router

    def _assert_https_refused(self, result, report, plan, hosts_paths):
        for path, host in hosts_paths:
            self.assertEqual(self._status(result, path, host), "refused", path)
        self.assertIn("traefik-tls-options-scope", codes(report, "error"))
        https = [spec for spec in plan.routes if spec.requires_tls]
        self.assertTrue(https)
        for spec in https:
            # Still HTTPS-only placeholders: never broadened to the plaintext listener.
            self.assertEqual(spec.protocols, frozenset({"https"}))
            self.assertTrue(any("global 'default' TLS handshake policy" in reason for reason in spec.refusals))

    def test_named_options_refuse_every_https_route_on_distinct_hosts_and_paths(self):
        result, report, plan = asserted(self._doc({
            "named": self._router("a.example.test", "/a", {"options": "relaxed"}),
            "implicit": self._router("b.example.test", "/b", {}),
            "explicit": self._router("c.example.test", "/c", {"options": "default"}),
            "plain": self._router("p.example.test", "/p"),
        }, {"default": {"minVersion": "VersionTLS12"}, "relaxed": {"minVersion": "VersionTLS13"}}))
        self._assert_https_refused(result, report, plan, (("=/a", "a.example.test"), ("=/b", "b.example.test"),
                                                          ("=/c", "c.example.test")))
        # Independent plaintext stays live on the plaintext listener only.
        self.assertEqual(self._status(result, "=/p", "p.example.test"), "migrated")
        self.assertEqual(live_routes(result.config), [("=/p", ["p.example.test"])])
        self.assertEqual(result.frontend_protocols, "http")
        self.assertNotIn("traefik-sni-strict", codes(report))
        self.assertNotIn("traefik-client-auth", codes(report))

    def test_unused_named_definitions_refuse_https(self):
        # No reachability analysis: a definition no router names still refuses HTTPS.
        cases = {
            "spare relaxed": {"spare": {"minVersion": "VersionTLS12"}},
            "spare strict": {"default": {}, "spare": {"sniStrict": True}},
            "spare client auth": {"spare": {"clientAuth": {"caFiles": ["/etc/test-only/ca.pem"]}}},
        }
        for label, options in cases.items():
            with self.subTest(label):
                result, report, plan = asserted(self._doc({"r": self._router("t.example.test", "/t", {})}, options))
                self._assert_https_refused(result, report, plan, (("=/t", "t.example.test"),))
                self.assertEqual(live_routes(result.config), [])
                self.assertEqual(plan.settings.client_ca_paths, [])

    def test_unresolved_or_unreadable_references_refuse_every_https_route(self):
        cases = {
            "other provider": ({"options": "mtls@kubernetescrd"}, None),
            "default of another provider": ({"options": "default@kubernetescrd"}, None),
            # Traefik stores the global default unqualified, so a qualified reference names another set.
            "default qualified by the file provider": ({"options": "default@file"}, None),
            "default with an empty provider suffix": ({"options": "default@"}, None),
            "qualifier without a name": ({"options": "@file"}, None),
            # TLS options names are case-sensitive: this is not the global default.
            "default in another letter case": ({"options": "Default"}, None),
            "undefined name": ({"options": "missing"}, None),
            "non-string reference": ({"options": ["default"]}, None),
            "unreadable tls block": ("yes", None),
            "unreadable tls.options section": ({}, ["default"]),
        }
        for label, (odd_tls, options) in cases.items():
            with self.subTest(label):
                result, report, plan = asserted(self._doc({
                    "odd": self._router("o.example.test", "/o", odd_tls),
                    "ordinary": self._router("n.example.test", "/n", {}),
                }, options))
                self._assert_https_refused(result, report, plan, (("=/o", "o.example.test"),
                                                                  ("=/n", "n.example.test")))

    def test_qualified_default_reference_never_inherits_the_default_options(self):
        # The input's 'default' options carry an ordinary client CA. Routers naming none or exactly 'default' would use
        # it, but 'default@file' does not name the global default, so every HTTPS route is refused instead and no
        # client CA is configured; the plaintext router is unaffected.
        ca = "/etc/test-only/client-ca.pem"  # synthetic path; never read by the tool
        for options in ({"default": {"clientAuth": {"caFiles": [ca]}}}, None):
            with self.subTest(default_defined=options is not None):
                result, report, plan = asserted(self._doc({
                    "implicit": self._router("a.example.test", "/a", {}),
                    "qualified": self._router("b.example.test", "/b", {"options": "default@file"}),
                    "plain": self._router("p.example.test", "/p"),
                }, options))
                self._assert_https_refused(result, report, plan, (("=/a", "a.example.test"),
                                                                  ("=/b", "b.example.test")))
                self.assertEqual(plan.settings.client_ca_paths, [])
                self.assertEqual(live_routes(result.config), [("=/p", ["p.example.test"])])
                self.assertEqual(result.frontend_protocols, "http")
                self.assertNotIn("traefik-client-auth", codes(report))

    def test_scope_is_decided_on_routers_before_parsing_early_exits_and_shadowing(self):
        # Routers that never become routes still name the TLS options Traefik loaded for the frontend.
        ordinary = {"ordinary": self._router("n.example.test", "/n", {})}
        cases = {
            "router without a rule": {"norule": {"service": "s", "tls": {"options": "elsewhere"}}},
            "router that is not a mapping": {"broken": "not a router"},
            "unparseable rule": {"bad": {"rule": "Host(`x.example.test`", "service": "s",
                                         "tls": {"options": "elsewhere"}}},
            "unsatisfiable rule": {"never": {"rule": "Host(`x.example.test`) && Host(`y.example.test`)",
                                             "service": "s", "tls": {"options": "elsewhere"}}},
            "shadowed router": {"wide": {"rule": "Host(`n.example.test`) && PathPrefix(`/`)", "priority": 1000,
                                         "service": "s", "tls": {}},
                                "narrow": {"rule": "Host(`n.example.test`) && Path(`/n`)", "service": "s",
                                           "tls": {"options": "elsewhere"}}},
        }
        for label, routers in cases.items():
            with self.subTest(label):
                merged = {**ordinary, **routers} if label != "shadowed router" else routers
                result, report, plan = asserted(self._doc(merged))
                self.assertEqual(live_routes(result.config), [])
                self.assertIn("traefik-tls-options-scope", codes(report, "error"))
                for spec in plan.routes:
                    if spec.requires_tls and not spec.skip:
                        self.assertTrue(any("global 'default' TLS handshake policy" in reason
                                            for reason in spec.refusals), spec.ref)

    def test_scope_refusal_applies_without_the_statement(self):
        result, report, plan = migrate("traefik", self._doc({
            "named": self._router("a.example.test", "/a", {"options": "relaxed"}),
            "plain": self._router("p.example.test", "/p"),
        }, {"relaxed": {"minVersion": "VersionTLS12"}}))
        self.assertEqual(live_routes(result.config), [])
        self.assertIn("traefik-tls-options-scope", codes(report, "error"))
        self.assertIn("traefik-controls-unverified", codes(report, "error"))
        [https] = [spec for spec in plan.routes if spec.requires_tls]
        self.assertTrue(any("global 'default' TLS handshake policy" in reason for reason in https.refusals))

    def test_plaintext_only_input_ignores_tls_options(self):
        result, report, _plan = asserted(self._doc({"plain": self._router("p.example.test", "/p")},
                                                   {"relaxed": {"minVersion": "VersionTLS12"}}))
        self.assertEqual(self._status(result, "=/p", "p.example.test"), "migrated")
        self.assertNotIn("traefik-tls-options-scope", codes(report))

    def test_builtin_default_without_tls_options_stays_supported(self):
        result, report, plan = asserted(self._doc({
            "a": self._router("a.example.test", "/a", {}),
            "b": self._router("b.example.test", "/b", {"options": "default"}),
        }))
        self.assertEqual(sorted(live_routes(result.config)),
                         [("=/a", ["a.example.test"]), ("=/b", ["b.example.test"])])
        self.assertTrue(result.tls_only)
        self.assertEqual(plan.settings.client_ca_paths, [])
        self.assertIn("traefik-tls-default-options", codes(report, "info"))
        self.assertNotIn("traefik-tls-options-scope", codes(report))


class TraefikInputControlsTest(unittest.TestCase):
    """Controls outside the dynamic input (static entryPoints, other providers' TLS options and routers): no
    forwarding without the operator's explicit statement that the input includes every effective control."""

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
                self.assertIn("traefik-controls-unverified", codes(report, "error"))
                self.assertNotIn("traefik-controls-asserted", codes(report))
                self.assertTrue(any("static entryPoints" in reason for reason in plan.routes[0].refusals))

    def test_default_refusal_names_the_remediation_without_calling_it_validation(self):
        _result, report, _plan = migrate("traefik", self._doc({"r": self.ROUTERS["plaintext, no entryPoints"]}))
        [caveat] = [c for c in report.caveats if c.code == "traefik-controls-unverified"]
        self.assertEqual(caveat.severity, "error")
        self.assertIn(CONTROLS_ASSERTION_FLAG, caveat.action)
        self.assertIn("cannot verify", caveat.action)
        # The operator checklist names every kind of control outside the input, not only static entryPoints.
        for item in ("static entryPoints", "omitted TLS options", "'default' TLS options", "SNI option conflicts",
                     "competing routers"):
            self.assertIn(item, caveat.action)
        self.assertNotIn("p.example.test", caveat.message + caveat.action)

    def test_tls_router_without_options_requires_the_statement(self):
        # A TLS router that names no options uses the 'default' TLS options, which another provider may define
        # outside the input. Without the statement it is refused; with it Traefik's built-in default is taken, and
        # the report says that rests on the operator's statement.
        router = {"r": self.ROUTERS["explicit tls"]}
        result, report, _plan = migrate("traefik", self._doc(router))
        self.assertEqual(self._status(one_proxy(self, result.config, "=/p", "p.example.test")), "refused")
        self.assertIn("traefik-controls-unverified", codes(report, "error"))
        result, report, plan = asserted(self._doc(router))
        self.assertEqual(self._status(one_proxy(self, result.config, "=/p", "p.example.test")), "migrated")
        self.assertEqual(plan.settings.client_ca_paths, [])
        [note] = [c for c in report.caveats if c.code == "traefik-tls-default-options"]
        self.assertIn(CONTROLS_ASSERTION_FLAG, note.message)

    def test_default_refuses_the_real_fixtures(self):
        for name, fmt in (("dynamic.yaml", "yaml"), ("dynamic.toml", "toml")):
            with self.subTest(name):
                result, report, _plan = migrate("traefik", read_fixture("traefik", name), fmt=fmt)
                assert_structurally_valid(self, result.config)
                self.assertEqual(live_routes(result.config), [])
                self.assertEqual(result.config["upstreams"], [])
                self.assertIn("traefik-controls-unverified", codes(report, "error"))

    def test_assertion_restores_the_dynamic_mapping(self):
        for label, router in self.ROUTERS.items():
            with self.subTest(label):
                result, report, _plan = asserted(self._doc({"r": router}))
                self.assertEqual(self._status(one_proxy(self, result.config, "=/p", "p.example.test")), "migrated")
                self.assertNotIn("traefik-controls-unverified", codes(report))
                self.assertIn("traefik-controls-asserted", codes(report, "warning"))
                # The router's own tls block still decides the frontend: HTTPS-only output for the tls router.
                self.assertEqual(result.tls_only, "tls" in router)

    def test_assertion_is_reported_as_unverified(self):
        _result, report, _plan = asserted(self._doc({"r": self.ROUTERS["plaintext, no entryPoints"]}))
        [caveat] = [c for c in report.caveats if c.code == "traefik-controls-asserted"]
        self.assertIn(CONTROLS_ASSERTION_FLAG, caveat.message)
        self.assertIn("cannot verify", caveat.message)
        self.assertIn("includes every effective routing, TLS and access control", caveat.message)

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
        self.assertNotIn("traefik-controls-asserted", codes(report))

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


class TraefikCanonicalSchemaTest(unittest.TestCase):
    """Traefik matches typed field names case-insensitively; this converter reads canonical spellings only.

    A typed field spelled in another letter case, or given in several letter cases, rejects the whole input (exit 3,
    nothing built), with or without the operator's statement. Resource names stay case-sensitive and are never folded.

    Benign synthetic inputs only: one ordinary HTTPS router under the default TLS options (client CA, sniStrict off),
    reached through a chain to a headers middleware and a load balancer with a serversTransport.
    """

    CA = "/etc/test-only/client-ca.pem"  # synthetic paths; never read by the tool
    BACKEND_CA = "/etc/test-only/backend-ca.pem"

    def _base(self):
        return {
            "http": {
                "routers": {"router-zq": {"rule": "Host(`c.example.test`) && Path(`/c`)", "service": "svc-zq",
                                          "middlewares": ["guard-zq"], "tls": {"options": "default"}}},
                "middlewares": {"guard-zq": {"chain": {"middlewares": ["hosts-zq"]}},
                                "hosts-zq": {"headers": {"allowedHosts": ["c.example.test"]}}},
                "services": {"svc-zq": {"loadBalancer": {"servers": [{"url": "https://s.internal:443"}],
                                                         "serversTransport": "transport-zq"}}},
                "serversTransports": {"transport-zq": {"rootCAs": [self.BACKEND_CA]}},
            },
            "tls": {
                "certificates": [{"certFile": "/etc/test-only/server.crt", "keyFile": "/etc/test-only/server.key"}],
                "options": {"default": {"clientAuth": {"caFiles": [self.CA],
                                                       "clientAuthType": "RequireAndVerifyClientCert"},
                                        "sniStrict": False}},
            },
        }

    @staticmethod
    def _parent(doc, path):
        node = doc
        for key in path:  # mapping keys, or list indexes
            node = node[key]
        return node

    # (label, path to the mapping holding the field, canonical key, other spelling, expected value-free path)
    RESPELLED = (
        ("top-level http section", (), "http", "HTTP", "http"),
        ("top-level tls section", (), "tls", "Tls", "tls"),
        ("http routers", ("http",), "routers", "Routers", "http.routers"),
        ("http middlewares", ("http",), "middlewares", "Middlewares", "http.middlewares"),
        ("http services", ("http",), "services", "Services", "http.services"),
        ("http serversTransports", ("http",), "serversTransports", "serverstransports", "http.serversTransports"),
        ("router rule", ("http", "routers", "router-zq"), "rule", "Rule", "http.routers.<name>.rule"),
        ("router tls", ("http", "routers", "router-zq"), "tls", "TLS", "http.routers.<name>.tls"),
        ("router middlewares", ("http", "routers", "router-zq"), "middlewares", "Middlewares",
         "http.routers.<name>.middlewares"),
        ("router tls options", ("http", "routers", "router-zq", "tls"), "options", "Options",
         "http.routers.<name>.tls.options"),
        ("tls options section", ("tls",), "options", "Options", "tls.options"),
        ("tls certificate file", ("tls", "certificates", 0), "certFile", "CertFile", "tls.certificates[].certFile"),
        ("default clientAuth", ("tls", "options", "default"), "clientAuth", "ClientAuth",
         "tls.options.<name>.clientAuth"),
        ("clientAuth caFiles", ("tls", "options", "default", "clientAuth"), "caFiles", "CAFiles",
         "tls.options.<name>.clientAuth.caFiles"),
        ("clientAuth type", ("tls", "options", "default", "clientAuth"), "clientAuthType", "clientauthtype",
         "tls.options.<name>.clientAuth.clientAuthType"),
        ("default sniStrict", ("tls", "options", "default"), "sniStrict", "SniStrict", "tls.options.<name>.sniStrict"),
        ("service loadBalancer", ("http", "services", "svc-zq"), "loadBalancer", "LoadBalancer",
         "http.services.<name>.loadBalancer"),
        ("loadBalancer servers", ("http", "services", "svc-zq", "loadBalancer"), "servers", "Servers",
         "http.services.<name>.loadBalancer.servers"),
        ("loadBalancer serversTransport", ("http", "services", "svc-zq", "loadBalancer"), "serversTransport",
         "ServersTransport", "http.services.<name>.loadBalancer.serversTransport"),
        ("transport rootCAs", ("http", "serversTransports", "transport-zq"), "rootCAs", "RootCAs",
         "http.serversTransports.<name>.rootCAs"),
        ("middleware type chain", ("http", "middlewares", "guard-zq"), "chain", "Chain",
         "http.middlewares.<name>.chain"),
        ("chain middlewares", ("http", "middlewares", "guard-zq", "chain"), "middlewares", "Middlewares",
         "http.middlewares.<name>.chain.middlewares"),
        ("middleware type headers", ("http", "middlewares", "hosts-zq"), "headers", "Headers",
         "http.middlewares.<name>.headers"),
        ("headers allowedHosts", ("http", "middlewares", "hosts-zq", "headers"), "allowedHosts", "AllowedHosts",
         "http.middlewares.<name>.headers.allowedHosts"),
    )

    def _assert_rejected(self, doc, expected_path):
        text = yaml.safe_dump(doc)
        for controls_asserted in (True, False):
            with self.subTest(controls_asserted=controls_asserted):
                with self.assertRaises(InputError) as caught:
                    migrate("traefik", text, traefik_controls_asserted=controls_asserted)
                message = str(caught.exception)
                self.assertIn(expected_path, message)
                # Value-free: canonical names and placeholders only, never input values or resource names.
                for value in (self.CA, self.BACKEND_CA, "c.example.test", "-zq"):
                    self.assertNotIn(value, message)

    def test_canonical_input_converts_with_every_control(self):
        doc = self._base()
        self.assertEqual(typed_field_problems(doc), [])
        result, report, plan = asserted(yaml.safe_dump(doc))
        proxy = one_proxy(self, result.config, "=/c", "c.example.test")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(proxy["backend_tls_server_ca_cert_path"], self.BACKEND_CA)
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])
        self.assertTrue(result.tls_only)
        self.assertNotIn("traefik-tls-options-scope", codes(report))

    def test_existing_fixtures_use_canonical_spellings(self):
        self.assertEqual(typed_field_problems(yaml.safe_load(read_fixture("traefik", "dynamic.yaml"))), [])

    def test_other_letter_case_rejects_the_whole_input(self):
        for label, path, canonical, other, expected in self.RESPELLED:
            with self.subTest(label):
                doc = self._base()
                parent = self._parent(doc, path)
                parent[other] = parent.pop(canonical)
                self.assertIn(expected, typed_field_problems(doc))
                self._assert_rejected(doc, expected)

    def test_case_equivalent_duplicates_reject_the_whole_input(self):
        cases = (
            ("router tls given twice", ("http", "routers", "router-zq"), "TLS", {}, "http.routers.<name>.tls"),
            ("sniStrict given twice", ("tls", "options", "default"), "SniStrict", True,
             "tls.options.<name>.sniStrict"),
            ("http section given twice", (), "Http", {}, "http"),
            ("middleware type given twice", ("http", "middlewares", "hosts-zq"), "Headers", {},
             "http.middlewares.<name>.headers"),
        )
        for label, path, other, value, expected in cases:
            with self.subTest(label):
                doc = self._base()
                self._parent(doc, path)[other] = value
                self._assert_rejected(doc, expected)

    def test_resource_names_stay_case_sensitive(self):
        # Router, service, middleware and serversTransport names that differ only in letter case are separate
        # resources: none is folded, rejected or merged, and references resolve by exact name only.
        doc = {"http": {
            "routers": {
                "Api": {"rule": "Host(`u.example.test`) && Path(`/u`)", "service": "Backend"},
                "api": {"rule": "Host(`l.example.test`) && Path(`/l`)", "service": "backend",
                        "middlewares": ["Tag-Request"]},
                "mismatch": {"rule": "Host(`m.example.test`) && Path(`/m`)", "service": "backend",
                             "middlewares": ["tag-request"]},
            },
            "middlewares": {"Tag-Request": {"headers": {"customRequestHeaders": {"X-Migration-Test": "lower"}}}},
            "services": {
                "Backend": {"loadBalancer": {"servers": [{"url": "https://upper.internal:443"}],
                                             "serversTransport": "Pinned"}},
                "backend": {"loadBalancer": {"servers": [{"url": "http://lower.internal:80"}]}},
            },
            "serversTransports": {"Pinned": {"rootCAs": [self.BACKEND_CA]}},
        }}
        self.assertEqual(typed_field_problems(doc), [])
        result, _report, _plan = asserted(yaml.safe_dump(doc))
        upper = one_proxy(self, result.config, "=/u", "u.example.test")
        lower = one_proxy(self, result.config, "=/l", "l.example.test")
        self.assertEqual([p["labels"]["ferrum-migration/status"] for p in (upper, lower)], ["migrated", "migrated"])
        self.assertEqual((upper["backend_host"], upper["backend_tls_server_ca_cert_path"]),
                         ("upper.internal", self.BACKEND_CA))
        self.assertEqual(lower["backend_host"], "lower.internal")
        rules = plugin(self, result.config, lower, "request_transformer")["config"]["rules"]
        self.assertIn({"operation": "update", "target": "header", "key": "x-migration-test", "value": "lower"}, rules)
        # 'tag-request' is not 'Tag-Request': the reference is undefined, so that router is refused.
        mismatch = one_proxy(self, result.config, "=/m", "m.example.test")
        self.assertEqual(mismatch["labels"]["ferrum-migration/status"], "refused")

    def test_tls_option_and_store_names_stay_case_sensitive(self):
        router = {"rule": "Host(`t.example.test`) && Path(`/t`)", "service": "s", "tls": {}}
        service = {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}
        # 'Default' is a named TLS options set, not the global default: HTTPS is refused through the handshake scope,
        # and its settings are not read as the default's.
        doc = {"http": {"routers": {"r": router}, "services": service},
               "tls": {"options": {"Default": {"sniStrict": True}}}}
        self.assertEqual(typed_field_problems(doc), [])
        result, report, _plan = asserted(yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result.config, "=/t", "t.example.test")["labels"]["ferrum-migration/status"],
                         "refused")
        self.assertIn("traefik-tls-options-scope", codes(report, "error"))
        self.assertNotIn("traefik-sni-strict", codes(report))
        # Only the store named exactly 'default' supplies the default certificate.
        pair = {"certFile": "/etc/test-only/server.crt", "keyFile": "/etc/test-only/server.key"}
        for store, expected in (("default", [("/etc/test-only/server.crt", "/etc/test-only/server.key")]),
                                ("Default", [])):
            with self.subTest(store=store):
                doc = {"http": {"routers": {"r": router}, "services": service},
                       "tls": {"stores": {store: {"defaultCertificate": pair}}}}
                self.assertEqual(typed_field_problems(doc), [])
                _result, _report, plan = asserted(yaml.safe_dump(doc))
                self.assertEqual(plan.settings.frontend_cert_pairs, expected)


class TraefikParentRefsTest(unittest.TestCase):
    """Router ``parentRefs`` (Traefik v3.6 multi-layer routing) is never projected as an independent root route.

    Absent or exactly ``[]``: an ordinary root router. Anything else on any router of the input as written (a nonempty
    list, an explicit null, another shape) rejects the whole input (exit 3) before any route, report entry or profile
    setting is built, with or without the operator's statement. Benign structural inputs only: plain routers and a
    synthetic load balancer; no parent middleware or inherited routing is modelled.
    """

    SERVICE = {"svc-zq": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}
    VALUES = ("parent-zq", "c.example.test", "s.internal", "svc-zq", "router-zq", "sibling-zq")

    def _router(self, parent_refs=..., path="/c"):
        router = {"rule": f"Host(`c.example.test`) && Path(`{path}`)", "service": "svc-zq"}
        if parent_refs is not ...:
            router["parentRefs"] = parent_refs
        return router

    def _doc(self, routers):
        return {"http": {"routers": routers, "services": self.SERVICE}}

    def _assert_rejected(self, doc, fmt="yaml", text=None):
        text = text if text is not None else (json.dumps(doc) if fmt == "json" else yaml.safe_dump(doc))
        for controls_asserted in (True, False):
            with self.subTest(controls_asserted=controls_asserted):
                report = Report("traefik", "test-input")
                context = SourceContext(report=report, limits=Limits(),
                                        traefik_controls_asserted=controls_asserted)
                with self.assertRaises(InputError) as caught:
                    translate(text, fmt, context)
                message = str(caught.exception)
                self.assertIn("http.routers.<name>.parentRefs", message)
                for value in self.VALUES:
                    self.assertNotIn(value, message)
                # Preflight: nothing was built or reported before the rejection.
                self.assertEqual(report.caveats, [])

    def test_absent_and_empty_list_stay_ordinary_roots(self):
        for label, parent_refs in (("absent", ...), ("empty list", [])):
            with self.subTest(label):
                doc = self._doc({"router-zq": self._router(parent_refs)})
                self.assertEqual(parent_refs_violations(doc), 0)
                self.assertEqual(typed_field_problems(doc), [])
                result, report, _plan = asserted(yaml.safe_dump(doc))
                proxy = one_proxy(self, result.config, "=/c", "c.example.test")
                self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
                assert_structurally_valid(self, result.config)
                self.assertIn("traefik-controls-asserted", codes(report, "warning"))

    def test_empty_list_is_accepted_in_json_and_toml(self):
        doc = self._doc({"router-zq": self._router([])})
        toml_text = textwrap.dedent("""\
            [http.routers.router-zq]
            rule = "Host(`c.example.test`) && Path(`/c`)"
            service = "svc-zq"
            parentRefs = []

            [[http.services.svc-zq.loadBalancer.servers]]
            url = "http://s.internal:80"
            """)
        for fmt, text in (("json", json.dumps(doc)), ("toml", toml_text)):
            with self.subTest(fmt=fmt):
                result, _report, _plan = asserted(text, fmt=fmt)
                self.assertEqual(live_routes(result.config), [("=/c", ["c.example.test"])])

    def test_nonempty_parent_refs_reject_the_whole_input(self):
        cases = {
            "one parent": ["parent-zq"],
            "several parents": ["parent-zq", "sibling-zq"],
            "provider-qualified parent": ["parent-zq@file"],
        }
        for label, parent_refs in cases.items():
            with self.subTest(label):
                doc = self._doc({"router-zq": self._router(parent_refs),
                                 "sibling-zq": self._router(path="/d")})
                self.assertEqual(parent_refs_violations(doc), 1)
                self._assert_rejected(doc)
                self._assert_rejected(doc, fmt="json")

    def test_nonempty_parent_refs_on_routers_that_would_be_skipped_still_reject(self):
        # Checked on every router as written: no rule, unparseable or unsatisfiable rules do not hide it.
        cases = {
            "router without a rule": {"service": "svc-zq", "parentRefs": ["parent-zq"]},
            "unparseable rule": {"rule": "Host(`c.example.test`", "service": "svc-zq", "parentRefs": ["parent-zq"]},
            "unsatisfiable rule": {"rule": "Host(`c.example.test`) && Host(`d.example.test`)", "service": "svc-zq",
                                   "parentRefs": ["parent-zq"]},
        }
        for label, router in cases.items():
            with self.subTest(label):
                self._assert_rejected(self._doc({"router-zq": self._router(), "sibling-zq": router}))

    def test_null_and_malformed_parent_refs_reject_the_whole_input(self):
        cases = {
            "explicit null": None,
            "bare string": "parent-zq",
            "empty string": "",
            "mapping": {"name": "parent-zq"},
            "empty mapping": {},
            "boolean": False,
            "number": 0,
            "list with an empty name": [""],
            "list with a null": [None],
            "list with a non-string": [1],
            "nested list": [[]],
        }
        for label, parent_refs in cases.items():
            with self.subTest(label):
                doc = self._doc({"router-zq": self._router(parent_refs)})
                self.assertEqual(parent_refs_violations(doc), 1)
                self._assert_rejected(doc)

    def test_rejection_precedes_every_other_section(self):
        # A tcp section would normally add a report entry; the preflight runs first, so nothing is reported.
        doc = self._doc({"router-zq": self._router(["parent-zq"])})
        doc["tcp"] = {"routers": {}}
        self._assert_rejected(doc)

    def test_canonical_spelling_gate_still_covers_parent_refs_variants(self):
        # Other letter cases are rejected by the canonical schema gate, even with an empty-list value.
        for other in ("ParentRefs", "parentrefs", "PARENTREFS", "parentREFS"):
            with self.subTest(other=other):
                router = self._router()
                router[other] = []
                doc = self._doc({"router-zq": router})
                self.assertIn("http.routers.<name>.parentRefs", typed_field_problems(doc))
                for controls_asserted in (True, False):
                    with self.assertRaises(InputError) as caught:
                        migrate("traefik", yaml.safe_dump(doc), traefik_controls_asserted=controls_asserted)
                    self.assertIn("http.routers.<name>.parentRefs", str(caught.exception))
                    self.assertIn("letter case", str(caught.exception))
        # Given twice in different letter case, both empty: still rejected by the gate.
        router = self._router([])
        router["ParentRefs"] = []
        doc = self._doc({"router-zq": router})
        self.assertIn("http.routers.<name>.parentRefs", typed_field_problems(doc))
        with self.assertRaises(InputError):
            asserted(yaml.safe_dump(doc))
        # The helper folds the key too, in case it is ever called without the gate.
        router = self._router()
        router["ParentRefs"] = ["parent-zq"]
        self.assertEqual(parent_refs_violations(self._doc({"router-zq": router})), 1)


if __name__ == "__main__":
    unittest.main()
