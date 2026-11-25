import json
import textwrap
import unittest

import yaml

from helpers import assert_structurally_valid, codes, migrate, one_proxy, plugin, plugins_of, read_fixture, upstream_of


class KongFixtureTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, self.plan = migrate("kong", read_fixture("kong", "kong.yaml"))
        self.config = self.result.config

    def test_structure(self):
        assert_structurally_valid(self, self.config)

    def test_service_route_backend_and_timeouts(self):
        proxy = one_proxy(self, self.config, "/orders")
        self.assertEqual(proxy["allowed_methods"], ["GET", "POST"])
        self.assertEqual((proxy["backend_scheme"], proxy["backend_host"], proxy["backend_port"]),
                         ("http", "orders.internal", 8080))
        self.assertEqual(proxy["backend_path"], "/v1")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertFalse(proxy["preserve_host_header"])
        self.assertEqual(proxy["backend_connect_timeout_ms"], 5000)
        self.assertEqual(proxy["backend_read_timeout_ms"], 30000)
        self.assertEqual(proxy["retry"]["max_retries"], 3)

    def test_service_plugins_are_shared_route_plugin_is_scoped(self):
        proxy = one_proxy(self, self.config, "/orders")
        key_auth = plugin(self, self.config, proxy, "key_auth")
        self.assertEqual(key_auth["scope"], "proxy_group")
        self.assertEqual(key_auth["config"], {"key_location": "header:apikey", "hide_credentials": True})
        acl = plugin(self, self.config, proxy, "access_control")
        self.assertEqual(acl["config"], {"allowed_groups": ["engineering"]})
        rate = plugin(self, self.config, proxy, "rate_limiting")
        self.assertEqual(rate["scope"], "proxy")
        self.assertEqual(rate["config"]["limit_by"], "consumer")
        self.assertEqual(rate["config"]["limits"], [{"scope": "default", "requests_per_minute": 100}])

    def test_upstream_weights_health_and_trailing_slash(self):
        proxy = one_proxy(self, self.config, "/catalog", "shop.example.com")
        self.assertFalse(proxy["strip_listen_path"])
        upstream = upstream_of(self.config, proxy)
        self.assertEqual(upstream["algorithm"], "weighted_round_robin")
        self.assertEqual([(t["host"], t["port"], t["weight"]) for t in upstream["targets"]],
                         [("catalog-a.internal", 8080, 100), ("catalog-b.internal", 8080, 50)])
        self.assertEqual(upstream["health_checks"]["active"]["http_path"], "/healthz")
        bare = one_proxy(self, self.config, "=/catalog", "shop.example.com")
        self.assertEqual(plugin(self, self.config, bare, "request_termination")["config"]["status_code"], 404)

    def test_cors_and_transformer(self):
        proxy = one_proxy(self, self.config, "/catalog", "shop.example.com")
        cors = plugin(self, self.config, proxy, "cors")["config"]
        self.assertEqual(cors["allowed_origins"], ["https://shop.example.com"])
        self.assertEqual(cors["max_age"], 600)
        rules = plugin(self, self.config, proxy, "request_transformer")["config"]["rules"]
        self.assertIn({"operation": "remove", "target": "header", "key": "x-debug"}, rules)
        self.assertIn({"operation": "add", "target": "header", "key": "x-gateway", "value": "ferrum"}, rules)

    def test_untranslatable_plugin_becomes_fail_closed_placeholder(self):
        proxy = one_proxy(self, self.config, "/admin")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")
        names = [p["plugin_name"] for p in plugins_of(self.config, proxy)]
        self.assertEqual(names, ["request_termination"])
        self.assertEqual(plugins_of(self.config, proxy)[0]["config"]["status_code"], 503)
        self.assertIn("route-refused", codes(self.report, "error"))

    def test_prefix_divergence_guard_on_catch_all(self):
        # /admin is refused (oauth2); Kong sent /adminx to it, so /adminx must not reach the open "/" route either.
        root = one_proxy(self, self.config, "/")
        guards = [p for p in plugins_of(self.config, root) if p["plugin_name"] == "request_termination"]
        self.assertEqual([g["config"]["trigger"]["path_prefix"] for g in guards], ["/orders", "/admin"])

    def test_consumers_without_secrets(self):
        consumers = {c["username"]: c for c in self.config["consumers"]}
        self.assertEqual(consumers["alice"]["acl_groups"], ["engineering"])
        self.assertEqual(consumers["alice"]["custom_id"], "alice-001")
        self.assertNotIn("credentials", consumers["alice"])
        self.assertIn("credentials-withheld", codes(self.report, "warning"))
        self.assertIn("kong-basicauth-credentials", codes(self.report, "error"))
        dumped = yaml.safe_dump(self.config)
        self.assertNotIn("test-only-key-alice-0001", dumped)
        self.assertNotIn("test-only-password-hash-bob", dumped)

    def test_observability_plugin_omitted_safely(self):
        self.assertIn("kong-plugin-observability", codes(self.report, "info"))
        self.assertEqual([p for p in self.config["plugin_configs"] if p["scope"] == "global"], [])


class KongSecretsTest(unittest.TestCase):
    def test_include_secrets_only_in_resources_never_in_report(self):
        result, report, _plan = migrate("kong", read_fixture("kong", "kong.yaml"), include_secrets=True)
        consumers = {c["username"]: c for c in result.config["consumers"]}
        self.assertEqual(consumers["alice"]["credentials"], {"keyauth": [{"key": "test-only-key-alice-0001"}]})
        self.assertNotIn("credentials", consumers["bob"])
        self.assertIn("keyauth-weak", codes(report, "error"))
        self.assertEqual(result.secrets_emitted, 1)
        text = json.dumps([c.to_dict() for c in report.caveats])
        self.assertNotIn("test-only-key-alice-0001", text)
        self.assertNotIn("short-key", text)

    def test_duplicate_keys_are_not_migrated(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            consumers:
              - username: a
                keyauth_credentials: [{key: shared-test-key-000000001}]
              - username: b
                keyauth_credentials: [{key: shared-test-key-000000001}]
        """)
        result, report, _ = migrate("kong", text, include_secrets=True)
        self.assertTrue(all("credentials" not in c for c in result.config["consumers"]))
        self.assertIn("keyauth-duplicate", codes(report, "error"))

    def test_jwt_plugin_migrated_but_single_hmac_credential_withheld(self):
        # Kong selects the credential by its exact key; Ferrum resolves any consumer alias and accepts the
        # consumer-wide secret. Without a one-to-one selector contract the (synthetic) secret is never written,
        # while the route keeps jwt_auth (fail closed) and the consumer's key-auth credential is still migrated.
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:80
                routes: [{name: r, paths: [/jwt]}]
                plugins:
                  - name: jwt
                    config: {claims_to_verify: [exp], uri_param_names: []}
            consumers:
              - username: carol
                keyauth_credentials: [{key: test-only-key-carol-00000001}]
                jwt_secrets:
                  - {key: carol-issuer, algorithm: HS256, secret: test-only-jwt-secret-carol-000000000001}
                  - {key: other, algorithm: RS256, rsa_public_key: not-a-real-key}
              - username: dan
                jwt_secrets:
                  - {key: dan, algorithm: HS256, secret: test-only-jwt-secret-dan-00000000000001}
        """)
        result, report, _ = migrate("kong", text, include_secrets=True)
        proxy = one_proxy(self, result.config, "/jwt")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
        jwt = plugin(self, result.config, proxy, "jwt_auth")["config"]
        self.assertEqual(jwt["consumer_claim_field"], "iss")
        self.assertEqual(jwt["algorithm"], "HS256")
        self.assertTrue(jwt["require_exp"])
        consumers = {c["username"]: c for c in result.config["consumers"]}
        self.assertNotIn("custom_id", consumers["carol"])
        self.assertEqual(consumers["carol"]["credentials"], {"keyauth": [{"key": "test-only-key-carol-00000001"}]})
        # Even a key equal to the username is withheld: Ferrum would also accept the consumer's other aliases.
        self.assertNotIn("credentials", consumers["dan"])
        self.assertEqual(result.secrets_emitted, 1)
        self.assertNotIn("test-only-jwt-secret", json.dumps(result.config))
        self.assertIn("kong-jwt-credential", codes(report, "error"))
        withheld = [c.ref for c in report.caveats if c.code == "kong-jwt-credential-withheld"]
        self.assertEqual(sorted(withheld), ["kong consumer 'carol'", "kong consumer 'dan'"])
        self.assertNotIn("test-only-jwt-secret", json.dumps([c.to_dict() for c in report.caveats]))

    def test_several_jwt_credentials_on_one_consumer_are_withheld(self):
        # Kong binds each key claim to its own credential's secret; Ferrum would accept either secret for either
        # key once both sit on one consumer, so neither synthetic secret may be written.
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:80
                routes: [{name: r, paths: [/jwt]}]
                plugins:
                  - name: jwt
                    config: {claims_to_verify: [exp], uri_param_names: []}
            consumers:
              - username: erin
                jwt_secrets:
                  - {key: erin, algorithm: HS256, secret: test-only-jwt-secret-erin-primary-000001}
                  - {key: erin-partner, algorithm: HS256, secret: test-only-jwt-secret-erin-partner-00001}
        """)
        result, report, _ = migrate("kong", text, include_secrets=True)
        erin = result.config["consumers"][0]
        self.assertNotIn("credentials", erin)
        self.assertNotIn("custom_id", erin)
        self.assertEqual(result.secrets_emitted, 0)
        self.assertIn("kong-jwt-multiple-credentials", codes(report, "error"))
        self.assertNotIn("test-only-jwt-secret-erin", json.dumps(result.config))


class KongAuthCompositionTest(unittest.TestCase):
    # Static conversion-policy checks only (which routes are emitted live, refused or unchanged); no traffic.
    def test_service_and_route_auth_methods_together_are_refused(self):
        # Kong requires both methods here and authenticates the consumer of the plugin that runs last; Ferrum's
        # composition and principal selection differ, and withholding the JWT secret does not make the remaining
        # key-auth path equivalent. The single-method route on the same service stays as before.
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                plugins:
                  - name: key-auth
                    config: {key_names: [apikey], key_in_query: false}
                routes:
                  - name: both
                    paths: [/both]
                    plugins:
                      - name: jwt
                        config: {claims_to_verify: [exp], uri_param_names: []}
                  - name: key-only
                    paths: [/key]
        """)
        result, report, _ = migrate("kong", text)
        assert_structurally_valid(self, result.config)
        both = one_proxy(self, result.config, "/both")
        self.assertEqual(both["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual([p["plugin_name"] for p in plugins_of(result.config, both)], ["request_termination"])
        key_only = one_proxy(self, result.config, "/key")
        self.assertEqual(key_only["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugin(self, result.config, key_only, "key_auth")["scope"], "proxy_group")
        composition = [c.ref for c in report.caveats if c.code == "kong-auth-composition"]
        self.assertEqual(composition, ["kong route 'both'"])

    def test_global_auth_combined_with_another_scoped_method_is_refused(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: basic-auth
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: r
                    paths: [/r]
                    plugins:
                      - name: key-auth
                        config: {key_names: [apikey], key_in_query: false}
        """)
        result, report, _ = migrate("kong", text)
        self.assertEqual(one_proxy(self, result.config, "/r")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("kong-auth-composition", codes(report, "error"))

    def test_scoped_plugin_replacing_global_plugin_of_same_method_stays_single_method(self):
        # Kong's most specific key-auth wins, and Ferrum's proxy-scoped key_auth replaces the global key_auth of
        # the same name: one method in both, so the route migrates as before.
        text = textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: key-auth
                config: {key_names: [apikey]}
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: r
                    paths: [/r]
                    plugins:
                      - name: key-auth
                        config: {key_names: [x-key], key_in_query: false}
        """)
        result, report, _ = migrate("kong", text)
        proxy = one_proxy(self, result.config, "/r")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugin(self, result.config, proxy, "key_auth")["config"]["key_location"], "header:x-key")
        self.assertNotIn("kong-auth-composition", codes(report))


class KongFailClosedTest(unittest.TestCase):
    def test_header_matched_route_poisons_more_specific_overlaps(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - {name: special, paths: [/api], headers: {x-tenant: [gold]}}
                  - {name: deep, paths: [/api/v2]}
                  - {name: other, paths: [/other]}
        """)
        result, report, _ = migrate("kong", text)
        api = one_proxy(self, result.config, "/api")
        deep = one_proxy(self, result.config, "/api/v2")
        self.assertEqual(api["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(deep["labels"]["ferrum-migration/status"], "refused")
        other = one_proxy(self, result.config, "/other")
        self.assertEqual(other["labels"]["ferrum-migration/status"], "migrated")

    def test_global_untranslatable_plugin_refuses_everything(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/x]}]
            plugins:
              - name: openid-connect
                config: {issuer: https://idp.example}
        """)
        result, report, _ = migrate("kong", text)
        proxy = one_proxy(self, result.config, "/x")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("kong-plugin-refused", codes(report, "error"))

    def test_https_only_route_needs_tls_only(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - {name: secure, paths: [/secure], protocols: [https]}
                  - {name: plain, paths: [/plain]}
        """)
        result, report, _ = migrate("kong", text)
        self.assertEqual(one_proxy(self, result.config, "/secure")["labels"]["ferrum-migration/status"], "refused")
        self.assertFalse(result.tls_only)
        result, report, _ = migrate("kong", text, tls_only=True)
        self.assertEqual(one_proxy(self, result.config, "/secure")["labels"]["ferrum-migration/status"], "migrated")
        self.assertTrue(result.tls_only)

    def test_consumer_scoped_plugin_quarantines_consumer(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            consumers:
              - username: dave
                keyauth_credentials: [{key: test-only-key-dave-000001}]
                plugins:
                  - name: rate-limiting
                    config: {minute: 1000}
        """)
        result, report, _ = migrate("kong", text, include_secrets=True)
        self.assertNotIn("credentials", result.config["consumers"][0])
        self.assertIn("kong-consumer-quarantined", codes(report, "error"))

    def test_vault_reference_refuses_plugin(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/v]}]
                plugins:
                  - name: request-transformer
                    config: {add: {headers: ["x-token:{vault://env/token}"]}}
        """)
        result, report, _ = migrate("kong", text)
        self.assertEqual(one_proxy(self, result.config, "/v")["labels"]["ferrum-migration/status"], "refused")
        self.assertNotIn("vault://env/token", json.dumps([c.to_dict() for c in report.caveats]))

    def test_replace_operation_is_refused_not_downgraded(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/r]}]
                plugins:
                  - name: request-transformer
                    config: {replace: {headers: ["x-user:anonymous"]}}
        """)
        result, _report, _ = migrate("kong", text)
        self.assertEqual(one_proxy(self, result.config, "/r")["labels"]["ferrum-migration/status"], "refused")

    def test_rate_limit_day_window_refused(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/d]}]
                plugins: [{name: rate-limiting, config: {minute: 10, day: 1000}}]
        """)
        result, _report, _ = migrate("kong", text)
        self.assertEqual(one_proxy(self, result.config, "/d")["labels"]["ferrum-migration/status"], "refused")

    def test_https_backend_verification_is_enabled_by_default(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: https://secure.internal:8443
                routes: [{name: r, paths: [/t]}]
        """)
        result, report, _ = migrate("kong", text)
        self.assertIs(one_proxy(self, result.config, "/t")["backend_tls_verify_server_cert"], True)
        self.assertIn("backend-tls-verify-enabled", codes(report, "warning"))
        self.assertNotIn("backend-tls-unverified", codes(report))

    def test_restricted_ca_certificates_refuse_routes_instead_of_default_trust_store(self):
        # Synthetic CA reference only (no certificate material): the restricted trust set cannot be emitted,
        # so the route must fail closed rather than verify against Ferrum's broader default trust store.
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: pinned
                url: https://pinned.internal:8443
                tls_verify: true
                ca_certificates: ["00000000-0000-4000-8000-000000000001"]
                routes: [{name: pinned-route, paths: [/pinned/]}]
              - name: public
                url: https://public.internal:8443
                tls_verify: true
                routes: [{name: public-route, paths: [/public/]}]
            ca_certificates:
              - id: "00000000-0000-4000-8000-000000000001"
        """)
        result, report, _ = migrate("kong", text)
        pinned = one_proxy(self, result.config, "/pinned")
        self.assertEqual(pinned["labels"]["ferrum-migration/status"], "refused")
        self.assertNotIn("backend_tls_server_ca_cert_path", pinned)
        self.assertEqual([p["config"]["status_code"] for p in plugins_of(result.config, pinned)], [503])
        self.assertIn("kong-ca-certificates", codes(report, "error"))
        public = one_proxy(self, result.config, "/public")
        self.assertEqual(public["labels"]["ferrum-migration/status"], "migrated")
        self.assertIs(public["backend_tls_verify_server_cert"], True)


class KongPrefixSemanticsTest(unittest.TestCase):
    def test_string_prefix_path_siblings_are_reported_not_widened(self):
        # Kong's traditional routers match paths as plain string prefixes: /api also forwarded /apix.
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api]}]
        """)
        result, report, _ = migrate("kong", text)
        self.assertEqual([p.get("listen_path") for p in result.config["proxies"]], ["/api"])
        self.assertIn("prefix-string-siblings", codes(report, "error"))

    def test_equivalent_unstripped_fallback_needs_no_sibling_report(self):
        # /apix falls back to the / route with the same service and policy, so Ferrum forwards it identically.
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - {name: root, paths: [/], strip_path: false}
                  - {name: api, paths: [/api], strip_path: false}
        """)
        _result, report, _ = migrate("kong", text)
        self.assertNotIn("prefix-string-siblings", codes(report))
        self.assertFalse(report.has_errors, [c.to_dict() for c in report.caveats if c.severity == "error"])


class KongHardeningTest(unittest.TestCase):
    def test_malformed_healthcheck_timeout_and_bool_statuses_do_not_crash_or_emit_invalid(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            upstreams:
              - name: pool
                targets: [{target: "10.0.0.1:8080", weight: 100}]
                healthchecks:
                  active:
                    timeout: "not-a-number"
                    healthy: {interval: 5, http_statuses: [true, 999]}
                  passive:
                    unhealthy: {http_failures: 3, http_statuses: [false, 502]}
            services:
              - name: s
                host: pool
                routes: [{name: r, paths: [/api/]}]
        """)
        result, _report, _ = migrate("kong", text)
        assert_structurally_valid(self, result.config)
        hc = result.config["upstreams"][0]["health_checks"]
        self.assertEqual(hc["active"]["timeout_ms"], 1000)
        self.assertNotIn("healthy_status_codes", hc["active"])
        self.assertNotIn("unhealthy_status_codes", hc["passive"])

    def test_malformed_protocols_and_plugin_lists_fail_closed(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: bad-proto
                    paths: [/p/]
                    protocols: [123]
                  - name: bad-keyauth
                    paths: [/k/]
                    plugins:
                      - name: key-auth
                        config: {key_names: [123]}
                  - name: bad-jwt
                    paths: [/j/]
                    plugins:
                      - name: jwt
                        config: {claims_to_verify: 123}
                  - name: bad-rt
                    paths: [/t/]
                    plugins:
                      - name: request-transformer
                        config: {remove: {headers: [123]}}
                  - name: bad-redirect
                    paths: [/r/]
                    plugins:
                      - name: redirect
                        config: {status_code: 999, location: "https://example.test/"}
        """)
        result, _report, _ = migrate("kong", text)
        assert_structurally_valid(self, result.config)
        for path in ("/p", "/k", "/j", "/t", "/r"):
            self.assertEqual(one_proxy(self, result.config, path)["labels"]["ferrum-migration/status"], "refused", path)
        # Top-level alternation regex refuses instead of mis-anchoring only the last branch.
        alt_text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: bad-alt-regex
                    paths: ["~/a|/b"]
                    strip_path: false
        """)
        alt_res, _alt_rep, _ = migrate("kong", alt_text)
        assert_structurally_valid(self, alt_res.config)
        self.assertEqual(one_proxy(self, alt_res.config, "~/a|/b")["labels"]["ferrum-migration/status"], "refused")
        # Untranslatable CORS (malformed origins, regex origins, preflight_continue: true, host-only/bare-IPv6
        # origins, or cors combined with request-termination) refuses fail-closed; single-origin default/leading-zero
        # ports wrap as {'exact': ...}, while multi-origin canonical lowercase URLs stay plain strings (matching
        # Kong's url.parse normalization); explicit methods: [] stays empty and headers: [] warns + defaults.
        cors_text = textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: cors
                config: {origins: ["https://global.example.test"], credentials: true}
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: bad-cors-local
                    paths: [/c/]
                    plugins:
                      - name: cors
                        config: {origins: [123]}
                  - name: bad-cors-passthrough
                    paths: [/cp/]
                    plugins:
                      - name: cors
                        config: {origins: ["https://ok.example.test"], preflight_continue: true}
                  - name: bad-cors-host-only
                    paths: [/host/]
                    plugins:
                      - name: cors
                        config: {origins: ["example.com"]}
                  - name: bad-cors-bare-v6
                    paths: [/v6/]
                    plugins:
                      - name: cors
                        config: {origins: ["http://::1"]}
                  - name: bad-cors-term
                    paths: [/term/]
                    plugins:
                      - name: cors
                        config: {origins: ["https://ok.example.test"]}
                      - name: request-termination
                        config: {status_code: 410, message: gone}
                  - name: null-and-default-port
                    paths: [/exact/]
                    plugins:
                      - name: cors
                        config: {origins: ["null", "https://app.example.test:443", "https://app.example.test:08443"], methods: [], headers: [], credentials: false}
                  - name: single-leading-zero-port
                    paths: [/zport/]
                    plugins:
                      - name: cors
                        config: {origins: ["https://app.example.test:08443"], headers: [X-App], credentials: false}
                  - name: inherits-global
                    paths: [/g/]
        """)
        cors_res, _cors_rep, _ = migrate("kong", cors_text)
        assert_structurally_valid(self, cors_res.config)
        for refused_path in ("/c", "/cp", "/host", "/v6", "/term"):
            self.assertEqual(one_proxy(self, cors_res.config, refused_path)["labels"]["ferrum-migration/status"],
                             "refused", refused_path)
        self.assertFalse(any(p["plugin_name"] == "cors" and p["scope"] == "global"
                             for p in cors_res.config["plugin_configs"]))
        exact_p = one_proxy(self, cors_res.config, "/exact")
        exact_cors = plugin(self, cors_res.config, exact_p, "cors")["config"]
        self.assertEqual(exact_cors["allowed_origins"],
                         [{"exact": "null"}, "https://app.example.test:443",
                          {"exact": "https://app.example.test:08443"}])
        self.assertEqual(exact_cors["unmatched_preflights"], "ignore")
        self.assertNotIn("allowed_methods", exact_cors)
        self.assertIn("authorization", [h.lower() for h in exact_cors["allowed_headers"]])
        zport_p = one_proxy(self, cors_res.config, "/zport")
        self.assertEqual(plugin(self, cors_res.config, zport_p, "cors")["config"]["allowed_origins"],
                         [{"exact": "https://app.example.test:08443"}])
        g_p = one_proxy(self, cors_res.config, "/g")
        g_cors = plugin(self, cors_res.config, g_p, "cors")["config"]
        self.assertEqual(g_cors["allowed_origins"], ["https://global.example.test"])
        self.assertEqual(g_cors["unmatched_preflights"], "ignore")

        # Isolated explicit empty headers: [] emits kong-cors-headers warning; global request-termination + cors refuses.
        empty_hdr_res, empty_hdr_rep, _ = migrate("kong", textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: r
                    paths: [/eh/]
                    plugins:
                      - name: cors
                        config: {origins: ["https://ok.example.test"], headers: []}
        """))
        self.assertIn("kong-cors-headers", codes(empty_hdr_rep, "warning"))
        eh_cors = plugin(self, empty_hdr_res.config, one_proxy(self, empty_hdr_res.config, "/eh"), "cors")["config"]
        self.assertIn("authorization", [h.lower() for h in eh_cors["allowed_headers"]])
        glob_term_res, _glob_term_rep, _ = migrate("kong", textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: request-termination
                config: {status_code: 503, message: maintenance}
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: r
                    paths: [/gt/]
                    plugins:
                      - name: cors
                        config: {origins: ["https://ok.example.test"]}
        """))
        self.assertEqual(one_proxy(self, glob_term_res.config, "/gt")["labels"]["ferrum-migration/status"], "refused")

    def test_top_level_consumer_group_plugin_quarantines_group_members(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            consumer_groups:
              - name: vip
                consumers: [alice]
            consumers:
              - username: alice
                keyauth_credentials: [{key: "synthetic-key-at-least-16-chars"}]
            plugins:
              - name: rate-limiting
                consumer_group: vip
                config: {minute: 100}
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api/]}]
        """)
        result, report, _ = migrate("kong", text, include_secrets=True)
        self.assertEqual(result.secrets_emitted, 0)
        self.assertNotIn("credentials", result.config["consumers"][0])
        self.assertIn("kong-consumer-group", codes(report, "error"))

    def test_dbless_consumer_group_consumers_and_plugins_quarantine_members(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            consumer_groups:
              - id: grp-uuid-1
                name: gold
            consumers:
              - id: cons-uuid-1
                username: alice
                keyauth_credentials: [{key: "alice-synthetic-key-16-chars"}]
              - id: cons-uuid-2
                username: bob
                keyauth_credentials: [{key: "bob-synthetic-key-16-chars"}]
            consumer_group_consumers:
              - consumer: {id: cons-uuid-1}
                consumer_group: {id: grp-uuid-1}
            consumer_group_plugins:
              - name: rate-limiting
                consumer_group: gold
                config: {minute: 50}
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api/]}]
        """)
        result, report, _ = migrate("kong", text, include_secrets=True)
        by_user = {c["username"]: c for c in result.config["consumers"]}
        self.assertNotIn("credentials", by_user["alice"])
        self.assertIn("credentials", by_user["bob"])
        self.assertIn("kong-consumer-group", codes(report, "error"))

    def test_health_check_huge_timeout_and_empty_redirect_location(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            upstreams:
              - name: up
                targets: [{target: 10.0.0.1:8080, weight: 100}]
                healthchecks:
                  active:
                    timeout: 1e308
                    healthy: {interval: 99999, successes: 1}
                    unhealthy: {interval: 10, http_failures: 2}
            services:
              - name: s
                url: http://up:8080
                routes:
                  - name: ok
                    paths: [/ok/]
                  - name: bad-redir
                    paths: [/go/]
                    plugins:
                      - name: redirect
                        config: {location: "", status_code: 301}
        """)
        result, _report, _ = migrate("kong", text)
        assert_structurally_valid(self, result.config)
        active = result.config["upstreams"][0]["health_checks"]["active"]
        self.assertEqual(active["timeout_ms"], 86_400_000)
        self.assertEqual(active["interval_seconds"], 3600)
        self.assertEqual(one_proxy(self, result.config, "/go")["labels"]["ferrum-migration/status"], "refused")

    def test_nested_consumer_group_plugins_top_level_acls_and_huge_int_timeout(self):
        # Nested consumer_group_plugins + top-level consumer_group_consumers quarantines member;
        # top-level acls attaches deny-list group to consumer.
        text = textwrap.dedent("""
            _format_version: "3.0"
            consumer_groups:
              - id: grp-1
                name: gold
                consumer_group_plugins:
                  - name: rate-limiting
                    config: {minute: 10}
            consumers:
              - id: c-alice
                username: alice
                keyauth_credentials: [{key: "alice-synthetic-key-16-chars"}]
              - id: c-bob
                username: bob
                keyauth_credentials: [{key: "bob-synthetic-key-16-chars"}]
            consumer_group_consumers:
              - consumer: {id: c-alice}
                consumer_group: {id: grp-1}
            acls:
              - consumer: {id: c-bob}
                group: blocked
            plugins:
              - name: key-auth
                config: {}
              - name: acl
                config: {deny: [blocked]}
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api/]}]
        """)
        res, _rep, _ = migrate("kong", text, include_secrets=True)
        by_user = {c["username"]: c for c in res.config["consumers"]}
        self.assertNotIn("credentials", by_user["alice"])
        self.assertEqual(by_user["bob"]["acl_groups"], ["blocked"])

        # Unresolved consumer_group_consumers member fails closed on authenticated routes.
        unres = textwrap.dedent("""
            _format_version: "3.0"
            consumers:
              - username: alice
                keyauth_credentials: [{key: "alice-synthetic-key-16-chars"}]
            consumer_group_consumers:
              - consumer: {id: missing-consumer-uuid}
                consumer_group: gold
            plugins:
              - name: key-auth
                config: {}
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api/]}]
        """)
        unres_res, _unres_rep, _ = migrate("kong", unres, include_secrets=True)
        self.assertEqual(one_proxy(self, unres_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertNotIn("credentials", unres_res.config["consumers"][0])

        # Huge JSON integer timeout (10**309) does not abort; >2048-byte http_path omits active check cleanly.
        huge_doc = {
            "_format_version": "3.0",
            "upstreams": [
                {"name": "up1", "targets": [{"target": "10.0.0.1:8080", "weight": 100}],
                 "healthchecks": {"active": {"timeout": 10 ** 309, "http_path": "/health",
                                             "healthy": {"interval": 5, "successes": 1}}}},
                {"name": "up2", "targets": [{"target": "10.0.0.2:8080", "weight": 100}],
                 "healthchecks": {"active": {"timeout": 1, "http_path": "/" + "a" * 2048,
                                             "healthy": {"interval": 5, "successes": 1}}}},
            ],
            "services": [
                {"name": "s1", "url": "http://up1:8080", "routes": [{"name": "r1", "paths": ["/a/"]}]},
                {"name": "s2", "url": "http://up2:8080", "routes": [{"name": "r2", "paths": ["/b/"]}]},
            ],
        }
        import json
        huge_res, _huge_rep, _ = migrate("kong", json.dumps(huge_doc), fmt="json")
        assert_structurally_valid(self, huge_res.config)
        by_up = {u["name"]: u for u in huge_res.config["upstreams"]}
        self.assertEqual(by_up["up1"]["health_checks"]["active"]["timeout_ms"], 86_400_000)
        self.assertNotIn("health_checks", by_up["up2"])

        # Typed ACL {consumer: {id: id-a}} must NOT grant the group to another consumer whose custom_id == id-a,
        # and undeclared consumer_group in consumer_group_plugins must fail closed on authenticated routes.
        typed_acl = textwrap.dedent("""
            _format_version: "3.0"
            consumers:
              - id: id-a
                username: alice
                keyauth_credentials: [{key: "alice-synthetic-key-16-chars"}]
              - id: id-b
                username: bob
                custom_id: id-a
                keyauth_credentials: [{key: "bob-synthetic-key-16-chars"}]
            acls:
              - consumer: {id: id-a}
                group: vip
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api/]}]
        """)
        t_res, _t_rep, _ = migrate("kong", typed_acl, include_secrets=True)
        by_u = {c["username"]: c for c in t_res.config["consumers"]}
        self.assertEqual(by_u["alice"].get("acl_groups"), ["vip"])
        self.assertNotIn("acl_groups", by_u["bob"])

        undeclared_grp = textwrap.dedent("""
            _format_version: "3.0"
            consumers:
              - username: alice
                keyauth_credentials: [{key: "alice-synthetic-key-16-chars"}]
            consumer_group_plugins:
              - name: rate-limiting
                consumer_group: undeclared-group
                config: {minute: 5}
            plugins:
              - name: key-auth
                config: {}
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/api/]}]
        """)
        ug_res, _ug_rep, _ = migrate("kong", undeclared_grp, include_secrets=True)
        self.assertEqual(one_proxy(self, ug_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertNotIn("credentials", ug_res.config["consumers"][0])

        # Ambiguous/conflicting typed consumer ref ({id: id-a, username: bob}) or empty consumer ("") on a plugin
        # must never register globally; matched/all consumers are quarantined and authenticated routes fail closed.
        for bad_consumer in ("{id: id-a, username: bob}", '""'):
            with self.subTest(consumer=bad_consumer):
                ambig_plugin = textwrap.dedent(f"""
                    _format_version: "3.0"
                    consumers:
                      - id: id-a
                        username: alice
                        keyauth_credentials: [{{key: "alice-synthetic-key-16-chars"}}]
                      - id: id-b
                        username: bob
                        keyauth_credentials: [{{key: "bob-synthetic-key-16-chars"}}]
                    plugins:
                      - name: key-auth
                        config: {{}}
                      - name: rate-limiting
                        consumer: {bad_consumer}
                        config: {{minute: 5}}
                    services:
                      - name: s
                        url: http://s.internal:8080
                        routes: [{{name: r, paths: [/api/]}}]
                """)
                ap_res, ap_rep, _ = migrate("kong", ambig_plugin, include_secrets=True)
                self.assertEqual(one_proxy(self, ap_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
                self.assertIn("kong-consumer-quarantined", codes(ap_rep, "error"))
                for c in ap_res.config["consumers"]:
                    self.assertNotIn("credentials", c)


class KongExtendedPluginsAndConsumersTest(unittest.TestCase):
    def test_correlation_id_consumer_tags_and_fail_closed_plugins(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            consumers:
              - username: alice
                tags: [tier-gold, team-api, tier-gold, "{vault://env/secret}", "token=abc123", "api-key-prod"]
                hmacauth_credentials: [{username: alice-hmac, secret: test-only-hmac-secret}]
                oauth2_credentials: [{name: app, client_id: cid, client_secret: test-only-secret}]
                mtls_auth_credentials: [{subject_name: alice@example.test}]
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: ok
                    paths: [/ok/]
                    plugins:
                      - name: correlation-id
                        config: {header_name: X-Trace-ID, echo_downstream: true, generator: uuid#counter}
                  - name: bot-refused
                    paths: [/bot/]
                    plugins:
                      - name: bot-detection
                        config: {}
                  - name: grpc-web-refused
                    paths: [/grpc-web/]
                    plugins:
                      - name: grpc-web
                        config: {}
                  - name: cache-omitted
                    paths: [/cache/]
                    plugins:
                      - name: proxy-cache
                        config: {strategy: memory, cache_ttl: 60}
        """)
        result, report, _ = migrate("kong", text)
        assert_structurally_valid(self, result.config)

        # Free-form consumer tags are withheld by default (value-free warning) so UUID/credential-like tags can never
        # leak into labels; only migration provenance labels remain. Unsupported creds produce actionable errors.
        alice = result.config["consumers"][0]
        self.assertEqual(set(alice["labels"]), {"ferrum-migration/source", "ferrum-migration/ref"})
        dumped = json.dumps(result.config) + json.dumps([c.to_dict() for c in report.caveats])
        self.assertNotIn("test-only-hmac-secret", dumped)
        self.assertNotIn("test-only-secret", dumped)
        self.assertNotIn("vault://env/secret", dumped)
        self.assertNotIn("token=abc123", dumped)
        self.assertNotIn("api-key-prod", dumped)
        self.assertNotIn("tier-gold", dumped)
        self.assertIn("kong-consumer-tags-omitted", codes(report, "warning"))
        cred_errs = [c.message for c in report.caveats if c.code == "kong-credentials-unsupported"]
        self.assertEqual(len(cred_errs), 3)
        self.assertTrue(any("Draft-Cavage" in m for m in cred_errs))
        self.assertTrue(any("Authorization Server" in m for m in cred_errs))
        self.assertTrue(any("cert_field" in m for m in cred_errs))

        # Clean route emits correlation_id.
        ok = one_proxy(self, result.config, "/ok")
        self.assertEqual(ok["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugin(self, result.config, ok, "correlation_id")["config"],
                         {"header_name": "x-trace-id", "echo_downstream": True, "inbound_policy": "preserve"})
        self.assertIn("kong-correlation-id", codes(report, "warning"))

        # Fail-closed refusals for Kong bot-detection (different default list) and grpc-web (passes native gRPC).
        for path in ("/bot", "/grpc-web"):
            self.assertEqual(one_proxy(self, result.config, path)["labels"]["ferrum-migration/status"], "refused", path)

        # proxy-cache safely omitted (MIME allow-list mismatch / scoped override safety).
        cache_proxy = one_proxy(self, result.config, "/cache")
        self.assertEqual(cache_proxy["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugins_of(result.config, cache_proxy), [])
        self.assertIn("kong-plugin-omitted", codes(report, "warning"))

        # Global correlation-id is resolved per route so an omitted scoped override (e.g. reserved header_name
        # X-Geo-Country) never activates the global correlation-id header on that overridden route.
        scoped_cid = textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: correlation-id
                config: {header_name: X-Audit-ID, echo_downstream: true, generator: uuid}
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: inherit
                    paths: [/inherit/]
                  - name: overridden
                    paths: [/overridden/]
                    plugins:
                      - name: correlation-id
                        config: {header_name: X-Geo-Country, echo_downstream: true, generator: uuid}
        """)
        sc_res, sc_rep, _ = migrate("kong", scoped_cid)
        inherit_p = one_proxy(self, sc_res.config, "/inherit")
        override_p = one_proxy(self, sc_res.config, "/overridden")
        self.assertEqual(plugin(self, sc_res.config, inherit_p, "correlation_id")["config"],
                         {"header_name": "x-audit-id", "echo_downstream": True, "inbound_policy": "preserve"})
        self.assertEqual(plugins_of(sc_res.config, override_p), [])
        self.assertFalse(any(p["plugin_name"] == "correlation_id" and p["scope"] == "global"
                             for p in sc_res.config["plugin_configs"]))
        self.assertIn("kong-correlation-id", codes(sc_rep, "warning"))

        # Restricted-protocol global correlation-id (https only): omitted with warning on all HTTP/HTTPS routes
        # because Kong's plugin iterator qualifies by subsystem and Ferrum correlation_id rejects triggers.
        proto_cid = textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: correlation-id
                protocols: [https]
                config: {header_name: X-Tls-ID, echo_downstream: false, generator: uuid}
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: plain
                    protocols: [http]
                    paths: [/plain/]
                  - name: both
                    protocols: [http, https]
                    paths: [/both/]
                  - name: tls
                    protocols: [https]
                    paths: [/tls/]
        """)
        pc_res, pc_rep, _ = migrate("kong", proto_cid)
        self.assertEqual(plugins_of(pc_res.config, one_proxy(self, pc_res.config, "/plain")), [])
        self.assertEqual(plugins_of(pc_res.config, one_proxy(self, pc_res.config, "/both")), [])
        self.assertIn("kong-correlation-id", codes(pc_rep, "warning"))
        tls_res, tls_rep, _ = migrate("kong", proto_cid, tls_only=True)
        tls_p = one_proxy(self, tls_res.config, "/tls")
        self.assertEqual(tls_p["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugins_of(tls_res.config, tls_p), [])
        self.assertIn("kong-correlation-id", codes(tls_rep, "warning"))

        # Default-protocol correlation-id migrates without any Ferrum trigger (Ferrum v0.9.21 rejects triggers
        # on correlation_id, and omitting triggers keeps WebSocket upgrades over HTTP/HTTPS routes tagged);
        # stream-only protocols ([tcp]) are skipped, and a restricted route-level correlation-id suppresses the
        # global plugin and omits with a warning.
        default_cid = textwrap.dedent("""
            _format_version: "3.0"
            plugins:
              - name: correlation-id
                config: {header_name: X-Global-ID, echo_downstream: false, generator: uuid}
            services:
              - name: s
                url: http://s.internal:8080
                routes:
                  - name: grpc-route
                    protocols: [grpc, grpcs]
                    paths: [/grpc/]
                  - name: http-route
                    protocols: [http, https]
                    paths: [/http/]
                  - name: narrowed-override
                    protocols: [http, https]
                    paths: [/narrow/]
                    plugins:
                      - name: correlation-id
                        protocols: [http]
                        config: {header_name: X-Narrow, echo_downstream: false, generator: uuid}
                  - name: tcp-noop-override
                    protocols: [http, https]
                    paths: [/tcp-noop/]
                    plugins:
                      - name: correlation-id
                        protocols: [tcp]
                        config: {header_name: X-Tcp, echo_downstream: false, generator: uuid}
        """)
        dc_res, dc_rep, _ = migrate("kong", default_cid)
        grpc_pl = plugin(self, dc_res.config, one_proxy(self, dc_res.config, "/grpc"), "correlation_id")
        self.assertEqual(grpc_pl["config"]["header_name"], "x-global-id")
        self.assertNotIn("trigger", grpc_pl)
        http_pl = plugin(self, dc_res.config, one_proxy(self, dc_res.config, "/http"), "correlation_id")
        self.assertEqual(http_pl["config"]["header_name"], "x-global-id")
        self.assertNotIn("trigger", http_pl)
        narrow_p = one_proxy(self, dc_res.config, "/narrow")
        self.assertEqual(narrow_p["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugins_of(dc_res.config, narrow_p), [])
        tcp_p = one_proxy(self, dc_res.config, "/tcp-noop")
        self.assertEqual(plugin(self, dc_res.config, tcp_p, "correlation_id")["config"]["header_name"], "x-global-id")
        self.assertIn("kong-correlation-id", codes(dc_rep, "warning"))


if __name__ == "__main__":
    unittest.main()
