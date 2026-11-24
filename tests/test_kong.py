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


if __name__ == "__main__":
    unittest.main()
