"""Regression tests for defensive guards (benign synthetic inputs only).

Each test pins one fail-closed property found in review: backend TLS
verification can never be turned off, stored/pre-transformed credentials and
static credential-like header values are never copied, per-route filter
re-enablement and gateway-workload policies refuse routes instead of being
silently skipped, and the database-import guidance distinguishes additive
batch import from full restore.
"""

import contextlib
import copy
import io
import json
import os
import tempfile
import textwrap
import unittest

import yaml

from helpers import codes, fixture_path, migrate, one_proxy, read_fixture, upstream_of

from ferrum_migration.cli import main
from ferrum_migration.envprofile import next_steps
from ferrum_migration.ferrum import _assert_backend_tls_verified

ALL_FIXTURES = [("kong", ("kong", "kong.yaml"), "yaml"), ("nginx", ("nginx", "nginx.conf"), "nginx"),
                ("traefik", ("traefik", "dynamic.yaml"), "yaml"), ("traefik", ("traefik", "dynamic.toml"), "toml"),
                ("envoy", ("envoy", "envoy.yaml"), "yaml"), ("istio", ("istio", "istio.yaml"), "yaml")]


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def everything(result, report) -> str:
    return json.dumps(result.config) + json.dumps([c.to_dict() for c in report.caveats])


def status(test, config, path, host=None):
    return one_proxy(test, config, path, host)["labels"]["ferrum-migration/status"]


class BackendTlsNeverInsecureTest(unittest.TestCase):
    def test_removed_insecure_flag_is_a_hard_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            out = os.path.join(temp, "out")
            for command in (("convert", fixture_path("kong", "kong.yaml"), "--from", "kong", "--out", out),
                            ("check", fixture_path("kong", "kong.yaml"), "--from", "kong")):
                code, stdout, stderr = run_cli(*command, "--allow-insecure-backend-tls")
                self.assertEqual(code, 2, stdout + stderr)
                self.assertIn("not supported", stderr)
                self.assertFalse(os.path.exists(out))

    def test_every_fixture_emits_only_verified_backend_tls(self):
        for platform, parts, fmt in ALL_FIXTURES:
            with self.subTest(fixture="/".join(parts)):
                result, _report, _plan = migrate(platform, read_fixture(*parts), fmt=fmt)
                for kind in ("proxies", "upstreams"):
                    for item in result.config[kind]:
                        self.assertIs(item.get("backend_tls_verify_server_cert", True), True, item["id"])

    def test_traefik_insecure_skip_verify_is_overridden(self):
        doc = yaml.safe_dump({"http": {
            "routers": {"r": {"rule": "PathPrefix(`/s`)", "service": "s"}},
            "services": {"s": {"loadBalancer": {"servers": [{"url": "https://s.internal:8443"}],
                                                "serversTransport": "t"}}},
            "serversTransports": {"t": {"insecureSkipVerify": True}},
        }})
        result, report, _ = migrate("traefik", doc)
        proxy = one_proxy(self, result.config, "/s")
        self.assertIs(proxy["backend_tls_verify_server_cert"], True)
        self.assertIn("backend-tls-verify-enabled", codes(report, "warning"))

    def test_istio_destination_rule_insecure_skip_verify_is_overridden(self):
        text = textwrap.dedent("""
            apiVersion: networking.istio.io/v1
            kind: Gateway
            metadata: {name: gw, namespace: default}
            spec:
              selector: {istio: ingressgateway}
              servers:
                - port: {number: 80, name: http, protocol: HTTP}
                  hosts: ["app.example.com"]
            ---
            apiVersion: networking.istio.io/v1
            kind: VirtualService
            metadata: {name: app, namespace: default}
            spec:
              hosts: [app.example.com]
              gateways: [gw]
              http:
                - route: [{destination: {host: web, port: {number: 443}}}]
            ---
            apiVersion: networking.istio.io/v1
            kind: DestinationRule
            metadata: {name: web, namespace: default}
            spec:
              host: web
              trafficPolicy: {tls: {mode: SIMPLE, insecureSkipVerify: true}}
        """)
        result, report, _ = migrate("istio", text)
        upstream = upstream_of(result.config, one_proxy(self, result.config, "/", "app.example.com"))
        self.assertIs(upstream["backend_tls_verify_server_cert"], True)
        self.assertIn("backend-tls-verify-enabled", codes(report, "warning"))

    def test_emitter_invariant_rejects_disabled_verification(self):
        with self.assertRaises(AssertionError):
            _assert_backend_tls_verified({"proxies": [{"id": "p", "backend_tls_verify_server_cert": False}],
                                          "upstreams": []})

    def test_operator_ca_reference_is_reported(self):
        result, report, _ = migrate("istio", read_fixture("istio", "istio.yaml"))
        self.assertIn("backend-tls-files", codes(report, "info"))
        catalog = upstream_of(result.config, one_proxy(self, result.config, "/catalog", "shop.example.com"))
        self.assertEqual(catalog["backend_tls_server_ca_cert_path"], "/etc/certs/internal-ca.pem")


class CredentialHandlingTest(unittest.TestCase):
    DECK = textwrap.dedent("""
        _format_version: "3.0"
        _info: {select_tags: [team-a]}
        _transform: false
        services:
          - name: s
            url: http://s.internal:8080
            routes: [{name: r, paths: [/k]}]
            plugins: [{name: key-auth}]
        consumers:
          - username: erin
            keyauth_credentials: [{key: test-only-stored-value-erin-0001}]
            jwt_secrets: [{key: erin, algorithm: HS256, secret: test-only-stored-jwt-value-erin-00000001}]
    """)

    def test_pretransformed_kong_credentials_are_never_reused(self):
        result, report, _ = migrate("kong", self.DECK, include_secrets=True)
        self.assertNotIn("credentials", result.config["consumers"][0])
        self.assertEqual(result.secrets_emitted, 0)
        self.assertIn("kong-transform", codes(report, "error"))
        text = everything(result, report)
        self.assertNotIn("test-only-stored-value-erin-0001", text)
        self.assertNotIn("test-only-stored-jwt-value-erin", text)

    def test_kong_input_flavor_is_stated(self):
        _result, report, _ = migrate("kong", self.DECK)
        flavor = [c.message for c in report.caveats if c.code == "kong-input-flavor"]
        self.assertEqual(len(flavor), 1)
        self.assertIn("decK dump", flavor[0])
        _result, report, _ = migrate("kong", read_fixture("kong", "kong.yaml"))
        self.assertIn("kong-input-flavor", codes(report, "info"))

    def test_nginx_static_authorization_header_is_refused_not_copied(self):
        result, report, _ = migrate("nginx", textwrap.dedent("""
            server {
                listen 80;
                location /a { proxy_set_header Authorization "Bearer test-only-static-token-0001"; proxy_pass http://a.internal:8080; }
                location /b { proxy_set_header X-Request-Id $request_id; proxy_pass http://b.internal:8080; }
            }
        """), fmt="nginx")
        self.assertEqual(status(self, result.config, "/a"), "refused")
        self.assertEqual(status(self, result.config, "/b"), "migrated")
        self.assertNotIn("test-only-static-token-0001", everything(result, report))

    def test_traefik_static_api_key_header_is_refused_not_copied(self):
        doc = yaml.safe_dump({"http": {
            "routers": {"r": {"rule": "PathPrefix(`/h`)", "service": "s", "middlewares": ["h"]}},
            "middlewares": {"h": {"headers": {"customRequestHeaders": {"X-Api-Key": "test-only-static-key-0002"}}}},
            "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}},
        }})
        result, report, _ = migrate("traefik", doc)
        self.assertEqual(status(self, result.config, "/h"), "refused")
        self.assertNotIn("test-only-static-key-0002", everything(result, report))

    def test_kong_static_query_credential_is_refused_not_copied(self):
        result, report, _ = migrate("kong", textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080
                routes: [{name: r, paths: [/q]}]
                plugins:
                  - name: request-transformer
                    config: {add: {querystring: ["apikey:test-only-static-query-0003"]}}
        """))
        self.assertEqual(status(self, result.config, "/q"), "refused")
        self.assertNotIn("test-only-static-query-0003", everything(result, report))


class AuthNeverSilentlySkippedTest(unittest.TestCase):
    def envoy_doc(self):
        return yaml.safe_load(read_fixture("envoy", "envoy.yaml"))

    @staticmethod
    def hcm(doc):
        return doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]

    def test_envoy_per_route_filter_reenable_refuses_route(self):
        doc = self.envoy_doc()
        hcm = self.hcm(doc)
        hcm["http_filters"].insert(0, {"name": "envoy.filters.http.jwt_authn", "disabled": True,
                                       "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters."
                                                                 "http.jwt_authn.v3.JwtAuthentication"}})
        users = hcm["route_config"]["virtual_hosts"][0]["routes"][0]
        users["typed_per_filter_config"] = {"envoy.filters.http.jwt_authn": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.PerRouteConfig",
            "requirement_name": "synthetic"}}
        result, report, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(status(self, result.config, "/users", "api.example.com"), "refused")
        self.assertIn("route-refused", codes(report, "error"))

    def test_envoy_disabled_filter_without_per_route_config_stays_migrated(self):
        doc = self.envoy_doc()
        self.hcm(doc)["http_filters"].insert(0, {"name": "envoy.filters.http.jwt_authn", "disabled": True})
        result, _report, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(status(self, result.config, "/users", "api.example.com"), "migrated")

    def istio_with_policy(self, policy_ns: str, selector: dict | None) -> str:
        policy = {"apiVersion": "security.istio.io/v1", "kind": "AuthorizationPolicy",
                  "metadata": {"name": "gw-policy", "namespace": policy_ns},
                  "spec": {"action": "ALLOW", "rules": [{"from": [{"source": {"ipBlocks": ["192.0.2.0/24"]}}]}]}}
        if selector is not None:
            policy["spec"]["selector"] = {"matchLabels": selector}
        return read_fixture("istio", "istio.yaml") + "---\n" + yaml.safe_dump(policy)

    def test_istio_selector_policy_in_gateway_pod_namespace_refuses_routes(self):
        result, _report, _ = migrate("istio", self.istio_with_policy("istio-ingress", {"istio": "ingressgateway"}))
        statuses = {p["labels"]["ferrum-migration/status"] for p in result.config["proxies"] if "listen_path" in p}
        self.assertEqual(statuses, {"refused"})

    def test_istio_namespace_wide_policy_elsewhere_requires_review(self):
        result, report, _ = migrate("istio", self.istio_with_policy("istio-ingress", None))
        self.assertIn("istio-policy-scope-unknown", codes(report, "error"))
        self.assertEqual(status(self, result.config, "/cart", "shop.example.com"), "migrated")


class ImportGuidanceTest(unittest.TestCase):
    def test_database_steps_distinguish_additive_batch_from_full_restore(self):
        text = " ".join(next_steps("database", "resources.yaml", False, False, 0))
        for needle in ("POST /batch", "additive", "POST /restore?confirm=true", "REPLACES", "GET /backup",
                       "resource_counts", "has not runtime-tested"):
            self.assertIn(needle, text)
        file_text = " ".join(next_steps("file", "resources.yaml", False, False, 0))
        self.assertNotIn("/restore", file_text)


if __name__ == "__main__":
    unittest.main()
