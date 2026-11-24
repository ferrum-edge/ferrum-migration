"""Frontend protocol invariant: Ferrum only opens listeners that every live route was served on in the source.

Normal, benign configurations only. Each test checks the emitted proxies, the decision and the rendered
ferrum.conf (the listener settings the invariant is tied to).
"""

import unittest

from helpers import codes, migrate, one_proxy, proxies

from ferrum_migration.envprofile import assert_listener_invariant, render
from ferrum_migration.ferrum import EmitOptions, emit
from ferrum_migration.model import BackendRef, Plan, RouteSpec, SettingsHints
from ferrum_migration.report import Report


def conf_values(profile: str) -> dict:
    values = {}
    for line in profile.splitlines():
        text = line.strip()
        if text and not text.startswith("#") and "=" in text:
            key, _, value = text.partition("=")
            values[key] = value
    return values


def profile_of(plan, result, run_mode="file") -> str:
    return render(run_mode, plan.platform, plan.settings, result.tls_only, result.basic_auth_used, "resources.yaml")


def status(proxy: dict) -> str:
    return proxy["labels"].get("ferrum-migration/status", "")


NGINX_DISJOINT = """
http {
  server {
    listen 80 default_server;
    listen 443 ssl default_server;
    server_name _;
    ssl_certificate /etc/nginx/tls/default.crt;
    ssl_certificate_key /etc/nginx/tls/default.key;
    location = /healthz { return 200 "ok"; }
  }
  server {
    listen 80;
    server_name app.example.com;
    location / { proxy_pass http://app.internal:8080; }
  }
  server {
    listen 443 ssl;
    server_name secure.example.com;
    ssl_certificate /etc/nginx/tls/secure.crt;
    ssl_certificate_key /etc/nginx/tls/secure.key;
    location / { proxy_pass http://secure.internal:8080; }
  }
}
"""

NGINX_DUAL = """
http {
  server {
    listen 80;
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate /etc/nginx/tls/app.crt;
    ssl_certificate_key /etc/nginx/tls/app.key;
    location / { proxy_pass http://app.internal:8080; }
  }
}
"""

NGINX_TLS_WITH_REDIRECT = """
http {
  server {
    listen 80;
    server_name app.example.com;
    return 301 https://app.example.com$request_uri;
  }
  server {
    listen 443 ssl;
    server_name app.example.com;
    ssl_certificate /etc/nginx/tls/app.crt;
    ssl_certificate_key /etc/nginx/tls/app.key;
    location / { proxy_pass http://app.internal:8080; }
  }
}
"""

ENVOY_HCM = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
ENVOY_PLAIN_AND_RDS_TLS = f"""
static_resources:
  listeners:
  - name: plain
    address: {{socket_address: {{address: 0.0.0.0, port_value: 8080}}}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": {ENVOY_HCM}
          stat_prefix: plain
          http_filters:
          - name: envoy.filters.http.router
          route_config:
            virtual_hosts:
            - name: app
              domains: ["app.example.com"]
              routes:
              - match: {{prefix: "/"}}
                route: {{cluster: app}}
  - name: secure
    address: {{socket_address: {{address: 0.0.0.0, port_value: 8443}}}}
    filter_chains:
    - transport_socket:
        name: envoy.transport_sockets.tls
        typed_config:
          "@type": type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext
          common_tls_context:
            tls_certificates:
            - certificate_chain: {{filename: /etc/envoy/tls/cert.pem}}
              private_key: {{filename: /etc/envoy/tls/key.pem}}
      filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": {ENVOY_HCM}
          stat_prefix: secure
          rds: {{route_config_name: secure-routes}}
          http_filters:
          - name: envoy.filters.http.router
  clusters:
  - name: app
    type: STRICT_DNS
    load_assignment:
      cluster_name: app
      endpoints:
      - lb_endpoints:
        - endpoint: {{address: {{socket_address: {{address: app.internal, port_value: 8080}}}}}}
"""

KONG_MIXED = """
_format_version: "3.0"
services:
- name: web
  url: http://web.internal:8080
  routes:
  - name: plain-only
    hosts: [plain.example.com]
    protocols: [http]
  - name: both
    hosts: [both.example.com]
"""

KONG_DEFAULT = """
_format_version: "3.0"
services:
- name: web
  url: http://web.internal:8080
  routes:
  - name: both
    hosts: [both.example.com]
"""

ISTIO_TEMPLATE = """
apiVersion: networking.istio.io/v1beta1
kind: Gateway
metadata: {{name: edge, namespace: web}}
spec:
  selector: {{istio: ingressgateway}}
  servers:
  - port: {{number: 80, name: http, protocol: HTTP}}
    hosts: [{http_hosts}]
  - port: {{number: 443, name: https, protocol: HTTPS}}
    hosts: ["app.example.com"]
    tls: {{mode: SIMPLE, serverCertificate: /etc/istio/tls/tls.crt, privateKey: /etc/istio/tls/tls.key}}
---
apiVersion: networking.istio.io/v1beta1
kind: VirtualService
metadata: {{name: app, namespace: web}}
spec:
  hosts: [{vs_hosts}]
  gateways: ["edge"]
  http:
  - route:
    - destination: {{host: app.web.svc.cluster.local, port: {{number: 8080}}}}
"""


class HttpOnlyOutputTest(unittest.TestCase):
    def test_nginx_disjoint_hosts_do_not_keep_https_open(self):
        result, report, plan = migrate("nginx", NGINX_DISJOINT, fmt="nginx")
        self.assertEqual(result.frontend_protocols, "http")
        self.assertIn("frontend-https-disabled", codes(report, "error"))
        self.assertNotIn("nginx-frontend-scope-conflict", codes(report))
        # The plaintext server stays live; the HTTPS-only server becomes a fail-closed placeholder.
        self.assertEqual(status(one_proxy(self, result.config, "/", host="app.example.com")), "migrated")
        self.assertEqual(status(one_proxy(self, result.config, "/", host="secure.example.com")), "refused")
        values = conf_values(profile_of(plan, result))
        self.assertEqual(values["FERRUM_PROXY_HTTP_PORT"], "80")
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "0")
        self.assertFalse(any(key.startswith("FERRUM_FRONTEND_TLS_") for key in values))

    def test_envoy_skipped_tls_listener_does_not_configure_https(self):
        result, report, plan = migrate("envoy", ENVOY_PLAIN_AND_RDS_TLS)
        self.assertIn("envoy-rds", codes(report, "error"))
        self.assertEqual(result.frontend_protocols, "http")
        self.assertIn("frontend-https-disabled", codes(report, "error"))
        self.assertEqual(status(one_proxy(self, result.config, "/", host="app.example.com")), "migrated")
        profile = profile_of(plan, result)
        values = conf_values(profile)
        self.assertEqual(values["FERRUM_PROXY_HTTP_PORT"], "8080")
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "0")
        self.assertNotIn("FERRUM_FRONTEND_TLS_CERT_PATH", values)
        self.assertNotIn("REQUIRED for HTTPS", profile)

    def test_kong_plaintext_route_disables_https(self):
        result, report, plan = migrate("kong", KONG_MIXED)
        self.assertEqual(result.frontend_protocols, "http")
        self.assertIn("frontend-https-disabled", codes(report, "error"))
        for host in ("plain.example.com", "both.example.com"):
            self.assertEqual(status(one_proxy(self, result.config, ..., host=host)), "migrated")
        self.assertEqual(conf_values(profile_of(plan, result))["FERRUM_PROXY_HTTPS_PORT"], "0")

    def test_istio_host_only_on_plaintext_server_disables_https(self):
        text = ISTIO_TEMPLATE.format(http_hosts='"app.example.com", "admin.example.com"',
                                     vs_hosts='"app.example.com", "admin.example.com"')
        result, report, plan = migrate("istio", text)
        self.assertEqual(result.frontend_protocols, "http")
        self.assertIn("frontend-https-disabled", codes(report, "error"))
        values = conf_values(profile_of(plan, result))
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "0")
        self.assertNotIn("FERRUM_FRONTEND_TLS_CERT_PATH", values)

    def test_plaintext_only_source_disables_https_explicitly(self):
        text = KONG_MIXED.replace("  - name: both\n    hosts: [both.example.com]\n", "")
        result, report, plan = migrate("kong", text)
        self.assertEqual(result.frontend_protocols, "http")
        self.assertIn("frontend-http-only", codes(report, "info"))
        self.assertNotIn("frontend-https-disabled", codes(report))
        self.assertEqual(conf_values(profile_of(plan, result))["FERRUM_PROXY_HTTPS_PORT"], "0")


class DualAndTlsOnlyOutputTest(unittest.TestCase):
    def test_nginx_server_on_both_listeners_keeps_both(self):
        result, report, plan = migrate("nginx", NGINX_DUAL, fmt="nginx")
        self.assertEqual(result.frontend_protocols, "both")
        self.assertNotIn("frontend-https-disabled", codes(report))
        self.assertTrue(any(status(p) == "migrated" for p in proxies(result.config, "/")))
        values = conf_values(profile_of(plan, result))
        self.assertEqual(values["FERRUM_PROXY_HTTP_PORT"], "80")
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "443")
        self.assertEqual(values["FERRUM_FRONTEND_TLS_CERT_PATH"], "/etc/nginx/tls/app.crt")

    def test_istio_same_hosts_on_both_servers_keeps_both(self):
        text = ISTIO_TEMPLATE.format(http_hosts='"app.example.com"', vs_hosts='"app.example.com"')
        result, report, plan = migrate("istio", text)
        self.assertEqual(result.frontend_protocols, "both")
        self.assertEqual(status(one_proxy(self, result.config, "/", host="app.example.com")), "migrated")
        values = conf_values(profile_of(plan, result))
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "443")
        self.assertNotEqual(values.get("FERRUM_PROXY_HTTP_PORT"), "0")

    def test_kong_default_protocols_keep_both(self):
        result, report, plan = migrate("kong", KONG_DEFAULT)
        self.assertEqual(result.frontend_protocols, "both")
        values = conf_values(profile_of(plan, result))
        self.assertNotEqual(values.get("FERRUM_PROXY_HTTPS_PORT"), "0")
        self.assertNotEqual(values.get("FERRUM_PROXY_HTTP_PORT"), "0")

    def test_nginx_tls_only_path_is_preserved(self):
        result, report, plan = migrate("nginx", NGINX_TLS_WITH_REDIRECT, fmt="nginx")
        self.assertTrue(result.tls_only)
        self.assertEqual(result.frontend_protocols, "https")
        self.assertNotIn("frontend-protocol-scope", codes(report))
        # The TLS server is the default server on its listener, so its route is a catch-all.
        self.assertTrue(any(status(p) == "migrated" for p in proxies(result.config, "/")))
        values = conf_values(profile_of(plan, result))
        self.assertEqual(values["FERRUM_PROXY_HTTP_PORT"], "0")
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "443")
        self.assertEqual(values["FERRUM_FRONTEND_TLS_CERT_PATH"], "/etc/nginx/tls/app.crt")

    def test_tls_only_flag_refuses_plaintext_only_routes(self):
        result, report, plan = migrate("kong", KONG_MIXED, tls_only=True)
        self.assertEqual(result.frontend_protocols, "https")
        self.assertIn("frontend-protocol-scope", codes(report, "error"))
        self.assertEqual(status(one_proxy(self, result.config, ..., host="plain.example.com")), "refused")
        self.assertEqual(status(one_proxy(self, result.config, ..., host="both.example.com")), "migrated")
        self.assertEqual(conf_values(profile_of(plan, result))["FERRUM_PROXY_HTTP_PORT"], "0")


class FrontendAccountingTest(unittest.TestCase):
    def test_unknown_frontend_metadata_refuses_the_plan(self):
        plan = Plan(platform="kong")
        plan.routes.append(RouteSpec(ref="route one", name="one", hosts=["one.example.com"], kind="prefix", path="/",
                                     backend=BackendRef(scheme="http", host="one.internal", port=8080)))
        report = Report("kong", "test-input")
        result = emit(plan, EmitOptions(), report)
        self.assertIn("frontend-protocol-unknown", codes(report, "error"))
        self.assertTrue(plan.routes[0].refusals)
        self.assertTrue(all(status(proxy) != "migrated" for proxy in result.config["proxies"]))

    def test_http_only_profile_drops_tls_settings(self):
        settings = SettingsHints(main_http_port=80, main_https_port=443, frontend_tls_expected=True,
                                 frontend_cert_pairs=[("/etc/tls/a.crt", "/etc/tls/a.key")], http3=True,
                                 frontend_protocols="http")
        profile = render("file", "nginx", settings, False, False, "resources.yaml")
        values = conf_values(profile)
        self.assertEqual(values["FERRUM_PROXY_HTTPS_PORT"], "0")
        self.assertFalse(any(key.startswith("FERRUM_FRONTEND_TLS_") for key in values))
        self.assertNotIn("FERRUM_ENABLE_HTTP3", profile)

    def test_listener_invariant_rejects_profiles_that_leave_https_to_defaults(self):
        profile = "FERRUM_MODE=file\nFERRUM_PROXY_HTTP_PORT=80\n"
        with self.assertRaises(AssertionError):
            assert_listener_invariant(profile, "http", "file")
        assert_listener_invariant(profile + "FERRUM_PROXY_HTTPS_PORT=0\n", "http", "file")
        with self.assertRaises(AssertionError):
            assert_listener_invariant(profile, "https", "file")


if __name__ == "__main__":
    unittest.main()
