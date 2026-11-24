import contextlib
import io
import json
import os
import tempfile
import textwrap
import unittest

from helpers import assert_structurally_valid, codes, migrate, one_proxy, plugin, plugins_of, proxies, read_fixture, \
    upstream_of

from ferrum_migration.cli import main as cli_main
from ferrum_migration.errors import InputError
from ferrum_migration.limits import Limits
from ferrum_migration.sources.nginx import parse


def nginx(text, **kwargs):
    return migrate("nginx", textwrap.dedent(text), fmt="nginx", **kwargs)


class NginxFixtureTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, self.plan = migrate("nginx", read_fixture("nginx", "nginx.conf"), fmt="nginx")
        self.config = self.result.config

    def test_structure_and_clean_exit(self):
        assert_structurally_valid(self, self.config)
        self.assertFalse(self.report.has_errors, [c.to_dict() for c in self.report.caveats if c.severity == "error"])

    def test_https_redirect_server_becomes_tls_only(self):
        self.assertTrue(self.result.tls_only)
        self.assertIn("nginx-https-redirect", codes(self.report, "info"))
        self.assertEqual(self.plan.settings.main_https_port, 443)
        self.assertIn(("/etc/nginx/tls/example.crt", "/etc/nginx/tls/example.key"),
                      self.plan.settings.frontend_cert_pairs)

    def test_upstream_location_with_strip_and_rate_limit(self):
        proxy = one_proxy(self, self.config, "/api")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertNotIn("backend_path", proxy)
        self.assertTrue(proxy["preserve_host_header"])
        self.assertEqual(proxy["backend_read_timeout_ms"], 60000)
        upstream = upstream_of(self.config, proxy)
        self.assertEqual(upstream["algorithm"], "least_connections")
        self.assertEqual([(t["host"], t["weight"]) for t in upstream["targets"]], [("10.0.0.11", 2), ("10.0.0.12", 1)])
        rate = plugin(self, self.config, proxy, "rate_limiting")
        self.assertEqual(rate["scope"], "proxy_group")
        self.assertEqual(rate["config"]["limits"], [{"scope": "default", "requests_per_second": 20}])
        self.assertEqual(plugin(self, self.config, proxy, "request_size_limiting")["config"]["max_bytes"], 10 * 1024 ** 2)
        hsts = plugin(self, self.config, proxy, "response_transformer")["config"]["rules"]
        self.assertIn({"operation": "update", "target": "header", "key": "strict-transport-security",
                       "value": "max-age=31536000"}, hsts)

    def test_allow_deny_becomes_ip_restriction(self):
        proxy = one_proxy(self, self.config, "/internal")
        self.assertFalse(proxy["strip_listen_path"])
        self.assertEqual(plugin(self, self.config, proxy, "ip_restriction")["config"], {"allow": ["10.0.0.0/8"]})

    def test_returns_and_deny_all_become_terminations(self):
        health = one_proxy(self, self.config, "=/healthz")
        config = plugin(self, self.config, health, "request_termination")["config"]
        self.assertEqual((config["status_code"], config["body"]), (200, "ok"))
        private = one_proxy(self, self.config, "/private")
        self.assertEqual(plugin(self, self.config, private, "request_termination")["config"]["status_code"], 403)

    def test_body_size_ceiling(self):
        self.assertEqual(self.plan.settings.max_request_body_bytes, 100 * 1024 ** 2)
        uploads = one_proxy(self, self.config, "/uploads")
        self.assertEqual(uploads["backend_host"], "uploads.internal")
        self.assertNotIn("request_size_limiting", [p["plugin_name"] for p in plugins_of(self.config, uploads)])


class NginxSemanticsTest(unittest.TestCase):
    def test_regex_and_prefix_overlap_refuses_whole_server(self):
        result, report, _ = nginx("""
            server {
                listen 80;
                server_name a.example.com;
                location / { proxy_pass http://app.internal:8080; }
                location ~ \\.php$ { proxy_pass http://php.internal:9000; }
            }
        """)
        self.assertTrue(result.config["proxies"])
        for proxy in result.config["proxies"]:
            self.assertEqual(proxy["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("route-refused", codes(report, "error"))

    def test_include_is_never_followed(self):
        result, _report, _ = nginx("""
            server {
                listen 80;
                location /x { include snippets/auth.conf; proxy_pass http://a.internal:1; }
            }
        """)
        self.assertEqual(one_proxy(self, result.config, "/x")["labels"]["ferrum-migration/status"], "refused")

    def test_lua_blocks_rejected(self):
        with self.assertRaises(InputError):
            nginx("""
                server { listen 80; location / { content_by_lua_block { ngx.say("hi") } } }
            """)

    def test_default_server_catch_all_and_host_scope_closure(self):
        result, report, _ = nginx("""
            server { listen 80 default_server; return 444; }
            server {
                listen 80;
                server_name api.example.com;
                location /v1/ { proxy_pass http://api.internal:8080/; }
            }
        """)
        catch_all = one_proxy(self, result.config, "/")
        self.assertNotIn("hosts", catch_all)
        self.assertEqual(plugin(self, result.config, catch_all, "request_termination")["config"]["status_code"], 403)
        closure = [p for p in result.config["proxies"] if "listen_path" not in p]
        self.assertEqual(len(closure), 1)
        self.assertEqual(closure[0]["hosts"], ["api.example.com"])
        self.assertEqual(plugin(self, result.config, closure[0], "request_termination")["config"]["status_code"], 404)
        self.assertIn("nginx-return-444", codes(report, "warning"))

    def test_loopback_listener_is_not_exposed(self):
        result, report, _ = nginx("""
            server { listen 127.0.0.1:8081; server_name admin.local; location / { proxy_pass http://127.0.0.1:9000; } }
            server { listen 80; server_name www.example.com; location / { proxy_pass http://web.internal:8080; } }
        """)
        self.assertEqual(proxies(result.config, host="admin.local"), [])
        self.assertIn("nginx-bind-address", codes(report, "error"))

    def test_extra_plaintext_port_uses_listen_port(self):
        result, _report, _ = nginx("""
            server { listen 80; server_name www.example.com; location / { proxy_pass http://web.internal:8080; } }
            server { listen 8081; server_name ops.example.com; location / { proxy_pass http://ops.internal:8080; } }
        """)
        scoped = [p for p in result.config["proxies"] if p.get("listen_port") == 8081]
        self.assertEqual(len(scoped), 1)
        self.assertEqual(scoped[0]["backend_host"], "ops.internal")

    def test_access_rules_never_loosen(self):
        result, report, _ = nginx("""
            server {
                listen 80;
                location /a { allow 10.1.0.0/16; deny 10.0.0.0/8; proxy_pass http://x.internal:1; }
            }
        """)
        proxy = one_proxy(self, result.config, "/a")
        self.assertEqual(plugin(self, result.config, proxy, "ip_restriction")["config"], {"deny": ["10.0.0.0/8"]})
        self.assertIn("nginx-access-rules", codes(report, "warning"))

    def test_basic_auth_is_fail_closed(self):
        result, report, _ = nginx("""
            server {
                listen 80;
                location /admin {
                    auth_basic "restricted";
                    auth_basic_user_file /etc/nginx/htpasswd;
                    proxy_pass http://admin.internal:8080;
                }
            }
        """)
        proxy = one_proxy(self, result.config, "/admin")
        self.assertEqual(plugin(self, result.config, proxy, "basic_auth")["config"], {"hide_credentials": False})
        self.assertTrue(result.basic_auth_used)
        self.assertIn("nginx-basic-auth", codes(report, "error"))

    def test_if_inside_location_is_refused_not_dropped(self):
        result, _report, _ = nginx("""
            server {
                listen 80;
                location /w { if ($request_method = POST) { return 405; } proxy_pass http://w.internal:1; }
            }
        """)
        self.assertEqual(one_proxy(self, result.config, "/w")["labels"]["ferrum-migration/status"], "refused")

    def test_unknown_directive_refuses_location(self):
        result, _report, _ = nginx("""
            server { listen 80; location /s { secure_link $arg_md5; proxy_pass http://s.internal:1; } }
        """)
        self.assertEqual(one_proxy(self, result.config, "/s")["labels"]["ferrum-migration/status"], "refused")

    def test_string_prefix_siblings_are_reported_not_widened(self):
        # location /api also matches /apix in NGINX; Ferrum's segment prefix does not. The route must stay
        # exactly /api (no widening) and the unrouted sibling paths must be a review error, not a silent 404.
        result, report, _ = nginx("""
            server {
                listen 80;
                location /api { proxy_pass http://api.internal:8080; }
            }
        """)
        proxy = one_proxy(self, result.config, "/api")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual([p.get("listen_path") for p in result.config["proxies"]], ["/api"])
        self.assertIn("prefix-string-siblings", codes(report, "error"))

    def test_string_prefix_siblings_with_equivalent_fallback_are_not_reported(self):
        # /apix falls back to location / with the same backend and policy, so Ferrum forwards it the same way.
        _result, report, _ = nginx("""
            server {
                listen 80;
                location / { proxy_pass http://app.internal:8080; }
                location /api { proxy_pass http://app.internal:8080; }
                location /v1/ { proxy_pass http://v1.internal:8080; }
            }
        """)
        self.assertNotIn("prefix-string-siblings", codes(report))
        self.assertFalse(report.has_errors, [c.to_dict() for c in report.caveats if c.severity == "error"])

    def test_string_prefix_sibling_error_sets_review_exit_code(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "nginx.conf")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("server { listen 80; location /api { proxy_pass http://api.internal:8080; } }\n")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                code = cli_main(["check", path, "--from", "nginx", "--json"])
        self.assertEqual(code, 4)
        errors = {c["code"] for c in json.loads(out.getvalue())["caveats"] if c["severity"] == "error"}
        self.assertIn("prefix-string-siblings", errors)

    def test_parse_errors_are_positioned_and_value_free(self):
        with self.assertRaises(InputError) as caught:
            parse('http { server { set $token "super-secret-value ; } }', Limits())
        self.assertNotIn("super-secret-value", str(caught.exception))
        self.assertIn("line", str(caught.exception))

    def test_block_depth_limit(self):
        text = "a {" * 40 + "}" * 40
        with self.assertRaises(InputError):
            parse(text, Limits())


if __name__ == "__main__":
    unittest.main()
