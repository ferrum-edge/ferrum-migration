import contextlib
import io
import json
import os
import tempfile
import textwrap
import unittest

from helpers import assert_listener_contract, assert_structurally_valid, codes, live_routes, migrate, one_proxy, \
    plugin, plugins_of, proxies, read_fixture, upstream_of

from ferrum_migration.cli import main as cli_main
from ferrum_migration.envprofile import render
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

    def test_named_default_server_keeps_its_named_tier(self):
        # NGINX sends app.example.test to the default server (exact name beats the wildcard). As a Ferrum catch-all,
        # /api/ for that host would reach the wildcard server's "/" route without the IP restriction.
        result, report, _ = nginx("""
            server {
                listen 80 default_server;
                server_name app.example.test;
                location /api/ { allow 10.0.0.0/8; deny all; proxy_pass http://app.internal:8080; }
            }
            server {
                listen 80;
                server_name *.example.test;
                location / { proxy_pass http://wild.internal:8080; }
            }
        """)
        api = one_proxy(self, result.config, "/api", "app.example.test")
        self.assertEqual(api["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugin(self, result.config, api, "ip_restriction")["config"], {"allow": ["10.0.0.0/8"]})
        self.assertEqual([p for p in proxies(result.config, "/api") if "hosts" not in p], [])
        closure = [p for p in proxies(result.config, host="app.example.test") if "listen_path" not in p]
        self.assertEqual(len(closure), 1)
        self.assertIn("nginx-default-server-named", codes(report, "error"))

    def test_named_default_server_without_competing_names_stays_catch_all(self):
        result, report, _ = nginx("""
            server {
                listen 80 default_server;
                server_name app.example.test;
                location /api/ { proxy_pass http://app.internal:8080; }
            }
            server {
                listen 80;
                server_name other.example.test;
                location / { proxy_pass http://other.internal:8080; }
            }
        """)
        self.assertNotIn("hosts", one_proxy(self, result.config, "/api"))
        self.assertNotIn("nginx-default-server-named", codes(report))

    def test_default_server_on_a_dropped_extra_port_is_not_a_catch_all(self):
        # side is the default server only on 8080, which Ferrum does not serve for it; on port 80 the main server
        # is the default. It must keep its own server_name instead of taking every unknown host on port 80.
        result, _report, _ = nginx("""
            server { listen 80; server_name main.example.test; location / { proxy_pass http://main.internal:8080; } }
            server {
                listen 80;
                listen 8080 default_server;
                server_name side.example.test;
                location /side/ { proxy_pass http://side.internal:8080; }
            }
        """)
        side = one_proxy(self, result.config, "/side", "side.example.test")
        self.assertEqual(side["hosts"], ["side.example.test"])
        self.assertEqual([p for p in proxies(result.config, "/side") if "hosts" not in p], [])

    def test_mixed_default_ownership_keeps_named_hosts(self):
        result, report, _ = nginx("""
            server {
                listen 80 default_server;
                listen 443 ssl;
                server_name a.example.test;
                ssl_certificate /etc/synthetic/server.crt;
                ssl_certificate_key /etc/synthetic/server.key;
                location /a/ { proxy_pass http://a.internal:8080; }
            }
            server {
                listen 443 ssl default_server;
                server_name b.example.test;
                ssl_certificate /etc/synthetic/server.crt;
                ssl_certificate_key /etc/synthetic/server.key;
                location /b/ { proxy_pass http://b.internal:8080; }
            }
        """, tls_only=True)
        self.assertEqual(one_proxy(self, result.config, "/a", "a.example.test")["hosts"], ["a.example.test"])
        self.assertIn("nginx-default-server-listener", codes(report, "error"))

    def test_different_default_servers_on_main_listeners_are_refused(self):
        result, report, _ = nginx("""
            server { listen 80; location /a/ { proxy_pass http://a.internal:8080; } }
            server {
                listen 443 ssl;
                ssl_certificate /etc/synthetic/server.crt;
                ssl_certificate_key /etc/synthetic/server.key;
                location /b/ { proxy_pass http://b.internal:8080; }
            }
        """, tls_only=True)
        self.assertEqual(one_proxy(self, result.config, "/a")["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(one_proxy(self, result.config, "/b")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("nginx-default-server-conflict", codes(report, "error"))

    def test_nested_wildcard_scope_routes_are_refused(self):
        # NGINX sends x.team.example.test only to the narrower wildcard server. Ferrum's wildcard tier would let
        # the broader server's /api route answer it, so that route is refused instead of only reported.
        result, report, _ = nginx("""
            server { listen 80 default_server; return 444; }
            server { listen 80; server_name *.example.test; location /api/ { proxy_pass http://broad.internal:8080; } }
            server { listen 80; server_name *.team.example.test; location /app/ { proxy_pass http://team.internal:8080; } }
        """)
        broad = one_proxy(self, result.config, "/api", "*.example.test")
        self.assertEqual(broad["labels"]["ferrum-migration/status"], "refused")
        team = one_proxy(self, result.config, "/app", "*.team.example.test")
        self.assertEqual(team["labels"]["ferrum-migration/status"], "migrated")
        self.assertIn("nested-wildcard-scope", codes(report, "error"))
        assert_structurally_valid(self, result.config)

    def test_wildcard_scope_with_nested_exact_scope_gets_a_closure(self):
        # The exact server's host-only closure overlaps the wildcard, so the wildcard scope is closed with a
        # catch-any regex 404 instead of being left to fall through to the default server.
        result, report, _ = nginx("""
            server { listen 80 default_server; return 444; }
            server { listen 80; server_name api.example.test; location /v1/ { proxy_pass http://api.internal:8080; } }
            server { listen 80; server_name *.example.test; location /shop/ { proxy_pass http://shop.internal:8080; } }
        """)
        closure = one_proxy(self, result.config, "~/.*", "*.example.test")
        self.assertEqual(plugin(self, result.config, closure, "request_termination")["config"]["status_code"], 404)
        self.assertNotIn("scope-closure-skipped", codes(report))
        catch_all = one_proxy(self, result.config, "/")
        self.assertNotEqual(catch_all["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(one_proxy(self, result.config, "/shop", "*.example.test")["labels"]["ferrum-migration/status"],
                         "migrated")
        assert_structurally_valid(self, result.config)

    def test_caret_prefix_siblings_cannot_reach_a_regex_location(self):
        # ^~ /static stops NGINX's regex search for every path starting with /static (also /staticx.php).
        # In Ferrum such a sibling would reach the regex route, so that route is guarded for /static.
        result, _report, _ = nginx("""
            server {
                listen 80;
                server_name app.example.test;
                location ^~ /static { proxy_pass http://static.internal:8080; }
                location ~ \\.php$ { proxy_pass http://php.internal:9000; }
            }
        """)
        # The only server is the default server, so its routes are catch-all (no hosts).
        self.assertEqual(one_proxy(self, result.config, "/static")["labels"]["ferrum-migration/status"], "migrated")
        regex = one_proxy(self, result.config, "~.*\\.php")
        guards = [p["config"]["trigger"]["path_prefix"] for p in plugins_of(result.config, regex)
                  if p["plugin_name"] == "request_termination"]
        self.assertEqual(guards, ["/static"])

    def test_loopback_listener_is_not_exposed(self):
        result, report, _ = nginx("""
            server { listen 127.0.0.1:8081; server_name admin.local; location / { proxy_pass http://127.0.0.1:9000; } }
            server { listen 80; server_name www.example.com; location / { proxy_pass http://web.internal:8080; } }
        """)
        self.assertEqual(proxies(result.config, host="admin.local"), [])
        self.assertIn("nginx-bind-address", codes(report, "error"))

    def test_extra_plaintext_listener_is_refused_not_port_scoped(self):
        # Ferrum ranks host/path before ports and serves port-agnostic routes on every listener, so a listen_port
        # route for 8081 could not be isolated from the main server's routes. The extra listener is not migrated
        # at all (no proxy, not even a placeholder), while the main single-listener server stays as before.
        result, report, _ = nginx("""
            server { listen 80; server_name www.example.com; location / { proxy_pass http://web.internal:8080; } }
            server { listen 8081; server_name ops.example.com; location / { proxy_pass http://ops.internal:8080; } }
        """)
        assert_structurally_valid(self, result.config)
        self.assertEqual([p for p in result.config["proxies"] if "listen_port" in p], [])
        self.assertEqual(proxies(result.config, host="ops.example.com"), [])
        self.assertNotIn("ops.internal", json.dumps(result.config))
        # www is the only (default) server on port 80: a catch-all route, migrated as before.
        main = one_proxy(self, result.config, "/")
        self.assertEqual((main["labels"]["ferrum-migration/status"], main["backend_host"]), ("migrated", "web.internal"))
        self.assertIn("extra-listener-refused", codes(report, "error"))

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


class NginxClientCaScopeTest(unittest.TestCase):
    # Synthetic paths only: no certificate material is read, written or needed.
    SERVERS = """
        server {
            listen 443 ssl;
            server_name a.example.test;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            ssl_client_certificate CA_A;
            ssl_verify_client on;
            location /a/ { proxy_pass http://a.internal:8080; }
        }
        server {
            listen 443 ssl;
            server_name b.example.test;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            ssl_client_certificate CA_B;
            ssl_verify_client on;
            location /b/ { proxy_pass http://b.internal:8080; }
        }
        server {
            listen 443 ssl;
            server_name open.example.test;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            location /open/ { proxy_pass http://open.internal:8080; }
        }
    """

    def status(self, result, path):
        return one_proxy(self, result.config, path)["labels"]["ferrum-migration/status"]

    def profile(self, result, plan):
        return render("file", "nginx", plan.settings, result.tls_only, result.basic_auth_used, "resources.yaml")

    def test_different_client_cas_are_refused_not_concatenated(self):
        result, report, plan = nginx(self.SERVERS.replace("CA_A", "/etc/synthetic/client-ca-a.pem")
                                     .replace("CA_B", "/etc/synthetic/client-ca-b.pem"))
        self.assertEqual(self.status(result, "/a"), "refused")
        self.assertEqual(self.status(result, "/b"), "refused")
        self.assertEqual(self.status(result, "/open"), "migrated")
        self.assertIn("frontend-client-ca-scope", codes(report, "error"))
        self.assertEqual(plan.settings.client_ca_paths, [])
        conf = self.profile(result, plan)
        self.assertNotIn("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH=", conf)
        self.assertNotIn("concatenate them into one file", conf)
        self.assertNotIn("client-ca-a.pem", conf)
        self.assertIn("REVIEW REQUIRED (frontend-client-ca-scope)", conf)

    def test_one_shared_client_ca_is_configured(self):
        ca = "/etc/synthetic/client-ca.pem"
        result, report, plan = nginx(self.SERVERS.replace("CA_A", ca).replace("CA_B", ca))
        for path in ("/a", "/b", "/open"):
            self.assertEqual(self.status(result, path), "migrated", path)
        self.assertEqual(plan.settings.client_ca_paths, [ca])
        self.assertNotIn("frontend-client-ca-scope", codes(report))
        self.assertIn("frontend-client-ca-shared", codes(report, "warning"))
        self.assertIn(f"FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH={ca}", self.profile(result, plan).splitlines())

    def test_inherited_verify_without_client_ca_file_is_refused(self):
        result, report, plan = nginx("""
            http {
                ssl_verify_client on;
                server {
                    listen 443 ssl;
                    server_name m.example.test;
                    ssl_certificate /etc/synthetic/server.crt;
                    ssl_certificate_key /etc/synthetic/server.key;
                    location /m/ { proxy_pass http://m.internal:8080; }
                }
            }
        """)
        self.assertEqual(self.status(result, "/m"), "refused")
        self.assertIn("nginx-client-ca", codes(report, "error"))
        self.assertEqual(plan.settings.client_ca_paths, [])


class NginxFrontendScopeTest(unittest.TestCase):
    # Synthetic paths only: no certificate material is read, written or needed.
    CA = "/etc/synthetic/client-ca.pem"
    DEFAULT = """
        server {
            listen 80 default_server;
            listen 443 ssl default_server;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            return 444;
        }
    """
    SECURE = """
        server {
            listen 443 ssl;
            server_name app.example.test;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            ssl_client_certificate /etc/synthetic/client-ca.pem;
            ssl_verify_client on;
            location /secure/ { proxy_pass http://secure.internal:8080; }
        }
    """

    def status(self, result, path, host=None):
        return one_proxy(self, result.config, path, host)["labels"]["ferrum-migration/status"]

    def test_plaintext_only_server_overlapping_https_server_never_shares_a_listener(self):
        # Ferrum serves port-agnostic routes on every listener it opens, so the plaintext-only server's routes must
        # never be live on an HTTPS listener (where the source required a client CA for this host), and the HTTPS
        # server's routes never on the plaintext listener. The default server listens on both and stays live.
        plain = """
            server {
                listen 80;
                server_name app.example.test;
                location /plain/ { proxy_pass http://plain.internal:8080; }
            }
        """
        for tls_only in (False, True):
            with self.subTest(tls_only=tls_only):
                result, report, plan = nginx(self.DEFAULT + plain + self.SECURE, tls_only=tls_only)
                assert_structurally_valid(self, result.config)
                self.assertNotIn("nginx-frontend-scope-conflict", codes(report))
                # return 444 on the default server (both listeners) becomes a live catch-all 403 termination.
                self.assertEqual(self.status(result, "/"), "terminated")
                if tls_only:
                    self.assertEqual(self.status(result, "/plain", "app.example.test"), "refused")
                    self.assertEqual(self.status(result, "/secure", "app.example.test"), "migrated")
                    self.assertEqual(live_routes(result.config), [("/secure", ["app.example.test"])])
                    self.assertIn("frontend-protocol-scope", codes(report, "error"))
                    # The one client CA now also applies to the default server's 403 over HTTPS (stricter).
                    self.assertEqual(plan.settings.client_ca_paths, [self.CA])
                    self.assertIn("frontend-client-ca-shared", codes(report, "warning"))
                    assert_listener_contract(self, plan, result, "https", http_port=0, https_port=443,
                                             cert_pair=("/etc/synthetic/server.crt", "/etc/synthetic/server.key"),
                                             client_ca=self.CA)
                else:
                    self.assertEqual(self.status(result, "/plain", "app.example.test"), "migrated")
                    self.assertEqual(self.status(result, "/secure", "app.example.test"), "refused")
                    self.assertEqual(live_routes(result.config), [("/plain", ["app.example.test"])])
                    self.assertIn("frontend-https-disabled", codes(report, "error"))
                    self.assertEqual(plan.settings.client_ca_paths, [])
                    assert_listener_contract(self, plan, result, "http", http_port=80, https_port=0)

    def test_https_scopes_behind_a_redirect_keep_their_single_frontend(self):
        # The plaintext server only redirects (not emitted) and the default server serves both listeners, so no
        # plaintext-only scope remains: the HTTPS server and its one client CA are migrated as before.
        redirect = """
            server { listen 80; server_name app.example.test; return 301 https://$host$request_uri; }
        """
        result, report, plan = nginx(self.DEFAULT + redirect + self.SECURE, tls_only=True)
        assert_structurally_valid(self, result.config)
        self.assertEqual(self.status(result, "/secure", "app.example.test"), "migrated")
        self.assertNotEqual(self.status(result, "/"), "refused")
        self.assertNotIn("nginx-frontend-scope-conflict", codes(report))
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])

    def test_ssl_reject_handshake_on_default_tls_server_refuses_all_https_routes(self):
        conf = """
        server { listen 443 ssl default_server; ssl_reject_handshake on; }
        server {
            listen 443 ssl; server_name app.example.test;
            ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key;
            location /api/ { proxy_pass http://app.internal:8080; }
        }
        """
        result, report, _ = nginx(conf)
        assert_structurally_valid(self, result.config)
        self.assertEqual(self.status(result, "/api", "app.example.test"), "refused")
        self.assertIn("nginx-ssl-reject-handshake", codes(report, "error"))

    def test_ssl_crl_and_ssl_ocsp_refuse_mtls_server(self):
        for directive in ("ssl_crl /etc/synthetic/crl.pem;", "ssl_ocsp on;"):
            with self.subTest(directive=directive):
                conf = f"""
                server {{
                    listen 443 ssl; server_name app.example.test;
                    ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key;
                    ssl_client_certificate /etc/synthetic/client-ca.pem; ssl_verify_client on;
                    {directive}
                    location /api/ {{ proxy_pass http://app.internal:8080; }}
                }}
                """
                result, report, _ = nginx(conf)
                assert_structurally_valid(self, result.config)
                self.assertEqual(self.status(result, "/api"), "refused")
                self.assertIn("nginx-client-ca", codes(report, "error"))

    def test_inline_or_variable_backend_tls_material_refuses_route(self):
        cases = (
            "proxy_ssl_trusted_certificate data:$ca;",
            "proxy_ssl_certificate /etc/c.pem;",
            "proxy_ssl_certificate $cert; proxy_ssl_certificate_key /etc/k.key;",
        )
        for tls_lines in cases:
            with self.subTest(tls=tls_lines):
                conf = f"""
                server {{
                    listen 80; server_name app.example.test;
                    location /api/ {{
                        proxy_ssl_verify on;
                        {tls_lines}
                        proxy_pass https://app.internal:8443;
                    }}
                }}
                """
                result, report, _ = nginx(conf)
                assert_structurally_valid(self, result.config)
                self.assertEqual(self.status(result, "/api"), "refused")
                self.assertIn("route-refused", codes(report, "error"))

    def test_named_ssl_reject_handshake_without_locations_refuses_default_tls_server(self):
        conf = """
        server {
            listen 443 ssl default_server;
            ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key;
            location / { proxy_pass http://app.internal:8080; }
        }
        server {
            listen 443 ssl; server_name blocked.example.test;
            ssl_reject_handshake on;
        }
        """
        result, report, _ = nginx(conf)
        assert_structurally_valid(self, result.config)
        self.assertEqual(live_routes(result.config), [])
        self.assertEqual(self.status(result, "/"), "refused")
        self.assertIn("nginx-ssl-reject-handshake", codes(report, "error"))

    def test_proxy_ssl_name_preserved_or_refused_when_dynamic(self):
        # Static proxy_ssl_name without proxy_ssl_server_name on is preserved on a 1-target upstream.
        static_conf = """
        server {
            listen 80; server_name app.example.test;
            location /api/ {
                proxy_ssl_verify on;
                proxy_ssl_name api.internal.test;
                proxy_pass https://10.0.0.5:8443;
            }
        }
        """
        result, _report, _ = nginx(static_conf)
        assert_structurally_valid(self, result.config)
        self.assertEqual(self.status(result, "/api"), "migrated")
        self.assertEqual(len(result.config["upstreams"]), 1)
        self.assertEqual(result.config["upstreams"][0]["backend_tls_sni"], "api.internal.test")
        # Dynamic proxy_ssl_name refuses the route (never silently replaced with dial target).
        dyn_conf = """
        server {
            listen 80; server_name app.example.test;
            location /api/ {
                proxy_ssl_verify on;
                proxy_ssl_name $host;
                proxy_pass https://10.0.0.5:8443;
            }
        }
        """
        dyn_res, dyn_rep, _ = nginx(dyn_conf)
        assert_structurally_valid(self, dyn_res.config)
        self.assertEqual(self.status(dyn_res, "/api"), "refused")
        self.assertIn("route-refused", codes(dyn_rep, "error"))

    def test_shared_tls_socket_handshake_rejection_and_separate_grpc_proxy_ssl(self):
        # listen 443 default_server without explicit `ssl` shares the TLS socket with `listen 443 ssl;`.
        shared_conf = """
        server {
            listen 443 default_server;
            ssl_reject_handshake on;
        }
        server {
            listen 443 ssl; server_name app.example.test;
            ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key;
            location /api/ { proxy_pass http://app.internal:8080; }
        }
        """
        res, rep, _ = nginx(shared_conf)
        assert_structurally_valid(self, res.config)
        self.assertEqual(live_routes(res.config), [])
        self.assertIn("nginx-ssl-reject-handshake", codes(rep, "error"))

        # proxy_ssl_name and grpc_ssl_name must not overwrite each other.
        sep_conf = """
        server {
            listen 80; server_name app.example.test;
            proxy_ssl_name secure.internal.test;
            grpc_ssl_name grpc.internal.test;
            location /http/ {
                proxy_ssl_verify on;
                proxy_pass https://10.0.0.5:8443;
            }
            location /grpc/ {
                grpc_ssl_verify on;
                grpc_pass grpcs://10.0.0.6:8443;
            }
        }
        """
        sep_res, _sep_rep, _ = nginx(sep_conf)
        assert_structurally_valid(self, sep_res.config)
        snis = {u["targets"][0]["host"]: u["backend_tls_sni"] for u in sep_res.config["upstreams"]}
        self.assertEqual(snis, {"10.0.0.5": "secure.internal.test", "10.0.0.6": "grpc.internal.test"})

        # UDP QUIC on 443 must not turn a separate plaintext TCP listen 443 into HTTPS.
        quic_conf = """
        server {
            listen 443 quic;
            ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key;
            server_name h3.example.test;
            location /h3/ { proxy_pass http://h3.internal:8080; }
        }
        server {
            listen 443;
            server_name plain.example.test;
            location /plain/ { proxy_pass http://plain.internal:8080; }
        }
        """
        q_res, _q_rep, q_plan = nginx(quic_conf)
        assert_structurally_valid(self, q_res.config)
        plain_routes = [r for r in q_plan.routes if r.path == "/plain"]
        self.assertEqual(len(plain_routes), 1)
        self.assertFalse(plain_routes[0].requires_tls)
        self.assertEqual(plain_routes[0].protocols, frozenset({"http"}))

        # IPv4 wildcard TLS listen 443 ssl must not turn a separate IPv6 wildcard plaintext listen [::]:443 into HTTPS.
        v4v6_conf = """
        server {
            listen 443 ssl;
            ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key;
            server_name tls.example.test;
            location /tls/ { proxy_pass http://tls.internal:8080; }
        }
        server {
            listen [::]:443;
            server_name v6plain.example.test;
            location /v6/ { proxy_pass http://v6.internal:8080; }
        }
        """
        v_res, v_rep, v_plan = nginx(v4v6_conf)
        assert_structurally_valid(self, v_res.config)
        v6_routes = [r for r in v_plan.routes if r.path == "/v6"]
        self.assertEqual(len(v6_routes), 1)
        self.assertFalse(v6_routes[0].requires_tls)
        self.assertEqual(v6_routes[0].protocols, frozenset({"http"}))
        # Because both HTTP and HTTPS elected port 443, the profile disables HTTPS so Ferrum never gets overlapping binds.
        self.assertEqual(v_res.frontend_protocols, "http")
        self.assertIn("frontend-port-conflict", codes(v_rep, "error"))

    def test_gzip_directives_map_to_compression_plugin_with_inheritance(self):
        conf = """
        http {
            gzip on;
            gzip_proxied any;
            gzip_http_version 1.0;
            gzip_comp_level 6;
            gzip_min_length 1k;
            gzip_types application/json text/plain;
            server {
                listen 80;
                server_name app.example.test;
                location /api/ {
                    proxy_pass http://api.internal:8080;
                }
                location /nogzip/ {
                    gzip off;
                    proxy_pass http://raw.internal:8080;
                }
                location /wild/ {
                    gzip_types *;
                    proxy_pass http://wild.internal:8080;
                }
                location /typewild/ {
                    gzip_types text/*;
                    proxy_pass http://typewild.internal:8080;
                }
                location /disabled-ua/ {
                    gzip_disable "msie6";
                    proxy_pass http://ua.internal:8080;
                }
            }
        }
        """
        result, report, _ = nginx(conf)
        assert_structurally_valid(self, result.config)
        api = one_proxy(self, result.config, "/api")
        comp = plugin(self, result.config, api, "compression")["config"]
        self.assertEqual(comp, {
            "algorithms": ["gzip"],
            "min_content_length": 1024,
            "content_types": ["text/html", "application/json", "text/plain"],
            "gzip_level": 6,
            "remove_accept_encoding": False,
            "weaken_strong_etag": True,
        })
        for path in ("/nogzip", "/wild", "/typewild", "/disabled-ua"):
            p = one_proxy(self, result.config, path)
            self.assertNotIn("compression", [pl["plugin_name"] for pl in plugins_of(result.config, p)], path)
        self.assertIn("nginx-gzip", codes(report, "warning"))

        # Default gzip_proxied (off) or default gzip_http_version (1.1) omits compression rather than widening.
        for extra in ("", "gzip_proxied any;"):
            default_conf = f"""
            server {{
                listen 80;
                server_name def.example.test;
                gzip on;
                {extra}
                location /html/ {{ proxy_pass http://html.internal:8080; }}
            }}
            """
            dp_res, dp_rep, _ = nginx(default_conf)
            dp_p = one_proxy(self, dp_res.config, "/html")
            self.assertNotIn("compression", [pl["plugin_name"] for pl in plugins_of(dp_res.config, dp_p)])
            self.assertIn("nginx-gzip", codes(dp_rep, "warning"))

        # Explicit gzip_proxied any + gzip_http_version 1.0 without gzip_types compresses ONLY text/html
        # and emits NGINX's explicit defaults (min_content_length: 20, gzip_level: 1).
        html_only_conf = """
        server {
            listen 80;
            server_name def.example.test;
            gzip on;
            gzip_proxied any;
            gzip_http_version 1.0;
            location /html/ { proxy_pass http://html.internal:8080; }
        }
        """
        def_res, def_rep, _ = nginx(html_only_conf)
        html_p = one_proxy(self, def_res.config, "/html")
        self.assertEqual(plugin(self, def_res.config, html_p, "compression")["config"], {
            "algorithms": ["gzip"], "min_content_length": 20, "content_types": ["text/html"],
            "gzip_level": 1, "remove_accept_encoding": False, "weaken_strong_etag": True,
        })
        self.assertIn("nginx-gzip", codes(def_rep, "warning"))

        # gzip_min_length exceeding u64::MAX, Python's int digit limit, or missing arguments omits compression cleanly.
        for min_directive in ("gzip_min_length 18446744073709551616;", f"gzip_min_length {'9' * 4400};",
                              "gzip_min_length;"):
            huge_min_conf = f"""
            server {{
                listen 80;
                server_name def.example.test;
                gzip on;
                gzip_proxied any;
                gzip_http_version 1.0;
                {min_directive}
                location /html/ {{ proxy_pass http://html.internal:8080; }}
            }}
            """
            hm_res, hm_rep, _ = nginx(huge_min_conf)
            self.assertEqual(plugins_of(hm_res.config, one_proxy(self, hm_res.config, "/html")), [])
            self.assertIn("nginx-gzip", codes(hm_rep, "warning"))

        # Malformed or huge proxy_read_timeout values do not backtrack catastrophically or crash int() (and warn).
        for bad_to in ("1" * 37 + "x", "9" * 4400 + "s"):
            bad_to_conf = f"""
            server {{
                listen 80;
                server_name to.example.test;
                proxy_read_timeout {bad_to};
                location /api/ {{ proxy_pass http://api.internal:8080; }}
            }}
            """
            bt_res, bt_rep, _ = nginx(bad_to_conf)
            self.assertEqual(one_proxy(self, bt_res.config, "/api")["labels"][
                "ferrum-migration/status"], "migrated")
            self.assertIn("nginx-timeout", codes(bt_rep, "warning"))
        # Valid spaced compound NGINX timeout ("1m 500ms") is parsed accurately.
        spaced_to_res, _spaced_rep, _ = nginx("""
            server {
                listen 80;
                server_name to.example.test;
                proxy_read_timeout "1m 500ms";
                location /api/ { proxy_pass http://api.internal:8080; }
            }
        """)
        self.assertEqual(one_proxy(self, spaced_to_res.config, "/api")["backend_read_timeout_ms"],
                         60_500)

        # Static HTTPS redirect location on a mixed plaintext server stays a live 301 termination (not refused);
        # 1-arg `return https://$host$request_uri;` folds cleanly alongside a live HTTPS server.
        mixed_static_res, _ms_rep, _ = nginx("""
            server {
                listen 80;
                server_name a.example.test;
                location / { proxy_pass http://app.internal:8080; }
                location = /login { return 301 https://auth.example.test/login; }
            }
        """)
        login_p = one_proxy(self, mixed_static_res.config, "=/login")
        self.assertEqual(login_p["labels"]["ferrum-migration/status"], "terminated")
        self.assertEqual(plugin(self, mixed_static_res.config, login_p, "request_termination")["config"]["status_code"],
                         301)
        one_arg_res, one_arg_rep, _ = nginx("""
            server {
                listen 80;
                server_name a.example.test;
                return https://$host$request_uri;
            }
            server {
                listen 443 ssl;
                server_name a.example.test;
                ssl_certificate /etc/certs/tls.crt;
                ssl_certificate_key /etc/certs/tls.key;
                location /api/ { proxy_pass http://app.internal:8080; }
            }
        """)
        self.assertTrue(one_arg_res.tls_only)
        self.assertIn("nginx-https-redirect", codes(one_arg_rep, "info"))
        # Plaintext server returning a static fixed HTTPS destination (not a $request_uri scheme upgrade) stays a
        # static 301 host-only termination route even alongside a default server; fail_timeout > 86400s clamps
        # regardless of flag order (max_fails before or after fail_timeout).
        for flags in ("max_fails=2 fail_timeout=2d", "fail_timeout=2d max_fails=2"):
            fixed_dest_res, fixed_dest_rep, _ = nginx(f"""
                upstream slow {{
                    server 10.0.0.1:8080 {flags};
                }}
                server {{
                    listen 80;
                    server_name legacy.example.test;
                    return 301 https://auth.example.test/login;
                }}
                server {{
                    listen 80 default_server;
                    location /api/ {{ proxy_pass http://slow; }}
                }}
            """)
            legacy_p = one_proxy(self, fixed_dest_res.config, None, "legacy.example.test")
            self.assertEqual(legacy_p["labels"]["ferrum-migration/status"], "terminated")
            self.assertEqual(proxies(fixed_dest_res.config, "~/.*", "legacy.example.test"), [])
            self.assertEqual(plugin(self, fixed_dest_res.config, legacy_p, "request_termination")["config"]["headers"][
                "location"], "https://auth.example.test/login")
            passive = fixed_dest_res.config["upstreams"][0]["health_checks"]["passive"]
            self.assertEqual(passive["unhealthy_window_seconds"], 86_400)
            self.assertEqual(passive["healthy_after_seconds"], 86_400)
            self.assertTrue(any(c.code == "nginx-passive-health" and "86400" in c.message
                                for c in fixed_dest_rep.caveats))

        # Redirect-only plaintext server alongside a wildcard/default plaintext server stays as a refused host-only
        # placeholder without any shadowing ~/.* 404 closure, so the default server's '/' stays live for other hosts.
        mixed_redir_conf = """
        server {
            listen 80;
            server_name secure.example.test;
            return 301 https://$host$request_uri;
        }
        server {
            listen 80 default_server;
            location / { proxy_pass http://public.internal:8080; }
        }
        """
        mr_res, _mr_rep, _ = nginx(mixed_redir_conf)
        self.assertEqual(one_proxy(self, mr_res.config, None, "secure.example.test")["labels"][
            "ferrum-migration/status"], "refused")
        self.assertEqual(proxies(mr_res.config, "~/.*", "secure.example.test"), [])
        catchall = [p for p in proxies(mr_res.config, "/") if "hosts" not in p]
        self.assertEqual(len(catchall), 1)
        self.assertEqual(catchall[0]["labels"]["ferrum-migration/status"], "migrated")
        # Mixed upstream passive health thresholds (1000 vs 1001) are compared BEFORE clamping and omitted with warning.
        mixed_hc_res, mixed_hc_rep, _ = nginx("""
            upstream mixed {
                server 10.0.0.1:8080 max_fails=1000 fail_timeout=10s;
                server 10.0.0.2:8080 max_fails=1001 fail_timeout=10s;
            }
            server {
                listen 80;
                location /api/ { proxy_pass http://mixed; }
            }
        """)
        self.assertNotIn("health_checks", mixed_hc_res.config["upstreams"][0])
        self.assertIn("nginx-passive-health", codes(mixed_hc_rep, "warning"))
        # Refused named HTTP server alongside a separate empty HTTP default and live catch-all HTTPS '/' in TLS-only
        # mode omits both the colliding '/' placeholder, the shadowing '/extra' placeholder, and the HTTP-only scope
        # closure so Ferrum validates cleanly and HTTPS forwards plain.example.test to the live HTTPS default.
        http_named_https_default = """
        server { listen 80 default_server; }
        server {
            listen 80;
            server_name plain.example.test;
            location / { proxy_pass http://plain.internal:8080; }
            location /extra/ { proxy_pass http://plain.internal:8080; }
        }
        server {
            listen 443 ssl default_server;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            location / { proxy_pass http://tls.internal:8080; }
        }
        """
        hn_res, hn_rep, _ = nginx(http_named_https_default, tls_only=True)
        assert_structurally_valid(self, hn_res.config)
        self.assertIn("frontend-protocol-scope", codes(hn_rep, "error"))
        self.assertNotIn("nginx-default-server-conflict", codes(hn_rep))
        self.assertEqual(len(hn_res.config["proxies"]), 1)
        root_proxy = hn_res.config["proxies"][0]
        self.assertEqual(root_proxy.get("listen_path"), "/")
        self.assertNotIn("hosts", root_proxy)
        self.assertEqual(root_proxy["labels"]["ferrum-migration/status"], "migrated")
        # A dual-listener server that redirects HTTP via `if ($scheme = http)` owns its hostname on HTTP: in
        # HTTP-only mode its HostScope stays active so HTTP requests for that host fail closed (404) instead of
        # reaching the plaintext default backend.
        redirect_owner_conf = """
        server {
            listen 80 default_server;
            location / { proxy_pass http://public.internal:8080; }
        }
        server {
            listen 80;
            listen 443 ssl;
            server_name secure.example.test;
            ssl_certificate /etc/synthetic/server.crt;
            ssl_certificate_key /etc/synthetic/server.key;
            if ($scheme = http) { return 301 https://$host$request_uri; }
            location = /secure { proxy_pass http://secure.internal:8080; }
        }
        """
        ro_res, _ro_rep, _ = nginx(redirect_owner_conf)
        assert_structurally_valid(self, ro_res.config)
        self.assertEqual(ro_res.frontend_protocols, "http")
        self.assertEqual(one_proxy(self, ro_res.config, None, "secure.example.test")["labels"][
            "ferrum-migration/status"], "scope-default")


if __name__ == "__main__":
    unittest.main()
