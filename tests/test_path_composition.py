"""Forwarded-path composition and client-IP settings, as resolved from Ferrum Edge source.

Ferrum forwards ``backend_path`` followed by the request path after the proxy's listen path, inserting
``/`` only when neither side has one (``with_backend_path_parts`` / ``backend_path_layout`` in Edge
``src/proxy/mod.rs``). The emitter forms the listen path from a source prefix minus one trailing ``/``.
Each source derives the ``backend_path`` that reproduces its own composition.
"""

import textwrap
import unittest

import yaml

from helpers import codes, migrate, one_proxy

from ferrum_migration.envprofile import render
from ferrum_migration.sources.common import replaced_prefix_backend_path
from test_envoy import bootstrap_with_routes


def compose(listen_path: str, backend_path: str | None, request: str) -> str:
    """Edge's forwarded path for a strip_listen_path prefix proxy (mirror of backend_path_layout)."""
    remaining = request[len(listen_path):]
    backend = backend_path or ""
    if not backend and not remaining:
        return "/"
    combined = backend + ("/" if backend and remaining and not backend.endswith("/")
                          and not remaining.startswith("/") else "") + remaining
    return combined if combined.startswith("/") else "/" + combined


def nginx(text):
    return migrate("nginx", textwrap.dedent(text), fmt="nginx")


class ReplacedPrefixTest(unittest.TestCase):
    """The helper reproduces "replace the matched prefix" (NGINX URI, Envoy prefix_rewrite, Istio rewrite)."""

    CASES = [
        # (source prefix, rewrite, requests)
        ("/api/", "/v1/", ["/api/x", "/api/"]),
        ("/api", "/v1/", ["/api/x", "/api"]),
        ("/api", "/v1", ["/api/x", "/api"]),
        ("/api", "/", ["/api/x", "/api"]),
        ("/api/", "/", ["/api/x", "/api/"]),
        ("/", "/v1/", ["/x", "/"]),
    ]

    def test_exact_reproduction(self):
        for prefix, rewrite, requests in self.CASES:
            backend, exact = replaced_prefix_backend_path("prefix", prefix, rewrite)
            self.assertTrue(exact, (prefix, rewrite))
            listen = prefix[:-1] if prefix != "/" and prefix.endswith("/") else prefix
            for request in requests:
                with self.subTest(prefix=prefix, rewrite=rewrite, request=request):
                    source = rewrite + request[len(prefix):]
                    self.assertEqual(compose(listen, backend, request), source)

    def test_slash_mismatch_is_reported_as_inexact(self):
        self.assertEqual(replaced_prefix_backend_path("prefix", "/api/", "/v1"), ("/v1", False))
        self.assertEqual(replaced_prefix_backend_path("prefix", "/", "/v1"), ("/v1", False))
        self.assertEqual(replaced_prefix_backend_path("exact", "/e", "/x/"), ("/x/", True))


class NginxPathTest(unittest.TestCase):
    def test_trailing_slashes_follow_nginx(self):
        result, report, _plan = nginx("""
            server { listen 80; server_name app.example.test;
              location /svc/ { proxy_pass http://a.internal:8080/inner/; }
              location = /exact { proxy_pass http://a.internal:8080/target/; }
            }
            """)
        svc = one_proxy(self, result.config, "/svc")
        self.assertEqual(svc["backend_path"], "/inner")
        self.assertEqual(compose("/svc", svc["backend_path"], "/svc/"), "/inner/")  # was /inner before the fix
        exact = one_proxy(self, result.config, "=/exact")
        self.assertEqual(exact["backend_path"], "/target/")
        self.assertNotIn("nginx-exact-rewrite", codes(report))
        self.assertNotIn("nginx-slash-mismatch", codes(report))

    def test_missing_slash_in_uri_is_reported(self):
        _result, report, _plan = nginx("""
            server { listen 80; server_name app.example.test;
              location /svc/ { proxy_pass http://a.internal:8080/inner; } }
            """)
        self.assertIn("nginx-slash-mismatch", codes(report))


class EnvoyPathTest(unittest.TestCase):
    def test_prefix_rewrite(self):
        doc = bootstrap_with_routes([
            {"name": "a", "match": {"prefix": "/api/"}, "route": {"cluster": "c", "prefix_rewrite": "/v1/"}},
            {"name": "b", "match": {"path_separated_prefix": "/raw"}, "route": {"cluster": "c", "prefix_rewrite": "/"}},
        ])
        result, report, _plan = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result.config, "/api", "app.example.test")["backend_path"], "/v1")
        raw = one_proxy(self, result.config, "/raw", "app.example.test")
        self.assertEqual(raw["backend_path"], "/")
        self.assertEqual(compose("/raw", raw["backend_path"], "/raw/x"), "//x")  # Envoy: "/" + "/x"
        self.assertNotIn("envoy-exact-rewrite", codes(report))

    def test_empty_rewrite_is_unset_and_empty_prefix_prepends(self):
        doc = bootstrap_with_routes([
            {"name": "keep", "match": {"prefix": "/keep"}, "route": {"cluster": "c", "prefix_rewrite": ""}},
            {"name": "all", "match": {"prefix": ""}, "route": {"cluster": "c", "prefix_rewrite": "/v1/"}},
        ])
        result, _report, _plan = migrate("envoy", yaml.safe_dump(doc))
        keep = one_proxy(self, result.config, "/keep", "app.example.test")
        self.assertFalse(keep["strip_listen_path"])  # Envoy: an empty prefix_rewrite is unset
        self.assertNotIn("backend_path", keep)
        catch_all = one_proxy(self, result.config, "/", "app.example.test")
        self.assertFalse(catch_all["strip_listen_path"])  # the empty matched prefix is replaced: no stripping
        self.assertEqual(catch_all["backend_path"], "/v1/")
        # Envoy: "/v1/" + "/x" = "/v1//x"; Ferrum appends the unstripped path to the backend path.
        self.assertEqual(catch_all["backend_path"] + "/x", "/v1//x")

    def test_proxy_protocol_options(self):
        def listener_with(config):
            doc = bootstrap_with_routes([{"name": "r", "match": {"prefix": "/"}, "route": {"cluster": "c"}}])
            doc["static_resources"]["listeners"][0]["listener_filters"] = [{
                "name": "envoy.filters.listener.proxy_protocol",
                "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.listener.proxy_protocol.v3."
                                          "ProxyProtocol", **config}}]
            result, report, plan = migrate("envoy", yaml.safe_dump(doc))
            return render("file", "envoy", plan.settings, result.tls_only, result.basic_auth_used,
                          "resources.yaml").splitlines(), report

        lines, report = listener_with({"allow_requests_without_proxy_protocol": True})
        self.assertFalse([line for line in lines if line.startswith("# FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP=")])
        self.assertIn("envoy-proxy-protocol-optional", codes(report))
        lines, _report = listener_with({"disallowed_versions": ["V1"]})
        self.assertIn("# FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP=v2", lines)
        lines, _report = listener_with({})
        self.assertIn("# FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP=auto", lines)


class TraefikPathTest(unittest.TestCase):
    def convert(self, middlewares, rule):
        doc = {"http": {
            "routers": {"r": {"rule": rule, "service": "s", "middlewares": list(middlewares)}},
            "middlewares": middlewares,
            "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:8080"}]}}}}}
        return migrate("traefik", yaml.safe_dump(doc), traefik_controls_asserted=True)

    def test_strip_prefix_below_a_trailing_slash_route(self):
        result, _report, _plan = self.convert({"strip": {"stripPrefix": {"prefixes": ["/api"]}}},
                                              "PathPrefix(`/api/v1/`)")
        proxy = one_proxy(self, result.config, "/api/v1")
        self.assertEqual(proxy["backend_path"], "/v1")
        self.assertEqual(compose("/api/v1", proxy["backend_path"], "/api/v1/x"), "/v1/x")  # Traefik: "/v1/x"

    def test_add_prefix_keeps_its_trailing_slash(self):
        result, _report, _plan = self.convert({"add": {"addPrefix": {"prefix": "/v1/"}}}, "PathPrefix(`/api`)")
        proxy = one_proxy(self, result.config, "/api")
        self.assertEqual(proxy["backend_path"], "/v1/")  # Traefik: "/v1/" + "/api/x" = "/v1//api/x"

    def test_strip_and_add_with_a_doubled_slash_is_representable(self):
        # Traefik: /api/orders/x -> strip /api -> /orders/x -> add /v1/ -> /v1//orders/x. Edge appends the
        # backend path verbatim, so the empty segment is emitted, not refused.
        result, report, _plan = self.convert({"strip": {"stripPrefix": {"prefixes": ["/api"]}},
                                              "add": {"addPrefix": {"prefix": "/v1/"}}}, "PathPrefix(`/api/orders`)")
        proxy = one_proxy(self, result.config, "/api/orders")
        self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(proxy["backend_path"], "/v1//orders")
        self.assertEqual(compose("/api/orders", proxy["backend_path"], "/api/orders/x"), "/v1//orders/x")
        self.assertNotIn("traefik-path-composition", codes(report))

    def test_bare_route_path_follows_force_slash(self):
        middlewares = {"strip": {"stripPrefix": {"prefixes": ["/api"]}}, "add": {"addPrefix": {"prefix": "/v1"}}}
        # forceSlash false (Traefik v3.8 default): /api strips to "" and /v1 + "" = /v1, exactly as Ferrum.
        result, report, _plan = self.convert(middlewares, "PathPrefix(`/api`)")
        proxy = one_proxy(self, result.config, "/api")
        self.assertEqual(compose("/api", proxy["backend_path"], "/api"), "/v1")
        self.assertEqual(compose("/api", proxy["backend_path"], "/api/x"), "/v1/x")
        self.assertNotIn("traefik-path-composition", codes(report))
        # forceSlash true: /api strips to "/" and Traefik sends /v1/, which Ferrum cannot (it sends /v1).
        middlewares["strip"]["stripPrefix"]["forceSlash"] = True
        _result, report, _plan = self.convert(middlewares, "PathPrefix(`/api`)")
        self.assertIn("traefik-path-composition", codes(report))

    def test_force_slash_on_an_exact_route_is_exact(self):
        middlewares = {"strip": {"stripPrefix": {"prefixes": ["/api"], "forceSlash": True}},
                       "add": {"addPrefix": {"prefix": "/v1"}}}
        result, report, _plan = self.convert(middlewares, "Path(`/api`)")
        proxy = one_proxy(self, result.config, "=/api")
        self.assertEqual(proxy["backend_path"], "/v1/")  # Traefik: /v1 + "/" (forceSlash)
        self.assertNotIn("traefik-path-composition", codes(report))


class KongPathTest(unittest.TestCase):
    def test_service_path_trailing_slash_follows_path_handling_v0(self):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080/v1/
                routes: [{name: r, paths: [/orders]}]
            """)
        result, _report, _plan = migrate("kong", text)
        proxy = one_proxy(self, result.config, "/orders")
        self.assertEqual(proxy["backend_path"], "/v1")
        # Kong v0: "/orders" -> "/v1", "/orders/x" -> "/v1/x"
        self.assertEqual(compose("/orders", proxy["backend_path"], "/orders"), "/v1")
        self.assertEqual(compose("/orders", proxy["backend_path"], "/orders/x"), "/v1/x")

    def kong(self, route):
        text = textwrap.dedent("""
            _format_version: "3.0"
            services:
              - name: s
                url: http://s.internal:8080/v1
                routes: [ROUTE]
            """).replace("ROUTE", route)
        return migrate("kong", text)

    def test_unstripped_root_request_is_reported(self):
        # Kong v0 forwards "/" as /v1 wherever Ferrum would not strip the root slash (it sends /v1/).
        for route in ("{name: r, paths: [/], strip_path: false}",
                      "{name: r, hosts: [app.example.test]}",
                      "{name: r, hosts: [app.example.test], strip_path: false}",
                      '{name: r, paths: ["~^/$"], strip_path: false}'):
            with self.subTest(route=route):
                _result, report, _plan = self.kong(route)
                self.assertIn("kong-path-composition", codes(report))

    def test_stripped_root_route_is_exact(self):
        # paths: [/] with strip: Kong and Ferrum both strip "/" and forward /v1 for "/".
        _result, report, _plan = self.kong("{name: r, paths: [/]}")
        self.assertNotIn("kong-path-composition", codes(report))


class IstioRouteSemanticsTest(unittest.TestCase):
    def convert(self, annotations):
        meta = {"name": "app", "namespace": "default"}
        if annotations:
            meta["annotations"] = annotations
        docs = [
            {"apiVersion": "networking.istio.io/v1", "kind": "Gateway", "metadata": {"name": "gw", "namespace": "default"},
             "spec": {"servers": [{"port": {"number": 80, "name": "http", "protocol": "HTTP"},
                                   "hosts": ["app.example.test"]}]}},
            {"apiVersion": "networking.istio.io/v1", "kind": "VirtualService", "metadata": meta,
             "spec": {"hosts": ["app.example.test"], "gateways": ["gw"], "http": [
                 {"name": "api", "match": [{"uri": {"prefix": "/api/"}}],
                  "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]},
                 {"name": "rest", "route": [{"destination": {"host": "web.default.svc.cluster.local", "port": {"number": 8080}}}]}]}},
        ]
        return migrate("istio", yaml.safe_dump_all(docs))

    def test_generated_virtual_service_uses_segment_prefixes(self):
        result, report, plan = self.convert({"internal.istio.io/route-semantics": "gateway"})
        api = [r for r in plan.routes if r.name == "api"][0]
        self.assertEqual((api.kind, api.path, api.prefix_semantics), ("prefix", "/api", "segment"))
        self.assertIn("/api", [p.get("listen_path") for p in result.config["proxies"]])
        self.assertNotIn("prefix-string-siblings", codes(report))

    def test_disjoint_segment_prefixes_both_forward(self):
        # /api before /apix: Istio's path-separated prefixes (and Ferrum's segments) never share a request.
        docs = [
            {"apiVersion": "networking.istio.io/v1", "kind": "Gateway", "metadata": {"name": "gw", "namespace": "default"},
             "spec": {"servers": [{"port": {"number": 80, "name": "http", "protocol": "HTTP"},
                                   "hosts": ["app.example.test"]}]}},
            {"apiVersion": "networking.istio.io/v1", "kind": "VirtualService",
             "metadata": {"name": "app", "namespace": "default",
                          "annotations": {"internal.istio.io/route-semantics": "ingress"}},
             "spec": {"hosts": ["app.example.test"], "gateways": ["gw"], "http": [
                 {"name": "api", "match": [{"uri": {"prefix": "/api"}}],
                  "route": [{"destination": {"host": "api.default.svc.cluster.local", "port": {"number": 8080}}}]},
                 {"name": "apix", "match": [{"uri": {"prefix": "/apix"}}],
                  "route": [{"destination": {"host": "apix.default.svc.cluster.local", "port": {"number": 8080}}}]}]}},
        ]
        result, _report, _plan = migrate("istio", yaml.safe_dump_all(docs))
        for path in ("/api", "/apix"):
            proxy = one_proxy(self, result.config, path, "app.example.test")
            self.assertEqual(proxy["labels"]["ferrum-migration/status"], "migrated", path)

    def test_ordinary_virtual_service_keeps_string_prefixes(self):
        _result, _report, plan = self.convert(None)
        api = [r for r in plan.routes if r.name == "api"][0]
        self.assertEqual(api.prefix_semantics, "string")


class ClientIpSettingsTest(unittest.TestCase):
    def conf(self, text):
        result, report, plan = nginx(text)
        return render("file", "nginx", plan.settings, result.tls_only, result.basic_auth_used, "resources.yaml"), \
            report

    def test_trusted_proxies_are_ips_or_cidrs_only(self):
        conf, report = self.conf("""
            http {
              set_real_ip_from 10.0.0.1;
              set_real_ip_from 192.168.1.5/24;
              set_real_ip_from unix:;
              set_real_ip_from proxy.example.test;
              real_ip_header X-Forwarded-For;
              real_ip_recursive on;
              server { listen 80; server_name app.example.test; location / { proxy_pass http://a.internal:8080; } }
            }
            """)
        self.assertIn("# FERRUM_TRUSTED_PROXIES=10.0.0.1,192.168.1.0/24", conf.splitlines())
        self.assertNotIn("FERRUM_REAL_IP_HEADER", conf)
        self.assertIn("nginx-real-ip-source", codes(report))

    def test_forwarded_for_without_recursion_is_not_suggested(self):
        # real_ip_recursive off (default): NGINX uses the last XFF address even when trusted; Ferrum skips it.
        conf, report = self.conf("""
            http {
              set_real_ip_from 10.0.0.0/8;
              real_ip_header X-Forwarded-For;
              server { listen 80; server_name app.example.test; location / { proxy_pass http://a.internal:8080; } }
            }
            """)
        self.assertNotIn("FERRUM_TRUSTED_PROXIES=", conf)
        self.assertIn("nginx-real-ip-recursive", codes(report))

    def test_default_header_is_x_real_ip(self):
        conf, report = self.conf("""
            http {
              set_real_ip_from 10.0.0.0/8;
              server { listen 80; server_name app.example.test; location / { proxy_pass http://a.internal:8080; } }
            }
            """)
        lines = conf.splitlines()
        self.assertIn("# FERRUM_REAL_IP_HEADER=X-Real-IP", lines)
        self.assertIn("# FERRUM_TRUSTED_PROXIES=10.0.0.0/8", lines)
        self.assertIn("nginx-real-ip-fallback", codes(report))

    def test_proxy_protocol_real_ip_source(self):
        conf, _report = self.conf("""
            http {
              set_real_ip_from 10.0.0.0/8;
              real_ip_header proxy_protocol;
              server { listen 80 proxy_protocol; server_name app.example.test;
                       location / { proxy_pass http://a.internal:8080; } }
            }
            """)
        lines = conf.splitlines()
        self.assertIn("# FERRUM_FRONTEND_PROXY_PROTOCOL_TRUSTED_CIDRS=10.0.0.0/8", lines)
        self.assertNotIn("FERRUM_TRUSTED_PROXIES=", conf)

    def test_real_ip_header_and_proxy_protocol(self):
        conf, _report = self.conf("""
            http {
              set_real_ip_from 10.0.0.0/8;
              real_ip_header X-Real-IP;
              server { listen 80 proxy_protocol; server_name app.example.test;
                       location / { proxy_pass http://a.internal:8080; } }
            }
            """)
        lines = conf.splitlines()
        self.assertIn("# FERRUM_REAL_IP_HEADER=X-Real-IP", lines)
        self.assertIn("# FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP=auto", lines)
        self.assertNotIn("# FERRUM_FRONTEND_PROXY_PROTOCOL_HTTP=true", lines)


class StatusWordingTest(unittest.TestCase):
    def test_preview_is_current_not_permanent(self):
        import os
        from helpers import ROOT
        for name in ("README.md", os.path.join("docs", "releasing.md")):
            with open(os.path.join(ROOT, name), encoding="utf-8") as handle:
                text = handle.read()
            with self.subTest(name=name):
                self.assertNotIn("stays on `0.x`", text)
                self.assertIn("currently a `0.x` preview", text)


if __name__ == "__main__":
    unittest.main()
