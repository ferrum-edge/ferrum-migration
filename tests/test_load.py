"""Scale and hostile-input tests: large synthetic configs must finish quickly and bounded.

Budgets are deliberately generous for slow CI runners; the point is to catch
accidental quadratic-or-worse behavior and unbounded resource use.
"""

import time
import unittest

import yaml

from helpers import assert_structurally_valid, migrate

from ferrum_migration.errors import InputError
from ferrum_migration.limits import Limits

BUDGET_SECONDS = 90


class LoadTest(unittest.TestCase):
    def timed(self, platform, text, fmt="yaml", **kwargs):
        start = time.perf_counter()
        result, report, plan = migrate(platform, text, fmt=fmt, **kwargs)
        elapsed = time.perf_counter() - start
        self.assertLess(elapsed, BUDGET_SECONDS, f"{platform} took {elapsed:.1f}s")
        assert_structurally_valid(self, result.config)
        return result

    def test_large_kong(self):
        count = 2000
        doc = {
            "_format_version": "3.0",
            "services": [{
                "name": f"svc-{i:05d}", "url": f"http://svc-{i:05d}.internal:8080",
                "routes": [{"name": f"route-{i:05d}", "paths": [f"/svc-{i:05d}"],
                            "plugins": [{"name": "rate-limiting", "config": {"second": 10}}]}],
                "plugins": [{"name": "key-auth", "config": {"key_names": ["apikey"]}}],
            } for i in range(count)],
            "consumers": [{"username": f"user-{i:05d}",
                           "keyauth_credentials": [{"key": f"test-only-load-key-{i:08d}"}]} for i in range(count)],
        }
        result = self.timed("kong", yaml.safe_dump(doc), include_secrets=True)
        self.assertEqual(result.stats["migrated_routes"], count)
        self.assertEqual(result.secrets_emitted, count)

    def test_large_nginx(self):
        locations = "\n".join(
            f"location /svc-{i:05d}/ {{ proxy_pass http://b{i:05d}.internal:8080/; proxy_set_header Host $host; }}"
            for i in range(1500))
        text = f"http {{ server {{ listen 80; server_name big.example.com; {locations} }} }}"
        result = self.timed("nginx", text, fmt="nginx")
        self.assertEqual(result.stats["migrated_routes"], 1500)

    def test_large_traefik(self):
        routers = {f"r{i}": {"rule": f"Host(`h{i}.example.com`) && PathPrefix(`/p`)", "service": "s"}
                   for i in range(1000)}
        doc = {"http": {"routers": routers,
                        "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}}}
        result = self.timed("traefik", yaml.safe_dump(doc), traefik_entrypoints_asserted=True)
        self.assertEqual(result.stats["migrated_routes"], 1000)

    def test_large_traefik_default_refusal(self):
        # Without the operator's entryPoint assertion every forwarding router is refused, still bounded.
        routers = {f"r{i}": {"rule": f"Host(`h{i}.example.com`) && PathPrefix(`/p`)", "service": "s",
                             "entryPoints": ["web"]} for i in range(1000)}
        doc = {"http": {"routers": routers,
                        "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}}}
        result = self.timed("traefik", yaml.safe_dump(doc))
        self.assertEqual(result.stats["migrated_routes"], 0)

    def test_large_envoy_virtual_host(self):
        routes = [{"name": f"r{i}", "match": {"prefix": f"/r-{i:05d}/"}, "route": {"cluster": "c"}} for i in range(800)]
        doc = {"static_resources": {
            "listeners": [{"name": "l", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
                           "filter_chains": [{"filters": [{
                               "name": "envoy.filters.network.http_connection_manager",
                               "typed_config": {"route_config": {"virtual_hosts": [
                                   {"name": "v", "domains": ["*"], "routes": routes}]},
                                   "http_filters": [{"name": "envoy.filters.http.router"}]}}]}]}],
            "clusters": [{"name": "c", "type": "STRICT_DNS", "load_assignment": {"endpoints": [{"lb_endpoints": [
                {"endpoint": {"address": {"socket_address": {"address": "c.internal", "port_value": 80}}}}]}]}}]}}
        result = self.timed("envoy", yaml.safe_dump(doc))
        self.assertEqual(result.stats["migrated_routes"], 800)

    def test_large_istio_virtual_service(self):
        gateway = {"apiVersion": "networking.istio.io/v1", "kind": "Gateway",
                   "metadata": {"name": "gw", "namespace": "default"},
                   "spec": {"servers": [{"port": {"number": 80, "protocol": "HTTP"}, "hosts": ["big.example.com"]}]}}
        http = [{"match": [{"uri": {"prefix": f"/p-{i:05d}/"}}],
                 "route": [{"destination": {"host": f"s{i}", "port": {"number": 80}}}]} for i in range(500)]
        vs = {"apiVersion": "networking.istio.io/v1", "kind": "VirtualService",
              "metadata": {"name": "vs", "namespace": "default"},
              "spec": {"hosts": ["big.example.com"], "gateways": ["gw"], "http": http}}
        result = self.timed("istio", yaml.safe_dump_all([gateway, vs]))
        self.assertEqual(result.stats["migrated_routes"], 500)


class HostileInputTest(unittest.TestCase):
    def assert_fast_rejection(self, platform, text, fmt="yaml", limits=None):
        start = time.perf_counter()
        with self.assertRaises(InputError):
            migrate(platform, text, fmt=fmt, limits=limits)
        self.assertLess(time.perf_counter() - start, 30)

    def test_nginx_token_flood(self):
        self.assert_fast_rejection("nginx", "a " * 50_000 + ";", fmt="nginx", limits=Limits(max_nginx_tokens=10_000))

    def test_yaml_node_flood(self):
        text = "routes: [" + ",".join(["1"] * 20_000) + "]\n"
        self.assert_fast_rejection("kong", text, limits=Limits(max_nodes=5_000))

    def test_alias_bomb_against_translator(self):
        lines = ["_format_version: '3.0'", 'x: &a ["y","y","y","y","y","y","y","y","y","y"]']
        previous = "a"
        for name in "bcdefg":
            lines.append(f"{name}{name}: &{name} [" + ",".join([f"*{previous}"] * 10) + "]")
            previous = name
        self.assert_fast_rejection("kong", "\n".join(lines) + "\n")

    def test_route_budget(self):
        doc = {"_format_version": "3.0", "services": [
            {"name": "s", "url": "http://s.internal", "routes": [{"name": f"r{i}", "paths": [f"/r{i}"]}
                                                               for i in range(60)]}]}
        self.assert_fast_rejection("kong", yaml.safe_dump(doc), limits=Limits(max_routes=50))

    def test_traefik_precedence_budget(self):
        routers = {f"r{i}": {"rule": f"PathPrefix(`/p{i}`)", "service": "s"} for i in range(60)}
        doc = {"http": {"routers": routers,
                        "services": {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}}}
        self.assert_fast_rejection("traefik", yaml.safe_dump(doc), limits=Limits(max_precedence_routes=50))


if __name__ == "__main__":
    unittest.main()
