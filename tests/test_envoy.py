import copy
import json
import unittest

import yaml

from helpers import assert_structurally_valid, codes, migrate, one_proxy, plugin, proxies, read_fixture, upstream_of


class EnvoyFixtureTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, self.plan = migrate("envoy", read_fixture("envoy", "envoy.yaml"))
        self.config = self.result.config

    def test_structure(self):
        assert_structurally_valid(self, self.config)
        self.assertFalse(self.result.tls_only)
        self.assertEqual(self.plan.settings.main_http_port, 8080)

    def test_route_cluster_timeouts_and_retries(self):
        proxy = one_proxy(self, self.config, "/users", "api.example.com")
        self.assertTrue(proxy["preserve_host_header"])
        self.assertEqual(proxy["backend_read_timeout_ms"], 10000)
        self.assertEqual(proxy["backend_connect_timeout_ms"], 2000)
        self.assertEqual(proxy["retry"]["max_retries"], 2)
        self.assertTrue(proxy["retry"]["retry_on_connect_failure"])
        self.assertEqual(len(proxy["retry"]["retryable_status_codes"]), 100)
        upstream = upstream_of(self.config, proxy)
        self.assertEqual(upstream["targets"], [{"host": "users.internal", "port": 8080, "weight": 1}])

    def test_shadowed_route_not_emitted(self):
        self.assertEqual(proxies(self.config, "/users/v2"), [])
        self.assertIn("route-shadowed", codes(self.report, "warning"))

    def test_weighted_clusters_and_prefix_rewrite(self):
        proxy = one_proxy(self, self.config, "/orders", "api.example.com")
        self.assertTrue(proxy["strip_listen_path"])
        self.assertEqual(proxy["backend_path"], "/api/orders")
        upstream = upstream_of(self.config, proxy)
        self.assertEqual([(t["host"], t["weight"]) for t in upstream["targets"]], [("10.0.1.10", 1000), ("10.0.1.20", 250)])

    def test_direct_response_and_header_match(self):
        health = one_proxy(self, self.config, "=/healthz", "api.example.com")
        self.assertEqual(plugin(self, self.config, health, "request_termination")["config"]["body"], "ok")
        beta = one_proxy(self, self.config, "/beta", "api.example.com")
        self.assertEqual(beta["labels"]["ferrum-migration/status"], "refused")
        catch_all = one_proxy(self, self.config, "/")
        self.assertEqual(catch_all["labels"]["ferrum-migration/status"], "migrated")

    def test_virtual_host_closure_prevents_fallthrough(self):
        closure = [p for p in proxies(self.config, host="api.example.com") if "listen_path" not in p]
        self.assertEqual(len(closure), 1)
        self.assertEqual(plugin(self, self.config, closure[0], "request_termination")["config"]["status_code"], 404)
        self.assertNotIn("prefix-divergence", codes(self.report))


class EnvoySemanticsTest(unittest.TestCase):
    def setUp(self):
        self.base = yaml.safe_load(read_fixture("envoy", "envoy.yaml"))

    def run_doc(self, doc, **kwargs):
        return migrate("envoy", yaml.safe_dump(doc), **kwargs)

    def hcm(self, doc):
        return doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]

    def test_unknown_http_filter_refuses_every_route(self):
        doc = copy.deepcopy(self.base)
        self.hcm(doc)["http_filters"].insert(0, {
            "name": "envoy.filters.http.ext_authz",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"}})
        result, report, _ = self.run_doc(doc)
        migrated = [p for p in result.config["proxies"] if p["labels"]["ferrum-migration/status"] == "migrated"]
        self.assertEqual(migrated, [])

    def test_regex_before_overlapping_prefix_is_refused(self):
        doc = copy.deepcopy(self.base)
        routes = self.hcm(doc)["route_config"]["virtual_hosts"][0]["routes"]
        routes.insert(0, {"name": "rx", "match": {"safe_regex": {"regex": "/users/[0-9]+"}},
                          "route": {"cluster": "users_service"}})
        result, _report, _ = self.run_doc(doc)
        users = one_proxy(self, result.config, "/users", "api.example.com")
        self.assertEqual(users["labels"]["ferrum-migration/status"], "refused")

    def test_inline_key_material_never_echoed(self):
        doc = copy.deepcopy(self.base)
        chain = doc["static_resources"]["listeners"][0]["filter_chains"][0]
        chain["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                "common_tls_context": {"tls_certificates": [{
                    "certificate_chain": {"inline_string": "-----BEGIN CERTIFICATE-----\nTESTONLYCERT\n"},
                    "private_key": {"inline_string": "-----BEGIN PRIVATE KEY-----\nTESTONLYKEYMATERIAL\n"}}]}}}
        result, report, plan = self.run_doc(doc)
        self.assertIn("envoy-inline-tls", codes(report, "error"))
        everything = json.dumps(result.config) + json.dumps([c.to_dict() for c in report.caveats]) + repr(plan.settings)
        self.assertNotIn("TESTONLYKEYMATERIAL", everything)
        self.assertTrue(result.tls_only)

    def test_upstream_tls_without_validation_is_verified(self):
        doc = copy.deepcopy(self.base)
        cluster = doc["static_resources"]["clusters"][0]
        cluster["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                             "sni": "users.internal"}}
        result, report, _ = self.run_doc(doc)
        upstream = upstream_of(result.config, one_proxy(self, result.config, "/users", "api.example.com"))
        self.assertTrue(upstream["backend_tls_verify_server_cert"])
        self.assertEqual(upstream["backend_tls_sni"], "users.internal")
        self.assertIn("backend-tls-verify-enabled", codes(report, "warning"))

    def test_dynamic_resources_reported(self):
        doc = copy.deepcopy(self.base)
        doc["dynamic_resources"] = {"ads_config": {"api_type": "GRPC"}}
        _result, report, _ = self.run_doc(doc)
        self.assertIn("envoy-xds", codes(report, "error"))


def minimal_bootstrap(match):
    return {"static_resources": {
        "listeners": [{"name": "l", "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8080}},
                       "filter_chains": [{"filters": [{
                           "name": "envoy.filters.network.http_connection_manager",
                           "typed_config": {"route_config": {"virtual_hosts": [
                               {"name": "v", "domains": ["*"],
                                "routes": [{"name": "r", "match": match, "route": {"cluster": "c"}}]}]},
                               "http_filters": [{"name": "envoy.filters.http.router"}]}}]}]}],
        "clusters": [{"name": "c", "type": "STRICT_DNS", "load_assignment": {"endpoints": [{"lb_endpoints": [
            {"endpoint": {"address": {"socket_address": {"address": "c.internal", "port_value": 80}}}}]}]}}]}}


def with_client_cert_listener(doc, validation_context):
    """Make the minimal bootstrap's listener require client certificates (synthetic file paths only)."""
    chain = doc["static_resources"]["listeners"][0]["filter_chains"][0]
    chain["transport_socket"] = {"name": "envoy.transport_sockets.tls", "typed_config": {
        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
        "require_client_certificate": True,
        "common_tls_context": {
            "tls_certificates": [{"certificate_chain": {"filename": "/etc/synthetic/server.crt"},
                                  "private_key": {"filename": "/etc/synthetic/server.key"}}],
            "validation_context": validation_context}}}
    return doc


class EnvoyClientCaTest(unittest.TestCase):
    def test_file_client_ca_is_configured(self):
        doc = with_client_cert_listener(minimal_bootstrap({"path_separated_prefix": "/api"}),
                                        {"trusted_ca": {"filename": "/etc/synthetic/client-ca.pem"}})
        result, _report, plan = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plan.settings.client_ca_paths, ["/etc/synthetic/client-ca.pem"])

    def test_client_certificate_constraints_beyond_ca_refuse_listener_routes(self):
        doc = with_client_cert_listener(minimal_bootstrap({"path_separated_prefix": "/api"}), {
            "trusted_ca": {"filename": "/etc/synthetic/client-ca.pem"},
            "match_typed_subject_alt_names": [{"san_type": "DNS", "matcher": {"exact": "client.example.test"}}]})
        result, report, plan = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("envoy-client-ca", codes(report, "error"))
        self.assertEqual(plan.settings.client_ca_paths, [])


class EnvoyPrefixSemanticsTest(unittest.TestCase):
    def test_string_prefix_siblings_are_reported_not_widened(self):
        # match.prefix /api also matches /apix in Envoy; Ferrum's segment prefix does not.
        result, report, _ = migrate("envoy", yaml.safe_dump(minimal_bootstrap({"prefix": "/api"})))
        self.assertEqual([p.get("listen_path") for p in result.config["proxies"]], ["/api"])
        self.assertIn("prefix-string-siblings", codes(report, "error"))

    def test_path_separated_prefix_is_segment_based(self):
        result, report, _ = migrate("envoy", yaml.safe_dump(minimal_bootstrap({"path_separated_prefix": "/api"})))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertNotIn("prefix-string-siblings", codes(report))


if __name__ == "__main__":
    unittest.main()
