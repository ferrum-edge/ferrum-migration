import copy
import json
import unittest

import yaml

from helpers import assert_listener_contract, assert_structurally_valid, codes, live_routes, migrate, one_proxy, \
    plugin, proxies, read_fixture, upstream_of


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


def two_listener_bootstrap(plain_domains, tls_domains, client_ca=None):
    """A main plaintext listener (/plain) and a main HTTPS listener (/secure). Synthetic file paths only."""
    doc = minimal_bootstrap({"path_separated_prefix": "/plain"})
    listeners = doc["static_resources"]["listeners"]
    secure = copy.deepcopy(listeners[0])
    secure["name"] = "tls"
    secure["address"]["socket_address"]["port_value"] = 8443
    listeners.append(secure)
    for listener, domains, path in ((listeners[0], plain_domains, "/plain"), (secure, tls_domains, "/secure")):
        vhost = listener["filter_chains"][0]["filters"][0]["typed_config"]["route_config"]["virtual_hosts"][0]
        vhost["domains"] = list(domains)
        vhost["routes"][0]["match"] = {"path_separated_prefix": path}
    context = {"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
               "common_tls_context": {"tls_certificates": [
                   {"certificate_chain": {"filename": "/etc/synthetic/server.crt"},
                    "private_key": {"filename": "/etc/synthetic/server.key"}}]}}
    if client_ca:
        context["require_client_certificate"] = True
        context["common_tls_context"]["validation_context"] = {"trusted_ca": {"filename": client_ca}}
    secure["filter_chains"][0]["transport_socket"] = {"name": "envoy.transport_sockets.tls", "typed_config": context}
    return doc


class EnvoyFrontendScopeTest(unittest.TestCase):
    CA = "/etc/synthetic/client-ca.pem"
    CERT = ("/etc/synthetic/server.crt", "/etc/synthetic/server.key")

    def status(self, result, path, host):
        return one_proxy(self, result.config, path, host)["labels"]["ferrum-migration/status"]

    def check_listener_split(self, plain_domains, tls_only):
        """A plaintext listener (/plain) and an HTTPS listener with a client CA (/secure) never share a listener.

        Ferrum serves every port-agnostic route on each listener it opens, whatever the host names, so host overlap
        or disjointness proves nothing. Default: the plaintext listener's routes stay live, the HTTPS-only routes
        become placeholders, and the profile disables HTTPS explicitly (no certificate, no client CA). --tls-only: the
        HTTPS listener's routes stay live with their one client CA, the plaintext-only routes become placeholders, and
        the profile disables the plaintext listener.
        """
        doc = two_listener_bootstrap(plain_domains, ("app.example.test",), client_ca=self.CA)
        result, report, plan = migrate("envoy", yaml.safe_dump(doc), tls_only=tls_only)
        assert_structurally_valid(self, result.config)
        plain_host = None if plain_domains == ("*",) else plain_domains[0]
        self.assertNotIn("envoy-frontend-scope-conflict", codes(report))
        if tls_only:
            self.assertEqual(self.status(result, "/plain", plain_host), "refused")
            self.assertEqual(self.status(result, "/secure", "app.example.test"), "migrated")
            self.assertEqual(live_routes(result.config), [("/secure", ["app.example.test"])])
            self.assertIn("frontend-protocol-scope", codes(report, "error"))
            self.assertEqual(plan.settings.client_ca_paths, [self.CA])
            assert_listener_contract(self, plan, result, "https", http_port=0, https_port=8443,
                                     cert_pair=self.CERT, client_ca=self.CA)
        else:
            self.assertEqual(self.status(result, "/plain", plain_host), "migrated")
            self.assertEqual(self.status(result, "/secure", "app.example.test"), "refused")
            self.assertEqual(live_routes(result.config), [("/plain", [plain_host] if plain_host else [])])
            self.assertIn("frontend-https-disabled", codes(report, "error"))
            self.assertEqual(plan.settings.client_ca_paths, [])
            assert_listener_contract(self, plan, result, "http", http_port=8080, https_port=0)

    def test_plaintext_and_https_listeners_with_overlapping_hosts_never_share_a_listener(self):
        for plain_domains in (("app.example.test",), ("*",)):
            for tls_only in (False, True):
                with self.subTest(plain_domains=plain_domains, tls_only=tls_only):
                    self.check_listener_split(plain_domains, tls_only)

    def test_disjoint_hosts_on_plaintext_and_https_listeners_never_share_a_listener(self):
        # Disjoint host names do not keep Ferrum's listeners apart: the same contract as for overlapping hosts.
        for tls_only in (False, True):
            with self.subTest(tls_only=tls_only):
                self.check_listener_split(("www.example.test",), tls_only)

    def test_single_listener_plans_are_unchanged(self):
        # Overlapping virtual hosts of one listener share one frontend; the emitter's checks apply as before.
        _result, report, _plan = migrate("envoy", read_fixture("envoy", "envoy.yaml"))
        self.assertNotIn("envoy-frontend-scope-conflict", codes(report))
        doc = with_client_cert_listener(minimal_bootstrap({"path_separated_prefix": "/api"}),
                                        {"trusted_ca": {"filename": self.CA}})
        result, report, plan = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertNotIn("envoy-frontend-scope-conflict", codes(report))
        self.assertEqual(plan.settings.client_ca_paths, [self.CA])


def bootstrap_with_routes(routes, domains=("app.example.test",)):
    doc = minimal_bootstrap({"prefix": "/"})
    vhost = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
        "route_config"]["virtual_hosts"][0]
    vhost["domains"] = list(domains)
    vhost["routes"] = routes
    return doc


class EnvoyCaseSensitivityTest(unittest.TestCase):
    def routes(self, case_sensitive):
        admin_match = {"prefix": "/admin/"}
        if case_sensitive is not None:
            admin_match["case_sensitive"] = case_sensitive
        return [{"name": "admin", "match": admin_match, "route": {"cluster": "c"}},
                {"name": "status", "match": {"path": "/status"}, "route": {"cluster": "c"}},
                {"name": "rest", "match": {"prefix": "/"}, "route": {"cluster": "c"}}]

    def status(self, result, path):
        return one_proxy(self, result.config, path, "app.example.test")["labels"]["ferrum-migration/status"]

    def test_case_insensitive_prefix_refuses_routes_that_would_receive_case_variants(self):
        # Envoy sent /ADMIN/x to the admin route; Ferrum would hand it to the broader "/" route. That route is
        # refused (fail closed); admin keeps its exact-case path and the unrelated exact /status route stays.
        for domains in (("app.example.test",), ("*",)):
            with self.subTest(domains=domains):
                result, report, _ = migrate("envoy", yaml.safe_dump(bootstrap_with_routes(self.routes(False), domains)))
                assert_structurally_valid(self, result.config)
                host = None if domains == ("*",) else "app.example.test"
                by_path = {p["listen_path"]: p["labels"]["ferrum-migration/status"]
                           for p in proxies(result.config, host=host) if "listen_path" in p}
                self.assertEqual(by_path["/admin"], "migrated")
                self.assertEqual(by_path["=/status"], "migrated")
                self.assertEqual(by_path["/"], "refused")
                self.assertIn("envoy-case-insensitive", codes(report, "warning"))

    def test_case_sensitive_routes_keep_expected_behavior(self):
        for case_sensitive in (None, True):
            with self.subTest(case_sensitive=case_sensitive):
                result, report, _ = migrate("envoy", yaml.safe_dump(bootstrap_with_routes(self.routes(case_sensitive))))
                for path in ("/admin", "=/status", "/"):
                    self.assertEqual(self.status(result, path), "migrated", path)
                self.assertNotIn("envoy-case-insensitive", codes(report))
                self.assertNotIn("route-refused", codes(report))

    def test_segment_exact_disjointness_is_not_applied_across_case_semantics(self):
        # A case-insensitive path_separated_prefix /api also matched /API first in Envoy, so a later exact /API is
        # unreachable there; it must not become a live Ferrum route that receives /API.
        routes = [{"name": "api", "match": {"path_separated_prefix": "/api", "case_sensitive": False},
                   "route": {"cluster": "c"}},
                  {"name": "upper", "match": {"path": "/API"}, "route": {"cluster": "c"}}]
        result, report, _ = migrate("envoy", yaml.safe_dump(bootstrap_with_routes(routes)))
        self.assertEqual(proxies(result.config, "=/API"), [])
        self.assertIn("route-shadowed", codes(report, "warning"))
        self.assertEqual(self.status(result, "/api"), "migrated")

    def test_regex_alternation_has_no_literal_prefix_proof_for_case_variants(self):
        # The first branch's literal (/other) says nothing about the later branch, which can match case variants of
        # the case-insensitive /admin/ route. A regex without top-level alternation keeps its literal-prefix proof.
        routes = [{"name": "admin", "match": {"prefix": "/admin/", "case_sensitive": False}, "route": {"cluster": "c"}},
                  {"name": "alt", "match": {"safe_regex": {"regex": "/other|/ADMIN/.*"}}, "route": {"cluster": "c"}},
                  {"name": "other", "match": {"safe_regex": {"regex": "/other/[0-9]+"}}, "route": {"cluster": "c"}}]
        result, _report, _ = migrate("envoy", yaml.safe_dump(bootstrap_with_routes(routes)))
        assert_structurally_valid(self, result.config)
        self.assertEqual(self.status(result, "~/other|/ADMIN/.*"), "refused")
        self.assertEqual(self.status(result, "~/other/[0-9]+"), "migrated")
        self.assertEqual(self.status(result, "/admin"), "migrated")


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

    def test_disjoint_segment_prefix_and_exact_path_both_migrate(self):
        # path_separated_prefix /api never matches /apix in Envoy or in Ferrum, so first-match order is irrelevant.
        doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        routes = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]["routes"]
        routes.append({"name": "apix", "match": {"path": "/apix"}, "route": {"cluster": "c"}})
        routes.append({"name": "api-child", "match": {"path": "/api/v1"}, "route": {"cluster": "c"}})
        result, report, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(one_proxy(self, result.config, "=/apix")["labels"]["ferrum-migration/status"], "migrated")
        # An exact path under the segment prefix is still covered by it (unreachable in Envoy): not emitted.
        self.assertEqual(proxies(result.config, "=/api/v1"), [])
        self.assertNotIn("route-refused", codes(report))


if __name__ == "__main__":
    unittest.main()
