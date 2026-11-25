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


class EnvoyHardeningTest(unittest.TestCase):
    def test_optional_downstream_validation_context_is_not_dropped(self):
        doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc["static_resources"]["listeners"][0]["filter_chains"][0]["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                "common_tls_context": {
                    "tls_certificates": [{"certificate_chain": {"filename": "/etc/s.crt"},
                                          "private_key": {"filename": "/etc/s.key"}}],
                    "validation_context": {"trusted_ca": {"filename": "/etc/ca.pem"}},
                },
            },
        }
        result, report, plan = migrate("envoy", yaml.safe_dump(doc))
        assert_structurally_valid(self, result.config)
        self.assertEqual(plan.settings.client_ca_paths, ["/etc/ca.pem"])
        self.assertIn("envoy-mtls-optional", codes(report, "warning"))
        # Optional validation with extra CRL constraint must refuse rather than silently drop.
        doc["static_resources"]["listeners"][0]["filter_chains"][0]["transport_socket"]["typed_config"][
            "common_tls_context"]["validation_context"]["crl"] = {"filename": "/etc/crl.pem"}
        result2, report2, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, result2.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("envoy-client-ca", codes(report2, "error"))

    def test_upstream_tls_constraints_and_non_tls_transport_socket_refused(self):
        for label, patch in (
            ("crl", {"transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "common_tls_context": {"validation_context": {
                    "trusted_ca": {"filename": "/etc/ca.pem"}, "crl": {"filename": "/etc/crl.pem"}}}}}}),
            ("email-san", {"transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "common_tls_context": {"validation_context": {
                    "trusted_ca": {"filename": "/etc/ca.pem"},
                    "match_typed_subject_alt_names": [{"san_type": "EMAIL", "matcher": {"exact": "a@b.test"}}]}}}}}),
            ("alts", {"transport_socket": {"name": "envoy.transport_sockets.alts", "typed_config": {}}}),
            ("matches", {"transport_socket_matches": [{"name": "m"}]}),
        ):
            with self.subTest(case=label):
                doc = minimal_bootstrap({"path_separated_prefix": "/api"})
                doc["static_resources"]["clusters"][0].update(patch)
                result, report, _ = migrate("envoy", yaml.safe_dump(doc))
                assert_structurally_valid(self, result.config)
                self.assertEqual(one_proxy(self, result.config, "/api")["labels"]["ferrum-migration/status"], "refused")
                self.assertIn("route-refused", codes(report, "error"))

    def test_empty_vhost_domains_refused_not_catch_all(self):
        doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]["domains"] = []
        result, report, _ = migrate("envoy", yaml.safe_dump(doc))
        assert_structurally_valid(self, result.config)
        self.assertEqual(live_routes(result.config), [])
        self.assertIn("envoy-domains", codes(report, "error"))

    def test_weighted_cluster_overrides_and_connect_timeout_independently(self):
        # Positive control: two weighted clusters with matching connect_timeout and no overrides migrate cleanly.
        doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc["static_resources"]["clusters"][0]["connect_timeout"] = "2s"
        doc["static_resources"]["clusters"].append({
            "name": "c2", "type": "STATIC", "connect_timeout": "2s",
            "load_assignment": {"endpoints": [{"lb_endpoints": [{"endpoint": {"address": {"socket_address": {
                "address": "10.0.0.2", "port_value": 8080}}}}]}]},
        })
        route = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]["routes"][0]
        route["route"] = {"weighted_clusters": {"clusters": [
            {"name": "c", "weight": 50},
            {"name": "c2", "weight": 50},
        ]}}
        ok_res, _ok_rep, _ = migrate("envoy", yaml.safe_dump(doc))
        assert_structurally_valid(self, ok_res.config)
        self.assertEqual(one_proxy(self, ok_res.config, "/api")["labels"]["ferrum-migration/status"], "migrated")

        # Per-cluster request_headers_to_remove refuses even when connect_timeout matches.
        route["route"]["weighted_clusters"]["clusters"][0]["request_headers_to_remove"] = ["x-auth"]
        hdr_res, _hdr_rep, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, hdr_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")

        # Removing the header override but making connect_timeout differ refuses independently.
        del route["route"]["weighted_clusters"]["clusters"][0]["request_headers_to_remove"]
        doc["static_resources"]["clusters"][0]["connect_timeout"] = "5s"
        to_res, _to_rep, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(one_proxy(self, to_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")

    def test_identical_mixed_domains_remain_migrated(self):
        doc = minimal_bootstrap({"path": "/api"})
        vhost = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]
        vhost["domains"] = ["api.example.com", "*.example.com"]
        vhost["routes"].append({"match": {"prefix": "/"}, "route": {"cluster": "c"}})
        result, _report, _ = migrate("envoy", yaml.safe_dump(doc))
        assert_structurally_valid(self, result.config)
        self.assertEqual(one_proxy(self, result.config, "=/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(one_proxy(self, result.config, "/")["labels"]["ferrum-migration/status"], "migrated")

    def test_envoy_san_precedence_type_match_malformed_bools_and_raw_buffer_type(self):
        # Typed SANs override deprecated match_subject_alt_names (retired SAN must NOT be emitted).
        doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc["static_resources"]["clusters"][0]["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {"@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                             "common_tls_context": {"validation_context": {
                                 "trusted_ca": {"filename": "/etc/ca.pem"},
                                 "match_subject_alt_names": [{"exact": "retired.example.test"}],
                                 "match_typed_subject_alt_names": [
                                     {"san_type": "DNS", "matcher": {"exact": "active.example.test"}}
                                 ]}}}}
        res, _rep, _ = migrate("envoy", yaml.safe_dump(doc))
        self.assertEqual(res.config["upstreams"][0]["backend_tls_san_allow_list"], ["active.example.test"])

        # SAN type mismatch (DNS declared with IP literal) or ignore_case: true refused.
        for bad_typed in (
            [{"san_type": "DNS", "matcher": {"exact": "10.0.0.1"}}],
            [{"san_type": "DNS", "matcher": {"exact": "active.example.test", "ignore_case": True}}],
        ):
            doc2 = minimal_bootstrap({"path_separated_prefix": "/api"})
            doc2["static_resources"]["clusters"][0]["transport_socket"] = {
                "name": "envoy.transport_sockets.tls",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                    "common_tls_context": {"validation_context": {
                        "trusted_ca": {"filename": "/etc/ca.pem"},
                        "match_typed_subject_alt_names": bad_typed}}}}
            r2, _rep2, _ = migrate("envoy", yaml.safe_dump(doc2))
            self.assertEqual(one_proxy(self, r2.config, "/api")["labels"]["ferrum-migration/status"], "refused")

        # Transport socket named raw_buffer or with /raw_buffer/ URL prefix wrapping another message type is refused.
        for sock in (
            {"name": "envoy.transport_sockets.raw_buffer",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.transport_sockets.alts.v3.Alts"}},
            {"name": "envoy.transport_sockets.http_11_proxy",
             "typed_config": {"@type": "example.invalid/raw_buffer/envoy.extensions.transport_sockets.http_11_proxy.v3.Http11ProxyUpstreamTransport"}},
        ):
            doc3 = minimal_bootstrap({"path_separated_prefix": "/api"})
            doc3["static_resources"]["clusters"][0]["transport_socket"] = sock
            r3, _rep3, _ = migrate("envoy", yaml.safe_dump(doc3))
            self.assertEqual(one_proxy(self, r3.config, "/api")["labels"]["ferrum-migration/status"], "refused")

        # Exact URI SAN matcher refused (case-sensitive in Envoy vs case-insensitive SPIFFE trust domain in Ferrum).
        doc_uri = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc_uri["static_resources"]["clusters"][0]["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                "common_tls_context": {"validation_context": {
                    "trusted_ca": {"filename": "/etc/ca.pem"},
                    "match_typed_subject_alt_names": [
                        {"san_type": "URI", "matcher": {"exact": "spiffe://trust.example/workload"}}
                    ]}}}}
        r_uri, _rep_uri, _ = migrate("envoy", yaml.safe_dump(doc_uri))
        self.assertEqual(one_proxy(self, r_uri.config, "/api")["labels"]["ferrum-migration/status"], "refused")

        # Protobuf final message type RawBuffer is classified as plaintext even if the URL prefix contains
        # 'transport_sockets.tls'; active health thresholds up to 10_000 are preserved.
        doc_rb = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc_rb["static_resources"]["clusters"][0]["transport_socket"] = {
            "name": "custom",
            "typed_config": {
                "@type": "example.invalid/transport_sockets.tls/envoy.extensions.transport_sockets.raw_buffer.v3.RawBuffer"
            },
        }
        doc_rb["static_resources"]["clusters"][0]["health_checks"] = [
            {"interval": "10s", "timeout": "2s", "healthy_threshold": 2000, "unhealthy_threshold": 3000,
             "http_health_check": {"path": "/healthz"}}
        ]
        r_rb, _rep_rb, _ = migrate("envoy", yaml.safe_dump(doc_rb))
        self.assertEqual(one_proxy(self, r_rb.config, "/api")["backend_scheme"], "http")
        hc = r_rb.config["upstreams"][0]["health_checks"]["active"]
        self.assertEqual(hc["healthy_threshold"], 2000)
        self.assertEqual(hc["unhealthy_threshold"], 3000)

        # Malformed require_client_certificate: "true" refuses TLS routes (never treated as absent).
        doc4 = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc4["static_resources"]["listeners"][0]["filter_chains"][0]["transport_socket"] = {
            "name": "envoy.transport_sockets.tls",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                "require_client_certificate": "true",
                "common_tls_context": {"tls_certificates": [
                    {"certificate_chain": {"filename": "/etc/s.crt"}, "private_key": {"filename": "/etc/s.key"}}
                ]}}}
        r4, rep4, _ = migrate("envoy", yaml.safe_dump(doc4))
        self.assertEqual(one_proxy(self, r4.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("envoy-client-ca", codes(rep4, "error"))

        # CORS allow_credentials: {value: false} decodes to False (not truthy dict).
        doc5 = minimal_bootstrap({"path_separated_prefix": "/api"})
        hcm = doc5["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        hcm["http_filters"].insert(0, {"name": "envoy.filters.http.cors"})
        hcm["route_config"]["virtual_hosts"][0]["cors"] = {
            "allow_origin_string_match": [{"exact": "https://app.example.test"}],
            "allow_credentials": {"value": False},
        }
        r5, _rep5, _ = migrate("envoy", yaml.safe_dump(doc5))
        cors_plugins = [p for p in r5.config["plugin_configs"] if p["plugin_name"] == "cors"]
        self.assertEqual(len(cors_plugins), 1)
        self.assertFalse(cors_plugins[0]["config"].get("allow_credentials", False))

    def test_grpc_web_compressor_fault_jwt_authn_and_request_mirror_policies(self):
        doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        doc["static_resources"]["clusters"].extend([
            {
                "name": "shadow", "type": "STRICT_DNS",
                "load_assignment": {"endpoints": [{"lb_endpoints": [
                    {"endpoint": {"address": {"socket_address": {"address": "shadow.internal", "port_value": 9000}}}}
                ]}]},
            },
            {
                "name": "jwks", "type": "STRICT_DNS",
                "load_assignment": {"endpoints": [{"lb_endpoints": [
                    {"endpoint": {"address": {"socket_address": {"address": "idp.example.test", "port_value": 443}}}}
                ]}]},
                "transport_socket": {
                    "name": "envoy.transport_sockets.tls",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                        "sni": "idp.example.test",
                    },
                },
            },
        ])
        hcm = doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        hcm["http_filters"] = [
            {"name": "envoy.filters.http.grpc_web",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.grpc_web.v3.GrpcWeb"}},
            {"name": "envoy.filters.http.compressor",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor",
                 "compressor_library": {"name": "text_optimized", "typed_config": {
                     "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"
                 }},
                 "response_direction_config": {
                     "common_config": {"min_content_length": 512, "content_type": ["application/json", "text/plain"]},
                     "remove_accept_encoding_header": True,
                 },
             }},
            {"name": "envoy.filters.http.fault",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                 "delay": {"fixed_delay": "0.5s", "percentage": {"numerator": 10, "denominator": "HUNDRED"}},
                 "abort": {"http_status": 503, "percentage": {"numerator": 5, "denominator": "HUNDRED"}},
             }},
            {"name": "envoy.filters.http.jwt_authn",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
                 "providers": {
                     "idp": {
                         "issuer": "https://idp.example.test",
                         "audiences": ["api"],
                         "remote_jwks": {"http_uri": {"uri": "https://idp.example.test/.well-known/jwks.json",
                                                      "cluster": "jwks", "timeout": "5s"}},
                         "from_headers": [{"name": "Authorization", "value_prefix": "Bearer "}],
                         "claim_to_headers": [{"header_name": "x-jwt-sub", "claim_name": "sub"}],
                     }
                 },
                 "rules": [{"match": {"prefix": "/"}, "requires": {"provider_name": "idp"}}],
             }},
            {"name": "envoy.filters.http.router"},
        ]
        route = hcm["route_config"]["virtual_hosts"][0]["routes"][0]
        route["route"]["request_mirror_policies"] = [{
            "cluster": "shadow",
            "runtime_fraction": {"default_value": {"numerator": 2500, "denominator": "TEN_THOUSAND"}},
        }]
        # Also add a direct_response route to verify fail-closed refusal when jwt_authn is active.
        hcm["route_config"]["virtual_hosts"][0]["routes"].append({
            "name": "health", "match": {"path": "/healthz"},
            "direct_response": {"status": 200, "body": {"inline_string": "ok"}},
        })
        result, report, _ = migrate("envoy", yaml.safe_dump(doc))
        assert_structurally_valid(self, result.config)
        api = one_proxy(self, result.config, "/api")
        self.assertEqual(api["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(plugin(self, result.config, api, "grpc_web")["config"], {})
        self.assertEqual(plugin(self, result.config, api, "compression")["config"], {
            "algorithms": ["gzip"], "min_content_length": 512,
            "content_types": ["application/json", "text/plain"], "remove_accept_encoding": True,
        })
        self.assertEqual(plugin(self, result.config, api, "fault_injection")["config"], {
            "delay": {"duration_ms": 500, "percentage": 10.0},
            "abort": {"status_code": 503, "percentage": 5.0},
        })
        # Omitted `forward` -> False, omitted `require_expiration` -> False, omitted `clock_skew_seconds` -> 60,
        # and omitted remote_jwks.cache_duration -> 600s staleness/refresh.
        self.assertEqual(plugin(self, result.config, api, "jwks_auth")["config"], {
            "providers": [{
                "jwks_uri": "https://idp.example.test/.well-known/jwks.json",
                "issuer": "https://idp.example.test",
                "audiences": ["api"],
                "from_headers": [{"name": "authorization", "prefix": "Bearer "}],
                "forward_original_token": False,
                "output_claim_headers": [{"claim": "sub", "header": "x-jwt-sub"}],
                "jwks_max_stale_seconds": 600,
                "require_exp": False,
                "clock_skew_seconds": 60,
            }],
            "jwks_refresh_interval_secs": 600,
        })
        # Explicit clock_skew_seconds: 0 (proto3 default) also maps to Envoy's 60s default, and require_expiration:
        # true emits require_exp: True.
        jwt_opts = copy.deepcopy(doc)
        jwt_opts["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"][3]["typed_config"]["providers"]["idp"].update(
                {"clock_skew_seconds": 0, "require_expiration": True})
        jo_res, _jo_rep, _ = migrate("envoy", yaml.safe_dump(jwt_opts))
        jo_prov = plugin(self, jo_res.config, one_proxy(self, jo_res.config, "/api"), "jwks_auth")["config"][
            "providers"][0]
        self.assertEqual(jo_prov["clock_skew_seconds"], 60)
        self.assertTrue(jo_prov["require_exp"])
        # Active Envoy mirrors are dropped with warning (Envoy -shadow authority vs Ferrum file-mode Host strip).
        self.assertNotIn("request_mirror", [p["plugin_name"] for p in result.config["plugin_configs"]])
        self.assertIn("envoy-mirror", codes(report, "warning"))
        # Empty runtime_fraction: {} is 0% (inert) and produces no mirror warning.
        inert_mirror = minimal_bootstrap({"path_separated_prefix": "/api"})
        inert_mirror["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]["routes"][0]["route"]["request_mirror_policies"] = [
            {"cluster": "c", "runtime_fraction": {}}
        ]
        _im_res, im_rep, _ = migrate("envoy", yaml.safe_dump(inert_mirror))
        self.assertNotIn("envoy-mirror", codes(im_rep))
        # Terminated route under jwt_authn refuses (Ferrum request_termination runs before jwks_auth).
        self.assertEqual(one_proxy(self, result.config, "=/healthz")["labels"]["ferrum-migration/status"], "refused")

        # Fail-closed regressions:
        # 1) Misnamed ext_authz masquerading as grpc_web name, or dynamic config_discovery, must refuse.
        for bad_filter in (
            {"name": "envoy.filters.http.grpc_web",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"}},
            {"name": "envoy.filters.http.grpc_web",
             "config_discovery": {"config_source": {"ads": {}}}},
        ):
            misnamed = minimal_bootstrap({"path_separated_prefix": "/api"})
            misnamed["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"] = [bad_filter, {"name": "envoy.filters.http.router"}]
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(misnamed))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused")
        # 2) Disabled jwt_authn named with "cors" enabled via typed_per_filter_config must refuse.
        cors_jwt = minimal_bootstrap({"path_separated_prefix": "/api"})
        chcm = cors_jwt["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        chcm["http_filters"] = [
            {"name": "custom_cors_jwt", "disabled": True,
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication"}},
            {"name": "envoy.filters.http.router"},
        ]
        chcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] = {
            "custom_cors_jwt": {"@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.PerRouteConfig"}
        }
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(cors_jwt))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        # 3) Reserved claim destination, implicit locations, from_params, query in jwks_uri, whitespace issuer/aud,
        #    and custom DNS resolvers refuse.
        for mutate in (
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"]["claim_to_headers"].append(
                    {"header_name": "x-forwarded-user", "claim_name": "sub"}),
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"].pop("from_headers"),
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"].update(
                    {"from_headers": [], "from_params": ["access_token"]}),
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"]["remote_jwks"]["http_uri"].update(
                    {"uri": "https://idp.example.test/.well-known/jwks.json?api_key=secret"}),
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"].update(
                    {"issuer": "https://idp.example.test "}),
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"].update(
                    {"audiences": [" api"]}),
            lambda d: d["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][3]["typed_config"]["providers"]["idp"].pop("audiences"),
            lambda d: d["static_resources"]["clusters"][2].update(
                {"dns_resolvers": [{"socket_address": {"address": "10.0.0.53", "port_value": 53}}]}),
        ):
            bad_jwt = copy.deepcopy(doc)
            mutate(bad_jwt)
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(bad_jwt))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused")
        # 4) Inline JWKS: rebuilds public fields only (strips x5u), rejects noncanonical base64url & non-sig key_ops.
        valid_ed_x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        noncanon_ed_x = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURp"
        inline_doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        inline_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"] = [
            {"name": "envoy.filters.http.jwt_authn", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
                "providers": {"idp": {
                    "issuer": "https://idp.example.test",
                    "audiences": ["api"],
                    "local_jwks": {"inline_string": json.dumps({"keys": [{
                        "kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": valid_ed_x,
                        "key_ops": ["verify"],
                        "x5u": "https://secret.example.test/cert?token=leak",
                    }]})},
                    "from_headers": [{"name": "Authorization", "value_prefix": "Bearer "}],
                }},
                "rules": [{"match": {"prefix": "/"}, "requires": {"provider_name": "idp"}}],
            }},
            {"name": "envoy.filters.http.router"},
        ]
        in_res, _in_rep, _ = migrate("envoy", yaml.safe_dump(inline_doc))
        self.assertEqual(one_proxy(self, in_res.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertNotIn("token=leak", json.dumps(in_res.config))
        self.assertNotIn("x5u", json.dumps(in_res.config))
        for bad_jwk in (
            {"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": noncanon_ed_x},
            {"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": valid_ed_x, "key_ops": ["verify", "leak=secret"]},
        ):
            bad_in = copy.deepcopy(inline_doc)
            bad_in["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][0]["typed_config"]["providers"]["idp"]["local_jwks"]["inline_string"] = json.dumps(
                    {"keys": [bad_jwk]})
            bad_in_res = migrate("envoy", yaml.safe_dump(bad_in))[0]
            self.assertEqual(one_proxy(self, bad_in_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
            self.assertNotIn("leak=secret", json.dumps(bad_in_res.config))
        # 5) Fault filter regressions: max_active_faults: 0 and header matchers refuse; 0% fault omits only without
        #    runtime layers, and ANY fault filter (including positive delay + 0% abort) refuses under layered_runtime.
        for bad_fault in (
            {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
             "abort": {"http_status": 503, "percentage": {"numerator": 5, "denominator": "HUNDRED"}},
             "max_active_faults": 0},
            {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
             "abort": {"http_status": 503, "percentage": {"numerator": 5, "denominator": "HUNDRED"}},
             "headers": [{"name": "x-chaos", "exact_match": "1"}]},
        ):
            bf = minimal_bootstrap({"path_separated_prefix": "/api"})
            bf["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"] = [
                {"name": "envoy.filters.http.fault", "typed_config": bad_fault},
                {"name": "envoy.filters.http.router"},
            ]
            bf_res = migrate("envoy", yaml.safe_dump(bf))[0]
            self.assertEqual(one_proxy(self, bf_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        zero_fault = minimal_bootstrap({"path_separated_prefix": "/api"})
        zero_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"] = [
            {"name": "envoy.filters.http.fault",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                 "abort": {"http_status": 503, "percentage": {"numerator": 0, "denominator": "HUNDRED"}},
             }},
            {"name": "envoy.filters.http.router"},
        ]
        zf_res, zf_rep, _ = migrate("envoy", yaml.safe_dump(zero_fault))
        self.assertEqual(one_proxy(self, zf_res.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
        self.assertEqual(zf_res.config["plugin_configs"], [])
        self.assertIn("envoy-fault-noop", codes(zf_rep, "info"))
        for rt_fault in (
            {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
             "abort": {"http_status": 503, "percentage": {"numerator": 0, "denominator": "HUNDRED"}}},
            {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
             "delay": {"fixed_delay": "0.1s", "percentage": {"numerator": 10, "denominator": "HUNDRED"}},
             "abort": {"http_status": 503, "percentage": {"numerator": 0, "denominator": "HUNDRED"}}},
        ):
            rt_doc = minimal_bootstrap({"path_separated_prefix": "/api"})
            rt_doc["layered_runtime"] = {"layers": [{"name": "static", "static_layer": {}}]}
            rt_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"] = [
                {"name": "envoy.filters.http.fault", "typed_config": rt_fault},
                {"name": "envoy.filters.http.router"},
            ]
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(rt_doc))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused")
        # 6) Shadow-only CORS, route.cors override disabling credentialed vhost CORS, and wildcard-only compressor.
        shadow_cors = minimal_bootstrap({"path_separated_prefix": "/api"})
        shcm = shadow_cors["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        shcm["http_filters"].insert(0, {"name": "envoy.filters.http.cors"})
        shcm["http_filters"].insert(0, {
            "name": "envoy.filters.http.compressor",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor",
                "compressor_library": {"name": "gzip", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"}},
                "response_direction_config": {"common_config": {"content_type": ["text/*"]}},
            },
        })
        shcm["route_config"]["virtual_hosts"][0]["cors"] = {
            "allow_origin_string_match": [{"exact": "https://app.example.test"}],
            "allow_credentials": {"value": True},
        }
        # RouteAction route.cors with filter_enabled: 0% must override the credentialed vhost CORS.
        shcm["route_config"]["virtual_hosts"][0]["routes"][0]["route"]["cors"] = {
            "allow_origin_string_match": [{"exact": "https://app.example.test"}],
            "filter_enabled": {"default_value": {"numerator": 0, "denominator": "HUNDRED"}},
            "shadow_enabled": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}},
        }
        sc_res, sc_rep, _ = migrate("envoy", yaml.safe_dump(shadow_cors))
        self.assertEqual(sc_res.config["plugin_configs"], [])
        self.assertIn("envoy-cors-inactive", codes(sc_rep, "info"))
        self.assertIn("envoy-compressor", codes(sc_rep, "warning"))
        # 7) Envoy cors_filter.cc precedence regressions:
        #    (A) vhost FilterConfig{disabled: true} disables CORS even when a stale legacy route.cors exists.
        #    (B) route_config typed CorsPolicy overrides stale legacy route.cors.
        #    (C) route typed CorsPolicy inherits narrower allow_methods from vhost typed CorsPolicy.
        dis_cors = minimal_bootstrap({"path_separated_prefix": "/api"})
        dhcm = dis_cors["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        dhcm["http_filters"].insert(0, {"name": "envoy.filters.http.cors"})
        dhcm["route_config"]["virtual_hosts"][0]["typed_per_filter_config"] = {
            "envoy.filters.http.cors": {
                "@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig",
                "disabled": True,
            }
        }
        dhcm["route_config"]["virtual_hosts"][0]["routes"][0]["route"]["cors"] = {
            "allow_origin_string_match": [{"exact": "https://partner.example.net"}],
            "allow_credentials": {"value": True},
        }
        dis_res, dis_rep, _ = migrate("envoy", yaml.safe_dump(dis_cors))
        self.assertEqual(dis_res.config["plugin_configs"], [])
        self.assertIn("envoy-cors-inactive", codes(dis_rep, "info"))

        typed_over_legacy = minimal_bootstrap({"path_separated_prefix": "/api"})
        thcm = typed_over_legacy["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        thcm["http_filters"].insert(0, {"name": "envoy.filters.http.cors"})
        thcm["route_config"]["typed_per_filter_config"] = {
            "envoy.filters.http.cors": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                "allow_origin_string_match": [{"exact": "https://app.example.com"}],
                "allow_methods": "GET",
            }
        }
        thcm["route_config"]["virtual_hosts"][0]["routes"][0]["route"]["cors"] = {
            "allow_origin_string_match": [{"exact": "https://partner.example.net"}],
            "allow_credentials": {"value": True},
        }
        tol_res, _tol_rep, _ = migrate("envoy", yaml.safe_dump(typed_over_legacy))
        tol_cors = plugin(self, tol_res.config, one_proxy(self, tol_res.config, "/api"), "cors")["config"]
        self.assertEqual(tol_cors["allowed_origins"], [{"exact": "https://app.example.com"}])
        self.assertEqual(tol_cors["allowed_methods"], ["GET"])
        self.assertEqual(tol_cors["unmatched_preflights"], "forward")
        self.assertNotIn("allowed_headers", tol_cors)
        self.assertNotIn("max_age", tol_cors)
        self.assertFalse(tol_cors.get("allow_credentials", False))

        typed_inherit = copy.deepcopy(typed_over_legacy)
        ihcm = typed_inherit["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ihcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] = {
            "envoy.filters.http.cors": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                "allow_origin_string_match": [{"exact": "https://route.example.com"}],
            }
        }
        ti_res, _ti_rep, _ = migrate("envoy", yaml.safe_dump(typed_inherit))
        ti_cors = plugin(self, ti_res.config, one_proxy(self, ti_res.config, "/api"), "cors")["config"]
        self.assertEqual(ti_cors["allowed_origins"], [{"exact": "https://route.example.com"}])
        self.assertEqual(ti_cors["allowed_methods"], ["GET"])
        self.assertEqual(ti_cors["unmatched_preflights"], "forward")

        # (D) Inherited allow_credentials: true combined with a route prefix origin lacking a scheme://host: boundary
        #     refuses the route before emitting an un-admissible CORS plugin.
        cred_prefix = copy.deepcopy(typed_inherit)
        ch = cred_prefix["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        ch["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]["allow_credentials"] = {"value": True}
        ch["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"]["envoy.filters.http.cors"][
            "allow_origin_string_match"] = [{"prefix": "https://preview.example.test"}]
        cp_res, _cp_rep, _ = migrate("envoy", yaml.safe_dump(cred_prefix))
        self.assertEqual(one_proxy(self, cp_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")

        # (E) Active HCM fault filter on direct_response or HTTP-to-HTTPS redirect refuses (never folded away).
        fault_term = minimal_bootstrap({"path": "/healthz"})
        fhcm = fault_term["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        fhcm["http_filters"] = [
            {"name": "envoy.filters.http.fault",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                 "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
             }},
            {"name": "envoy.filters.http.router"},
        ]
        fhcm["route_config"]["virtual_hosts"][0]["routes"] = [
            {"name": "dr", "match": {"path": "/healthz"}, "direct_response": {"status": 200}},
            {"name": "redir", "match": {"prefix": "/"}, "redirect": {"https_redirect": True}},
        ]
        ft_res, _ft_rep, _ = migrate("envoy", yaml.safe_dump(fault_term))
        self.assertEqual(one_proxy(self, ft_res.config, "=/healthz")["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(one_proxy(self, ft_res.config, "/")["labels"]["ferrum-migration/status"], "refused")
        # Pure HTTP-to-HTTPS redirect vhost under an active fault is refused rather than silently folded away.
        fhcm["route_config"]["virtual_hosts"][0]["routes"] = [
            {"name": "redir", "match": {"prefix": "/"}, "redirect": {"https_redirect": True}},
        ]
        fr_res, _fr_rep, _ = migrate("envoy", yaml.safe_dump(fault_term))
        self.assertEqual(one_proxy(self, fr_res.config, "/")["labels"]["ferrum-migration/status"], "refused")


if __name__ == "__main__":
    unittest.main()
