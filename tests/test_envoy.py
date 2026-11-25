import copy
import json
import unittest

import yaml

from helpers import assert_listener_contract, assert_structurally_valid, codes, live_routes, migrate, one_proxy, \
    plugin, proxies, read_fixture, upstream_of

from ferrum_migration.errors import InputError


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
        doc["static_resources"]["clusters"].append({
            "name": "shadow", "type": "STRICT_DNS",
            "load_assignment": {"endpoints": [{"lb_endpoints": [
                {"endpoint": {"address": {"socket_address": {"address": "shadow.internal", "port_value": 9000}}}}
            ]}]},
        })
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
            {"name": "envoy.filters.http.router"},
        ]
        route = hcm["route_config"]["virtual_hosts"][0]["routes"][0]
        route["route"]["request_mirror_policies"] = [{
            "cluster": "shadow",
            "runtime_fraction": {"default_value": {"numerator": 2500, "denominator": "TEN_THOUSAND"}},
        }]
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
            "abort": {"status_code": 503, "percentage": 5.0, "body": "fault filter abort"},
        })
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

        # Omitted Envoy compressor remove_accept_encoding_header and min_content_length emit Envoy defaults
        # (false and 30 bytes) rather than inheriting Ferrum's defaults (true and 256 bytes); malformed UInt32Value
        # like "--1" refuses cleanly rather than crashing.
        comp_def = minimal_bootstrap({"path_separated_prefix": "/api"})
        comp_def["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"] = [
            {"name": "envoy.filters.http.compressor",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor",
                 "compressor_library": {"name": "gzip", "typed_config": {
                     "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"}},
             }},
            {"name": "envoy.filters.http.router"},
        ]
        cd_res, cd_rep, _ = migrate("envoy", yaml.safe_dump(comp_def))
        cd_cfg = plugin(self, cd_res.config, one_proxy(self, cd_res.config, "/api"), "compression")["config"]
        self.assertEqual(cd_cfg["algorithms"], ["gzip"])
        self.assertEqual(cd_cfg["min_content_length"], 30)
        self.assertIs(cd_cfg["remove_accept_encoding"], False)
        self.assertIn("application/xml", cd_cfg["content_types"])
        self.assertIn("application/grpc-web+proto", cd_cfg["content_types"])
        self.assertEqual(len(cd_cfg["content_types"]), 20)
        self.assertIn("envoy-compressor", codes(cd_rep, "warning"))
        # Explicit min_content_length: 0 also normalizes to Envoy's 30-byte default.
        comp_zero = copy.deepcopy(comp_def)
        comp_zero["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"][0]["typed_config"]["response_direction_config"] = {
            "common_config": {"min_content_length": 0},
        }
        cz_res = migrate("envoy", yaml.safe_dump(comp_zero))[0]
        self.assertEqual(plugin(self, cz_res.config, one_proxy(self, cz_res.config, "/api"), "compression")[
            "config"]["min_content_length"], 30)
        # Inherited vhost / route_config request_mirror_policies emit envoy-mirror warnings.
        inh_mirror = minimal_bootstrap({"path_separated_prefix": "/api"})
        inh_mirror["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]["request_mirror_policies"] = [{"cluster": "shadow"}]
        _ihm_res, ihm_rep, _ = migrate("envoy", yaml.safe_dump(inh_mirror))
        self.assertIn("envoy-mirror", codes(ihm_rep, "warning"))
        # Multiple compressor HTTP filters in one HCM (whether both active or one active + one disabled via
        # common_config.enabled.default_value: false) refuse fail-closed because Envoy's client-order
        # Accept-Encoding tie-breaking, inter-filter header removal, and disabled-compressor registry
        # participation cannot be proven equivalent to one Ferrum compression plugin.
        multi_comp = minimal_bootstrap({"path_separated_prefix": "/api"})
        mchcm = multi_comp["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        mchcm["http_filters"] = [
            {"name": "comp-gzip", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor",
                "compressor_library": {"name": "gzip", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"}},
                "response_direction_config": {"common_config": {"min_content_length": 128, "content_type": ["text/plain"]}},
            }},
            {"name": "comp-br", "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor",
                "compressor_library": {"name": "brotli", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.compression.brotli.compressor.v3.Brotli"}},
                "response_direction_config": {"common_config": {"min_content_length": 128, "content_type": ["text/plain"]}},
            }},
            {"name": "envoy.filters.http.router"},
        ]
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(multi_comp))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        disabled_sibling = copy.deepcopy(multi_comp)
        disabled_sibling["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"][1]["typed_config"]["response_direction_config"]["common_config"]["enabled"] = {
            "default_value": False
        }
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(disabled_sibling))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        # Even when the active compressor has a wildcard-only content_type (omitted if alone), pairing it with
        # a disabled sibling still refuses because Envoy still registers and invokes the active filter.
        wild_plus_disabled = copy.deepcopy(disabled_sibling)
        wild_plus_disabled["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"][0]["typed_config"]["response_direction_config"]["common_config"]["content_type"] = [
            "text/*"
        ]
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(wild_plus_disabled))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")

        for bad_min_val in ("--1", "9" * 4301):
            comp_bad_min = copy.deepcopy(comp_def)
            comp_bad_min["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"][0]["typed_config"]["response_direction_config"] = {
                "common_config": {"min_content_length": {"value": bad_min_val}},
            }
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(comp_bad_min))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused", len(bad_min_val))

        # Opaque protobuf Structs (metadata.filterMetadata, typedFilterMetadata Struct Any, and node.metadata)
        # keep arbitrary keys untouched without duplicate-spelling collisions.
        opaque_meta = minimal_bootstrap({"path_separated_prefix": "/api"})
        opaque_meta["node"] = {"id": "edge-1", "metadata": {"tenantId": "a", "tenant_id": "b"}}
        opaque_meta["static_resources"]["clusters"][0]["metadata"] = {
            "filterMetadata": {"envoy.lb": {"tenantId": "a", "tenant_id": "b"}},
            "typedFilterMetadata": {
                "envoy.lb": {
                    "@type": "type.googleapis.com/google.protobuf.Struct",
                    "value": {"tenantId": "a", "tenant_id": "b"},
                }
            },
        }
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(opaque_meta))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "migrated")

        # Fail-closed regressions:
        # 1) Misnamed ext_authz, dynamic config_discovery, and jwt_authn (including camelCase protobuf JSON
        #    aliases httpFilters / typedPerFilterConfig) all refuse fail-closed; duplicate aliases raise InputError.
        for bad_filter in (
            {"name": "envoy.filters.http.grpc_web",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz"}},
            {"name": "envoy.filters.http.grpc_web",
             "config_discovery": {"config_source": {"ads": {}}}},
            {"name": "envoy.filters.http.jwt_authn",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
                 "providers": {"idp": {"issuer": "https://idp.example.test", "audiences": ["api"]}},
                 "rules": [{"match": {"prefix": "/"}, "requires": {"provider_name": "idp"}}],
             }},
        ):
            misnamed = minimal_bootstrap({"path_separated_prefix": "/api"})
            misnamed["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"] = [bad_filter, {"name": "envoy.filters.http.router"}]
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(misnamed))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused")
        camel_hcm = minimal_bootstrap({"path_separated_prefix": "/api"})
        chcm_raw = camel_hcm["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        del chcm_raw["http_filters"]
        chcm_raw["httpFilters"] = [
            {"name": "envoy.filters.http.jwt_authn",
             "typedConfig": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication",
                 "providers": {"idp": {"issuer": "https://idp.example.test", "audiences": ["api"]}},
                 "rules": [{"match": {"prefix": "/"}, "requires": {"providerName": "idp"}}],
             }},
            {"name": "envoy.filters.http.router"},
        ]
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(camel_hcm))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        camel_per_route = minimal_bootstrap({"path_separated_prefix": "/api"})
        cpr = camel_per_route["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        del cpr["http_filters"]
        cpr["httpFilters"] = [
            {"name": "myJwtFilter", "disabled": True,
             "typedConfig": {"@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.JwtAuthentication"}},
            {"name": "envoy.filters.http.router"},
        ]
        cpr["route_config"]["virtual_hosts"][0]["routes"][0]["typedPerFilterConfig"] = {
            "myJwtFilter": {"@type": "type.googleapis.com/envoy.extensions.filters.http.jwt_authn.v3.PerRouteConfig"}
        }
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(camel_per_route))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        dup_spelling = minimal_bootstrap({"path_separated_prefix": "/api"})
        dup_spelling["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "httpFilters"] = [{"name": "envoy.filters.http.router"}]
        with self.assertRaises(InputError):
            migrate("envoy", yaml.safe_dump(dup_spelling))
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
        # 0% faults (explicit numerator 0, empty {}, or denominator-only {denominator: HUNDRED}) are inert;
        # malformed explicit numerator refuses.
        for inert_pct in (
            {"numerator": 0, "denominator": "HUNDRED"},
            {},
            {"denominator": "HUNDRED"},
        ):
            zero_fault = minimal_bootstrap({"path_separated_prefix": "/api"})
            zero_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"] = [
                {"name": "envoy.filters.http.fault",
                 "typed_config": {
                     "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                     "abort": {"http_status": 503, "percentage": inert_pct},
                 }},
                {"name": "envoy.filters.http.router"},
            ]
            zf_res, zf_rep, _ = migrate("envoy", yaml.safe_dump(zero_fault))
            self.assertEqual(one_proxy(self, zf_res.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
            self.assertEqual(zf_res.config["plugin_configs"], [])
            self.assertIn("envoy-fault-noop", codes(zf_rep, "info"))
        # Numeric protobuf enum denominator (0 -> HUNDRED) migrates cleanly, while malformed or >100%
        # (including 310-digit quoted) numerators refuse without crashing.
        num_enum_fault = minimal_bootstrap({"path_separated_prefix": "/api"})
        num_enum_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"] = [
            {"name": "envoy.filters.http.fault",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                 "abort": {"http_status": 503, "percentage": {"numerator": 10, "denominator": 0}},
             }},
            {"name": "envoy.filters.http.router"},
        ]
        ne_res = migrate("envoy", yaml.safe_dump(num_enum_fault))[0]
        self.assertEqual(plugin(self, ne_res.config, one_proxy(self, ne_res.config, "/api"), "fault_injection")[
            "config"], {"abort": {"status_code": 503, "percentage": 10.0, "body": "fault filter abort"}})
        for bad_num in ("bad", "--1", "1" + "0" * 310):
            bad_num_fault = minimal_bootstrap({"path_separated_prefix": "/api"})
            bad_num_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "http_filters"] = [
                {"name": "envoy.filters.http.fault",
                 "typed_config": {
                     "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                     "abort": {"http_status": 503, "percentage": {"numerator": bad_num, "denominator": "HUNDRED"}},
                 }},
                {"name": "envoy.filters.http.router"},
            ]
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(bad_num_fault))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused", bad_num[:12])
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
        # A single wildcard-only Envoy compressor refuses fail-closed (Envoy still compresses responses without
        # Content-Type and can strip Accept-Encoding via remove_accept_encoding_header: true).
        wild_comp = minimal_bootstrap({"path_separated_prefix": "/api"})
        wild_comp["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"].insert(0, {
                "name": "envoy.filters.http.compressor",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.http.compressor.v3.Compressor",
                    "compressor_library": {"name": "gzip", "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.compression.gzip.compressor.v3.Gzip"}},
                    "response_direction_config": {
                        "common_config": {"content_type": ["text/*"]},
                        "remove_accept_encoding_header": True,
                    },
                },
            })
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(wild_comp))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
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

        # (D) Inherited allow_credentials: true combined with non-boundary prefix, regex origin (PSL-sensitive), or
        #     wildcard '*' in allow_methods / allow_headers / expose_headers refuses; non-credentialed allow_headers:
        #     "*" emits ["*", "authorization"] for Fetch bearer-token preflights; duplicate cors filters refuse.
        for bad_override in (
            {"allow_origin_string_match": [{"prefix": "https://preview.example.test"}]},
            {"allow_origin_string_match": [{"safe_regex": {"regex": r"https://.*\.vercel\.app"}}]},
            {"allow_origin_string_match": [{"safe_regex": {"regex": r"https://[a-z]{2,}\.com"}}]},
            {"allow_origin_string_match": [{"exact": "https://app.example.test"}], "allow_methods": "*"},
            {"allow_origin_string_match": [{"exact": "https://app.example.test"}], "allow_headers": "*"},
            {"allow_origin_string_match": [{"exact": "https://app.example.test"}], "expose_headers": "*"},
        ):
            cred_bad = copy.deepcopy(typed_inherit)
            ch = cred_bad["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
            ch["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]["allow_credentials"] = {"value": True}
            ch["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"]["envoy.filters.http.cors"] = {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                **bad_override,
            }
            cp_res, _cp_rep, _ = migrate("envoy", yaml.safe_dump(cred_bad))
            self.assertEqual(one_proxy(self, cp_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")

        non_cred_star = copy.deepcopy(typed_over_legacy)
        nc_hcm = non_cred_star["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]["allow_headers"] = "*"
        nc_res, _nc_rep, _ = migrate("envoy", yaml.safe_dump(non_cred_star))
        nc_cors = plugin(self, nc_res.config, one_proxy(self, nc_res.config, "/api"), "cors")["config"]
        self.assertEqual(nc_cors["allowed_headers"], ["*", "authorization"])

        # Mixed ("*, X-Trace") and padded (" * ") allow_headers must NOT add authorization;
        # max_age at u64::MAX migrates while u64::MAX + 1 omits/refuses cleanly.
        for raw_hdrs, expected_hdrs in (("*, X-Trace", ["*", "X-Trace"]), (" * ", ["*"])):
            nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]["allow_headers"] = raw_hdrs
            mix_res, _mix_rep, _ = migrate("envoy", yaml.safe_dump(non_cred_star))
            mix_cors = plugin(self, mix_res.config, one_proxy(self, mix_res.config, "/api"), "cors")["config"]
            self.assertEqual(mix_cors["allowed_headers"], expected_hdrs, raw_hdrs)
        max_ok = copy.deepcopy(non_cred_star)
        mo_cors = max_ok["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]
        mo_cors["max_age"] = "18446744073709551615"
        self.assertEqual(plugin(self, migrate("envoy", yaml.safe_dump(max_ok))[0].config,
                                one_proxy(self, migrate("envoy", yaml.safe_dump(max_ok))[0].config, "/api"),
                                "cors")["config"]["max_age"], 18446744073709551615)
        mo_cors["max_age"] = "18446744073709551616"
        over_res, _over_rep, _ = migrate("envoy", yaml.safe_dump(max_ok))
        self.assertEqual(one_proxy(self, over_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertFalse(any(p["plugin_name"] == "cors" for p in over_res.config["plugin_configs"]))
        for bad_rx in (
            r"https://(a(b(c(d(e(f(g(h(i(j(app\.example\.test)))))))))))",
            r"x|a(?:x|a(?:x|a(?:x|a(?:x|a(?:x|ab+)+)+)+)+)+",
            r"^https://(?:[a])" + "(?:" * 26 + "pp" + ")" * 26 + r"\.example\.test$",
            "https://portal(?:" + "[ab]01" * 70 + "){0,64}[.]example[.]test",
            "https://(?:a|" + "()" * 200 + r"b){64}\.example\.test",
            r"^https://{tenant}\.example\.test$",
            r"^https://a{,3}\.example\.test$",
            r"^https://.{64}.{64}\.example\.test$",
            r"^https://a{5000}\.example\.test$",
            r"^https://a{5000000000}\.example\.test$",
            r"^https://[a[]\.example\.test$",
            r"^https://[\<]app\.example\.test$",
            r"^https://\<app\.example\.test$",
            r"^https://[\b]app\.example\.test$",
        ):
            with self.subTest(regex=bad_rx):
                nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"][
                    "allow_origin_string_match"] = [{"safe_regex": {"regex": bad_rx}}]
                nest_res, _nest_rep, _ = migrate("envoy", yaml.safe_dump(non_cred_star))
                self.assertEqual(one_proxy(self, nest_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
                self.assertFalse(any(p["plugin_name"] == "cors" for p in nest_res.config["plugin_configs"]))
        # Active Envoy CORS with ignoreCase (even uncredentialed + forward_not_matching_preflights: false)
        # refuses fail-closed rather than dropping CORS and forwarding preflights to the backend.
        nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"][
            "allow_origin_string_match"] = [{"exact": "https://APP.example.test", "ignoreCase": True}]
        nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"][
            "forward_not_matching_preflights"] = {"value": False}
        ic_res, _ic_rep, _ = migrate("envoy", yaml.safe_dump(non_cred_star))
        self.assertEqual(one_proxy(self, ic_res.config, "/api")["labels"]["ferrum-migration/status"], "refused")
        self.assertFalse(any(p["plugin_name"] == "cors" for p in ic_res.config["plugin_configs"]))
        del nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"][
            "forward_not_matching_preflights"]
        for cred_bad_matcher in (
            {"exact": "https://APP.example.test", "ignoreCase": True},
            {"exact": "*"},
        ):
            cred_ic = copy.deepcopy(non_cred_star)
            ci_cors = cred_ic["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
                "route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]
            ci_cors["allow_headers"] = "X-Trace"
            ci_cors["allow_credentials"] = {"value": True}
            ci_cors["allow_origin_string_match"] = [cred_bad_matcher]
            self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(cred_ic))[0].config, "/api")[
                "labels"]["ferrum-migration/status"], "refused")
        nc_hcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"][
            "allow_origin_string_match"] = [{"safe_regex": {"regex": r"^https://([a-z0-9-]+\.)?example\.test$"}}]
        ok_rx_res, _ok_rx_rep, _ = migrate("envoy", yaml.safe_dump(non_cred_star))
        self.assertEqual(plugin(self, ok_rx_res.config, one_proxy(self, ok_rx_res.config, "/api"), "cors")["config"][
            "allowed_origins"], [{"regex": r"^https://([a-z0-9-]+\.)?example\.test$"}])

        # Fault ordered BEFORE cors in http_filters refuses (Envoy aborts preflight before CORS),
        # whereas cors before fault migrates cleanly.
        for order_label, filters, expected_status in (
            ("fault-before-cors", [
                {"name": "envoy.filters.http.fault",
                 "typed_config": {
                     "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                     "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
                 }},
                {"name": "envoy.filters.http.cors"},
                {"name": "envoy.filters.http.router"},
            ], "refused"),
            ("cors-before-fault", [
                {"name": "envoy.filters.http.cors"},
                {"name": "envoy.filters.http.fault",
                 "typed_config": {
                     "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                     "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
                 }},
                {"name": "envoy.filters.http.router"},
            ], "migrated"),
        ):
            with self.subTest(order=order_label):
                fc_doc = minimal_bootstrap({"path_separated_prefix": "/api"})
                fc_hcm = fc_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
                fc_hcm["http_filters"] = filters
                fc_hcm["route_config"]["typed_per_filter_config"] = {
                    "envoy.filters.http.cors": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                        "allow_origin_string_match": [{"exact": "https://app.example.test"}],
                    }
                }
                fc_res = migrate("envoy", yaml.safe_dump(fc_doc))[0]
                self.assertEqual(one_proxy(self, fc_res.config, "/api")["labels"]["ferrum-migration/status"],
                                 expected_status)

        two_cors = minimal_bootstrap({"path_separated_prefix": "/api"})
        tchcm = two_cors["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        tchcm["http_filters"] = [
            {"name": "cors-a", "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors"}},
            {"name": "cors-b", "disabled": True,
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.Cors"}},
            {"name": "envoy.filters.http.router"},
        ]
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(two_cors))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")

        # (E) Active HCM fault filter on direct_response or HTTP-to-HTTPS redirect refuses (never folded away),
        #     and multiple fault filters in one HCM refuse (so disabling fault-b cannot erase fault-a).
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
        # Two fault filters (fault-a active, fault-b disabled on route) refuse the whole HCM.
        two_faults = minimal_bootstrap({"path": "/healthz"})
        tfhcm = two_faults["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        tfhcm["http_filters"] = [
            {"name": "fault-a",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                 "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
             }},
            {"name": "fault-b", "disabled": True,
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault"}},
            {"name": "envoy.filters.http.router"},
        ]
        tfhcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] = {
            "fault-b": {"@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig", "disabled": True}
        }
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(two_faults))[0].config, "=/healthz")[
            "labels"]["ferrum-migration/status"], "refused")


        # A route that disables an untranslatable vhost fault (raw or wrapped in FilterConfig.config) or
        # an untranslatable HCM fault via FilterConfig{disabled: true} migrates cleanly; grpc_web ordered
        # before fault with explicit grpc_status refuses; origin regex matching literal '*' normalizes to
        # ['*'] when uncredentialed and refuses when credentialed.
        for label, hcm_fault_cfg, vhost_fault_cfg in (
            ("raw-vhost-fault",
             {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault"},
             {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
              "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
              "headers": [{"name": "x-chaos", "exact_match": "1"}]}),
            ("wrapped-vhost-fault",
             {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault"},
             {"@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig",
              "config": {
                  "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                  "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
                  "headers": [{"name": "x-chaos", "exact_match": "1"}],
              }}),
            ("untranslatable-hcm-fault",
             {"@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
              "abort": {"http_status": 503, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
              "headers": [{"name": "x-chaos", "exact_match": "1"}]},
             None),
        ):
            with self.subTest(fault_disable=label):
                dis_fault = minimal_bootstrap({"path_separated_prefix": "/api"})
                dfhcm = dis_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
                dfhcm["http_filters"] = [
                    {"name": "envoy.filters.http.fault", "typed_config": hcm_fault_cfg},
                    {"name": "envoy.filters.http.router"},
                ]
                if vhost_fault_cfg is not None:
                    dfhcm["route_config"]["virtual_hosts"][0]["typed_per_filter_config"] = {
                        "envoy.filters.http.fault": vhost_fault_cfg,
                    }
                dfhcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] = {
                    "envoy.filters.http.fault": {
                        "@type": "type.googleapis.com/envoy.config.route.v3.FilterConfig",
                        "disabled": True,
                    }
                }
                df_res = migrate("envoy", yaml.safe_dump(dis_fault))[0]
                self.assertEqual(one_proxy(self, df_res.config, "/api")["labels"]["ferrum-migration/status"], "migrated")
                self.assertEqual(df_res.config["plugin_configs"], [])

        gw_fault = minimal_bootstrap({"path_separated_prefix": "/api"})
        gfhcm = gw_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        gfhcm["http_filters"] = [
            {"name": "envoy.filters.http.grpc_web",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.grpc_web.v3.GrpcWeb"}},
            {"name": "envoy.filters.http.fault",
             "typed_config": {
                 "@type": "type.googleapis.com/envoy.extensions.filters.http.fault.v3.HTTPFault",
                 "abort": {"grpc_status": 7, "percentage": {"numerator": 100, "denominator": "HUNDRED"}},
             }},
            {"name": "envoy.filters.http.router"},
        ]
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(gw_fault))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        # Standalone gRPC-status fault (without grpc_web ahead of it) emits HTTP status_code 200 matching Envoy.
        grpc_fault = copy.deepcopy(gw_fault)
        grpc_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"].pop(0)
        gf_res = migrate("envoy", yaml.safe_dump(grpc_fault))[0]
        self.assertEqual(plugin(self, gf_res.config, one_proxy(self, gf_res.config, "/api"), "fault_injection")[
            "config"], {"abort": {"status_code": 200, "grpc_status": 7, "percentage": 100.0,
                                  "body": "fault filter abort"}})
        # HCM local_reply_config refuses routes with active fault aborts, direct_response, or redirects.
        lr_fault = copy.deepcopy(grpc_fault)
        lr_fault["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "local_reply_config"] = {"body_format": {"text_format": "custom"}}
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(lr_fault))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        lr_local = minimal_bootstrap({"path": "/healthz"})
        llhcm = lr_local["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        llhcm["local_reply_config"] = {"body_format": {"json_format": {"msg": "%LOCAL_REPLY_BODY%"}}}
        llhcm["route_config"]["virtual_hosts"][0]["routes"] = [
            {"name": "dr", "match": {"path": "/healthz"}, "direct_response": {"status": 200}},
            {"name": "redir", "match": {"prefix": "/"}, "redirect": {"https_redirect": True}},
        ]
        ll_res, ll_rep, _ = migrate("envoy", yaml.safe_dump(lr_local))
        self.assertEqual(one_proxy(self, ll_res.config, "=/healthz")["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(one_proxy(self, ll_res.config, "/")["labels"]["ferrum-migration/status"], "refused")
        self.assertIn("envoy-local-reply", codes(ll_rep, "warning"))

        for star_pattern in (r"\*", r"\x{2a}", r"\Q*\E", r"(?:a?|\*?){30}"):
            with self.subTest(star_pattern=star_pattern):
                star_rx = minimal_bootstrap({"path_separated_prefix": "/api"})
                srhcm = star_rx["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
                srhcm["http_filters"] = [{"name": "envoy.filters.http.cors"}, {"name": "envoy.filters.http.router"}]
                srhcm["route_config"]["typed_per_filter_config"] = {
                    "envoy.filters.http.cors": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                        "allow_origin_string_match": [{"safe_regex": {"regex": star_pattern}}],
                        "allow_credentials": {"value": False},
                    }
                }
                sr_res = migrate("envoy", yaml.safe_dump(star_rx))[0]
                self.assertEqual(plugin(self, sr_res.config, one_proxy(self, sr_res.config, "/api"), "cors")["config"][
                    "allowed_origins"], ["*"])
                srhcm["route_config"]["typed_per_filter_config"]["envoy.filters.http.cors"]["allow_credentials"] = {
                    "value": True
                }
                self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(star_rx))[0].config, "/api")[
                    "labels"]["ferrum-migration/status"], "refused")
        # Divergent/unsupported RE2/Python syntax and over-budget repetitions refuse (never turn into allow-all);
        # linear-time star probe evaluates backtracking-heavy valid Rust regexes without hanging, and escaped
        # backslash before x{2a} ([\\x{2a}]) must NOT match literal '*'.
        for probe_err_pattern in (r".{,64}", r"(?=\*)\*", r"(?:a?|b?){100}x", r"\*{01}", r"\*{\x{31}}",
                                  r"\*{\Q1\E}", r"\x{D800}"):
            with self.subTest(probe_err=probe_err_pattern):
                pe_doc = minimal_bootstrap({"path_separated_prefix": "/api"})
                pehcm = pe_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
                pehcm["http_filters"] = [{"name": "envoy.filters.http.cors"}, {"name": "envoy.filters.http.router"}]
                pehcm["route_config"]["typed_per_filter_config"] = {
                    "envoy.filters.http.cors": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                        "allow_origin_string_match": [{"safe_regex": {"regex": probe_err_pattern}}],
                        "allow_credentials": {"value": False},
                    }
                }
                self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(pe_doc))[0].config, "/api")[
                    "labels"]["ferrum-migration/status"], "refused")
        # More than 64 origin matchers refuse immediately (even if exact '*' is present) before probing.
        many_doc = minimal_bootstrap({"path_separated_prefix": "/api"})
        mhcm = many_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        mhcm["http_filters"] = [{"name": "envoy.filters.http.cors"}, {"name": "envoy.filters.http.router"}]
        mhcm["route_config"]["typed_per_filter_config"] = {
            "envoy.filters.http.cors": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                "allow_origin_string_match": [{"exact": "*"}] + [{"exact": f"https://o{i}.example.test"} for i in range(64)],
                "allow_credentials": {"value": False},
            }
        }
        self.assertEqual(one_proxy(self, migrate("envoy", yaml.safe_dump(many_doc))[0].config, "/api")[
            "labels"]["ferrum-migration/status"], "refused")
        # Inherited allow_private_network_access maps to allow_private_network, and routes sharing the same
        # effective Envoy CORS policy deduplicate into one proxy_group PluginConfig.
        pna_doc = minimal_bootstrap({"path_separated_prefix": "/a"})
        pna_hcm = pna_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        pna_hcm["http_filters"] = [{"name": "envoy.filters.http.cors"}, {"name": "envoy.filters.http.router"}]
        pna_hcm["route_config"]["typed_per_filter_config"] = {
            "envoy.filters.http.cors": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                "allow_origin_string_match": [{"exact": "https://app.example.test"}],
                "allow_private_network_access": {"value": True},
            }
        }
        pna_hcm["route_config"]["virtual_hosts"][0]["routes"].append(
            {"name": "r2", "match": {"path_separated_prefix": "/b"}, "route": {"cluster": "c"}}
        )
        pna_res = migrate("envoy", yaml.safe_dump(pna_doc))[0]
        cors_pcs = [pc for pc in pna_res.config["plugin_configs"] if pc["plugin_name"] == "cors"]
        self.assertEqual(len(cors_pcs), 1)
        self.assertEqual(cors_pcs[0]["scope"], "proxy_group")
        self.assertIs(cors_pcs[0]["config"]["allow_private_network"], True)
        for non_star_rx in (r"(?:a?|b?){30}x", r"a?" * 30 + "x", r"^https://([a-z0-9-]+\.)*example\.com$", r"[\\x{2a}]"):
            with self.subTest(non_star=non_star_rx):
                ns_doc = minimal_bootstrap({"path_separated_prefix": "/api"})
                nshcm = ns_doc["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
                nshcm["http_filters"] = [{"name": "envoy.filters.http.cors"}, {"name": "envoy.filters.http.router"}]
                nshcm["route_config"]["typed_per_filter_config"] = {
                    "envoy.filters.http.cors": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                        "allow_origin_string_match": [{"safe_regex": {"regex": non_star_rx}}],
                        "allow_credentials": {"value": False},
                    }
                }
                ns_res = migrate("envoy", yaml.safe_dump(ns_doc))[0]
                ns_p = one_proxy(self, ns_res.config, "/api")
                self.assertEqual(ns_p["labels"]["ferrum-migration/status"], "migrated")
                self.assertEqual(plugin(self, ns_res.config, ns_p, "cors")["config"]["allowed_origins"],
                                 [{"regex": non_star_rx}])

        # Pure plaintext redirect vhost alongside a plaintext wildcard vhost stays as a refused placeholder so
        # plaintext traffic for the redirected host cannot fall through to the wildcard backend.
        mixed_redir = minimal_bootstrap({"prefix": "/"})
        mrhcm = mixed_redir["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        mrhcm["route_config"]["virtual_hosts"] = [
            {"name": "redir_vh", "domains": ["secure.example.test"],
             "routes": [{"name": "r", "match": {"prefix": "/"}, "redirect": {"https_redirect": True}}]},
            {"name": "catchall_vh", "domains": ["*"],
             "routes": [{"name": "c", "match": {"prefix": "/"}, "route": {"cluster": "c"}}]},
        ]
        mr_res = migrate("envoy", yaml.safe_dump(mixed_redir))[0]
        self.assertEqual(one_proxy(self, mr_res.config, None, "secure.example.test")["labels"][
            "ferrum-migration/status"], "refused")
        self.assertEqual(proxies(mr_res.config, "~/.*", "secure.example.test"), [])
        catchall = [p for p in proxies(mr_res.config, "/") if "hosts" not in p]
        self.assertEqual(len(catchall), 1)
        self.assertEqual(catchall[0]["labels"]["ferrum-migration/status"], "migrated")

        # Custom port_redirect (9443) alongside a live HTTPS listener does NOT fold away; it refuses fail-closed.
        port_redir = minimal_bootstrap({"prefix": "/"})
        port_redir["static_resources"]["listeners"] = [
            {
                "name": "plain",
                "address": {"socket_address": {"address": "0.0.0.0", "port_value": 80}},
                "filter_chains": [{"filters": [{
                    "name": "envoy.filters.network.http_connection_manager",
                    "typed_config": {
                        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                        "stat_prefix": "plain",
                        "http_filters": [{"name": "envoy.filters.http.router"}],
                        "route_config": {"virtual_hosts": [{
                            "name": "redir_vh", "domains": ["app.example.test"],
                            "routes": [{"name": "r", "match": {"prefix": "/"},
                                        "redirect": {"https_redirect": True, "port_redirect": 9443}}],
                        }]},
                    },
                }]}],
            },
            {
                "name": "tls",
                "address": {"socket_address": {"address": "0.0.0.0", "port_value": 443}},
                "filter_chains": [{
                    "transport_socket": {
                        "name": "envoy.transport_sockets.tls",
                        "typed_config": {
                            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                            "common_tls_context": {"tls_certificates": [{
                                "certificate_chain": {"filename": "/etc/certs/tls.crt"},
                                "private_key": {"filename": "/etc/certs/tls.key"},
                            }]},
                        },
                    },
                    "filters": [{
                        "name": "envoy.filters.network.http_connection_manager",
                        "typed_config": {
                            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                            "stat_prefix": "tls",
                            "http_filters": [{"name": "envoy.filters.http.router"}],
                            "route_config": {"virtual_hosts": [{
                                "name": "tls_vh", "domains": ["app.example.test"],
                                "routes": [{"name": "api", "match": {"path_separated_prefix": "/api"},
                                            "route": {"cluster": "c"}}],
                            }]},
                        },
                    }],
                }],
            },
        ]
        pr_res, pr_rep, _ = migrate("envoy", yaml.safe_dump(port_redir))
        self.assertNotIn("envoy-https-redirect", codes(pr_rep, "info"))
        self.assertEqual(one_proxy(self, pr_res.config, "/", "app.example.test")["labels"][
            "ferrum-migration/status"], "refused")
        # port_redirect: 0 (proto3 unset) folds cleanly alongside live HTTPS, whereas an active buffer filter
        # (which can locally return 413 before the redirect) prevents folding.
        zero_redir = copy.deepcopy(port_redir)
        zero_redir["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "route_config"]["virtual_hosts"][0]["routes"][0]["redirect"]["port_redirect"] = 0
        zr_res, zr_rep, _ = migrate("envoy", yaml.safe_dump(zero_redir))
        self.assertTrue(zr_res.tls_only)
        self.assertIn("envoy-https-redirect", codes(zr_rep, "info"))
        buf_redir = copy.deepcopy(zero_redir)
        buf_redir["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"][
            "http_filters"] = [
            {"name": "envoy.filters.http.buffer",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer",
                              "max_request_bytes": {"value": 1024}}},
            {"name": "envoy.filters.http.router"},
        ]
        br_res, br_rep, _ = migrate("envoy", yaml.safe_dump(buf_redir))
        self.assertNotIn("envoy-https-redirect", codes(br_rep, "info"))
        self.assertEqual(one_proxy(self, br_res.config, None, "app.example.test")["labels"][
            "ferrum-migration/status"], "refused")
        # Active buffer filter (including wrapped {value: N}) also refuses static redirects and direct_response routes.
        buf_static = minimal_bootstrap({"path": "/old"})
        bshcm = buf_static["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        bshcm["http_filters"] = [
            {"name": "envoy.filters.http.buffer",
             "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.buffer.v3.Buffer",
                              "max_request_bytes": {"value": 1024}}},
            {"name": "envoy.filters.http.router"},
        ]
        bshcm["route_config"]["virtual_hosts"][0]["routes"] = [
            {"name": "static_redir", "match": {"path": "/old"},
             "redirect": {"scheme_redirect": "https", "host_redirect": "new.example.test",
                          "path_redirect": "/new", "strip_query": True}},
            {"name": "direct_ok", "match": {"path": "/healthz"},
             "direct_response": {"status": 200, "body": {"inline_string": "ok"}}},
        ]
        bs_res = migrate("envoy", yaml.safe_dump(buf_static))[0]
        self.assertEqual(one_proxy(self, bs_res.config, "=/old")["labels"]["ferrum-migration/status"], "refused")
        self.assertEqual(one_proxy(self, bs_res.config, "=/healthz")["labels"]["ferrum-migration/status"], "refused")
        # Multiple Unicode \w shorthands exceed Ferrum's 64 KiB CORS regex compilation limit -> refused.
        w_cors = minimal_bootstrap({"path_separated_prefix": "/cors-w"})
        whcm = w_cors["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        whcm["http_filters"] = [{"name": "envoy.filters.http.cors"}, {"name": "envoy.filters.http.router"}]
        whcm["route_config"]["virtual_hosts"][0]["routes"][0]["typed_per_filter_config"] = {
            "envoy.filters.http.cors": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.cors.v3.CorsPolicy",
                "allow_credentials": {"value": False},
                "allow_origin_string_match": [{"safe_regex": {"regex": r"https://\w\.\w\.\w\.example\.test"}}],
            }
        }
        w_res = migrate("envoy", yaml.safe_dump(w_cors))[0]
        self.assertEqual(one_proxy(self, w_res.config, "/cors-w")["labels"]["ferrum-migration/status"], "refused")

    def test_tls_only_plaintext_exact_and_case_insensitive_routes_do_not_shadow_or_poison_https(self):
        # Plaintext named exact =/extra (including case_sensitive: false) must neither poison a live HTTPS catch-all
        # '/' nor shadow a live HTTPS named or wildcard '/' route in --tls-only mode.
        for tls_domains in (["*"], ["plain.example.test"], ["*.example.test"]):
            with self.subTest(tls_domains=tls_domains):
                doc = {
                    "static_resources": {
                        "clusters": [{
                            "name": "c", "type": "STRICT_DNS",
                            "load_assignment": {"endpoints": [{"lb_endpoints": [{
                                "endpoint": {"address": {"socket_address": {"address": "app.internal", "port_value": 8080}}}
                            }]}]},
                        }],
                        "listeners": [
                            {
                                "name": "http",
                                "address": {"socket_address": {"address": "0.0.0.0", "port_value": 80}},
                                "filter_chains": [{"filters": [{
                                    "name": "envoy.filters.network.http_connection_manager",
                                    "typed_config": {
                                        "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                                        "stat_prefix": "http",
                                        "http_filters": [{"name": "envoy.filters.http.router"}],
                                        "route_config": {"virtual_hosts": [{
                                            "name": "plain_vh", "domains": ["plain.example.test"],
                                            "routes": [{"name": "extra", "match": {"path": "/extra", "case_sensitive": False},
                                                        "route": {"cluster": "c"}}],
                                        }]},
                                    },
                                }]}],
                            },
                            {
                                "name": "tls",
                                "address": {"socket_address": {"address": "0.0.0.0", "port_value": 443}},
                                "filter_chains": [{
                                    "transport_socket": {
                                        "name": "envoy.transport_sockets.tls",
                                        "typed_config": {
                                            "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.DownstreamTlsContext",
                                            "common_tls_context": {"tls_certificates": [{
                                                "certificate_chain": {"filename": "/etc/certs/tls.crt"},
                                                "private_key": {"filename": "/etc/certs/tls.key"},
                                            }]},
                                        },
                                    },
                                    "filters": [{
                                        "name": "envoy.filters.network.http_connection_manager",
                                        "typed_config": {
                                            "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                                            "stat_prefix": "tls",
                                            "http_filters": [{"name": "envoy.filters.http.router"}],
                                            "route_config": {"virtual_hosts": [{
                                                "name": "tls_vh", "domains": tls_domains,
                                                "routes": [{"name": "root", "match": {"prefix": "/"}, "route": {"cluster": "c"}}],
                                            }]},
                                        },
                                    }],
                                }],
                            },
                        ],
                    }
                }
                res, _rep, _ = migrate("envoy", yaml.safe_dump(doc), tls_only=True)
                assert_structurally_valid(self, res.config)
                self.assertEqual(proxies(res.config, "=/extra"), [])
                root_p = one_proxy(self, res.config, "/")
                self.assertEqual(root_p["labels"]["ferrum-migration/status"], "migrated")


if __name__ == "__main__":
    unittest.main()
