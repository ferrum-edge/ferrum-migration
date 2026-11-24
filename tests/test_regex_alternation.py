"""Shared regex reasoning: a pipe proves nothing unless the narrow grammar places it inside a group.

Ordinary alternatives and pipe-free control patterns only.
"""

import unittest

from helpers import migrate

from ferrum_migration import util


class RegexLiteralPrefixTest(unittest.TestCase):
    def test_controls_without_pipe_are_unchanged(self):
        self.assertEqual(util.regex_literal_prefix("/api/v1/.*"), "/api/v1/")
        self.assertEqual(util.regex_literal_prefix("^/files/[a-z]+"), "/files/")
        self.assertFalse(util.regex_alternation_unproven("/api/v1/.*"))

    def test_grouped_alternatives_keep_their_literal_prefix(self):
        self.assertEqual(util.regex_literal_prefix("/api/(v1|v2)/.*"), "/api/")
        self.assertEqual(util.regex_literal_prefix("/static/.*\\.(?:css|js)"), "/static/")
        self.assertFalse(util.regex_alternation_unproven("/api/(v1|v2)/.*"))

    def test_top_level_alternatives_are_unknown(self):
        self.assertEqual(util.regex_literal_prefix("/api/.*|/admin/.*"), "")
        self.assertEqual(util.regex_literal_prefix("^/api/.*|/admin/.*"), "")
        self.assertTrue(util.regex_alternation_unproven("/api/.*|/admin/.*"))

    def test_pipes_outside_the_narrow_grammar_are_unknown(self):
        # A character class or an escaped pipe next to an alternative: nothing is proven.
        self.assertEqual(util.regex_literal_prefix("/files/[a-z]+/(v1|v2)"), "")
        self.assertEqual(util.regex_literal_prefix("/docs/a\\|b"), "")
        self.assertTrue(util.regex_alternation_unproven("/files/[a-z]+/(v1|v2)"))
        self.assertTrue(util.regex_alternation_unproven("/docs/a\\|b"))


ENVOY_HCM = "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager"
ENVOY_ROUTES = f"""
static_resources:
  listeners:
  - name: main
    address: {{socket_address: {{address: 0.0.0.0, port_value: 8080}}}}
    filter_chains:
    - filters:
      - name: envoy.filters.network.http_connection_manager
        typed_config:
          "@type": {ENVOY_HCM}
          stat_prefix: main
          http_filters:
          - name: envoy.filters.http.router
          route_config:
            virtual_hosts:
            - name: app
              domains: ["app.example.com"]
              routes:
              - name: api
                match: {{prefix: "/api"}}
                route: {{cluster: app}}
              - name: versions
                match: {{safe_regex: {{regex: "/api/(v1|v2)/.*"}}}}
                route: {{cluster: app}}
              - name: either
                match: {{safe_regex: {{regex: "/api/.*|/admin/.*"}}}}
                route: {{cluster: app}}
  clusters:
  - name: app
    type: STRICT_DNS
    load_assignment:
      cluster_name: app
      endpoints:
      - lb_endpoints:
        - endpoint: {{address: {{socket_address: {{address: app.internal, port_value: 8080}}}}}}
"""


class FirstMatchCoverageTest(unittest.TestCase):
    def test_only_a_grouped_alternative_is_proven_covered(self):
        _result, _report, plan = migrate("envoy", ENVOY_ROUTES)
        by_name = {route.name: route for route in plan.routes}
        # Every match of the grouped pattern starts with /api/, so the earlier /api prefix covers it.
        self.assertTrue(by_name["versions"].skip)
        # A top-level alternative also matches /admin/...: not covered by /api, so it stays in the plan.
        self.assertFalse(by_name["either"].skip)


if __name__ == "__main__":
    unittest.main()
