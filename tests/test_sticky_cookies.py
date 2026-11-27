"""Consistent hashing on cookies and headers: every source maps within Ferrum's admission limits.

Ferrum Edge (``src/config/types.rs``) admits ``hash_on`` only as ``ip``, ``header:<token>`` or
``cookie:<token>`` (at most 255 bytes), and ``hash_on_cookie_config`` only with a ``/``-rooted path
without ``;`` or control characters, ``ttl_seconds`` from 0 to 86400 (a ``u64``), a valid domain and
``SameSite`` ``Strict``/``Lax``/``None``. One unrepresentable value rejects the whole resources file.
"""

import unittest

from helpers import migrate, read_fixture

from ferrum_migration.ferrum import _admissible_hash_policy
from ferrum_migration.model import Target, UpstreamSpec
from ferrum_migration.report import Report


def upstream_for(config: dict, target_host: str) -> dict:
    found = [u for u in config["upstreams"] if any(t["host"] == target_host for t in u["targets"])]
    assert len(found) == 1, (target_host, [u["id"] for u in config["upstreams"]])
    return found[0]


def codes(report: Report) -> set[str]:
    return {item.code for item in report.ordered()}


class TraefikStickyTest(unittest.TestCase):
    def setUp(self):
        self.result, self.report, _plan = migrate("traefik", read_fixture("sticky", "traefik.yaml"),
                                                  traefik_controls_asserted=True)

    def test_negative_max_age_expires_immediately(self):
        # Go sends Max-Age=0 for a negative MaxAge; Ferrum's ttl_seconds 0 sends the same (never a negative u64).
        upstream = upstream_for(self.result.config, "expiring-1.internal")
        self.assertEqual(upstream["algorithm"], "consistent_hashing")
        self.assertEqual(upstream["hash_on"], "cookie:expiring_affinity")
        self.assertEqual(upstream["hash_on_cookie_config"],
                         {"path": "/", "http_only": False, "secure": False, "ttl_seconds": 0})

    def test_oversized_age_invalid_name_and_attributes(self):
        upstream = upstream_for(self.result.config, "long-1.internal")
        self.assertTrue(upstream["hash_on"].startswith("cookie:traefik-"))
        self.assertEqual(upstream["hash_on_cookie_config"],
                         {"path": "/app", "http_only": True, "secure": True, "ttl_seconds": 86400,
                          "domain": "example.test", "same_site": "Lax"})
        self.assertLessEqual({"traefik-sticky-cookie-name", "traefik-sticky-max-age"}, codes(self.report))

    def test_default_session_cookie_and_invalid_path(self):
        upstream = upstream_for(self.result.config, "session-1.internal")
        self.assertTrue(upstream["hash_on"].startswith("cookie:traefik-"))
        self.assertEqual(upstream["hash_on_cookie_config"],
                         {"path": "/", "http_only": False, "secure": False, "session_cookie": True,
                          "same_site": "Strict"})
        self.assertIn("traefik-sticky-cookie-path", codes(self.report))


class KongStickyTest(unittest.TestCase):
    def test_cookie_is_a_session_cookie_like_kong(self):
        result, _report, _plan = migrate("kong", read_fixture("sticky", "kong.yaml"))
        carts = upstream_for(result.config, "carts-1.internal")
        self.assertEqual(carts["hash_on"], "cookie:cart_affinity")
        self.assertEqual(carts["hash_on_cookie_config"], {"path": "/carts", "session_cookie": True, "http_only": True})
        users = upstream_for(result.config, "users-1.internal")
        self.assertEqual(users["hash_on"], "header:x-user-id")
        self.assertNotIn("hash_on_cookie_config", users)

    def test_unrepresentable_cookie_falls_back_to_round_robin(self):
        text = read_fixture("sticky", "kong.yaml").replace("hash_on_cookie_path: /carts",
                                                           'hash_on_cookie_path: "/carts;x"')
        result, report, _plan = migrate("kong", text)
        carts = upstream_for(result.config, "carts-1.internal")
        self.assertNotIn("hash_on", carts)
        self.assertNotIn("hash_on_cookie_config", carts)
        self.assertIn("kong-hash-on", codes(report))


class EnvoyIstioStickyTest(unittest.TestCase):
    def test_envoy_generated_and_existing_cookies(self):
        result, report, _plan = migrate("envoy", read_fixture("sticky", "envoy.yaml"))
        generated = upstream_for(result.config, "generated-1.internal")
        self.assertEqual(generated["hash_on"], "cookie:envoy_affinity")
        self.assertEqual(generated["hash_on_cookie_config"], {"path": "/", "http_only": True, "ttl_seconds": 86400})
        existing = upstream_for(result.config, "existing-1.internal")
        self.assertEqual(existing["hash_on"], "cookie:app_session")
        self.assertEqual(existing["hash_on_cookie_config"], {"path": "/", "http_only": True, "session_cookie": True})
        self.assertIn("envoy-hash", codes(report))

    def test_istio_session_and_sub_second_ttl(self):
        result, report, _plan = migrate("istio", read_fixture("sticky", "istio.yaml"))
        session = upstream_for(result.config, "session.shop.svc.cluster.local")
        self.assertEqual(session["hash_on"], "cookie:session_affinity")
        self.assertEqual(session["hash_on_cookie_config"],
                         {"path": "/session", "http_only": True, "session_cookie": True})
        timed = upstream_for(result.config, "timed.shop.svc.cluster.local")
        # Envoy truncates a 0.5s ttl to Max-Age=0.
        self.assertEqual(timed["hash_on_cookie_config"], {"path": "/", "http_only": True, "ttl_seconds": 0})
        self.assertIn("istio-hash", codes(report))


class EmitterSafetyNetTest(unittest.TestCase):
    def spec(self, hash_on, cookie):
        return UpstreamSpec(key="k", name="n", ref="test upstream", targets=[Target("a.internal", 80, 1)],
                            algorithm="consistent_hashing", hash_on=hash_on, hash_on_cookie_config=cookie)

    def test_invalid_hash_key_drops_to_round_robin(self):
        report = Report("test", "input")
        for hash_on in ("cookie:not a token", "header:", "query:x", "cookie:" + "x" * 300):
            with self.subTest(hash_on=hash_on):
                self.assertEqual(_admissible_hash_policy(self.spec(hash_on, {"path": "/"}), report), (None, None))
        self.assertIn("hash-on-not-representable", codes(report))

    def test_invalid_cookie_settings_are_replaced(self):
        report = Report("test", "input")
        hash_on, cookie = _admissible_hash_policy(self.spec("cookie:a", {
            "path": "relative", "ttl_seconds": -1, "domain": "bad domain", "same_site": "lax", "secure": "yes",
            "unknown": 1}), report)
        self.assertEqual(hash_on, "cookie:a")
        self.assertEqual(cookie, {"path": "/", "session_cookie": True})
        self.assertIn("hash-cookie-not-representable", codes(report))

    def test_valid_policy_is_unchanged(self):
        report = Report("test", "input")
        cookie = {"path": "/x", "ttl_seconds": 86400, "domain": ".example.test", "same_site": "None",
                  "secure": True, "http_only": False}
        self.assertEqual(_admissible_hash_policy(self.spec("cookie:a", dict(cookie)), report), ("cookie:a", cookie))
        self.assertEqual(_admissible_hash_policy(self.spec("header:x-user", None), report), ("header:x-user", None))
        self.assertEqual(codes(report), set())


if __name__ == "__main__":
    unittest.main()
