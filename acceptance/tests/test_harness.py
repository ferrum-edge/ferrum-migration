"""Self-tests for the acceptance harness (stdlib unittest, loopback only).

    python3 -m unittest discover -s acceptance/tests -v

These tests exercise the harness's own mechanics with a fake converter and a
fake gateway. They prove nothing about Ferrum Edge or ferrum-migration.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path.insert(0, str(ROOT))

import run as run_cli  # noqa: E402
from harness import probe  # noqa: E402
from harness.cases import ADAPTERS, load_cases  # noqa: E402
from harness.converter import ConverterProfile, exit_code_verdict  # noqa: E402
from harness.echo import PROBE_HEADER, EchoBackend, EchoRecorder  # noqa: E402
from harness.ferrum import GatewayIdentity, ferrum_env, FerrumOptions  # noqa: E402
from harness.procs import ManagedProcess, minimal_env  # noqa: E402
from harness.runner import outcome_kind  # noqa: E402
from harness.util import (  # noqa: E402
    SyntheticCanaries,
    TemplateError,
    declared_listen_ports,
    expand_argv,
    mint_hs256_jwt,
    render_source,
    source_placeholders,
)

SMOKE_CASES = ("kong-dbless-smoke", "kong-deck-smoke", "nginx-proxy-pass-uri", "traefik-smoke", "envoy-smoke",
               "istio-smoke")


class TemplateTests(unittest.TestCase):
    def test_tokens_expand_per_element_without_reexpansion(self):
        out = expand_argv(["{python}", "--in", "{source}", "{{literal}}"], {"python": "py", "source": "{outdir} ; rm -rf /"})
        self.assertEqual(out, ["py", "--in", "{outdir} ; rm -rf /", "{literal}"])

    def test_unknown_token_is_an_error(self):
        with self.assertRaises(TemplateError):
            expand_argv(["{nope}"], {})

    def test_argv_must_be_list_of_strings(self):
        with self.assertRaises(TemplateError):
            expand_argv("ferrum-edge run", {})

    def test_source_unknown_placeholder_is_an_error(self):
        with self.assertRaises(TemplateError):
            render_source("port: ${NOT_A_THING}", {})

    def test_listen_port_scan(self):
        text = 'proxies:\n  - id: a\n    listen_port: 18080\n{"listen_port": "9090"}'
        self.assertEqual(declared_listen_ports(text), {18080, 9090})


class FixtureTests(unittest.TestCase):
    def test_all_fixtures_load_and_render(self):
        cases = load_cases(ROOT / "fixtures")
        adapters = {c.adapter for c in cases}
        self.assertTrue({a for a in ADAPTERS if a != "selftest"} <= adapters)
        canaries = SyntheticCanaries()
        values = {"ECHO_A_PORT": 1, "ECHO_B_PORT": 2, "LISTEN_PORT": 3, "WORKDIR": "/tmp/x", **canaries.source_values()}
        for case in cases:
            rendered = render_source(case.source.read_text(encoding="utf-8"), values)
            # Only harness placeholders (${UPPER_CASE}) must be gone; a literal "${" can be legitimate
            # source syntax (nginx ${var}) and comments may mention it.
            self.assertEqual(source_placeholders(rendered), set(), case.id)
            self.assertTrue(case.claims, case.id)
            for p in case.probes:
                for value in p.headers.values():
                    render_source(value, canaries.header_values())

    def test_smoke_cases_cover_all_five_sources_with_forwarding_and_denial(self):
        cases = {c.id: c for c in load_cases(ROOT / "fixtures")}
        adapters = set()
        for case_id in SMOKE_CASES:
            self.assertIn(case_id, cases)
            case = cases[case_id]
            adapters.add(case.adapter)
            self.assertFalse(case.allow_rejection, case_id)
            self.assertTrue(any(p.positive for p in case.probes), case_id)
            self.assertTrue(any(p.deny for p in case.probes), case_id)
        self.assertEqual(adapters, {"kong-dbless", "kong-deck", "nginx", "traefik", "envoy", "istio"})

    def test_canaries_are_unique_per_run(self):
        a, b = SyntheticCanaries(), SyntheticCanaries()
        self.assertNotEqual(a.key, b.key)
        self.assertNotEqual(a.stored_hash, b.stored_hash)
        self.assertEqual(len(a.stored_hash), 40)


class ConverterContractTests(unittest.TestCase):
    def setUp(self):
        self.profile = ConverterProfile.load(ROOT / "profiles" / "converter.default.json")

    def test_default_profile_matches_real_cli(self):
        self.assertFalse(self.profile.assumed)
        self.assertEqual(self.profile.argv[3:], ["convert", "{source}", "--from", "{platform}", "--out", "{outdir}"])
        self.assertEqual(self.profile.platform("kong-deck"), "kong")
        self.assertEqual(self.profile.platform("kong-dbless"), "kong")
        self.assertEqual(self.profile.outputs["report"], ["migration-report.json"])

    def test_exit_code_must_agree_with_report(self):
        clean = {"caveats": [], "counts": {"error": 0}}
        dirty = {"caveats": [{"severity": "error", "code": "x"}], "counts": {"error": 1}}
        self.assertEqual(exit_code_verdict(self.profile, 0, clean), ([], False))
        self.assertEqual(exit_code_verdict(self.profile, 4, dirty), ([], False))
        self.assertTrue(exit_code_verdict(self.profile, 0, dirty)[0])
        self.assertTrue(exit_code_verdict(self.profile, 4, clean)[0])
        self.assertTrue(exit_code_verdict(self.profile, 1, None)[0])
        self.assertTrue(exit_code_verdict(self.profile, 5, clean)[0])
        self.assertEqual(exit_code_verdict(self.profile, 3, None), ([], True))

    def test_outcome_kinds_separate_conversion_from_refusal(self):
        cases = {c.id: c for c in load_cases(ROOT / "fixtures")}
        positive, deny_only = cases["kong-dbless-smoke"], cases["kong-deck-basic-auth-hash"]
        self.assertEqual(outcome_kind(positive, "PASS"), "behavioral-conversion")
        self.assertEqual(outcome_kind(deny_only, "PASS"), "fail-closed-deny-only")
        self.assertEqual(outcome_kind(positive, "REJECTED_ACCEPTABLE"), "safe-refusal")
        self.assertEqual(outcome_kind(positive, "FAIL"), "none")

    def test_basic_auth_secret_is_supplied_and_scrubbed(self):
        with tempfile.TemporaryDirectory() as tmp:
            identity = GatewayIdentity()
            env = ferrum_env(FerrumOptions(argv_prefix=["x"]), Path(tmp), 1, 2, identity)
            secret = env["FERRUM_BASIC_AUTH_HMAC_SECRET"]
            self.assertGreaterEqual(len(secret), 32)
            self.assertIn(secret, identity.sensitive())
            self.assertNotEqual(secret, GatewayIdentity().basic_auth_hmac_secret)


class JwtTests(unittest.TestCase):
    def test_hs256_signature_verifies(self):
        token = mint_hs256_jwt("s" * 40, "iss-x", ttl_seconds=60)
        head, body, sig = token.split(".")
        expected = hmac.new(b"s" * 40, f"{head}.{body}".encode(), hashlib.sha256).digest()
        self.assertEqual(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)), expected)
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        self.assertEqual(claims["iss"], "iss-x")
        self.assertLessEqual(claims["exp"] - claims["iat"], 60)


class EchoTests(unittest.TestCase):
    def test_echo_records_probe(self):
        recorder = EchoRecorder()
        backend = EchoBackend("a", recorder).start()
        try:
            resp = probe.send(backend.port, "GET", "/x/y?z=1", "h.example.test", {PROBE_HEADER: "p1"}, 5)
            self.assertEqual(resp["status"], 200)
            records = recorder.for_probe("p1")
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["path"], "/x/y?z=1")
            self.assertEqual(records[0]["host"], "h.example.test")
        finally:
            backend.stop()


class ProcessTests(unittest.TestCase):
    def test_stop_is_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            proc = ManagedProcess(
                "sleeper",
                [sys.executable, "-c", "import time; time.sleep(120)"],
                work,
                minimal_env(work),
                work / "o.log",
                work / "e.log",
            )
            started = time.monotonic()
            proc.stop(grace_seconds=2)
            self.assertFalse(proc.alive())
            self.assertLess(time.monotonic() - started, 10)


class EndToEndSelfTest(unittest.TestCase):
    def _run(self, mode: str) -> dict:
        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results.json"
            argv = [
                "--fixtures", str(TESTS / "selftest_fixtures"),
                "--converter-argv", json.dumps(["{python}", str(TESTS / "fake_converter.py"), "{source}", "{outdir}"]),
                "--converter-env", f"FAKE_CONVERTER_MODE={mode}",
                "--ferrum-argv", json.dumps([sys.executable, str(TESTS / "fake_ferrum.py")]),
                "--work-root", str(Path(tmp) / "work"),
                "--results", str(results),
                "--startup-timeout", "20",
            ]
            code = run_cli.main(argv)
            payload = json.loads(results.read_text(encoding="utf-8"))
            payload["_exit"] = code
            return payload

    def test_pass_path(self):
        payload = self._run("copy")
        case = payload["cases"][0]
        self.assertEqual(case["status"], "PASS", json.dumps(case, indent=1))
        self.assertEqual(payload["_exit"], 0)

    def test_credential_leak_is_caught_and_scrubbed(self):
        payload = self._run("leak")
        case = payload["cases"][0]
        self.assertEqual(case["status"], "FAIL")
        self.assertTrue(any("synthetic API key" in f for f in case["failures"]))
        self.assertNotIn("synthetic-acceptance-key-", json.dumps(payload))
        self.assertEqual(payload["_exit"], 1)

    def test_rejection_of_supported_case_fails(self):
        payload = self._run("reject")
        self.assertEqual(payload["cases"][0]["status"], "FAIL")

    def test_exit_code_contradicting_report_fails(self):
        payload = self._run("liar")
        case = payload["cases"][0]
        self.assertEqual(case["status"], "FAIL")
        self.assertTrue(any("error finding" in f for f in case["failures"]), case["failures"])

    def test_pass_is_labelled_behavioral(self):
        payload = self._run("copy")
        self.assertEqual(payload["cases"][0]["outcome_kind"], "behavioral-conversion")
        self.assertEqual(payload["outcome_kinds"], {"behavioral-conversion": 1})


if __name__ == "__main__":
    unittest.main()
