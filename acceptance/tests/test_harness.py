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
import os
import stat
import sys
import tempfile
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

TESTS = Path(__file__).resolve().parent
ROOT = TESTS.parent
sys.path.insert(0, str(ROOT))

import run as run_cli  # noqa: E402
from harness import ferrum as ferrum_mod  # noqa: E402
from harness import probe  # noqa: E402
from harness.cases import ADAPTERS, load_cases  # noqa: E402
from harness.converter import ConverterProfile, exit_code_verdict, run_converter  # noqa: E402
from harness.echo import PROBE_HEADER, EchoBackend, EchoRecorder  # noqa: E402
from harness.ferrum import GatewayIdentity, ferrum_env, FerrumOptions  # noqa: E402
from harness.loopback import LoopbackThreadingHTTPServer  # noqa: E402
from harness.procs import ManagedProcess, PortHold, minimal_env  # noqa: E402
from harness.runner import RunContext, outcome_kind, run_case  # noqa: E402
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

    def test_traefik_cases_pass_the_entrypoint_assertion_explicitly(self):
        # The converter refuses forwarding Traefik routes unless the operator asserts the static entryPoints add no
        # controls; each Traefik case states that it passes it (its source is served on the harness's plain
        # loopback entryPoint), and no other adapter's case does.
        for case in load_cases(ROOT / "fixtures"):
            with self.subTest(case=case.id):
                expected = ["traefik-entrypoints-add-no-controls"] if case.adapter == "traefik" else []
                self.assertEqual(case.converter_assertions, expected)

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
        self.assertEqual(self.profile.assertion_argv,
                         {"traefik-entrypoints-add-no-controls": ["--assert-traefik-entrypoints-add-no-controls"]})

    def test_unmapped_converter_assertion_is_a_template_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            with self.assertRaises(TemplateError):
                run_converter(self.profile, "traefik", "x", work / "in.yaml", work / "out", work, False, {}, [], [],
                              assertions=["not-a-known-assertion"])
            self.assertFalse((work / "out").exists())

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


# Runs fake_ferrum.py as __main__ in a child whose socket.getfqdn raises, so any
# reverse-DNS lookup during fake gateway startup crashes the child before readiness.
_NO_FQDN_CHILD = (
    "import runpy, socket, sys\n"
    "def _no_fqdn(*_args, **_kwargs):\n"
    "    raise AssertionError('socket.getfqdn called during fake gateway startup')\n"
    "socket.getfqdn = _no_fqdn\n"
    "sys.argv = sys.argv[1:]\n"
    "runpy.run_path(sys.argv[0], run_name='__main__')\n"
)


class LoopbackStartupTests(unittest.TestCase):
    """Listener startup must not reverse-resolve its numeric loopback address (socket.getfqdn)."""

    @staticmethod
    def _forbid_getfqdn():
        return mock.patch("socket.getfqdn", side_effect=AssertionError("socket.getfqdn called"))

    def test_control_patch_target_is_what_stdlib_http_server_calls(self):
        # Proves the patch used below would catch a regression on this CPython.
        with mock.patch("socket.getfqdn", return_value="control.invalid") as fqdn:
            server = ThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
            server.server_close()
        if not fqdn.called:
            self.skipTest("this CPython's HTTPServer.server_bind no longer calls socket.getfqdn")
        self.assertEqual(server.server_name, "control.invalid")

    def test_echo_backend_startup_never_calls_getfqdn(self):
        recorder = EchoRecorder()
        with self._forbid_getfqdn() as fqdn:
            backend = EchoBackend("a", recorder).start()
            try:
                self.assertEqual(backend.server.server_address[0], "127.0.0.1")
                self.assertEqual(backend.server.server_name, "127.0.0.1")
                self.assertGreater(backend.port, 0)
                resp = probe.send(backend.port, "GET", "/n", "h.example.test", {PROBE_HEADER: "p-nofqdn"}, 5)
                self.assertEqual(resp["status"], 200)
                self.assertEqual(len(recorder.for_probe("p-nofqdn")), 1)
            finally:
                backend.stop()
        fqdn.assert_not_called()

    def test_loopback_server_refuses_names_and_non_loopback_hosts(self):
        with self._forbid_getfqdn() as fqdn:
            for host in ("localhost", "0.0.0.0", "192.0.2.1", "::1", "127.1", "", None):
                with self.subTest(host=host), self.assertRaises(ValueError):
                    LoopbackThreadingHTTPServer((host, 0), BaseHTTPRequestHandler)
        fqdn.assert_not_called()

    def test_fake_gateway_child_becomes_ready_without_getfqdn(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            spec = work / "spec.json"
            spec.write_text(json.dumps({"proxies": []}), encoding="utf-8")
            opts = FerrumOptions(
                argv_prefix=[sys.executable, "-c", _NO_FQDN_CHILD, str(TESTS / "fake_ferrum.py")],
                startup_timeout=20.0,
            )
            try:
                gateway = ferrum_mod.start_gateway(opts, spec, None, work)
            except ferrum_mod.FerrumStartupError as exc:
                self.fail(f"fake gateway did not become ready without getfqdn: {exc}\n{exc.output_tail}")
            try:
                self.assertEqual(gateway.proxies_loaded, 0)
                self.assertTrue(gateway.proc.alive())
            finally:
                gateway.stop()
            self.assertFalse(gateway.proc.alive())
            self.assertIn("fake gateway listeners bound", gateway.output_tail())


class ReadinessDiagnosticsTests(unittest.TestCase):
    def test_timeout_names_transport_error_without_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            hold = PortHold()
            port = hold.port
            hold.release()  # nothing listens on this port
            identity = GatewayIdentity()
            proc = ManagedProcess(
                "sleeper",
                [sys.executable, "-c", "import time; time.sleep(120)"],
                work,
                minimal_env(work),
                work / "o.log",
                work / "e.log",
            )
            try:
                with self.assertRaises(ferrum_mod.FerrumStartupError) as caught:
                    ferrum_mod._wait_ready(proc, port, identity, timeout=1.0)
            finally:
                proc.stop(grace_seconds=2)
            message = str(caught.exception)
            self.assertIn("no HTTP response from the admin listener", message)
            self.assertRegex(message, r"last transport error \w+")
            self.assertNotIn("last transport error unknown", message)
            for value in identity.sensitive():
                self.assertNotIn(value, message)


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


class WorkRootOwnershipTests(unittest.TestCase):
    """Case scratch lives in fresh, private, run-owned dirs; pre-existing --work-root entries are left alone."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name).resolve()
        self.work = self.tmp / "work"
        self.cases = load_cases(TESTS / "selftest_fixtures")
        self.preexisting = [c.id for c in self.cases] + ["_preflight"]
        # Ordinary directories carrying exactly the names the harness used to reuse or delete.
        self.sentinels = {}
        for name in self.preexisting:
            sentinel = self.work / name / "keep-me.txt"
            sentinel.parent.mkdir(parents=True)
            sentinel.write_text(f"pre-existing {name}\n", encoding="utf-8")
            self.sentinels[sentinel] = sentinel.read_text(encoding="utf-8")

    def assert_sentinels_intact(self):
        for sentinel, text in self.sentinels.items():
            self.assertEqual(sentinel.read_text(encoding="utf-8"), text)
            self.assertEqual([p.name for p in sentinel.parent.iterdir()], ["keep-me.txt"], sentinel.parent)

    def _run_cli(self, *extra: str) -> "tuple[int, dict]":
        results = self.tmp / "results.json"
        argv = [
            "--fixtures", str(TESTS / "selftest_fixtures"),
            "--converter-argv", json.dumps(["{python}", str(TESTS / "fake_converter.py"), "{source}", "{outdir}"]),
            "--converter-env", "FAKE_CONVERTER_MODE=copy",
            "--ferrum-argv", json.dumps([sys.executable, str(TESTS / "fake_ferrum.py")]),
            "--work-root", str(self.work),
            "--results", str(results),
            "--startup-timeout", "20",
            *extra,
        ]
        code = run_cli.main(argv)
        return code, json.loads(results.read_text(encoding="utf-8"))

    def test_passing_run_keeps_preexisting_entries_and_removes_only_its_own_scratch(self):
        code, payload = self._run_cli()
        self.assertEqual(code, 0, json.dumps(payload["cases"], indent=1))
        self.assertTrue(payload["cases"])
        for case in payload["cases"]:
            self.assertEqual(case["status"], "PASS")
            self.assertIsNone(case["workdir"])
        self.assert_sentinels_intact()
        self.assertEqual(sorted(p.name for p in self.work.iterdir()), sorted(self.preexisting))

    def test_kept_workdirs_live_in_a_fresh_private_run_dir(self):
        code, payload = self._run_cli("--keep-workdirs")
        self.assertEqual(code, 0, json.dumps(payload["cases"], indent=1))
        self.assert_sentinels_intact()
        run_dirs = [p for p in self.work.iterdir() if p.name not in self.preexisting]
        self.assertEqual(len(run_dirs), 1, run_dirs)
        run_dir = run_dirs[0]
        self.assertTrue(run_dir.name.startswith("run-"), run_dir)
        self.assertTrue((run_dir / "_preflight").is_dir())
        owned = [run_dir]
        for case in payload["cases"]:
            workdir = Path(case["workdir"])
            self.assertEqual(workdir.parent, run_dir)
            self.assertTrue(workdir.name.startswith(case["id"] + "-"), workdir)
            self.assertTrue((workdir / "input").is_dir())
            owned.append(workdir)
        if os.name == "posix":
            for directory in owned:
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode) & 0o077, 0, directory)

    def test_runner_creates_a_new_case_dir_instead_of_reusing_an_existing_one(self):
        case = self.cases[0]
        ctx = RunContext(
            work_root=self.work, converter=None, converter_env={}, ferrum=None, upstream=None,
            pass_env=[], mesh_validate_env=None, strict_mesh=False, keep_workdirs=False,
        )
        first = run_case(case, ctx, SyntheticCanaries())
        second = run_case(case, ctx, SyntheticCanaries())
        self.assertEqual((first["status"], second["status"]), ("SKIPPED", "SKIPPED"))
        dirs = [Path(first["workdir"]), Path(second["workdir"])]
        self.assertNotEqual(dirs[0], dirs[1])
        for workdir in dirs:
            self.assertEqual(workdir.parent, self.work)
            self.assertNotEqual(workdir, self.work / case.id)
            self.assertTrue((workdir / "input" / case.source.name).is_file())
        self.assert_sentinels_intact()


if __name__ == "__main__":
    unittest.main()
