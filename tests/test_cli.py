import contextlib
import io
import json
import os
import stat
import tempfile
import unittest

import yaml

from helpers import fixture_path

from ferrum_migration.cli import main
from ferrum_migration.envprofile import KNOWN_SETTINGS, conf_value
from ferrum_migration.errors import InputError

OUTPUT_FILES = ("resources.yaml", "ferrum.conf", "migration-report.json", "migration-report.md")
FIXTURES = {
    "kong": ("kong", "kong.yaml"),
    "nginx": ("nginx", "nginx.conf"),
    "traefik": ("traefik", "dynamic.yaml"),
    "envoy": ("envoy", "envoy.yaml"),
    "istio": ("istio", "istio.yaml"),
}
EXPECTED_EXIT = {"kong": 4, "nginx": 0, "traefik": 4, "envoy": 4, "istio": 4}
# The synthetic Traefik fixture stands for a source whose static entryPoints add no frontend controls, so its
# end-to-end run passes the operator assertion explicitly (the default refusal is tested separately below).
EXTRA_ARGS = {"traefik": ("--assert-traefik-entrypoints-add-no-controls",)}
TRAEFIK_ASSERTION = "--assert-traefik-entrypoints-add-no-controls"
FIXTURE_SECRETS = ("test-only-key-alice-0001", "test-only-password-hash-bob", "short-key",
                   "dGVzdC1vbmx5LW5vdC1hLXJlYWwta2V5LWZpeHR1cmU=")


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


def conf_keys(text):
    keys = []
    for line in text.splitlines():
        if line and not line.startswith("#"):
            key, sep, _value = line.partition("=")
            assert sep, line
            keys.append(key)
    return keys


class CliTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def out_dir(self, name="out"):
        return os.path.join(self.temp.name, name)

    def read(self, directory, name):
        with open(os.path.join(directory, name), encoding="utf-8") as handle:
            return handle.read()

    def test_platforms(self):
        code, out, _ = run_cli("platforms")
        self.assertEqual(code, 0)
        for name in FIXTURES:
            self.assertIn(name, out)

    def test_every_platform_end_to_end(self):
        for platform, parts in FIXTURES.items():
            with self.subTest(platform=platform):
                out = self.out_dir(platform)
                code, stdout, stderr = run_cli("convert", fixture_path(*parts), "--from", platform, "--out", out,
                                               *EXTRA_ARGS.get(platform, ()))
                self.assertEqual(code, EXPECTED_EXIT[platform], stderr + stdout)
                for name in OUTPUT_FILES:
                    path = os.path.join(out, name)
                    self.assertTrue(os.path.isfile(path), name)
                    if os.name == "posix":
                        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600, name)
                if os.name == "posix":
                    self.assertEqual(stat.S_IMODE(os.stat(out).st_mode), 0o700)
                resources_text = self.read(out, "resources.yaml")
                self.assertTrue(resources_text.startswith("# Ferrum Edge file-mode resources"))
                resources = yaml.safe_load(resources_text)
                self.assertEqual(list(resources)[:2], ["version", "resource_counts"])
                report = json.loads(self.read(out, "migration-report.json"))
                self.assertEqual(report["platform"], platform)
                self.assertEqual(report["counts"]["error"] > 0, EXPECTED_EXIT[platform] == 4)
                conf = self.read(out, "ferrum.conf")
                self.assertIn("FERRUM_MODE=file", conf)
                self.assertTrue(set(conf_keys(conf)) <= KNOWN_SETTINGS)
                combined = "".join(self.read(out, name) for name in OUTPUT_FILES)
                for secret in FIXTURE_SECRETS:
                    self.assertNotIn(secret, combined)
                self.assertNotIn(".gitignore", os.listdir(out))

    def test_output_is_byte_stable(self):
        first, second = self.out_dir("a"), self.out_dir("b")
        run_cli("convert", fixture_path("traefik", "dynamic.yaml"), "--from", "traefik", "--out", first)
        run_cli("convert", fixture_path("traefik", "dynamic.yaml"), "--from", "traefik", "--out", second)
        for name in OUTPUT_FILES:
            self.assertEqual(self.read(first, name), self.read(second, name), name)

    def test_traefik_default_refuses_forwarding_until_the_operator_asserts_entrypoints(self):
        path = fixture_path("traefik", "dynamic.toml")
        code, stdout, _stderr = run_cli("check", path, "--from", "traefik", "--json")
        self.assertEqual(code, 4)
        report = json.loads(stdout)
        found = {c["code"] for c in report["caveats"]}
        self.assertIn("traefik-entrypoints-unverified", found)
        self.assertNotIn("traefik-entrypoints-asserted", found)
        self.assertEqual(report["summary"]["migrated_routes"], 0)
        code, stdout, _stderr = run_cli("check", path, "--from", "traefik", "--json", TRAEFIK_ASSERTION)
        self.assertEqual(code, 4)  # the remaining review item is the string-prefix sibling report
        report = json.loads(stdout)
        found = {c["code"] for c in report["caveats"]}
        self.assertNotIn("traefik-entrypoints-unverified", found)
        self.assertIn("traefik-entrypoints-asserted", found)
        self.assertEqual(report["summary"]["migrated_routes"], 1)

    def test_traefik_entrypoint_assertion_is_refused_for_other_sources(self):
        for platform, parts in (("nginx", ("nginx", "nginx.conf")), ("kong", ("kong", "kong.yaml"))):
            out = self.out_dir(platform)
            for command in (("convert", fixture_path(*parts), "--from", platform, "--out", out),
                            ("check", fixture_path(*parts), "--from", platform)):
                with self.subTest(platform=platform, command=command[0]):
                    code, _stdout, stderr = run_cli(*command, TRAEFIK_ASSERTION)
                    self.assertEqual(code, 2)
                    self.assertIn("only to --from traefik", stderr)
                    self.assertFalse(os.path.exists(out))

    def test_refuses_to_overwrite_without_force(self):
        out = self.out_dir()
        args = ("convert", fixture_path("nginx", "nginx.conf"), "--from", "nginx", "--out", out)
        self.assertEqual(run_cli(*args)[0], 0)
        code, _out, err = run_cli(*args)
        self.assertEqual(code, 5)
        self.assertIn("--force", err)
        self.assertEqual(run_cli(*args, "--force")[0], 0)

    @unittest.skipUnless(os.name == "posix", "symlinks")
    def test_symlinked_output_directory_refused(self):
        real = self.out_dir("real")
        os.mkdir(real)
        link = self.out_dir("link")
        os.symlink(real, link)
        code, _out, _err = run_cli("convert", fixture_path("nginx", "nginx.conf"), "--from", "nginx", "--out", link)
        self.assertEqual(code, 5)
        self.assertEqual(os.listdir(real), [])

    def test_include_secrets_is_explicit_and_private(self):
        out = self.out_dir()
        code, _stdout, stderr = run_cli("convert", fixture_path("kong", "kong.yaml"), "--from", "kong", "--out", out,
                                        "--include-secrets")
        self.assertEqual(code, 4)
        self.assertIn("test-only-key-alice-0001", self.read(out, "resources.yaml"))
        for name in ("ferrum.conf", "migration-report.json", "migration-report.md"):
            self.assertNotIn("test-only-key-alice-0001", self.read(out, name))
        self.assertEqual(self.read(out, ".gitignore").splitlines()[-1], "*")
        self.assertIn("plaintext credential", stderr)
        self.assertNotIn("test-only-key-alice-0001", stderr)

    def test_check_prints_report_without_writing(self):
        code, stdout, _ = run_cli("check", fixture_path("envoy", "envoy.yaml"), "--from", "envoy", "--json")
        self.assertEqual(code, 4)
        report = json.loads(stdout)
        self.assertIn("route-refused", {c["code"] for c in report["caveats"]})
        self.assertEqual(os.listdir(self.temp.name), [])

    def test_rejected_input_exit_3_without_echo(self):
        path = os.path.join(self.temp.name, "dup.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("_format_version: '3.0'\nservices: []\nservices: [{name: 'test-only-secret-zz9'}]\n")
        code, _out, err = run_cli("convert", path, "--from", "kong", "--out", self.out_dir())
        self.assertEqual(code, 3)
        self.assertIn("input rejected", err)
        self.assertNotIn("test-only-secret-zz9", err)
        self.assertFalse(os.path.exists(self.out_dir()))

    def test_max_input_bytes(self):
        code, _out, _err = run_cli("check", fixture_path("kong", "kong.yaml"), "--from", "kong",
                                   "--max-input-bytes", "64")
        self.assertEqual(code, 3)
        self.assertEqual(run_cli("check", fixture_path("kong", "kong.yaml"), "--from", "kong",
                                 "--max-input-bytes", "0")[0], 2)

    def test_strict_turns_warnings_into_review(self):
        self.assertEqual(run_cli("check", fixture_path("nginx", "nginx.conf"), "--from", "nginx", "--strict")[0], 4)

    def test_usage_errors(self):
        self.assertEqual(run_cli("convert", fixture_path("kong", "kong.yaml"))[0], 2)
        self.assertEqual(run_cli("check", fixture_path("nginx", "nginx.conf"), "--from", "nginx",
                                 "--input-format", "yaml")[0], 3)

    def test_run_mode_profiles(self):
        expectations = {
            "database": ("FERRUM_MODE=database", "FERRUM_DB_TYPE=sqlite"),
            "cp": ("FERRUM_MODE=cp", "FERRUM_CP_GRPC_LISTEN_ADDR=127.0.0.1:50051"),
            "dp": ("FERRUM_MODE=dp", "# FERRUM_DP_CP_GRPC_URLS="),
        }
        for mode, needles in expectations.items():
            with self.subTest(mode=mode):
                out = self.out_dir(mode)
                run_cli("convert", fixture_path("nginx", "nginx.conf"), "--from", "nginx", "--out", out,
                        "--run-mode", mode)
                conf = self.read(out, "ferrum.conf")
                for needle in needles:
                    self.assertIn(needle, conf)
                self.assertTrue(set(conf_keys(conf)) <= KNOWN_SETTINGS)
                self.assertNotIn("FERRUM_ADMIN_JWT_SECRET=", conf)

    def test_nginx_profile_values(self):
        out = self.out_dir()
        run_cli("convert", fixture_path("nginx", "nginx.conf"), "--from", "nginx", "--out", out)
        conf = self.read(out, "ferrum.conf")
        for needle in ("FERRUM_PROXY_HTTP_PORT=0", "FERRUM_PROXY_HTTPS_PORT=443",
                       "FERRUM_FRONTEND_TLS_CERT_PATH=/etc/nginx/tls/example.crt",
                       "FERRUM_FRONTEND_TLS_KEY_PATH=/etc/nginx/tls/example.key",
                       "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=104857600"):
            self.assertIn(needle, conf)

    def test_json_resources_format(self):
        out = self.out_dir()
        run_cli("convert", fixture_path("istio", "istio.yaml"), "--from", "istio", "--out", out,
                "--resources-format", "json")
        resources = json.loads(self.read(out, "resources.json"))
        self.assertEqual(resources["resource_counts"]["proxies"], len(resources["proxies"]))
        self.assertIn("--spec resources.json", self.read(out, "migration-report.md"))

    def test_alternating_resource_formats_never_leave_ambiguous_specs(self):
        # Ferrum discovers ./resources.yaml before ./resources.json, so a stale file of the other format must be
        # rejected before anything is written, even with --force.
        out = self.out_dir()
        args = ("convert", fixture_path("nginx", "nginx.conf"), "--from", "nginx", "--out", out)
        self.assertEqual(run_cli(*args)[0], 0)
        before = self.read(out, "ferrum.conf")
        code, _out, err = run_cli(*args, "--force", "--resources-format", "json")
        self.assertEqual(code, 5)
        self.assertIn("resources.yaml", err)
        self.assertNotIn("resources.json", os.listdir(out))
        self.assertEqual(self.read(out, "ferrum.conf"), before)

    def test_conf_values_round_trip_or_fail_closed(self):
        key = "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH"
        self.assertEqual(conf_value(key, "/etc/synthetic/ca.pem"), "/etc/synthetic/ca.pem")
        self.assertEqual(conf_value(key, "/etc/synthetic/client ca #1.pem"), '"/etc/synthetic/client ca #1.pem"')
        self.assertEqual(conf_value(key, '"quoted-start.pem'), "'\"quoted-start.pem'")
        self.assertEqual(conf_value(key, " padded.pem"), '" padded.pem"')
        for bad in ("", "/etc/synthetic/ca\n.pem", "/etc/synthetic/ca\r.pem", "/etc/synthetic/ca .pem",
                    "/etc/synthetic/both\"'quotes #.pem"):
            with self.subTest(value=repr(bad)), self.assertRaises(InputError):
                conf_value(key, bad)

    def test_unrepresentable_client_ca_path_writes_nothing(self):
        path = os.path.join(self.temp.name, "nginx.conf")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("server {\n listen 443 ssl;\n server_name m.example.test;\n"
                         " ssl_certificate /etc/synthetic/server.crt;\n ssl_certificate_key /etc/synthetic/server.key;\n"
                         ' ssl_client_certificate "/etc/synthetic/client\nca.pem";\n ssl_verify_client on;\n'
                         " location /m/ { proxy_pass http://m.internal:8080; }\n}\n")
        for command in (("convert", path, "--from", "nginx", "--out", self.out_dir()), ("check", path, "--from", "nginx")):
            with self.subTest(command=command[0]):
                code, _out, err = run_cli(*command)
                self.assertEqual(code, 3)
                self.assertIn("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH", err)
                self.assertNotIn("client\nca.pem", err)
        self.assertFalse(os.path.exists(self.out_dir()))


if __name__ == "__main__":
    unittest.main()
