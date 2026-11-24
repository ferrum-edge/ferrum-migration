"""Independent checks against Ferrum Edge itself (skipped when it is not available).

* ``FERRUM_EDGE_SRC`` (or a sibling ``../refs/ferrum-edge`` checkout): every key
  the tool emits must be a non-``serde(skip)`` field of the matching Ferrum struct,
  every plugin config key must appear in that plugin's source, and every
  ``ferrum.conf`` key must be in Ferrum's public settings inventory.
* ``FERRUM_EDGE_BIN``: every fixture's generated resources must pass
  ``ferrum-edge validate -m file -c resources.yaml`` (Ferrum's real admission
  pipeline). The command runs in an empty temp directory with a minimal
  environment; a random throwaway basic-auth HMAC secret is supplied only
  because basic_auth construction requires one.

  Some fixtures intentionally reference operator-supplied backend TLS files
  (the Istio DestinationRule names ``/etc/certs/internal-ca.pem``). Ferrum
  checks such files at load time, so a missing file is a correct rejection,
  not a converter bug. For admission testing, the test generates a throwaway
  synthetic CA with ``openssl`` inside its temp directory and points a *copy*
  of the resources at it. Verification stays enabled, and the converter output
  itself keeps the operator path (asserted by the unit tests). Without
  ``openssl`` those fixtures are skipped explicitly; the rest still run.
"""

import copy
import os
import re
import secrets
import shutil
import subprocess
import tempfile
import unittest

import yaml

from helpers import ROOT, migrate, read_fixture

from ferrum_migration import FERRUM_EDGE_REFERENCE_COMMIT
from ferrum_migration.envprofile import KNOWN_SETTINGS, render

CASES = [("kong", ("kong", "kong.yaml"), "yaml"), ("nginx", ("nginx", "nginx.conf"), "nginx"),
         ("traefik", ("traefik", "dynamic.yaml"), "yaml"), ("traefik", ("traefik", "dynamic.toml"), "toml"),
         ("envoy", ("envoy", "envoy.yaml"), "yaml"), ("istio", ("istio", "istio.yaml"), "yaml")]


def ferrum_src():
    candidates = [os.environ.get("FERRUM_EDGE_SRC"), os.path.join(ROOT, "..", "refs", "ferrum-edge")]
    for candidate in candidates:
        if candidate and os.path.isfile(os.path.join(candidate, "src", "config", "types.rs")):
            return os.path.abspath(candidate)
    return None


def struct_fields(source: str, name: str) -> set[str]:
    match = re.search(r"^pub struct " + re.escape(name) + r" \{\n(.*?)^\}", source, re.S | re.M)
    if not match:
        raise AssertionError(f"struct {name} not found")
    fields, skip = set(), False
    for line in match.group(1).splitlines():
        stripped = line.strip()
        if stripped.startswith("#[serde(") and re.search(r"\bskip\b(?!_)", stripped):
            skip = True
        field = re.match(r"pub (\w+):", stripped)
        if field:
            if not skip:
                fields.add(field.group(1))
            skip = False
    return fields


def outputs():
    for platform, parts, fmt in CASES:
        result, _report, plan = migrate(platform, read_fixture(*parts), fmt=fmt, include_secrets=False)
        yield platform, parts, result, plan


@unittest.skipUnless(ferrum_src(), "Ferrum Edge source not available (set FERRUM_EDGE_SRC)")
class FerrumSourceSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src = ferrum_src()
        with open(os.path.join(cls.src, "src", "config", "types.rs"), encoding="utf-8") as handle:
            cls.types = handle.read()

    def fields(self, name):
        return struct_fields(self.types, name)

    def test_reference_commit(self):
        head = os.path.join(self.src, ".git", "refs", "heads", "main")
        if not os.path.isfile(head):
            self.skipTest("checkout has no refs/heads/main")
        with open(head, encoding="utf-8") as handle:
            self.assertEqual(handle.read().strip(), FERRUM_EDGE_REFERENCE_COMMIT)

    def test_emitted_keys_are_accepted_struct_fields(self):
        top = self.fields("GatewayConfig") | {"resource_counts"}
        proxy, consumer = self.fields("Proxy"), self.fields("Consumer")
        upstream, plugin_config = self.fields("Upstream"), self.fields("PluginConfig")
        target, retry = self.fields("UpstreamTarget"), self.fields("RetryConfig")
        active, passive = self.fields("ActiveHealthCheck"), self.fields("PassiveHealthCheck")
        cookie, health = self.fields("HashOnCookieConfig"), self.fields("HealthCheckConfig")
        for platform, parts, result, _plan in outputs():
            config = result.config
            with self.subTest(fixture="/".join(parts)):
                self.assertLessEqual(set(config), top)
                for item in config["proxies"]:
                    self.assertLessEqual(set(item), proxy, item["id"])
                    self.assertLessEqual(set(item.get("retry", {})), retry)
                for item in config["consumers"]:
                    self.assertLessEqual(set(item), consumer)
                for item in config["plugin_configs"]:
                    self.assertLessEqual(set(item), plugin_config)
                for item in config["upstreams"]:
                    self.assertLessEqual(set(item), upstream, item["id"])
                    for t in item["targets"]:
                        self.assertLessEqual(set(t), target)
                    checks = item.get("health_checks", {})
                    self.assertLessEqual(set(checks), health)
                    self.assertLessEqual(set(checks.get("active", {})), active)
                    self.assertLessEqual(set(checks.get("passive", {})), passive)
                    self.assertLessEqual(set(item.get("hash_on_cookie_config", {})), cookie)

    def test_plugin_config_keys_appear_in_plugin_source(self):
        cache = {}
        for _platform, parts, result, _plan in outputs():
            for item in result.config["plugin_configs"]:
                name = item["plugin_name"]
                if name not in cache:
                    with open(os.path.join(self.src, "src", "plugins", f"{name}.rs"), encoding="utf-8") as handle:
                        cache[name] = set(re.findall(r'"([a-z][a-z0-9_]*)"', handle.read()))
                keys = set(item["config"])
                for rule in item["config"].get("rules", []):
                    keys |= set(rule) | {rule["operation"], rule["target"]}
                for limit in item["config"].get("limits", []):
                    keys |= set(limit)
                keys |= set(item["config"].get("trigger", {}))
                with self.subTest(fixture="/".join(parts), plugin=name):
                    self.assertLessEqual(keys, cache[name] | {"header"})

    def test_settings_are_in_public_inventory(self):
        with open(os.path.join(self.src, "src", "config", "public_env_inventory.rs"), encoding="utf-8") as handle:
            inventory = set(re.findall(r'"(FERRUM_[A-Z0-9_]+)"', handle.read()))
        self.assertLessEqual(KNOWN_SETTINGS, inventory)
        for platform, _parts, result, plan in outputs():
            for mode in ("file", "database", "cp", "dp"):
                text = render(mode, platform, plan.settings, result.tls_only, result.basic_auth_used, "resources.yaml")
                for line in text.splitlines():
                    if line and not line.startswith("#"):
                        self.assertIn(line.split("=", 1)[0], inventory)


TLS_FILE_FIELDS = {
    "backend_tls_server_ca_cert_path": "cert",
    "backend_tls_client_cert_path": "cert",
    "backend_tls_client_key_path": "key",
}


def operator_tls_files(config: dict) -> list[tuple[str, str, str]]:
    """``(kind, id, field)`` for every operator-supplied backend TLS file the output names."""
    found = []
    for kind in ("proxies", "upstreams"):
        for item in config.get(kind, []):
            for field in TLS_FILE_FIELDS:
                if item.get(field):
                    found.append((kind, item["id"], field))
    return found


def make_synthetic_ca(directory: str) -> dict | None:
    """Throwaway self-signed CA (cert + key) inside ``directory``; None without openssl.

    The key never leaves the temp directory, is valid for two days and protects nothing.
    """
    openssl = shutil.which("openssl")
    if not openssl:
        return None
    cert = os.path.join(directory, "synthetic-test-ca.pem")
    key = os.path.join(directory, "synthetic-test-ca.key")
    base = [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
            "-days", "2", "-subj", "/CN=ferrum-migration synthetic test CA"]
    extensions = ["-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]
    env = {"PATH": os.environ.get("PATH", ""), "HOME": directory, "RANDFILE": os.path.join(directory, ".rnd")}
    for argv in (base + extensions, base):  # older/LibreSSL builds may lack -addext
        completed = subprocess.run(argv, cwd=directory, env=env, capture_output=True, timeout=120, check=False)
        if completed.returncode == 0 and os.path.isfile(cert) and os.path.isfile(key):
            return {"cert": cert, "key": key}
    return None


def with_synthetic_tls_files(config: dict, files: dict) -> dict:
    """Copy of ``config`` whose backend TLS file fields point at the synthetic files."""
    patched = copy.deepcopy(config)
    for kind in ("proxies", "upstreams"):
        for item in patched.get(kind, []):
            for field, role in TLS_FILE_FIELDS.items():
                if item.get(field):
                    item[field] = files[role]
    return patched


@unittest.skipUnless(os.environ.get("FERRUM_EDGE_BIN"), "set FERRUM_EDGE_BIN to a ferrum-edge binary")
class FerrumBinaryValidateTest(unittest.TestCase):
    def validate(self, binary: str, directory: str, config: dict, basic_auth: bool):
        path = os.path.join(directory, "resources.yaml")
        with open(path, "w", encoding="utf-8") as handle:
            yaml.safe_dump(config, handle, sort_keys=False)
        env = {"PATH": os.environ.get("PATH", ""), "HOME": directory}
        if basic_auth:
            env["FERRUM_BASIC_AUTH_HMAC_SECRET"] = secrets.token_hex(32)
        return subprocess.run([binary, "validate", "-m", "file", "-c", path], cwd=directory, env=env,
                              capture_output=True, text=True, timeout=300, check=False)

    def test_fixture_outputs_pass_ferrum_validate(self):
        binary = os.environ["FERRUM_EDGE_BIN"]
        for _platform, parts, result, _plan in outputs():
            with self.subTest(fixture="/".join(parts)), tempfile.TemporaryDirectory() as directory:
                config = result.config
                if operator_tls_files(config):
                    files = make_synthetic_ca(directory)
                    if files is None:
                        self.skipTest("fixture names operator-supplied backend TLS files; openssl is needed to "
                                      "create a synthetic CA for admission testing")
                    config = with_synthetic_tls_files(config, files)
                completed = self.validate(binary, directory, config, result.basic_auth_used)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("Validation passed", completed.stdout)

    def test_repeated_source_names_pass_ferrum_validate(self):
        """Admission regression: one route and one host scope projected twice must not repeat proxy names.

        A normal synthetic Istio VirtualService bound through a plaintext and an HTTPS server with disjoint hosts
        yields two direct-response proxies and two closures from the same source names (Ferrum v0.9.21 admits
        neither duplicate proxy names nor duplicate ids). A plain emitter case with names that collide after
        truncation or case folding is validated too. No traffic is sent.
        """
        binary = os.environ["FERRUM_EDGE_BIN"]
        istio = (
            "apiVersion: networking.istio.io/v1\nkind: Gateway\nmetadata: {name: gw, namespace: default}\nspec:\n"
            "  servers:\n"
            "    - port: {number: 80, name: http, protocol: HTTP}\n      hosts: [a.example.test]\n"
            "    - port: {number: 443, name: https, protocol: HTTPS}\n      hosts: [b.example.test]\n"
            "      tls: {mode: SIMPLE, serverCertificate: /etc/synthetic/server.crt, "
            "privateKey: /etc/synthetic/server.key}\n"
            "---\napiVersion: networking.istio.io/v1\nkind: VirtualService\n"
            "metadata: {name: app, namespace: default}\nspec:\n  hosts: [a.example.test, b.example.test]\n"
            "  gateways: [gw]\n  http:\n    - name: maintenance\n      match: [{uri: {exact: /maintenance}}]\n"
            "      directResponse: {status: 503, body: {string: maintenance}}\n")
        kong = (
            "_format_version: \"3.0\"\nservices:\n  - name: s\n    url: http://s.internal:8080\n    routes:\n"
            + "".join(f"      - {{name: {name}, paths: [/r{index}/]}}\n"
                      for index, name in enumerate(["Api", "api", "x" * 300 + "a", "x" * 300 + "b"])))
        for platform, text, tls_only in (("istio", istio, False), ("istio", istio, True), ("kong", kong, False)):
            result, _report, _plan = migrate(platform, text, tls_only=tls_only)
            names = [proxy["name"] for proxy in result.config["proxies"]]
            with self.subTest(platform=platform, tls_only=tls_only), tempfile.TemporaryDirectory() as directory:
                self.assertEqual(len(names), len(set(names)))
                completed = self.validate(binary, directory, result.config, result.basic_auth_used)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("Validation passed", completed.stdout)

    def test_missing_operator_ca_is_rejected_not_ignored(self):
        """Evidence that the operator-CA reference is real: Ferrum refuses it while the file is absent."""
        binary = os.environ["FERRUM_EDGE_BIN"]
        result, _report, _plan = migrate("istio", read_fixture("istio", "istio.yaml"))
        self.assertTrue(operator_tls_files(result.config))
        with tempfile.TemporaryDirectory() as directory:
            for item in result.config["upstreams"]:
                path = item.get("backend_tls_server_ca_cert_path")
                if path and os.path.exists(path):
                    self.skipTest("the operator CA path exists on this machine; the negative check needs it absent")
            completed = self.validate(binary, directory, result.config, result.basic_auth_used)
            self.assertNotEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
