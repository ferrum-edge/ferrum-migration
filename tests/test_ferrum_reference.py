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
    # The synthetic Traefik fixtures stand for deployments whose every effective routing, TLS and access control is in
    # the input (no static entryPoint controls, no TLS options outside it, no competing routers), so they are converted
    # with the operator's statement (as with --assert-traefik-input-includes-effective-controls); the default refusal
    # output is admitted separately (test_traefik_default_refusal_passes_ferrum_validate), and so are the TLS options
    # scope and sniStrict refusals (test_traefik_tls_option_refusals_pass_ferrum_validate).
    for platform, parts, fmt in CASES:
        result, _report, plan = migrate(platform, read_fixture(*parts), fmt=fmt, include_secrets=False,
                                        traefik_controls_asserted=platform == "traefik")
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

    def test_frontend_scope_outputs_pass_ferrum_validate(self):
        """Admission regression: mixed main plaintext/HTTPS plans, refused or kept, load in Ferrum.

        Synthetic NGINX and Envoy inputs where a plaintext-only scope overlaps an HTTPS scope (both refused as
        fail-closed placeholders), plus an NGINX plan whose HTTPS scope sits behind a redirect (kept). Only the
        resources are validated; no client CA or certificate file is needed and no traffic is sent.
        """
        from test_envoy import two_listener_bootstrap

        binary = os.environ["FERRUM_EDGE_BIN"]
        default = ("server { listen 80 default_server; listen 443 ssl default_server; "
                   "ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key; "
                   "return 444; }\n")
        secure = ("server { listen 443 ssl; server_name app.example.test; "
                  "ssl_certificate /etc/synthetic/server.crt; ssl_certificate_key /etc/synthetic/server.key; "
                  "ssl_client_certificate /etc/synthetic/client-ca.pem; ssl_verify_client on; "
                  "location /secure/ { proxy_pass http://secure.internal:8080; } }\n")
        plain = ("server { listen 80; server_name app.example.test; "
                 "location /plain/ { proxy_pass http://plain.internal:8080; } }\n")
        redirect = "server { listen 80; server_name app.example.test; return 301 https://$host$request_uri; }\n"
        envoy = yaml.safe_dump(two_listener_bootstrap(("app.example.test",), ("app.example.test",),
                                                      client_ca="/etc/synthetic/client-ca.pem"))
        cases = (("nginx", default + plain + secure, "nginx", False), ("nginx", default + plain + secure, "nginx", True),
                 ("nginx", default + redirect + secure, "nginx", True), ("envoy", envoy, "yaml", False))
        for index, (platform, text, fmt, tls_only) in enumerate(cases):
            result, _report, _plan = migrate(platform, text, fmt=fmt, tls_only=tls_only)
            with self.subTest(case=index, platform=platform, tls_only=tls_only), \
                    tempfile.TemporaryDirectory() as directory:
                completed = self.validate(binary, directory, result.config, result.basic_auth_used)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("Validation passed", completed.stdout)

    def test_traefik_default_refusal_passes_ferrum_validate(self):
        """Admission regression: without the input-controls statement the Traefik fixtures become placeholders only.

        Benign synthetic fixtures, converted with the default (no operator statement): every forwarding router is a
        fail-closed 503 placeholder. Only the resources are validated; no traffic is sent.
        """
        binary = os.environ["FERRUM_EDGE_BIN"]
        for parts, fmt in ((("traefik", "dynamic.yaml"), "yaml"), (("traefik", "dynamic.toml"), "toml")):
            result, report, _plan = migrate("traefik", read_fixture(*parts), fmt=fmt)
            with self.subTest(fixture="/".join(parts)), tempfile.TemporaryDirectory() as directory:
                self.assertIn("traefik-controls-unverified", {c.code for c in report.caveats})
                self.assertFalse([p for p in result.config["proxies"]
                                  if p["labels"].get("ferrum-migration/status") == "migrated"])
                completed = self.validate(binary, directory, result.config, result.basic_auth_used)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("Validation passed", completed.stdout)

    def test_traefik_tls_option_refusals_pass_ferrum_validate(self):
        """Admission regression: Traefik handshake-policy refusals under the operator statement load as placeholders.

        Ordinary synthetic HTTPS routers are converted with the statement: under named TLS options (outside the one
        global 'default' policy, traefik-tls-options-scope), under a provider-qualified 'default@file' reference
        (not the unqualified global default, traefik-tls-options-scope) and under 'default' options that enable
        sniStrict (traefik-sni-strict). Each becomes a fail-closed 503 placeholder. Only the resources are validated;
        no traffic is sent.
        """
        binary = os.environ["FERRUM_EDGE_BIN"]
        service = {"s": {"loadBalancer": {"servers": [{"url": "http://s.internal:80"}]}}}
        router = {"rule": "Host(`t.example.test`) && Path(`/t`)", "service": "s"}
        cases = {"named": ({**router, "tls": {"options": "relaxed"}}, {"relaxed": {"minVersion": "VersionTLS12"}},
                           "traefik-tls-options-scope"),
                 "qualified default": ({**router, "tls": {"options": "default@file"}},
                                       {"default": {"minVersion": "VersionTLS12"}}, "traefik-tls-options-scope"),
                 "default": ({**router, "tls": {}}, {"default": {"sniStrict": True}}, "traefik-sni-strict")}
        for label, (spec, options, code) in cases.items():
            text = yaml.safe_dump({"http": {"routers": {"r": spec}, "services": service}, "tls": {"options": options}})
            result, report, _plan = migrate("traefik", text, traefik_controls_asserted=True)
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                self.assertIn(code, {c.code for c in report.caveats})
                self.assertFalse([p for p in result.config["proxies"]
                                  if p["labels"].get("ferrum-migration/status") == "migrated"])
                completed = self.validate(binary, directory, result.config, result.basic_auth_used)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("Validation passed", completed.stdout)

    def test_over_100_hosts_and_chunked_conflicts_pass_ferrum_validate(self):
        """Admission regression: source-generated >100-host closures and wildcard/host-only chunks pass ferrum-edge validate."""
        from ferrum_migration.ferrum import EmitOptions, emit
        from ferrum_migration.model import BackendRef, HostScope, Plan, RouteSpec
        from ferrum_migration.report import Report

        binary = os.environ["FERRUM_EDGE_BIN"]
        # Real NGINX source with 105 server_names + default server (exercises >100-host closure + chunked placeholders).
        names = " ".join(f"h{i}.example.test" for i in range(105))
        nginx_conf = (
            f"server {{ listen 80; server_name {names}; location /api/ {{ proxy_pass http://a.internal:80; }} }}\n"
            "server { listen 80 default_server; location / { proxy_pass http://b.internal:80; } }\n"
        )
        nginx_res, _nginx_rep, _ = migrate("nginx", nginx_conf, fmt="nginx")
        with tempfile.TemporaryDirectory() as directory:
            completed = self.validate(binary, directory, nginx_res.config, nginx_res.basic_auth_used)
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("Validation passed", completed.stdout)

        # Synthetic wildcard conflict merge + host-only conflict merge (>100 hosts) + HostScope.
        w1 = RouteSpec(ref="w1", name="w1", hosts=["*.example.test"] + [f"a{i}.other.test" for i in range(60)],
                       kind="prefix", path="/api", protocols=frozenset({"http"}),
                       backend=BackendRef("http", "a.internal", 80))
        w2 = RouteSpec(ref="w2", name="w2", hosts=["*.sub.example.test"] + [f"b{i}.other.test" for i in range(60)],
                       kind="prefix", path="/api", protocols=frozenset({"http"}),
                       backend=BackendRef("http", "b.internal", 80))
        ho1 = RouteSpec(ref="ho1", name="ho1", hosts=["*.ho.test"] + [f"c{i}.ho.test" for i in range(60)],
                        kind="hostonly", path=None, protocols=frozenset({"http"}),
                        backend=BackendRef("http", "c.internal", 80))
        ho2 = RouteSpec(ref="ho2", name="ho2", hosts=["exact.ho.test"] + [f"d{i}.ho.test" for i in range(60)],
                        kind="hostonly", path=None, protocols=frozenset({"http"}),
                        backend=BackendRef("http", "d.internal", 80))
        sib = RouteSpec(ref="sib", name="sib", hosts=["other.example.test"], kind="prefix", path="/api",
                        protocols=frozenset({"http"}), backend=BackendRef("http", "e.internal", 80))
        result = emit(Plan(platform="test", routes=[w1, w2, ho1, ho2, sib],
                           host_scopes=[HostScope("w1-scope", w1.hosts, None)]),
                      EmitOptions(), Report("test", "synthetic"))
        with tempfile.TemporaryDirectory() as directory:
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

    def test_extended_plugins_pass_ferrum_validate(self):
        """Admission regression: all newly mapped plugins and consumer labels pass real ferrum-edge validate."""
        binary = os.environ["FERRUM_EDGE_BIN"]
        kong_text = (
            '_format_version: "3.0"\n'
            "consumers:\n"
            "  - username: alice\n"
            "    tags: [tier-gold, team-api]\n"
            "services:\n"
            "  - name: s\n"
            "    url: http://s.internal:8080\n"
            "    routes:\n"
            "      - name: ok\n"
            "        paths: [/ok/]\n"
            "        plugins:\n"
            "          - name: correlation-id\n"
            "            config: {header_name: X-Trace-ID, echo_downstream: true}\n"
            "          - name: bot-detection\n"
            "            config: {allow: [Googlebot]}\n"
            "          - name: grpc-web\n"
            "            config: {}\n"
            "          - name: proxy-cache\n"
            "            config: {strategy: memory, request_method: [GET, HEAD], response_code: [200, 301], "
            "cache_ttl: 120, cache_control: true, vary_headers: [Accept-Encoding]}\n"
        )
        traefik_text = yaml.safe_dump({
            "http": {
                "routers": {"r": {"rule": "Host(`a.example.test`) && PathPrefix(`/api/`)", "service": "mirrored",
                                  "middlewares": ["comp", "gw", "buf"]}},
                "middlewares": {
                    "comp": {"compress": {"encodings": ["br", "gzip"], "minResponseBodyBytes": 1024,
                                          "includedContentTypes": ["application/json", "text/plain"]}},
                    "gw": {"grpcWeb": {}},
                    "buf": {"buffering": {"maxRequestBodyBytes": 1048576, "maxResponseBodyBytes": 2097152}},
                },
                "services": {
                    "mirrored": {"mirroring": {"service": "main", "mirrorBody": True, "maxBodySize": 65536,
                                               "mirrors": [{"name": "shadow", "percent": 20}]}},
                    "main": {"loadBalancer": {"servers": [{"url": "http://main.internal:8080"}]}},
                    "shadow": {"loadBalancer": {"servers": [{"url": "http://shadow.internal:9090"}]}},
                },
            }
        })
        istio_text = (
            "apiVersion: networking.istio.io/v1\nkind: Gateway\nmetadata: {name: gw, namespace: edge}\nspec:\n"
            "  selector: {istio: ingressgateway}\n"
            "  servers: [{port: {number: 80, name: http, protocol: HTTP}, hosts: [api.example.test]}]\n"
            "---\napiVersion: security.istio.io/v1\nkind: RequestAuthentication\n"
            "metadata: {name: jwt-policy, namespace: edge}\nspec:\n"
            "  selector: {matchLabels: {istio: ingressgateway}}\n"
            "  jwtRules:\n"
            "    - issuer: https://idp.example.test\n"
            "      jwksUri: https://idp.example.test/.well-known/jwks.json\n"
            "      audiences: [api]\n"
            "      fromHeaders: [{name: Authorization, prefix: 'Bearer '}]\n"
            "      forwardOriginalToken: true\n"
            "      outputClaimToHeaders: [{header: x-jwt-sub, claim: sub}]\n"
            "---\napiVersion: networking.istio.io/v1\nkind: VirtualService\n"
            "metadata: {name: vs, namespace: edge}\nspec:\n"
            "  hosts: [api.example.test]\n  gateways: [gw]\n  http:\n"
            "    - name: api\n      match: [{uri: {exact: /api}}]\n"
            "      route: [{destination: {host: svc.edge.svc.cluster.local, port: {number: 8080}}}]\n"
            "      fault:\n        delay: {fixedDelay: 250ms, percentage: {value: 15}}\n"
            "        abort: {httpStatus: 503, grpcStatus: UNAVAILABLE, percentage: {value: 5}}\n"
            "      mirror: {host: shadow.edge.svc.cluster.local, port: {number: 9090}}\n"
            "      mirrorPercentage: {value: 10}\n"
        )
        for label, platform, text, kw in (
            ("kong-extended", "kong", kong_text, {}),
            ("traefik-extended", "traefik", traefik_text, {"traefik_controls_asserted": True}),
            ("istio-extended", "istio", istio_text, {}),
        ):
            result, _report, _plan = migrate(platform, text, **kw)
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                completed = self.validate(binary, directory, result.config, result.basic_auth_used)
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
                self.assertIn("Validation passed", completed.stdout)


if __name__ == "__main__":
    unittest.main()
