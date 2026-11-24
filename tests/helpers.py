"""Shared test helpers. Tests run without installation: ``python -m unittest discover -s tests``."""

from __future__ import annotations

import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

from ferrum_migration.ferrum import EmitOptions, emit  # noqa: E402
from ferrum_migration.limits import Limits  # noqa: E402
from ferrum_migration.report import Report  # noqa: E402
from ferrum_migration.sources import SOURCES  # noqa: E402
from ferrum_migration.sources.common import SourceContext  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures")
ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def fixture_path(*parts: str) -> str:
    return os.path.join(FIXTURES, *parts)


def read_fixture(*parts: str) -> str:
    with open(fixture_path(*parts), encoding="utf-8") as handle:
        return handle.read()


def migrate(platform: str, text: str, fmt: str = "yaml", include_secrets: bool = False, tls_only: bool = False,
            limits: Limits | None = None):
    report = Report(platform, "test-input")
    context = SourceContext(report=report, limits=limits or Limits(), include_secrets=include_secrets)
    plan = SOURCES[platform].translate(text, fmt, context)
    result = emit(plan, EmitOptions(include_secrets=include_secrets, tls_only=tls_only), report)
    return result, report, plan


def proxies(config: dict, listen_path=..., host: str | None = None) -> list[dict]:
    found = []
    for proxy in config["proxies"]:
        if listen_path is not ... and proxy.get("listen_path") != listen_path:
            continue
        if host is not None and host not in proxy.get("hosts", []):
            continue
        found.append(proxy)
    return found


def one_proxy(test, config: dict, listen_path, host: str | None = None) -> dict:
    found = proxies(config, listen_path, host)
    test.assertEqual(len(found), 1, f"expected exactly one proxy for {listen_path!r} host={host!r}, got {found}")
    return found[0]


def plugins_of(config: dict, proxy: dict) -> list[dict]:
    ids = [ref["plugin_config_id"] for ref in proxy.get("plugins", [])]
    by_id = {plugin["id"]: plugin for plugin in config["plugin_configs"]}
    return [by_id[pid] for pid in ids]


def plugin(test, config: dict, proxy: dict, name: str) -> dict:
    matches = [p for p in plugins_of(config, proxy) if p["plugin_name"] == name]
    test.assertTrue(matches, f"plugin {name} not attached to {proxy['id']}")
    return matches[0]


def upstream_of(config: dict, proxy: dict) -> dict:
    return next(u for u in config["upstreams"] if u["id"] == proxy["upstream_id"])


def codes(report: Report, severity: str | None = None) -> set[str]:
    return {item.code for item in report.caveats if severity is None or item.severity == severity}


def assert_structurally_valid(test, config: dict) -> None:
    """Invariants Ferrum enforces at load time that the emitter must always satisfy."""
    test.assertEqual(config["version"], "1")
    counts = config["resource_counts"]
    for key in ("proxies", "consumers", "plugin_configs", "upstreams"):
        test.assertEqual(counts[key], len(config[key]), key)
    for kind in ("proxies", "consumers", "plugin_configs", "upstreams"):
        ids = [item["id"] for item in config[kind]]
        test.assertEqual(len(ids), len(set(ids)), f"duplicate ids in {kind}")
        for ident in ids:
            test.assertRegex(ident, ID_RE)
            test.assertLessEqual(len(ident), 254)
    plugin_ids = {p["id"] for p in config["plugin_configs"]}
    upstream_ids = {u["id"] for u in config["upstreams"]}
    proxy_ids = {p["id"] for p in config["proxies"]}
    slots = {}
    for proxy in config["proxies"]:
        test.assertTrue(proxy.get("hosts") or proxy.get("listen_path"), proxy["id"])
        for ref in proxy.get("plugins", []):
            test.assertIn(ref["plugin_config_id"], plugin_ids)
        if "upstream_id" in proxy:
            test.assertIn(proxy["upstream_id"], upstream_ids)
        else:
            test.assertTrue(proxy["backend_host"])
            test.assertGreater(proxy["backend_port"], 0)
        test.assertIn(proxy["backend_scheme"], ("http", "https"))
        key = (proxy.get("listen_port"), proxy.get("listen_path"))
        for host in proxy.get("hosts", []) or ["*any*"]:
            test.assertNotIn((key, host), slots, f"duplicate route slot {key} {host}")
            slots[(key, host)] = proxy["id"]
    for plugin_config in config["plugin_configs"]:
        if plugin_config["scope"] == "proxy":
            test.assertIn(plugin_config["proxy_id"], proxy_ids)
        else:
            test.assertNotIn("proxy_id", plugin_config)
    for consumer in config["consumers"]:
        test.assertTrue(consumer["username"])
