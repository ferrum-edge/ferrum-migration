"""Optional differential runs against the *source* product (nginx, traefik, envoy, kong).

Without this, each fixture's expectations are documented source semantics
(inferred). With a caller-provided upstream profile the same rendered fixture
is served by the real product on a harness-allocated loopback port and every
non-``ferrum_only`` probe is replayed, turning the expectation into runtime
evidence or exposing a wrong fixture.

The profile is JSON keyed by adapter. Each entry:

    {
      "argv":   ["nginx", "-p", "{workdir}", "-e", "{workdir}/nginx-error.log",
                 "-c", "{source}", "-g", "daemon off;"],
      "env":    {"KEY": "value with {tokens}"},
      "mkdirs": ["{workdir}/nginx-tmp"],
      "stop_argv": ["docker", "rm", "-f", "{container}"],
      "ready_timeout_seconds": 20
    }

Tokens: {source} {workdir} {listen_port} {container} {python}. Each argv element
is expanded on its own and executed without a shell.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from . import probe as http_probe
from .echo import PROBE_HEADER, EchoRecorder
from .procs import ManagedProcess, minimal_env, run_bounded, wait_for_tcp
from .util import TemplateError, expand_argv, expand_env, expand_optional_argv, scrub, tail

_ENTRY_KEYS = {"argv", "env", "mkdirs", "stop_argv", "ready_timeout_seconds", "description"}


@dataclass
class UpstreamEntry:
    argv: list[str]
    env: dict[str, str]
    mkdirs: list[str]
    stop_argv: list[str]
    ready_timeout: float


def load_upstream_profile(path: Path) -> dict[str, UpstreamEntry]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise TemplateError("upstream profile must be a JSON object keyed by adapter")
    entries: dict[str, UpstreamEntry] = {}
    for adapter, raw in data.items():
        if adapter.startswith("_"):
            continue
        if not isinstance(raw, dict) or set(raw) - _ENTRY_KEYS:
            raise TemplateError(f"upstream profile entry {adapter!r} is malformed")
        entries[adapter] = UpstreamEntry(
            argv=list(raw.get("argv") or []),
            env=dict(raw.get("env") or {}),
            mkdirs=list(raw.get("mkdirs") or []),
            stop_argv=list(raw.get("stop_argv") or []),
            ready_timeout=float(raw.get("ready_timeout_seconds", 20)),
        )
    return entries


def run_differential(
    entry: UpstreamEntry,
    case,
    source: Path,
    workdir: Path,
    listen_port: int,
    recorder: EchoRecorder,
    header_values: dict,
    sensitive: list[str],
    request_timeout: float,
    pass_env,
    render_headers,
) -> dict:
    """Serve the fixture with the source product and replay source-semantic probes."""
    container = "ferrum-acceptance-" + secrets.token_hex(6)
    values = {
        "source": str(source),
        "workdir": str(workdir),
        "listen_port": str(listen_port),
        "container": container,
        "python": sys.executable,
    }
    for item in entry.mkdirs:
        Path(expand_argv([item], values)[0]).mkdir(parents=True, exist_ok=True)
    argv = expand_argv(entry.argv, values)
    env = minimal_env(workdir, pass_env)
    env.update(expand_env(entry.env, values))
    logs = workdir / "logs"
    proc = ManagedProcess(
        "upstream", argv, workdir, env, logs / "upstream.stdout.log", logs / "upstream.stderr.log"
    )
    outcome: dict = {"ran": True, "probes": [], "ready": False}
    try:
        if not wait_for_tcp(listen_port, entry.ready_timeout, proc):
            outcome["error"] = "upstream product did not open its listener"
            return outcome
        source_probes = [p for p in case.probes if not p.ferrum_only]
        # Some products (traefik file provider) bind before routes load: wait
        # until the first positive probe stops answering 404, bounded.
        warm = next((p for p in source_probes if p.positive), None)
        if warm is not None:
            deadline = time.monotonic() + entry.ready_timeout
            while time.monotonic() < deadline:
                pid = f"warmup-{secrets.token_hex(4)}"
                headers = dict(render_headers(warm.headers, header_values))
                headers[PROBE_HEADER] = pid
                resp = http_probe.send(listen_port, warm.method, warm.path, warm.host, headers, request_timeout)
                if recorder.for_probe(pid):
                    break
                time.sleep(0.3)
        outcome["ready"] = True
        for p in source_probes:
            pid = f"{case.id}-{p.id}-upstream-{secrets.token_hex(4)}"
            headers = dict(render_headers(p.headers, header_values))
            headers[PROBE_HEADER] = pid
            resp = http_probe.send(listen_port, p.method, p.path, p.host, headers, request_timeout)
            records = recorder.for_probe(pid)
            entry_out = {"probe": p.id, "status": resp["status"], "transport_error": resp["error"]}
            if p.positive:
                ok = bool(records) and all(
                    r["backend"] == p.forward_backend and r["path"] == p.forward_path for r in records
                )
                entry_out["observed"] = [{"backend": r["backend"], "path": r["path"]} for r in records]
            else:
                # Status codes legitimately differ across products (e.g. Kong 404
                # vs Ferrum 405 for a method miss); the source-truth question is
                # only whether the request reached a backend.
                ok = not records
                entry_out["observed"] = [{"backend": r["backend"]} for r in records]
            entry_out["confirmed"] = ok
            outcome["probes"].append(entry_out)
        return outcome
    finally:
        proc.stop(grace_seconds=10.0)
        if entry.stop_argv:
            stop = expand_optional_argv(entry.stop_argv, values)
            run_bounded("upstream-stop", stop, workdir, env, logs, 30.0)
        stdout, stderr = proc.read_output()
        outcome["log_tail"] = tail(scrub(stderr + "\n" + stdout, sensitive))
