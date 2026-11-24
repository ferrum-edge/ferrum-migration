"""Drive the Ferrum Edge v0.9.21 CLI: ``version``, ``validate`` and file-mode ``run``.

Runtime contract (verified by reading ferrum-edge @ c1d73c35, Cargo version 0.9.21):

* ``ferrum-edge version --json`` prints ``{"version":"…","target":"…"}``
  (src/cli.rs ``execute_version``).
* ``ferrum-edge validate -m file -c SPEC [-s SETTINGS]`` exits 0 on success and
  1 on failure, binds no sockets (docs/cli.md "validate").
* ``ferrum-edge run -m file -c SPEC`` serves; CLI flags become env vars
  before config is read (src/cli.rs ``apply_run_overrides``).
* Defaults: proxy HTTP 8000 on 0.0.0.0, proxy HTTPS 8443, admin HTTP 9000 and
  admin HTTPS 9443 on 127.0.0.1; port 0 disables a listener
  (docs/configuration.md "Proxy Listener"/"Admin API"). The harness therefore
  pins every one of them explicitly.
* Readiness: ``GET /health`` with ``Authorization: Bearer
  $FERRUM_METRICS_BEARER_TOKEN`` returns the detail tier (contains
  ``cached_config``) and ``ready: true`` only after every listener is bound;
  ``GET /proxies`` with an admin JWT proves this child owns the admin port
  (tests/common/gateway_harness.rs).
"""

from __future__ import annotations

import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from . import probe
from .procs import ManagedProcess, PortHold, minimal_env, run_bounded
from .util import mint_hs256_jwt, scrub, tail

EXPECTED_FERRUM_VERSION = "0.9.21"
_ADDR_IN_USE_MARKERS = ("address already in use", "addrinuse", "address in use", "os error 48", "os error 98")


@dataclass
class FerrumOptions:
    argv_prefix: list[str]
    expected_version: str = EXPECTED_FERRUM_VERSION
    startup_timeout: float = 45.0
    validate_timeout: float = 90.0
    request_timeout: float = 10.0
    pass_env: Sequence[str] = field(default_factory=tuple)


class FerrumStartupError(RuntimeError):
    def __init__(self, message: str, addr_in_use: bool, output_tail: str) -> None:
        super().__init__(message)
        self.addr_in_use = addr_in_use
        self.output_tail = output_tail


def check_version(opts: FerrumOptions, workdir: Path) -> dict:
    workdir.mkdir(parents=True, exist_ok=True)
    result = run_bounded(
        "ferrum-version",
        opts.argv_prefix + ["version", "--json"],
        workdir,
        minimal_env(workdir, opts.pass_env),
        workdir / "logs",
        30.0,
    )
    info = {"ok": False, "version": None, "target": None, "returncode": result.returncode}
    if result.timed_out:
        info["error"] = "ferrum-edge version timed out"
        return info
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            info["version"] = parsed.get("version")
            info["target"] = parsed.get("target")
            break
    info["ok"] = info["version"] == opts.expected_version
    if info["version"] is None:
        info["error"] = "could not parse `version --json` output"
    return info


class GatewayIdentity:
    """Per-instance synthetic secrets (never real secrets, never printed, scrubbed from logs).

    ``basic_auth_hmac_secret`` exists because Ferrum's basic_auth plugin refuses
    to construct without ``FERRUM_BASIC_AUTH_HMAC_SECRET`` (>= 32 bytes,
    src/plugins/basic_auth.rs). Converted basic-auth routes carry no
    credentials, so this secret makes the fail-closed plugin loadable without
    granting anyone access.
    """

    def __init__(self) -> None:
        self.metrics_token = "acceptance-probe-" + secrets.token_hex(24)
        self.jwt_secret = "acceptance-admin-" + secrets.token_hex(24)
        self.jwt_issuer = "ferrum-acceptance-" + secrets.token_hex(6)
        self.basic_auth_hmac_secret = secrets.token_hex(32)

    def sensitive(self) -> list[str]:
        return [self.metrics_token, self.jwt_secret, self.basic_auth_hmac_secret]


def ferrum_env(
    opts: FerrumOptions,
    workdir: Path,
    proxy_port: int,
    admin_port: int,
    identity: GatewayIdentity,
) -> dict[str, str]:
    env = minimal_env(workdir, opts.pass_env)
    env.update(
        {
            "FERRUM_PROXY_HTTP_PORT": str(proxy_port),
            "FERRUM_ADMIN_HTTP_PORT": str(admin_port),
            "FERRUM_PROXY_HTTPS_PORT": "0",
            "FERRUM_ADMIN_HTTPS_PORT": "0",
            "FERRUM_PROXY_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_ADMIN_BIND_ADDRESS": "127.0.0.1",
            "FERRUM_ACCEPT_THREADS": "1",
            "FERRUM_POOL_WARMUP_ENABLED": "false",
            "FERRUM_SHUTDOWN_DRAIN_SECONDS": "0",
            "FERRUM_TLS_MANAGED_STORE_PATH": str(workdir / "managed-tls"),
            "FERRUM_METRICS_BEARER_TOKEN": identity.metrics_token,
            "FERRUM_ADMIN_JWT_SECRET": identity.jwt_secret,
            "FERRUM_ADMIN_JWT_ISSUER": identity.jwt_issuer,
            "FERRUM_BASIC_AUTH_HMAC_SECRET": identity.basic_auth_hmac_secret,
            "FERRUM_LOG_LEVEL": "info",
            "RUST_LOG": "info",
        }
    )
    return env


def validate(
    opts: FerrumOptions,
    mode: str,
    spec: Path,
    settings: "Path | None",
    workdir: Path,
    log_name: str,
    extra_env: "dict[str, str] | None" = None,
) -> dict:
    """Run ``ferrum-edge validate``. Listener env is pinned so settings cannot widen binds."""
    cwd = workdir / "ferrum-cwd"
    cwd.mkdir(parents=True, exist_ok=True)
    identity = GatewayIdentity()
    # validate binds nothing (docs/cli.md), but give it the same non-zero
    # loopback listener shape `run` uses so both see identical settings.
    proxy_hold, admin_hold = PortHold(), PortHold()
    env = ferrum_env(opts, workdir, proxy_hold.port, admin_hold.port, identity)
    proxy_hold.release()
    admin_hold.release()
    if extra_env:
        env.update(extra_env)
    argv = opts.argv_prefix + ["validate", "-m", mode, "-c", str(spec)]
    if settings is not None:
        argv += ["-s", str(settings)]
    result = run_bounded(log_name, argv, cwd, env, workdir / "logs", opts.validate_timeout)
    combined = result.stderr + "\n" + result.stdout
    return {
        "ok": (not result.timed_out) and result.returncode == 0,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "output_tail": tail(scrub(combined, identity.sensitive())),
        "used_settings": settings is not None,
    }


@dataclass
class RunningGateway:
    proc: ManagedProcess
    proxy_port: int
    admin_port: int
    identity: GatewayIdentity
    proxies_loaded: "int | None"

    def stop(self) -> None:
        self.proc.stop(grace_seconds=10.0)

    def output_tail(self, extra_sensitive: Sequence[str] = ()) -> str:
        stdout, stderr = self.proc.read_output()
        return tail(scrub(stderr + "\n" + stdout, list(self.identity.sensitive()) + list(extra_sensitive)))


def _count_proxies(payload: object) -> "int | None":
    if isinstance(payload, list):
        return len(payload)
    if isinstance(payload, dict):
        for key in ("data", "proxies", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return len(value)
    return None


def start_gateway(
    opts: FerrumOptions,
    spec: Path,
    settings: "Path | None",
    workdir: Path,
    attempts: int = 3,
) -> RunningGateway:
    """Start file-mode Ferrum on fresh loopback ports; retry only on address-in-use."""
    last_error: "FerrumStartupError | None" = None
    for attempt in range(1, attempts + 1):
        proxy_hold, admin_hold = PortHold(), PortHold()
        identity = GatewayIdentity()
        env = ferrum_env(opts, workdir, proxy_hold.port, admin_hold.port, identity)
        cwd = workdir / "ferrum-cwd"
        cwd.mkdir(parents=True, exist_ok=True)
        argv = opts.argv_prefix + ["run", "-m", "file", "-c", str(spec)]
        if settings is not None:
            argv += ["-s", str(settings)]
        logs = workdir / "logs"
        proxy_port, admin_port = proxy_hold.port, admin_hold.port
        proxy_hold.release()
        admin_hold.release()
        proc = ManagedProcess(
            f"ferrum-run-{attempt}",
            argv,
            cwd,
            env,
            logs / f"ferrum-run-{attempt}.stdout.log",
            logs / f"ferrum-run-{attempt}.stderr.log",
        )
        try:
            loaded = _wait_ready(proc, admin_port, identity, opts.startup_timeout)
            return RunningGateway(proc, proxy_port, admin_port, identity, loaded)
        except FerrumStartupError as exc:
            proc.stop(grace_seconds=3.0)
            last_error = exc
            if exc.addr_in_use and attempt < attempts:
                continue
            raise
    assert last_error is not None
    raise last_error


def _wait_ready(proc: ManagedProcess, admin_port: int, identity: GatewayIdentity, timeout: float) -> "int | None":
    deadline = time.monotonic() + timeout
    observation = "no response yet"
    while time.monotonic() < deadline:
        if not proc.alive():
            stdout, stderr = proc.read_output()
            combined = scrub(stderr + "\n" + stdout, identity.sensitive())
            lowered = combined.lower()
            raise FerrumStartupError(
                f"ferrum-edge exited with {proc.poll()} before becoming ready",
                any(marker in lowered for marker in _ADDR_IN_USE_MARKERS),
                tail(combined),
            )
        status, payload = probe.get_json(admin_port, "/health", identity.metrics_token)
        if status is not None and isinstance(payload, dict):
            if "cached_config" not in payload:
                observation = "health answered without detail tier (not this instance's credential)"
            elif status == 200 and payload.get("ready") is True:
                jwt = mint_hs256_jwt(identity.jwt_secret, identity.jwt_issuer)
                p_status, p_payload = probe.get_json(admin_port, "/proxies", jwt)
                if p_status == 200 and proc.alive():
                    return _count_proxies(p_payload)
                observation = f"/proxies ownership probe returned {p_status}"
            else:
                observation = f"health status {status}, not ready"
        time.sleep(0.25)
    stdout, stderr = proc.read_output()
    raise FerrumStartupError(
        f"ferrum-edge did not become ready within {timeout:.0f}s ({observation})",
        False,
        tail(scrub(stderr + "\n" + stdout, identity.sensitive())),
    )
