"""Child-process lifecycle, bounded execution, loopback port holds, clean envs.

Every child is started without a shell, with stdin closed and stdout/stderr
redirected to files (no unread pipe can block a chatty child). On POSIX each
child gets its own session so teardown can signal the whole process group
(nginx/kong spawn workers) while the leader is still unreaped, which avoids
signalling a recycled group id.
"""

from __future__ import annotations

import atexit
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Mapping, Sequence

_ACTIVE: "set[ManagedProcess]" = set()
_ACTIVE_LOCK = threading.Lock()

# Variables a child may inherit from the caller. Everything else is dropped so
# a developer shell's FERRUM_*, RUST_LOG, KONG_* or proxy settings cannot leak
# into the run.
BASE_ENV_KEEP = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "SYSTEMROOT", "WINDIR")


def minimal_env(workdir: Path, pass_env: Sequence[str] = ()) -> dict[str, str]:
    env = {key: os.environ[key] for key in BASE_ENV_KEEP if key in os.environ}
    for key in pass_env:
        if key in os.environ:
            env[key] = os.environ[key]
    home = workdir / "home"
    tmp = workdir / "tmp"
    home.mkdir(parents=True, exist_ok=True)
    tmp.mkdir(parents=True, exist_ok=True)
    env["HOME"] = str(home)
    env["TMPDIR"] = str(tmp)
    return env


class ManagedProcess:
    def __init__(
        self,
        name: str,
        argv: Sequence[str],
        cwd: Path,
        env: Mapping[str, str],
        stdout_path: Path,
        stderr_path: Path,
    ) -> None:
        self.name = name
        self.argv = list(argv)
        self.stdout_path = stdout_path
        self.stderr_path = stderr_path
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        self._out = open(stdout_path, "wb")
        self._err = open(stderr_path, "wb")
        kwargs: dict = {}
        if os.name == "posix":
            kwargs["start_new_session"] = True
        else:  # pragma: no cover - Windows is not a supported runtime target
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            self.proc = subprocess.Popen(
                self.argv,
                cwd=str(cwd),
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=self._out,
                stderr=self._err,
                shell=False,
                close_fds=True,
                **kwargs,
            )
        except BaseException:
            self._out.close()
            self._err.close()
            raise
        with _ACTIVE_LOCK:
            _ACTIVE.add(self)

    @property
    def pid(self) -> int:
        return self.proc.pid

    def poll(self) -> "int | None":
        return self.proc.poll()

    def alive(self) -> bool:
        return self.proc.poll() is None

    def wait(self, timeout: float) -> "int | None":
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def _signal_group(self, sig: int) -> None:
        if os.name == "posix":
            try:
                os.killpg(self.proc.pid, sig)
                return
            except (ProcessLookupError, PermissionError, OSError):
                pass
        try:
            if sig == getattr(signal, "SIGKILL", None):
                self.proc.kill()
            else:
                self.proc.terminate()
        except OSError:
            pass

    def stop(self, grace_seconds: float = 10.0) -> "int | None":
        """SIGTERM the group, wait, then SIGKILL the group. Idempotent."""
        try:
            if self.proc.poll() is None:
                self._signal_group(signal.SIGTERM)
                if self.wait(grace_seconds) is None:
                    self._signal_group(getattr(signal, "SIGKILL", signal.SIGTERM))
                    self.wait(5.0)
            return self.proc.poll()
        finally:
            for handle in (self._out, self._err):
                try:
                    handle.close()
                except OSError:
                    pass
            with _ACTIVE_LOCK:
                _ACTIVE.discard(self)

    def read_output(self, max_bytes: int = 2_000_000) -> tuple[str, str]:
        def read(path: Path) -> str:
            try:
                with open(path, "rb") as handle:
                    data = handle.read(max_bytes)
                return data.decode("utf-8", errors="replace")
            except OSError:
                return ""

        return read(self.stdout_path), read(self.stderr_path)


def stop_all_active() -> None:
    with _ACTIVE_LOCK:
        active = list(_ACTIVE)
    for proc in active:
        proc.stop(grace_seconds=3.0)


atexit.register(stop_all_active)


def install_signal_cleanup() -> None:
    """Turn SIGTERM/SIGHUP into SystemExit so ``finally`` blocks and atexit run."""

    def handler(signum, _frame):  # noqa: ANN001
        raise SystemExit(128 + signum)

    for name in ("SIGTERM", "SIGHUP"):
        sig = getattr(signal, name, None)
        if sig is not None:
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):
                pass


class BoundedResult:
    def __init__(self, returncode: "int | None", timed_out: bool, stdout: str, stderr: str, seconds: float):
        self.returncode = returncode
        self.timed_out = timed_out
        self.stdout = stdout
        self.stderr = stderr
        self.seconds = seconds


def run_bounded(
    name: str,
    argv: Sequence[str],
    cwd: Path,
    env: Mapping[str, str],
    logs_dir: Path,
    timeout_seconds: float,
) -> BoundedResult:
    started = time.monotonic()
    proc = ManagedProcess(
        name, argv, cwd, env, logs_dir / f"{name}.stdout.log", logs_dir / f"{name}.stderr.log"
    )
    code = proc.wait(timeout_seconds)
    timed_out = code is None
    proc.stop(grace_seconds=3.0)
    stdout, stderr = proc.read_output()
    return BoundedResult(proc.poll(), timed_out, stdout, stderr, time.monotonic() - started)


class PortHold:
    """Hold an OS-assigned loopback TCP port until it is handed to a child.

    The socket stays bound (and listening, without SO_REUSEADDR) so no other
    local process can claim the number while configs are being rendered;
    ``release()`` is called immediately before the child that binds it starts.
    """

    def __init__(self, host: str = "127.0.0.1") -> None:
        self._sock: "socket.socket | None" = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self._sock.bind((host, 0))
            self._sock.listen(1)
        except OSError:
            self._sock.close()
            raise
        self.port: int = self._sock.getsockname()[1]

    def release(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


def wait_for_tcp(port: int, timeout_seconds: float, proc: "ManagedProcess | None" = None) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if proc is not None and not proc.alive():
            return False
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.2)
    return False
