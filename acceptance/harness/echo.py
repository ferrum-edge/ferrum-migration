"""Loopback echo backends that record which probe reached which backend.

The record is the evidence for every routing assertion: a probe counts as
"forwarded" only if a backend actually received a request carrying its probe
id, and as "denied" only if no backend did. Header *values* other than the
probe id are never stored, so synthetic credentials do not end up in results.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler

from .loopback import LoopbackThreadingHTTPServer

PROBE_HEADER = "X-Acceptance-Probe"
_MAX_BODY = 1_048_576


class EchoRecorder:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._records: list[dict] = []

    def add(self, record: dict) -> None:
        with self._lock:
            self._records.append(record)

    def for_probe(self, probe_id: str) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._records if r.get("probe") == probe_id]

    def all(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._records]


def _make_handler(tag: str, recorder: EchoRecorder):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "acceptance-echo"
        sys_version = ""

        def _handle(self) -> None:
            length = self.headers.get("Content-Length")
            remaining = 0
            if length is not None:
                try:
                    remaining = max(0, min(int(length), _MAX_BODY))
                except ValueError:
                    remaining = 0
            if remaining:
                self.rfile.read(remaining)
            record = {
                "backend": tag,
                "method": self.command,
                "path": self.path,
                "host": self.headers.get("Host"),
                "probe": self.headers.get(PROBE_HEADER),
                "header_names": sorted({name.lower() for name in self.headers.keys()}),
            }
            recorder.add(record)
            body = json.dumps(
                {"backend": tag, "method": self.command, "path": self.path, "probe": record["probe"]}
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_HEAD = _handle

        def log_message(self, format, *args):  # noqa: A002 - stdlib signature
            return

    return Handler


class EchoBackend:
    """One loopback HTTP/1.1 echo server bound to 127.0.0.1 on an OS-assigned port.

    The listener is bound in the constructor and held for the backend's whole
    lifetime, so there is no bind-drop-rebind race with the configs that name it.
    The server never reverse-resolves its address (see ``harness.loopback``).
    """

    def __init__(self, tag: str, recorder: EchoRecorder) -> None:
        self.tag = tag
        self.server = LoopbackThreadingHTTPServer(("127.0.0.1", 0), _make_handler(tag, recorder))
        self.server.daemon_threads = True
        self.port: int = self.server.server_address[1]
        self._thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True
        )

    def start(self) -> "EchoBackend":
        self._thread.start()
        return self

    def stop(self) -> None:
        try:
            self.server.shutdown()
        finally:
            self.server.server_close()
            self._thread.join(timeout=5)
