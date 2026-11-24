#!/usr/bin/env python3
"""TEST-ONLY imitation of the ferrum-edge CLI surface the harness drives.

It is NOT Ferrum and proves nothing about Ferrum; it only lets the harness's
own plumbing (argv handling, readiness/ownership probes, routing assertions,
cleanup) be exercised without the real binary. JSON specs only. Loopback only.
"""

import base64
import hashlib
import hmac
import http.client
import json
import os
import signal
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _arg(argv, short, long_):
    for i, item in enumerate(argv):
        if item in (short, long_) and i + 1 < len(argv):
            return argv[i + 1]
    return None


def _load_spec(path):
    with open(path, encoding="utf-8") as handle:
        doc = json.load(handle)
    if not isinstance(doc, dict) or not isinstance(doc.get("proxies"), list):
        raise ValueError("spec must contain a proxies list")
    return doc


def _jwt_ok(token, secret, issuer):
    try:
        head, body, sig = token.split(".")
        expected = hmac.new(secret.encode(), f"{head}.{body}".encode(), hashlib.sha256).digest()
        given = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        return hmac.compare_digest(expected, given) and claims.get("iss") == issuer and "role" in claims
    except (ValueError, TypeError):
        return False


def _route(proxies, host, path):
    best = None
    for proxy in proxies:
        hosts = proxy.get("hosts") or []
        if hosts and host not in hosts:
            continue
        lp = proxy.get("listen_path", "")
        if path == lp or path.startswith(lp.rstrip("/") + "/") or lp == "/":
            if best is None or len(lp) > len(best.get("listen_path", "")):
                best = proxy
    return best


def run(argv):
    spec = _load_spec(_arg(argv, "-c", "--spec"))
    proxies = spec["proxies"]
    bind = os.environ.get("FERRUM_PROXY_BIND_ADDRESS", "127.0.0.1")
    admin_bind = os.environ.get("FERRUM_ADMIN_BIND_ADDRESS", "127.0.0.1")
    token = os.environ["FERRUM_METRICS_BEARER_TOKEN"]
    secret = os.environ["FERRUM_ADMIN_JWT_SECRET"]
    issuer = os.environ["FERRUM_ADMIN_JWT_ISSUER"]

    class Admin(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            auth = self.headers.get("Authorization", "")
            bearer = auth[7:] if auth.startswith("Bearer ") else ""
            if self.path == "/health":
                body = {"status": "ok", "ready": True}
                if hmac.compare_digest(bearer, token):
                    body["cached_config"] = {"available": True}
                self._send(200, body)
            elif self.path == "/proxies":
                if _jwt_ok(bearer, secret, issuer):
                    self._send(200, proxies)
                else:
                    self._send(401, {"error": "unauthorized"})
            else:
                self._send(404, {"error": "not found"})

        def _send(self, status, obj):
            data = json.dumps(obj).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            return

    class Proxy(BaseHTTPRequestHandler):
        def _handle(self):
            raw_path, _, query = self.path.partition("?")
            host = (self.headers.get("Host") or "").split(":")[0]
            proxy = _route(proxies, host, raw_path)
            if proxy is None:
                return self._send(404, b'{"error":"no route"}')
            allowed = [m.upper() for m in proxy.get("allowed_methods") or []]
            if allowed and self.command not in allowed:
                return self._send(405, b'{"error":"method not allowed"}')
            rest = raw_path
            if proxy.get("strip_listen_path"):
                rest = raw_path[len(proxy["listen_path"].rstrip("/")):] or "/"
            target = (proxy.get("backend_path") or "").rstrip("/") + rest
            if query:
                target += "?" + query
            headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "connection", "content-length")}
            conn = http.client.HTTPConnection(proxy["backend_host"], int(proxy["backend_port"]), timeout=5)
            try:
                conn.request(self.command, target, headers=headers)
                resp = conn.getresponse()
                self._send(resp.status, resp.read())
            except OSError:
                self._send(502, b'{"error":"backend"}')
            finally:
                conn.close()

        def _send(self, status, data):
            self.send_response(status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _handle

        def log_message(self, *args):
            return

    admin = ThreadingHTTPServer((admin_bind, int(os.environ["FERRUM_ADMIN_HTTP_PORT"])), Admin)
    proxy = ThreadingHTTPServer((bind, int(os.environ["FERRUM_PROXY_HTTP_PORT"])), Proxy)
    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    for server in (admin, proxy):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print(json.dumps({"level": "INFO", "message": "fake gateway ready"}), flush=True)
    stop.wait()
    for server in (admin, proxy):
        server.shutdown()
        server.server_close()
    return 0


def main(argv):
    if not argv:
        return 2
    command = argv[0]
    if command == "version":
        print(json.dumps({"version": "0.9.21", "target": "selftest-fake"}, separators=(",", ":")))
        return 0
    if command == "validate":
        try:
            _load_spec(_arg(argv, "-c", "--spec"))
        except (OSError, ValueError, TypeError) as exc:
            print(f"Validation error: {type(exc).__name__}", file=sys.stderr)
            return 1
        print("Validation passed.")
        return 0
    if command == "run":
        return run(argv)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
