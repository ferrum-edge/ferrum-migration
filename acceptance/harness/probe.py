"""Minimal loopback HTTP/1.1 client (stdlib ``http.client``) with exact Host control."""

from __future__ import annotations

import http.client
import json
from typing import Mapping

_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_MAX_READ = 1_048_576


def send(
    port: int,
    method: str,
    path: str,
    host: str,
    headers: Mapping[str, str],
    timeout: float,
) -> dict:
    """Send one request to 127.0.0.1:port. Returns status/headers or a transport error."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", host)
        for name, value in headers.items():
            conn.putheader(name, value)
        if method.upper() in _BODY_METHODS:
            conn.putheader("Content-Length", "0")
        conn.putheader("Connection", "close")
        conn.endheaders()
        response = conn.getresponse()
        body = response.read(_MAX_READ)
        return {
            "status": response.status,
            "headers": {k.lower(): v for k, v in response.getheaders()},
            "body_bytes": len(body),
            "error": None,
        }
    except (OSError, http.client.HTTPException) as exc:
        return {"status": None, "headers": {}, "body_bytes": 0, "error": type(exc).__name__}
    finally:
        conn.close()


def get_json(port: int, path: str, bearer: "str | None", timeout: float = 3.0) -> tuple["int | None", object]:
    """GET a JSON document from a loopback admin listener."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        headers = {"Accept": "application/json", "Connection": "close"}
        if bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()
        raw = response.read(_MAX_READ)
        try:
            payload: object = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            payload = None
        return response.status, payload
    except (OSError, http.client.HTTPException):
        return None, None
    finally:
        conn.close()
