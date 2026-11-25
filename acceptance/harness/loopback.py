"""Numeric IPv4-loopback HTTP servers for the harness and its test doubles.

``http.server.HTTPServer.server_bind`` binds the socket and then calls
``socket.getfqdn(host)`` only to fill ``server_name``. That reverse lookup goes
through the system name service and can block for seconds on some hosts; the
harness never reads ``server_name`` and listens only on numeric loopback
addresses, so the lookup is pure startup latency. (Hosted macOS CI timings are
consistent with this lookup stalling; that is inferred, not established.)

``LoopbackThreadingHTTPServer`` accepts only a numeric IPv4 loopback host,
binds the real socket exactly as ``socketserver.TCPServer.server_bind`` does
(same reuse options, same ``getsockname()`` result), and records the numeric
bound address as ``server_name`` instead of reverse-resolving it.
"""

from __future__ import annotations

import ipaddress
import socket
import socketserver
from http.server import ThreadingHTTPServer


def require_numeric_loopback(host: object) -> str:
    """Return ``host`` if it is a numeric IPv4 loopback address, else raise ``ValueError``.

    Hostnames (including ``localhost``), wildcard and non-loopback addresses are
    refused, so a caller can never trigger a name lookup or a wider bind
    through this path. The rejected value is not echoed.
    """
    if not isinstance(host, str):
        raise ValueError("loopback server host must be a numeric IPv4 loopback string")
    try:
        address = ipaddress.IPv4Address(host)
    except ValueError:
        raise ValueError("loopback server host must be a numeric IPv4 loopback address") from None
    if not address.is_loopback:
        raise ValueError("loopback server host must be a numeric IPv4 loopback address")
    return host


class LoopbackThreadingHTTPServer(ThreadingHTTPServer):
    """``ThreadingHTTPServer`` restricted to numeric IPv4 loopback, without reverse DNS."""

    address_family = socket.AF_INET

    def __init__(self, server_address, RequestHandlerClass, bind_and_activate: bool = True) -> None:  # noqa: N803
        if not isinstance(server_address, tuple) or len(server_address) != 2:
            raise ValueError("loopback server address must be a (host, port) tuple")
        # Validate before any socket exists.
        require_numeric_loopback(server_address[0])
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)

    def server_bind(self) -> None:
        # Real bind (SO_REUSEADDR/SO_REUSEPORT per class attributes, bind, getsockname).
        socketserver.TCPServer.server_bind(self)
        host, port = self.server_address[:2]
        # Record the numeric bound address; deliberately no socket.getfqdn(). A failure
        # here propagates out of TCPServer.__init__, which closes the socket first.
        self.server_name = require_numeric_loopback(host)
        self.server_port = port
