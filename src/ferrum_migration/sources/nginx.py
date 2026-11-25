"""NGINX OSS ``http {}`` reverse-proxy configuration to the IR.

The parser is a small, bounded tokenizer for the nginx configuration grammar.
``include`` directives are never followed (only well-known ``mime.types`` and
Debian ``proxy_params`` are recognized by name); Lua/Perl/JS blocks are refused.
Only ``http`` reverse proxying (``proxy_pass``/``grpc_pass``/``return``) is
migrated; ``stream``/``mail`` contexts and static file serving are reported.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field

from .. import matching, util
from ..errors import InputError
from ..limits import Limits
from ..model import BackendRef, HostScope, Plan, PluginSpec, RouteSpec, Target, TlsSpec, UpstreamSpec
from ..redact import safe_label
from .common import (SourceContext, check_route_budget, choose_main_port, compression_config, header_value_ok,
                     is_sensitive_header, literal_value, request_header_rule, response_header_rule)

PLATFORM = "nginx"


@dataclass
class Directive:
    name: str
    args: list[str]
    block: list["Directive"] | None
    line: int


def tokenize(text: str, limits: Limits) -> list[tuple[str, int, bool]]:
    tokens: list[tuple[str, int, bool]] = []
    index, length, line = 0, len(text), 1
    while index < length:
        char = text[index]
        if char == "\n":
            line += 1
            index += 1
            continue
        if char in " \t\r":
            index += 1
            continue
        if char == "#":
            while index < length and text[index] != "\n":
                index += 1
            continue
        if char in "{};":
            tokens.append((char, line, True))
            index += 1
        elif char in "\"'":
            quote, start_line = char, line
            index += 1
            buf: list[str] = []
            while index < length and text[index] != quote:
                if text[index] == "\\" and index + 1 < length:
                    following = text[index + 1]
                    buf.append(following if following in (quote, "\\") else "\\" + following)
                    if following == "\n":
                        line += 1
                    index += 2
                    continue
                if text[index] == "\n":
                    line += 1
                buf.append(text[index])
                index += 1
            if index >= length:
                raise InputError(f"unterminated quoted string starting at line {start_line}")
            index += 1
            tokens.append(("".join(buf), start_line, False))
        else:
            start_line = line
            buf = []
            while index < length:
                char = text[index]
                if char == "{" and buf and buf[-1] == "$":
                    end = text.find("}", index)
                    if end < 0:
                        raise InputError(f"unterminated variable at line {line}")
                    buf.append(text[index:end + 1])
                    index = end + 1
                    continue
                if char in " \t\r\n;{}":
                    break
                if char == "\\" and index + 1 < length:
                    buf.append(text[index:index + 2])
                    index += 2
                    continue
                buf.append(char)
                index += 1
            tokens.append(("".join(buf), start_line, False))
        if len(tokens) > limits.max_nginx_tokens:
            raise InputError(f"NGINX input exceeds {limits.max_nginx_tokens} tokens")
    return tokens


def parse(text: str, limits: Limits) -> list[Directive]:
    tokens = tokenize(text, limits)
    position = 0

    def block(depth: int) -> list[Directive]:
        nonlocal position
        items: list[Directive] = []
        while position < len(tokens):
            value, line, special = tokens[position]
            if special and value == "}":
                if depth == 0:
                    raise InputError(f"unexpected '}}' at line {line}")
                position += 1
                return items
            if special:
                raise InputError(f"unexpected '{value}' at line {line}")
            name, args = value, []
            position += 1
            while True:
                if position >= len(tokens):
                    raise InputError(f"unexpected end of input in directive starting at line {line}")
                token, token_line, token_special = tokens[position]
                if token_special and token == ";":
                    position += 1
                    items.append(Directive(name, args, None, line))
                    break
                if token_special and token == "{":
                    if name.endswith("_by_lua_block") or name in ("perl", "js_content", "lua_block"):
                        raise InputError(f"embedded script blocks are not supported (line {line})")
                    if depth + 1 > limits.max_nginx_block_depth:
                        raise InputError(f"NGINX blocks nested deeper than {limits.max_nginx_block_depth}")
                    position += 1
                    items.append(Directive(name, args, block(depth + 1), line))
                    break
                if token_special:
                    raise InputError(f"missing ';' before line {token_line}")
                args.append(token)
                position += 1
        if depth > 0:
            raise InputError("unbalanced braces: missing '}'")
        return items

    return block(0)


# ------------------------------------------------------------------ scopes

INHERITED_ARRAYS = {"proxy_set_header", "grpc_set_header", "allow", "deny", "add_header", "proxy_hide_header",
                    "limit_req"}
SAFE_IGNORED = {
    "access_log", "error_log", "log_format", "sendfile", "tcp_nopush", "tcp_nodelay", "keepalive_timeout",
    "keepalive_requests", "types_hash_max_size", "types_hash_bucket_size", "server_names_hash_bucket_size",
    "server_names_hash_max_size", "default_type", "types", "charset", "server_tokens", "proxy_buffering",
    "proxy_buffers", "proxy_buffer_size", "proxy_busy_buffers_size", "proxy_http_version",
    "proxy_request_buffering", "proxy_max_temp_file_size", "proxy_temp_path", "client_body_buffer_size",
    "client_header_buffer_size", "large_client_header_buffers", "client_body_timeout", "client_header_timeout",
    "send_timeout", "resolver", "resolver_timeout", "ssl_session_cache", "ssl_session_timeout",
    "ssl_session_tickets", "ssl_prefer_server_ciphers", "ssl_ciphers", "ssl_protocols", "ssl_dhparam",
    "ssl_ecdh_curve", "ssl_stapling", "ssl_stapling_verify", "ssl_trusted_certificate", "ssl_buffer_size",
    "gzip_vary",
    "gzip_buffers", "open_file_cache", "open_file_cache_valid", "open_file_cache_min_uses",
    "open_file_cache_errors", "reset_timedout_connection", "index", "absolute_redirect", "port_in_redirect",
    "server_name_in_redirect", "chunked_transfer_encoding", "merge_slashes", "proxy_ignore_client_abort",
    "proxy_socket_keepalive", "keepalive_disable", "lingering_close", "lingering_time", "lingering_timeout",
    "output_buffers", "postpone_output", "aio", "directio", "proxy_next_upstream_tries",
    "proxy_next_upstream_timeout", "real_ip_recursive", "variables_hash_max_size", "variables_hash_bucket_size",
    "map_hash_max_size", "map_hash_bucket_size", "status_zone", "http2_push_preload", "ssl_early_data",
    "grpc_buffer_size", "proxy_headers_hash_max_size", "proxy_headers_hash_bucket_size",
    "client_body_temp_path", "fastcgi_temp_path", "uwsgi_temp_path", "scgi_temp_path", "sendfile_max_chunk",
    "log_subrequest", "open_log_file_cache", "limit_req_status", "limit_req_log_level", "ssl_password_file",
    "ssl_conf_command", "http2_max_concurrent_streams", "client_body_in_file_only",
    # main-context directives that may appear in a bare snippet file
    "events", "worker_processes", "pid", "user", "worker_rlimit_nofile", "daemon", "master_process",
    "worker_cpu_affinity", "worker_priority", "pcre_jit", "timer_resolution", "lock_file", "working_directory",
    "worker_shutdown_timeout",
}
COSMETIC_IGNORED = {"error_page", "proxy_cache", "proxy_cache_valid", "proxy_cache_key", "proxy_cache_bypass",
                    "proxy_no_cache", "proxy_cache_use_stale", "proxy_cache_lock", "proxy_cache_methods",
                    "proxy_cookie_domain", "proxy_cookie_path", "sub_filter", "sub_filter_once", "sub_filter_types",
                    "expires", "etag", "proxy_intercept_errors", "proxy_next_upstream", "limit_rate",
                    "limit_rate_after", "proxy_pass_header", "proxy_ignore_headers", "proxy_redirect",
                    "add_trailer"}
DEFINITIONS = {"map", "geo", "split_clients", "limit_conn_zone", "proxy_cache_path", "upstream", "limit_req_zone",
               "log_not_found", "underscores_in_headers", "ignore_invalid_headers"}
STRUCTURAL = {"server", "location", "listen", "server_name", "proxy_pass", "grpc_pass", "return", "if",
              "ssl_certificate", "ssl_certificate_key", "ssl_client_certificate", "ssl_verify_client",
              "ssl_crl", "ssl_ocsp", "ssl_reject_handshake",
              "set_real_ip_from", "real_ip_header", "http2", "http3", "quic", "ssl", "include", "satisfy",
              "client_max_body_size", "proxy_connect_timeout", "proxy_read_timeout", "proxy_send_timeout",
              "grpc_connect_timeout", "grpc_read_timeout", "grpc_send_timeout", "auth_basic",
              "auth_basic_user_file", "proxy_ssl_verify", "proxy_ssl_trusted_certificate", "proxy_ssl_certificate",
              "proxy_ssl_certificate_key", "proxy_ssl_name", "proxy_ssl_server_name", "grpc_ssl_verify",
              "grpc_ssl_trusted_certificate", "grpc_ssl_certificate", "grpc_ssl_certificate_key", "grpc_ssl_name",
              "grpc_ssl_server_name", "gzip", "gzip_types", "gzip_comp_level", "gzip_min_length",
              "gzip_proxied", "gzip_disable", "gzip_http_version"} | INHERITED_ARRAYS
PROXY_PARAMS = [("Host", "$http_host"), ("X-Real-IP", "$remote_addr"),
                ("X-Forwarded-For", "$proxy_add_x_forwarded_for"), ("X-Forwarded-Proto", "$scheme")]


@dataclass
class _Scope:
    arrays: dict[str, list[list[str]]] = field(default_factory=dict)
    body_size: int | None = None
    timeouts: dict[str, int] = field(default_factory=dict)
    auth_basic: str | None = None
    auth_basic_file: str | None = None
    proxy_ssl: dict[str, str] = field(default_factory=dict)
    grpc_ssl: dict[str, str] = field(default_factory=dict)
    gzip: str | None = None
    gzip_types: list[str] | None = None
    gzip_min_length: int | None = None
    gzip_comp_level: int | None = None
    gzip_proxied: list[str] | None = None
    gzip_disable: list[str] = field(default_factory=list)
    gzip_http_version: str | None = None
    problems: list[str] = field(default_factory=list)


class _Nginx:
    def __init__(self, text: str, ctx: SourceContext) -> None:
        self.text = text
        self.ctx = ctx
        self.report = ctx.report
        self.plan = Plan(platform=PLATFORM)
        self.upstream_blocks: dict[str, Directive] = {}
        self.zones: dict[str, dict] = {}
        self.body_sizes: list[tuple[RouteSpec, int]] = []
        self.catch_all_routes: dict[int, list[RouteSpec]] = {}

    # --------------------------------------------------------- scope merge

    def apply(self, parent: _Scope, directives: list[Directive], ref: str) -> _Scope:
        child = _Scope(arrays=dict(parent.arrays), body_size=parent.body_size, timeouts=dict(parent.timeouts),
                       auth_basic=parent.auth_basic, auth_basic_file=parent.auth_basic_file,
                       proxy_ssl=dict(parent.proxy_ssl), grpc_ssl=dict(parent.grpc_ssl),
                       gzip=parent.gzip,
                       gzip_types=list(parent.gzip_types) if parent.gzip_types is not None else None,
                       gzip_min_length=parent.gzip_min_length, gzip_comp_level=parent.gzip_comp_level,
                       gzip_proxied=list(parent.gzip_proxied) if parent.gzip_proxied is not None else None,
                       gzip_disable=list(parent.gzip_disable),
                       gzip_http_version=parent.gzip_http_version,
                       problems=list(parent.problems))
        level: dict[str, list[list[str]]] = {}
        for directive in directives:
            name, args = directive.name, directive.args
            if name in ("allow", "deny"):
                # ngx_http_access_module keeps allow and deny in ONE ordered array.
                level.setdefault("access", []).append([name] + list(args))
            elif name in INHERITED_ARRAYS:
                level.setdefault(name, []).append(args)
            elif name == "include":
                target = args[0] if args else ""
                base = target.rsplit("/", 1)[-1]
                if base == "mime.types":
                    continue
                if base == "proxy_params":
                    level.setdefault("proxy_set_header", []).extend([[k, v] for k, v in PROXY_PARAMS])
                    self.report.warning("nginx-proxy-params", ref, "include proxy_params was assumed to contain the "
                                        "Debian/Ubuntu defaults (Host $http_host and X-Forwarded-*); it was not read.")
                    continue
                child.problems.append("an include directive was not followed (input is limited to one file)")
            elif name == "client_max_body_size" and args:
                size = util.parse_nginx_size(args[0])
                if size is None:
                    child.problems.append("client_max_body_size is not a valid size")
                else:
                    child.body_size = size
            elif name in ("proxy_connect_timeout", "grpc_connect_timeout", "proxy_read_timeout", "grpc_read_timeout",
                          "proxy_send_timeout", "grpc_send_timeout") and args:
                value = util.parse_nginx_time_ms(args[0])
                if value is not None:
                    child.timeouts[name.split("_", 1)[1].replace("_timeout", "")] = value
            elif name == "auth_basic" and args:
                child.auth_basic = args[0]
            elif name == "auth_basic_user_file" and args:
                child.auth_basic_file = args[0]
            elif name.startswith("proxy_ssl_") and name in STRUCTURAL and args:
                child.proxy_ssl[name.split("_", 2)[2]] = args[0]
            elif name.startswith("grpc_ssl_") and name in STRUCTURAL and args:
                child.grpc_ssl[name.split("_", 2)[2]] = args[0]
            elif name == "gzip" and args:
                if args[0] in ("on", "off"):
                    child.gzip = args[0]
            elif name == "gzip_comp_level" and args:
                gzip_level = util.as_int(args[0])
                if gzip_level is not None and 1 <= gzip_level <= 9:
                    child.gzip_comp_level = gzip_level
            elif name == "gzip_min_length" and args:
                length = util.parse_nginx_size(args[0])
                if length is not None and length >= 0:
                    child.gzip_min_length = length
            elif name == "gzip_types" and args:
                child.gzip_types = list(args)
            elif name == "gzip_proxied" and args:
                child.gzip_proxied = list(args)
            elif name == "gzip_disable" and args:
                child.gzip_disable = list(args)
            elif name == "gzip_http_version" and args:
                child.gzip_http_version = args[0]
            elif name == "satisfy" and args and args[0] == "any":
                child.problems.append("satisfy any (OR of access and auth) has no Ferrum equivalent")
            elif name in STRUCTURAL or name in SAFE_IGNORED or name in DEFINITIONS:
                continue
            elif name in COSMETIC_IGNORED:
                self.report.warning("nginx-directive-omitted", ref,
                                    f"{safe_label(name, 40)} is not migrated (cosmetic or caching behavior).")
            elif name.startswith("gzip_") or name.startswith("ssl_"):
                continue
            else:
                child.problems.append(f"directive {safe_label(name, 40)} is not supported")
        for name, entries in level.items():
            child.arrays[name] = entries
        return child

    # ----------------------------------------------------------------- run

    def run(self) -> Plan:
        top = parse(self.text, self.ctx.limits)
        http_blocks = [d for d in top if d.name == "http"]
        if len(http_blocks) > 1:
            raise InputError("more than one http block")
        if http_blocks:
            for directive in top:
                if directive.name in ("stream", "mail"):
                    self.report.error("nginx-context-unsupported", f"nginx {directive.name} (line {directive.line})",
                                      "TCP/UDP stream and mail proxying are not migrated.")
            http = http_blocks[0].block or []
        else:
            if any(d.name == "location" for d in top):
                raise InputError("location blocks must be inside a server block")
            http = top
        self.http_directives = http
        self.http_scope = self.apply(_Scope(), [d for d in http if d.name not in ("server",)], "nginx http")
        servers = []
        for directive in http:
            if directive.name == "upstream" and directive.args and directive.block is not None:
                self.upstream_blocks[directive.args[0]] = directive
            elif directive.name == "limit_req_zone":
                self._zone(directive)
            elif directive.name == "server" and directive.block is not None:
                servers.append(directive)
            elif directive.name == "set_real_ip_from" and directive.args:
                self.plan.settings.trusted_proxies.append(directive.args[0])
            elif directive.name == "real_ip_header" and directive.args:
                self.plan.settings.real_ip_header = directive.args[0]
        if self.plan.settings.trusted_proxies or self.plan.settings.real_ip_header:
            self.report.warning("nginx-real-ip", "nginx http", "Client-IP resolution behind trusted proxies is only "
                                "suggested in ferrum.conf; ip_restriction and rate limits use the socket peer until "
                                "FERRUM_TRUSTED_PROXIES is set.")
        infos = [self._server_info(server, index) for index, server in enumerate(servers)]
        self._merge_shared_tls_sockets(infos)
        self.infos = infos
        self._elect_ports(infos)
        for info in infos:
            self._translate_server(info)
        self._apply_ssl_reject_handshake(infos)
        self._refuse_conflicting_defaults()
        # Each route records the main listeners its server was served on (RouteSpec.protocols). The emitter keeps a
        # plaintext-only server's routes off Ferrum's HTTPS listener (and vice versa) for every host name.
        check_route_budget(len(self.plan.routes), self.ctx.limits)
        self._finish_body_sizes()
        return self.plan

    def _zone(self, directive: Directive) -> None:
        key = directive.args[0] if directive.args else ""
        zone = rate = None
        for arg in directive.args[1:]:
            if arg.startswith("zone="):
                zone = arg[5:].split(":", 1)[0]
            elif arg.startswith("rate="):
                rate = arg[5:]
        if zone:
            self.zones[zone] = {"key": key, "rate": rate}

    # -------------------------------------------------------------- servers

    def _server_info(self, server: Directive, index: int) -> dict:
        listens = []
        names: list[str] = []
        ssl_on = False
        for directive in server.block or []:
            if directive.name == "listen" and directive.args:
                parsed = _parse_listen(directive.args)
                if parsed is None:
                    listens.append({"invalid": True})
                else:
                    listens.append(parsed)
            elif directive.name == "server_name":
                names.extend(directive.args)
            elif directive.name == "ssl" and directive.args == ["on"]:
                ssl_on = True
        if not listens:
            listens = [{"addr": None, "port": 80, "family": "v4", "ssl": False, "default": False, "flags": set()}]
        if ssl_on:
            for listen in listens:
                listen["ssl"] = True
        label = names[0] if names and names[0] not in ("_", "") else "default"
        return {"directive": server, "listens": listens, "names": names, "index": index,
                "ref": f"nginx server '{safe_label(label, 64)}' (line {server.line})", "label": label}

    def _merge_shared_tls_sockets(self, infos: list[dict]) -> None:
        """NGINX marks a shared (addr, port, family, transport) socket as TLS if any server on that exact socket sets ``ssl``."""
        tls_sockets = {
            (listen["addr"], listen["port"], listen.get("family", "v4"), bool(listen.get("http3")))
            for info in infos for listen in info["listens"]
            if not listen.get("invalid") and listen["ssl"]
        }
        if not tls_sockets:
            return
        for info in infos:
            for listen in info["listens"]:
                if listen.get("invalid") or listen["ssl"]:
                    continue
                if (listen["addr"], listen["port"], listen.get("family", "v4"), bool(listen.get("http3"))) in tls_sockets:
                    listen["ssl"] = True

    def _elect_ports(self, infos: list[dict]) -> None:
        plain: dict[int, int] = {}
        tls: dict[int, int] = {}
        for info in infos:
            for listen in info["listens"]:
                if listen.get("invalid"):
                    continue
                bucket = tls if listen["ssl"] else plain
                bucket[listen["port"]] = bucket.get(listen["port"], 0) + 1
        settings = self.plan.settings
        settings.main_http_port = choose_main_port(plain)
        settings.main_https_port = choose_main_port(tls)
        explicit = {}
        for info in infos:
            for listen in info["listens"]:
                if not listen.get("invalid") and listen["default"]:
                    explicit[(listen["port"], listen["ssl"])] = info["index"]
        first: dict[tuple[int, bool], int] = {}
        for info in infos:
            for listen in info["listens"]:
                if not listen.get("invalid"):
                    first.setdefault((listen["port"], listen["ssl"]), info["index"])
        self.default_server = {key: explicit.get(key, index) for key, index in first.items()}
        addresses = {listen.get("addr") for info in infos for listen in info["listens"] if not listen.get("invalid")}
        specific = {addr for addr in addresses if addr}
        if specific and None not in addresses and len(specific) == 1:
            settings.bind_address = next(iter(specific))
        self.bind_conflict = bool(specific) and (None in addresses or len(specific) > 1)
        if any(listen.get("http3") for info in infos for listen in info["listens"] if not listen.get("invalid")):
            settings.http3 = True
        if any(listen.get("proxy_protocol") for info in infos for listen in info["listens"]
               if not listen.get("invalid")):
            settings.proxy_protocol = True
            self.report.warning("nginx-proxy-protocol", "nginx listen", "PROXY protocol listeners are only suggested in "
                                "ferrum.conf; configure Ferrum's frontend PROXY protocol and trusted CIDRs.")

    def _translate_server(self, info: dict) -> None:
        server: Directive = info["directive"]
        ref = info["ref"]
        settings = self.plan.settings
        listens = [listen for listen in info["listens"] if not listen.get("invalid")]
        if len(listens) != len(info["listens"]):
            self.report.error("nginx-listen-invalid", ref, "A listen directive (unix socket or malformed) is not "
                              "migrated; the server is skipped.")
            return
        if self.bind_conflict and any(listen["addr"] for listen in listens):
            self.report.error("nginx-bind-address", ref, "This server listens on a specific address while others "
                              "listen elsewhere; Ferrum binds one proxy address, which would expose it more widely. "
                              "Skipped.")
            return
        plain_ports = {listen["port"] for listen in listens if not listen["ssl"]}
        tls_ports = {listen["port"] for listen in listens if listen["ssl"]}
        on_plain = settings.main_http_port in plain_ports
        on_tls = settings.main_https_port in tls_ports
        listen_port = None
        if on_plain or on_tls:
            requires_tls = not on_plain
            extra = (plain_ports - {settings.main_http_port}) | (tls_ports - {settings.main_https_port})
            if extra:
                self.report.warning("nginx-extra-ports", ref, "The server also listened on other ports; Ferrum serves "
                                    "it only on the main ports (stricter).")
        elif plain_ports:
            listen_port = min(plain_ports)
            requires_tls = False
            self.report.info("nginx-listen-port", ref, f"The server listens only on plaintext port {listen_port}, not "
                             "on the main ports. Ferrum cannot isolate a port-scoped route from the main routes, so "
                             "its routes are not migrated (see extra-listener-refused).")
        else:
            self.report.error("nginx-tls-port", ref, "TLS on a non-main port cannot be scoped reliably in Ferrum file "
                              "mode; the server is skipped.", "Move it to the main TLS port or migrate it manually.")
            return
        # Default ownership is decided on the listeners Ferrum actually serves this server on. Ports dropped above
        # (extra plaintext/TLS ports) must not make it a catch-all on the main ports, where another server may be
        # the default.
        if on_plain or on_tls:
            selected = [listen for listen in listens
                        if (not listen["ssl"] and listen["port"] == settings.main_http_port)
                        or (listen["ssl"] and listen["port"] == settings.main_https_port)]
        else:
            selected = [listen for listen in listens if not listen["ssl"] and listen["port"] == listen_port]
        ownership = {self.default_server.get((listen["port"], listen["ssl"])) == info["index"] for listen in selected}
        is_default = ownership == {True}
        hosts, host_problem = _server_hosts(info["names"])
        if ownership == {True, False}:
            # Ferrum serves the same port-agnostic routes on every selected listener, so a catch-all would also take
            # unknown host names from the listener where another server is the default.
            self.report.error("nginx-default-server-listener", ref,
                              "This server is the default server on some of the listeners Ferrum serves it on, but "
                              "not on others. Ferrum cannot scope a catch-all route to one of them, so it is migrated "
                              "for its own server_name hosts only; requests for unknown host names, which NGINX sent "
                              "to it on one listener, are not routed to it (fail closed).",
                              "Give each listener its own default server in the source (or serve them from separate "
                              "Ferrum frontends), then convert again.")
        if is_default and hosts and not host_problem and self._names_covered_elsewhere(info, selected, hosts):
            # NGINX picks this server for its own names (exact beats wildcard, longer wildcard beats shorter) and
            # only falls back to it for unknown names. As a Ferrum catch-all, its own names would go to the other
            # server's exact/wildcard tier instead. Keep the named tier; the fallback role is not migrated.
            self.report.error("nginx-default-server-named", ref,
                              "This default server also has server_name entries that another server on the same "
                              "listener covers (same name or a wildcard). NGINX sends those names to this server, "
                              "but a Ferrum catch-all route would lose them to the other server's routes. It is "
                              "migrated for its own server_name hosts only; requests for unknown host names, which "
                              "NGINX also sent to this default server, are not routed to it (fail closed).",
                              "If unknown host names must reach this server, add a separate catch-all server for "
                              "them in the source and convert again.")
        elif is_default:
            hosts, host_problem = [], None
            self.report.info("nginx-default-server", ref, "Default server: its routes are catch-all (any Host).")
        elif hosts == [] and not host_problem:
            self.report.info("nginx-unreachable-server", ref, "Server name only matches no real host and the server "
                             "is not a default server; skipped.")
            return
        if host_problem:
            self.report.error("nginx-server-name", ref, f"server_name not representable ({host_problem}).")
        scope = self.apply(self.http_scope, [d for d in server.block or [] if d.name != "location"], ref)
        for directive in server.block or []:
            if directive.name == "ssl_certificate" and directive.args:
                cert = directive.args[0]
                key = next((d.args[0] for d in server.block or [] if d.name == "ssl_certificate_key" and d.args), None)
                if key and "$" not in cert and "$" not in key:
                    settings.frontend_cert_pairs.append((cert, key))
        client_cas, client_ca_problem = self._client_trust(server, ref, on_tls)
        reject_hs = self._tls_setting(server, "ssl_reject_handshake") if on_tls else None
        if reject_hs is not None and reject_hs != "off":
            self.report.error("nginx-ssl-reject-handshake", ref,
                              "ssl_reject_handshake rejects TLS handshakes before HTTP routing, which Ferrum's HTTPS "
                              "listener cannot reproduce. Affected routes were refused (fail closed).",
                              "Keep SNI handshake rejection on a front proxy, or review whether accepting handshakes "
                              "for unknown SNIs is acceptable before migrating.")
            scope.problems.append("ssl_reject_handshake cannot be reproduced by Ferrum's HTTPS listener")
        base = {"hosts": None if host_problem else hosts, "listen_port": listen_port, "requires_tls": requires_tls,
                "server_label": info["label"], "server_ref": ref, "extra": bool(host_problem),
                "client_cas": client_cas, "client_ca_problem": client_ca_problem,
                "on_plain": on_plain, "on_tls": on_tls}
        server_return = next((d for d in server.block or [] if d.name == "return"), None)
        server_if = [d for d in server.block or [] if d.name == "if"]
        for condition in server_if:
            if _is_https_redirect_if(condition):
                if tls_ports:
                    base["requires_tls"] = True
                    settings.https_redirect_seen = True
                    continue
            scope.problems.append("an 'if' block is not supported")
        if server_return is not None:
            if _is_https_redirect(server_return.args) and not tls_ports:
                settings.https_redirect_seen = True
                self.report.info("nginx-https-redirect", ref, "HTTP-to-HTTPS redirect server: not emitted; Ferrum's "
                                 "TLS-only profile disables the plaintext listener instead.")
                return
            route = self._new_route(base, "/", "prefix", ref + " return")
            self._apply_return(route, server_return.args)
            for problem in scope.problems:
                route.refuse(problem)
            self.plan.routes.append(route)
            self._note_catch_all(info, base, [route])
            return
        locations = [d for d in server.block or [] if d.name == "location"]
        if not locations:
            self.report.warning("nginx-no-locations", ref, "Server has no locations (static files); skipped.")
            return
        routes = []
        for location in locations:
            route = self._location(location, scope, base)
            if route is not None:
                routes.append(route)
        if all(route.termination and _is_https_redirect_termination(route.termination) for route in routes) \
                and routes and not tls_ports:
            settings.https_redirect_seen = True
            self.report.info("nginx-https-redirect", ref, "HTTP-to-HTTPS redirect server: not emitted.")
            return
        _check_precedence(routes)
        self.plan.routes.extend(routes)
        self._note_catch_all(info, base, routes)
        if base["hosts"]:
            self.plan.host_scopes.append(HostScope(ref, list(base["hosts"]), listen_port))

    def _note_catch_all(self, info: dict, base: dict, routes: list[RouteSpec]) -> None:
        """Remember port-agnostic catch-all routes per server (checked for conflicting defaults in run())."""
        if base["hosts"] == [] and base["listen_port"] is None and routes:
            self.catch_all_routes.setdefault(info["index"], []).extend(routes)

    def _apply_ssl_reject_handshake(self, infos: list[dict]) -> None:
        """If any server on the main TLS listener enables ssl_reject_handshake, refuse every HTTPS route."""
        port = self.plan.settings.main_https_port
        if port is None:
            return
        rejecting = []
        for info in infos:
            on_main_tls = any(not l.get("invalid") and l["ssl"] and l["port"] == port for l in info["listens"])
            if not on_main_tls:
                continue
            setting = self._tls_setting(info["directive"], "ssl_reject_handshake")
            if setting is not None and setting != "off":
                rejecting.append(info)
        if not rejecting:
            return
        https_routes = [r for r in self.plan.routes
                        if not r.skip and (r.requires_tls or "https" in (r.protocols or ()))]
        if not https_routes:
            return
        unrefused = [r for r in https_routes if not r.refusals]
        for route in https_routes:
            route.refuse("a server on the main TLS listener enables ssl_reject_handshake (SNI admission control), "
                         "which Ferrum's HTTPS listener cannot reproduce")
        if unrefused:
            refs = ", ".join(info["ref"] for info in rejecting[:3])
            self.report.error("nginx-ssl-reject-handshake", refs,
                              "A server on the main TLS listener enables ssl_reject_handshake, rejecting TLS "
                              "handshakes for matched/unknown SNIs before HTTP routing. Ferrum's HTTPS listener "
                              f"completes every handshake with its frontend certificate, so all {len(https_routes)} "
                              "HTTPS route(s) were refused (fail closed).",
                              "Keep SNI handshake rejection on a front proxy, or remove ssl_reject_handshake only if "
                              "accepting handshakes for those SNIs is acceptable, then convert again.")

    def _refuse_conflicting_defaults(self) -> None:
        """Different default servers on the main plaintext and TLS listeners cannot share one catch-all tier.

        Ferrum serves port-agnostic routes on both listeners, so each server's catch-all routes would also answer
        unknown host names on the listener where the other server is the default. Neither envelope is kept.
        """
        if len(self.catch_all_routes) < 2:
            return
        for routes in self.catch_all_routes.values():
            for route in routes:
                route.refuse("another server is the default server on the other main listener; Ferrum's port-agnostic "
                             "catch-all tier cannot keep the two default servers apart")
        self.report.error("nginx-default-server-conflict", "nginx default servers",
                          f"{len(self.catch_all_routes)} different servers are default servers on the main plaintext "
                          "and TLS listeners. Ferrum serves catch-all routes on both listeners, so unknown host names "
                          "on one listener would reach the other default server's routes. Their catch-all routes were "
                          "refused (fail closed).",
                          "Use one default server for both main listeners in the source, or serve them from separate "
                          "Ferrum frontends, then convert again.")

    def _names_covered_elsewhere(self, info: dict, listens: list[dict], hosts: list[str]) -> bool:
        """Whether another server sharing a listen socket has a server name equal to or covering one of ``hosts``."""
        sockets = {(listen["port"], listen["ssl"]) for listen in listens}
        for other in self.infos:
            if other is info:
                continue
            other_sockets = {(listen["port"], listen["ssl"]) for listen in other["listens"] if not listen.get("invalid")}
            if not sockets & other_sockets:
                continue
            other_hosts, other_problem = _server_hosts(other["names"])
            if other_problem:
                continue
            if any(matching.host_cover(outer, name) for outer in other_hosts for name in hosts):
                return True
        return False

    def _new_route(self, base: dict, path: str, kind: str, ref: str) -> RouteSpec:
        route = RouteSpec(ref=ref, name=f"{base['server_label']}-{path}")
        route.hosts = None if base["hosts"] is None else list(base["hosts"])
        route.kind, route.path = kind, path
        route.listen_port = base["listen_port"]
        route.requires_tls = base["requires_tls"]
        # The main listeners NGINX served this server on (a plaintext side that only redirects to HTTPS does not
        # count; neither do dropped extra ports). Extra-listener servers are never emitted.
        protocols = set()
        if base["listen_port"] is None:
            if base["on_plain"] and not base["requires_tls"]:
                protocols.add("http")
            if base["on_tls"]:
                protocols.add("https")
        route.protocols = frozenset(protocols)
        if base["extra"]:
            route.extra_conditions = True
            route.refuse("server_name is not representable")
        route.client_cas = list(base["client_cas"])
        if base["client_ca_problem"]:
            route.refuse(base["client_ca_problem"])
        return route

    def _tls_setting(self, server: Directive, name: str) -> str | None:
        """First value of an ``ssl_*`` directive in the server block, else inherited from ``http``."""
        for block in (server.block or [], self.http_directives):
            value = next((d.args[0] for d in block if d.name == name and d.args), None)
            if value is not None:
                return value
        return None

    def _client_trust(self, server: Directive, ref: str, on_tls: bool) -> tuple[list[str], str | None]:
        """Client CA bundle this server required on Ferrum's TLS listener, or a refusal reason.

        The emitter decides whether one listener-wide bundle preserves every server's trust
        scope; this only records each server's own scope and never merges bundles.
        """
        verify = self._tls_setting(server, "ssl_verify_client") or "off"
        if verify == "off" or not on_tls:
            return [], None
        crl = self._tls_setting(server, "ssl_crl")
        ocsp = self._tls_setting(server, "ssl_ocsp")
        if crl or (ocsp and ocsp != "off"):
            self.report.error("nginx-client-ca", ref,
                              "Client certificate revocation checking (ssl_crl/ssl_ocsp) cannot be reproduced by "
                              "Ferrum's frontend client CA bundle. The server's routes were refused (fail closed).",
                              "Enforce client certificate revocation externally or wait for CRL/OCSP support before "
                              "serving this trust boundary.")
            return [], "client certificate revocation checking (ssl_crl/ssl_ocsp) cannot be reproduced"
        ca = self._tls_setting(server, "ssl_client_certificate")
        if ca is None and verify == "optional_no_ca":
            return [], None  # the certificate was never verified against a CA: no trust boundary to keep
        if ca is None or "$" in ca or ca.startswith("data:"):
            self.report.error("nginx-client-ca", ref,
                              "ssl_verify_client requires client certificates, but no single ssl_client_certificate "
                              "file path defines the trusted client CAs, so the original trust set cannot be "
                              "reproduced. The server's routes were refused (fail closed).",
                              "Write this server's client CA bundle to a file, configure it in a Ferrum frontend "
                              "dedicated to this trust boundary (FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH), and "
                              "validate it before serving traffic.")
            return [], "client certificate trust (ssl_verify_client) has no single client CA file to reproduce"
        if verify != "on":
            self.report.warning("nginx-mtls-optional", ref, "Optional client certificates become "
                                "mandatory under Ferrum's frontend client CA (stricter).")
        if self._tls_setting(server, "ssl_trusted_certificate"):
            self.report.warning("nginx-mtls-trusted-certificate", ref,
                                "ssl_trusted_certificate also trusted client certificate issuers in NGINX; Ferrum "
                                "trusts only the ssl_client_certificate bundle (stricter).")
        return [ca], None

    # ------------------------------------------------------------ locations

    def _location(self, location: Directive, server_scope: _Scope, base: dict) -> RouteSpec | None:
        args = location.args
        if len(args) == 1:
            modifier, path = None, args[0]
        elif len(args) == 2:
            modifier, path = args
        else:
            raise InputError(f"malformed location at line {location.line}")
        ref = f"nginx location '{safe_label((modifier + ' ' if modifier else '') + path, 64)}' in {base['server_ref']}"
        if path.startswith("@"):
            self.report.info("nginx-named-location", ref, "Named locations are only reachable internally; skipped.")
            return None
        if modifier == "=":
            route = self._new_route(base, path, "exact", ref)
        elif modifier in (None, "^~"):
            route = self._new_route(base, path, "prefix", ref)
            route.prefix_semantics = "string"
            # NGINX prefix locations are plain string prefixes (/api also matches /apix). Ferrum cannot
            # express that without widening the route, so the emitter reports sibling paths it cannot
            # route equivalently instead of dropping them silently.
            route.report_prefix_siblings = True
            if modifier == "^~":
                route.name += "-caret"
        elif modifier in ("~", "~*"):
            pattern = _nginx_regex(path, modifier == "~*")
            route = self._new_route(base, pattern or path, "regex", ref)
            if pattern is None:
                route.refuse("regex with top-level alternation cannot be anchored faithfully")
                route.extra_conditions = True
        else:
            raise InputError(f"unknown location modifier at line {location.line}")
        route.caret = modifier == "^~"  # type: ignore[attr-defined]
        block = location.block or []
        if any(d.name == "location" for d in block):
            route.refuse("nested locations are not migrated")
        if any(d.name == "if" for d in block):
            route.refuse("an 'if' block is not supported")
        scope = self.apply(server_scope, block, ref)
        for problem in scope.problems:
            route.refuse(problem)
        returns = [d for d in block if d.name == "return"]
        proxy = next((d for d in block if d.name in ("proxy_pass", "grpc_pass")), None)
        access_config, deny_all, notes, access_problem = _access_policy(scope.arrays.get("access", []))
        for note in notes:
            self.report.warning("nginx-access-rules", ref, note)
        if access_problem:
            route.refuse(access_problem)
        if returns:
            self._apply_return(route, returns[0].args)
            return route
        if deny_all:
            route.termination = {"status_code": 403, "content_type": "application/json", "message": "Forbidden"}
            return route
        if proxy is None:
            route.refuse("serves local content (no proxy_pass/grpc_pass/return)")
            return route
        self._apply_proxy(route, proxy, scope, ref)
        if access_config:
            route.plugins.insert(0, PluginSpec("ip_restriction", access_config, ref))
        return route

    def _apply_return(self, route: RouteSpec, args: list[str]) -> None:
        if not args:
            route.refuse("empty return")
            return
        if len(args) == 1 and not args[0].isdigit():
            code, value = 302, args[0]
        else:
            code = util.as_int(args[0]) or 0
            value = args[1] if len(args) > 1 else None
        if code == 444:
            code = 403
            self.report.warning("nginx-return-444", route.ref, "return 444 (close connection) becomes HTTP 403.")
        if not 200 <= code <= 599:
            route.refuse("return status outside 200-599")
            return
        if value is not None and "$" in value:
            route.refuse("return with variables cannot be reproduced statically")
            return
        if code in (301, 302, 303, 307, 308):
            if not value or not header_value_ok(value, nonempty=True, strict_ws=True):
                route.refuse("redirect target is missing or not a valid header value")
                return
            route.termination = {"status_code": code, "headers": {"location": value}, "body": ""}
        elif code in (204, 205, 304):
            route.termination = {"status_code": code, "body": value or ""}
        else:
            route.termination = {"status_code": code, "content_type": "text/plain", "body": value or ""}

    def _apply_proxy(self, route: RouteSpec, directive: Directive, scope: _Scope, ref: str) -> None:
        if len(directive.args) != 1 or "$" in directive.args[0]:
            route.refuse(f"{directive.name} with variables or extra arguments is not migrated")
            return
        url = directive.args[0]
        grpc = directive.name == "grpc_pass"
        match = re.fullmatch(r"(?i)(https?|grpcs?)://([^/]+)(/.*)?", url)
        if not match or "@" in match.group(2):
            route.refuse(f"{directive.name} target is not an http(s)/grpc(s) URL")
            return
        scheme = "https" if match.group(1).lower() in ("https", "grpcs") else "http"
        hostport, uri = match.group(2), match.group(3)
        tls, tls_problems = self._tls(scope, grpc)
        if scheme == "https":
            for problem in tls_problems:
                route.refuse(problem)
        if hostport in self.upstream_blocks:
            key = self._upstream(hostport, tls, scheme)
            route.backend = BackendRef(scheme=scheme, upstream_key=key) if key else None
            if key is None:
                route.refuse("upstream block is not representable")
        else:
            parsed = util.split_host_port(hostport, 443 if scheme == "https" else 80)
            if parsed is None:
                route.refuse("backend host/port is invalid")
                return
            if scheme == "https" and (tls.sni or tls.san_allow_list):
                key = f"direct:{parsed[0]}:{parsed[1]}|{scheme}|{tls.key()}"
                if key not in self.plan.upstreams:
                    self.plan.upstreams[key] = UpstreamSpec(
                        key=key, name=f"{parsed[0]}-{parsed[1]}", ref=ref,
                        targets=[Target(parsed[0], parsed[1], 1)], tls=tls,
                    )
                route.backend = BackendRef(scheme=scheme, upstream_key=key)
            else:
                route.backend = BackendRef(scheme=scheme, host=parsed[0], port=parsed[1], tls=tls)
        if uri is not None:
            if route.kind == "regex":
                route.refuse("proxy_pass with a URI inside a regex location is invalid in NGINX")
            elif route.kind == "exact":
                if uri != route.path:
                    route.strip = True
                    route.backend_path = uri
                    self.report.warning("nginx-exact-rewrite", ref, "Exact location with a different proxy_pass URI: "
                                        "verify the forwarded path (Ferrum may append '/').")
            else:
                route.strip = True
                route.backend_path = uri if uri != "/" else None
                if (route.path or "").endswith("/") != uri.endswith("/"):
                    self.report.warning("nginx-slash-mismatch", ref, "Location and proxy_pass URI disagree on the "
                                        "trailing slash; NGINX produces doubled or missing slashes, Ferrum joins them "
                                        "cleanly.")
        for name, attr in (("connect", "connect_timeout_ms"), ("read", "read_timeout_ms"), ("send", "write_timeout_ms")):
            if name in scope.timeouts:
                setattr(route, attr, scope.timeouts[name])
        self._headers(route, scope, grpc, ref)
        self._auth_and_limits(route, scope, ref)

    def _tls(self, scope: _Scope, grpc: bool) -> tuple[TlsSpec, list[str]]:
        ssl = scope.grpc_ssl if grpc else scope.proxy_ssl
        tls = TlsSpec(verify=ssl.get("verify") == "on")
        problems: list[str] = []
        ca = ssl.get("trusted_certificate")
        if ca is not None:
            if "$" in ca or ca.startswith("data:") or not ca.strip():
                problems.append("backend TLS trusted CA uses a variable or inline data, which cannot be migrated")
            else:
                tls.ca_path = ca
        cert, key = ssl.get("certificate"), ssl.get("certificate_key")
        if cert is not None or key is not None:
            if not cert or not key:
                problems.append("backend TLS client certificate requires both certificate and key paths")
            elif "$" in cert or "$" in key or cert.startswith("data:") or key.startswith("data:") \
                    or not cert.strip() or not key.strip():
                problems.append("backend TLS client certificate uses a variable or inline data, which cannot be "
                                "migrated")
            else:
                tls.client_cert_path = cert
                tls.client_key_path = key
        ssl_name = ssl.get("name")
        if ssl_name is not None:
            if "$" in ssl_name or not ssl_name.strip():
                problems.append("backend TLS verification name (proxy_ssl_name/grpc_ssl_name) uses a variable or is "
                                "empty, which cannot be migrated")
            else:
                tls.sni = ssl_name.strip()
        return tls, problems

    def _upstream(self, name: str, tls: TlsSpec, scheme: str) -> str | None:
        key = f"{name}|{scheme}|{tls.key()}"
        if key in self.plan.upstreams:
            return key
        block = self.upstream_blocks[name]
        ref = f"nginx upstream '{safe_label(name)}' (line {block.line})"
        spec = UpstreamSpec(key=key, name=name, ref=ref, tls=tls)
        passive = None
        for directive in block.block or []:
            if directive.name == "server" and directive.args:
                flags = directive.args[1:]
                if any(flag in ("backup", "down") for flag in flags):
                    self.report.warning("nginx-upstream-backup", ref, "Backup/down servers are not migrated (Ferrum "
                                        "has no standby targets).")
                    continue
                if directive.args[0].startswith("unix:"):
                    self.report.error("nginx-upstream-unix", ref, "unix: socket upstream servers are not supported.")
                    return None
                parsed = util.split_host_port(directive.args[0], 80)
                if parsed is None:
                    return None
                weight = 1
                for flag in flags:
                    if flag.startswith("weight="):
                        weight = util.as_int(flag[7:]) or 1
                    elif flag.startswith("max_fails="):
                        fails = util.as_int(flag[10:]) or 0
                        if fails > 0:
                            passive = {"unhealthy_threshold": min(fails, 1000)}
                    elif flag.startswith("fail_timeout=") and passive is not None:
                        seconds = (util.parse_nginx_time_ms(flag[13:]) or 10_000) // 1000
                        passive["unhealthy_window_seconds"] = max(1, seconds)
                        passive["healthy_after_seconds"] = max(1, seconds)
                spec.targets.append(Target(parsed[0], parsed[1], weight))
            elif directive.name == "least_conn":
                spec.algorithm = "least_connections"
            elif directive.name == "ip_hash":
                spec.algorithm, spec.hash_on = "consistent_hashing", "ip"
            elif directive.name == "hash":
                if directive.args and directive.args[0] in ("$remote_addr", "$binary_remote_addr"):
                    spec.algorithm, spec.hash_on = "consistent_hashing", "ip"
                else:
                    self.report.warning("nginx-upstream-hash", ref, "hash key has no equivalent; using round robin.")
            elif directive.name == "random":
                spec.algorithm = "random"
            elif directive.name in ("keepalive", "keepalive_timeout", "keepalive_requests", "keepalive_time", "zone"):
                continue
            else:
                self.report.warning("nginx-upstream-directive", ref,
                                    f"Upstream directive {safe_label(directive.name, 40)} is not migrated.")
        if passive:
            spec.health_checks = {"passive": passive}
            self.report.warning("nginx-passive-health", ref, "max_fails/fail_timeout mapped approximately to passive "
                                "health checks.")
        self.plan.upstreams[key] = spec
        return key

    def _headers(self, route: RouteSpec, scope: _Scope, grpc: bool, ref: str) -> None:
        entries = scope.arrays.get("grpc_set_header" if grpc else "proxy_set_header", [])
        request_rules: list[dict] = []
        for entry in entries:
            if len(entry) != 2:
                route.refuse("malformed proxy_set_header")
                continue
            name, value = entry
            lower = name.lower()
            if lower == "host":
                if value in ("$host", "$http_host"):
                    route.preserve_host = True
                elif value not in ("$proxy_host", "$upstream_addr"):
                    self.report.warning("nginx-host-override", ref, "A custom Host header is not representable; Ferrum "
                                        "sends the selected target's authority.")
                continue
            if lower in ("x-forwarded-for", "x-forwarded-proto", "x-forwarded-host", "x-forwarded-port", "forwarded"):
                self.report.info("nginx-forwarded-headers", ref, "X-Forwarded-* headers are set by Ferrum itself.")
                continue
            if lower == "x-real-ip":
                self.report.warning("nginx-x-real-ip", ref, "X-Real-IP is not reproduced; backends should read "
                                    "X-Forwarded-For set by Ferrum.")
                continue
            if lower in ("connection", "upgrade"):
                self.report.info("nginx-websocket-headers", ref, "WebSocket upgrades are detected automatically.")
                continue
            if value == "":
                rule, problem = request_header_rule("remove", name)
            else:
                translated = _header_value(value)
                if translated is None:
                    route.refuse(f"proxy_set_header {safe_label(name, 40)} uses variables Ferrum cannot reproduce")
                    continue
                rule, problem = request_header_rule("update", name, translated)
            if problem:
                route.refuse(problem)
            else:
                request_rules.append(rule)
        response_rules: list[dict] = []
        for entry in scope.arrays.get("add_header", []):
            if len(entry) < 2 or "$" in entry[1]:
                self.report.warning("nginx-add-header", ref, "An add_header with variables was not migrated.")
                continue
            rule, problem = response_header_rule("update", entry[0], literal_value(entry[1]))
            if rule:
                response_rules.append(rule)
                if len(entry) < 3 or entry[2] != "always":
                    self.report.warning("nginx-add-header-always", ref, "add_header applied only to 2xx/3xx in NGINX; "
                                        "Ferrum sets it on every response.")
            else:
                self.report.warning("nginx-add-header", ref, f"add_header not migrated ({problem}).")
        for entry in scope.arrays.get("proxy_hide_header", []):
            if entry:
                rule, _problem = response_header_rule("remove", entry[0])
                if rule:
                    response_rules.append(rule)
        if request_rules:
            route.plugins.append(PluginSpec("request_transformer", {"rules": request_rules}, ref))
        if response_rules:
            route.plugins.append(PluginSpec("response_transformer", {"rules": response_rules}, ref))

    def _auth_and_limits(self, route: RouteSpec, scope: _Scope, ref: str) -> None:
        if scope.auth_basic and scope.auth_basic != "off":
            route.plugins.append(PluginSpec("basic_auth", {"hide_credentials": False}, ref))
            self.report.error("nginx-basic-auth", ref, "auth_basic is emitted fail-closed: htpasswd files are never "
                              "read, so nobody can authenticate until Ferrum credentials exist.",
                              "Create consumers with hmac_sha256 Basic credentials and export "
                              "FERRUM_BASIC_AUTH_HMAC_SECRET_FILE.")
        for entry in scope.arrays.get("limit_req", []):
            zone_name = next((arg[5:] for arg in entry if arg.startswith("zone=")), None)
            zone = self.zones.get(zone_name or "")
            if zone is None:
                route.refuse("limit_req references an unknown zone")
                continue
            limit_by = {"$binary_remote_addr": "ip", "$remote_addr": "ip", "$server_name": "service",
                        "$host": "service"}.get(zone["key"])
            rate = re.fullmatch(r"(\d+)r/([sm])", zone["rate"] or "")
            if limit_by is None or rate is None or int(rate.group(1)) <= 0:
                route.refuse("limit_req zone key or rate has no Ferrum equivalent")
                continue
            window = "requests_per_second" if rate.group(2) == "s" else "requests_per_minute"
            config = {"limit_by": limit_by, "limits": [{"scope": "default", window: int(rate.group(1))}]}
            route.plugins.append(PluginSpec("rate_limiting", config, ref, shared_key=f"zone-{zone_name}"))
            self.report.warning("nginx-limit-req", ref, "limit_req burst/delay semantics differ: Ferrum enforces the "
                                "same average rate with its own bucket behavior.")
        if scope.gzip == "on":
            content_types: list[str] | None = ["text/html"]
            omit_gzip = False
            if scope.gzip_proxied != ["any"]:
                self.report.warning("nginx-gzip", ref,
                                    "gzip omitted: NGINX gzip_proxied defaults to 'off' (skipping requests with a "
                                    "Via header) and Ferrum compression cannot reproduce proxied-request exclusions "
                                    "(only explicit 'gzip_proxied any' is migrated).")
                omit_gzip = True
            elif scope.gzip_http_version != "1.0":
                self.report.warning("nginx-gzip", ref,
                                    "gzip omitted: NGINX gzip_http_version defaults to 1.1 (skipping HTTP/1.0 "
                                    "requests) whereas Ferrum compression compresses HTTP/1.0 responses too (only "
                                    "explicit 'gzip_http_version 1.0' is migrated).")
                omit_gzip = True
            elif scope.gzip_disable:
                self.report.warning("nginx-gzip", ref,
                                    "gzip omitted: gzip_disable User-Agent exclusions have no Ferrum equivalent.")
                omit_gzip = True
            elif scope.gzip_types is not None:
                if any("*" in item for item in scope.gzip_types):
                    self.report.warning("nginx-gzip", ref,
                                        "gzip omitted: wildcard gzip_types entries ('*' or 'type/*') cannot be "
                                        "mapped safely (NGINX treats 'type/*' as a literal MIME key whereas Ferrum "
                                        "treats it as a range, and rejects '*/*').")
                    omit_gzip = True
                else:
                    candidate = ["text/html"] + [t for t in scope.gzip_types if t.lower() != "text/html"]
                    built_check, problem = compression_config(["gzip"], content_types=candidate)
                    if built_check is not None:
                        content_types = built_check["content_types"]
                    else:
                        self.report.warning("nginx-gzip", ref,
                                            f"gzip omitted: gzip_types could not be represented ({problem}).")
                        omit_gzip = True
            if not omit_gzip:
                # NGINX defaults gzip_min_length to 20 bytes, gzip_comp_level to 1, weakens strong ETags when
                # compressing, and leaves inbound Accept-Encoding intact for proxy_pass upstreams.
                comp_cfg, comp_problem = compression_config(
                    ["gzip"],
                    min_content_length=scope.gzip_min_length if scope.gzip_min_length is not None else 20,
                    content_types=content_types,
                    gzip_level=scope.gzip_comp_level if scope.gzip_comp_level is not None else 1,
                    remove_accept_encoding=False,
                    weaken_strong_etag=True,
                )
                if comp_cfg is not None:
                    route.plugins.append(PluginSpec("compression", comp_cfg, ref))
                    self.report.warning("nginx-gzip", ref,
                                        "NGINX only gzips HTTP 200, 403, and 404 responses, whereas Ferrum "
                                        "compression also compresses eligible responses with other body-bearing "
                                        "status codes (such as 500). Ferrum also returns HTTP 406 when "
                                        "Accept-Encoding excludes identity and no acceptable coding can be produced "
                                        "(e.g. 'br, identity;q=0', or a response below min_content_length / "
                                        "non-whitelisted MIME type / no-transform under 'gzip, identity;q=0'), "
                                        "whereas NGINX forwards the unencoded response. Under Ferrum's default "
                                        "10 MiB response ceiling, eligible chunked/unknown-length responses are still "
                                        "compressed; if FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES is set to 0 or above "
                                        "32 MiB, Ferrum skips unknown-length responses lacking Content-Length "
                                        "(serving identity, or 406 when identity is excluded).")
                else:
                    self.report.warning("nginx-gzip", ref, f"gzip omitted ({comp_problem}).")
        size = scope.body_size if scope.body_size is not None else 1024 * 1024
        self.body_sizes.append((route, size))

    def _finish_body_sizes(self) -> None:
        live = [(route, size) for route, size in self.body_sizes if not route.refusals]
        if not live:
            return
        if any(size == 0 for _, size in live):
            self.report.warning("nginx-body-unlimited", "nginx client_max_body_size",
                                "Some locations allowed unlimited bodies; Ferrum's global default body limit applies "
                                "to them.")
            ceiling = max((size for _, size in live if size), default=0)
            if not ceiling:
                return
        else:
            ceiling = max(size for _, size in live)
        self.plan.settings.max_request_body_bytes = ceiling
        for route, size in live:
            if 0 < size < ceiling:
                route.plugins.append(PluginSpec("request_size_limiting", {"max_bytes": size}, route.ref))


# ------------------------------------------------------------------ helpers

def _parse_listen(args: list[str]) -> dict | None:
    target = args[0]
    flags = set(args[1:])
    if target.startswith("unix:"):
        return None
    addr: str | None
    if target.isdigit():
        addr, port = None, int(target)
    elif target.startswith("["):
        end = target.find("]")
        if end < 0:
            return None
        addr = target[1:end]
        rest = target[end + 1:]
        port = int(rest[1:]) if rest.startswith(":") and rest[1:].isdigit() else 80
    elif ":" in target:
        addr, _, port_text = target.rpartition(":")
        if not port_text.isdigit():
            return None
        port = int(port_text)
    else:
        addr, port = target, 80
    if not 1 <= port <= 65535:
        return None
    family = "v6" if target.startswith("[") else "v4"
    if addr in ("*", "0.0.0.0", "::", ""):
        addr = None
    return {"addr": addr, "port": port, "family": family, "ssl": "ssl" in flags or "quic" in flags,
            "default": "default_server" in flags or "default" in flags, "flags": flags,
            "http3": "quic" in flags, "proxy_protocol": "proxy_protocol" in flags}


def _server_hosts(names: list[str]) -> tuple[list[str], str | None]:
    hosts: list[str] = []
    for name in names:
        if name in ("_", ""):
            continue
        if name.startswith("~"):
            return [], "regex server_name"
        if name.startswith("."):
            hosts.extend([name[1:], "*" + name])
        elif name.endswith(".*") or ("*" in name and not name.startswith("*.")):
            return [], "trailing or embedded wildcard"
        else:
            hosts.append(name)
    return hosts, None


def _is_https_redirect(args: list[str]) -> bool:
    return len(args) == 2 and args[0] in ("301", "302", "307", "308") and args[1].startswith("https://")


def _is_https_redirect_termination(termination: dict) -> bool:
    location = mapping_get(termination, "headers", "location")
    return termination.get("status_code") in (301, 302, 307, 308) and isinstance(location, str) \
        and location.startswith("https://")


def mapping_get(data: dict, *keys: str):
    for key in keys:
        if not isinstance(data, dict):
            return None
        data = data.get(key)
    return data


def _is_https_redirect_if(directive: Directive) -> bool:
    condition = " ".join(directive.args)
    if condition not in ("($scheme = http)", "($scheme != https)", "($scheme != \"https\")", "($scheme = \"http\")",
                         "($scheme != 'https')"):
        return False
    body = directive.block or []
    return len(body) == 1 and body[0].name == "return" and len(body[0].args) == 2 \
        and body[0].args[0] in ("301", "302", "307", "308") and body[0].args[1].startswith("https://")


def _nginx_regex(pattern: str, case_insensitive: bool) -> str | None:
    if util.has_top_level_alternation(pattern):
        return None
    body = pattern
    anchored_start = body.startswith("^")
    if anchored_start:
        body = body[1:]
    anchored_end = util.ends_with_unescaped_dollar(body)
    if anchored_end:
        body = body[:-1]
    if not anchored_start:
        body = ".*" + body
    if not anchored_end:
        body += ".*"
    if case_insensitive:
        body = "(?i)" + body
    return body


def _header_value(value: str) -> str | None:
    if "$" not in value:
        return value
    if value == "$remote_addr":
        return "$(client_ip)"
    if value == "$request_id":
        return "$(request_id)"
    match = re.fullmatch(r"\$http_([a-z0-9_]+)", value)
    if match:
        name = match.group(1).replace("_", "-")
        if is_sensitive_header(name):
            return None
        return f"$(header.{name})"
    return None


def _cidr_overlaps(a: str, b: str) -> bool:
    try:
        net_a = ipaddress.ip_network(a, strict=False)
        net_b = ipaddress.ip_network(b, strict=False)
    except ValueError:
        return True
    return net_a.version == net_b.version and net_a.overlaps(net_b)


def _access_policy(entries: list[list[str]]) -> tuple[dict | None, bool, list[str], str | None]:
    """Translate effective allow/deny rules (first match wins in NGINX) without loosening them."""
    ordered = [(entry[0], entry[1]) for entry in entries if len(entry) >= 2]
    allow: list[str] = []
    deny: list[str] = []
    terminal = None
    notes: list[str] = []
    for action, value in ordered:
        if terminal:
            notes.append("allow/deny rules after an 'all' rule are unreachable in NGINX and were ignored")
            break
        if value == "all":
            terminal = action
            continue
        if value.startswith("unix:"):
            continue
        cidr = util.canonical_cidr(value)
        if cidr is None:
            return None, False, notes, "an allow/deny entry is not an IP address or CIDR"
        if action == "allow":
            allow.append(cidr)
        else:
            if any(_cidr_overlaps(cidr, existing) for existing in allow):
                notes.append("an allow rule precedes an overlapping deny rule; Ferrum lets the deny rule win (stricter)")
            deny.append(cidr)
    if terminal == "deny":
        if not allow:
            return None, True, notes, None
        config: dict = {"allow": allow}
        if deny:
            config["deny"] = deny
        return config, False, notes, None
    if allow and deny:
        notes.append("allow rules without a final 'deny all' only act as exceptions; Ferrum applies the deny rules to "
                     "those clients as well (stricter)")
    return ({"deny": deny} if deny else None), False, notes, None


def _check_precedence(routes: list[RouteSpec]) -> None:
    regexes = [r for r in routes if r.kind == "regex"]
    prefixes = [r for r in routes if r.kind == "prefix" and not getattr(r, "caret", False)]
    for regex in regexes:
        for prefix in prefixes:
            if matching.spaces_overlap(matching.path_space("regex", regex.path),
                                       matching.path_space("prefix", prefix.path)):
                reason = ("this server mixes regex locations with overlapping prefix locations; NGINX lets the regex "
                          "win and Ferrum lets the prefix win, so the whole server is refused")
                for route in routes:
                    route.refuse(reason)
                return


def translate(text: str, fmt: str, ctx: SourceContext) -> Plan:
    if fmt not in ("nginx", "auto"):
        raise InputError("NGINX input must be nginx configuration syntax")
    return _Nginx(text, ctx).run()
