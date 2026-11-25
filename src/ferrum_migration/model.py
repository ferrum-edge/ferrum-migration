"""Platform-neutral intermediate representation produced by source translators."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TlsSpec:
    """Backend TLS posture. ``verify=False`` records that the *source* did not verify."""

    verify: bool = True
    ca_path: str | None = None
    client_cert_path: str | None = None
    client_key_path: str | None = None
    sni: str | None = None
    san_allow_list: list[str] = field(default_factory=list)

    def key(self) -> str:
        return "|".join([
            "v" if self.verify else "nv", self.ca_path or "", self.client_cert_path or "",
            self.client_key_path or "", self.sni or "", ",".join(self.san_allow_list),
        ])


@dataclass
class Target:
    host: str
    port: int
    weight: int = 1


@dataclass
class UpstreamSpec:
    key: str
    name: str
    ref: str
    targets: list[Target] = field(default_factory=list)
    algorithm: str = "round_robin"
    hash_on: str | None = None
    hash_on_cookie_config: dict | None = None
    health_checks: dict | None = None
    tls: TlsSpec = field(default_factory=TlsSpec)


@dataclass
class BackendRef:
    scheme: str
    host: str | None = None
    port: int | None = None
    upstream_key: str | None = None
    tls: TlsSpec = field(default_factory=TlsSpec)


@dataclass
class PluginSpec:
    """A Ferrum plugin instance. ``shared_key`` makes it a shared proxy_group instance."""

    name: str
    config: dict
    ref: str = ""
    shared_key: str | None = None


@dataclass
class RouteSpec:
    """One Ferrum proxy candidate.

    ``kind`` is ``prefix``, ``exact``, ``regex`` (Ferrum pattern, auto-anchored)
    or ``hostonly``. ``hosts=None`` means the source host match is not
    representable. ``extra_conditions`` means the source matched on something
    Ferrum cannot express (headers, queries, SNI...), so the route is refused
    and every overlapping route is refused with it.

    ``report_prefix_siblings`` (opt-in per source) makes the emitter raise a
    review error when a string-prefix route's sibling paths (``/apix`` for
    ``/api``) would not reach an equivalent route in Ferrum, instead of letting
    them silently become 404s.

    ``client_cas`` lists the frontend client CA bundle file paths whose verified
    client certificates the source required for this route's TLS traffic (empty:
    no client certificate required). Sources never configure the listener-wide
    bundle themselves: the emitter sets ``SettingsHints.client_ca_paths`` only
    when one bundle provably preserves every route's original trust scope.

    ``case_insensitive`` records that the source matched this route's literal
    (prefix or exact) path case-insensitively (Envoy ``case_sensitive: false``,
    Istio ``ignoreUriCase``). Ferrum matches paths case-sensitively, so the
    emitted route only receives the exact-case path; the emitter refuses every
    other route that could receive the case variants the source sent here.
    Overlap and coverage checks fold case for such routes and never apply the
    segment/exact disjointness proof to them.

    ``protocols`` is the set of source main frontends (``"http"``: the main
    plaintext listener, ``"https"``: the main TLS listener) on which the source
    served exactly this route's match and policy for every one of its hosts.
    ``None`` means unknown. Ferrum serves every emitted route on every listener
    its profile opens, so the emitter only opens protocols that every live route
    was served on; unknown metadata never proves isolation. ``requires_tls``
    always removes ``"http"``.
    """

    ref: str
    name: str
    hosts: list[str] | None = field(default_factory=list)
    kind: str = "prefix"
    path: str | None = "/"
    prefix_semantics: str = "string"
    report_prefix_siblings: bool = False
    methods: list[str] | None = None
    listen_port: int | None = None
    requires_tls: bool = False
    backend: BackendRef | None = None
    backend_path: str | None = None
    strip: bool = False
    preserve_host: bool = False
    connect_timeout_ms: int | None = None
    read_timeout_ms: int | None = None
    write_timeout_ms: int | None = None
    retry: dict | None = None
    plugins: list[PluginSpec] = field(default_factory=list)
    termination: dict | None = None
    refusals: list[str] = field(default_factory=list)
    extra_conditions: bool = False
    client_cas: list[str] = field(default_factory=list)
    case_insensitive: bool = False
    protocols: frozenset[str] | None = None
    skip: bool = False
    skip_reason: str = ""
    https_redirect_fold: tuple[str, str] | None = None
    # Maintained by the emitter.
    path_ok: bool = True
    trailing_slash: bool = False
    placeholder_emitted: bool = False

    def refuse(self, reason: str) -> None:
        if reason not in self.refusals:
            self.refusals.append(reason)


@dataclass
class ConsumerSpec:
    ref: str
    key: str
    username: str
    custom_id: str | None = None
    acl_groups: list[str] = field(default_factory=list)
    #: Plaintext API keys; only populated with explicit --include-secrets.
    keyauth: list[str] = field(default_factory=list)
    #: HMAC JWT secrets; only populated with explicit --include-secrets.
    jwt: list[str] = field(default_factory=list)
    #: Non-sensitive source metadata preserved as Ferrum consumer labels (e.g., Kong tags).
    labels: dict[str, str] = field(default_factory=dict)
    withheld_secrets: int = 0
    quarantined: list[str] = field(default_factory=list)


@dataclass
class HostScope:
    """A source scope that never falls through to other hosts' routes (server/vhost)."""

    ref: str
    hosts: list[str]
    listen_port: int | None = None
    protocols: frozenset[str] | None = None


@dataclass
class SettingsHints:
    main_http_port: int | None = None
    main_https_port: int | None = None
    bind_address: str | None = None
    frontend_cert_pairs: list[tuple[str, str]] = field(default_factory=list)
    #: Set by the emitter only: at most one bundle, and only when it preserves every route's trust scope.
    client_ca_paths: list[str] = field(default_factory=list)
    #: Set by the emitter when per-scope client CA trust could not be established on one shared listener.
    client_ca_scope_conflict: bool = False
    trusted_proxies: list[str] = field(default_factory=list)
    real_ip_header: str | None = None
    proxy_protocol: bool = False
    http3: bool = False
    max_request_body_bytes: int | None = None
    https_redirect_seen: bool = False
    frontend_tls_expected: bool = False
    #: Set by the emitter only: the Ferrum listeners the profile must open, ``"http"``, ``"https"`` or ``"both"``.
    frontend_protocols: str | None = None


@dataclass
class Plan:
    platform: str
    routes: list[RouteSpec] = field(default_factory=list)
    upstreams: dict[str, UpstreamSpec] = field(default_factory=dict)
    consumers: list[ConsumerSpec] = field(default_factory=list)
    global_plugins: list[PluginSpec] = field(default_factory=list)
    global_refusals: list[str] = field(default_factory=list)
    host_scopes: list[HostScope] = field(default_factory=list)
    settings: SettingsHints = field(default_factory=SettingsHints)
