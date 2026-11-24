# Mappings

All Ferrum facts below were checked against Ferrum Edge `main` at
`c1d73c35ef2e61a2c58c7a62a08ea70e35fff924`: `src/config/types.rs` (`Proxy`, `Upstream`,
`Consumer`, `PluginConfig`, `GatewayConfig`, all `deny_unknown_fields`), the plugin
constructors in `src/plugins/*.rs` (closed key sets), `src/consumer_index.rs`,
`src/router_cache.rs`, `docs/routing.md`, `docs/request_path_canonicalization.md`,
`docs/cli.md`, `src/config/file_loader.rs` and `src/config/public_env_inventory.rs`.
`tests/test_ferrum_reference.py` re-checks emitted keys against that source when it is available.

## Ferrum facts the tool relies on

| Fact | Source |
|---|---|
| Prefix `listen_path` matching walks the request path back through **segment boundaries**; `=` is exact, `~` is a fully anchored regex, and host-only proxies are the last fallback in each host tier. Host tiers: exact > wildcard > catch-all, falling through when a tier has no match. | `router_cache.rs`, `docs/routing.md` |
| `listen_port` only ranks candidates that share a host/path slot: a port-agnostic proxy serves any HTTP frontend (losing only to a same-slot port-scoped sibling), and the reference source also remaps a single same-class listen port onto another frontend. The tool therefore never emits `listen_port` (see `extra-listener-refused`). | `router_cache.rs` (`port_match_priority`) |
| Auth mode `single` (default) runs auth plugins in priority order and rejects on the first failure; `multi` stops at the first success. Principal state (claim headers, identity metadata) belongs to the first accepted attempt; later accepted instances cannot replace it. The tool never combines several auth methods on one proxy (Kong `kong-auth-composition`). | `docs/functional_testing_auth_acl.md`, `src/plugins/utils/auth_attempt.rs` |
| Scoped (proxy/proxy_group) plugins replace global plugins of the same name. | `FEATURES.md` (plugin scopes) |
| Literal listen paths are looked up as exact strings (hash-indexed by `listen_path`), so path matching is treated as case-sensitive. If Ferrum ever folded case, the tool's handling of case-insensitive source matches would only be stricter. | `router_cache.rs` (`IndexedPrefixRoutes`, `IndexedExactPathRoutes`) |
| Literal listen paths must be canonical: no `%`, `\`, dot segments, empty segments, or `;` without `allow_path_parameters`. | `docs/request_path_canonicalization.md` |
| `strip_listen_path` defaults to true; backends default to `https` when `backend_scheme` is omitted. The tool always sets both. | `types.rs` |
| `request_termination` runs at priority 125 in `on_request_received`, before auth, and supports `trigger.path_prefix`. | `src/plugins/request_termination.rs` |
| `key_auth` keys need at least 16 non-whitespace characters; `jwt_auth` secrets need at least 32; shared JWT secrets are quarantined; `jwt_auth` resolves the consumer from one claim by username, id or custom_id; the algorithm is pinned per plugin (HS256/384/512). | `types.rs`, `jwt_auth.rs`, `consumer_index.rs` |
| `basic_auth` verifies only `hmac_sha256:<hex>` hashes keyed by `FERRUM_BASIC_AUTH_HMAC_SECRET`, and refuses to construct without that secret. | `basic_auth.rs` |
| `access_control` refuses explicitly empty allow-lists and requires at least one rule. | `access_control.rs` |
| `rate_limiting` takes one `scope: default` rule with `requests_per_second/minute/hour` presets **or** one `window_seconds` + `max_requests`; `limit_by` is `ip`, `consumer`, `spiffe_identity` or `service`. | `rate_limiting.rs` |
| `request_transformer` header `add` is add-if-absent, `update` always sets, `remove` drops; Ferrum-owned headers (Host, X-Forwarded-*, `x-consumer-*`, ...) cannot be set; `$(` starts a template (`$$(` is literal). | `request_transformer.rs` |
| `ip_restriction` keys are `allow`/`deny` (canonical IPs or CIDRs); a deny match always wins. | `ip_restriction.rs` |
| A top-level `resource_counts` seal is accepted and stripped by the file loader. | `file_loader.rs` |
| The plaintext proxy listener is open (default 8000) unless `FERRUM_PROXY_HTTP_PORT=0`. The HTTPS proxy listener opens on its default port (8443) whenever frontend TLS material is configured, and `FERRUM_PROXY_HTTPS_PORT=0` disables it even then. Port-agnostic routes serve every open listener, so the profile opens only protocols every live route was served on in the source (`frontend-https-disabled`, `frontend-protocol-scope`). | `ferrum.conf` template, `docs/configuration.md` |
| `ferrum-edge validate -m file -c <spec>` runs the real admission pipeline. | `docs/cli.md` |
| `backend_read_timeout_ms` (v0.9.21) is one budget covering the wait for response headers, idle time between streamed response frames, and the total time to send a buffered client request body. No source read timeout means exactly that, so every projected timeout is an **approximation** (report warning `timeout-approximate`): the number in milliseconds carries over, the semantics do not. | Ferrum Edge v0.9.21 |

## Kong Gateway (DB-less / decK)

| Kong | Ferrum | Notes |
|---|---|---|
| service `url` / `protocol`, `host`, `port`, `path` | `backend_scheme`/`backend_host`/`backend_port`, `backend_path` | grpc/ws → http, grpcs/wss → https; tcp/tls/udp refused |
| service host naming an upstream | `upstream_id` | one Ferrum upstream per (upstream, TLS posture) |
| `connect/read/write_timeout`, `retries` | `backend_*_timeout_ms`, `retry` (connect failures) | timeouts approximate: Kong read/write timeouts are idle bounds between two successive operations |
| `tls_verify` absent/false | verification **on** (warning) | no opt-out; insecure backend TLS is never emitted |
| https service with `ca_certificates` | **refused** (placeholder, error `kong-ca-certificates`) | the restricted backend trust set is never copied, and Ferrum's default trust store would trust more issuers; provision the CA file manually and set `backend_tls_server_ca_cert_path` |
| route `paths` (one proxy per path), `hosts`, `methods`, `strip_path`, `preserve_host` | `listen_path`, `hosts`, `allowed_methods`, `strip_listen_path`, `preserve_host_header` | `~regex` paths become anchored Ferrum regexes; regex + `strip_path` refused. Literal paths are string prefixes in Kong's traditional and traditional_compatible routers, so `/api` also matched `/apix`. The path is never widened; when such siblings do not reach an equivalent route in Ferrum (always the case with `strip_path: true`), the route gets a `prefix-string-siblings` error |
| route `headers`, `snis`, `expression`, `sources/destinations` | refused + overlap poisoning | |
| `protocols: [https]` only | emitted only in TLS-only mode | route `protocols` are the route's source frontends: `[http]` only routes are refused in TLS-only mode, and keep HTTPS disabled otherwise |
| upstream targets/weights, algorithm, `hash_on` ip/header/cookie, healthchecks | targets, `weighted_round_robin`/`least_connections`/`least_latency`/`consistent_hashing`, `hash_on`, `health_checks` (approximate) | weight 0 targets dropped; default target port 8000 |
| `key-auth` (`key_names` × header/query) | `key_auth.key_location` (max 8) | `anonymous` and body keys are not supported (stricter) |
| `basic-auth` | `basic_auth` without credentials (fail closed) | password hashes are not convertible |
| `jwt` (HS*) | `jwt_auth` (`consumer_claim_field` = `key_claim_name`, algorithm pinned) | `maximum_expiration`, `secret_is_base64` refused; query/cookie tokens dropped (stricter) |
| several of `key-auth`, `basic-auth`, `jwt` in one route's effective policy (global plugins not replaced by a same-name service/route plugin, plus service and route plugins) | **refused** (placeholder, error `kong-auth-composition`) | Kong requires all of them (or any one with `anonymous`) and authenticates the consumer of the plugin that runs last; Ferrum commits the first accepted principal. One method per route is migrated as before |
| `acl` allow/deny | `access_control` allowed/disallowed groups | `include_consumer_groups` refused |
| `rate-limiting` second/minute/hour, limit_by consumer/ip/service | `rate_limiting` presets | day/month/year and other `limit_by` refused; cluster/redis policy is reported as an error (per-node in Ferrum) |
| `cors` | `cors` | regex origins → omitted (browsers block) |
| `ip-restriction` | `ip_restriction` | |
| `request-size-limiting` | `request_size_limiting.max_bytes` | |
| `request-transformer` remove/rename/add (headers, querystring) | `request_transformer` rules | replace/append/body/uri/http_method and Kong templates refused |
| `response-transformer` remove/rename/add headers | `response_transformer` | other parts omitted (warning) |
| `request-termination` (no trigger/echo), `redirect` (static) | `request_termination` | Ferrum answers before auth |
| logging/metrics/tracing plugins | omitted (info) | configure Ferrum observability separately |
| any other plugin (oauth2, openid-connect, hmac-auth, pre-function, …) | **refused** (placeholder; global → every route refused) | |
| consumers: username/custom_id, `acls`, `keyauth_credentials`, HMAC `jwt_secrets` | consumers, `acl_groups`, `credentials.keyauth` (only with `--include-secrets`) | consumer-scoped plugins and consumer groups quarantine the consumer; with `_transform: false` keys are stored values and are never migrated. HMAC JWT secrets are **never** written, even with `--include-secrets` and even for a single credential (`kong-jwt-credential-withheld`; several credentials: `kong-jwt-multiple-credentials`). Kong selects the credential by its exact `key`, while Ferrum's `jwt_auth` resolves the claim against every consumer alias (username, id, custom_id) and accepts the consumer-wide secret, so no one-to-one selector contract exists. The route's `jwt_auth`, the consumer and its key-auth credentials are still migrated (JWT authentication fails closed). Follow-up: issue a new random HMAC secret (at least 32 characters) per consumer in Ferrum and have clients sign with a claim that names exactly that consumer; keep the Kong credential until clients switch |
| DB-less `kong.yml` vs decK dump | same translation (`--from kong`, no extra flag) | report `kong-input-flavor` states which was detected (decK metadata `_info`/`_konnect`/`_workspace`) |
| certificates, vaults, ca_certificates | not copied (warning/error) | provide frontend cert paths in `ferrum.conf` |

Representative output (abridged) for `tests/fixtures/kong/kong.yaml`:

```yaml
proxies:
  - id: kong-orders-api
    listen_path: /orders
    allowed_methods: [GET, POST]
    backend_scheme: http
    backend_host: orders.internal
    backend_port: 8080
    backend_path: /v1
    strip_listen_path: true
    plugins: [{plugin_config_id: kong-group-service-orders-key-auth}, ...]
  - id: kong-legacy-admin-refused          # oauth2 is untranslatable -> 503 placeholder
    listen_path: /admin
    backend_host: ferrum-migration-refused.invalid
    plugins: [{plugin_config_id: kong-legacy-admin-refused-terminate}]
  - id: kong-legacy-root
    listen_path: /
    plugins: [{plugin_config_id: kong-legacy-root-guard}, ...]   # path_prefix /orders and /admin guards
```

## NGINX OSS

| NGINX | Ferrum | Notes |
|---|---|---|
| `server` + `listen` + `server_name` | `hosts`; default server → catch-all | regex/trailing-wildcard names refused; `.example.com` → `example.com` + `*.example.com`. A default server whose own name another server on the same listener covers (same name or a wildcard) keeps its named hosts instead, because a catch-all would lose those names to the other server; unknown names are then not routed to it (error `nginx-default-server-named`). Default roles count only on the listeners Ferrum serves (not on dropped extra ports); default on only some of them → named hosts only (`nginx-default-server-listener`); different defaults on the main plaintext and TLS listeners → their catch-all routes refused (`nginx-default-server-conflict`). Nested wildcard servers → the broader server's routes refused (`nested-wildcard-scope`) |
| main plaintext/TLS ports | `FERRUM_PROXY_HTTP(S)_PORT` | a server listening only on another plaintext port is **not migrated** (`extra-listener-refused`; a `listen_port` route cannot be isolated from the main routes); extra ports of a main-port server are dropped (stricter); other TLS ports and conflicting bind addresses skipped (error) |
| HTTPS redirect server / `if ($scheme = http) { return 301 https://… }` | TLS-only profile | |
| `location /p`, `^~ /p`, `= /p`, `~`/`~*` | prefix, prefix, exact, anchored regex (`(?i)`) | overlapping regex + non-`^~` prefix → whole server refused; `/p` is never widened, and when sibling paths such as `/px` (string-prefix matches) do not reach an equivalent route in Ferrum, the location gets a `prefix-string-siblings` error (exit 4). NGINX never sends `^~ /p` siblings (`/px.php`) to a regex location, so such a regex route gets a `trigger.path_prefix /p` guard |
| `proxy_pass` with/without URI, `grpc_pass` | strip + `backend_path` / no strip | variables, unix sockets refused |
| `proxy_connect_timeout`, `proxy_read_timeout`, `proxy_send_timeout` (and `grpc_*`) | `backend_connect_timeout_ms`, `backend_read_timeout_ms`, `backend_write_timeout_ms` | approximate: NGINX read/send timeouts are idle bounds between two successive operations |
| `send_timeout` (downstream, to the client) | not migrated (ignored) | set Ferrum's `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS` manually if needed |
| `upstream` servers/weights, `least_conn`, `ip_hash`, `hash $remote_addr`, `random`, `max_fails`/`fail_timeout` | upstream targets, algorithms, passive health (approximate) | `backup`/`down` servers dropped |
| `proxy_set_header Host $host` | `preserve_host_header: true` | other static headers → `request_transformer` update; `$remote_addr`/`$request_id`/`$http_x` → templates |
| `add_header`, `proxy_hide_header` | `response_transformer` update/remove | variables dropped (warning) |
| `allow`/`deny` (first match wins) | `ip_restriction` (never looser; warnings when stricter) | location with only `deny all` → 403 termination |
| `return` (static) | `request_termination` | 444 → 403 |
| `auth_basic` | `basic_auth` without credentials (fail closed) | htpasswd never read |
| `limit_req` + `limit_req_zone` (`$binary_remote_addr`, `$server_name`) | `rate_limiting` (shared per zone) | burst/delay differ (warning) |
| `client_max_body_size` (default 1m) | `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` = largest; smaller → `request_size_limiting` | |
| `ssl_certificate(_key)`, `ssl_client_certificate` + `ssl_verify_client` (server or inherited from `http`), `ssl_crl`/`ssl_ocsp`, `ssl_reject_handshake` | frontend TLS paths, client CA | one listener-wide client CA only when every mTLS server on the main TLS port uses the same file; different files → affected routes refused (`frontend-client-ca-scope`), never concatenated; `ssl_verify_client` without a client CA file or with `ssl_crl`/`ssl_ocsp` → refused (`nginx-client-ca`); `ssl_reject_handshake on` refuses affected HTTPS routes (or all HTTPS routes when set on the default TLS server; `nginx-ssl-reject-handshake`) |
| `include` (except `mime.types`, Debian `proxy_params`), `if`, `rewrite`, `auth_request`, `satisfy any`, unknown directives | containing location/server refused | |

## Traefik OSS (file provider)

| Traefik | Ferrum | Notes |
|---|---|---|
| typed field names (canonical spelling as Traefik documents it: `http`, `tls`, `routers`, `rule`, `middlewares`, `options`, `clientAuth`, `caFiles`, `sniStrict`, `loadBalancer`, `serversTransport`, `rootCAs`, middleware type keys such as `chain`, `headers`, `basicAuth`, and so on) | read only under the canonical spelling | Traefik's file provider matches typed field names case-insensitively. A typed field spelled in another letter case, or given more than once in different letter case, **rejects the whole input** (exit 3, nothing written), with or without the operator statement. Checked: top level, `http`, `tls` (certificates, options including `clientAuth`, stores), routers and their `tls`, services (load balancer, servers, sticky, health check, weighted, mirroring), `serversTransports` (including `forwardingTimeouts`), the middleware type key and the configuration of every translated middleware type. The error lists canonical paths only (`http.routers.<name>.tls`). Resource names (routers, services, middlewares, `serversTransports`, TLS options, stores) are case-sensitive and never folded |
| router `parentRefs` (v3.6 multi-layer routing) | absent or exactly `[]`: ordinary root router. Anything else: **rejects the whole input** (exit 3, nothing written) | a router with parent references runs inside its parents' muxer in Traefik, after the parents' middlewares and under their entryPoint and TLS constraints; inherited routing is not translated, so a child is never projected as an independent root route. Checked on every router of the input as written (also routers without a rule or with an unparseable or unsatisfiable rule), right after the canonical spelling check and before any route, report entry or profile setting is built, with or without the operator statement. A nonempty list, an explicit null and any other shape (string, mapping, list with non-string or empty items) all reject. The error carries the canonical path `http.routers.<name>.parentRefs` and a count only. Other spellings are rejected by the canonical spelling check |
| `rule` with `Host`, `HostHeader`, `Path`, `PathPrefix`, `Method` (`&&`, `||`, parentheses; v2 multi-arg) | one proxy per DNF alternative group | `Header*`, `Query*`, `ClientIP`, `*Regexp`, negation → refused + poisoning. `PathPrefix` is a string prefix (`/api` also matched `/apix`): never widened, `prefix-string-siblings` error when such siblings do not reach an equivalent route. `Path` and prefixes ending in `/` are not affected |
| `priority` / rule length | checked against Ferrum specificity | shadowed → dropped; contradictory/equal → refused |
| controls outside the input: static entryPoints (`http.tls`, `http.middlewares`, `http.redirections`, `forwardedHeaders`, `proxyProtocol`, `address`), TLS options of other providers or files (including `default`), routers of other providers (SNI option conflicts, competing routes), middlewares/services/transports outside the input | **refused by default** (placeholders, error `traefik-controls-unverified`, whose action is the operator checklist) | a missing router `tls` does not prove plaintext and a present one does not prove that no other control applied, so every route that would forward is refused. `--assert-traefik-input-includes-effective-controls` is the operator's scoped statement, after verification, that the input includes every effective routing, TLS and access control within the converted scope, or that no additional control applies: the entryPoints used (named, or the defaults for routers that name none) add none of the static controls above and routers naming no entryPoints share the entryPoint of the others; no TLS options outside the input apply (no `default` from another provider); no router outside the input maps the same hosts to other TLS options or competes for the same hosts and paths. It is not verified (warning `traefik-controls-asserted`) and only applies to `--from traefik`. It never lifts refusals for unresolved or unreproducible controls in the input. A static `entryPoints` section inside the input is never overridden by it: forwarding routes stay refused (`traefik-entrypoints-in-input`) |
| router `entryPoints` (with the statement) | one Ferrum listener per protocol | routers whose list leaves out the entryPoint the other routers of the same protocol (plaintext or HTTPS) share are refused (`traefik-entrypoint-scope`); malformed lists refuse the router. Extra entryPoints of a router are dropped (stricter) |
| router `tls` (with the statement) | HTTPS-only route | certResolver not migrated; without `tls` the router is plaintext-only |
| `tls.options` other than `default` (any definition, used or not; names are case-sensitive, so `Default` is another set) and router `tls.options` references other than unset, empty or exactly `default` (named, provider-qualified including `default@file`, malformed such as `default@`, another provider, undefined, non-string), an unreadable `tls.options` section, router or router `tls` block | **every HTTPS route refused** (`traefik-tls-options-scope`, placeholders) | Traefik selects TLS options during the handshake by SNI, for every path of an entryPoint at once; Ferrum's HTTPS listener applies one policy to every connection. HTTPS is translated only under one global handshake policy: the `default` options (or Traefik's built-in default) used by every TLS router. Traefik stores `default` globally without a provider qualifier and resolves only an unset, empty or exactly `default` reference to it; any other reference is qualified by provider and names a different set, so `default@file` is not equivalent. Checked on every router of the input as written (before rule parsing, invalid/unsatisfiable/redirect early exits and shadowing), whatever the hosts or paths, with or without the operator statement. Per-route SNI selection is not reconstructed, and no partial SNI equivalence is claimed. Plaintext routers are unaffected; refused HTTPS routes stay HTTPS-only placeholders |
| `tls.options.default` `clientAuth` (routers naming no options, an empty reference or exactly `default`) | frontend client CA | one `caFiles` file path with `RequireAndVerifyClientCert` (or no `clientAuthType`) → client CA of every HTTPS route; the listener-wide bundle follows the shared `frontend-client-ca-scope` rule. `VerifyClientCertIfGiven` becomes mandatory (warning, stricter). **Every HTTPS route refused** (`traefik-client-auth`, placeholders) when the requirement cannot be reproduced: malformed entry or `clientAuth`; inline or several `caFiles`; `RequestClientCert`/`RequireAnyClientCert`; unknown types. With no `default` in the input, Traefik's built-in default (no client certificates, no `sniStrict`) is used on the operator's statement that no other provider defines one (info `traefik-tls-default-options`) |
| `tls.options.default` `sniStrict` | **every HTTPS route refused** when enabled or non-boolean (`traefik-sni-strict`, placeholders) | an admission control: Traefik rejects handshakes without SNI or for names matching no certificate before routing, while Ferrum's HTTPS listener completes every handshake. `sniStrict: false` or absent keeps ordinary TLS routes. Applies with or without the operator statement; plaintext routers are unaffected. (`sniStrict` in any other options refuses HTTPS through `traefik-tls-options-scope`) |
| other settings of `tls.options.default` (versions, ciphers, curves, ALPN) | not migrated (info `traefik-tls-options`) | set `FERRUM_TLS_*` settings manually |
| `redirectScheme: https` router | TLS-only profile | |
| `loadBalancer` servers/weights, `passHostHeader` (default true), `healthCheck`, `sticky.cookie`, `serversTransport` | upstream/direct backend, `preserve_host_header`, `health_checks`, cookie consistent hashing, backend TLS/timeouts | server URLs with paths refused |
| `serversTransport.forwardingTimeouts` `dialTimeout`, `responseHeaderTimeout` | `backend_connect_timeout_ms`, `backend_read_timeout_ms` | approximate: `responseHeaderTimeout` only waits for headers after the request is written |
| `serversTransport` that is undefined or from another provider; inline or several `rootCAs`; inline, malformed or several client `certificates`; `spiffe`; `peerCertURI` | **refused** (placeholder) | applies to direct load balancers and weighted children alike. Ferrum presents one client certificate from file paths and has no SPIFFE or URI-SAN pinning equivalent here; configure backend identity in Ferrum by hand |
| `weighted` services | merged weighted upstream | children must agree on scheme, `passHostHeader`, backend TLS and forwarding timeouts; their shared `dialTimeout`/`responseHeaderTimeout` are carried over, and differing timeouts are refused. `healthCheck`/`sticky` on the weighted service or its children are not migrated (warning `traefik-weighted-lb-options`) |
| `mirroring` | main service only (warning) | `failover` refused |
| `stripPrefix` / `addPrefix` | `strip_listen_path` + `backend_path` | partial/conditional strip refused |
| `headers` custom request/response, STS/frame/nosniff/XSS/CSP/referrer/permissions, `accessControl*` | `request_transformer`, `response_transformer`, `cors` | `sslRedirect` etc. refused. `allowedHosts` is a no-op only when the router's hosts are inside every applicable list (lists from several middlewares are intersected); otherwise the route is refused, and so is `allowedHosts` combined with `hostsProxyHeaders` (Ferrum cannot check those headers) |
| `basicAuth` | `basic_auth` without credentials | hashes never echoed |
| `ipAllowList`/`ipWhiteList` | `ip_restriction.allow` | `ipStrategy` refused |
| `rateLimit` average/period | `rate_limiting` limit_by ip | `sourceCriterion` refused |
| `buffering.maxRequestBodyBytes`, `retry.attempts` | `request_size_limiting`, `retry` | |
| `forwardAuth`, `digestAuth`, `replacePath*`, `stripPrefixRegex`, `redirectRegex`, `inFlightReq`, plugins | refused | |
| `api@internal` and other providers | refused | |

## Envoy v3 static

| Envoy | Ferrum | Notes |
|---|---|---|
| listener port, downstream TLS | main ports, TLS-only, frontend cert paths | inline/SDS material never copied; a plaintext listener on another port is **not migrated** (`extra-listener-refused`). Each route has exactly one source frontend (its listener), so a plan with live plaintext routes gets `FERRUM_PROXY_HTTPS_PORT=0` and no frontend TLS settings, even when the TLS listener itself was skipped (RDS) |
| `require_client_certificate` or `validation_context` with a file `trusted_ca` | frontend client CA | optional `validation_context` becomes mandatory (`envoy-mtls-optional`, stricter); inline/SDS/combined/missing CA or extra validation constraints (SAN/hash/SPKI pins, CRLs) → listener's routes refused (`envoy-client-ca`) |
| HCM with inline `route_config` | routes | RDS/scoped routes/xDS not read |
| virtual host `domains` | `hosts` (+ host-only 404 closure) | prefix wildcards refused |
| route `prefix` / `path` / `safe_regex` / `path_separated_prefix` | prefix / exact / regex / prefix (segment, no guard) | header/query/grpc/runtime matchers refused + poisoning. `prefix` is a string prefix (`/api` also matched `/apix`): never widened, `prefix-string-siblings` error when such siblings do not reach an equivalent route |
| `case_sensitive: false` (prefix, path, path_separated_prefix) | exact-case path only | Ferrum matches paths case-sensitively; every route that could receive the case variants (`/API` for `/api`) is refused (route-refused). Overlap/coverage is compared case-folded |
| ordered routes | first-match analysis | a `path_separated_prefix` only shadows later routes under its own segments (`/api`, `/api/...`), never `/apix`; it is also treated as disjoint from an exact `path` outside its segments (`/apix`) when both are case-sensitive. Other overlap checks stay conservative (string-prefix), so such a pair may be refused instead |
| `cluster`, `weighted_clusters` | upstream / merged weighted upstream | EDS/original_dst refused; priority>0 endpoints dropped |
| `prefix_rewrite`, `auto_host_rewrite`, default host pass-through | strip + `backend_path`, `preserve_host_header` | regex rewrites refused |
| `timeout` (default 15s), `retry_policy` | `backend_read_timeout_ms`, `retry` | timeout approximate: Envoy's route timeout covers the complete response, Ferrum's value is not a total deadline |
| request/response header add/remove | transformers | Envoy append semantics on requests refused |
| `cors` policy (with cors filter) | `cors` with exact/prefix/regex origins | |
| `direct_response` (inline), static `redirect` | `request_termination` | |
| UpstreamTlsContext (file CA, SNI, exact SANs, client cert files) | upstream backend TLS | no validation context → verification on (warning) |
| HTTP filters other than router/cors/buffer/grpc_stats/health_check | every route in that HCM refused | filters with `disabled: true` are skipped |
| non-CORS `typed_per_filter_config` on a route, virtual host or route configuration | route refused | it can re-enable a disabled filter for that route |

## Istio networking CRDs

The Istio translation is an **ingress projection**: Gateway-bound VirtualServices become Ferrum
edge proxies. Mesh routing, sidecar behavior and workload mTLS are not migrated, and no mesh
behavior is claimed. Ferrum documents its own Istio CRD/mesh support separately; this project does
not exercise it.

| Istio | Ferrum | Notes |
|---|---|---|
| `Gateway` servers (HTTP, HTTPS SIMPLE/MUTUAL with file paths) | ports, TLS-only, frontend cert/client CA | `credentialName` Secrets are never read (warning). PASSTHROUGH/AUTO_PASSTHROUGH/ISTIO_MUTUAL, and MUTUAL without a `caCertificates` file path, cannot be projected: on the main TLS port the routes bound to such a server are refused (placeholders), elsewhere the server is skipped. MUTUAL servers with different `caCertificates` → affected routes refused (`frontend-client-ca-scope`), never concatenated. MUTUAL/OPTIONAL_MUTUAL with `subjectAltNames`, `verifyCertificateSpki`, `verifyCertificateHash` or `caCrl` → refused (`istio-client-ca`). A host bound by both a plaintext and an HTTPS server gets one route set that keeps the HTTPS server's client CA or refusal (`istio-shared-host-tls`); `match.port` routes in that shared set are refused. Host scopes that overlap through different names (a wildcard and a host it covers) with a stricter HTTPS server or `match.port` routes refuse both projections (`istio-shared-host-scope`). Across separate bindings (other VirtualServices or Gateways), overlapping hosts with a different frontend (plaintext vs HTTPS, client CA, refused frontend) refuse every projection involved (`istio-frontend-scope-conflict`). HTTP servers on a non-main port are **not migrated** (`extra-listener-refused`) |
| `Server.bind` | `FERRUM_PROXY_BIND_ADDRESS` | only when every HTTP(S) server binds the same IP address; otherwise servers with a specific address or Unix socket are skipped (`istio-server-bind`), never exposed on Ferrum's shared address |
| `VirtualService` bound to a Gateway; `gateways: [mesh]` | edge routes; mesh routes reported only | not translated |
| `http[].match` uri exact/prefix/regex, method exact | exact/prefix/regex, `allowed_methods` | headers/query/authority/... refused + poisoning. A VirtualService `uri.prefix` is a string prefix (`/api` also matched `/apix`): never widened, `prefix-string-siblings` error when such siblings do not reach an equivalent route. `ignoreUriCase` (exact/prefix) keeps the exact-case path only; routes that could receive the case variants are refused |
| ordered `http[]` | first-match analysis | |
| destinations, weights, ports | upstream / merged weighted upstream | subsets refused (need pod labels) |
| `ServiceEntry` static endpoints | upstream targets | resolution NONE refused |
| `DestinationRule` tls DISABLE/SIMPLE/MUTUAL, loadBalancer simple/consistentHash | backend scheme/TLS, algorithm/hash_on | ISTIO_MUTUAL, credentialName refused; `insecureSkipVerify` ignored (verification stays on); `caCertificates` path must exist on the Ferrum host |
| `rewrite.uri` / `rewrite.authority` | strip + `backend_path` / no host preserve | |
| `timeout`, `retries`, `corsPolicy`, header set/remove | `backend_read_timeout_ms` (approximate: Istio's timeout covers the complete response), `retry`, `cors`, transformers | request header `add` refused (append semantics) |
| `directResponse`, static `redirect` | `request_termination` | |
| `AuthorizationPolicy` / `RequestAuthentication` / `EnvoyFilter` / `WasmPlugin` that may select the gateway | every route of that gateway refused | applies in any namespace unless provably unrelated: a `targetRef` to another resource, or a selector pinning one of the Gateway selector's label keys to a different value. Other or extra label keys are not proof; namespace-wide policies (no selector) always refuse, with `istio-policy-scope-unknown` outside the Gateway/root namespace |
| `Secret` objects | never read | |

## Run-mode settings

`ferrum.conf` only uses names from Ferrum's public settings inventory: `FERRUM_MODE`,
`FERRUM_PROXY_HTTP(S)_PORT`, `FERRUM_PROXY_BIND_ADDRESS`, `FERRUM_FRONTEND_TLS_*`,
`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`, `FERRUM_ADMIN_BIND_ADDRESS`, `FERRUM_DB_TYPE` and
`FERRUM_CP_GRPC_LISTEN_ADDR`. Suggestions (trusted proxies, PROXY protocol, HTTP/3) are
written as comments. Secrets appear only as comments asking for `*_FILE` environment variables.

Values follow Ferrum's `ferrum.conf` grammar (`src/config/conf_file.rs`): one `KEY=value` per line,
values trimmed, a value starting with `"` or `'` is literal up to the next identical quote (no
escapes), and an unquoted value ends at the first ` #`. Source-derived values that need it are
quoted. Values that cannot round-trip (empty, line breaks or other non-printable characters, or
both quote characters when quoting is needed) reject the input with exit 3 before anything is
written, so a client CA path is never silently dropped or altered. Unrepresentable values in
commented suggestions are replaced by a note.

The resources file is `resources.yaml` or `resources.json`. Ferrum's spec discovery tries
`./resources.yaml` before `./resources.json`, so `convert` refuses (exit 5, even with `--force`) to
write one format next to an existing file of the other format. The report's next steps always pass
`--spec` explicitly.

## Open questions (not verifiable from source alone; review on first real run)

* Exact composition of `backend_path` with a stripped path of `""` vs `"/"` (exact-match
  rewrites are flagged with a warning).
* Whether `request_termination`'s `trigger.path_prefix` is a plain string prefix. The guard
  logic assumes it is, as its name and validator suggest.
* `FERRUM_TRUSTED_PROXIES` list syntax (only suggested, commented).
* Istio VirtualServices that Istio itself generates from Kubernetes Ingress or Gateway API
  resources (marked with an internal route-semantics annotation) are understood to use
  path-separated prefixes. This was inferred from Istio's implementation, not its API docs. The
  tool treats every `uri.prefix` as a string prefix, so such input gets extra guards and possibly
  an unnecessary `prefix-string-siblings` error. That errs on the stricter side.
* Behavior of the placeholder backend host `ferrum-migration-refused.invalid` during DNS/pool
  warm-up. Placeholders never dial, because termination runs first, but warm-up may log.
* Whether Ferrum v0.9.21 normalizes proxy names (case, whitespace) before its duplicate-name check.
  Emitted names are unique even after trimming and case folding, so either answer is safe.
* Whether Ferrum's HTTPS listener can reject handshakes without SNI or for names its certificate does not
  cover. The tool assumes it cannot and refuses routes under Traefik `sniStrict`, so either answer is safe.
* Whether the reference source's single-listener `listen_port` remap exists in v0.9.21. The tool
  emits no `listen_port`, so the answer does not change the output.
