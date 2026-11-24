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
| `ferrum-edge validate -m file -c <spec>` runs the real admission pipeline. | `docs/cli.md` |
| `backend_read_timeout_ms` (v0.9.21) is one budget covering the wait for response headers, idle time between streamed response frames, and the total time to send a buffered client request body. No source read timeout means exactly that, so every projected timeout is an **approximation** (report warning `timeout-approximate`): the number in milliseconds carries over, the semantics do not. | Ferrum Edge v0.9.21 |

## Kong Gateway (DB-less / decK)

| Kong | Ferrum | Notes |
|---|---|---|
| service `url` / `protocol`, `host`, `port`, `path` | `backend_scheme`/`backend_host`/`backend_port`, `backend_path` | grpc/ws → http, grpcs/wss → https; tcp/tls/udp refused |
| service host naming an upstream | `upstream_id` | one Ferrum upstream per (upstream, TLS posture) |
| `connect/read/write_timeout`, `retries` | `backend_*_timeout_ms`, `retry` (connect failures) | timeouts approximate: Kong read/write timeouts are idle bounds between two successive operations |
| `tls_verify` absent/false | verification **on** (warning) | no opt-out; insecure backend TLS is never emitted |
| route `paths` (one proxy per path), `hosts`, `methods`, `strip_path`, `preserve_host` | `listen_path`, `hosts`, `allowed_methods`, `strip_listen_path`, `preserve_host_header` | `~regex` paths become anchored Ferrum regexes; regex + `strip_path` refused |
| route `headers`, `snis`, `expression`, `sources/destinations` | refused + overlap poisoning | |
| `protocols: [https]` only | emitted only in TLS-only mode | |
| upstream targets/weights, algorithm, `hash_on` ip/header/cookie, healthchecks | targets, `weighted_round_robin`/`least_connections`/`least_latency`/`consistent_hashing`, `hash_on`, `health_checks` (approximate) | weight 0 targets dropped; default target port 8000 |
| `key-auth` (`key_names` × header/query) | `key_auth.key_location` (max 8) | `anonymous` and body keys are not supported (stricter) |
| `basic-auth` | `basic_auth` without credentials (fail closed) | password hashes are not convertible |
| `jwt` (HS*) | `jwt_auth` (`consumer_claim_field` = `key_claim_name`, algorithm pinned) | `maximum_expiration`, `secret_is_base64` refused; query/cookie tokens dropped (stricter) |
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
| consumers: username/custom_id, `acls`, `keyauth_credentials`, HMAC `jwt_secrets` | consumers, `acl_groups`, `credentials.keyauth/jwt` (only with `--include-secrets`) | consumer-scoped plugins and consumer groups quarantine the consumer; with `_transform: false` keys/secrets are stored values and are never migrated |
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
    plugins: [{plugin_config_id: kong-legacy-root-guard}]   # path_prefix /orders guard
```

## NGINX OSS

| NGINX | Ferrum | Notes |
|---|---|---|
| `server` + `listen` + `server_name` | `hosts`; default server → catch-all | regex/trailing-wildcard names refused; `.example.com` → `example.com` + `*.example.com` |
| main plaintext/TLS ports | `FERRUM_PROXY_HTTP(S)_PORT`; other plaintext ports → `listen_port` | other TLS ports and conflicting bind addresses skipped (error) |
| HTTPS redirect server / `if ($scheme = http) { return 301 https://… }` | TLS-only profile | |
| `location /p`, `^~ /p`, `= /p`, `~`/`~*` | prefix, prefix, exact, anchored regex (`(?i)`) | overlapping regex + prefix → whole server refused; `/p` is never widened, and when sibling paths such as `/px` (string-prefix matches) do not reach an equivalent route in Ferrum, the location gets a `prefix-string-siblings` error (exit 4) |
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
| `ssl_certificate(_key)`, `ssl_client_certificate` + `ssl_verify_client` | frontend TLS paths, client CA | |
| `include` (except `mime.types`, Debian `proxy_params`), `if`, `rewrite`, `auth_request`, `satisfy any`, unknown directives | containing location/server refused | |

## Traefik OSS (file provider)

| Traefik | Ferrum | Notes |
|---|---|---|
| `rule` with `Host`, `HostHeader`, `Path`, `PathPrefix`, `Method` (`&&`, `||`, parentheses; v2 multi-arg) | one proxy per DNF alternative group | `Header*`, `Query*`, `ClientIP`, `*Regexp`, negation → refused + poisoning |
| `priority` / rule length | checked against Ferrum specificity | shadowed → dropped; contradictory/equal → refused |
| router `tls` | HTTPS-only route | certResolver not migrated |
| `redirectScheme: https` router | TLS-only profile | |
| `loadBalancer` servers/weights, `passHostHeader` (default true), `healthCheck`, `sticky.cookie`, `serversTransport` | upstream/direct backend, `preserve_host_header`, `health_checks`, cookie consistent hashing, backend TLS/timeouts | server URLs with paths refused |
| `serversTransport.forwardingTimeouts` `dialTimeout`, `responseHeaderTimeout` | `backend_connect_timeout_ms`, `backend_read_timeout_ms` | approximate: `responseHeaderTimeout` only waits for headers after the request is written |
| `weighted` services | merged weighted upstream | children must agree on scheme/transport |
| `mirroring` | main service only (warning) | `failover` refused |
| `stripPrefix` / `addPrefix` | `strip_listen_path` + `backend_path` | partial/conditional strip refused |
| `headers` custom request/response, STS/frame/nosniff/XSS/CSP/referrer/permissions, `accessControl*` | `request_transformer`, `response_transformer`, `cors` | `sslRedirect` etc. refused |
| `basicAuth` | `basic_auth` without credentials | hashes never echoed |
| `ipAllowList`/`ipWhiteList` | `ip_restriction.allow` | `ipStrategy` refused |
| `rateLimit` average/period | `rate_limiting` limit_by ip | `sourceCriterion` refused |
| `buffering.maxRequestBodyBytes`, `retry.attempts` | `request_size_limiting`, `retry` | |
| `forwardAuth`, `digestAuth`, `replacePath*`, `stripPrefixRegex`, `redirectRegex`, `inFlightReq`, plugins | refused | |
| `api@internal` and other providers | refused | |

## Envoy v3 static

| Envoy | Ferrum | Notes |
|---|---|---|
| listener port, downstream TLS | main ports, TLS-only, frontend cert paths | inline/SDS material never copied |
| HCM with inline `route_config` | routes | RDS/scoped routes/xDS not read |
| virtual host `domains` | `hosts` (+ host-only 404 closure) | prefix wildcards refused |
| route `prefix` / `path` / `safe_regex` / `path_separated_prefix` | prefix / exact / regex / prefix (segment, no guard) | header/query/grpc/runtime matchers refused + poisoning |
| ordered routes | first-match analysis | |
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
| `Gateway` servers (HTTP, HTTPS SIMPLE/MUTUAL with file paths) | ports, TLS-only, frontend cert/client CA | PASSTHROUGH/ISTIO_MUTUAL/credentialName not migrated |
| `VirtualService` bound to a Gateway; `gateways: [mesh]` | edge routes; mesh routes reported only | not translated |
| `http[].match` uri exact/prefix/regex, method exact | exact/prefix/regex, `allowed_methods` | headers/query/authority/... refused + poisoning |
| ordered `http[]` | first-match analysis | |
| destinations, weights, ports | upstream / merged weighted upstream | subsets refused (need pod labels) |
| `ServiceEntry` static endpoints | upstream targets | resolution NONE refused |
| `DestinationRule` tls DISABLE/SIMPLE/MUTUAL, loadBalancer simple/consistentHash | backend scheme/TLS, algorithm/hash_on | ISTIO_MUTUAL, credentialName refused; `insecureSkipVerify` ignored (verification stays on); `caCertificates` path must exist on the Ferrum host |
| `rewrite.uri` / `rewrite.authority` | strip + `backend_path` / no host preserve | |
| `timeout`, `retries`, `corsPolicy`, header set/remove | `backend_read_timeout_ms` (approximate: Istio's timeout covers the complete response), `retry`, `cors`, transformers | request header `add` refused (append semantics) |
| `directResponse`, static `redirect` | `request_termination` | |
| `AuthorizationPolicy` / `RequestAuthentication` / `EnvoyFilter` / `WasmPlugin` selecting the gateway | every route of that gateway refused | a matching selector counts in any namespace; namespace-wide policies outside the Gateway/root namespace are review errors (`istio-policy-scope-unknown`) |
| `Secret` objects | never read | |

## Run-mode settings

`ferrum.conf` only uses names from Ferrum's public settings inventory: `FERRUM_MODE`,
`FERRUM_PROXY_HTTP(S)_PORT`, `FERRUM_PROXY_BIND_ADDRESS`, `FERRUM_FRONTEND_TLS_*`,
`FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`, `FERRUM_ADMIN_BIND_ADDRESS`, `FERRUM_DB_TYPE` and
`FERRUM_CP_GRPC_LISTEN_ADDR`. Suggestions (trusted proxies, PROXY protocol, HTTP/3) are
written as comments. Secrets appear only as comments asking for `*_FILE` environment variables.

## Open questions (not verifiable from source alone; review on first real run)

* Exact composition of `backend_path` with a stripped path of `""` vs `"/"` (exact-match
  rewrites are flagged with a warning).
* Whether `request_termination`'s `trigger.path_prefix` is a plain string prefix. The guard
  logic assumes it is, as its name and validator suggest.
* `FERRUM_TRUSTED_PROXIES` list syntax (only suggested, commented).
* Behavior of the placeholder backend host `ferrum-migration-refused.invalid` during DNS/pool
  warm-up. Placeholders never dial, because termination runs first, but warm-up may log.
