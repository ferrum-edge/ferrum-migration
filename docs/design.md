# Design

## Pipeline

```
input file --(safe_load / nginx parser)--> source translator --> Plan (IR) --> emitter --> resources + profile + report
```

1. **Loading** (`safe_load.py`, `sources/nginx.py`). Reads at most `max_input_bytes + 1` bytes
   from one regular file and rejects NUL bytes and invalid UTF-8. YAML uses a `SafeLoader`
   subclass that rejects duplicate keys, merge keys and binary/set/omap/pairs tags, keeps
   timestamps as strings, and bounds aliases and composed nodes. Every decoded tree is then
   walked once under a visit budget, in which shared aliases count on each visit. This
   defeats alias-expansion bombs before any translator iterates the data. The NGINX tokenizer
   is bounded by token count and block depth and refuses embedded script blocks.
2. **Translation** (`sources/*.py`). Each source produces a platform-neutral `Plan`:
   `RouteSpec`s (hosts, path kind, methods, port, TLS requirement, backend, plugins,
   termination, refusal reasons, and an `extra_conditions` flag), `UpstreamSpec`s,
   `ConsumerSpec`s, global plugins and settings hints. Translators never emit anything they
   cannot justify. They call `route.refuse(reason)` instead.
3. **Emission** (`ferrum.py`). Applies the fail-closed rules below and produces Ferrum
   resources with deterministic ids and ordering.
4. **Output** (`writer.py`). The output directory is created `0700`. Each file goes through
   `mkstemp` (`0600`), `fsync` and an atomic rename. Collisions are checked before anything is
   written, and symlinks are refused.

## Fail-closed rules in the emitter

| Rule | Why |
|---|---|
| Refused route with a representable match: placeholder proxy (same hosts/path/port) with `request_termination` 503 | Ferrum runs `request_termination` in `on_request_received` (priority 125), before auth. The refused traffic cannot reach a broader route. |
| Refused route with an unrepresentable match (`extra_conditions`): refuse every overlapping route Ferrum would prefer over its placeholder | Requests the source sent to the refused route must not land on a different backend or policy. |
| Duplicate Ferrum slot (same port, same listen path, overlapping hosts): refuse all, emit one merged placeholder | Ferrum rejects duplicates. Picking one would silently drop another source route's policy. |
| Frontend protocols (final output invariant): every live route must have been served by the source on every listener the profile opens (`RouteSpec.protocols`, recorded by each translator). `--tls-only` or no plaintext route: `FERRUM_PROXY_HTTP_PORT=0`, plaintext-only routes refused (`frontend-protocol-scope`). Otherwise HTTPS-only routes are refused, and unless every live route was also served over HTTPS the profile disables HTTPS explicitly (`FERRUM_PROXY_HTTPS_PORT=0`, no `FERRUM_FRONTEND_TLS_*`, no HTTP/3 suggestion; `frontend-https-disabled`). Unknown frontend metadata refuses the whole plan (`frontend-protocol-unknown`). Decided before candidates are built, re-checked on the final candidates and on the rendered `ferrum.conf` | Ferrum serves port-agnostic routes on each listener it opens, whatever the host names, so disjoint or unknown host patterns and identical frontend strings prove nothing. Absent TLS settings prove nothing either: Ferrum opens HTTPS on its default port when frontend TLS material is configured, and translators record TLS settings even for listeners they then skip (Envoy RDS). |
| String-prefix guard (`request_termination` + `trigger.path_prefix`) on broader routes with different policy, including the placeholder of a refused string-prefix route (guarded even when the broader route serves more hosts: `prefix-divergence-refused` error) | Source `/api` matched `/apix`; Ferrum's segment matching would hand `/apix` to the broader route, which for a refused route would skip the policy that caused the refusal. |
| String-prefix siblings that no equivalent route catches (no fallback, a guard, a placeholder or a termination): `prefix-string-siblings` error, route not widened. Applies to NGINX prefix locations, Kong `paths`, Traefik `PathPrefix`, Envoy `prefix` and Istio `uri.prefix`; not to Envoy `path_separated_prefix`, exact/regex matches or prefixes ending in `/` | `/apix` was forwarded by the source but gets a 404 or fail-closed answer in Ferrum; that must be reviewed, not dropped silently. A regex or broader route would change precedence or expose more. |
| Traefik without `--assert-traefik-input-includes-effective-controls`: every route that would forward is refused (`traefik-controls-unverified`, action: the operator checklist of static entryPoints, omitted cross-provider/`default` TLS options, SNI option conflicts and competing routers). With it (the operator's scoped statement that the input includes every effective routing, TLS and access control within the converted scope, or that none is added; not verified; warning `traefik-controls-asserted`) routes keep the dynamic translation, router `tls`, TLS options, middlewares and explicit `entryPoints` lists still apply, unresolved or unreproducible controls still refuse, and routers whose list leaves out the entryPoint shared by the other routers of their protocol are refused (`traefik-entrypoint-scope`); a static `entryPoints` section in the input keeps forwarding routes refused (`traefik-entrypoints-in-input`). The option is refused (exit 2) for other sources | The file provider input has no static configuration and no other provider's configuration. entryPoints can add TLS, client certificate options, prepended middlewares, redirections, forwarded-header trust and bind restrictions; another provider can define the `default` TLS options a TLS router without options inherits, map its hosts to other TLS options, or add competing routers. Neither the absence nor the presence of a router `tls` block proves how the source served a route. Ferrum serves every route of a protocol on one listener, so separate entryPoints named in the input cannot be kept apart. |
| Traefik `tls.options` `sniStrict` enabled (or not a boolean): the HTTPS routes it applies to are refused (`traefik-sni-strict`), whatever the operator states: an explicit reference or SNI-dependent candidate refuses that route, the `default` options refuse every HTTPS route | sniStrict rejects handshakes without SNI or for unknown names before routing. Ferrum's HTTPS listener completes every handshake with its frontend certificate, so dropping the setting would admit connections the source refused. The `default` options govern every handshake without SNI. |
| Traefik `serversTransport` that is undefined, from another provider, or carries trust, client identity or pinning Ferrum cannot reproduce (inline or several `rootCAs` or client certificates, `spiffe`, `peerCertURI`): route refused, for direct and weighted-child load balancers alike | Falling back to default transport settings would silently trust more CAs, or drop the client identity the backend sees or the pinning of its certificate. |
| Kong https service with `ca_certificates`: route refused (`kong-ca-certificates`) | The restricted backend trust set is never copied; Ferrum's default trust store would trust more issuers. |
| Frontend client CA: one listener-wide bundle only when every migrated route that required client certificates named the same single bundle; otherwise those routes are refused (`frontend-client-ca-scope`) and no bundle is configured. Unreproducible per-scope trust (no CA file, Envoy SAN/hash pins) refuses that scope's routes | Ferrum file mode has one client CA bundle per HTTPS listener. Concatenating bundles from separate NGINX servers, Envoy listeners, Istio Gateway servers or Traefik TLS options would let clients trusted by one scope reach another. Separately configured frontends keep the boundaries. |
| Traefik `tls.options` `clientAuth` is resolved per HTTPS router (named options, or `default`, Traefik's built-in default only on the operator's statement) and becomes that route's client CA; options that are undefined, from another provider, malformed, unverified (`RequestClientCert`/`RequireAnyClientCert`) or not one `caFiles` path refuse the route (`traefik-client-auth`), as do SNI-dependent selections whose candidate options differ in `clientAuth` (no `Host` matcher; one host mapped to different options) | Traefik enforces client certificates in the TLS handshake, chosen by SNI. Treating clientAuth as metadata would drop mandatory client certificates from the migrated route. |
| Projected backend timeouts carry a `timeout-approximate` warning | Same unit, different semantics: Ferrum's `backend_read_timeout_ms` also bounds header wait, stream idle time and buffered uploads. |
| Exact 404 route for the bare path of a trailing-slash prefix | Source `/api/` did not match `/api`; Ferrum's `/api` would. |
| Host-only 404 route per closed host scope (NGINX server, Envoy vhost, Istio host); only a closure for the same host names counts. When an overlapping host-only route blocks it, a `~/.*` regex 404 route appended after the scope's routes closes it. When neither fits, every emitted route that could receive the scope's unmatched requests (catch-all, or a covering wildcard of another scope) is refused (`scope-closure-skipped`) | Those sources never fall through to other hosts' routes; Ferrum's host tiers do. Ferrum tries every matching wildcard pattern's exact, prefix and regex routes before any wildcard host-only route, so a covering wildcard closure does not close a narrower scope. Ferrum rejects overlapping host-only proxies, but a regex route is not host-only; within a tier it runs after exact and prefix routes (regex in config order), so at worst it shadows another route with a 404. |
| A wildcard host scope covering another scope's narrower wildcard: routes carrying the broader pattern refused (`nested-wildcard-scope`) | The source sends the narrower hosts only to the narrower scope. Ferrum's wildcard tier compares the path routes of every matching pattern, so the broader scope's routes could answer them, and no closure can prevent that. |
| NGINX default server with a `server_name` that another server on the same listener covers keeps its named hosts (`nginx-default-server-named`). Default roles are taken only from the listeners Ferrum serves the server on: a default on some of them only keeps its named hosts (`nginx-default-server-listener`); different default servers on the main plaintext and TLS listeners have their catch-all routes refused (`nginx-default-server-conflict`) | NGINX prefers it for its own names; as a Ferrum catch-all those names would go to the other server's exact/wildcard tier. The fallback role for unknown names is not migrated. Dropped extra ports must not create a catch-all, and Ferrum's port-agnostic catch-all tier cannot keep two default servers apart. |
| String-prefix guards consider regex routes that can match a sibling when no ancestor prefix in the same host tier catches it first. A competing regex route the guard cannot scope exactly is guarded anyway (`prefix-divergence`) | The source's priority (NGINX `^~`, Envoy/Istio first match) kept siblings away from those regex routes; Ferrum's tier order (prefix, then regex) does not. |
| No listener-scoped proxy is ever emitted (final output invariant). Routes the source served only on an extra plaintext listener (NGINX server, Envoy listener, Istio Gateway server on another port) get no proxy, no placeholder and no closure (`extra-listener-refused`) | Ferrum's router selects the host tier and the longest path before it compares `listen_port`, and port-agnostic routes serve every HTTP listener. Main routes would answer on the extra listener, and its routes could not be isolated. Not emitting any proxy for that port keeps Ferrum from serving it at all. |
| Case-insensitive source matches (Envoy `case_sensitive: false`, Istio `ignoreUriCase`; exact and prefix only) keep their exact-case path; every route in the same or a more specific host tier that could match a case variant is refused. Less specific tiers are spared only when the route's host scope is closed. Overlap and coverage checks fold case for such routes and skip the segment/exact disjointness proof | Ferrum matches paths case-sensitively, so `/API` would reach a broader route with another policy instead of the route the source chose. A closed scope answers unmatched variants with 404. |
| Kong: a route whose effective policy (global plugins not replaced by a same-name scoped plugin, plus service and route plugins) combines several authentication methods is refused (`kong-auth-composition`) | Kong requires every method (or any one with `anonymous`) and authenticates the consumer of the plugin that runs last; Ferrum commits the first accepted principal. Required methods and the consumer seen by ACL or consumer rate limits are not proven equal. Withholding one method's credentials does not make the remaining method equivalent. |
| Istio: overlapping hosts served by projections of different VirtualService-to-Gateway bindings through different frontends (plaintext vs HTTPS, client CA, refused frontend) refuse every projection involved (`istio-frontend-scope-conflict`), checked on the final plan with refused projections included | Ferrum serves port-agnostic routes on both listeners with one client CA bundle. One binding's routes would otherwise answer another binding's frontend. |
| Envoy and NGINX: each route records its server's or listener's main frontends (`protocols`); the former pairwise host-overlap check (`envoy-frontend-scope-conflict`, `nginx-frontend-scope-conflict`) is replaced by the emitter's frontend protocol invariant above | A pairwise check only saw named overlaps between migrated scopes. Ferrum exposes a plaintext-only route on HTTPS for every host, including HTTPS listeners that were skipped or unprojected. |
| Istio `Server.bind`, MUTUAL client-certificate constraints, and hosts shared by plaintext and HTTPS servers | A restricted bind is never widened to Ferrum's shared address; SAN/SPKI/hash/CRL constraints refuse the server's routes; a shared host's single route set keeps the HTTPS server's client CA or refusal. |
| `ferrum.conf` values are validated or quoted for Ferrum's parser; unrepresentable values reject the input before writing. A resources file of the other format in the output directory is refused | A setting Ferrum would read differently (or a dropped client CA) must never be written; a stale `resources.yaml` would win Ferrum's spec discovery over a new `resources.json`. |
| Backend TLS verification always on; every emitted `backend_tls_verify_server_cert` is `true`, checked by a final output invariant; the former opt-out flag is refused (exit 2) | Never downgrade transport security; insecure output is never produced. |
| Credentials only with `--include-secrets`; key/secret strength and uniqueness checks; quarantined consumers get none | Plaintext secrets are explicit and private. Ferrum would reject or quarantine weak or shared secrets anyway. |
| Kong `_transform: false` credentials are never migrated | They are stored (pre-transformed) values, not what clients send. |
| Static values for credential-like header/query names refuse the route (value never echoed) | They would put secret bytes into the resources file without `--include-secrets`. |
| Envoy routes/vhosts with non-CORS `typed_per_filter_config` are refused | Per-route config can re-enable a filter disabled at the HCM (for example authentication). |
| Istio policies refuse a Gateway's routes in any namespace unless provably unrelated: a `targetRef` to another resource, or a selector pinning one of the Gateway selector's label keys to another value. Extra label keys and namespace-wide policies refuse (outside the Gateway/root namespace also `istio-policy-scope-unknown`) | Neither the gateway pods' namespace nor their labels are part of the input; one pod can carry every label of both selectors. |
| Istio plaintext/HTTPS servers sharing hosts: merged only for the same host names or a catch-all side; a shared projection keeps both server ports, so `match.port` routes in it are refused; overlap through different names with a stricter HTTPS server or `match.port` routes refuses both projections (`istio-shared-host-scope`) | Ferrum serves port-agnostic routes on both listeners; equality of the strings is not the same as equal host scopes, and one port's view of `match.port` must not serve the other listener. |

### Precedence analysis

* **First-match sources** (Envoy routes, Istio `http[]`): `apply_first_match_order` drops
  routes fully covered by an earlier unconditional route (unreachable in the source). Coverage is
  definitive and segment-aware: an Envoy `path_separated_prefix` `/api` covers `/api` and
  `/api/...`, never `/apix`. Overlap stays conservative (string prefixes), except that a segment
  prefix and an exact path outside it (`/api` and `/apix`) are disjoint when both match
  case-sensitively. With a case-insensitive side, paths are compared case-folded and that
  disjointness proof is not used. When a partial overlap would be resolved differently by Ferrum's
  specificity order, both routes are refused.
* **Traefik**: router priority (explicit, or the default rule length) is compared with
  Ferrum's preference for every overlapping pair. A shadowed route is dropped; a
  contradictory or equal-priority pair is refused.
* **NGINX**: a server mixing regex locations with overlapping non-`^~` prefix locations is
  refused entirely, because NGINX lets the regex win and Ferrum lets the prefix win.
* **Kong**: regex paths overlapping prefix paths are refused and poison their overlaps.

### Residual risks (documented, not hidden)

* A host-level refusal (regex `server_name`, unrepresentable Envoy domains) poisons only
  catch-all routes. A backend that is virtual-host aware could still receive such hosts
  through the catch-all route.
* Divergent string-prefix paths on a narrower host set than the broader route cannot be
  guarded exactly. These cases are reported as `prefix-divergence` errors (for refused routes the
  guard is added anyway: `prefix-divergence-refused`).
* Nested wildcard host scopes from different source servers (`*.example.com` and
  `*.a.example.com`) cannot be kept apart in Ferrum's wildcard tier, so the broader scope's routes
  are refused (`nested-wildcard-scope`). Its own hosts then get 503 placeholders until it is served
  from a separate frontend.
* The regex closure (`~/.*`) relies on Ferrum trying regex routes in config order within a tier.
  If that ever differs, it can only shadow another route with a 404 (fail closed), never forward.
* Extra plaintext listeners are not migrated at all (`extra-listener-refused`); serve them from a
  separately configured Ferrum instance. A server that listens on a main port and on extra ports is
  served on the main ports only (stricter).
* Istio Gateways with different selectors (different gateway workloads, possibly on different
  networks or load balancers) are projected onto one Ferrum frontend when their projections have the
  same frontend properties. The tool cannot know the workloads' reachability, so it does not claim that
  routes from an internal-only Gateway stay internal. Review multi-Gateway inputs, and convert each
  Gateway workload's resources separately when their reachability differs.
* Client-IP based plugins (`ip_restriction`, IP rate limits) use the socket peer until
  `FERRUM_TRUSTED_PROXIES` is configured. Trusted-proxy settings are only suggested.

## Determinism

Output contains no timestamps or random values. IDs derive from source names with stable
de-duplication, and plugin, upstream and consumer order follows source order. Proxy and upstream
names keep the source name for its first holder; repeats (one source route projected twice, closures
of one source scope, names equal after truncation or case folding, redacted names) get `-2`, `-3`...
within Ferrum's 255-byte limit. Uniqueness is compared trimmed and case-folded, and a final output
invariant checks it, because Ferrum admits neither duplicate proxy names nor duplicate ids. Running
twice produces byte-identical files (tested).

## Resource ceilings (defaults)

| Limit | Default |
|---|---|
| Input bytes | 8 MiB (max 256 MiB) |
| Structured node visits | 500,000 |
| Depth | 64 |
| YAML aliases | 64 |
| YAML documents (Istio) | 2,000 |
| String size | 1 MiB |
| Routes | 20,000 |
| NGINX tokens / block depth | 1,000,000 / 32 |
| Traefik pairwise precedence routes | 4,000 |
| Rule DNF alternatives | 32 |
