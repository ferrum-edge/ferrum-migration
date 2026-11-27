<p align="center">
  <img src="https://raw.githubusercontent.com/ferrum-edge/ferrum-migration/main/docs/ferrum_migration.png" alt="Ferrum Migration" width="400" />
</p>

<h1 align="center">Ferrum Migration</h1>

<p align="center"><b>Translate your config. Move to the Edge.</b></p>

<p align="center">
  <a href="#status"><img src="https://img.shields.io/badge/status-preview%20%280.x%29-yellow" alt="Status: preview (0.x)" /></a>
  <a href="https://github.com/ferrum-edge/ferrum-migration/actions/workflows/ci.yml"><img src="https://github.com/ferrum-edge/ferrum-migration/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI" /></a>
  <a href="https://github.com/ferrum-edge/ferrum-migration/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue" alt="License" /></a>
  <img src="https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue?logo=python&logoColor=white" alt="Python 3.11, 3.12, 3.13" />
  <img src="https://img.shields.io/badge/migrates%20from-Kong%20%7C%20NGINX%20%7C%20Traefik%20%7C%20Envoy%20%7C%20Istio-orange" alt="Migrates from Kong, NGINX, Traefik, Envoy, Istio" />
  <a href="https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.21"><img src="https://img.shields.io/badge/Ferrum%20Edge-v0.9.21-brightgreen" alt="Mappings verified against Ferrum Edge v0.9.21" /></a>
</p>

Offline, best-effort, **fail-closed** migration of existing gateway, reverse-proxy and
service-mesh configuration into [Ferrum Edge](https://github.com/ferrum-edge/ferrum-edge)
declarative config, so you can try Ferrum without rewriting every route by hand. The output is
a starting point for review, not a guaranteed equivalent of the source: whatever the tool
cannot reproduce is refused or reported.

| Source | Input accepted |
|---|---|
| Kong Gateway | DB-less `kong.yml` or a decK dump (`deck gateway dump`), YAML or JSON. Both share one schema, so `--from kong` handles either; no extra flag is needed, and the report states which flavor was detected. The tool never talks to a Kong database or Admin API. |
| NGINX OSS | One `nginx.conf`-syntax file with an `http {}` block (or bare `server {}` blocks). Includes are never followed. |
| Traefik OSS | Dynamic configuration for the file provider (`http` section), YAML, TOML or JSON. The static configuration (entryPoints) and other providers are not read, so forwarding routes are refused unless you pass `--assert-traefik-input-includes-effective-controls` (see Options). |
| Envoy | v3 static bootstrap (`static_resources`) with HTTP connection managers and inline `route_config`. |
| Istio | Networking CRDs (`Gateway`, `VirtualService`, `DestinationRule`, `ServiceEntry`) as multi-document YAML or a `kind: List`. This is an **ingress projection**: only Gateway-bound routes become Ferrum edge proxies. Mesh routing, sidecars and workload mTLS are reported, not migrated. |

It writes, into a private output directory:

* `resources.yaml`: Ferrum file-mode resources (proxies, upstreams, consumers, plugin_configs)
  with a `resource_counts` truncation seal.
* `ferrum.conf`: `KEY=value` settings for the run mode you pick (`file`, `database`, `cp`, `dp`).
  It contains no secrets. Values from the source (certificate, key and client CA paths, bind
  address) are quoted when Ferrum's parser needs it. A value that cannot be read back unchanged
  (line breaks or other non-printable characters) rejects the input (exit 3) before anything is
  written.
* `migration-report.md` and `migration-report.json`: every caveat, refusal and safe omission,
  plus next steps. These never contain credential values.

Mappings were verified against Ferrum Edge `v0.9.21` at
`f9915358c8032214f4034a17c28cdf72d14006c3` (config structs, plugin validators, and the settings
inventory). See [docs/mappings.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/docs/mappings.md).

## Install

Python 3.11+ and PyYAML. Ferrum Migration is a **preview** (see [Status](#status)).

From a release tag (`vX.Y.Z`; see the
[releases](https://github.com/ferrum-edge/ferrum-migration/releases) and the
[changelog](https://github.com/ferrum-edge/ferrum-migration/blob/main/CHANGELOG.md)):

```bash
python -m pip install "ferrum-migration @ git+https://github.com/ferrum-edge/ferrum-migration@vX.Y.Z"
ferrum-migrate --version
```

Each GitHub release also carries the wheel, the sdist, a `SHA256SUMS` file and GitHub build
provenance attestations. To install a downloaded wheel only if both checks pass (on macOS,
use `shasum -a 256 -c -` in place of `sha256sum --strict -c -`):

```bash
wheel=ferrum_migration-X.Y.Z-py3-none-any.whl
grep -F "  $wheel" SHA256SUMS | sha256sum --strict -c - &&
  gh attestation verify "$wheel" -R ferrum-edge/ferrum-migration &&
  python -m pip install "$wheel"
```

From a checkout of this repository:

```bash
python -m pip install .            # or: python -m pip install -e .
```

PyPI: the release workflow publishes to PyPI only after the maintainers have enabled it
([docs/releasing.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/docs/releasing.md)),
so a GitHub release does not imply a PyPI upload. If
[pypi.org/project/ferrum-migration](https://pypi.org/project/ferrum-migration/) lists a
release, `python -m pip install ferrum-migration==X.Y.Z` installs it; otherwise install from a
tag as above.

## Use

```bash
ferrum-migrate platforms
ferrum-migrate check   kong.yaml   --from kong                 # report only, writes nothing
ferrum-migrate convert kong.yaml   --from kong    --out ./ferrum-out
ferrum-migrate convert nginx.conf  --from nginx   --out ./ferrum-out --tls-only
ferrum-migrate convert dynamic.yml --from traefik --out ./ferrum-out --run-mode database \
    --assert-traefik-input-includes-effective-controls       # only after the checklist under Options
ferrum-migrate convert envoy.yaml  --from envoy   --out ./ferrum-out
ferrum-migrate convert istio.yaml  --from istio   --out ./ferrum-out

# then, with a ferrum-edge binary:
cd ferrum-out && ferrum-edge validate --settings ferrum.conf --spec resources.yaml
```

Options:

| Option | Meaning |
|---|---|
| `--run-mode file\|database\|cp\|dp` | Which Ferrum operating mode `ferrum.conf` targets (default `file`). For database/cp, validate in file mode, then import through Ferrum's documented Admin API. This tool does no network I/O. |
| `--tls-only` | Disable Ferrum's plaintext listener so routes that were HTTPS-only in the source can be migrated. This is chosen automatically when every migrated route requires HTTPS. Routes the source served over plaintext only are then refused (`frontend-protocol-scope`), because Ferrum would serve them on its HTTPS listener. |
| `--assert-traefik-input-includes-effective-controls` | Traefik only (refused with exit 2 for other sources). Your scoped statement, made after you verified the Traefik deployment, that the input includes every effective routing, TLS and access control that applies within the converted scope (static, dynamic or from another provider), or that no additional control applies. Checklist, for every converted router: **static entryPoints** (file, CLI flags or environment) used by it (named in `entryPoints`, or the default entryPoints of routers that name none) add no TLS (`http.tls`), middlewares (`http.middlewares`), redirections (`http.redirections`), forwarded-header or PROXY protocol trust (`forwardedHeaders`, `proxyProtocol`) or bind restriction (`address`), and routers naming no entryPoints share the entryPoint the other routers of their protocol use; **omitted TLS options**: no TLS options from another provider or file apply, in particular no `default` TLS options outside the input (Traefik applies them to TLS routers that name none and to connections whose SNI no router claims); **SNI option conflicts**: no router outside the input maps the same host names to other TLS options; **competing routers**: no router of another provider or file matches the same hosts and paths on those entryPoints; and no middleware, service or `serversTransport` outside the input applies. The tool cannot check any of this; it is your representation, not a validation. Without it, every Traefik route that would forward traffic is refused (`traefik-controls-unverified`). With it, the report carries a `traefik-controls-asserted` warning, and everything the input states still applies or refuses, whatever you state: router `tls` (HTTPS-only), the one global handshake policy (HTTPS routes are translated only under the `default` TLS options, reached by naming no options, an empty reference or exactly `default`; any other TLS options definition or reference, including a provider-qualified `default@file`, refuses every HTTPS route, `traefik-tls-options-scope`), `default` `clientAuth` and `sniStrict` (enabled `sniStrict` refuses every HTTPS route, `traefik-sni-strict`), unresolved references (other providers, undefined names), middlewares, and explicit `entryPoints` lists (routers that leave out the entryPoint the other routers of their protocol share are refused, `traefik-entrypoint-scope`). An input that itself contains a static `entryPoints` section stays refused (`traefik-entrypoints-in-input`), and an input with a typed field spelled other than canonically is rejected outright (exit 3; see Safety model). |
| `--kubernetes-service-discovery` | Istio only (refused with exit 2 for other sources). Resolve destinations that are in-cluster Kubernetes Services (`<name>.<namespace>.svc.cluster.local`, no ServiceEntry) through Ferrum's Kubernetes service discovery: Ferrum lists the Service's EndpointSlices and balances across ready pods, as Istio's gateway does, instead of sending to the Service DNS name (its cluster IP). Include the Kubernetes `Service` objects in the input: they map the destination's Service port to the EndpointSlice port name. Discovery is used only where Ferrum reproduces Istio's endpoint set exactly; a destination whose Service is missing, an ExternalName, node-local (`internalTrafficPolicy: Local`), publishes not-ready addresses, has invalid names, or whose port is ambiguous keeps its DNS name (`istio-k8s-sd-port`); a non-TCP Service port refuses the route; a weighted split over several destinations keeps DNS names (`istio-k8s-sd-weighted`). HTTPS destinations keep verifying the Service name (`backend_tls_sni`). Ferrum must then run in the cluster with permission to list `discovery.k8s.io` EndpointSlices, and trust the API server through its outbound trust store: add the cluster CA (`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`) to the container's system roots, or set `FERRUM_TLS_CA_BUNDLE_PATH` to a bundle containing it and every other root Ferrum's outbound TLS needs (it replaces the system roots; Ferrum does not read the service account's `ca.crt` itself). The report spells this out (`kubernetes-service-discovery`). |
| `--include-secrets` | Explicit opt-in to write migratable plaintext credentials (Kong key-auth keys) into the resources file. Kong JWT secrets are never written (see Safety model). Output files are always mode `0600`; with this flag a `.gitignore` containing `*` is also written. |
| `--strict` | Treat warnings as "review required" (exit 4). |
| `--max-input-bytes N` | Input size cap (default 8 MiB). |
| `--resources-format yaml\|json` | Output format for the resources file. A resources file of the other format already in the output directory is refused (exit 5), even with `--force`, because Ferrum discovers `resources.yaml` before `resources.json`. Pass `--spec` explicitly when you run Ferrum. |
| `--force` | Replace existing output files (atomic rename). |

There is no option to turn backend TLS verification off. The former `--allow-insecure-backend-tls` flag
is refused with exit code 2, and nothing is written.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Migrated; no error-level caveats (warnings allowed unless `--strict`). |
| 1 | Internal error; nothing written. The exception text is never printed, because it could echo input. |
| 2 | Usage error. |
| 3 | Input rejected (syntax, duplicate keys, size/node/depth/alias limits, unsupported shape such as a Traefik typed field spelled other than canonically, or a Traefik router whose `parentRefs` is set to anything but an empty list); nothing written. |
| 4 | Output written, but it contains items that need review: refused or fail-closed routes, unmigrated credentials, or approximations that are less strict (also warnings with `--strict`). |
| 5 | Output could not be written safely (existing files without `--force`, symlinked target, permissions). |

## Safety model

The tool is conservative. When it cannot reproduce something faithfully, it fails closed
rather than opening routes or downgrading security:

* **Refused routes become placeholders.** A route that cannot be translated (unknown or
  unsupported auth/policy plugin, unrepresentable rewrite, HTTPS-only route in a mixed config, and so on)
  is replaced by a proxy with the same hosts, path and port. Its only plugin is
  `request_termination` (HTTP 503), which Ferrum runs before authentication. The refused
  traffic therefore cannot fall through to a broader, less protected route.
* **Unrepresentable matches poison overlaps.** Routes that match on headers, queries, SNI,
  regex hosts or similar cannot be expressed in Ferrum. Every route Ferrum would prefer for the
  overlapping requests is refused too.
* **Case-insensitive paths keep only their exact case.** Envoy `case_sensitive: false` and Istio
  `ignoreUriCase` matches stay migrated for their exact-case path, because Ferrum matches paths
  case-sensitively. Every other route that could receive their case variants (`/API` for `/api`) is
  refused instead of forwarding them; overlap checks compare such paths case-folded.
* **Precedence is checked, not assumed.** The tool checks first-match order (Envoy, Istio), router
  priorities (Traefik) and regex-versus-prefix precedence (NGINX, Kong) against Ferrum's specificity
  order. Unreachable routes are dropped and contradictory pairs are refused.
* **Prefix semantics are guarded.** The source prefix matchers listed below match plain strings,
  so `/api` also matches `/apix`, while Ferrum matches by path segment. Where a broader route has a different
  policy, a `request_termination` guard (`trigger.path_prefix`) is added so `/apix` cannot
  reach it. Trailing-slash prefixes get an exact 404 route for the bare path. Routes are never
  widened to cover `/apix`. When `/apix` would not reach an equivalent route in Ferrum, the report
  carries a `prefix-string-siblings` error (exit 4) instead of a silent 404. This applies to NGINX
  prefix locations, Kong `paths`, Traefik `PathPrefix`, Envoy `prefix` and Istio `uri.prefix`
  (except in VirtualServices Istio generates from Ingress or Gateway API resources, marked
  `internal.istio.io/route-semantics`, whose prefixes match by path segment like Ferrum's).
  It does not apply to Envoy `path_separated_prefix` (already segment-based), exact or regex
  matches, or prefixes ending in `/`. A refused route's placeholder is guarded the same way, so
  `/adminx` cannot reach a broader, open route when `/admin` was refused. If the broader route
  serves more hosts, the guard still applies to all of them and a `prefix-divergence-refused`
  error reports the extra 404s. Regex routes that the source's priority kept away from such
  siblings (an NGINX `^~` prefix, an earlier Envoy/Istio prefix) are guarded the same way when no
  prefix route in the host tier catches the siblings first. For a refused route, or a competing
  regex route, a guard that cannot be scoped exactly is still added (fail closed) and reported.
* **No cross-host fallthrough.** An NGINX server, Envoy virtual host or Istio host never falls
  through to another host's routes. Ferrum can, so a host-only 404 route closes each such scope.
  When another host-only route overlaps a scope without closing exactly its host names, a regex
  route matching every path (`~/.*`, 404, emitted after the scope's own routes) closes it instead.
  If that is not possible either, the routes that would receive its unmatched requests are refused
  (`scope-closure-skipped`). A wildcard scope that covers another scope's narrower wildcard
  (`*.example.com` and `*.team.example.com`) has its routes refused (`nested-wildcard-scope`),
  because Ferrum's wildcard tier compares the path routes of every matching pattern. An NGINX
  default server whose own `server_name` another server on the same listener covers keeps its
  named routes instead of becoming a catch-all (error `nginx-default-server-named`; unknown host
  names are then not routed to it). Default-server roles are decided on the listeners Ferrum
  actually serves (dropped extra ports do not count). A server that is the default on only some of
  them keeps its named hosts (`nginx-default-server-listener`), and different default servers on
  the main plaintext and TLS listeners have their catch-all routes refused
  (`nginx-default-server-conflict`).
* **Credentials are handled narrowly.** The only credentials that can be carried over are Kong
  key-auth keys. They are written only with `--include-secrets`, and only where Ferrum's semantics
  match: key length minimums and no shared keys. Kong HMAC JWT secrets are never written, not even
  with `--include-secrets` (`kong-jwt-credential-withheld`, or `kong-jwt-multiple-credentials`).
  Kong selects a JWT credential by its exact `key`. Ferrum's `jwt_auth` resolves the claim against
  every alias of a consumer (username, id, custom_id) and accepts the consumer-wide secret, so
  the one-to-one binding between a key and its secret cannot be reproduced. The `jwt_auth`
  plugin, the consumer and its other credentials are still migrated, so JWT authentication fails
  closed. A route that combines JWT with another authentication method is refused outright
  (`kong-auth-composition`), because the other method's credentials could still migrate. Issue a new random secret per consumer in Ferrum, and keep the Kong credential until
  clients have switched. No other source's credentials, and no other credential type, are portable.
  Password hashes (Kong basic-auth, htpasswd, Traefik `basicAuth`) cannot be converted.
  The matching auth plugin is emitted with no credentials, so nobody can authenticate until
  you create new Ferrum credentials. Consumers with consumer-scoped plugins or consumer groups
  are quarantined (credentials withheld). Kong input with `_transform: false` declares its
  credentials as stored (pre-transformed) values, so its key-auth keys and JWT secrets are never
  migrated. Static values for credential-like headers or query parameters (`Authorization`,
  `X-Api-Key`, `Cookie`, `apikey=`...) are never copied: the route is refused instead.
* **Backend TLS verification is always on.** NGINX, Kong and Envoy often do not verify upstream
  certificates by default, and Traefik/Istio can skip verification. Ferrum output always verifies
  (`backend_tls_verify_server_cert: true`), and there is no opt-out. Requests to backends with
  private CAs fail closed until you provide the CA. CA paths named by the source must exist on the
  Ferrum host, because Ferrum checks them when it loads the config. A Kong service whose
  `ca_certificates` restrict backend trust is refused rather than falling back to Ferrum's default
  trust store.
* **Client-certificate trust is never merged.** Ferrum file mode has one frontend client CA bundle
  per listener. It is configured only when every migrated mTLS scope used the same CA file. Different
  CA bundles from separate servers/listeners are never concatenated: the affected routes are refused
  with a `frontend-client-ca-scope` error, and you configure a separate Ferrum frontend per trust boundary.
  Client-certificate requirements are never dropped as metadata. Istio `MUTUAL` servers with `subjectAltNames`,
  `verifyCertificateSpki`, `verifyCertificateHash` or `caCrl` are refused (`istio-client-ca`).
  When a plaintext and an HTTPS Istio server bind the same host, the shared routes keep the HTTPS
  server's client CA or refusal. A `match.port` route in such a shared projection is refused.
  When the two servers' host scopes overlap through different names (a wildcard and a host it
  covers) and the HTTPS server is stricter or routes depend on `match.port`, both projections are
  refused (`istio-shared-host-scope`). Separate Gateway bindings (other VirtualServices, or the same
  one through another Gateway) are checked together on the final plan, refused projections included:
  overlapping hosts served through different frontends (plaintext vs HTTPS, different client CA, or
  a refused frontend) refuse every projection involved (`istio-frontend-scope-conflict`).
* **Traefik HTTPS needs one global handshake policy.** Traefik chooses TLS options during the handshake, by
  SNI, for every path of an entryPoint at once, while Ferrum's HTTPS listener applies one policy to every
  connection. HTTPS routes are therefore translated only when every TLS router uses the `default` TLS options
  (or Traefik's built-in default) and the input defines no other TLS options. Traefik stores `default` globally,
  without a provider qualifier, so a router uses it only when its `tls.options` is unset, empty or exactly
  `default`. This is checked on every router of the input as written, before rule parsing or shadowing. Any other
  TLS options definition (used or not, including a differently cased `Default`), or a reference to named,
  provider-qualified (`default@file` included), malformed (such as `default@`), undefined or unreadable options,
  refuses every HTTPS route whatever its hosts or paths (`traefik-tls-options-scope`). Per-route SNI selection is not reconstructed and no partial SNI
  equivalence is claimed. Plaintext routes are unaffected, and refused HTTPS routes stay HTTPS-only placeholders.
  Under that policy, `default` `clientAuth` becomes the client CA of every HTTPS route, or refuses them all
  when it cannot be reproduced (several or inline CA files, unverified certificate types, malformed;
  `traefik-client-auth`). Enabled `sniStrict` in `default` is an admission control Ferrum's listener cannot
  reproduce, so every HTTPS route is refused (`traefik-sni-strict`).
* **Traefik typed fields must be spelled canonically.** Traefik's file provider matches the field names of its typed
  configuration case-insensitively (`TLS` and `clientauth` act like `tls` and `clientAuth`), while this tool reads
  only the canonical spelling Traefik documents. A typed field spelled in another letter case, or given more than
  once in different letter case, rejects the whole input (exit 3, nothing written), with or without
  `--assert-traefik-input-includes-effective-controls`. This covers the top-level sections, `http` and `tls`,
  routers and their `tls` block, TLS options (`clientAuth` included), certificates and stores, services, load
  balancers, weighted and mirroring services, `serversTransports`, the middleware type key and the configuration of
  every middleware type the tool translates. The error names the canonical field path only. Names of routers,
  services, middlewares, `serversTransports`, TLS options and stores are case-sensitive identifiers in Traefik and
  are never folded: `Backend` and `backend` are two services, and `Default` is not the `default` TLS options.
* **Traefik child routers are never migrated as root routes.** Traefik v3.6 runs a router whose `parentRefs` names
  parent routers inside those parents: after the parents' middlewares, and under the parents' entryPoint and TLS
  constraints. The tool does not translate this inheritance, and serving the child as an independent route would drop
  the parents' controls. A router with `parentRefs` absent or exactly an empty list (`[]`) is an ordinary root router.
  Any other value on any router of the input (a nonempty list, an explicit null, or any other shape) rejects the
  whole input (exit 3, nothing written), with or without `--assert-traefik-input-includes-effective-controls`. The
  error names the canonical field path and a router count only. Other spellings of `parentRefs` are rejected by the
  canonical spelling check above.
* **Each route is served only on the protocols the source used.** Ferrum serves every route on each
  listener its profile opens, whatever the host names, so host names that look disjoint, unknown hosts
  or a missing TLS setting prove nothing (Ferrum opens HTTPS on its default port as soon as a frontend
  certificate is configured). Every translator records which main frontends (plaintext, HTTPS) served
  each route, and the output opens only protocols that every live route was served on:
  both listeners when every live route was served on both. When a live route was plaintext-only,
  HTTPS-only routes are refused and HTTPS is disabled explicitly (`FERRUM_PROXY_HTTPS_PORT=0`, no
  frontend TLS settings; `frontend-https-disabled`). With `--tls-only` or HTTPS-only sources, the
  plaintext listener is disabled (`FERRUM_PROXY_HTTP_PORT=0`) and plaintext-only routes are refused. This
  holds even when the source's HTTPS listener was not migrated (Envoy RDS, skipped listeners). A route
  without that information refuses the whole plan (`frontend-protocol-unknown`). The rendered `ferrum.conf`
  is checked against the decision before anything is written.
* **Traefik controls outside the input are never assumed.** The file provider input is dynamic configuration
  only. The entryPoints a router is attached to can add TLS, client certificate options, prepended middlewares,
  redirections, forwarded-header trust and bind restrictions; another provider can define the `default` TLS
  options, map the same hosts to other TLS options, or add competing routers. So a router without a `tls` block is
  not proven plaintext, and one with a `tls` block is not proven free of other controls. By default every Traefik
  route that would forward traffic is refused (503 placeholder, error `traefik-controls-unverified`, with the
  operator checklist). Only `--assert-traefik-input-includes-effective-controls`, given after you verified that the
  input includes every effective control within the converted scope (or that none is added), lets them forward;
  the tool records it as your unverified statement and still applies or refuses every control the input states.
* **Restricted listeners stay restricted.** NGINX `listen`, Envoy listener and Istio `Server.bind`
  addresses are reproduced only when every server shares one address (`FERRUM_PROXY_BIND_ADDRESS`).
  Otherwise the address-restricted servers (and Unix sockets) are skipped, never exposed on
  Ferrum's shared address.
* **Extra listeners are not migrated.** Ferrum's router selects host and path before it compares
  ports, and port-agnostic routes serve every HTTP listener, so a route scoped to an extra plaintext
  port (`listen_port`) cannot be kept apart from the main routes. Servers, Envoy listeners and Istio
  Gateway servers that only listen on another plaintext port get no proxy at all
  (`extra-listener-refused`), so Ferrum does not serve that port. The output never contains
  `listen_port`. A server that also listens on a main port is served on the main ports only.
* **Auth is not silently skipped.** Auth plugins, middlewares, directives and HTTP filters the
  tool cannot translate refuse their routes (see above). A Kong route whose effective policy (global,
  service and route plugins together) combines several authentication methods is refused
  (`kong-auth-composition`): Kong's composition and the consumer it selects are not proven
  equivalent in Ferrum, even when one method's credentials are withheld. One method per route is
  migrated as before. In addition, an Envoy route or virtual host whose
  `typed_per_filter_config` could enable or change an HTTP filter is refused. An Istio
  `AuthorizationPolicy`/`RequestAuthentication`/`EnvoyFilter`/`WasmPlugin` refuses a Gateway's
  routes unless it provably does not apply to the gateway pods, whatever namespace it lives in
  (neither the gateway pods' namespace nor their labels are part of the input). Only a `targetRef`
  to another resource, or a selector that pins one of the Gateway selector's label keys to another
  value, counts as proof. Extra label keys do not, and namespace-wide policies (no selector) always
  refuse.
* **No secrets in diagnostics.** Parser errors keep positions but withhold quoted spans.
  Reports name resources and counts, never values. PEM blocks, vault references and Kubernetes
  Secrets are never read into output.
* **Bounded, offline input handling.** Inputs are read from one regular file with size, node,
  depth, alias, document, token and route ceilings. YAML duplicate keys, merge keys and unsafe
  tags are rejected, and multi-document input is accepted only for Istio. Includes are not
  followed. There is no network, database or subprocess use.

See [docs/design.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/docs/design.md) for details and [SECURITY.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/SECURITY.md) for reporting issues.

## Limitations (read before serving any traffic)

* This is a starting point for trying Ferrum, not a production-readiness check. **Review every
  error in the report** before serving real traffic.
* Behavior has been checked only with original synthetic fixtures: unit tests, `ferrum-edge
  validate` admission, and loopback runtime acceptance against Ferrum Edge v0.9.21. It has not
  been validated against real deployments, so equivalence with your source configuration is not
  established.
* Only HTTP(S) reverse proxying is migrated. TCP/UDP/TLS-passthrough, mail, static file serving,
  dynamic xDS and Istio subsets (which need pod labels) are reported, not translated. Kubernetes service
  discovery is used only with `--kubernetes-service-discovery` (Istio).
* Ferrum file mode serves one default frontend certificate. With several source certificates
  you must pick one, or use a SAN certificate.
* Rate limits keep the average rate but not burst/delay semantics. Kong `cluster`/`redis`
  policies become per-node limits unless you configure Ferrum's Redis sync.
* Live databases are never migrated. Export Kong with decK first. For Ferrum database/cp
  mode, validate in file mode, then import through Ferrum's Admin API yourself. Convert the
  resources to JSON and drop the file-mode-only `resource_counts` key first. Then choose:
  `POST /batch` is an **additive**, all-or-nothing import next to existing configuration
  (1 MiB request limit). `POST /restore?confirm=true` **replaces** the namespace's whole
  configuration, so take `GET /backup` first. Neither import path is runtime-tested by this
  project.
* Istio output is an ingress projection only; it makes no claim about mesh behavior.
  `*.svc.cluster.local` destinations are emitted as plain DNS names that must resolve from the
  Ferrum host, unless `--kubernetes-service-discovery` is given (see Options).
* Host-level refusals (regex `server_name`, unrepresentable domains) only poison catch-all
  routes; the residual cross-scope risk is described in docs/design.md.
* Every Ferrum behavior the mappings rely on is cited to Ferrum Edge source in
  [docs/mappings.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/docs/mappings.md)
  ("Resolved from Ferrum Edge source" and "Forwarded path composition").

## Development

```bash
python -m pip install -r requirements-ci.txt
python -m unittest discover -s tests -v
python -m unittest discover -s acceptance/tests -v      # runtime harness self-tests (stdlib only)
# optional, against Ferrum itself:
FERRUM_EDGE_SRC=../refs/ferrum-edge python -m unittest discover -s tests -p 'test_ferrum_reference.py' -v
FERRUM_EDGE_BIN=/path/to/ferrum-edge python -m unittest discover -s tests -p 'test_ferrum_reference.py' -v
# runtime acceptance on loopback against a checksum-verified ferrum-edge v0.9.21:
python acceptance/run.py --ferrum-bin /path/to/ferrum-edge --converter-env PYTHONPATH="$PWD/src"
```

The binary admission test generates a throwaway synthetic CA with `openssl` for fixtures that
name operator-supplied backend CA files. See [acceptance/README.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/acceptance/README.md) for
the runtime harness. CI runs it on Linux against the pinned published v0.9.21 binary.

Test fixtures under `tests/fixtures/` are original synthetic configurations; every credential
in them is a fake test string. See [CONTRIBUTING.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/CONTRIBUTING.md).

## Status

**Preview.** Ferrum Migration is currently a `0.x` preview, offered alongside the Ferrum 1.0
product family (Ferrum Edge and its companion tools). Its `0.x` releases are **not** covered by the
compatibility promises that Ferrum's 1.0 products make. It is young, and it has only been checked
with synthetic fixtures, not against real deployments (see Limitations). A `1.0.0` release of this
tool, when it comes, will state its own compatibility promises in this section and the changelog.

* **No compatibility promise on `0.x`.** Any minor release (`0.x` to `0.y`) may change
  report codes and the JSON report layout, exit codes, CLI flags and output files. Every
  such change is recorded in the
  [changelog](https://github.com/ferrum-edge/ferrum-migration/blob/main/CHANGELOG.md).
  Pin an exact version in scripts.
* **One target Edge release per version.** The output of this version targets Ferrum Edge
  **v0.9.21** (`f9915358c8032214f4034a17c28cdf72d14006c3`). CI validates it against that
  exact release binary, verified against the release's checksum and a digest pinned in CI:
  every fixture's output must pass `ferrum-edge validate`, and the loopback runtime acceptance
  suite serves it with that binary. Other Edge versions are not validated; output may use
  settings or fields an older Edge lacks, and a newer Edge may behave differently. Two weekly,
  non-gating CI jobs detect drift early: one runs the same checks against Edge's newest
  published release, the other against the newest signed Edge `main` image, where it also
  checks the keys in every test fixture's output (one fixture set per source, including sticky
  cookie hashing) against Edge `main`'s source and files a tracking issue labelled
  `edge-main-drift` when anything fails. These key checks are fixture-based: they cover what
  the fixtures exercise.
* `ferrum-migrate --version` and both reports name the tool version and the Ferrum Edge
  commit the mappings were verified against.

Releases are `vX.Y.Z` Git tags with GitHub releases; see
[docs/releasing.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/docs/releasing.md).

## License

Ferrum Migration is licensed under the [PolyForm Noncommercial License 1.0.0](https://github.com/ferrum-edge/ferrum-migration/blob/main/LICENSE).
For commercial use, see [LICENSE-COMMERCIAL.md](https://github.com/ferrum-edge/ferrum-migration/blob/main/LICENSE-COMMERCIAL.md).
Ferrum Edge is a separate product governed by its own license; the terms here cover
Ferrum Migration only.

Kong, NGINX, Traefik, Envoy and Istio are trademarks of their respective owners. This
project is not affiliated with them and contains no code from them.
