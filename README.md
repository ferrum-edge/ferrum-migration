# ferrum-migration

Offline, best-effort, **fail-closed** migration of existing gateway, reverse-proxy and
service-mesh configuration into [Ferrum Edge](https://github.com/ferrum-edge/ferrum-edge)
declarative config, so you can try Ferrum without rewriting every route by hand. The output is
a starting point for review, not a guaranteed equivalent of the source: whatever the tool
cannot reproduce is refused or reported.

| Source | Input accepted |
|---|---|
| Kong Gateway | DB-less `kong.yml` or a decK dump (`deck gateway dump`), YAML or JSON. Both share one schema, so `--from kong` handles either; no extra flag is needed, and the report states which flavor was detected. The tool never talks to a Kong database or Admin API. |
| NGINX OSS | One `nginx.conf`-syntax file with an `http {}` block (or bare `server {}` blocks). Includes are never followed. |
| Traefik OSS | Dynamic configuration for the file provider (`http` section), YAML, TOML or JSON. |
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

Mappings were verified against Ferrum Edge `main` at
`c1d73c35ef2e61a2c58c7a62a08ea70e35fff924` (config structs, plugin validators, and the settings
inventory). See [docs/mappings.md](docs/mappings.md).

## Install

Python 3.11+ and PyYAML.

```bash
python -m pip install .            # or: python -m pip install -e .
ferrum-migrate --version
```

## Use

```bash
ferrum-migrate platforms
ferrum-migrate check   kong.yaml   --from kong                 # report only, writes nothing
ferrum-migrate convert kong.yaml   --from kong    --out ./ferrum-out
ferrum-migrate convert nginx.conf  --from nginx   --out ./ferrum-out --tls-only
ferrum-migrate convert dynamic.yml --from traefik --out ./ferrum-out --run-mode database
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
| 3 | Input rejected (syntax, duplicate keys, size/node/depth/alias limits, unsupported shape); nothing written. |
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
  prefix locations, Kong `paths`, Traefik `PathPrefix`, Envoy `prefix` and Istio `uri.prefix`.
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
  Client-certificate requirements are never dropped as metadata. Traefik `tls.options` `clientAuth`
  (named or `default`) becomes the route's client CA. If it cannot be known or reproduced (another
  provider, undefined, several or inline CA files, unverified certificate types, or SNI-dependent
  selection), the route is refused. Istio `MUTUAL` servers with `subjectAltNames`,
  `verifyCertificateSpki`, `verifyCertificateHash` or `caCrl` are refused (`istio-client-ca`).
  When a plaintext and an HTTPS Istio server bind the same host, the shared routes keep the HTTPS
  server's client CA or refusal. A `match.port` route in such a shared projection is refused.
  When the two servers' host scopes overlap through different names (a wildcard and a host it
  covers) and the HTTPS server is stricter or routes depend on `match.port`, both projections are
  refused (`istio-shared-host-scope`). Separate Gateway bindings (other VirtualServices, or the same
  one through another Gateway) are checked together on the final plan, refused projections included:
  overlapping hosts served through different frontends (plaintext vs HTTPS, different client CA, or
  a refused frontend) refuse every projection involved (`istio-frontend-scope-conflict`).
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

See [docs/design.md](docs/design.md) for details and [SECURITY.md](SECURITY.md) for reporting issues.

## Limitations (read before serving any traffic)

* This is a starting point for trying Ferrum, not a production-readiness check. **Review every
  error in the report** before serving real traffic.
* Behavior has been checked only with original synthetic fixtures: unit tests, `ferrum-edge
  validate` admission, and loopback runtime acceptance against Ferrum Edge v0.9.21. It has not
  been validated against real deployments, so equivalence with your source configuration is not
  established.
* Only HTTP(S) reverse proxying is migrated. TCP/UDP/TLS-passthrough, mail, static file serving,
  dynamic xDS, Kubernetes service discovery and Istio subsets (which need pod labels) are reported, not translated.
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
  Ferrum host.
* Host-level refusals (regex `server_name`, unrepresentable domains) only poison catch-all
  routes; the residual cross-scope risk is described in docs/design.md.
* Some Ferrum behaviors could not be confirmed from source alone. They are listed under
  "Open questions" in [docs/mappings.md](docs/mappings.md).

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
name operator-supplied backend CA files. See [acceptance/README.md](acceptance/README.md) for
the runtime harness. CI runs it on Linux against the pinned published v0.9.21 binary.

Test fixtures under `tests/fixtures/` are original synthetic configurations; every credential
in them is a fake test string. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status and license

Early public build-out (v0.1.0).

Ferrum Migration is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).
For commercial use, see [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md).
Ferrum Edge is a separate product governed by its own license; the terms here cover
Ferrum Migration only.

Kong, NGINX, Traefik, Envoy and Istio are trademarks of their respective owners. This
project is not affiliated with them and contains no code from them.
