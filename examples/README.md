# Examples

The synthetic inputs used by the test suite double as examples. Each one exercises
supported mappings and at least one fail-closed refusal:

| Platform | Input | Expected exit | Highlights |
|---|---|---|---|
| Kong | [`tests/fixtures/kong/kong.yaml`](../tests/fixtures/kong/kong.yaml) | 4 | shared service plugins (key-auth, ACL), route rate limit, weighted upstream with health checks, CORS/transformer, oauth2 route → 503 placeholder, `/orders` guard on `/`, withheld keys, unconvertible basic-auth hashes |
| NGINX | [`tests/fixtures/nginx/nginx.conf`](../tests/fixtures/nginx/nginx.conf) | 0 | HTTPS redirect → TLS-only, upstream with least_conn, `limit_req` → shared rate limit, allow/deny → ip_restriction, `return` → termination, body-size ceiling |
| Traefik | [`tests/fixtures/traefik/dynamic.yaml`](../tests/fixtures/traefik/dynamic.yaml) | 4 | with `--assert-traefik-entrypoints-add-no-controls`: DNF rule expansion, stripPrefix, security headers, weighted canary, header-matched router and `api@internal` refused. Without it: every forwarding router refused (`traefik-entrypoints-unverified`) |
| Traefik (TOML) | [`tests/fixtures/traefik/dynamic.toml`](../tests/fixtures/traefik/dynamic.toml) | 4 | with the assertion: v2 multi-host rule, ipAllowList, `prefix-string-siblings` review item. Without it: refused (`traefik-entrypoints-unverified`) |
| Envoy | [`tests/fixtures/envoy/envoy.yaml`](../tests/fixtures/envoy/envoy.yaml) | 4 | first-match shadowing, weighted clusters + prefix_rewrite, direct_response, header-matched route refused, vhost 404 closure |
| Istio | [`tests/fixtures/istio/istio.yaml`](../tests/fixtures/istio/istio.yaml) | 4 | Gateway TLS, weighted destinations, DestinationRule TLS/LB, ServiceEntry endpoints, CORS, subset route refused, mesh VS and Secret ignored |

Try them:

```bash
for p in kong:kong/kong.yaml nginx:nginx/nginx.conf traefik:traefik/dynamic.yaml envoy:envoy/envoy.yaml istio:istio/istio.yaml; do
  platform=${p%%:*}; file=${p#*:}
  ferrum-migrate convert "tests/fixtures/$file" --from "$platform" --out "/tmp/ferrum-example-$platform" --force
done
less /tmp/ferrum-example-kong/migration-report.md

# The synthetic Traefik fixtures stand for sources whose static entryPoints add no frontend controls.
# For a real source, pass this only after inspecting the Traefik static configuration (it is not verified):
ferrum-migrate convert tests/fixtures/traefik/dynamic.yaml --from traefik --out /tmp/ferrum-example-traefik-asserted \
  --force --assert-traefik-entrypoints-add-no-controls
```

Exit code 4 is expected for inputs that deliberately contain untranslatable items.
