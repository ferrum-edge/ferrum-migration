# Runtime acceptance harness

Standalone, Python-stdlib-only acceptance tests for `ferrum-migration` output
against **Ferrum Edge v0.9.21** (reference commit `f9915358`). For each
synthetic fixture the harness:

1. starts two loopback echo backends (`127.0.0.1`, OS-assigned ports, held
   for the whole case),
2. renders the fixture source (`${ECHO_A_PORT}`, `${LISTEN_PORT}`, synthetic
   `${CANARY_*}` values…),
3. optionally serves it with the real source product and replays the probes
   (`--upstream-profile`, differential mode),
4. runs the converter through a caller-selected argv template (no shell),
5. checks credential handling and report findings,
6. runs `ferrum-edge validate -m file`,
7. runs `ferrum-edge run -m file` on fresh loopback ports, waits for
   authenticated `/health` readiness plus JWT `/proxies` ownership, and
8. sends each probe and asserts **which backend received it and with which
   request-target**, or that **no backend received it**.

## Run

```bash
# self-tests of the harness (fake converter + fake gateway; ~10 s)
python3 -m unittest discover -s acceptance/tests -v

# list cases
python3 acceptance/run.py --list

# representative smoke: one working migration per source (what CI gates on)
python3 acceptance/run.py --ferrum-bin /path/to/ferrum-edge --strict --require-behavioral \
  --converter-env PYTHONPATH=/path/to/ferrum-migration/src \
  --case kong-dbless-smoke --case kong-deck-smoke --case nginx-proxy-pass-uri \
  --case traefik-smoke --case envoy-smoke --case istio-smoke

# full runtime acceptance (all cases)
python3 acceptance/run.py --ferrum-bin /path/to/ferrum-edge \
  --converter-env PYTHONPATH=/path/to/ferrum-migration/src \
  --results acceptance-results.json

# converter-only gates (no Ferrum binary; STATIC_ONLY results)
python3 acceptance/run.py --no-ferrum --converter-env PYTHONPATH=/path/to/ferrum-migration/src
```

The default converter profile (`profiles/converter.default.json`) mirrors the
real CLI in `src/ferrum_migration/cli.py`:
`{python} -m ferrum_migration convert {source} --from {platform} --out {outdir}`,
plus `--include-secrets` for cases that opt in, and the argv the profile's
`assertion_argv` maps to each operator assertion a case names in
`converter_assertions`. Every Traefik case names
`traefik-input-includes-effective-controls`
(`--assert-traefik-input-includes-effective-controls`): its source is served on
the harness's own static configuration, the file provider alone with one
plaintext loopback entryPoint without TLS, middlewares, redirections or
forwarded-header settings, no router names entryPoints, and no TLS options or
routers exist outside the input, so the input includes every effective routing,
TLS and access control. Without the statement the converter refuses every
forwarding Traefik route. DB-less (`kong-dbless`) and
decK (`kong-deck`) cases both map to `--from kong`. There is no decK-specific
flag, because both share one schema; the report's `kong-input-flavor` caveat
records which flavor was detected. The output names are fixed
(`resources.yaml`, `ferrum.conf`, `migration-report.json`). The exit code is
cross-checked against the report: `0` must have no error findings, `4` must
have at least one, and `3` (input rejected, nothing written) can only count as
a safe refusal. Any other code fails the case.

`--converter-argv` overrides the argv template. Tokens: `{python} {source}
{outdir} {platform} {adapter} {workdir} {case_id}`; literal braces are
`{{`/`}}`. If the profile names no output files, outputs are discovered by
content.

Ferrum can be a binary (`--ferrum-bin`, or `$FERRUM_EDGE_BIN`) or any argv
prefix (`--ferrum-argv '["/opt/ferrum/bin/ferrum-edge"]'`). `version --json`
must report `0.9.21` unless `--allow-version-mismatch` is given.

Exit code: `0` when no case is `FAIL`/`ERROR` (with `--strict`, also no
`BLOCKED`/`SKIPPED`/`STATIC_ONLY`; with `--require-behavioral`, every selected
case must be a behavioral conversion); `1` otherwise; `2` for usage or
preflight errors.

## Statuses

| Status | Meaning |
|---|---|
| `PASS` | every probe matched; the case's `claims` are asserted with runtime evidence |
| `REJECTED_ACCEPTABLE` | **intentional safe refusal**, never a behavioral pass: the case allows refusal (or is deny-only), the converter refused with evidence (report error, or exit 3 input rejected), and no deny probe was forwarded; nothing claimed |
| `STATIC_ONLY` | `--no-ferrum`; converter/credential/report gates only |
| `BLOCKED` | output declares a `listen_port` the harness did not allocate; runtime skipped |
| `SKIPPED` | prerequisite missing |
| `FAIL` | wrong backend/path, forwarded deny probe, silent route drop, invalid output, credential leak, missing required finding, or fixture contradicted by the upstream run |
| `ERROR` | harness problem |

Each result also carries `outcome_kind`, which keeps "the migration works"
apart from "the migration safely refused":

| `outcome_kind` | Meaning |
|---|---|
| `behavioral-conversion` | `PASS` with at least one forwarded probe: traffic reached the right backend with the right request-target |
| `fail-closed-deny-only` | `PASS` whose probes are all denials (for example basic-auth routes emitted without credentials) |
| `safe-refusal` | `REJECTED_ACCEPTABLE` |
| `static-only` / `none` | no runtime evidence / failure |

Results also carry `source_truth` (`inferred-from-documentation` or
`verified-against-upstream-runtime`), `not_claimed` and `not_established`.

## Coverage by source

| Source | Representative working migration (smoke) | Other cases |
|---|---|---|
| Kong DB-less | `kong-dbless-smoke`: strip_path + service path, pass-through, method/host scoping, unrouted 404 | see `--list` |
| Kong decK | `kong-deck-smoke`: decK metadata, key-auth with an explicitly included synthetic key (valid key forwards; wrong/missing key denied) | `kong-deck-basic-auth-hash` (fail-closed deny-only: a stored hash never works as a password) |
| NGINX | `nginx-proxy-pass-uri`: proxy_pass URI replacement vs pass-through, exact location, no fallback | see `--list` |
| Traefik | `traefik-smoke`: Host + PathPrefix, stripPrefix, pass-through, host scoping | see `--list` |
| Envoy | `envoy-smoke`: prefix_rewrite, exact path, direct_response 403, vhost scoping | see `--list` |
| Istio | `istio-smoke`: ingress projection of a Gateway-bound VirtualService with ServiceEntry endpoints, uri rewrite, exact match | see `--list` |

No case claims Istio mesh behavior, database-mode import (`/batch` additive or
`/restore` replace), or live-database migration.

## Isolation

* Ferrum: `FERRUM_PROXY_HTTP_PORT`/`FERRUM_ADMIN_HTTP_PORT` are fresh
  loopback ports; `FERRUM_PROXY_HTTPS_PORT=0`, `FERRUM_ADMIN_HTTPS_PORT=0`; both
  bind addresses are `127.0.0.1` (Ferrum's proxy default is `0.0.0.0`); cwd,
  `HOME`, `TMPDIR` and `FERRUM_TLS_MANAGED_STORE_PATH` are inside the case work
  dir; the child gets a minimal environment (no inherited `FERRUM_*`/`RUST_LOG`).
* Synthetic gateway secrets (`FERRUM_METRICS_BEARER_TOKEN`,
  `FERRUM_ADMIN_JWT_SECRET`, `FERRUM_BASIC_AUTH_HMAC_SECRET`) are random per
  spawn, never printed, and scrubbed from logs. The basic-auth secret exists
  only because Ferrum's `basic_auth` plugin refuses to load without one;
  converted basic-auth routes carry no credentials, so it grants no access.
* Converter-emitted `ferrum.conf` is used for `validate`; for `run` it is
  dropped (with a note) if it names listener keys the harness does not pin.
* The harness's own HTTP listeners (echo backends, the self-test fake gateway)
  accept only numeric IPv4 loopback addresses and skip the stdlib's reverse-DNS
  `socket.getfqdn` lookup at bind time (`harness/loopback.py`).
* Every child runs in its own process group with bounded waits:
  SIGTERM → grace → SIGKILL, also from `atexit` and on SIGTERM/SIGHUP.
* Scratch: each run creates its own fresh private (mode `0700`) directory: a
  new temp dir by default, or a new `run-*` directory inside `--work-root`.
  Every case then gets its own fresh `<case-id>-*` directory in that run
  directory. `--work-root` is only a parent: entries already beneath it are
  never reused, followed or deleted. The work dirs of `PASS`,
  `REJECTED_ACCEPTABLE` and `STATIC_ONLY` cases are removed unless
  `--keep-workdirs` is given. Other cases keep theirs, and each result's
  `workdir` field records the path. When no work dir is kept, the run directory
  is removed too. `--results` is written exactly where given.

## Adding a case

`fixtures/<id>/case.json` plus one source file. The loader is strict (unknown
keys fail). Positive probes: `{"forward": {"backend": "a|b", "path": "…"}}`.
Deny probes: `{"deny": true, "status": [...]}`. Mark migration-policy probes
that the source product would answer differently with `"ferrum_only": true`.
Only add a claim when the request-target and backend are exactly determined by
the source product's documented semantics. Name a converter assertion in
`converter_assertions` only when the case's synthetic source is known to
satisfy it; an assertion the converter profile does not map is an `ERROR`.

To exercise behaviour that depends on backend failures (outlier detection), a case
can make echo backends answer every request with a 5xx status while still recording
it, for example `"backend_faults": {"a": 503}`, and send state-priming probes
`{"expect": {"prime": true}}` whose outcome asserts nothing. At least one probe of a
case must assert something; the assertions that follow the priming probes are the
evidence (see `fixtures/envoy-outlier-ejection`).
