# Changelog

All notable changes to Ferrum Migration (`ferrum-migrate`) are recorded here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Ferrum Migration is currently a **preview** on `0.x`: until `1.0.0`, any minor release may
change report codes, exit codes, CLI flags and output layout (see
[Status](README.md#status)). Releases are `vX.Y.Z` tags; see
[docs/releasing.md](docs/releasing.md).

## [Unreleased]

### Added

- Release workflow (`.github/workflows/release.yml`): a pushed `vX.Y.Z` tag that
  equals the package version runs the full CI (unit, harness self-tests, packaging,
  and Ferrum Edge admission plus loopback runtime acceptance), builds the sdist and
  wheel, publishes `SHA256SUMS` and GitHub build provenance attestations, and creates
  a GitHub release whose notes are the version's section of this file. Publishing to
  PyPI uses Trusted Publishing and stays off until the repository variable
  `PYPI_PUBLISH` is exactly `true`; a re-run uploads only the files PyPI does not have
  yet and fails if a published file's SHA-256 differs from the run's build. A re-run of
  the GitHub release job accepts an existing release only if its assets match the run's
  files.
- CI `package` job: builds the sdist and wheel, runs `twine check --strict`, checks
  the core metadata, and runs the installed wheel's `ferrum-migrate`.
- Weekly, non-required `edge-release-drift` workflow that runs the admission tests
  and the full runtime acceptance against Ferrum Edge's newest published release.
- Packaging metadata: project URLs, classifiers (`Development Status :: 4 - Beta`),
  the PEP 639 license expression `PolyForm-Noncommercial-1.0.0` with both licence
  files, and a Markdown readme whose image and links resolve outside GitHub.
- README status section (preview, no compatibility promise on `0.x`, the Ferrum Edge
  release the output targets, installation from a tag) and `docs/releasing.md`.
- Envoy cluster `outlier_detection` and Istio DestinationRule `outlierDetection` map to
  passive health checks on consecutive 5xx errors (Ferrum Edge's own DestinationRule
  projection) where Ferrum reproduces them exactly: individual IP endpoints, a constant
  ejection time, no split local-origin counting, and one route per destination.
  Istio `connectionPool.tcp.connectTimeout` maps to the proxy connect timeout. Every
  other case and field (Envoy `circuit_breakers`, success-rate ejection, DNS-named
  endpoints, growing ejection times, Istio `minHealthPercent`, `maxConcurrentStreams`,
  `idleTimeout`, `http2MaxRequests`, ...) is reported with its own code instead of
  being approximated.
- Istio `portLevelSettings` replace the destination-level traffic policy wholesale
  (TLS and load balancer included), as Istio does, instead of inheriting omitted
  settings.
- The acceptance harness can run a backend that fails on demand (`backend_faults`) and
  send state-priming probes; the new `envoy-outlier-ejection` case shows an outlier
  ejection against the pinned Ferrum Edge.

- `--kubernetes-service-discovery` (Istio): in-cluster Service destinations use Ferrum's
  Kubernetes service discovery (EndpointSlices, one target per ready pod) instead of the
  Service DNS name, with the port chosen by name from the Kubernetes `Service` objects
  in the input. Node-local or not-ready-publishing Services, missing or invalid Service
  metadata and ambiguous ports keep their DNS name and are reported; non-TCP Service
  ports refuse the route. The report states Ferrum's runtime needs, including trusting
  the cluster CA through its outbound trust store.
- An outlier detector is kept only when no other route, including a weighted split that
  contains its destination, uses that destination.

### Changed

- The version has one source, `ferrum_migration.__version__`; `pyproject.toml`
  reads it as a dynamic version.
- README logo and badge header.
- CI pins PyYAML 6.0.4 and uses `actions/checkout` v7.0.1 and
  `actions/setup-python` v7.1.0.

## [0.1.0] - 2026-11-25

Initial build-out, merged as ferrum-edge/ferrum-migration#1. This version was set in
the source but never tagged or published, and it cannot be released: the release
workflow refuses a section carrying the marker below. The first tagged release gets
its own section.

<!-- release-check: untagged historical entry; never released -->

### Added

- `ferrum-migrate` CLI (`convert`, `check`, `platforms`; also
  `python -m ferrum_migration`) that translates one local file, offline, into Ferrum
  Edge file-mode configuration:
  - Kong Gateway DB-less `kong.yml` and decK dumps (YAML or JSON);
  - NGINX OSS `http {}` / `server {}` configuration (includes are never followed);
  - Traefik file-provider dynamic configuration (YAML, TOML or JSON); forwarding
    routes need `--assert-traefik-input-includes-effective-controls`;
  - Envoy v3 static bootstrap with inline `route_config`;
  - Istio `Gateway`, `VirtualService`, `DestinationRule` and `ServiceEntry`, as an
    ingress projection only.
- Output written to a private directory: `resources.yaml` (or `.json`) with a
  `resource_counts` seal, a secret-free `ferrum.conf` for the chosen run mode
  (`file`, `database`, `cp`, `dp`), and Markdown and JSON migration reports listing
  every caveat, refusal and safe omission.
- Fail-closed safety model: untranslatable routes become `request_termination`
  placeholders, unrepresentable matches poison overlapping routes, precedence and
  prefix-string semantics are checked, backend TLS verification is always on,
  client-certificate trust is never merged, and credentials are carried over only
  for Kong key-auth keys with `--include-secrets`.
- Bounded, offline input handling (size, node, depth, alias, document, token and
  route ceilings; YAML duplicate keys, merge keys and unsafe tags rejected), and
  diagnostics and reports that never contain input values.
- Exit codes 0 to 5 (migrated, internal error, usage, input rejected, review
  required, output not written safely).
- Mappings verified against Ferrum Edge v0.9.21
  (`f9915358c8032214f4034a17c28cdf72d14006c3`), documented in `docs/mappings.md`.
- Tests: unit and fail-closed tests on Python 3.11 to 3.13 (Linux and macOS), and a
  Linux job that admits the output with the checksum-verified Ferrum Edge v0.9.21
  binary (`ferrum-edge validate`) and runs the loopback runtime acceptance harness
  (`acceptance/`) on synthetic fixtures for every source.
