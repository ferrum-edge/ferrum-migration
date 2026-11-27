# Releasing ferrum-migration

Ferrum Migration is a preview on `0.x` (see the README's Status section). A release is a
`vX.Y.Z` tag on `main` (strict `X.Y.Z`: no `-rc`, `-beta` or other suffix), a GitHub release
with the sdist, the wheel, `SHA256SUMS` and build provenance attestations, and, once enabled,
the same files on PyPI. Everything after the tag push is done by
[`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Release steps

1. **Prepare on a branch and merge through a pull request.**
   * Set `__version__` in `src/ferrum_migration/__init__.py` to `X.Y.Z`. It is the only
     version literal: `pyproject.toml` reads it, and `ferrum-migrate --version`, both reports,
     `ferrum.conf` and `resources.yaml` print it.
   * In `CHANGELOG.md`, move the `## [Unreleased]` entries into a new
     `## [X.Y.Z] - YYYY-MM-DD` section below it and leave `## [Unreleased]` in place. That
     section becomes the GitHub release notes; the workflow refuses a missing, undated or empty
     one.
   * If the release targets a different Ferrum Edge release, re-pin it in the same or an
     earlier pull request (see "Changing the target Ferrum Edge release").
   * Merge once every CI check on the pull request's head is green.
2. **Tag the merge commit on `main` and push the tag** (maintainers only):

   ```bash
   git fetch origin
   git tag -a vX.Y.Z -m "ferrum-migration X.Y.Z" <merge-commit-on-main>
   git push origin vX.Y.Z
   ```

3. **Watch the Release workflow.** Its jobs run in this order, and each stops the rest on
   failure:
   * `validate`: the tag is exactly `v` + `__version__`, names the run's commit, that commit is
     reachable from `main`, and the `CHANGELOG.md` section exists (`scripts/release_check.py`).
   * `ci`: the whole of `ci.yml` (unit and fail-closed tests on Linux and macOS, harness
     self-tests, packaging checks, and admission plus loopback runtime acceptance against the
     pinned Ferrum Edge binary).
   * `build`: sdist, then the wheel from the sdist, `twine check --strict`, metadata checks,
     `SHA256SUMS`.
   * `attest`: GitHub build provenance attestations for the sdist and the wheel.
   * `github-release`: creates the release with the files and the changelog section.
   * `pypi`: runs only when the repository variable `PYPI_PUBLISH` is `true`; uploads the same
     files with PyPI Trusted Publishing (no token).
4. **Check the result:** `gh release view vX.Y.Z -R ferrum-edge/ferrum-migration`, and
   `gh attestation verify <wheel> -R ferrum-edge/ferrum-migration` on a downloaded wheel.

A tag is never moved or reused. If the workflow fails because of the code or the changelog,
fix it on `main` and release the next patch version. If it fails because of the runner or the
network, re-run the failed jobs. If only `pypi` failed, re-run that job: it uploads the files
the run already built and attested.

## One-time owner setup

These are repository and account settings that only the owner can make. Until the first three
are done and `PYPI_PUBLISH` is set, releases go to GitHub only.

1. **PyPI project and trusted publisher.** On PyPI, add a *pending* trusted publisher (Account
   settings, Publishing) for the project `ferrum-migration`: owner `ferrum-edge`, repository
   `ferrum-migration`, workflow `release.yml`, environment `pypi`. The first successful upload
   creates the project. Before enabling it, confirm that publishing a PolyForm Noncommercial
   package on PyPI is acceptable to you under PyPI's terms of use; the package metadata
   declares `License-Expression: PolyForm-Noncommercial-1.0.0`.
2. **GitHub environment `pypi`.** Settings, Environments, New environment `pypi`. Limit its
   deployment branches and tags to the tag pattern `v*`, and add required reviewers if a manual
   approval before every PyPI upload is wanted.
3. **Repository variable `PYPI_PUBLISH`.** Settings, Secrets and variables, Actions,
   Variables: `PYPI_PUBLISH` = `true` once steps 1 and 2 are done. Any other value, or no
   variable, skips the `pypi` job.
4. **Branch ruleset for `main`** (recommended; the repository has none). Require a pull request
   before merging, block force pushes and deletion, and require these status checks from the
   CI workflow:
   * `test (ubuntu-24.04, python 3.11)`
   * `test (ubuntu-24.04, python 3.12)`
   * `test (ubuntu-24.04, python 3.13)`
   * `test (macos-15, python 3.12)`
   * `package (sdist + wheel, twine check)`
   * `ferrum-edge pinned release admission + runtime acceptance (linux)`

   Do not require `Edge release drift`: it tracks Edge's newest release and is an early warning.
5. **Tag ruleset for `v*`** (recommended): restrict creating, updating and deleting `v*` tags
   to maintainers, so only they can start a release and no published tag can be moved.

## Changing the target Ferrum Edge release

Each version targets exactly one Ferrum Edge release. Moving to another one is a
re-verification, not a version bump alone:

* `src/ferrum_migration/__init__.py`: `FERRUM_EDGE_REFERENCE_COMMIT`.
* `acceptance/harness/__init__.py`: `FERRUM_EDGE_REFERENCE_COMMIT`;
  `acceptance/harness/ferrum.py`: `EXPECTED_FERRUM_VERSION` and its docstring;
  `acceptance/run.py` and `acceptance/README.md`: the named version;
  `acceptance/tests/fake_ferrum.py`: the fake `version --json` answer.
* `.github/workflows/ci.yml` (`ferrum-runtime` job): `FERRUM_EDGE_VERSION`,
  `FERRUM_EDGE_SHA256` (the release asset's digest, cross-checked against the release's
  `.sha256` file) and the source commit fetched for the schema checks.
* `README.md` (badge, the verified-against paragraph, Limitations, Development, Status) and
  `docs/mappings.md`, after re-checking every mapping and "Open questions" entry against the
  new release's source.
* Code comments, docstrings and report messages that cite the old Edge version (search for
  it, for example `rg -n '0\.9\.21'` while v0.9.21 is the pin).
* A `CHANGELOG.md` entry.
