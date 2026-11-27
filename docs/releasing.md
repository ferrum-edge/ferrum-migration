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
     one, and one marked `<!-- release-check: untagged historical entry; never released -->`.
     `0.1.0` carries that marker (it was set in the source but never tagged), so the first
     tagged release needs a new version and section.
   * If the release targets a different Ferrum Edge release, re-pin it in the same or an
     earlier pull request (see "Changing the target Ferrum Edge release").
   * Merge once every CI check on the pull request's head is green.
2. **Tag the merge commit on `main` and push the tag** (maintainers only; the two tag rulesets
   in the one-time setup must exist before the first release tag is pushed):

   ```bash
   git fetch origin
   git tag -a vX.Y.Z -m "ferrum-migration X.Y.Z" <merge-commit-on-main>
   git push origin vX.Y.Z
   ```

3. **Watch the Release workflow.** Its jobs run in this order, and each stops the rest on
   failure:
   * `validate`: the tag is exactly `v` + `__version__`, names the run's commit, that commit is
     reachable from `main`, and the `CHANGELOG.md` section exists (`scripts/release_check.py`).
     These checks run from the tagged revision itself, so they catch mistakes but are not an
     authorization control: that is the tag rulesets and the `pypi` environment (see the
     one-time setup).
   * `ci`: the whole of `ci.yml` (unit and fail-closed tests on Linux and macOS, harness
     self-tests, packaging checks, and admission plus loopback runtime acceptance against the
     pinned Ferrum Edge binary).
   * `build`: sdist, then the wheel from the sdist, `twine check --strict`, metadata checks
     (including that both contain exactly the modules of `src/ferrum_migration`), the same
     clean-venv install and CLI smoke test CI runs (`scripts/smoke-wheel.sh`) on the exact
     wheel to be released, then `SHA256SUMS`.
   * `attest`: GitHub build provenance attestations for the sdist and the wheel.
   * `github-release`: re-resolves the remote tag and refuses to continue unless it still names
     the run's commit, then creates the release with the files and the changelog section. If a
     published release for the tag already exists (a re-run), it downloads its assets and
     continues only if they are exactly this run's files with the same SHA-256 digests.
   * `pypi`: runs only when the repository variable `PYPI_PUBLISH` is exactly `true` (compared
     case-sensitively in `validate`), after a required reviewer approves the `pypi` deployment. It reads which files PyPI already has for the
     version (JSON API), fails if any of them differs in SHA-256 from this run's build or was
     not built by this run, and uploads only the missing ones with PyPI Trusted Publishing (no
     token).
4. **Check the result:** `gh release view vX.Y.Z -R ferrum-edge/ferrum-migration`, and
   `gh attestation verify <wheel> -R ferrum-edge/ferrum-migration` on a downloaded wheel.

A tag is never moved or reused. If the workflow fails because of the code or the changelog,
fix it on `main` and release the next patch version. If it fails because of the runner or the
network, re-run the failed jobs; a re-run of `github-release` after the release was already
published verifies the existing release instead of failing, so `pypi` can still run. If its
assets differ from the run's files, stop: do not edit the release, release the next patch
version. If `pypi` failed, also after a partial upload, re-run that job: it uploads only the files PyPI does not have yet, from the run's already built and
attested artifacts. PyPI's JSON API can lag a fresh upload by a few minutes; if a re-run then
fails with PyPI's "file already exists" error, wait and re-run it again. Never re-run with
`skip-existing`: it would accept a published file without comparing its digest. A digest
mismatch means PyPI holds different bytes under that version, which cannot be replaced
(PyPI never reuses a filename); stop and release the next patch version.

## One-time owner setup

These are repository and account settings that only the owner can make. Do them in this order.
Steps 1 and 2 are required before the **first release tag** is pushed (a GitHub-only release
included); steps 4 and 5 are required before PyPI; step 6 enables PyPI and comes last. Until
then, releases go to GitHub only.

Why the order matters: a workflow triggered by a tag push is loaded from the tagged revision,
so anyone who can push a `v*` tag decides which `release.yml` runs, including its `validate`
checks. Those checks cannot authorize a release. PyPI's trusted publisher trusts this
repository, the `release.yml` workflow name and the `pypi` environment, nothing more. The
controls that decide who can publish are therefore outside the workflow: the tag rulesets
(who can create a `v*` tag, and that no tag can be moved) and the `pypi` environment's
required reviewers.

1. **Tag ruleset "release tags: creation"** (required before the first release): target tags matching
   `v*`, enforcement *Active*, rule *Restrict creations*, with only the release maintainers
   (a team or named users) in the bypass list.
2. **Tag ruleset "release tags: immutable"** (required before the first release): target tags
   matching `v*`, enforcement *Active*, rules *Restrict updates* and *Restrict deletions*, and
   **no bypass list**. Keep it separate from step 1: a bypass granted for creation would
   otherwise also exempt maintainers from the update and deletion rules. Without it, a tag
   moved between the workflow's tag re-check and the release's creation would give a GitHub
   release whose wheel comes from one commit and whose source archives come from another; the
   re-check narrows that window but cannot close it, only tag immutability does.
3. **Branch ruleset for `main`** (recommended; the repository has none). Require a pull request
   before merging, block force pushes and deletion, and require these status checks from the
   CI workflow:
   * `test (ubuntu-24.04, python 3.11)`
   * `test (ubuntu-24.04, python 3.12)`
   * `test (ubuntu-24.04, python 3.13)`
   * `test (macos-15, python 3.12)`
   * `package (sdist + wheel, twine check)`
   * `ferrum-edge pinned release admission + runtime acceptance (linux)`

   Do not require `Edge release drift` or `Edge main drift`: they track Edge's newest release
   and Edge `main`, and are early warnings.
4. **GitHub environment `pypi`** (required before PyPI). Settings, Environments, New
   environment `pypi`: under deployment branches and tags allow only the tag pattern `v*`, and
   add **required reviewers** (release maintainers; enable *Prevent self-review* if more than
   one maintainer can approve). Every PyPI upload then waits for an approval in addition to
   the tag rulesets.
5. **PyPI project and trusted publisher.** On PyPI, add a *pending* trusted publisher (Account
   settings, Publishing) for the project `ferrum-migration`: owner `ferrum-edge`, repository
   `ferrum-migration`, workflow `release.yml`, environment `pypi`. The first successful upload
   creates the project. Before this, confirm that publishing a PolyForm Noncommercial package
   on PyPI is acceptable to you under PyPI's terms of use; the package metadata declares
   `License-Expression: PolyForm-Noncommercial-1.0.0`.
6. **Repository variable `PYPI_PUBLISH`, last.** Settings, Secrets and variables, Actions,
   Variables: `PYPI_PUBLISH` = `true` only after steps 1, 2, 4 and 5. Any other value (`TRUE`
   and `True` included: the workflow compares it case-sensitively), or no variable, skips the
   `pypi` job.

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
  `docs/mappings.md`, after re-checking every mapping and every "Resolved from Ferrum Edge source"
  entry against the new release's source.
* Code comments, docstrings and report messages that cite the old Edge version (search for
  it, for example `rg -n '0\.9\.21'` while v0.9.21 is the pin).
* A `CHANGELOG.md` entry.
