#!/usr/bin/env bash
# Install a built wheel into an empty venv and run its console script.
#
# Usage: scripts/smoke-wheel.sh DIST_DIR
#
# Shared by the CI `package` job and the release `build` job, so the wheel a release
# uploads gets exactly the checks CI runs. Dependencies come from the wheel's own
# Requires-Dist (resolved into the empty venv); requirements-ci.txt only constrains their
# versions, so a wheel that drops a dependency fails here.
set -euo pipefail

dist_dir="$(cd "${1:?usage: scripts/smoke-wheel.sh DIST_DIR}" && pwd)"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected="$(python3 "$repo_root/scripts/release_check.py" version)"
wheel="$dist_dir/ferrum_migration-${expected}-py3-none-any.whl"
if [ ! -f "$wheel" ]; then
  echo "::error::$wheel not found"
  exit 1
fi

venv="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/wheel-venv.XXXXXX")"
trap 'rm -rf "$venv"' EXIT
python3 -m venv "$venv"
"$venv/bin/python" -m pip install --quiet --upgrade pip
"$venv/bin/python" -m pip install -c "$repo_root/requirements-ci.txt" "$wheel"
"$venv/bin/python" -m pip check

# Run from outside the checkout so nothing can be imported from the source tree.
cd "$venv"
installed="$("$venv/bin/python" -I -c 'import importlib.metadata as m; print(m.version("ferrum-migration"))')"
if [ "$installed" != "$expected" ]; then
  echo "::error::installed version $installed, expected $expected"
  exit 1
fi
out="$("$venv/bin/ferrum-migrate" --version)"
case "$out" in
  "ferrum-migration $expected "*) ;;
  *) echo "::error::ferrum-migrate --version printed '$out', expected version $expected"; exit 1 ;;
esac
"$venv/bin/ferrum-migrate" platforms
for pair in kong:kong/kong.yaml nginx:nginx/nginx.conf traefik:traefik/dynamic.yaml \
            traefik:traefik/dynamic.toml envoy:envoy/envoy.yaml istio:istio/istio.yaml; do
  platform="${pair%%:*}"; file="${pair#*:}"
  set +e
  "$venv/bin/ferrum-migrate" check "$repo_root/tests/fixtures/$file" --from "$platform" > /dev/null
  code=$?
  set -e
  # 0 = migrated, 4 = output needs review (expected for some fixtures); anything else is a failure.
  if [ "$code" -ne 0 ] && [ "$code" -ne 4 ]; then
    echo "::error::installed wheel: unexpected exit $code for $file"
    exit 1
  fi
done
echo "wheel smoke test passed: ferrum-migration $expected"
