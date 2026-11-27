#!/usr/bin/env python3
"""Release checks for ferrum-migration (standard library only).

Used by CI (``package`` job) and by ``.github/workflows/release.yml``:

* ``version`` prints the package version, read from ``src/ferrum_migration/__init__.py``
  without importing the package.
* ``tag --tag vX.Y.Z`` requires the tag to be exactly ``v`` + the package version, both
  strict ``X.Y.Z`` (no prerelease or build suffix, no leading zeros).
* ``notes --version X.Y.Z --out FILE`` writes the body of the ``## [X.Y.Z] - YYYY-MM-DD``
  section of ``CHANGELOG.md`` (refuses a missing, undated or empty section, and a section
  carrying the ``UNTAGGED_MARKER`` comment, which marks a historical, never-tagged version).
* ``dist --dir DIR`` requires exactly one sdist and one wheel for the package version, checks
  their core metadata (name, version, license expression and files, dependency, entry point),
  and requires both to contain exactly the package's modules under ``src/ferrum_migration``.
* ``release-assets --dist DIR --sums FILE --downloaded DIR`` accepts an existing GitHub release
  (a re-run of the release job) only if its downloaded assets are exactly this run's
  distributions plus ``SHA256SUMS``, byte for byte (SHA-256).
* ``pypi-plan --dir DIR --upload-dir OUT`` makes re-running the PyPI publish job safe: it reads
  the files PyPI already has for the package version (JSON API), refuses any published file whose
  SHA-256 differs from the local one or that is not a local file, and copies only the missing
  distributions into ``OUT``.
"""

from __future__ import annotations

import argparse
import ast
import datetime
import hashlib
import json
import re
import shutil
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from email.parser import HeaderParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INIT = Path("src") / "ferrum_migration" / "__init__.py"
DIST_NAME = "ferrum-migration"
FILE_STEM = "ferrum_migration"
LICENSE_EXPRESSION = "PolyForm-Noncommercial-1.0.0"
LICENSE_FILES = ("LICENSE", "LICENSE-COMMERCIAL.md")
ENTRY_POINT = "ferrum-migrate = ferrum_migration.cli:main"
REQUIRED_DEPENDENCY = re.compile(r"(?i)^pyyaml\b")
PYPI_JSON = "https://pypi.org/pypi"
#: A changelog section containing this comment documents a version that was never tagged
#: (a historical entry); the release workflow refuses to release it.
UNTAGGED_MARKER = "<!-- release-check: untagged historical entry; never released -->"

_NUM = r"(?:0|[1-9][0-9]*)"
VERSION_RE = re.compile(rf"{_NUM}\.{_NUM}\.{_NUM}")
TAG_RE = re.compile(rf"v{_NUM}\.{_NUM}\.{_NUM}")
_SECTION_RE = re.compile(r"^## \[(?P<name>[^\]]+)\](?P<rest>.*)$")
_DATE_RE = re.compile(r" - [0-9]{4}-[0-9]{2}-[0-9]{2}")


class ReleaseError(Exception):
    """A release precondition does not hold."""


def package_version(root: Path = ROOT) -> str:
    """Return the ``__version__`` literal of the package, without importing it."""
    path = root / INIT
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found = []
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "__version__" for target in node.targets
        ):
            if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                raise ReleaseError(f"{INIT}: __version__ must be a string literal")
            found.append(node.value.value)
    if len(found) != 1:
        raise ReleaseError(f"{INIT}: expected exactly one __version__ assignment, found {len(found)}")
    version = found[0]
    if not VERSION_RE.fullmatch(version):
        raise ReleaseError(f"{INIT}: __version__ {version!r} is not a strict X.Y.Z version")
    return version


def check_tag(tag: str, version: str) -> None:
    if not TAG_RE.fullmatch(tag):
        raise ReleaseError(f"tag {tag!r} is not a strict vX.Y.Z release tag")
    if tag != f"v{version}":
        raise ReleaseError(f"tag {tag!r} does not match the package version {version!r} (expected 'v{version}')")


def changelog_section(text: str, version: str) -> str:
    """Return the stripped body of the dated ``## [version]`` section of a changelog."""
    if not VERSION_RE.fullmatch(version):
        raise ReleaseError(f"{version!r} is not a strict X.Y.Z version")
    lines = text.splitlines()
    start = None
    for index, line in enumerate(lines):
        match = _SECTION_RE.match(line)
        if match and match.group("name") == version:
            if start is not None:
                raise ReleaseError(f"CHANGELOG.md has more than one [{version}] section")
            rest = match.group("rest").rstrip()
            if not _DATE_RE.fullmatch(rest):
                raise ReleaseError(f"CHANGELOG.md section [{version}] must be headed '## [{version}] - YYYY-MM-DD'")
            try:
                datetime.date.fromisoformat(rest[3:])
            except ValueError:
                raise ReleaseError(f"CHANGELOG.md section [{version}] has an impossible date {rest[3:]!r}") from None
            start = index + 1
    if start is None:
        raise ReleaseError(f"CHANGELOG.md has no [{version}] section")
    end = len(lines)
    for index in range(start, len(lines)):
        if lines[index].startswith("## "):
            end = index
            break
    body = "\n".join(lines[start:end]).strip()
    if not body:
        raise ReleaseError(f"CHANGELOG.md section [{version}] is empty")
    if UNTAGGED_MARKER in body:
        raise ReleaseError(f"CHANGELOG.md section [{version}] is marked as an untagged historical entry; "
                           "release a new version with its own section instead")
    return body + "\n"


def _metadata(raw: bytes):
    return HeaderParser().parsestr(raw.decode("utf-8"))


def _check_metadata(meta, version: str, where: str) -> None:
    problems = []
    if meta.get("Name") != DIST_NAME:
        problems.append(f"Name is {meta.get('Name')!r}, expected {DIST_NAME!r}")
    if meta.get("Version") != version:
        problems.append(f"Version is {meta.get('Version')!r}, expected {version!r}")
    if meta.get("License-Expression") != LICENSE_EXPRESSION:
        problems.append(f"License-Expression is {meta.get('License-Expression')!r}, expected {LICENSE_EXPRESSION!r}")
    license_files = meta.get_all("License-File") or []
    for name in LICENSE_FILES:
        if name not in license_files:
            problems.append(f"License-File {name!r} is missing")
    if meta.get_all("Classifier") and any(c.startswith("License ::") for c in meta.get_all("Classifier")):
        problems.append("a License :: classifier is present next to License-Expression")
    if meta.get("Description-Content-Type", "").split(";")[0].strip() != "text/markdown":
        problems.append("Description-Content-Type is not text/markdown")
    if not meta.get_all("Project-URL"):
        problems.append("no Project-URL entries")
    if not any(REQUIRED_DEPENDENCY.match(req) for req in meta.get_all("Requires-Dist") or []):
        problems.append("Requires-Dist does not name PyYAML")
    if problems:
        raise ReleaseError(f"{where}: " + "; ".join(problems))


def source_modules(root: Path = ROOT) -> list[str]:
    """The package's ``.py`` files, relative to ``src/`` (``ferrum_migration/cli.py``...)."""
    src = root / "src"
    modules = sorted(path.relative_to(src).as_posix() for path in (src / FILE_STEM).rglob("*.py")
                     if "__pycache__" not in path.parts)
    if not modules:
        raise ReleaseError(f"no modules found under {src / FILE_STEM}")
    return modules


def _compare_modules(found: list[str], expected: list[str], where: str) -> None:
    missing = sorted(set(expected) - set(found))
    extra = sorted(set(found) - set(expected))
    if missing or extra:
        raise ReleaseError(f"{where}: modules differ from src/{FILE_STEM}: missing {missing}, unexpected {extra}")


def check_dists(dist_dir: Path, version: str, root: Path = ROOT) -> list[str]:
    expected_modules = source_modules(root)
    sdist = f"{FILE_STEM}-{version}.tar.gz"
    wheel = f"{FILE_STEM}-{version}-py3-none-any.whl"
    present = sorted(path.name for path in dist_dir.iterdir())
    if present != sorted([sdist, wheel]):
        raise ReleaseError(f"{dist_dir}: expected exactly {sdist} and {wheel}, found {present}")

    with zipfile.ZipFile(dist_dir / wheel) as archive:
        info = f"{FILE_STEM}-{version}.dist-info"
        names = set(archive.namelist())
        _check_metadata(_metadata(archive.read(f"{info}/METADATA")), version, wheel)
        entry_points = archive.read(f"{info}/entry_points.txt").decode("utf-8")
        if ENTRY_POINT not in [line.strip() for line in entry_points.splitlines()]:
            raise ReleaseError(f"{wheel}: console script {ENTRY_POINT!r} is missing")
        for name in LICENSE_FILES:
            if f"{info}/licenses/{name}" not in names:
                raise ReleaseError(f"{wheel}: {info}/licenses/{name} is missing")
        _compare_modules([name for name in names if name.startswith(f"{FILE_STEM}/") and name.endswith(".py")],
                         expected_modules, wheel)

    with tarfile.open(dist_dir / sdist, "r:gz") as archive:
        prefix = f"{FILE_STEM}-{version}"
        member = archive.extractfile(f"{prefix}/PKG-INFO")
        if member is None:
            raise ReleaseError(f"{sdist}: PKG-INFO is missing")
        _check_metadata(_metadata(member.read()), version, sdist)
        names = set(archive.getnames())
        for name in LICENSE_FILES + ("README.md", "pyproject.toml"):
            if f"{prefix}/{name}" not in names:
                raise ReleaseError(f"{sdist}: {name} is missing")
        src_prefix = f"{prefix}/src/"
        _compare_modules([name[len(src_prefix):] for name in names
                          if name.startswith(f"{src_prefix}{FILE_STEM}/") and name.endswith(".py")],
                         expected_modules, sdist)
    return [sdist, wheel]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch_pypi_release(version: str, base: str = PYPI_JSON, timeout: float = 30.0) -> dict | None:
    """Return PyPI's JSON for ``DIST_NAME`` ``version``, or None when PyPI has no such release."""
    url = f"{base}/{DIST_NAME}/{version}/json"
    request = urllib.request.Request(url, headers={"Accept": "application/json", "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise ReleaseError(f"PyPI answered HTTP {exc.code} for {url}") from None


def pypi_upload_plan(dist_dir: Path, version: str, release: dict | None) -> list[Path]:
    """Return the local distributions PyPI does not have yet.

    A file PyPI already has must be byte-identical to the local one (same SHA-256), and PyPI
    must not have any file for this version that is not a local distribution.
    """
    local = {path.name: path for path in sorted(dist_dir.iterdir()) if path.is_file()}
    if not local:
        raise ReleaseError(f"{dist_dir}: no distributions")
    published: dict[str, str] = {}
    if release is not None:
        info_version = (release.get("info") or {}).get("version")
        if info_version is not None and info_version != version:
            raise ReleaseError(f"PyPI answered for version {info_version!r}, expected {version!r}")
        for entry in release.get("urls") or []:
            name = entry.get("filename")
            digest = (entry.get("digests") or {}).get("sha256")
            if not isinstance(name, str) or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ReleaseError("PyPI listed a file without a filename or a SHA-256 digest")
            if name in published:
                raise ReleaseError(f"PyPI listed {name} twice")
            published[name] = digest
    unexpected = sorted(set(published) - set(local))
    if unexpected:
        raise ReleaseError(f"PyPI has files for {version} that this run did not build: {unexpected}")
    missing = []
    for name, path in local.items():
        if name in published:
            actual = sha256_file(path)
            if published[name] != actual:
                raise ReleaseError(f"{name} on PyPI has SHA-256 {published[name]}, but this run built {actual}")
        else:
            missing.append(path)
    return missing


def check_release_assets(dist_dir: Path, sums: Path, downloaded: Path) -> list[str]:
    """Require the assets of an existing GitHub release to equal this run's files exactly."""
    expected = {path.name: path for path in dist_dir.iterdir() if path.is_file()}
    if sums.name in expected:
        raise ReleaseError(f"{dist_dir} must not contain {sums.name}")
    expected[sums.name] = sums
    actual = {path.name: path for path in downloaded.iterdir() if path.is_file()}
    others = [path.name for path in downloaded.iterdir() if not path.is_file()]
    if others or set(actual) != set(expected):
        raise ReleaseError(f"existing release assets {sorted(actual) + sorted(others)} are not exactly "
                           f"{sorted(expected)}")
    for name in sorted(expected):
        want, got = sha256_file(expected[name]), sha256_file(actual[name])
        if want != got:
            raise ReleaseError(f"existing release asset {name} has SHA-256 {got}, but this run built {want}")
    return sorted(expected)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("version", help="print the package version")
    tag = sub.add_parser("tag", help="require a tag equal to v + the package version")
    tag.add_argument("--tag", required=True)
    notes = sub.add_parser("notes", help="write a CHANGELOG.md section body")
    notes.add_argument("--version", required=True)
    notes.add_argument("--changelog", type=Path, default=ROOT / "CHANGELOG.md")
    notes.add_argument("--out", type=Path, required=True)
    dist = sub.add_parser("dist", help="check built sdist and wheel")
    dist.add_argument("--dir", type=Path, required=True)
    assets = sub.add_parser("release-assets", help="compare an existing release's assets with this run's files")
    assets.add_argument("--dist", type=Path, required=True)
    assets.add_argument("--sums", type=Path, required=True)
    assets.add_argument("--downloaded", type=Path, required=True)
    plan = sub.add_parser("pypi-plan", help="copy the distributions PyPI does not have yet into --upload-dir")
    plan.add_argument("--dir", type=Path, required=True)
    plan.add_argument("--upload-dir", type=Path, required=True)
    plan.add_argument("--github-output", type=Path, help="append upload=true|false to this file")
    plan.add_argument("--index", default=PYPI_JSON, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        version = package_version()
        if args.command == "version":
            print(version)
        elif args.command == "tag":
            check_tag(args.tag, version)
            print(version)
        elif args.command == "notes":
            if args.version != version:
                raise ReleaseError(f"--version {args.version!r} is not the package version {version!r}")
            args.out.write_text(changelog_section(args.changelog.read_text(encoding="utf-8"), version),
                                encoding="utf-8")
        elif args.command == "dist":
            for name in check_dists(args.dir, version):
                print(f"ok: {name}")
        elif args.command == "release-assets":
            for name in check_release_assets(args.dist, args.sums, args.downloaded):
                print(f"matches: {name}")
        elif args.command == "pypi-plan":
            check_dists(args.dir, version)
            missing = pypi_upload_plan(args.dir, version, fetch_pypi_release(version, args.index))
            args.upload_dir.mkdir(parents=True, exist_ok=False)
            for path in missing:
                shutil.copy2(path, args.upload_dir / path.name)
            for path in sorted(args.dir.iterdir()):
                state = "upload" if path in missing else "already on PyPI (SHA-256 matches)"
                print(f"{path.name}: {state}")
            if args.github_output is not None:
                with args.github_output.open("a", encoding="utf-8") as handle:
                    handle.write(f"upload={'true' if missing else 'false'}\n")
    except (ReleaseError, OSError, KeyError, ValueError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"release check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
