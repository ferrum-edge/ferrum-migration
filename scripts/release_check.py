#!/usr/bin/env python3
"""Release checks for ferrum-migration (standard library only).

Used by CI (``package`` job) and by ``.github/workflows/release.yml``:

* ``version`` prints the package version, read from ``src/ferrum_migration/__init__.py``
  without importing the package.
* ``tag --tag vX.Y.Z`` requires the tag to be exactly ``v`` + the package version, both
  strict ``X.Y.Z`` (no prerelease or build suffix, no leading zeros).
* ``notes --version X.Y.Z --out FILE`` writes the body of the ``## [X.Y.Z] - YYYY-MM-DD``
  section of ``CHANGELOG.md`` (refuses a missing, undated or empty section).
* ``dist --dir DIR`` requires exactly one sdist and one wheel for the package version and
  checks their core metadata (name, version, license expression and files, entry point).
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
import tarfile
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
            if not _DATE_RE.fullmatch(match.group("rest").rstrip()):
                raise ReleaseError(f"CHANGELOG.md section [{version}] must be headed '## [{version}] - YYYY-MM-DD'")
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
    if problems:
        raise ReleaseError(f"{where}: " + "; ".join(problems))


def check_dists(dist_dir: Path, version: str) -> list[str]:
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
        for module in ("__init__.py", "cli.py", "sources/__init__.py"):
            if f"ferrum_migration/{module}" not in names:
                raise ReleaseError(f"{wheel}: ferrum_migration/{module} is missing")

    with tarfile.open(dist_dir / sdist, "r:gz") as archive:
        prefix = f"{FILE_STEM}-{version}"
        member = archive.extractfile(f"{prefix}/PKG-INFO")
        if member is None:
            raise ReleaseError(f"{sdist}: PKG-INFO is missing")
        _check_metadata(_metadata(member.read()), version, sdist)
        names = set(archive.getnames())
        for name in LICENSE_FILES + ("README.md", "pyproject.toml", "src/ferrum_migration/__init__.py"):
            if f"{prefix}/{name}" not in names:
                raise ReleaseError(f"{sdist}: {name} is missing")
    return [sdist, wheel]


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
    except (ReleaseError, OSError, KeyError, zipfile.BadZipFile, tarfile.TarError) as exc:
        print(f"release check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
