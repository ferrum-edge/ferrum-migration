"""scripts/release_check.py: the tag, changelog and distribution gates of the release workflow."""

import importlib.util
import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from helpers import ROOT

from ferrum_migration import __version__

_SPEC = importlib.util.spec_from_file_location("release_check", os.path.join(ROOT, "scripts", "release_check.py"))
release_check = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(release_check)
ReleaseError = release_check.ReleaseError

CHANGELOG = """# Changelog

## [Unreleased]

### Added

- Something not released yet.

## [1.2.3] - 2026-01-02

### Fixed

- A fix.

## [1.2.2] - 2025-12-01

- Older.
"""

METADATA = """Metadata-Version: 2.4
Name: ferrum-migration
Version: {version}
Summary: test
License-Expression: PolyForm-Noncommercial-1.0.0
License-File: LICENSE
License-File: LICENSE-COMMERCIAL.md
Project-URL: Source, https://github.com/ferrum-edge/ferrum-migration
Classifier: Development Status :: 4 - Beta
Description-Content-Type: text/markdown

# readme
"""


def build_fake_dists(directory: Path, version: str, metadata: str = METADATA) -> None:
    info = f"ferrum_migration-{version}.dist-info"
    with zipfile.ZipFile(directory / f"ferrum_migration-{version}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"{info}/METADATA", metadata.format(version=version))
        wheel.writestr(f"{info}/entry_points.txt", "[console_scripts]\nferrum-migrate = ferrum_migration.cli:main\n")
        for name in ("LICENSE", "LICENSE-COMMERCIAL.md"):
            wheel.writestr(f"{info}/licenses/{name}", "license\n")
        for module in ("__init__.py", "cli.py", "sources/__init__.py"):
            wheel.writestr(f"ferrum_migration/{module}", "")
    prefix = f"ferrum_migration-{version}"
    with tarfile.open(directory / f"{prefix}.tar.gz", "w:gz") as sdist:
        members = {"PKG-INFO": metadata.format(version=version)}
        for name in ("LICENSE", "LICENSE-COMMERCIAL.md", "README.md", "pyproject.toml",
                     "src/ferrum_migration/__init__.py"):
            members[name] = "x\n"
        for name, text in members.items():
            data = text.encode("utf-8")
            entry = tarfile.TarInfo(f"{prefix}/{name}")
            entry.size = len(data)
            sdist.addfile(entry, io.BytesIO(data))


class PackageVersionTest(unittest.TestCase):
    def test_reads_the_package_version_without_importing(self):
        self.assertEqual(release_check.package_version(), __version__)

    def test_rejects_non_strict_or_ambiguous_versions(self):
        for body in ('__version__ = "1.0.0rc1"\n', '__version__ = "01.0.0"\n', '__version__ = "1.0"\n',
                     '__version__ = VERSION\n', '__version__ = "1.0.0"\n__version__ = "1.0.1"\n', "x = 1\n"):
            with self.subTest(body=body), tempfile.TemporaryDirectory() as temp:
                init = Path(temp) / "src" / "ferrum_migration" / "__init__.py"
                init.parent.mkdir(parents=True)
                init.write_text(body, encoding="utf-8")
                with self.assertRaises(ReleaseError):
                    release_check.package_version(Path(temp))


class TagTest(unittest.TestCase):
    def test_accepts_exactly_v_plus_version(self):
        release_check.check_tag("v1.2.3", "1.2.3")
        release_check.check_tag("v0.10.0", "0.10.0")

    def test_rejects_other_tags(self):
        for tag in ("1.2.3", "v1.2.4", "v1.2.3-rc.1", "v1.2.3rc1", "v1.2.3+build", "v1.2", "v01.2.3",
                    "v1.2.3 ", "V1.2.3", "v1.2.3\n", "release-1.2.3"):
            with self.subTest(tag=tag), self.assertRaises(ReleaseError):
                release_check.check_tag(tag, "1.2.3")


class ChangelogTest(unittest.TestCase):
    def test_extracts_the_dated_section(self):
        self.assertEqual(release_check.changelog_section(CHANGELOG, "1.2.3"), "### Fixed\n\n- A fix.\n")
        self.assertEqual(release_check.changelog_section(CHANGELOG, "1.2.2"), "- Older.\n")

    def test_refuses_missing_undated_empty_or_duplicate_sections(self):
        cases = {
            "missing": (CHANGELOG, "9.9.9"),
            "undated": ("## [1.0.0]\n\n- x\n", "1.0.0"),
            "bad date": ("## [1.0.0] - soon\n\n- x\n", "1.0.0"),
            "empty": ("## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-01-01\n\n- x\n", "1.0.0"),
            "duplicate": ("## [1.0.0] - 2026-01-01\n\n- a\n\n## [1.0.0] - 2026-01-02\n\n- b\n", "1.0.0"),
            "unreleased": (CHANGELOG, "Unreleased"),
        }
        for label, (text, version) in cases.items():
            with self.subTest(label), self.assertRaises(ReleaseError):
                release_check.changelog_section(text, version)

    def test_repository_changelog_has_the_current_version(self):
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("## [Unreleased]", text)
        self.assertTrue(release_check.changelog_section(text, __version__).strip())


class DistTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def test_accepts_matching_dists(self):
        build_fake_dists(self.dir, "1.2.3")
        self.assertEqual(release_check.check_dists(self.dir, "1.2.3"),
                         ["ferrum_migration-1.2.3.tar.gz", "ferrum_migration-1.2.3-py3-none-any.whl"])

    def test_rejects_wrong_version_or_extra_files(self):
        build_fake_dists(self.dir, "1.2.3")
        with self.assertRaises(ReleaseError):
            release_check.check_dists(self.dir, "1.2.4")
        (self.dir / "SHA256SUMS").write_text("", encoding="utf-8")
        with self.assertRaises(ReleaseError):
            release_check.check_dists(self.dir, "1.2.3")

    def test_rejects_wrong_metadata(self):
        bad = {
            "license": METADATA.replace("License-Expression: PolyForm-Noncommercial-1.0.0", "License-Expression: MIT"),
            "license file": METADATA.replace("License-File: LICENSE-COMMERCIAL.md\n", ""),
            "classifier": METADATA.replace("Classifier: Development Status :: 4 - Beta",
                                           "Classifier: License :: Free for non-commercial use"),
            "content type": METADATA.replace("text/markdown", "text/x-rst"),
            "urls": METADATA.replace("Project-URL: Source, https://github.com/ferrum-edge/ferrum-migration\n", ""),
            "version": METADATA.replace("Version: {version}", "Version: 0.0.1"),
        }
        for label, metadata in bad.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as temp:
                build_fake_dists(Path(temp), "1.2.3", metadata)
                with self.assertRaises(ReleaseError):
                    release_check.check_dists(Path(temp), "1.2.3")


if __name__ == "__main__":
    unittest.main()
