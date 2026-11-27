"""scripts/release_check.py: the tag, changelog and distribution gates of the release workflow."""

import contextlib
import hashlib
import importlib.util
import io
import os
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

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
Requires-Python: >=3.11
Requires-Dist: PyYAML<7,>=6.0.1
Description-Content-Type: text/markdown

# readme
"""


def build_fake_dists(directory: Path, version: str, metadata: str = METADATA, wheel_modules=None,
                     sdist_modules=None) -> None:
    modules = release_check.source_modules()
    wheel_modules = modules if wheel_modules is None else wheel_modules
    sdist_modules = modules if sdist_modules is None else sdist_modules
    info = f"ferrum_migration-{version}.dist-info"
    with zipfile.ZipFile(directory / f"ferrum_migration-{version}-py3-none-any.whl", "w") as wheel:
        wheel.writestr(f"{info}/METADATA", metadata.format(version=version))
        wheel.writestr(f"{info}/entry_points.txt", "[console_scripts]\nferrum-migrate = ferrum_migration.cli:main\n")
        for name in ("LICENSE", "LICENSE-COMMERCIAL.md"):
            wheel.writestr(f"{info}/licenses/{name}", "license\n")
        for module in wheel_modules:
            wheel.writestr(module, "")
    prefix = f"ferrum_migration-{version}"
    with tarfile.open(directory / f"{prefix}.tar.gz", "w:gz") as sdist:
        members = {"PKG-INFO": metadata.format(version=version)}
        for name in ("LICENSE", "LICENSE-COMMERCIAL.md", "README.md", "pyproject.toml"):
            members[name] = "x\n"
        for module in sdist_modules:
            members[f"src/{module}"] = ""
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
            "impossible date": ("## [1.0.0] - 2026-02-30\n\n- x\n", "1.0.0"),
            "month 13": ("## [1.0.0] - 2026-13-01\n\n- x\n", "1.0.0"),
            "empty": ("## [1.0.0] - 2026-01-01\n\n## [0.9.0] - 2025-01-01\n\n- x\n", "1.0.0"),
            "duplicate": ("## [1.0.0] - 2026-01-01\n\n- a\n\n## [1.0.0] - 2026-01-02\n\n- b\n", "1.0.0"),
            "unreleased": (CHANGELOG, "Unreleased"),
            "untagged historical entry": (
                f"## [1.0.0] - 2026-01-01\n\nNever tagged.\n\n{release_check.UNTAGGED_MARKER}\n\n- x\n", "1.0.0"),
        }
        for label, (text, version) in cases.items():
            with self.subTest(label), self.assertRaises(ReleaseError):
                release_check.changelog_section(text, version)

    def test_untagged_marker_only_blocks_its_own_section(self):
        text = (f"## [1.0.1] - 2026-02-01\n\n- y\n\n## [1.0.0] - 2026-01-01\n\n{release_check.UNTAGGED_MARKER}\n"
                "\n- x\n")
        self.assertEqual(release_check.changelog_section(text, "1.0.1"), "- y\n")
        with self.assertRaises(ReleaseError):
            release_check.changelog_section(text, "1.0.0")

    def test_repository_changelog_cannot_release_the_untagged_0_1_0(self):
        # 0.1.0 was set in the source when PR #1 merged but never tagged; its section carries the marker, so a
        # v0.1.0 tag fails the release workflow's validate job. The next version gets its own section.
        with open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8") as handle:
            text = handle.read()
        self.assertIn("## [Unreleased]", text)
        self.assertIn(release_check.UNTAGGED_MARKER, text)
        with self.assertRaisesRegex(ReleaseError, "untagged historical entry"):
            release_check.changelog_section(text, "0.1.0")


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

    def test_modules_must_match_the_source_package(self):
        modules = release_check.source_modules()
        self.assertIn("ferrum_migration/envprofile.py", modules)
        self.assertIn("ferrum_migration/sources/kong.py", modules)
        variants = {
            "wheel misses a module": {"wheel_modules": [m for m in modules if m != "ferrum_migration/envprofile.py"]},
            "wheel has an extra module": {"wheel_modules": modules + ["ferrum_migration/stray.py"]},
            "sdist misses a module": {"sdist_modules": [m for m in modules if m != "ferrum_migration/sources/kong.py"]},
        }
        for label, kwargs in variants.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as temp:
                build_fake_dists(Path(temp), "1.2.3", **kwargs)
                with self.assertRaisesRegex(ReleaseError, "modules differ"):
                    release_check.check_dists(Path(temp), "1.2.3")

    def test_rejects_wrong_metadata(self):
        bad = {
            "license": METADATA.replace("License-Expression: PolyForm-Noncommercial-1.0.0", "License-Expression: MIT"),
            "license file": METADATA.replace("License-File: LICENSE-COMMERCIAL.md\n", ""),
            "classifier": METADATA.replace("Classifier: Development Status :: 4 - Beta",
                                           "Classifier: License :: Free for non-commercial use"),
            "content type": METADATA.replace("text/markdown", "text/x-rst"),
            "urls": METADATA.replace("Project-URL: Source, https://github.com/ferrum-edge/ferrum-migration\n", ""),
            "version": METADATA.replace("Version: {version}", "Version: 0.0.1"),
            "dependency": METADATA.replace("Requires-Dist: PyYAML<7,>=6.0.1\n", ""),
        }
        for label, metadata in bad.items():
            with self.subTest(label), tempfile.TemporaryDirectory() as temp:
                build_fake_dists(Path(temp), "1.2.3", metadata)
                with self.assertRaises(ReleaseError):
                    release_check.check_dists(Path(temp), "1.2.3")



def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pypi_json(version: str, files: dict) -> dict:
    return {"info": {"version": version},
            "urls": [{"filename": name, "digests": {"sha256": digest}} for name, digest in files.items()]}


class PypiPlanTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name) / "dist"
        self.dir.mkdir()
        build_fake_dists(self.dir, "1.2.3")
        self.sdist = self.dir / "ferrum_migration-1.2.3.tar.gz"
        self.wheel = self.dir / "ferrum_migration-1.2.3-py3-none-any.whl"

    def plan(self, release):
        return release_check.pypi_upload_plan(self.dir, "1.2.3", release)

    def test_nothing_published_uploads_everything(self):
        self.assertEqual(self.plan(None), [self.wheel, self.sdist])
        self.assertEqual(self.plan(pypi_json("1.2.3", {})), [self.wheel, self.sdist])

    def test_partial_upload_retries_only_the_missing_file(self):
        self.assertEqual(self.plan(pypi_json("1.2.3", {self.wheel.name: sha256(self.wheel)})), [self.sdist])

    def test_complete_upload_needs_nothing(self):
        files = {self.wheel.name: sha256(self.wheel), self.sdist.name: sha256(self.sdist)}
        self.assertEqual(self.plan(pypi_json("1.2.3", files)), [])

    def test_refuses_digest_mismatch_unexpected_files_and_bad_answers(self):
        bad = {
            "digest mismatch": pypi_json("1.2.3", {self.wheel.name: "0" * 64}),
            "unexpected file": pypi_json("1.2.3", {"ferrum_migration-1.2.3-py3-none-manylinux.whl": "0" * 64}),
            "other version": pypi_json("1.2.4", {}),
            "malformed digest": pypi_json("1.2.3", {self.wheel.name: "not-a-digest"}),
            "duplicate": {"info": {"version": "1.2.3"}, "urls": [
                {"filename": self.wheel.name, "digests": {"sha256": sha256(self.wheel)}},
                {"filename": self.wheel.name, "digests": {"sha256": sha256(self.wheel)}}]},
        }
        for label, release in bad.items():
            with self.subTest(label), self.assertRaises(ReleaseError):
                self.plan(release)

    def test_command_copies_missing_files_and_reports_the_decision(self):
        dist = Path(self.temp.name) / "current"
        dist.mkdir()
        build_fake_dists(dist, __version__)
        wheel = dist / f"ferrum_migration-{__version__}-py3-none-any.whl"
        upload = Path(self.temp.name) / "upload"
        output = Path(self.temp.name) / "github-output"
        published = pypi_json(__version__, {wheel.name: sha256(wheel)})
        with mock.patch.object(release_check, "fetch_pypi_release", return_value=published) as fetch, \
                contextlib.redirect_stdout(io.StringIO()):
            code = release_check.main(["pypi-plan", "--dir", str(dist), "--upload-dir", str(upload),
                                       "--github-output", str(output)])
        self.assertEqual(code, 0)
        fetch.assert_called_once()
        self.assertEqual(sorted(path.name for path in upload.iterdir()), [f"ferrum_migration-{__version__}.tar.gz"])
        self.assertEqual(output.read_text(encoding="utf-8"), "upload=true\n")

        with mock.patch.object(release_check, "fetch_pypi_release", return_value=pypi_json(__version__, {
                wheel.name: "0" * 64})), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = release_check.main(["pypi-plan", "--dir", str(dist), "--upload-dir", str(Path(self.temp.name) / "u2")])
        self.assertEqual(code, 1)


class ReleaseAssetsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.dist = base / "dist"
        self.dist.mkdir()
        build_fake_dists(self.dist, "1.2.3")
        self.sums = base / "SHA256SUMS"
        self.sums.write_text("".join(f"{sha256(p)}  {p.name}\n" for p in sorted(self.dist.iterdir())), encoding="utf-8")
        self.downloaded = base / "downloaded"
        self.downloaded.mkdir()
        for path in list(self.dist.iterdir()) + [self.sums]:
            (self.downloaded / path.name).write_bytes(path.read_bytes())

    def check(self):
        return release_check.check_release_assets(self.dist, self.sums, self.downloaded)

    def test_accepts_identical_assets(self):
        self.assertEqual(self.check(), sorted([p.name for p in self.dist.iterdir()] + ["SHA256SUMS"]))

    def test_refuses_changed_missing_or_extra_assets(self):
        wheel = self.downloaded / "ferrum_migration-1.2.3-py3-none-any.whl"
        original = wheel.read_bytes()
        wheel.write_bytes(original + b"x")
        with self.assertRaisesRegex(ReleaseError, "SHA-256"):
            self.check()
        wheel.unlink()
        with self.assertRaisesRegex(ReleaseError, "not exactly"):
            self.check()
        wheel.write_bytes(original)
        (self.downloaded / "extra.txt").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(ReleaseError, "not exactly"):
            self.check()


if __name__ == "__main__":
    unittest.main()
