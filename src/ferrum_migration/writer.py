"""Private, atomic output writing.

* The output directory is created with mode 0700 and must not be a symlink.
* Every file is written to a ``mkstemp`` temp file (mode 0600) in the same
  directory, fsynced and atomically renamed into place.
* Existing files are only replaced with ``--force``; symlinked targets are refused.
* All collisions are checked before anything is written.
"""

from __future__ import annotations

import os
import stat
import tempfile

from .errors import OutputError


def prepare_output_dir(path: str) -> str:
    target = os.path.abspath(path)
    if os.path.lexists(target):
        info = os.lstat(target)
        if stat.S_ISLNK(info.st_mode):
            raise OutputError("the output directory must not be a symlink")
        if not stat.S_ISDIR(info.st_mode):
            raise OutputError("the output path exists and is not a directory")
    else:
        try:
            os.makedirs(target, mode=0o700)
        except OSError:
            raise OutputError("the output directory cannot be created") from None
    return target


def write_files(directory: str, files: dict[str, str], force: bool) -> list[str]:
    for name in files:
        if os.sep in name or name.startswith("."):
            if name != ".gitignore":
                raise OutputError("invalid output file name")
        target = os.path.join(directory, name)
        if os.path.lexists(target):
            if os.path.islink(target):
                raise OutputError(f"{name} in the output directory is a symlink; refusing to write")
            if not force:
                raise OutputError(f"{name} already exists in the output directory (use --force to replace)")
    written = []
    for name, content in files.items():
        target = os.path.join(directory, name)
        handle, temp_path = tempfile.mkstemp(prefix=".ferrum-migration-", dir=directory)
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, target)
        except OSError:
            try:
                os.unlink(temp_path)
            except OSError:
                pass
            raise OutputError(f"failed to write {name}") from None
        written.append(target)
    return written
