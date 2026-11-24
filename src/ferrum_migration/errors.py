"""Exception types whose messages are safe to print.

Every message passed to these exceptions is composed by this package from
positions, counts and schema names only. Input values (which may carry
credentials) must never be interpolated into them.
"""

from __future__ import annotations


class MigrationError(Exception):
    """Base class for errors that terminate a migration run."""


class InputError(MigrationError):
    """The input was rejected (syntax, limits, unsupported shape)."""


class OutputError(MigrationError):
    """Output could not be written safely."""
