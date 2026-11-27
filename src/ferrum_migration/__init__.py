"""ferrum-migration: offline, best-effort, fail-closed migration into Ferrum Edge config.

The tool reads one local configuration file (or export) from another gateway,
proxy or mesh and writes Ferrum Edge file-mode resources, a ``ferrum.conf``
profile and a migration report. It never performs network I/O, never follows
includes outside the given input and never starts or deploys anything.
"""

#: The package version, and its only source: pyproject.toml reads it as a dynamic
#: version, ``ferrum-migrate --version`` prints it, and reports record it as
#: ``tool_version``. A plain ``X.Y.Z`` literal; the release workflow requires the
#: pushed ``vX.Y.Z`` tag to equal it.
__version__ = "0.1.0"

#: Ferrum Edge commit whose config structs, plugin validators and settings
#: inventory the mappings were verified against.
FERRUM_EDGE_REFERENCE_COMMIT = "f9915358c8032214f4034a17c28cdf72d14006c3"

__all__ = ["__version__", "FERRUM_EDGE_REFERENCE_COMMIT"]
