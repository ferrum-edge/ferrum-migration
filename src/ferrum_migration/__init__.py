"""ferrum-migration: offline, best-effort, fail-closed migration into Ferrum Edge config.

The tool reads one local configuration file (or export) from another gateway,
proxy or mesh and writes Ferrum Edge file-mode resources, a ``ferrum.conf``
profile and a migration report. It never performs network I/O, never follows
includes outside the given input and never starts or deploys anything.
"""

__version__ = "0.1.0"

#: Ferrum Edge commit whose config structs, plugin validators and settings
#: inventory the mappings were verified against.
FERRUM_EDGE_REFERENCE_COMMIT = "c1d73c35ef2e61a2c58c7a62a08ea70e35fff924"

__all__ = ["__version__", "FERRUM_EDGE_REFERENCE_COMMIT"]
