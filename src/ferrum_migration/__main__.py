"""Allow ``python -m ferrum_migration``."""

import sys

from .cli import main

if __name__ == "__main__":  # pragma: no cover - exercised through the CLI tests
    sys.exit(main())
