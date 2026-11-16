"""Allow ``python -m aegis``."""

from __future__ import annotations

import sys

from aegis.cli import main

if __name__ == "__main__":
    sys.exit(main())
