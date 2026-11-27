"""Enable ``python -m threatintel``."""

from __future__ import annotations

from threatintel.cli import main

if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
