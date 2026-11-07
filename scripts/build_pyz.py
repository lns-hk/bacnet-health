"""Build dist/bacnet-health.pyz: a single-file zipapp of the stdlib-only core and CLI (no GUI).

Usage: python scripts/build_pyz.py
"""

from __future__ import annotations

import pathlib
import shutil
import tempfile
import zipapp

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "bacnet_health"
DIST = ROOT / "dist"


def main() -> None:
    DIST.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        stage = pathlib.Path(tmp)
        shutil.copytree(SRC, stage / "bacnet_health",
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "gui"))
        (stage / "__main__.py").write_text("from bacnet_health.cli import main\nraise SystemExit(main())\n")
        target = DIST / "bacnet-health.pyz"
        zipapp.create_archive(stage, target, interpreter="/usr/bin/env python3", compressed=True)
    print(f"built {target} ({target.stat().st_size // 1024} KiB)")


if __name__ == "__main__":
    main()
