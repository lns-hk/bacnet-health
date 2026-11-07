"""Zip the release folder with '/' separators (APPNOTE 4.4.17).

Windows PowerShell 5.1's Compress-Archive writes '\' separators, which non-Windows unzip tools turn into flat
file names. Entries are sorted so the archive layout is stable.

    python make_zip.py ZIP APP_DIR [EXTRA_FILE ...]   # APP_DIR goes in as its folder name; extras at the zip root
"""

from __future__ import annotations

import os
import sys
import zipfile


def main(argv: list[str]) -> int:
    zip_path, app_dir, *extras = argv
    app_dir = os.path.abspath(app_dir)
    top = os.path.basename(app_dir)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for extra in extras:
            z.write(extra, os.path.basename(extra))
        for root, dirs, files in os.walk(app_dir):
            dirs.sort()
            for f in sorted(files):
                full = os.path.join(root, f)
                rel = os.path.relpath(full, app_dir).replace(os.sep, "/")
                z.write(full, f"{top}/{rel}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
