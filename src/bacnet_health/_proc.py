"""Run helper programs without ever showing a console window.

The Windows GUI build has no console, so each console program it starts (w32tm, tasklist, ...) would otherwise flash a
window of its own. Every subprocess in the package goes through :func:`run_hidden`, or passes ``creationflags`` itself.
"""

from __future__ import annotations

import subprocess
import sys
from typing import Any, Sequence

CREATE_NO_WINDOW = 0x08000000  # subprocess.CREATE_NO_WINDOW only exists on Windows


def run_hidden(cmd: Sequence[str], **kwargs: Any) -> subprocess.CompletedProcess:
    if sys.platform == "win32":
        kwargs["creationflags"] = kwargs.get("creationflags", 0) | CREATE_NO_WINDOW
    # A windowed exe has no valid stdin to inherit.
    kwargs.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(list(cmd), **kwargs)
