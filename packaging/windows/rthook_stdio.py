"""PyInstaller runtime hook: never crash on printing a character the output encoding cannot represent.

A frozen app ignores PYTHONIOENCODING/PYTHONUTF8. In a console window Python writes Unicode directly, but when the
CLI's output is redirected or piped it uses the ANSI code page (e.g. cp1252, cp932), and a localised adapter name
outside that code page would raise UnicodeEncodeError. Keep the encoding (Notepad/Excel read the file as the user's
locale) and escape what it cannot hold. UTF-8 mode is deliberately not used: it would also change how subprocess
output (w32tm, PowerShell) is decoded.
"""

import sys

for _name in ("stdout", "stderr"):
    _s = getattr(sys, _name, None)  # None in the windowed GUI exe
    if _s is not None and hasattr(_s, "reconfigure") and getattr(_s, "errors", "") == "strict":
        try:
            _s.reconfigure(errors="backslashreplace")
        except (OSError, ValueError):
            pass
