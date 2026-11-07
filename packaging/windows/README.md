# Windows packaging

PyInstaller `--onedir` build of the real application: one folder `bacnet-health\` with two launchers that share
`_internal\`.

| Exe | Entry point | PE subsystem |
|---|---|---|
| `bacnet-health.exe` | `bacnet_health.gui.app:main` (PySide6 Widgets) | 2, windowed: no console window |
| `bacnet-health-cli.exe` | `bacnet_health.cli:main` | 3, console |

```powershell
# from the repository root, with the dev venv (pip install -e ".[dev,gui]" pyinstaller)
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Python .venv\Scripts\python.exe
# or in a clean build venv (created under <OutDir>\..\build\venv)
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -Venv
```

Output (default `-OutDir` = `<repo>\dist`, work files in `<repo>\build`; both are git-ignored, and paths inside a
SynologyDrive folder are refused):

```
dist\bacnet-health\                               the app folder (README-FIRST.txt, THIRD_PARTY_NOTICES.md, licenses\ inside)
dist\bacnet-health-<version>-win-x64.zip          README-FIRST.txt at the zip root + the bacnet-health\ folder
dist\bacnet-health-<version>-win-x64.zip.sha256   "<sha256> *<zip name>" (sha256sum -c compatible)
```

`build.ps1` prints a JSON summary (folder size, file count, Qt DLLs, zip size, SHA-256) and fails if a trimmed
module (WebEngine, Quick/QML, Pdf, Network, Svg, `opengl32sw.dll`) is still in the folder.

| File | Purpose |
|---|---|
| `bacnet-health.spec` | Two `Analysis` → two `EXE` → one `COLLECT`. Trimming, version resources, icon, LGPL layout |
| `build.ps1` | Runs PyInstaller, adds the release extras, zips, hashes, prints metrics |
| `entry_gui.py`, `entry_cli.py` | PyInstaller entry scripts |
| `rthook_stdio.py` | Runtime hook (both exes): redirected output never crashes on characters outside the ANSI code page |
| `rthook_gui_windows.py` | Runtime hook (GUI): `QT_QPA_PLATFORM=windows:darkmode=0` unless already set, so Windows dark mode does not turn parts of the light UI black |
| `make_icon.py` → `bacnet-health.ico` | Generates the app icon with QPainter (no third-party art). Re-run only to change the icon |
| `make_zip.py` | Writes the zip with `/` separators (PowerShell 5.1 `Compress-Archive` writes `\`, which breaks non-Windows unzip) |
| `README-FIRST.txt` | First-run instructions shipped in the zip (`{VERSION}` is filled in by `build.ps1`) |
| `licenses\` | LGPL-3.0 and GPL-3.0 texts from gnu.org (the PySide6 wheels ship none). Python's `LICENSE.txt` is copied from the build interpreter |
| `smoke-gui.ps1` | GUI smoke test: launch, no-console check, "Analyse a capture file" → sample → Done via UI Automation, screenshots |
| `screenshots\` | Phase 2 smoke-test screenshots at 100 % and 150 % (`QT_SCALE_FACTOR`) |

## Build decisions

- **Only QtCore/QtGui/QtWidgets.** The GUI imports nothing else; reports open in the default browser, so there is no
  QtWebEngine (it cost ~500 MB in the spike). The spec excludes the other PySide6 modules and drops plugin DLLs that
  pull in unused Qt libraries: QML/Quick (virtual keyboard), Pdf, Network (TLS/network-information), Svg, the
  software OpenGL fallback, unused image formats (only `qico` stays) and the `qdirect2d`/`qminimal` platform plugins.
  `qwindows` is the real platform plugin; `qoffscreen` is kept for headless smoke tests.
- **No OpenSSL.** `_hashlib`/`_ssl` are excluded (5 MB `libcrypto-3.dll`). sha256, blake2b and hmac fall back to
  CPython's built-in implementations; the tool never opens TLS connections.
- **Version resource** (both exes): FileVersion/ProductVersion string `0.1.0a1`, fixed version 0.1.0.0 with the
  pre-release flag, ProductName `bacnet-health`.
- **Icon:** embedded in both exes. The GUI exe also carries a group-icon resource named `IDI_ICON1`, which Qt's
  Windows platform plugin uses as the default window/taskbar icon (the GUI code does not set one).
- **UPX off**, unsigned. UPX-packed bootloaders attract AV false positives and UPX would also modify the Qt DLLs.

## LGPL notes (PySide6 / Qt are LGPL-3.0)

- The `--onedir` layout ships every Qt library as a separate file (`_internal\PySide6\Qt6*.dll`, plugins,
  `_internal\PySide6\*.pyd`, `_internal\shiboken6\*`). `module_collection_mode={"PySide6": "py", "shiboken6": "py"}`
  keeps their Python modules as loose `.py` files, not in the PYZ archive. A user can replace all of them with
  modified builds of the same version (LGPL-3.0 §4(d)(1)).
- `THIRD_PARTY_NOTICES.md` (repo root, shipped in the zip) gives the copyright notices, the versions, where to get
  the Qt/PySide6 source, and points to `licenses\LGPL-3.0.txt` + `licenses\GPL-3.0.txt` (§4(a)(b)).
- Do not use `--onefile` (it packs the DLLs into the exe). Have the LGPL wording reviewed before the release
  (design §10 [TBV]).

Measured results are in `docs/dev/windows-validation.md` ("Phase 2").
