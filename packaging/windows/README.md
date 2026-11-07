# Windows packaging (spike)

A PyInstaller `--onedir` build of a **test app**, not the real GUI: a minimal PySide6 window
("bacnet-health packaging test", shows `bacnet_health.__version__`) plus a console CLI exe in the same folder.
It exists to measure size, startup time, AV/SmartScreen behaviour and the LGPL layout before the real GUI (M4/M5).

| File | Purpose |
|---|---|
| `bacnet_health_test.spec` | Two `Analysis` → two `EXE` (`bacnet-health.exe` windowed, `bacnet-health-cli.exe` console) → one `COLLECT` folder |
| `build.ps1` | Creates a venv **outside the source tree**, runs PyInstaller, zips the folder, prints metrics as JSON |
| `bh_gui_test.py`, `bh_cli_test.py` | Entry scripts of the test app |

```powershell
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -OutDir C:\path\outside\repo\bh-build
powershell -ExecutionPolicy Bypass -File packaging\windows\build.ps1 -OutDir C:\path\outside\repo\bh-build -WebEngine
```

`-OutDir` is refused if it is inside the repository or a Synology folder. `-WebEngine` builds the variant that also
bundles QtWebEngine (the design shows the HTML report in-app with QWebEngine, §8.2).

## Results (Windows 11 Pro 25H2, build 26200.9457, Python 3.12.10, PySide6 6.12.0, PyInstaller 6.22.3)

| Variant | Folder | Files | Zip | GUI cold start | GUI warm start |
|---|---|---|---|---|---|
| widgets, untrimmed | 114.8 MB | 210 | 46.2 MB | 1.03 s | 0.22 s |
| **widgets, trimmed (current spec)** | **77.5 MB** | 204 | **30.8 MB** | 0.98 s | 0.22 s |
| with QtWebEngine (not yet trimmed) | 563.7 MB | 3103 | 213 MB | 0.68 s* | 0.60 s |

Start time = launch until the window has been shown once and the app has quit (`--startup-probe`). In-process time
from the first Python line to "window shown" is 0.12 s warm / 0.5 s cold. *The WebEngine row was measured after the
widgets builds had warmed the file cache.

- **Trimming:** Qt plugins pulled in QML/Quick (through the virtual-keyboard input plugin), Qt6Pdf (through the PDF
  image-format plugin) and the 20 MB Mesa `opengl32sw.dll`. The spec drops them for the widgets build. The window
  still renders. If a target PC has no usable GPU driver (some VMs/RDP), Qt may want `opengl32sw.dll` for
  Quick/WebEngine content. Keep it in the WebEngine build.
- **QtWebEngine costs about 500 MB unpacked / 180 MB zipped.** The spec's module excludes do not stop the PySide6
  hooks collecting most Qt DLLs once WebEngine is in. Options: trim aggressively, or render the report in the user's
  default browser (`QDesktopServices.openUrl` on the self-contained HTML file) and drop QtWebEngine. Recommendation:
  open the report in the default browser for 0.1.0a1. → owner decision.
- **Subsystems:** `bacnet-health.exe` is PE subsystem 2 (GUI, no console window). `bacnet-health-cli.exe` is subsystem
  3 (console).
- **USB-like path:** the folder copied to `C:\...\USB Drive (E)\Site Tools v1 ü 測試\bacnet-health\` (spaces,
  parentheses, Latin-1 and CJK characters) runs. The CLI exits 0 and the GUI shows its window and exits 0.
- **Windows Defender:** an on-demand `MpCmdRun -Scan -ScanType 3` of the folder found no threats. Real-time
  protection is **off** on the build PC, so the on-access scan was not exercised. Repeat on a PC with real-time
  protection on.
- **SmartScreen:** not observed. A locally built exe has no Mark-of-the-Web, so SmartScreen never checks it.
  SmartScreen policy on this PC is the default (on). The exe is unsigned (`Get-AuthenticodeSignature` →
  `NotSigned`). Expected behaviour when the zip is downloaded: "Windows protected your PC" → *More info* →
  *Run anyway*, until signing or reputation exists (D10: SignPath). **Human check needed:** download the zip from a
  GitHub release (or a test URL), extract it with Explorer and double-click the exe.
- **UPX is off** on purpose. UPX-packed PyInstaller bootloaders are a common AV false-positive trigger.

## LGPL notes (PySide6 / Qt are LGPL-3.0)

- The `--onedir` layout ships every Qt library as a separate file (`_internal\PySide6\Qt6*.dll`,
  `_internal\PySide6\*.pyd`, `_internal\shiboken6\*`). A user can replace them with modified builds of the same
  version, which is the "suitable shared library mechanism" of LGPL-3.0 §4(d)(1).
- PyInstaller normally puts pure-Python modules into its PYZ archive, where they cannot be replaced. The spec sets
  `module_collection_mode={"PySide6": "py", "shiboken6": "py"}` so the PySide6/shiboken6 Python modules are loose
  `.py` files on disk as well.
- Still to do for the release (M5): ship `THIRD_PARTY_NOTICES` with the LGPL-3.0 and GPL-3.0 texts and the Qt/PySide6
  copyright notices (§4(a)(b)). State the exact PySide6 version and where to get its source (download.qt.io / the
  PySide6 sdist). Do not use `--onefile`, which packs the DLLs into the exe. Keep UPX off (it also modifies the
  Qt DLLs). Have the LGPL wording reviewed before release (design §10 [TBV]).
