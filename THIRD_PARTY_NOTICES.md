# Third-party notices

bacnet-health is released under the MIT licence. The Python package (`pip install bacnet-health`) has **no**
third-party runtime dependencies. The optional GUI (`bacnet-health[gui]`) and the Windows/macOS release builds include
the components below. The full licence texts are in the `licenses/` folder of the release zip.

| Component | Version in 0.1.0a1 Windows build | Licence | Where in the build |
|---|---|---|---|
| Qt (Qt Core, Qt GUI, Qt Widgets and plugins) | 6.12.0 | LGPL-3.0 | `_internal/PySide6/Qt6*.dll`, `_internal/PySide6/plugins/` |
| PySide6 (Qt for Python) | 6.12.0 | LGPL-3.0 | `_internal/PySide6/` |
| shiboken6 | 6.12.0 | LGPL-3.0 | `_internal/shiboken6/` |
| Python | 3.12.10 | PSF License Agreement | `_internal/python312.dll`, `_internal/*.pyd`, `_internal/base_library.zip` |
| Microsoft Visual C++ runtime (VCRUNTIME140, MSVCP140, UCRT) | 14.x | Microsoft Visual Studio redistributable terms | `_internal/`, `_internal/PySide6/`, `_internal/shiboken6/` |
| PyInstaller bootloader | 6.22.3 | GPL-2.0-or-later with the PyInstaller bootloader exception | `bacnet-health.exe`, `bacnet-health-cli.exe` |

## Qt, PySide6 and shiboken6 (LGPL-3.0)

Copyright (C) The Qt Company Ltd. and other contributors.

Qt, PySide6 and shiboken6 are used under the GNU Lesser General Public License version 3 (LGPL-3.0). The LGPL-3.0
text is in `licenses/LGPL-3.0.txt`; it supplements the GNU General Public License version 3, whose text is in
`licenses/GPL-3.0.txt`. bacnet-health does not modify Qt, PySide6 or shiboken6.

- **Replacing the libraries.** The Windows build is a PyInstaller "one-folder" build. Every Qt library is a separate
  file (`_internal/PySide6/Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Widgets.dll`, the plugins, and the PySide6/shiboken6
  `.pyd`/`.dll` binaries), and the PySide6/shiboken6 Python modules are shipped as plain `.py` files. You may replace
  them with your own, interface-compatible builds of the same version. Nothing is statically linked and no file is
  compressed or encrypted.
- **Source code.** The complete source of the versions used is available from The Qt Company:
  - Qt 6.12.0: <https://download.qt.io/official_releases/qt/6.12/>
  - PySide6 / shiboken6 6.12.0: <https://download.qt.io/official_releases/QtForPython/> (source archives
    `pyside-setup-everywhere-src-6.12.0`), and the `PySide6` / `shiboken6` source distributions on PyPI.
- Qt itself contains third-party code under permissive licences (for example zlib, libpng, HarfBuzz, FreeType,
  PCRE2, double-conversion, md4c). Their notices are listed at <https://doc.qt.io/qt-6/licenses-used-in-qt.html>.

The Qt modules in this build were installed from the official PySide6 wheels on PyPI, which are offered under
"LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only" (or a commercial licence). bacnet-health uses them under LGPL-3.0.

## Python (PSF License Agreement)

Copyright (c) 2001-2025 Python Software Foundation. All Rights Reserved.

The Windows build embeds the CPython 3.12 runtime and parts of its standard library. The Python licence, including
the notices of the third-party code built into CPython (for example zlib, bzip2, xz/liblzma, libmpdec, libffi), is in
`licenses/Python-PSF-LICENSE.txt` (copied from the Python installation used for the build).

## Microsoft Visual C++ runtime

`VCRUNTIME140*.dll`, `MSVCP140*.dll`, `ucrtbase.dll` and the `api-ms-win-*.dll` forwarders are Microsoft
redistributable runtime files, distributed under the Microsoft Visual Studio licence terms for redistributable code.

## PyInstaller bootloader

The two `.exe` launchers are built from the PyInstaller bootloader, Copyright (c) 2010-2025 PyInstaller Development
Team, licensed under GPL-2.0-or-later with an exception that permits distribution of the generated executables under
any licence (<https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt>).
