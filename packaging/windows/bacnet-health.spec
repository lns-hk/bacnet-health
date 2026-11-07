# PyInstaller spec: one --onedir folder `bacnet-health\` holding
#   bacnet-health.exe      windowed GUI (bacnet_health.gui.app:main) - what onsite engineers double-click
#   bacnet-health-cli.exe  console CLI  (bacnet_health.cli:main)
# Build with packaging/windows/build.ps1 (it also zips the folder and writes the .sha256).
import os
import re

from PyInstaller import config as _pyi_config
from PyInstaller.utils.hooks import collect_submodules
from PyInstaller.utils.win32.icon import IconFile
from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo,
)

HERE = SPECPATH
REPO = os.path.abspath(os.path.join(HERE, "..", ".."))
SRC = os.path.join(REPO, "src")
ICON = os.path.join(HERE, "bacnet-health.ico")
RTHOOK = os.path.join(HERE, "rthook_stdio.py")
RTHOOK_GUI = os.path.join(HERE, "rthook_gui_windows.py")

# Qt's Windows platform plugin uses an icon resource named IDI_ICON1 as the default window/taskbar icon. PyInstaller
# embeds the .ico as RT_ICON 1..n plus RT_GROUP_ICON 1; add a second group directory, named IDI_ICON1, that points
# at the same RT_ICON entries, so the window gets the app icon without any GUI code.
_ico = IconFile(ICON)
IDI_ICON1 = os.path.join(_pyi_config.CONF["workpath"], "idi_icon1.grp")
os.makedirs(os.path.dirname(IDI_ICON1), exist_ok=True)
with open(IDI_ICON1, "wb") as fh:
    fh.write(_ico.grp_icon_dir() + _ico.grp_icondir_entries(1))

with open(os.path.join(SRC, "bacnet_health", "__init__.py"), encoding="utf-8") as fh:
    VERSION = re.search(r'__version__\s*=\s*"([^"]+)"', fh.read()).group(1)
_nums = [int(x) for x in re.findall(r"\d+", VERSION)[:3]]
VERSION_TUPLE = tuple(_nums + [0] * (4 - len(_nums)))


def version_info(internal_name, description):
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=VERSION_TUPLE, prodvers=VERSION_TUPLE, mask=0x3F, flags=0x2 if "a" in VERSION
                          or "b" in VERSION or "rc" in VERSION else 0x0, OS=0x40004, fileType=0x1, subtype=0x0),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", "bacnet-health contributors"),
                StringStruct("FileDescription", description),
                StringStruct("FileVersion", VERSION),
                StringStruct("InternalName", internal_name),
                StringStruct("LegalCopyright", "MIT licence. Qt/PySide6: LGPL-3.0, see THIRD_PARTY_NOTICES.md"),
                StringStruct("OriginalFilename", internal_name + ".exe"),
                StringStruct("ProductName", "bacnet-health"),
                StringStruct("ProductVersion", VERSION),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )


# Everything except the GUI uses only the stdlib. Collect all core submodules explicitly: several are imported
# lazily inside functions (runner, report, active/_win, testing.synth for the demo/sample capture).
CORE = [m for m in collect_submodules("bacnet_health") if not m.startswith("bacnet_health.gui")]
GUI = collect_submodules("bacnet_health.gui")

# Qt modules the GUI never imports (it uses only QtCore, QtGui, QtWidgets). No QtWebEngine: reports open in the
# user's default browser.
QT_EXCLUDES = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
    "PySide6.Qt3DRender", "PySide6.QtBluetooth", "PySide6.QtCharts", "PySide6.QtConcurrent",
    "PySide6.QtDataVisualization", "PySide6.QtDBus", "PySide6.QtDesigner", "PySide6.QtGraphs",
    "PySide6.QtGraphsWidgets", "PySide6.QtHelp", "PySide6.QtHttpServer", "PySide6.QtLocation",
    "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets", "PySide6.QtNetwork", "PySide6.QtNetworkAuth",
    "PySide6.QtNfc", "PySide6.QtOpenGL", "PySide6.QtOpenGLWidgets", "PySide6.QtPdf", "PySide6.QtPdfWidgets",
    "PySide6.QtPositioning", "PySide6.QtPrintSupport", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtQuick3D",
    "PySide6.QtQuickControls2", "PySide6.QtQuickWidgets", "PySide6.QtRemoteObjects", "PySide6.QtScxml",
    "PySide6.QtSensors", "PySide6.QtSerialBus", "PySide6.QtSerialPort", "PySide6.QtSpatialAudio", "PySide6.QtSql",
    "PySide6.QtStateMachine", "PySide6.QtSvg", "PySide6.QtSvgWidgets", "PySide6.QtTest", "PySide6.QtTextToSpeech",
    "PySide6.QtUiTools", "PySide6.QtWebChannel", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineQuick",
    "PySide6.QtWebEngineWidgets", "PySide6.QtWebSockets", "PySide6.QtWebView", "PySide6.QtXml",
]
# _hashlib/_ssl pull in OpenSSL (libcrypto, 5 MB). Nothing needs it: sha256, blake2b and hmac fall back to
# CPython's built-in implementations, and the tool never opens TLS connections.
COMMON_EXCLUDES = ["tkinter", "unittest", "pydoc", "pytest", "_pytest", "lib2to3", "idlelib", "_hashlib", "_ssl",
                   "ssl"]

gui_a = Analysis(
    [os.path.join(HERE, "entry_gui.py")],
    pathex=[SRC],
    hiddenimports=CORE + GUI,
    excludes=QT_EXCLUDES + COMMON_EXCLUDES,
    # LGPL-3.0: keep the PySide6/shiboken6 Python modules as loose, replaceable .py files (the Qt6*.dll and *.pyd
    # binaries are separate files in the onedir layout anyway).
    module_collection_mode={"PySide6": "py", "shiboken6": "py"},
    runtime_hooks=[RTHOOK, RTHOOK_GUI],
)
cli_a = Analysis(
    [os.path.join(HERE, "entry_cli.py")],
    pathex=[SRC],
    hiddenimports=CORE,
    excludes=["PySide6", "shiboken6", "bacnet_health.gui"] + COMMON_EXCLUDES,
    runtime_hooks=[RTHOOK],
)

# Qt plugins pull in DLLs a widgets-only app never loads: QML/Quick (virtual-keyboard input plugin), Qt6Pdf (PDF
# image-format plugin), Qt6Network (TLS / network-information plugins), Qt6Svg (SVG icon/image plugins) and the 20 MB
# Mesa software OpenGL fallback. Drop them; the window renders through the native Windows platform plugin.
_DROP_PREFIXES = ("opengl32sw.dll", "qt6pdf", "qt6quick", "qt6qml", "qt6virtualkeyboard", "qt6network", "qt6svg",
                  "qt6opengl", "qtvirtualkeyboardplugin", "qpdf", "qsvg", "qschannelbackend", "qcertonlybackend",
                  "qopensslbackend", "qnetworklistmanager", "qtuiotouchplugin", "qtvirtualkeyboard",
                  # image formats the app never reads (it draws its icons; .ico stays) and unused platform plugins
                  # (qwindows is the real one; qoffscreen is kept for headless smoke tests)
                  "qgif", "qicns", "qjpeg", "qtga", "qtiff", "qwbmp", "qwebp", "qdirect2d", "qminimal")
_DROP_DIRS = ("translations", "qml", "networkinformation", "tls", "iconengines", "generic")


def _keep(entry):
    dest = entry[0].replace("\\", "/").lower()
    if os.path.basename(dest).startswith(_DROP_PREFIXES):
        return False
    return not any(f"/{d}/" in f"/{dest}" for d in _DROP_DIRS)


gui_a.binaries = [b for b in gui_a.binaries if _keep(b)]
gui_a.datas = [d for d in gui_a.datas if _keep(d)]

gui_exe = EXE(
    PYZ(gui_a.pure), gui_a.scripts, [],
    exclude_binaries=True,
    name="bacnet-health",
    console=False,               # PE subsystem 2: no console window
    icon=ICON,
    resources=[f"{IDI_ICON1},14,IDI_ICON1"],  # 14 = RT_GROUP_ICON
    version=version_info("bacnet-health", "bacnet-health (BACnet/IP network health check)"),
    upx=False,                   # UPX-packed binaries attract more AV heuristics
)
cli_exe = EXE(
    PYZ(cli_a.pure), cli_a.scripts, [],
    exclude_binaries=True,
    name="bacnet-health-cli",
    console=True,
    icon=ICON,
    version=version_info("bacnet-health-cli", "bacnet-health command line"),
    upx=False,
)

coll = COLLECT(
    gui_exe, gui_a.binaries, gui_a.datas,
    cli_exe, cli_a.binaries, cli_a.datas,
    strip=False, upx=False,
    name="bacnet-health",
)
