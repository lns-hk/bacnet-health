# PyInstaller spec - packaging spike: one --onedir folder holding a windowed GUI exe and a console CLI exe.
# Build with packaging/windows/build.ps1 (it puts work/dist dirs outside the synced source tree).
# Env BH_TEST_WEBENGINE=1 builds the variant that also bundles QtWebEngine (the real GUI shows reports in it).
import os

REPO = os.path.abspath(os.path.join(SPECPATH, "..", ".."))
SRC = os.path.join(REPO, "src")
WEBENGINE = os.environ.get("BH_TEST_WEBENGINE") == "1"

# Qt modules we never use; keeps the folder small.
QT_EXCLUDES = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
    "PySide6.Qt3DRender", "PySide6.QtBluetooth", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtGraphs", "PySide6.QtLocation", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtNfc", "PySide6.QtQuick3D", "PySide6.QtRemoteObjects",
    "PySide6.QtScxml", "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtSerialBus",
    "PySide6.QtSpatialAudio", "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtTextToSpeech",
    "PySide6.QtWebSockets", "PySide6.QtHttpServer", "PySide6.QtPdfWidgets",
    "tkinter", "unittest", "pydoc",
]
if not WEBENGINE:
    QT_EXCLUDES += [
        "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick",
        "PySide6.QtWebChannel", "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtQuickWidgets",
        "PySide6.QtPositioning", "PySide6.QtPdf",
    ]

gui_a = Analysis(
    [os.path.join(SPECPATH, "bh_gui_test.py")],
    pathex=[SRC],
    hiddenimports=["PySide6.QtWebEngineWidgets"] if WEBENGINE else [],
    excludes=QT_EXCLUDES,
    # LGPL: keep PySide6/shiboken6 Python modules as loose, replaceable .py files on disk
    # (the Qt6*.dll and *.pyd binaries are separate files in the onedir layout anyway).
    module_collection_mode={"PySide6": "py", "shiboken6": "py"},
)
cli_a = Analysis(
    [os.path.join(SPECPATH, "bh_cli_test.py")],
    pathex=[SRC],
    hiddenimports=["bacnet_health.active._win"],
    excludes=["PySide6", "shiboken6", "tkinter", "unittest", "pydoc"],
)

if not WEBENGINE:
    # Qt plugins pull in DLLs a widgets-only app never loads (QML/Quick via the virtual-keyboard
    # input plugin, Qt6Pdf via the PDF image-format plugin, and the 20 MB Mesa software OpenGL
    # fallback). Drop them; the window still renders through the native Windows platform plugin.
    _DROP = ("opengl32sw.dll", "qt6pdf.dll", "qt6quick", "qt6qml", "qt6virtualkeyboard",
             "qtvirtualkeyboardplugin.dll", "qpdf.dll")

    def _keep(entry):
        return not os.path.basename(entry[0]).lower().startswith(_DROP)

    gui_a.binaries = [b for b in gui_a.binaries if _keep(b)]

gui_pyz = PYZ(gui_a.pure)
cli_pyz = PYZ(cli_a.pure)

gui_exe = EXE(
    gui_pyz, gui_a.scripts, [],
    exclude_binaries=True,
    name="bacnet-health",       # windowed GUI: what onsite engineers double-click
    console=False,
    upx=False,                  # UPX-packed binaries attract more AV heuristics
)
cli_exe = EXE(
    cli_pyz, cli_a.scripts, [],
    exclude_binaries=True,
    name="bacnet-health-cli",   # console CLI in the same folder
    console=True,
    upx=False,
)

coll = COLLECT(
    gui_exe, gui_a.binaries, gui_a.datas,
    cli_exe, cli_a.binaries, cli_a.datas,
    strip=False, upx=False,
    name="bacnet-health",
)
