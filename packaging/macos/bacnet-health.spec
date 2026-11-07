# PyInstaller spec for the macOS .app (unsigned). Build with packaging/macos/build.sh.
import os

SRC = os.path.abspath(os.path.join(SPECPATH, "..", "..", "src"))
VERSION = "0.1.0a1"
EXCLUDES = [
    "PySide6.Qt3DAnimation", "PySide6.Qt3DCore", "PySide6.Qt3DExtras", "PySide6.Qt3DInput", "PySide6.Qt3DLogic",
    "PySide6.Qt3DRender", "PySide6.QtBluetooth", "PySide6.QtCharts", "PySide6.QtDataVisualization",
    "PySide6.QtGraphs", "PySide6.QtLocation", "PySide6.QtMultimedia", "PySide6.QtMultimediaWidgets",
    "PySide6.QtNfc", "PySide6.QtQuick3D", "PySide6.QtRemoteObjects", "PySide6.QtScxml", "PySide6.QtSensors",
    "PySide6.QtSerialPort", "PySide6.QtSerialBus", "PySide6.QtSpatialAudio", "PySide6.QtSql", "PySide6.QtTest",
    "PySide6.QtTextToSpeech", "PySide6.QtWebSockets", "PySide6.QtHttpServer", "PySide6.QtPdfWidgets",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtWebEngineQuick", "PySide6.QtWebChannel",
    "PySide6.QtQuick", "PySide6.QtQml", "PySide6.QtQuickWidgets", "PySide6.QtPositioning", "PySide6.QtPdf",
    "tkinter", "unittest", "pydoc",
]

a = Analysis(
    [os.path.join(SPECPATH, "entry_gui.py")],
    pathex=[SRC],
    hiddenimports=["bacnet_health.cli"],
    excludes=EXCLUDES,
    module_collection_mode={"PySide6": "py", "shiboken6": "py"},
)
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name="bacnet-health", console=False,
          target_arch=None, codesign_identity=None)
coll = COLLECT(exe, a.binaries, a.datas, name="bacnet-health")
app = BUNDLE(
    coll,
    name="bacnet-health.app",
    bundle_identifier="hk.lns.bacnet-health",
    version=VERSION,
    info_plist={
        "CFBundleShortVersionString": VERSION,
        "NSHighResolutionCapable": True,
        "LSMinimumSystemVersion": "12.0",
        "NSLocalNetworkUsageDescription": "bacnet-health listens to and queries BACnet devices on the building "
                                          "network you select. It never changes device settings.",
    },
)
