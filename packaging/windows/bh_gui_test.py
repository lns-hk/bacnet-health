"""Packaging spike: minimal windowed PySide6 app (no console)."""
import os
import sys
import time

_T0 = time.perf_counter()

import bacnet_health  # noqa: E402
from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget  # noqa: E402

# The variant is detected by whether the spec bundled QtWebEngine (BH_TEST_WEBENGINE=1 at build time).
try:
    from PySide6.QtWebEngineWidgets import QWebEngineView  # type: ignore
except ImportError:  # widgets-only bundle
    QWebEngineView = None


def main() -> int:
    app = QApplication(sys.argv)
    w = QWidget()
    w.setWindowTitle("bacnet-health packaging test")
    lay = QVBoxLayout(w)
    lay.addWidget(QLabel(f"bacnet-health packaging test\nversion {bacnet_health.__version__}"))
    if QWebEngineView is not None and os.environ.get("BH_TEST_NO_WEB") != "1":
        v = QWebEngineView()
        v.setHtml("<p>QtWebEngine OK</p>")
        lay.addWidget(v)
    w.resize(420, 160)
    w.show()

    # --startup-probe=<file>: write seconds from process start of Python code to first
    # event-loop turn after show(), then quit (used by build.ps1 for timing).
    probe = next((a.split("=", 1)[1] for a in sys.argv if a.startswith("--startup-probe=")), None)
    if probe:
        def _done() -> None:
            with open(probe, "w", encoding="utf-8") as f:
                f.write(f"{time.perf_counter() - _T0:.3f}\n")
            app.quit()

        QTimer.singleShot(0, _done)
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
