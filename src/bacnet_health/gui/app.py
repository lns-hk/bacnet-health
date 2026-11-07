"""bacnet-health desktop application (PySide6 Widgets).

``main(argv)``: ``argv`` may contain one ``.bhprofile`` path; the app then opens straight into the health-check wizard
with that profile applied. Nothing is registered with the operating system.
"""

from __future__ import annotations

import copy
import os
import sys
import threading
import traceback
from typing import Any, Sequence

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QFont, QKeySequence
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from bacnet_health import __version__
from bacnet_health.gui import state, theme
from bacnet_health.gui.advanced import AdvancedDialog
from bacnet_health.gui.analyse import AnalysePage, VantageBar
from bacnet_health.gui.compare import ComparePage
from bacnet_health.gui.report_view import ReportPage
from bacnet_health.gui.widgets import Banner, label, scroll_page, show_error
from bacnet_health.gui.wizard import HealthCheckWizard
from bacnet_health.model import Result
from bacnet_health.profile import Profile

PROFILE_FILTER = "bacnet-health profile (*.bhprofile);;All files (*)"


def is_prerelease(v: str) -> bool:
    return any(t in v for t in ("a", "b", "rc", "dev"))


# =============================================================================================== home
class HomeButton(QPushButton):
    def __init__(self, icon: str, title: str, text: str):
        super().__init__()
        self.setObjectName("HomeButton")
        self.setAccessibleName(title)
        self.setAccessibleDescription(text)
        self.setCursor(Qt.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(22, 20, 22, 20)
        lay.setSpacing(18)
        ic = QLabel()
        ic.setPixmap(theme.home_icon(icon, 48))
        ic.setAttribute(Qt.WA_TransparentForMouseEvents)
        lay.addWidget(ic, 0, Qt.AlignTop)
        col = QVBoxLayout()
        col.setSpacing(4)
        t = QLabel(title)
        t.setStyleSheet("font-size: 14pt; font-weight: 600; background: transparent;")
        d = QLabel(text)
        d.setWordWrap(True)
        d.setObjectName("Muted")
        d.setStyleSheet("background: transparent;")
        for w in (t, d):
            w.setAttribute(Qt.WA_TransparentForMouseEvents)
        col.addWidget(t)
        col.addWidget(d)
        lay.addLayout(col, 1)
        arrow = QLabel("›")
        arrow.setStyleSheet(f"font-size: 22pt; color: {theme.ACCENT}; background: transparent;")
        arrow.setAttribute(Qt.WA_TransparentForMouseEvents)
        lay.addWidget(arrow, 0, Qt.AlignVCenter)
        self._labels = (t, d)

    def resizeEvent(self, e) -> None:  # noqa: N802
        super().resizeEvent(e)
        h = self.layout().heightForWidth(self.width())
        if h > 0 and h != self.minimumHeight():
            self.setMinimumHeight(h)


class HomePage(QWidget):
    def __init__(self, win: "MainWindow"):
        super().__init__()
        self.setObjectName("Page")
        body = QWidget()
        page = QVBoxLayout(self)
        page.setContentsMargins(0, 0, 0, 0)
        page.addWidget(scroll_page(body))
        outer = QHBoxLayout(body)
        outer.setContentsMargins(40, 36, 40, 28)
        outer.addStretch(1)
        col = QVBoxLayout()
        col.setSpacing(16)
        col.addWidget(label("What would you like to do?", "PageTitle"))
        col.addWidget(label("This tool checks the health of a building-management network. It only reads; it never "
                            "changes any setting on any device.", "PageIntro"))
        col.addSpacing(6)
        self.profile_note = Banner("info", "")
        col.addWidget(self.profile_note)
        self.run_btn = HomeButton("check", "Run health check",
                                  "Connect this laptop to the building network and check it. A step-by-step guide "
                                  "walks you through it and produces a report at the end.")
        self.analyse_btn = HomeButton("file", "Analyse a capture file",
                                      "Already have a recording of the network traffic (for example from Wireshark)? "
                                      "Check it here. Nothing is sent on the network.")
        self.compare_btn = HomeButton("compare", "Open & compare reports",
                                      "Open saved results, combine several into one report, or compare with an "
                                      "earlier visit to see what changed.")
        for b in (self.run_btn, self.analyse_btn, self.compare_btn):
            col.addWidget(b)
        self.run_btn.clicked.connect(win.show_wizard)
        self.analyse_btn.clicked.connect(win.show_analyse)
        self.compare_btn.clicked.connect(win.show_compare)
        col.addStretch(1)
        foot = label("Read-only by design: the tool only asks devices to identify themselves and reads a few "
                     "properties, at a gentle rate. Advanced options are in the Settings menu.", "Muted")
        col.addWidget(foot)
        wrap = QWidget()
        wrap.setLayout(col)
        wrap.setMaximumWidth(820)
        wrap.setMinimumWidth(520)
        outer.addWidget(wrap, 10)
        outer.addStretch(1)


# =============================================================================================== window
class MainWindow(QMainWindow):
    def __init__(self, runner: Any = None, runner_error: str = "", profile: Profile | None = None,
                 profile_path: str | None = None):
        super().__init__()
        self.runner = runner
        self.runner_error = runner_error
        self.profile = profile or Profile()
        self.profile_path = profile_path
        self._close_pending = False
        self._force_close = False
        self.setWindowTitle("bacnet-health")
        self.resize(1120, 780)
        self.setMinimumSize(880, 620)

        central = QWidget()
        cl = QVBoxLayout(central)
        cl.setContentsMargins(0, 0, 0, 0)
        cl.setSpacing(0)
        cl.addWidget(self._header())
        self.stack = QStackedWidget()
        cl.addWidget(self.stack, 1)
        self.setCentralWidget(central)

        self.home = HomePage(self)
        self.wizard = HealthCheckWizard(self)
        self.analyse = AnalysePage(self)
        self.compare = ComparePage(self)
        self.report = ReportPage(lambda: self.profile)
        for w in (self.home, self.wizard, self.analyse, self.compare, self.report):
            self.stack.addWidget(w)
        self.wizard.home.connect(self.show_home)
        self.wizard.done.connect(self._check_done)
        self.analyse.home.connect(self.show_home)
        self.analyse.analysed.connect(self._analysed)
        self.compare.home.connect(self.show_home)
        self.compare.built.connect(self._compared)
        self.report.home.connect(self.show_home)
        self._menus()
        self._sync_profile_note()
        self.show_home()

    # ------------------------------------------------------------------ chrome
    def _header(self) -> QWidget:
        h = QWidget()
        h.setObjectName("Header")
        h.setAttribute(Qt.WA_StyledBackground, True)
        lay = QHBoxLayout(h)
        lay.setContentsMargins(24, 12, 24, 12)
        lay.setSpacing(12)
        t = QLabel("bacnet-health")
        t.setObjectName("AppTitle")
        lay.addWidget(t)
        sub = QLabel("BACnet/IP network health check")
        sub.setObjectName("HeaderVersion")
        lay.addWidget(sub)
        lay.addStretch(1)
        self.header_profile = QLabel("")
        self.header_profile.setObjectName("HeaderVersion")
        lay.addWidget(self.header_profile)
        v = QLabel(f"v{__version__}")
        v.setObjectName("HeaderVersion")
        lay.addWidget(v)
        if is_prerelease(__version__):
            b = QLabel("Pre-release")
            b.setObjectName("Badge")
            b.setToolTip("Not yet validated on physical controllers.")
            lay.addWidget(b)
        return h

    def _menus(self) -> None:
        mb = self.menuBar()
        f = mb.addMenu("&File")
        a = QAction("&Open profile…", self)
        a.setShortcut(QKeySequence.Open)
        a.triggered.connect(self.open_profile_dialog)
        f.addAction(a)
        a = QAction("&Save profile as…", self)
        a.setShortcut(QKeySequence.SaveAs)
        a.triggered.connect(self.save_profile_dialog)
        f.addAction(a)
        f.addSeparator()
        a = QAction("&Home", self)
        a.setShortcut(QKeySequence("Ctrl+H"))
        a.triggered.connect(self.show_home)
        f.addAction(a)
        f.addSeparator()
        a = QAction("E&xit", self)
        a.setShortcut(QKeySequence.Quit)
        a.triggered.connect(self.close)
        f.addAction(a)
        s = mb.addMenu("&Settings")
        a = QAction("&Advanced settings…", self)
        a.triggered.connect(lambda: self.open_advanced("scan"))
        s.addAction(a)
        a = QAction("&Known workstations…", self)
        a.triggered.connect(lambda: self.open_advanced("analysis"))
        s.addAction(a)
        a = QAction("&Report branding…", self)
        a.triggered.connect(lambda: self.open_advanced("branding"))
        s.addAction(a)
        hm = mb.addMenu("&Help")
        a = QAction("&About bacnet-health", self)
        a.triggered.connect(self.about)
        hm.addAction(a)

    def about(self) -> None:
        QMessageBox.about(self, "About bacnet-health",
                          f"<b>bacnet-health</b> v{__version__}<br>Read-only BACnet/IP network health check.<br><br>"
                          "Pre-release: not yet validated on physical controllers.<br>MIT licence. "
                          "Qt for Python (PySide6) is used under the LGPL-3.0.")

    # ------------------------------------------------------------------ navigation
    def _busy(self) -> bool:
        return self.wizard.busy() or self.analyse.busy or self.analyse.capturing or self.compare.busy

    def show_home(self) -> None:
        self.stack.setCurrentWidget(self.home)
        QTimer.singleShot(0, self.home.run_btn.setFocus)

    def show_wizard(self) -> None:
        if self.runner is None:
            show_error(self, "Health check not available", message=(
                self.runner_error or "The network check engine is not available in this version.")
                + " You can still analyse capture files and open reports.")
            return
        if not self.wizard.busy():
            self.wizard.reset()
        self.stack.setCurrentWidget(self.wizard)

    def show_analyse(self) -> None:
        self.analyse.enter()
        self.stack.setCurrentWidget(self.analyse)

    def show_compare(self) -> None:
        self.stack.setCurrentWidget(self.compare)

    def _check_done(self, result: Result) -> None:
        if self._close_pending:
            QTimer.singleShot(0, self.close)
            return
        self.report.show_result(result)
        self.stack.setCurrentWidget(self.report)

    def _analysed(self, result: Result, path: str, vantage) -> None:
        if self._close_pending:
            QTimer.singleShot(0, self.close)
            return
        bar = VantageBar(result, vantage)
        bar.rerun.connect(lambda v: self._reanalyse(path, v))
        self.report.show_result(result, title="Capture analysis complete",
                                subtitle=os.path.basename(path), extra=bar)
        self.stack.setCurrentWidget(self.report)

    def _reanalyse(self, path: str, vantage) -> None:
        self.analyse.analyse(path, vantage)
        self.stack.setCurrentWidget(self.analyse)

    def _compared(self, result: Result, diff, n: int) -> None:
        sub = f"{n} result file{'s' if n != 1 else ''} combined" if n > 1 else "1 result file"
        if diff is not None:
            sub += ", compared with the previous visit"
        self.report.show_result(result, diff=diff, title="Report", subtitle=sub)
        self.stack.setCurrentWidget(self.report)

    # ------------------------------------------------------------------ profiles & settings
    def open_advanced(self, tab: str = "scan") -> bool:
        dlg = AdvancedDialog(self.profile, self, tab=tab)
        if dlg.exec() == AdvancedDialog.Accepted:
            self.profile = dlg.profile()
            return True
        return False

    def set_profile(self, p: Profile, path: str | None = None) -> None:
        self.profile = p
        self.profile_path = path
        self._sync_profile_note()
        if not self.wizard.busy():
            self.wizard.reset()

    def _sync_profile_note(self) -> None:
        if self.profile_path:
            name = os.path.basename(self.profile_path)
            who = f" prepared by {self.profile.prepared_by}" if self.profile.prepared_by else ""
            locked = f" Some settings are locked by the profile." if self.profile.locked else ""
            self.home.profile_note.set_text(f"Using profile {name}{who}.{locked}", title="Profile")
            self.header_profile.setText(f"Profile: {name}")
        else:
            self.home.profile_note.set_text("")
            self.header_profile.setText("")

    def load_profile(self, path: str) -> bool:
        try:
            p = Profile.load(path)
        except Exception as exc:  # noqa: BLE001
            show_error(self, "Could not open the profile", exc, traceback.format_exc(),
                       message=f"{os.path.basename(path)} could not be opened as a bacnet-health profile. ({exc})")
            return False
        self.set_profile(p, path)
        return True

    def open_profile_dialog(self) -> None:
        if self._busy():
            show_error(self, "Please wait", message="Profiles can be opened when no check is running.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Open profile", state.documents_dir(), PROFILE_FILTER)
        if path and self.load_profile(path):
            self.show_wizard()

    def save_profile_dialog(self) -> None:
        self.wizard.site.store(self.profile)
        self.wizard.plan.store(self.profile)
        start = self.profile_path or os.path.join(state.documents_dir(),
                                                  (state.slug(self.profile.site) or "site") + ".bhprofile")
        path, _ = QFileDialog.getSaveFileName(self, "Save profile as", start, PROFILE_FILTER)
        if not path:
            return
        if not path.lower().endswith(".bhprofile"):
            path += ".bhprofile"
        try:
            copy.deepcopy(self.profile).save(path)
        except Exception as exc:  # noqa: BLE001
            show_error(self, "Could not save the profile", exc, traceback.format_exc())
            return
        self.profile_path = path
        self._sync_profile_note()

    # ------------------------------------------------------------------ closing
    def ask_yes_no(self, title: str, text: str) -> bool:
        return QMessageBox.question(self, title, text, QMessageBox.Yes | QMessageBox.No,
                                    QMessageBox.No) == QMessageBox.Yes

    def closeEvent(self, e) -> None:  # noqa: N802
        if self._force_close or not self._busy():
            self.wizard.shutdown()
            self.analyse.shutdown()
            e.accept()
            return
        if self._close_pending:
            e.ignore()
            return
        if self.wizard.busy():
            q = "A check is running. Stop it and close? The results so far will not be saved."
        elif self.analyse.capturing:
            q = "A capture is being recorded. Stop it and close?"
        else:
            q = "Work is still in progress. Close when it has finished?"
        if not self.ask_yes_no("Stop and close?", q):
            e.ignore()
            return
        self._close_pending = True
        e.ignore()
        if self.wizard.busy():
            self.wizard.stop()
        if self.analyse.capturing:
            self.analyse.shutdown()
        self._poll_close()

    def _poll_close(self) -> None:
        if self._busy():
            QTimer.singleShot(100, self._poll_close)
            return
        self._force_close = True
        self.close()


# =============================================================================================== entry points
def _install_excepthook(win: MainWindow) -> None:
    def hook(etype, value, tb):
        details = "".join(traceback.format_exception(etype, value, tb))
        sys.stderr.write(details)
        try:
            show_error(win, "Something went wrong", value, details)
        except Exception:  # noqa: BLE001
            pass

    sys.excepthook = hook

    def thook(args):
        details = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
        sys.stderr.write(details)
        QTimer.singleShot(0, lambda: show_error(win, "Something went wrong", args.exc_value, details))

    threading.excepthook = thook


def ensure_app(argv: Sequence[str] | None = None) -> QApplication:
    app = QApplication.instance()
    if app is None:
        app = QApplication([sys.argv[0] if sys.argv else "bacnet-health", *(argv or [])])
    app.setApplicationName("bacnet-health")
    app.setApplicationDisplayName("bacnet-health")
    app.setApplicationVersion(__version__)
    app.setStyle("Fusion")
    if sys.platform == "win32":
        f = QFont(app.font())
        if f.pointSizeF() < 10:
            f.setPointSizeF(10)
        app.setFont(f)
    app.setStyleSheet(theme.stylesheet())
    return app


def create_window(runner: Any = None, profile_path: str | None = None, use_real_runner: bool = True) -> MainWindow:
    err = ""
    if runner is None and use_real_runner:
        runner, err = state.load_runner()
    win = MainWindow(runner=runner, runner_error=err)
    if profile_path and win.load_profile(profile_path):
        win.show_wizard()
    return win


def main(argv: Sequence[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    profile_path = next((a for a in args if not a.startswith("-")), None)
    app = ensure_app()
    win = create_window(profile_path=profile_path)
    _install_excepthook(win)
    win.show()
    return int(app.exec())


if __name__ == "__main__":
    raise SystemExit(main())
