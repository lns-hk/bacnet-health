""""Analyse a capture file": drag & drop / pick a pcap, optional full capture with dumpcap/tcpdump, vantage override."""

from __future__ import annotations

import os
import tempfile

from PySide6.QtCore import QProcess, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from bacnet_health.gui import state, theme
from bacnet_health.gui.widgets import Banner, button, card, label, page_header, run_task, scroll_page, show_error
from bacnet_health.model import Result, Vantage

CAPTURE_EXT = (".pcap", ".pcapng", ".cap", ".gz")
FILE_FILTER = "Capture files (*.pcap *.pcapng *.cap *.gz);;All files (*)"


def _accept_path(path: str) -> bool:
    return path.lower().endswith(CAPTURE_EXT)


class DropZone(QFrame):
    dropped = Signal(str)
    pick = Signal()

    def __init__(self):
        super().__init__()
        self.setObjectName("DropZone")
        self.setAcceptDrops(True)
        self.setMinimumHeight(170)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 24, 24, 24)
        lay.setSpacing(10)
        lay.setAlignment(Qt.AlignCenter)
        ic = QLabel()
        ic.setPixmap(theme.home_icon("file", 40))
        ic.setAlignment(Qt.AlignCenter)
        lay.addWidget(ic)
        t = QLabel("Drop a capture file here")
        t.setObjectName("SectionTitle")
        t.setAlignment(Qt.AlignCenter)
        lay.addWidget(t)
        m = QLabel("Files from Wireshark or tcpdump: .pcap, .pcapng, or the same compressed as .gz")
        m.setObjectName("Muted")
        m.setAlignment(Qt.AlignCenter)
        m.setWordWrap(True)
        lay.addWidget(m)
        row = QHBoxLayout()
        row.addStretch(1)
        self.btn = button("Choose a file…", "Primary", self.pick.emit)
        row.addWidget(self.btn)
        row.addStretch(1)
        lay.addLayout(row)

    def _set_hover(self, on: bool) -> None:
        self.setProperty("hover", "true" if on else "false")
        self.style().unpolish(self)
        self.style().polish(self)

    def dragEnterEvent(self, e) -> None:  # noqa: N802
        urls = e.mimeData().urls() if e.mimeData().hasUrls() else []
        if urls and any(_accept_path(u.toLocalFile()) for u in urls):
            e.acceptProposedAction()
            self._set_hover(True)

    def dragLeaveEvent(self, e) -> None:  # noqa: N802
        self._set_hover(False)

    def dropEvent(self, e) -> None:  # noqa: N802
        self._set_hover(False)
        for u in e.mimeData().urls():
            p = u.toLocalFile()
            if _accept_path(p):
                self.dropped.emit(p)
                e.acceptProposedAction()
                return


class VantageBar(QFrame):
    """Shown above the report for capture analyses: inferred vantage, reason, and an override."""

    rerun = Signal(object)  # Vantage | None

    CHOICES = [(None, "Detected automatically"), (Vantage.ACCESS, "Normal switch port (access port)"),
               (Vantage.SPAN, "Mirror port (SPAN port)")]

    def __init__(self, result: Result, current: Vantage | None):
        super().__init__()
        self.setObjectName("Info")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(16, 10, 16, 10)
        lay.setSpacing(12)
        v = result.run.vantage.value if result.run.vantage else "access"
        reason = str(result.metrics.get("vantage_reason", ""))
        where = {"access": "a normal switch port", "span": "a mirror (SPAN) port", "self": "this laptop"}.get(v, v)
        how = "you chose" if result.run.vantage_source == "user" else "detected"
        reason = reason[:1].upper() + reason[1:]
        txt = label(f"<b>Where was the capture taken?</b> Treated as {where} ({how}).<br>"
                    f"<span style='color:{theme.MUTED}'>{_esc(reason)}</span>")
        lay.addWidget(txt, 1)
        lay.addWidget(QLabel("Change:"))
        self.combo = QComboBox()
        self.combo.setAccessibleName("Where the capture was taken")
        for _v, text in self.CHOICES:
            self.combo.addItem(text)
        self.combo.setCurrentIndex([c[0] for c in self.CHOICES].index(current))
        self.combo.currentIndexChanged.connect(lambda k: self.rerun.emit(self.CHOICES[k][0]))
        lay.addWidget(self.combo)


def _esc(s: str) -> str:
    import html  # noqa: PLC0415

    return html.escape(s)


class AnalysePage(QWidget):
    analysed = Signal(object, str, object)  # Result, path, vantage override
    home = Signal()

    def __init__(self, ctx, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        self.busy = False
        self.proc: QProcess | None = None
        self.capture_out = ""
        self.tool = state.find_capture_tool()
        self.ifaces: list = []

        holder = QWidget()
        lay = QVBoxLayout(holder)
        lay.setContentsMargins(40, 28, 40, 28)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Analyse a capture file",
            "A capture file is a recording of network traffic, for example made with Wireshark. The file is read "
            "on this laptop only; nothing is sent on the network."))
        self.drop = DropZone()
        self.drop.dropped.connect(self.analyse)
        self.drop.pick.connect(self.pick)
        lay.addWidget(self.drop)
        row = QHBoxLayout()
        self.sample = button("No capture file yet? Try a sample capture", "Link", self.sample_capture)
        row.addWidget(self.sample)
        row.addStretch(1)
        lay.addLayout(row)

        self.progress_card, pl = card(margins=16)
        self.progress_text = label("Reading the capture…")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setTextVisible(False)
        pl.addWidget(self.progress_text)
        pl.addWidget(self.progress_bar)
        self.progress_card.setVisible(False)
        lay.addWidget(self.progress_card)

        # ---- full capture
        cap, cl = card()
        cl.addWidget(label("Record a new capture", "SectionTitle"))
        if self.tool:
            cl.addWidget(label(
                "If the laptop is plugged into a mirror (SPAN) port, a full capture sees traffic between devices, "
                "which allows more checks. This uses " + ("Wireshark's dumpcap" if self.tool[0] == "dumpcap"
                                                          else "tcpdump") + " and sends nothing.", "Muted"))
            r = QHBoxLayout()
            r.setSpacing(10)
            r.addWidget(QLabel("Connection"))
            self.cap_iface = QComboBox()
            self.cap_iface.setMinimumWidth(320)
            self.cap_iface.setAccessibleName("Connection to capture on")
            r.addWidget(self.cap_iface, 1)
            r.addWidget(QLabel("for"))
            self.cap_minutes = QSpinBox()
            self.cap_minutes.setRange(1, 240)
            self.cap_minutes.setValue(10)
            self.cap_minutes.setSuffix(" minutes")
            self.cap_minutes.setAccessibleName("Capture duration in minutes")
            r.addWidget(self.cap_minutes)
            cl.addLayout(r)
            r2 = QHBoxLayout()
            self.cap_btn = button("Full capture (SPAN port)", slot=self.start_capture)
            self.cap_stop = button("Stop capture", slot=self.stop_capture)
            self.cap_stop.setVisible(False)
            r2.addWidget(self.cap_btn)
            r2.addWidget(self.cap_stop)
            r2.addStretch(1)
            cl.addLayout(r2)
            self.cap_status = label("", "Muted")
            self.cap_status.setVisible(False)
            cl.addWidget(self.cap_status)
            self.cap_bar = QProgressBar()
            self.cap_bar.setTextVisible(False)
            self.cap_bar.setVisible(False)
            cl.addWidget(self.cap_bar)
            self.cap_timer = QTimer(self)
            self.cap_timer.setInterval(1000)
            self.cap_timer.timeout.connect(self._cap_tick)
        else:
            self.cap_btn = None
            cl.addWidget(label(
                "To record a full capture from a mirror (SPAN) port, install Wireshark on this laptop (it includes "
                "the capture tool this program uses), then reopen this screen. On Windows, also install Npcap when "
                "the Wireshark installer offers it. Without Wireshark you can still run a health check, which "
                "listens to the network directly.", "Muted"))
            url = label(f"Wireshark download page: {state.WIRESHARK_URL}")
            url.setTextInteractionFlags(Qt.TextSelectableByMouse)
            cl.addWidget(url)
        lay.addWidget(cap)
        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addStretch(1)
        nav = QHBoxLayout()
        nav.addStretch(1)
        nav.addWidget(button("Back to home", slot=self.home.emit))
        lay.addLayout(nav)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll_page(holder))

    def enter(self) -> None:
        self.error.set_text("")
        if self.cap_btn is not None and not self.ifaces:
            run_task(self, lambda _p: self._iface_list(), self._ifaces_loaded, lambda e, t: None)

    def _iface_list(self):
        if self.ctx.runner is not None:
            best, ranked, _r = self.ctx.runner.interface_choices()
        else:
            from bacnet_health.active.iface import auto_pick, list_interfaces  # noqa: PLC0415

            best, ranked, _r = auto_pick(list_interfaces())
        return best, ranked

    def _ifaces_loaded(self, res) -> None:
        best, ranked = res
        self.ifaces = list(ranked)
        self.cap_iface.clear()
        for i in self.ifaces:
            self.cap_iface.addItem(i.label())
        for k, i in enumerate(self.ifaces):
            if best is not None and i.name == best.name and i.ip == best.ip:
                self.cap_iface.setCurrentIndex(k)

    # ------------------------------------------------------------------ analysis
    def pick(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a capture file", state.documents_dir(), FILE_FILTER)
        if path:
            self.analyse(path)

    def sample_capture(self) -> None:
        from bacnet_health.testing.synth import demo_capture  # noqa: PLC0415

        d = os.path.join(tempfile.gettempdir(), "bacnet-health")
        os.makedirs(d, exist_ok=True)
        try:
            path = demo_capture(os.path.join(d, "sample-capture.pcap"))
        except Exception as exc:  # noqa: BLE001
            show_error(self, "Could not create the sample capture", exc)
            return
        self.analyse(path)

    def analyse(self, path: str, vantage: Vantage | None = None) -> None:
        if self.busy:
            return
        if not os.path.isfile(path):
            self.error.set_text(f"The file {path} does not exist.")
            return
        self.busy = True
        self.error.set_text("")
        self.drop.setEnabled(False)
        self.sample.setEnabled(False)
        self.progress_card.setVisible(True)
        self.progress_text.setText(f"Reading {os.path.basename(path)}…")
        writers = list(self.ctx.profile.known_writers)

        def work(progress):
            from bacnet_health.analysis.analyze import analyze_file  # noqa: PLC0415

            return analyze_file(path, vantage_override=vantage, known_writers=writers, progress=progress)

        run_task(self, work, lambda res: self._done(res, path, vantage), self._failed, self._progress)

    def _progress(self, ev: dict) -> None:
        if ev.get("type") == "frames":
            self.progress_text.setText(f"Read {ev['frames']:,} packets…")

    def _reset(self) -> None:
        self.busy = False
        self.drop.setEnabled(True)
        self.sample.setEnabled(True)
        self.progress_card.setVisible(False)

    def _done(self, res: Result, path: str, vantage) -> None:
        self._reset()
        self.analysed.emit(res, path, vantage)

    def _failed(self, exc, tb) -> None:
        self._reset()
        self.error.set_text(f"The file could not be analysed: {exc}")
        show_error(self, "The file could not be analysed", exc, tb,
                   message=f"The file could not be read as a network capture. {exc}")

    # ------------------------------------------------------------------ full capture
    @property
    def capturing(self) -> bool:
        return self.proc is not None

    def start_capture(self) -> None:
        if self.proc is not None or not self.tool:
            return
        k = self.cap_iface.currentIndex()
        if not (0 <= k < len(self.ifaces)):
            self.error.set_text("Choose the connection to capture on.")
            return
        iface = self.ifaces[k]
        d = os.path.join(state.documents_dir(), "bacnet-health captures")
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as exc:
            show_error(self, "Could not create the capture folder", exc)
            return
        ext = "pcapng" if self.tool[0] == "dumpcap" else "pcap"
        self.capture_out = os.path.join(d, state.default_filename(self.ctx.profile, "capture", ext))
        seconds = self.cap_minutes.value() * 60
        cmd = state.capture_command(self.tool[0], self.tool[1], iface.name, seconds, self.capture_out)
        self.proc = QProcess(self)
        self.proc.setProcessChannelMode(QProcess.MergedChannels)
        self.proc.finished.connect(self._cap_finished)
        self.proc.errorOccurred.connect(self._cap_error)
        self.cap_seconds = seconds
        self.cap_elapsed = 0
        self.cap_bar.setRange(0, seconds)
        self.cap_bar.setValue(0)
        self.cap_bar.setVisible(True)
        self.cap_btn.setEnabled(False)
        self.cap_stop.setVisible(True)
        self.cap_status.setVisible(True)
        self.cap_status.setText(f"Capturing on {iface.name}. The file is saved to {self.capture_out}")
        self.cap_timer.start()
        self.proc.start(cmd[0], cmd[1:])

    def _cap_tick(self) -> None:
        self.cap_elapsed += 1
        self.cap_bar.setValue(min(self.cap_elapsed, self.cap_seconds))
        left = max(0, self.cap_seconds - self.cap_elapsed)
        self.cap_status.setText(f"Capturing… {left // 60}:{left % 60:02d} left. The file is saved to "
                                f"{self.capture_out}")

    def stop_capture(self) -> None:
        if self.proc is None:
            return
        self.cap_status.setText("Stopping the capture…")
        self.proc.terminate()
        QTimer.singleShot(3000, lambda: self.proc is not None and self.proc.kill())

    def _cap_error(self, err) -> None:
        if err == QProcess.FailedToStart:
            out = self._cap_cleanup()
            self.error.set_text(f"The capture tool could not be started ({self.tool[1]}). {out}")

    def _cap_cleanup(self) -> str:
        self.cap_timer.stop()
        self.cap_bar.setVisible(False)
        self.cap_stop.setVisible(False)
        self.cap_btn.setEnabled(True)
        out = ""
        if self.proc is not None:
            out = bytes(self.proc.readAll()).decode("utf-8", "replace").strip()
            self.proc.deleteLater()
        self.proc = None
        return out

    def _cap_finished(self, code: int, _status) -> None:
        if self.proc is None:
            return
        out = self._cap_cleanup()
        if os.path.isfile(self.capture_out) and os.path.getsize(self.capture_out) > 0:
            self.cap_status.setText(f"Capture saved to {self.capture_out}")
            self.analyse(self.capture_out)
        else:
            hint = ""
            if "ermission" in out or "privileges" in out:
                hint = (" The capture tool needs permission to capture. On macOS, install Wireshark's "
                        "'ChmodBPF' helper; on Windows, install Npcap.")
            self.cap_status.setText("")
            self.error.set_text(f"The capture did not produce a file (exit code {code}).{hint} {out[-400:]}")

    def shutdown(self) -> None:
        if self.proc is not None:
            self.proc.kill()
            self.proc.waitForFinished(2000)
