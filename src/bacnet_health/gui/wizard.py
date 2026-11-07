"""The "Run health check" wizard: site & authorisation, network, pre-flight, plan, running.

Everything network-related goes through the runner API (docs/dev/runner-api.md); this module contains no BACnet logic.
Every call that can block (interface enumeration, pre-flight, prepare, run) runs in a worker thread.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from PySide6.QtCore import QElapsedTimer, Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFrame,
    QGridLayout,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from bacnet_health.gui import state, theme
from bacnet_health.gui.advanced import ConfirmTargetDialog, action_label
from bacnet_health.gui.widgets import Banner, button, card, label, page_header, run_task, scroll_page, show_error, \
    with_lock
from bacnet_health.profile import Profile

STEP_NAMES = ["Site and authorisation", "Network connection", "Pre-flight checks", "Plan", "Running"]


class Ctx:
    """What the wizard needs from the main window."""

    runner: Any
    profile: Profile

    def open_advanced(self, tab: str = "scan") -> bool: ...  # noqa: D102


# =============================================================================================== step 1
class SitePage(QWidget):
    changed = Signal()

    FIELDS = [
        ("site", "Site name", "For example: Building A plant room"),
        ("client", "Client", ""),
        ("prepared_by", "Prepared by", "Your name"),
        ("org", "Organisation", "Your company"),
        ("authorised_by", "Authorised by (required)", "Name of the person at the site who approved this check"),
    ]

    def __init__(self, ctx: Ctx):
        super().__init__()
        self.ctx = ctx
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Site and authorisation",
            "Before the laptop sends anything on the building network, record where you are and who allowed the "
            "check. This appears on the first page of the report."))
        c, cl = card()
        self.form = QFormLayout()
        self.form.setVerticalSpacing(12)
        self.form.setHorizontalSpacing(18)
        self.form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.edits: dict[str, QLineEdit] = {}
        cl.addLayout(self.form)
        lay.addWidget(c)
        self.notified = QCheckBox("I have told the site (for example the BMS operator or IT security team) that a "
                                  "network check is about to run.")
        self.notified.setStyleSheet("QCheckBox { font-weight: 600; }")
        lay.addWidget(self.notified)
        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addStretch(1)
        self.notified.toggled.connect(lambda _v: self.changed.emit())
        self.rebuild()

    def rebuild(self) -> None:
        p = self.ctx.profile
        while self.form.rowCount():
            self.form.removeRow(0)
        self.edits = {}
        for name, text, ph in self.FIELDS:
            e = QLineEdit(getattr(p, name) or "")
            e.setPlaceholderText(ph)
            e.setAccessibleName(text)
            e.textChanged.connect(lambda _t: self.changed.emit())
            self.edits[name] = e
            self.form.addRow(text, with_lock(e, p.is_locked(name)))
        self.scope = QPlainTextEdit(p.scope_note or "")
        self.scope.setPlaceholderText("Optional: what was agreed, for example which networks and the time window")
        self.scope.setMaximumHeight(80)
        self.scope.setTabChangesFocus(True)
        self.scope.setAccessibleName("Scope note")
        self.form.addRow("Scope note", with_lock(self.scope, p.is_locked("scope_note")))

    def store(self, p: Profile) -> None:
        for name, e in self.edits.items():
            if not p.is_locked(name):
                setattr(p, name, e.text().strip())
        if not p.is_locked("scope_note"):
            p.scope_note = self.scope.toPlainText().strip()

    def problem(self) -> str:
        if not self.edits["authorised_by"].text().strip():
            return "Enter the name of the person who authorised this check."
        if not self.notified.isChecked():
            return "Tick the box to confirm the site knows a network check is running."
        return ""

    def first_focus(self) -> QWidget:
        for name, _t, _p in self.FIELDS:
            e = self.edits[name]
            if not e.isReadOnly() and not e.text():
                return e
        return self.notified


# =============================================================================================== step 2
class NetworkPage(QWidget):
    changed = Signal()

    def __init__(self, ctx: Ctx):
        super().__init__()
        self.ctx = ctx
        self.ranked: list[Any] = []
        self.best: Any = None
        self.loading = False
        self.loaded = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Network connection",
            "The laptop may have several connections (for example Wi-Fi to the office and a cable to the building "
            "network). The check must only run on the building network. A connection has been suggested below; "
            "please confirm it."))
        c, cl = card()
        self.status = label("Looking for network connections…", "Muted")
        cl.addWidget(self.status)
        row = QHBoxLayout()
        row.addWidget(QLabel("Connection"))
        self.combo = QComboBox()
        self.combo.setAccessibleName("Network connection")
        self.combo.setMinimumWidth(380)
        self.combo_box = QWidget()
        row.addWidget(self.combo, 1)
        self.refresh = button("Refresh", slot=self.load)
        row.addWidget(self.refresh)
        cl.addLayout(row)
        self.lock_note = label("", "Muted")
        cl.addWidget(self.lock_note)
        self.sentence = label("", "Sentence")
        self.sentence.setTextInteractionFlags(Qt.TextSelectableByMouse)
        cl.addWidget(self.sentence)
        self.warn = Banner("warn", "")
        cl.addWidget(self.warn)
        self.reasons_title = label("Why this connection was suggested", "SectionTitle")
        cl.addWidget(self.reasons_title)
        self.reasons = label("", "Muted")
        cl.addWidget(self.reasons)
        lay.addWidget(c)
        self.confirm = QCheckBox("Yes, this is the connection to the building network.")
        self.confirm.setStyleSheet("QCheckBox { font-weight: 600; }")
        lay.addWidget(self.confirm)
        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addStretch(1)
        self.combo.currentIndexChanged.connect(self._sync)
        self.confirm.toggled.connect(lambda _v: self.changed.emit())

    def enter(self) -> None:
        if not self.loaded and not self.loading:
            self.load()

    def load(self) -> None:
        if self.loading:
            return
        self.loading = True
        self.status.setText("Looking for network connections…")
        self.combo.clear()
        self.confirm.setChecked(False)
        self.refresh.setEnabled(False)
        run_task(self, lambda _p: self.ctx.runner.interface_choices(), self._loaded, self._failed)
        self.changed.emit()

    def _failed(self, exc, tb) -> None:
        self.loading = False
        self.refresh.setEnabled(True)
        self.status.setText("")
        self.error.set_text(f"The network connections could not be listed: {exc}")
        self.changed.emit()

    def _loaded(self, res) -> None:
        self.loading = False
        self.loaded = True
        self.refresh.setEnabled(True)
        best, ranked, reasons = res
        self.best, self.ranked = best, list(ranked)
        self.combo.blockSignals(True)
        self.combo.clear()
        for i in self.ranked:
            suffix = "  (suggested)" if best is not None and _same(i, best) else ""
            self.combo.addItem(i.label() + suffix)
        p = self.ctx.profile
        idx = 0
        if p.interface:
            for k, i in enumerate(self.ranked):
                if i.name == p.interface:
                    idx = k
                    break
        elif best is not None:
            for k, i in enumerate(self.ranked):
                if _same(i, best):
                    idx = k
        self.combo.setCurrentIndex(idx if self.ranked else -1)
        self.combo.blockSignals(False)
        locked = p.is_locked("interface") and bool(p.interface)
        self.combo.setEnabled(not locked)
        self.combo.setToolTip("Set by your consultant's profile" if locked else "")
        self.lock_note.setText("This connection is set by your consultant's profile." if locked else "")
        self.lock_note.setVisible(locked)
        self.reasons.setText("<br>".join(f"&bull;&nbsp;{_esc(r)}" for r in reasons))
        if not self.ranked:
            self.status.setText("")
            self.error.set_text("No network connection was found. Plug the laptop into the building network, "
                                "wait a few seconds and press Refresh.")
        else:
            self.error.set_text("")
            self.status.setText(f"{len(self.ranked)} connection{'s' if len(self.ranked) != 1 else ''} found.")
        self._sync()

    def selected(self):
        k = self.combo.currentIndex()
        return self.ranked[k] if 0 <= k < len(self.ranked) else None

    def _sync(self) -> None:
        i = self.selected()
        self.confirm.setChecked(False)
        if i is None:
            self.sentence.setText("")
            self.warn.set_text("")
            self.changed.emit()
            return
        self.sentence.setText(f"Will broadcast on {i.broadcast} via {i.name} ({i.ip}/{i.prefix})")
        w = []
        if getattr(i, "has_default_route", False):
            w.append("This connection carries the laptop's internet / default route. It is usually the office or "
                     "corporate network, not the building network.")
        if getattr(i, "wireless_guess", False):
            w.append("This looks like a Wi-Fi connection. Building networks are normally reached with a cable.")
        if not getattr(i, "is_up", True):
            w.append("This connection is down.")
        self.warn.set_text(" ".join(w), title="Check this is right" if w else None)
        self.changed.emit()

    def problem(self) -> str:
        if self.loading:
            return "Still looking for network connections…"
        if self.selected() is None:
            return "No network connection is available."
        if not self.confirm.isChecked():
            return "Tick the box to confirm this is the building network connection."
        return ""


def _same(a, b) -> bool:
    return a.name == b.name and a.ip == b.ip


def _esc(s: str) -> str:
    import html  # noqa: PLC0415

    return html.escape(str(s))


# =============================================================================================== step 3
class PreflightPage(QWidget):
    changed = Signal()

    def __init__(self, ctx: Ctx, options: Callable[[], Any]):
        super().__init__()
        self.ctx = ctx
        self.options = options
        self.items: list[dict] = []
        self.running = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Pre-flight checks",
            "A few quick checks on this laptop, before anything is sent. Nothing is sent on the network yet."))
        c, cl = card()
        self.status = label("", "Muted")
        self.status.setVisible(False)
        cl.addWidget(self.status)
        self.list = QVBoxLayout()
        self.list.setSpacing(10)
        cl.addLayout(self.list)
        row = QHBoxLayout()
        row.addStretch(1)
        self.again = button("Check again", slot=self.run)
        row.addWidget(self.again)
        cl.addLayout(row)
        lay.addWidget(c)
        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addStretch(1)

    def enter(self) -> None:
        self.run()

    def run(self) -> None:
        if self.running:
            return
        self.running = True
        self.again.setEnabled(False)
        self.error.set_text("")
        self._status("Checking…")
        _clear_layout(self.list)
        opts = self.options()
        run_task(self, lambda _p: self.ctx.runner.preflight(opts), self._done, self._failed)
        self.changed.emit()

    def _status(self, text: str) -> None:
        self.status.setText(text)
        self.status.setVisible(bool(text))

    def _failed(self, exc, tb) -> None:
        self.running = False
        self.again.setEnabled(True)
        self._status("")
        self.items = [{"name": "Pre-flight", "status": "error", "message": str(exc)}]
        self._show()

    def _done(self, items) -> None:
        self.running = False
        self.again.setEnabled(True)
        self.items = list(items or [])
        self._show()

    def _show(self) -> None:
        _clear_layout(self.list)
        for it in self.items:
            st = it.get("status", "unknown")
            colour, text = theme.STATUS.get(st, theme.STATUS["unknown"])
            row = QWidget()
            rl = QHBoxLayout(row)
            rl.setContentsMargins(0, 0, 0, 0)
            rl.setSpacing(10)
            ic = QLabel()
            ic.setPixmap(theme.status_icon(st, 20).pixmap(20, 20))
            rl.addWidget(ic, 0, Qt.AlignTop)
            badge = QLabel(text)
            badge.setMinimumWidth(92)
            badge.setStyleSheet(f"color: {colour}; font-weight: 700;")
            rl.addWidget(badge, 0, Qt.AlignTop)
            body = label(f"<b>{_esc(it.get('name', ''))}</b><br>{_esc(it.get('message', ''))}")
            body.setTextInteractionFlags(Qt.TextSelectableByMouse)
            rl.addWidget(body, 1)
            row.setAccessibleName(f"{it.get('name', '')}: {text}. {it.get('message', '')}")
            self.list.addWidget(row)
        errs = [i for i in self.items if i.get("status") == "error"]
        warns = [i for i in self.items if i.get("status") == "warning"]
        if errs:
            self._status("")
            self.error.set_text(_esc(self.problem()))
        else:
            self._status("All checks passed." if not warns else
                         "You can continue. Read the warnings first; they may affect the results.")
        self.changed.emit()

    def problem(self) -> str:
        if self.running:
            return "Pre-flight checks are still running…"
        errs = [i for i in self.items if i.get("status") == "error"]
        if errs:
            return ("Fix the items marked 'Problem' and press Check again. "
                    + " ".join(str(e.get("message", "")) for e in errs))
        if not self.items:
            return "Pre-flight checks have not run."
        return ""


def _clear_layout(lay) -> None:
    while lay.count():
        it = lay.takeAt(0)
        if it.widget():
            it.widget().deleteLater()


# =============================================================================================== step 4
class PlanPage(QWidget):
    changed = Signal()

    def __init__(self, ctx: Ctx, options: Callable[[], Any]):
        super().__init__()
        self.ctx = ctx
        self.options = options
        self.session = None
        self.preparing = False
        self._again = False
        self.active = False
        self.confirmed: set[tuple[str, str]] = set()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Plan",
            "This is exactly what the check will do. The laptop first listens quietly, then (if selected) asks "
            "the devices to identify themselves, slowly and read-only."))
        c, cl = card()
        form = QFormLayout()
        form.setHorizontalSpacing(18)
        form.setVerticalSpacing(12)
        form.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.form = form
        cl.addLayout(form)
        inset = QFrame()
        inset.setObjectName("Inset")
        il = QVBoxLayout(inset)
        il.setContentsMargins(16, 12, 16, 12)
        il.setSpacing(6)
        il.addWidget(label("What will be sent", "SectionTitle"))
        self.plan_text = label("Preparing the plan…")
        self.plan_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        il.addWidget(self.plan_text)
        cl.addWidget(inset)
        row = QHBoxLayout()
        self.show_packets = QPushButton("Show packets")
        self.show_packets.setCheckable(True)
        self.show_packets.toggled.connect(self._toggle_packets)
        self.adv = button("Advanced settings…", slot=self._advanced)
        row.addWidget(self.show_packets)
        row.addWidget(self.adv)
        row.addStretch(1)
        cl.addLayout(row)
        self.packets = QPlainTextEdit()
        self.packets.setObjectName("Mono")
        self.packets.setReadOnly(True)
        self.packets.setMinimumHeight(200)
        self.packets.setVisible(False)
        cl.addWidget(self.packets)
        lay.addWidget(c)
        self.cross = Banner("warn", "")
        lay.addWidget(self.cross)
        self.reminder = Banner("info", "Stay with the laptop while the check runs. You can stop it at any time with "
                                       "the Stop button; whatever was found so far is kept.")
        lay.addWidget(self.reminder)
        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addStretch(1)
        self.debounce = QTimer(self)
        self.debounce.setSingleShot(True)
        self.debounce.setInterval(350)
        self.debounce.timeout.connect(self.prepare)
        self.rebuild()

    def rebuild(self) -> None:
        p = self.ctx.profile
        while self.form.rowCount():
            self.form.removeRow(0)
        self.minutes = QSpinBox()
        self.minutes.setRange(1, 240)
        self.minutes.setSuffix(" minutes")
        self.minutes.setAccessibleName("Listening time in minutes")
        self.minutes.setValue(max(1, int(round(p.listen_minutes))))
        self.minutes.setMaximumWidth(170)
        self.scan = QCheckBox("Also ask the devices to identify themselves (sends a small, rate-limited amount of "
                              "read-only traffic)")
        self.scan.setChecked(p.do_scan)
        self.minutes.valueChanged.connect(self._edited)
        self.scan.toggled.connect(self._edited)
        self.form.addRow("Listen for", with_lock(self.minutes, p.is_locked("listen_minutes")))
        self.form.addRow("", with_lock(self.scan, p.is_locked("do_scan")))

    def store(self, p: Profile) -> None:
        if not p.is_locked("listen_minutes"):
            p.listen_minutes = float(self.minutes.value())
        if not p.is_locked("do_scan"):
            p.do_scan = self.scan.isChecked()

    def _edited(self) -> None:
        self.store(self.ctx.profile)
        self.debounce.start()
        self.changed.emit()

    def enter(self) -> None:
        self.active = True
        self.prepare()

    def leave(self) -> None:
        self.active = False
        self.debounce.stop()
        self.close_session()

    def close_session(self) -> None:
        s, self.session = self.session, None
        self.confirmed = set()
        if s is not None:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass

    def prepare(self) -> None:
        if self.preparing:
            self._again = True
            return
        self.close_session()
        self.error.set_text("")
        self.cross.set_text("")
        self.plan_text.setText("Preparing the plan…")
        self.packets.clear()
        p = self.ctx.profile
        kind = state.kind_for(p)
        try:
            opts = self.options()
        except Exception as exc:  # noqa: BLE001
            self.error.set_text(str(exc))
            return
        self.preparing = True
        run_task(self, lambda _p: self.ctx.runner.prepare(kind, opts), self._prepared, self._failed)
        self.changed.emit()

    def _failed(self, exc, tb) -> None:
        self.preparing = False
        if self._again and self.active:
            self._again = False
            self.prepare()
            return
        self.plan_text.setText("")
        self.error.set_text(str(exc) or type(exc).__name__)
        self.changed.emit()

    def _prepared(self, session) -> None:
        self.preparing = False
        if not self.active or self._again:
            try:
                session.close()
            except Exception:  # noqa: BLE001
                pass
            if self._again and self.active:
                self._again = False
                self.prepare()
            return
        self.session = session
        self.plan_text.setText(_esc(session.describe()).replace("\n", "<br>"))
        if self.show_packets.isChecked():
            self._fill_packets()
        req = self._required()
        if req:
            lines = "".join(f"<br>&bull;&nbsp;<b>{_esc(action_label(a))}</b> (target {_esc(t)}): {_esc(r)}"
                            for a, t, r in req)
            self.cross.set_text("This check reaches beyond the local network. Before it starts you will be asked to "
                                "type each target address to confirm." + lines, title="Beyond this network")
        self.changed.emit()

    def _required(self) -> list[tuple[str, str, str]]:
        try:
            return list(self.session.required_confirmations()) if self.session else []
        except Exception:  # noqa: BLE001
            return []

    def _toggle_packets(self, on: bool) -> None:
        self.packets.setVisible(on)
        self.show_packets.setText("Hide packets" if on else "Show packets")
        if on:
            self._fill_packets()

    def _fill_packets(self) -> None:
        if self.session is None:
            return
        try:
            self.packets.setPlainText(self.session.dry_run_text())
        except Exception as exc:  # noqa: BLE001
            self.packets.setPlainText(f"The packet preview is not available: {exc}")

    def _advanced(self) -> None:
        if self.ctx.open_advanced("scan"):
            self.prepare()

    def problem(self) -> str:
        if self.preparing:
            return "Preparing the plan…"
        if self.session is None:
            return "The plan could not be prepared."
        return ""

    def confirm_all(self, ask: Callable[[str, str, str], bool]) -> bool:
        """Typed confirmation for every cross-subnet action. False if any was declined."""
        for action, target, risk in self._required():
            if (action, target) in self.confirmed:
                continue
            if not ask(action, target, risk):
                return False
            self.session.confirm(action, target, user=state.os_user())
            self.confirmed.add((action, target))
        return True


# =============================================================================================== step 5
PHASES = [
    ("listen", "Listening to normal traffic"),
    ("discover", "Finding devices"),
    ("read", "Reading device details"),
    ("bbmd", "Checking BBMDs"),
    ("report", "Preparing the report"),
]


class RunningPage(QWidget):
    finished = Signal(object)  # Result
    failed = Signal()

    def __init__(self, ctx: Ctx):
        super().__init__()
        self.ctx = ctx
        self.session = None
        self.task = None
        self.cancelled = False
        self.devices: set = set()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(16)
        lay.addWidget(page_header("Check running",
                                  "You can leave the laptop running. Press Stop at any time; the results so far "
                                  "are kept."))
        c, cl = card()
        top = QHBoxLayout()
        top.setSpacing(40)
        dv = QVBoxLayout()
        dv.setSpacing(0)
        self.dev_count = QLabel("0")
        self.dev_count.setObjectName("BigNumber")
        self.dev_count.setAccessibleName("Devices found")
        dv.addWidget(self.dev_count)
        dv.addWidget(label("devices found", "Muted"))
        dv.addStretch(1)
        top.addLayout(dv)
        ev = QVBoxLayout()
        ev.setSpacing(0)
        self.elapsed = QLabel("0:00")
        self.elapsed.setObjectName("BigNumber")
        self.elapsed.setAccessibleName("Elapsed time")
        ev.addWidget(self.elapsed)
        ev.addWidget(label("elapsed", "Muted"))
        ev.addStretch(1)
        top.addLayout(ev)
        top.addStretch(1)
        self.stop = QPushButton("Stop")
        self.stop.setObjectName("Danger")
        self.stop.setAccessibleName("Stop the check")
        self.stop.setMinimumWidth(180)
        self.stop.clicked.connect(self.request_stop)
        top.addWidget(self.stop, 0, Qt.AlignVCenter)
        cl.addLayout(top)
        self.phase_rows: dict[str, tuple[QLabel, QLabel]] = {}
        self.phase_box = QGridLayout()
        self.phase_box.setHorizontalSpacing(14)
        self.phase_box.setVerticalSpacing(6)
        self.phase_box.setColumnStretch(1, 1)
        cl.addLayout(self.phase_box)
        self.phase_msg = label("", "Muted")
        cl.addWidget(self.phase_msg)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.bar.setTextVisible(False)
        self.bar.setAccessibleName("Progress of the current step")
        cl.addWidget(self.bar)
        lay.addWidget(c)
        self.budget = Banner("warn", "")
        lay.addWidget(self.budget)
        lay.addWidget(label("Activity", "SectionTitle"))
        self.log = QListWidget()
        self.log.setAccessibleName("Activity log")
        self.log.setMinimumHeight(140)
        lay.addWidget(self.log, 1)
        self.clock = QElapsedTimer()
        self.tick = QTimer(self)
        self.tick.setInterval(500)
        self.tick.timeout.connect(self._tick)

    @property
    def running(self) -> bool:
        return self.task is not None

    def start(self, session) -> None:
        self.session = session
        self.cancelled = False
        self.devices = set()
        self.dev_count.setText("0")
        self.log.clear()
        self.budget.set_text("")
        self.bar.setValue(0)
        self.stop.setEnabled(True)
        self.stop.setText("Stop")
        _clear_layout(self.phase_box)
        self.phase_rows = {}
        kind = getattr(session, "kind", "audit")
        wanted = [p for p in PHASES if kind != "listen" or p[0] in ("listen", "report")]
        if kind == "scan":
            wanted = [p for p in PHASES if p[0] != "listen"]
        for n, (pid, text) in enumerate(wanted):
            st, name = QLabel(), QLabel(text)
            self.phase_rows[pid] = (st, name)
            self.phase_box.addWidget(st, n, 0)
            self.phase_box.addWidget(name, n, 1)
            self._set_phase_state(pid, "waiting")
        self.current = None
        self.clock.start()
        self.tick.start()
        self._add_log("info", "Check started.")
        self.task = run_task(self, lambda progress: session.run(progress=progress), self._ok, self._err,
                             self._progress)
        self.stop.setFocus()

    def _set_phase_state(self, pid: str, st: str) -> None:
        text = dict(PHASES).get(pid, pid)
        mark = {"waiting": ("#9aa3ad", "Waiting"), "active": (theme.ACCENT, "In progress"),
                "done": (theme.OK, "Done")}[st]
        st_lb, name_lb = self.phase_rows[pid]
        st_lb.setText(mark[1])
        st_lb.setStyleSheet(f"color: {mark[0]}; font-weight: 700;")
        name_lb.setStyleSheet(f"font-weight: {'600' if st == 'active' else '400'};"
                              + ("" if st != "waiting" else f" color: {theme.MUTED};"))
        name_lb.setAccessibleName(f"{text}: {mark[1]}")

    def _progress(self, ev: dict) -> None:
        t = ev.get("type")
        if t == "phase":
            ph = ev.get("phase")
            if self.current and self.current in self.phase_rows:
                self._set_phase_state(self.current, "done")
            if ph in self.phase_rows:
                self._set_phase_state(ph, "active")
            self.current = ph if ph != "done" else None
            self.bar.setValue(0)
            if ev.get("message"):
                self.phase_msg.setText(ev["message"])
                self._add_log("info", ev["message"])
        elif t == "progress":
            self.bar.setValue(int(max(0.0, min(1.0, float(ev.get("fraction", 0)))) * 1000))
            if ev.get("message"):
                self.phase_msg.setText(ev["message"])
        elif t == "device":
            key = (ev.get("instance"), ev.get("address"))
            if key not in self.devices:
                self.devices.add(key)
                self.dev_count.setText(str(len(self.devices)))
                self._add_log("info", f"Found device {ev.get('instance')} at {ev.get('address')}")
        elif t == "log":
            self._add_log(ev.get("level", "info"), ev.get("message", ""))
        elif t == "budget-exceeded":
            msg = ev.get("message", "The check is sending more traffic than planned.")
            self.budget.set_text(msg + " Press Stop if you are not comfortable continuing.",
                                 title="More traffic than planned")
            self._add_log("warning", msg)

    def _add_log(self, level: str, msg: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        it = QListWidgetItem(f"{stamp}   {'Warning: ' if level == 'warning' else ''}{msg}")
        if level == "warning":
            it.setForeground(Qt.darkYellow)
        self.log.addItem(it)
        self.log.scrollToBottom()

    def _tick(self) -> None:
        s = int(self.clock.elapsed() / 1000)
        self.elapsed.setText(f"{s // 3600}:{(s // 60) % 60:02d}:{s % 60:02d}" if s >= 3600
                             else f"{s // 60}:{s % 60:02d}")

    def request_stop(self) -> None:
        if self.session is None or self.cancelled:
            return
        self.cancelled = True
        self.stop.setEnabled(False)
        self.stop.setText("Stopping…")
        self._add_log("warning", "Stop requested. Finishing up and keeping the results so far.")
        try:
            self.session.cancel()
        except Exception as exc:  # noqa: BLE001
            self._add_log("warning", f"Could not stop cleanly: {exc}")

    def _finish(self):
        self.tick.stop()
        self.task = None
        s, self.session = self.session, None
        if s is not None:
            try:
                s.close()
            except Exception:  # noqa: BLE001
                pass
        return s

    def _ok(self, result) -> None:
        self._finish()
        if self.cancelled and result is not None:
            result.run.incomplete = True
        self.finished.emit(result)

    def _err(self, exc, tb) -> None:
        s = self.session
        partial = None
        if s is not None:
            try:
                partial = s.result()
            except Exception:  # noqa: BLE001
                partial = None
        self._finish()
        if self.cancelled and partial is not None:
            partial.run.incomplete = True
            self.finished.emit(partial)
            return
        show_error(self, "The check stopped with a problem", exc, tb)
        if partial is not None and (partial.devices or partial.findings):
            partial.run.incomplete = True
            self.finished.emit(partial)
        else:
            self.failed.emit()


# =============================================================================================== the wizard
class HealthCheckWizard(QWidget):
    home = Signal()
    done = Signal(object)  # Result

    def __init__(self, ctx: Ctx, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        self.ask_confirmation: Callable[[str, str, str], bool] = self._ask_confirmation
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        self.stack = QStackedWidget()
        self.site = SitePage(ctx)
        self.network = NetworkPage(ctx)
        self.preflight = PreflightPage(ctx, self.options)
        self.plan = PlanPage(ctx, self.options)
        self.running = RunningPage(ctx)
        self.pages = [self.site, self.network, self.preflight, self.plan, self.running]
        for pg in self.pages:
            holder = QWidget()
            hl = QVBoxLayout(holder)
            hl.setContentsMargins(40, 28, 40, 20)
            hl.addWidget(pg)
            sp = scroll_page(holder)
            self.stack.addWidget(sp)
            if hasattr(pg, "changed"):
                pg.changed.connect(self._sync_nav)
        outer.addWidget(self.stack, 1)

        nav = QWidget()
        nav.setObjectName("NavBar")
        nav.setStyleSheet(f"QWidget#NavBar {{ background: {theme.CARD}; border-top: 1px solid {theme.BORDER}; }}")
        nl = QHBoxLayout(nav)
        nl.setContentsMargins(40, 12, 40, 12)
        nl.setSpacing(10)
        self.crumb = label("", "StepCrumb", wrap=False)
        nl.addWidget(self.crumb)
        nl.addStretch(1)
        self.hint = label("", "Muted", wrap=False)
        nl.addWidget(self.hint)
        self.cancel_btn = button("Cancel", slot=self.cancel)
        self.back_btn = button("Back", slot=self.back)
        self.next_btn = button("Next", "Primary", self.next)
        self.next_btn.setMinimumWidth(120)
        nl.addWidget(self.cancel_btn)
        nl.addWidget(self.back_btn)
        nl.addWidget(self.next_btn)
        self.nav = nav
        outer.addWidget(nav)

        self.running.finished.connect(self._run_finished)
        self.running.failed.connect(lambda: self.go(3))
        self.index = 0
        self.go(0)

    # ------------------------------------------------------------------ options
    def options(self):
        self.site.store(self.ctx.profile)
        self.plan.store(self.ctx.profile)
        i = self.network.selected()
        return state.build_options(self.ctx.runner, self.ctx.profile, i.name if i is not None else None)

    def reset(self) -> None:
        """Start again from step 1 with the current profile."""
        self.plan.leave()
        self.site.rebuild()
        self.site.notified.setChecked(False)
        self.plan.rebuild()
        self.network.loaded = False
        self.preflight.items = []
        self.go(0)

    # ------------------------------------------------------------------ navigation
    def go(self, k: int) -> None:
        if self.index == 3 and k != 3 and k != 4:
            self.plan.leave()
        self.index = k
        self.stack.setCurrentIndex(k)
        pg = self.pages[k]
        if k == 1:
            self.network.enter()
        elif k == 2:
            self.preflight.enter()
        elif k == 3:
            self.plan.enter()
        self.nav.setVisible(k != 4)
        self.crumb.setText(f"Step {k + 1} of 5  ·  {STEP_NAMES[k]}")
        self.next_btn.setText("Start check" if k == 3 else "Next")
        self.back_btn.setEnabled(k > 0)
        self._sync_nav()
        if k == 0:
            QTimer.singleShot(0, lambda: self.site.first_focus().setFocus())

    def _sync_nav(self) -> None:
        if self.index >= len(self.pages) - 1:
            return
        pg = self.pages[self.index]
        prob = pg.problem()
        busy = prob.endswith("…")
        self.next_btn.setEnabled(not busy)
        self.hint.setText(prob if busy else "")

    def next(self) -> None:
        pg = self.pages[self.index]
        prob = pg.problem()
        if prob:
            if hasattr(pg, "error"):
                pg.error.set_text(prob)
            return
        if hasattr(pg, "error") and self.index != 3:
            pg.error.set_text("")
        if self.index == 0:
            self.site.store(self.ctx.profile)
            self.go(1)
        elif self.index == 1:
            self.go(2)
        elif self.index == 2:
            self.go(3)
        elif self.index == 3:
            self.start()

    def back(self) -> None:
        if self.index > 0:
            self.go(self.index - 1)

    def cancel(self) -> None:
        self.plan.leave()
        self.home.emit()

    def _ask_confirmation(self, action: str, target: str, risk: str) -> bool:
        return ConfirmTargetDialog(action, target, risk, self).exec() == QDialog.Accepted

    def start(self) -> None:
        if self.plan.session is None:
            return
        try:
            ok = self.plan.confirm_all(self.ask_confirmation)
        except Exception as exc:  # noqa: BLE001
            show_error(self, "Could not record the confirmation", exc)
            return
        if not ok:
            self.plan.error.set_text("The check was not started because an action beyond this network was not "
                                     "confirmed. Confirm the target address, or turn the option off in Advanced "
                                     "settings.")
            return
        session, self.plan.session = self.plan.session, None  # the running page owns it now
        self.plan.active = False
        self.go(4)
        self.running.start(session)

    def _run_finished(self, result) -> None:
        self.done.emit(result)

    # ------------------------------------------------------------------ lifecycle
    def busy(self) -> bool:
        return self.running.running

    def stop(self) -> None:
        self.running.request_stop()

    def shutdown(self) -> None:
        self.plan.leave()
