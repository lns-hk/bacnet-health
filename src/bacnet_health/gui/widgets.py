"""Shared widgets and helpers: worker thread, friendly error dialog, cards, banners, locked-field marking."""

from __future__ import annotations

import traceback
from typing import Any, Callable

from PySide6.QtCore import QThread, Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from bacnet_health.gui import theme

LOCK_TIP = "Set by your consultant's profile"


# --------------------------------------------------------------------------------------------- worker thread
class Task(QThread):
    """Runs ``fn(progress)`` off the UI thread. ``progress(obj)`` may be called from the worker; it is marshalled
    to the UI thread through the ``progressed`` signal. Exactly one of ``succeeded``/``failed`` is emitted."""

    progressed = Signal(object)
    succeeded = Signal(object)
    failed = Signal(object, str)  # exception, formatted traceback

    _live: set["Task"] = set()  # keep Python references while running

    def __init__(self, fn: Callable[[Callable[[Any], None]], Any], parent: QWidget | None = None):
        super().__init__(parent)
        self._fn = fn
        Task._live.add(self)
        self.finished.connect(self._done)

    def run(self) -> None:  # worker thread
        try:
            res = self._fn(self.progressed.emit)
        except BaseException as exc:  # noqa: BLE001 - everything must reach the UI as a friendly dialog
            self.failed.emit(exc, traceback.format_exc())
        else:
            self.succeeded.emit(res)

    def _done(self) -> None:
        Task._live.discard(self)


def run_task(parent: QWidget, fn, on_ok=None, on_fail=None, on_progress=None) -> Task:
    t = Task(fn, parent)
    if on_progress:
        t.progressed.connect(on_progress)
    if on_ok:
        t.succeeded.connect(on_ok)
    t.failed.connect(on_fail or (lambda exc, tb: show_error(parent, "Something went wrong", exc, tb)))
    t.start()
    return t


# --------------------------------------------------------------------------------------------- errors
def friendly_message(exc: BaseException) -> str:
    name = type(exc).__name__
    if name == "RunnerError" or isinstance(exc, (ValueError, OSError)):
        return str(exc) or name
    return f"An unexpected problem occurred ({name}: {exc})."


class ErrorDialog(QDialog):
    def __init__(self, parent: QWidget | None, title: str, message: str, details: str):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        head = QLabel(title)
        head.setObjectName("SectionTitle")
        lay.addWidget(head)
        msg = QLabel(message)
        msg.setWordWrap(True)
        msg.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(msg)
        hint = QLabel("Nothing has been lost. If this keeps happening, copy the details and send them to your "
                      "consultant.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        lay.addWidget(hint)
        self.details = QPlainTextEdit(details)
        self.details.setObjectName("Mono")
        self.details.setReadOnly(True)
        self.details.setVisible(False)
        self.details.setMinimumHeight(180)
        lay.addWidget(self.details)
        row = QHBoxLayout()
        show = QPushButton("Show details")
        show.setCheckable(True)
        show.toggled.connect(lambda on: (self.details.setVisible(on), self.adjustSize()))
        copy = QPushButton("Copy details")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(f"{title}\n{message}\n\n{details}"))
        ok = QPushButton("OK")
        ok.setObjectName("Primary")
        ok.setDefault(True)
        ok.clicked.connect(self.accept)
        row.addWidget(show)
        row.addWidget(copy)
        row.addStretch(1)
        row.addWidget(ok)
        lay.addLayout(row)


def show_error(parent: QWidget | None, title: str, exc: BaseException | None = None, tb: str = "",
               message: str | None = None) -> None:
    msg = message or (friendly_message(exc) if exc else title)
    dlg = ErrorDialog(parent, title, msg, tb or (repr(exc) if exc else ""))
    if QApplication.platformName() == "offscreen":
        dlg.setAttribute(Qt.WA_DeleteOnClose)
        dlg.show()  # never block in headless runs (tests, screenshots)
        _last_errors.append(msg)
        return
    dlg.exec()


_last_errors: list[str] = []


# --------------------------------------------------------------------------------------------- layout helpers
def card(parent: QWidget | None = None, margins: int = 20, spacing: int = 12) -> tuple[QFrame, QVBoxLayout]:
    f = QFrame(parent)
    f.setObjectName("Card")
    lay = QVBoxLayout(f)
    lay.setContentsMargins(margins, margins, margins, margins)
    lay.setSpacing(spacing)
    return f, lay


def label(text: str, obj: str | None = None, wrap: bool = True) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    return lb


class Banner(QFrame):
    """Coloured message box. kind: warn | error | info. Always starts with a text label (not colour only)."""

    PREFIX = {"warn": "Warning", "error": "Cannot continue", "info": "Note"}

    def __init__(self, kind: str = "warn", text: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self.kind = kind
        self.setObjectName({"warn": "Warn", "error": "Error", "info": "Info"}[kind])
        lay = QHBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(10)
        self.icon = QLabel()
        status = {"warn": "warning", "error": "error", "info": "unknown"}[kind]
        if kind != "info":
            self.icon.setPixmap(theme.status_icon(status, 18).pixmap(18, 18))
            self.icon.setAlignment(Qt.AlignTop)
            lay.addWidget(self.icon, 0, Qt.AlignTop)
        self.text = QLabel()
        self.text.setWordWrap(True)
        self.text.setTextInteractionFlags(Qt.TextSelectableByMouse)
        lay.addWidget(self.text, 1)
        self.set_text(text)

    def set_text(self, text: str, title: str | None = None) -> None:
        t = title if title is not None else self.PREFIX[self.kind]
        self.text.setText(f"<b>{t}:</b> {text}" if t else text)
        self.setVisible(bool(text))


def scroll_page(inner: QWidget) -> QScrollArea:
    sa = QScrollArea()
    sa.setWidgetResizable(True)
    sa.setFrameShape(QFrame.NoFrame)
    inner.setObjectName("ScrollBody")
    sa.setWidget(inner)
    return sa


def page_header(title: str, intro: str = "", crumb: str = "") -> QWidget:
    w = QWidget()
    lay = QVBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 4)
    lay.setSpacing(6)
    if crumb:
        lay.addWidget(label(crumb, "StepCrumb"))
    lay.addWidget(label(title, "PageTitle"))
    if intro:
        lay.addWidget(label(intro, "PageIntro"))
    return w


def mark_locked(widget: QWidget, locked: bool) -> None:
    """Show a profile-locked option read-only with a lock icon and a tooltip."""
    widget.setProperty("locked", locked)
    if hasattr(widget, "setReadOnly") and widget.metaObject().className() in ("QLineEdit", "QPlainTextEdit"):
        widget.setReadOnly(locked)
        widget.setFocusPolicy(Qt.TabFocus if locked else Qt.StrongFocus)
    else:
        widget.setEnabled(not locked)
    if locked:
        widget.setToolTip(LOCK_TIP)
        widget.setAccessibleDescription(LOCK_TIP)


def with_lock(widget: QWidget, locked: bool) -> QWidget:
    """Wrap a field so a lock icon sits next to it when the profile locks it."""
    mark_locked(widget, locked)
    if not locked:
        return widget
    box = QWidget()
    lay = QHBoxLayout(box)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(6)
    lay.addWidget(widget, 1)
    ic = QLabel()
    ic.setPixmap(theme.lock_icon(16).pixmap(16, 16))
    ic.setToolTip(LOCK_TIP)
    ic.setObjectName("LockIcon")
    lay.addWidget(ic)
    return box


def button(text: str, kind: str | None = None, slot=None) -> QPushButton:
    b = QPushButton(text)
    if kind:
        b.setObjectName(kind)
    if slot:
        b.clicked.connect(slot)
    b.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
    return b


def ok_cancel(dialog: QDialog, ok_text: str = "OK") -> QDialogButtonBox:
    bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
    bb.button(QDialogButtonBox.Ok).setText(ok_text)
    bb.button(QDialogButtonBox.Ok).setObjectName("Primary")
    bb.accepted.connect(dialog.accept)
    bb.rejected.connect(dialog.reject)
    return bb
