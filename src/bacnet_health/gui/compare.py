""""Open & compare reports": one or more JSON results -> merged report, optional diff against a previous visit."""

from __future__ import annotations

import os

from PySide6.QtCore import Signal
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QLineEdit, QListWidget, QVBoxLayout, QWidget

from bacnet_health.gui import state
from bacnet_health.gui.widgets import Banner, button, card, label, page_header, run_task, scroll_page
from bacnet_health.model import Result

JSON_FILTER = "bacnet-health results (*.json);;All files (*)"


def build_report(paths: list[str], previous: str | None) -> tuple[Result, dict | None]:
    from bacnet_health.report.diff import diff_results  # noqa: PLC0415
    from bacnet_health.report.merge import merge_results  # noqa: PLC0415

    results = []
    for p in paths:
        try:
            results.append(Result.load(p))
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"{os.path.basename(p)} is not a bacnet-health result file ({exc}).") from exc
    res = results[0] if len(results) == 1 else merge_results(results)
    diff = None
    if previous:
        try:
            old = Result.load(previous)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"{os.path.basename(previous)} is not a bacnet-health result file ({exc}).") from exc
        diff = diff_results(old, res)
    return res, diff


class ComparePage(QWidget):
    built = Signal(object, object, int)  # Result, diff, number of inputs
    home = Signal()

    def __init__(self, ctx, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.ctx = ctx
        holder = QWidget()
        lay = QVBoxLayout(holder)
        lay.setContentsMargins(40, 28, 40, 28)
        lay.setSpacing(16)
        lay.addWidget(page_header(
            "Open & compare reports",
            "Open the result files (.json) saved after a check. Several files from the same visit, for example "
            "from different network segments, are combined into one report. Add a file from an earlier visit to "
            "see what changed."))
        c, cl = card()
        cl.addWidget(label("Results from this visit", "SectionTitle"))
        self.list = QListWidget()
        self.list.setAccessibleName("Result files")
        self.list.setMinimumHeight(140)
        cl.addWidget(self.list)
        r = QHBoxLayout()
        r.addWidget(button("Add files…", slot=self.add))
        self.remove_btn = button("Remove", slot=self.remove)
        r.addWidget(self.remove_btn)
        r.addStretch(1)
        cl.addLayout(r)
        lay.addWidget(c)
        c2, cl2 = card()
        cl2.addWidget(label("Compare with a previous visit (optional)", "SectionTitle"))
        r2 = QHBoxLayout()
        self.prev = QLineEdit()
        self.prev.setReadOnly(True)
        self.prev.setPlaceholderText("No previous visit selected")
        self.prev.setAccessibleName("Previous visit result file")
        r2.addWidget(self.prev, 1)
        r2.addWidget(button("Choose…", slot=self.pick_prev))
        r2.addWidget(button("Clear", slot=lambda: self.prev.clear()))
        cl2.addLayout(r2)
        lay.addWidget(c2)
        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addStretch(1)
        nav = QHBoxLayout()
        nav.addStretch(1)
        nav.addWidget(button("Back to home", slot=self.home.emit))
        self.go_btn = button("Build report", "Primary", self.build)
        self.go_btn.setMinimumWidth(140)
        nav.addWidget(self.go_btn)
        lay.addLayout(nav)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.addWidget(scroll_page(holder))
        self.paths: list[str] = []
        self.busy = False

    def add_paths(self, paths: list[str]) -> None:
        for p in paths:
            if p not in self.paths:
                self.paths.append(p)
                self.list.addItem(p)
        self.error.set_text("")

    def add(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, "Open result files", state.documents_dir(), JSON_FILTER)
        self.add_paths(paths)

    def remove(self) -> None:
        for it in self.list.selectedItems():
            self.paths.remove(it.text())
            self.list.takeItem(self.list.row(it))

    def pick_prev(self) -> None:
        p, _ = QFileDialog.getOpenFileName(self, "Previous visit", state.documents_dir(), JSON_FILTER)
        if p:
            self.prev.setText(p)

    def build(self) -> None:
        if self.busy:
            return
        if not self.paths:
            self.error.set_text("Add at least one result file.")
            return
        self.busy = True
        self.go_btn.setEnabled(False)
        self.go_btn.setText("Building…")
        paths, prev = list(self.paths), self.prev.text() or None
        run_task(self, lambda _p: build_report(paths, prev), self._ok, self._fail)

    def _reset(self) -> None:
        self.busy = False
        self.go_btn.setEnabled(True)
        self.go_btn.setText("Build report")

    def _ok(self, res) -> None:
        self._reset()
        self.built.emit(res[0], res[1], len(self.paths))

    def _fail(self, exc, tb) -> None:
        self._reset()
        self.error.set_text(str(exc))
