"""The Done screen: a native summary of a Result plus save / open-in-browser actions.

QtWebEngine is deliberately not used (it adds ~500 MB to the Windows build). The full HTML report is opened in the
system browser from a file.
"""

from __future__ import annotations

import html
import os
import secrets
import tempfile
from datetime import datetime, timezone
from typing import Any, Callable

from PySide6.QtCore import QUrl, Qt, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter
from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QStyle,
    QStyledItemDelegate,
    QTextBrowser,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from bacnet_health.gui import state, theme
from bacnet_health.gui.widgets import Banner, button, card, label, scroll_page, show_error
from bacnet_health.model import Result, Severity
from bacnet_health.profile import Profile


def _open_url(url: QUrl) -> bool:
    return QDesktopServices.openUrl(url)


# Tests and the screenshot script replace this so no browser is launched.
open_url: Callable[[QUrl], Any] = _open_url

VANTAGE_TEXT = {
    "self": "This laptop's own connection",
    "access": "Normal switch port",
    "span": "Mirror (SPAN) port",
}

KIND_TEXT = {"audit": "Health check", "listen": "Listening check", "scan": "Device scan",
             "analyze": "Capture analysis", "report": "Combined report"}


def render_report_html(result: Result, profile: Profile, diff: dict | None = None, redact: bool = False) -> str:
    from bacnet_health.report.html import render_html  # noqa: PLC0415

    branding = state.branding_from(profile)
    if redact:
        from bacnet_health.report.redact import redact_result  # noqa: PLC0415

        result = redact_result(result, secrets.token_bytes(32))
        diff = None  # a diff against unredacted data would leak
        branding.site = ""
        branding.client = ""
    return render_html(result, branding, diff)


class SeverityDelegate(QStyledItemDelegate):
    """Paints the severity cell as a coloured label that stays visible when the row is selected."""

    def paint(self, painter: QPainter, option, index) -> None:
        sev = index.data(Qt.UserRole + 1)
        if sev not in theme.SEVERITY:
            return super().paint(painter, option, index)
        fg, bg, text = theme.SEVERITY[sev]
        painter.save()
        if option.state & QStyle.State_Selected:
            painter.fillRect(option.rect, QColor(theme.ACCENT_SOFT))
        r = option.rect.adjusted(6, 4, -6, -4)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor(bg))
        painter.drawRoundedRect(r, 4, 4)
        f = option.font
        f.setBold(True)
        painter.setFont(f)
        painter.setPen(QColor(fg))
        painter.drawText(r, Qt.AlignCenter, text)
        painter.restore()

    def sizeHint(self, option, index):  # noqa: N802
        sz = super().sizeHint(option, index)
        sz.setWidth(max(sz.width(), option.fontMetrics.horizontalAdvance("Critical") + 32))
        sz.setHeight(max(sz.height(), option.fontMetrics.height() + 14))
        return sz


class SeverityTile(QFrame):
    def __init__(self, sev: str, count: int):
        super().__init__()
        fg, bg, text = theme.SEVERITY[sev]
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 10, 14, 12)
        lay.setSpacing(2)
        strip = QFrame()
        strip.setFixedHeight(5)
        strip.setStyleSheet(f"background: {bg}; border-radius: 2px; border: none;")
        lay.addWidget(strip)
        n = QLabel(str(count))
        n.setObjectName("BigNumber")
        n.setStyleSheet(f"color: {theme.TEXT if count else '#9aa3ad'};")
        lay.addWidget(n)
        lb = QLabel(text)
        lb.setObjectName("Muted")
        lay.addWidget(lb)
        self.setAccessibleName(f"{text}: {count}")
        self.setMinimumWidth(96)


class FactBox(QWidget):
    def __init__(self, title: str, value: str):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        t = QLabel(title)
        t.setObjectName("Muted")
        v = QLabel(value)
        v.setStyleSheet("font-size: 12.5pt; font-weight: 600;")
        v.setWordWrap(True)
        lay.addWidget(t)
        lay.addWidget(v)


def finding_details_html(f) -> str:
    e = html.escape
    fg, bg, sev = theme.SEVERITY[f.severity.value]
    conf = "Observed" if f.confidence.value == "observed" else "Inferred"
    parts = [
        f'<p style="margin:0 0 6px 0"><span style="background:{bg}; color:{fg}; font-weight:600">'
        f"&nbsp;{sev}&nbsp;</span>&nbsp;&nbsp;<span style='color:{theme.MUTED}'>{e(f.id)} · Confidence: {conf}"
        "</span></p>",
        f'<h3 style="margin:4px 0 4px 0">{e(f.title)}</h3>',
    ]
    if f.subject:
        parts.append(f'<p style="color:{theme.MUTED}; margin:0 0 10px 0">About: {e(f.subject)}</p>')
    parts.append(f"<p>{e(f.explanation)}</p>")
    parts.append(f'<p style="margin-top:12px"><b>What to do</b><br>{e(f.recommendation)}</p>')
    if f.evidence:
        parts.append('<p style="margin-top:12px"><b>Evidence</b></p><table cellspacing="0" cellpadding="4" '
                     f'style="border-collapse:collapse" width="100%">')
        for ev in f.evidence[:25]:
            ts = datetime.fromtimestamp(ev.ts, timezone.utc).strftime("%Y-%m-%d %H:%M:%S") if ev.ts else ""
            parts.append(f'<tr><td style="color:{theme.MUTED}" width="70">{e(ev.kind)}</td>'
                         f"<td>{e(ev.detail)}</td><td style='color:{theme.MUTED}'>{e(ts)}</td></tr>")
        parts.append("</table>")
        if len(f.evidence) > 25:
            parts.append(f'<p style="color:{theme.MUTED}">{len(f.evidence) - 25} more items in the full report.</p>')
    return "".join(parts)


class ReportPage(QWidget):
    """Done view, shared by the wizard, the analyse flow and the compare flow."""

    home = Signal()

    def __init__(self, get_profile: Callable[[], Profile], parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Page")
        self.get_profile = get_profile
        self.result: Result | None = None
        self.diff: dict | None = None
        self.last_opened: str | None = None

        body = QWidget()
        page = QVBoxLayout(self)
        page.setContentsMargins(0, 0, 0, 0)
        page.addWidget(scroll_page(body))
        outer = QVBoxLayout(body)
        outer.setContentsMargins(32, 24, 32, 24)
        outer.setSpacing(14)

        top = QHBoxLayout()
        tl = QVBoxLayout()
        tl.setSpacing(4)
        self.title = label("Report", "PageTitle")
        self.subtitle = label("", "PageIntro")
        tl.addWidget(self.title)
        tl.addWidget(self.subtitle)
        top.addLayout(tl, 1)
        self.open_btn = button("Open full report in browser", "Primary", self.open_in_browser)
        self.open_btn.setMinimumHeight(40)
        top.addWidget(self.open_btn, 0, Qt.AlignTop)
        outer.addLayout(top)

        self.extra_holder = QVBoxLayout()
        outer.addLayout(self.extra_holder)
        self.incomplete = Banner("warn", "")
        outer.addWidget(self.incomplete)

        facts_card, fl = card(margins=16)
        self.facts = QHBoxLayout()
        self.facts.setSpacing(36)
        fl.addLayout(self.facts)
        self.tiles = QHBoxLayout()
        self.tiles.setSpacing(10)
        fl.addLayout(self.tiles)
        self.note = label("", "Muted")
        fl.addWidget(self.note)
        outer.addWidget(facts_card)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Severity", "Finding", "About"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(False)
        self.tree.setUniformRowHeights(True)
        self.tree.setItemDelegateForColumn(0, SeverityDelegate(self.tree))
        self.tree.setAccessibleName("Findings")
        hdr = self.tree.header()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.Stretch)
        hdr.setSectionResizeMode(2, QHeaderView.Interactive)
        hdr.setStretchLastSection(False)
        self.tree.currentItemChanged.connect(self._show_finding)
        self.details = QTextBrowser()
        self.details.setOpenLinks(False)
        self.details.setAccessibleName("Finding details")
        self.details.document().setDocumentMargin(14)
        split.addWidget(self.tree)
        split.addWidget(self.details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        split.setSizes([560, 420])
        split.setMinimumHeight(300)
        outer.addWidget(split, 1)

        row = QHBoxLayout()
        row.setSpacing(10)
        self.save_html_btn = button("Save HTML report…", slot=self.on_save_html)
        self.save_json_btn = button("Save JSON…", slot=self.on_save_json)
        self.save_red_btn = button("Save redacted HTML for sharing…", slot=self.on_save_redacted)
        if not state.redact_available():
            self.save_red_btn.setEnabled(False)
            self.save_red_btn.setToolTip("Redaction is not available in this version.")
        self.back_btn = button("Back to home", slot=self.home.emit)
        row.addWidget(self.save_html_btn)
        row.addWidget(self.save_json_btn)
        row.addWidget(self.save_red_btn)
        row.addStretch(1)
        row.addWidget(self.back_btn)
        bar = QWidget()
        bar.setObjectName("NavBar")
        bar.setStyleSheet(f"QWidget#NavBar {{ background: {theme.CARD}; border-top: 1px solid {theme.BORDER}; }}")
        bar.setLayout(row)
        row.setContentsMargins(32, 12, 32, 12)
        page.addWidget(bar)

    # ------------------------------------------------------------------ content
    def set_extra(self, w: QWidget | None) -> None:
        while self.extra_holder.count():
            it = self.extra_holder.takeAt(0)
            if it.widget():
                it.widget().setParent(None)
        if w is not None:
            self.extra_holder.addWidget(w)

    def show_result(self, result: Result, diff: dict | None = None, title: str = "", subtitle: str = "",
                    extra: QWidget | None = None) -> None:
        self.result = result
        self.diff = diff
        self.last_opened = None
        r = result.run
        self.title.setText(title or f"{KIND_TEXT.get(r.kind, 'Check')} complete")
        p = self.get_profile()
        site = p.site or r.site
        bits = [b for b in (site, _when(r.started)) if b]
        self.subtitle.setText(subtitle or " · ".join(bits))
        self.set_extra(extra)
        self.incomplete.set_text(
            "This check was stopped before it finished. The results below are partial and the report is marked "
            "incomplete." if r.incomplete else "")

        _clear(self.facts)
        remote = sum(1 for d in result.devices if d.remote)
        dev_txt = str(len(result.devices)) + (f" ({remote} behind routers)" if remote else "")
        self.facts.addWidget(FactBox("Devices found", dev_txt))
        self.facts.addWidget(FactBox("BBMDs", str(len([b for b in result.bbmds if b.status != "not-bbmd"]))))
        self.facts.addWidget(FactBox("Findings", str(len(result.findings))))
        if r.vantage is not None:
            self.facts.addWidget(FactBox("Seen from", VANTAGE_TEXT.get(r.vantage.value, r.vantage.value)))
        if diff:
            s = diff.get("summary", {})
            self.facts.addWidget(FactBox("Since previous visit",
                                         f"{s.get('findings_new', 0)} new, {s.get('findings_resolved', 0)} resolved"))
        self.facts.addStretch(1)

        _clear(self.tiles)
        counts = result.severity_counts()
        for sev in Severity:
            self.tiles.addWidget(SeverityTile(sev.value, counts.get(sev.value, 0)))
        self.tiles.addStretch(1)

        n_np = len(result.checks_not_performed)
        self.note.setText(
            (f"{n_np} check{'s' if n_np != 1 else ''} could not be performed from this vantage point; "
             "the full report lists them so a missing finding is not mistaken for a healthy network. ")
            if n_np else "")
        self.note.setVisible(bool(n_np))

        self.tree.clear()
        for f in result.sorted_findings():
            text = theme.SEVERITY[f.severity.value][2]
            it = QTreeWidgetItem([text, f.title, f.subject])
            it.setData(0, Qt.UserRole + 1, f.severity.value)
            it.setData(0, Qt.AccessibleTextRole, f"Severity {text}")
            it.setToolTip(1, f.title)
            it.setData(0, Qt.UserRole, f)
            self.tree.addTopLevelItem(it)
        self.tree.resizeColumnToContents(2)
        if self.tree.columnWidth(2) > 260:
            self.tree.setColumnWidth(2, 260)
        if self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))
        else:
            self.details.setHtml("<h3>No findings</h3><p>No problems were found by the checks that could be "
                                 "performed. Open the full report for the inventory, scope and limitations.</p>")

    def _show_finding(self, cur: QTreeWidgetItem | None, _prev=None) -> None:
        if cur is None:
            return
        self.details.setHtml(finding_details_html(cur.data(0, Qt.UserRole)))

    # ------------------------------------------------------------------ actions
    def _html(self, redact: bool = False) -> str:
        assert self.result is not None
        return render_report_html(self.result, self.get_profile(), self.diff, redact=redact)

    def open_in_browser(self) -> None:
        if self.result is None:
            return
        try:
            d = os.path.join(tempfile.gettempdir(), "bacnet-health")
            os.makedirs(d, exist_ok=True)
            path = os.path.join(d, state.default_filename(self.get_profile(), "report", "html"))
            self.write_file(path, self._html())
            self.last_opened = path
            if not open_url(QUrl.fromLocalFile(path)):
                show_error(self, "Could not open the browser",
                           message=f"The report was saved to {path}. Open it with any web browser.")
        except Exception as exc:  # noqa: BLE001
            show_error(self, "Could not create the report", exc, _tb())

    @staticmethod
    def write_file(path: str, text: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def _ask(self, caption: str, what: str, ext: str, filt: str) -> str:
        start = os.path.join(state.documents_dir(), state.default_filename(self.get_profile(), what, ext))
        path, _ = QFileDialog.getSaveFileName(self, caption, start, filt)
        return path

    def save_html(self, path: str, redact: bool = False) -> None:
        self.write_file(path, self._html(redact=redact))

    def save_json(self, path: str) -> None:
        assert self.result is not None
        self.result.save(path)

    def _guarded(self, fn, path: str, title: str) -> None:
        if not path:
            return
        try:
            fn(path)
        except Exception as exc:  # noqa: BLE001
            show_error(self, title, exc, _tb())

    def on_save_html(self) -> None:
        self._guarded(self.save_html, self._ask("Save HTML report", "report", "html", "HTML report (*.html)"),
                      "Could not save the report")

    def on_save_json(self) -> None:
        self._guarded(self.save_json, self._ask("Save JSON result", "result", "json", "JSON result (*.json)"),
                      "Could not save the JSON result")

    def on_save_redacted(self) -> None:
        self._guarded(lambda p: self.save_html(p, redact=True),
                      self._ask("Save redacted HTML for sharing", "report-redacted", "html", "HTML report (*.html)"),
                      "Could not save the redacted report")


def _clear(layout) -> None:
    while layout.count():
        it = layout.takeAt(0)
        if it.widget():
            it.widget().deleteLater()


def _when(iso: str | None) -> str:
    if not iso:
        return ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00")).astimezone()
    except ValueError:
        return iso
    return dt.strftime("%d %b %Y, %H:%M")


def _tb() -> str:
    import traceback  # noqa: PLC0415

    return traceback.format_exc()
