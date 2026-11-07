"""Advanced settings (every runner option, analysis and branding) and the typed cross-subnet confirmation."""

from __future__ import annotations

import copy
import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import (
    QCheckBox,
    QColorDialog,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from bacnet_health.gui import state
from bacnet_health.gui.widgets import Banner, button, label, ok_cancel, with_lock
from bacnet_health.profile import Profile

ACTION_LABELS = {
    "read_remote": "Read devices behind routers",
    "read-remote": "Read devices behind routers",
    "follow_bdt": "Follow BBMD peer tables",
    "follow-bdt": "Follow BBMD peer tables",
    "fdr": "Register as a foreign device with a BBMD",
    "fdr_bbmd": "Register as a foreign device with a BBMD",
}

RISK_NOTE = {
    "read_remote": "Sends read requests through BACnet routers to devices on other networks. Slow links "
                   "(for example MS/TP) can be loaded by this. Requests are limited to one at a time per network.",
    "follow_bdt": "Contacts the peer BBMDs listed in each broadcast table, which are usually on other subnets or "
                  "sites, to read their tables.",
    "fdr_bbmd": "Registers this laptop as a foreign device with the BBMD you name. This is not strictly read-only: "
                "the BBMD keeps an entry for this laptop for about a minute and then forgets it. Who-Is is then "
                "distributed through that BBMD to every network it serves.",
}


def action_label(action_id: str) -> str:
    return ACTION_LABELS.get(action_id, action_id.replace("_", " ").replace("-", " ").capitalize())


class ConfirmTargetDialog(QDialog):
    """Cross-subnet confirmation: the user must type the target IP exactly (design D19)."""

    def __init__(self, action_id: str, target: str, risk_text: str, parent: QWidget | None = None):
        super().__init__(parent)
        self.target = target
        self.setWindowTitle("Confirm traffic beyond this network")
        self.setMinimumWidth(520)
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.addWidget(label(action_label(action_id), "SectionTitle"))
        warn = Banner("warn", risk_text or "This action sends traffic beyond the local subnet.")
        lay.addWidget(warn)
        lay.addWidget(label(f"Target: <b>{target}</b>"))
        lay.addWidget(label(f"To confirm, type the target address <b>{target}</b> below. Your user name "
                            f"({state.os_user()}), the time and the target are recorded in the report."))
        self.edit = QLineEdit()
        self.edit.setPlaceholderText(target)
        self.edit.setAccessibleName("Type the target address to confirm")
        lay.addWidget(self.edit)
        self.hint = label("", "Muted")
        lay.addWidget(self.hint)
        self.bb = ok_cancel(self, "Confirm")
        self.ok = self.bb.button(QDialogButtonBox.Ok)
        self.ok.setEnabled(False)
        lay.addWidget(self.bb)
        self.edit.textChanged.connect(self._check)
        self.edit.setFocus()

    def matches(self) -> bool:
        return self.edit.text().strip() == self.target

    def _check(self) -> None:
        ok = self.matches()
        self.ok.setEnabled(ok)
        t = self.edit.text().strip()
        self.hint.setText("" if ok or not t else "The address does not match yet.")

    def accept(self) -> None:
        if self.matches():
            super().accept()


class AdvancedDialog(QDialog):
    TABS = ("scan", "cross", "analysis", "branding")

    def __init__(self, profile: Profile, parent: QWidget | None = None, tab: str = "scan",
                 analysis_only: bool = False):
        super().__init__(parent)
        self.setWindowTitle("Advanced settings")
        self.setMinimumSize(640, 520)
        self.p = copy.deepcopy(profile)
        lk = self.p.is_locked
        lay = QVBoxLayout(self)
        lay.setSpacing(12)
        lay.addWidget(label("These settings are for consultants. The defaults are safe for live building networks.",
                            "Muted"))
        self.tabs = QTabWidget()
        lay.addWidget(self.tabs, 1)

        # ---- scan
        w = QWidget()
        f = QFormLayout(w)
        f.setContentsMargins(16, 16, 16, 16)
        f.setVerticalSpacing(10)
        f.setHorizontalSpacing(16)
        f.setLabelAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self.port = QSpinBox()
        self.port.setRange(47808, 47823)
        self.port.setValue(int(self.p.port or 47808))
        self.port.setMaximumWidth(180)
        f.addRow("UDP port", with_lock(self.port, lk("port")))
        self.targets = QPlainTextEdit("\n".join(self.p.targets))
        self.targets.setPlaceholderText("One IP address per line (optional)")
        self.targets.setMaximumHeight(90)
        self.targets.setTabChangesFocus(True)
        f.addRow("Unicast targets", with_lock(self.targets, lk("targets")))
        self.gap = self._dspin(0.2, 60.0, self.p.whois_gap_s, " s", 1)
        f.addRow("Gap between Who-Is", with_lock(self.gap, lk("whois_gap_s")))
        self.rate = self._dspin(0.5, 50.0, self.p.max_req_per_s, " req/s", 1)
        f.addRow("Max requests per second", with_lock(self.rate, lk("max_req_per_s")))
        self.timeout = self._dspin(0.5, 30.0, self.p.apdu_timeout_s, " s", 1)
        f.addRow("Reply timeout", with_lock(self.timeout, lk("apdu_timeout_s")))
        self.retries = QSpinBox()
        self.retries.setRange(0, 3)
        self.retries.setValue(int(self.p.apdu_retries))
        self.retries.setMaximumWidth(180)
        f.addRow("Retries", with_lock(self.retries, lk("apdu_retries")))
        self.read_props = QCheckBox("Read device details (vendor, model, firmware, name)")
        self.read_props.setChecked(self.p.read_properties)
        f.addRow("", with_lock(self.read_props, lk("read_properties")))
        self.bbmd = QCheckBox("Check BBMD broadcast and foreign-device tables")
        self.bbmd.setChecked(self.p.bbmd_audit)
        f.addRow("", with_lock(self.bbmd, lk("bbmd_audit")))
        self.tabs.addTab(w, "Scan")

        # ---- cross-subnet
        w = QWidget()
        v = QVBoxLayout(w)
        v.setContentsMargins(16, 16, 16, 16)
        v.setSpacing(10)
        v.addWidget(Banner("info", "Each option below reaches beyond the local subnet. They are off by default. "
                                   "Before the check starts you will be asked to type each target address to "
                                   "confirm, and the confirmation is recorded in the report."))
        self.read_remote = QCheckBox(ACTION_LABELS["read_remote"])
        self.read_remote.setChecked(self.p.read_remote)
        self.follow_bdt = QCheckBox(ACTION_LABELS["follow_bdt"])
        self.follow_bdt.setChecked(self.p.follow_bdt)
        self.fdr_on = QCheckBox(ACTION_LABELS["fdr_bbmd"])
        self.fdr_on.setChecked(bool(self.p.fdr_bbmd))
        self.fdr_ip = QLineEdit(self.p.fdr_bbmd or "")
        self.fdr_ip.setPlaceholderText("BBMD IP address, e.g. 192.0.2.2")
        self.fdr_ip.setAccessibleName("Foreign Device Registration BBMD IP")
        self.risk_labels = {}
        for name, cb in (("read_remote", self.read_remote), ("follow_bdt", self.follow_bdt),
                         ("fdr_bbmd", self.fdr_on)):
            v.addWidget(with_lock(cb, lk(name)))
            if name == "fdr_bbmd":
                row = QHBoxLayout()
                row.setContentsMargins(28, 0, 0, 0)
                row.addWidget(with_lock(self.fdr_ip, lk(name)))
                v.addLayout(row)
            rl = Banner("warn", RISK_NOTE[name])
            rl.setContentsMargins(20, 0, 0, 0)
            self.risk_labels[name] = rl
            v.addWidget(rl)
            cb.toggled.connect(self._sync_cross)
        v.addStretch(1)
        self.tabs.addTab(w, "Beyond this network")

        # ---- analysis
        w = QWidget()
        f2 = QFormLayout(w)
        f2.setContentsMargins(16, 16, 16, 16)
        f2.setVerticalSpacing(10)
        self.writers = QPlainTextEdit("\n".join(self.p.known_writers))
        self.writers.setPlaceholderText("One IP address per line")
        self.writers.setMaximumHeight(120)
        self.writers.setTabChangesFocus(True)
        f2.addRow(label("Known engineering workstations. Write traffic from these addresses is treated as "
                        "authorised.", "Muted"))
        f2.addRow("Workstations", with_lock(self.writers, lk("known_writers")))
        self.tabs.addTab(w, "Analysis")

        # ---- branding
        w = QWidget()
        f3 = QFormLayout(w)
        f3.setContentsMargins(16, 16, 16, 16)
        f3.setVerticalSpacing(10)
        f3.setHorizontalSpacing(16)
        f3.addRow(label("Shown on the cover of every report. Saved in the profile.", "Muted"))
        self.org = QLineEdit(self.p.org)
        f3.addRow("Organisation", with_lock(self.org, lk("org")))
        self.prepared = QLineEdit(self.p.prepared_by)
        f3.addRow("Prepared by", with_lock(self.prepared, lk("prepared_by")))
        logo_row = QWidget()
        lr = QHBoxLayout(logo_row)
        lr.setContentsMargins(0, 0, 0, 0)
        self.logo = QLineEdit(self.p.logo_path or "")
        self.logo.setReadOnly(True)
        self.logo.setPlaceholderText("No logo")
        self.logo_btn = button("Choose…", slot=self._pick_logo)
        self.logo_clear = button("Remove", slot=lambda: self._set_logo(""))
        lr.addWidget(self.logo, 1)
        lr.addWidget(self.logo_btn)
        lr.addWidget(self.logo_clear)
        if lk("logo_path"):
            self.logo_btn.setEnabled(False)
            self.logo_clear.setEnabled(False)
        f3.addRow("Logo", with_lock(logo_row, lk("logo_path")))
        self.logo_preview = QLabel()
        self.logo_preview.setMinimumHeight(48)
        f3.addRow("", self.logo_preview)
        acc_row = QWidget()
        ar = QHBoxLayout(acc_row)
        ar.setContentsMargins(0, 0, 0, 0)
        self.accent = QLineEdit(self.p.accent or "#1f4e79")
        self.accent.setMaximumWidth(120)
        self.swatch = QPushButton()
        self.swatch.setFixedSize(34, 28)
        self.swatch.setToolTip("Choose colour")
        self.swatch.setAccessibleName("Choose accent colour")
        self.swatch.clicked.connect(self._pick_colour)
        ar.addWidget(self.accent)
        ar.addWidget(self.swatch)
        ar.addStretch(1)
        self.accent.textChanged.connect(self._sync_swatch)
        if lk("accent"):
            self.swatch.setEnabled(False)
        f3.addRow("Accent colour", with_lock(acc_row, lk("accent")))
        self.tabs.addTab(w, "Report branding")

        self.error = Banner("error", "")
        lay.addWidget(self.error)
        lay.addWidget(ok_cancel(self, "Save settings"))
        self._sync_cross()
        self._sync_swatch()
        self._set_logo(self.p.logo_path or "")
        if analysis_only:
            for i in (0, 1):
                self.tabs.setTabEnabled(i, False)
        self.tabs.setCurrentIndex(self.TABS.index(tab) if tab in self.TABS else 0)

    @staticmethod
    def _dspin(lo: float, hi: float, value: float, suffix: str, dec: int) -> QDoubleSpinBox:
        s = QDoubleSpinBox()
        s.setRange(lo, hi)
        s.setDecimals(dec)
        s.setSingleStep(0.5)
        s.setSuffix(suffix)
        s.setValue(float(value))
        s.setMaximumWidth(180)
        return s

    def _sync_cross(self) -> None:
        for name, cb in (("read_remote", self.read_remote), ("follow_bdt", self.follow_bdt),
                         ("fdr_bbmd", self.fdr_on)):
            self.risk_labels[name].setVisible(cb.isChecked())
        self.fdr_ip.setEnabled(self.fdr_on.isChecked() and not self.p.is_locked("fdr_bbmd"))

    def _sync_swatch(self) -> None:
        c = self.accent.text().strip()
        ok = QColor(c).isValid() and c.startswith("#")
        self.swatch.setStyleSheet(f"background: {c if ok else '#ffffff'}; border: 1px solid #b9c2cc;"
                                  "border-radius: 5px;")

    def _pick_colour(self) -> None:
        c = QColorDialog.getColor(QColor(self.accent.text().strip() or "#1f4e79"), self, "Accent colour")
        if c.isValid():
            self.accent.setText(c.name())

    def _pick_logo(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose a logo", state.documents_dir(),
                                              "Images (*.png *.jpg *.jpeg *.gif *.svg *.webp)")
        if path:
            self._set_logo(path)

    def _set_logo(self, path: str) -> None:
        self.logo.setText(path)
        pm = QPixmap(path) if path and os.path.isfile(path) else QPixmap()
        if pm.isNull():
            self.logo_preview.setText("" if not path else "The logo file could not be read.")
            self.logo_preview.setPixmap(QPixmap())
        else:
            self.logo_preview.setPixmap(pm.scaledToHeight(44, Qt.SmoothTransformation))

    # ------------------------------------------------------------------ result
    def validate(self) -> str:
        for ip in state.parse_ip_list(self.targets.toPlainText()):
            if not state.is_ipv4(ip):
                return f"Unicast target '{ip}' is not an IPv4 address."
        for ip in state.parse_ip_list(self.writers.toPlainText()):
            if not state.is_ipv4(ip):
                return f"Workstation '{ip}' is not an IPv4 address."
        if self.fdr_on.isChecked() and not state.is_ipv4(self.fdr_ip.text()):
            return "Enter the BBMD IP address for foreign device registration (for example 192.0.2.2)."
        acc = self.accent.text().strip()
        if not (acc.startswith("#") and len(acc) in (4, 7) and QColor(acc).isValid()):
            return "The accent colour must look like #1f4e79."
        return ""

    def accept(self) -> None:
        msg = self.validate()
        if msg:
            self.error.set_text(msg)
            return
        super().accept()

    def profile(self) -> Profile:
        """The edited copy. Locked options keep their profile values."""
        p = copy.deepcopy(self.p)
        new = dict(
            port=self.port.value(),
            targets=state.parse_ip_list(self.targets.toPlainText()),
            whois_gap_s=self.gap.value(),
            max_req_per_s=self.rate.value(),
            apdu_timeout_s=self.timeout.value(),
            apdu_retries=self.retries.value(),
            read_properties=self.read_props.isChecked(),
            bbmd_audit=self.bbmd.isChecked(),
            read_remote=self.read_remote.isChecked(),
            follow_bdt=self.follow_bdt.isChecked(),
            fdr_bbmd=self.fdr_ip.text().strip() if self.fdr_on.isChecked() else None,
            known_writers=state.parse_ip_list(self.writers.toPlainText()),
            org=self.org.text().strip(),
            prepared_by=self.prepared.text().strip(),
            logo_path=self.logo.text().strip() or None,
            accent=self.accent.text().strip(),
        )
        for k, v in new.items():
            if not p.is_locked(k):
                setattr(p, k, v)
        return p
