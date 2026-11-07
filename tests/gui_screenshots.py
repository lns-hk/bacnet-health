"""Render the main GUI screens offscreen to docs/samples/gui-*.png with the fake runner (not a test).

    QT_QPA_PLATFORM=offscreen .venv/bin/python tests/gui_screenshots.py [OUT_DIR]

Set QT_SCALE_FACTOR=1.5 to review the layout at 150% scaling, BH_SHOT_SIZE=900x640 for a small window and
BH_SHOT_SUFFIX=-small to keep those images apart.
"""

from __future__ import annotations

import os
import sys
import time

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from gui_fake_runner import FakeRunner, demo_path  # noqa: E402

from bacnet_health.gui import app as gapp  # noqa: E402
from bacnet_health.gui import report_view  # noqa: E402
from bacnet_health.gui.advanced import AdvancedDialog, ConfirmTargetDialog  # noqa: E402
from bacnet_health.profile import Profile  # noqa: E402


def pump(seconds: float = 0.15) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QApplication.processEvents()
        time.sleep(0.005)


def wait(cond, timeout: float = 15.0) -> None:
    end = time.monotonic() + timeout
    while time.monotonic() < end and not cond():
        pump(0.02)
    if not cond():
        raise RuntimeError("timed out")
    pump(0.1)


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "docs", "samples")
    os.makedirs(out, exist_ok=True)
    suffix = os.environ.get("BH_SHOT_SUFFIX", "")
    report_view.open_url = lambda url: True
    gapp.ensure_app()

    def shot(widget, name: str) -> None:
        pump()
        path = os.path.join(out, f"gui-{name}{suffix}.png")
        widget.grab().save(path)
        print(path)

    size = tuple(int(x) for x in os.environ.get("BH_SHOT_SIZE", "1120x800").split("x"))
    profile = Profile(site="Sample Site, Building A", client="Sample Client", prepared_by="A. Engineer",
                      org="Sample Consulting", scope_note="BMS VLAN only, 10:00-12:00", locked=["org"])
    runner = FakeRunner(step_delay=0.03, steps=40)
    w = gapp.create_window(runner=runner, use_real_runner=False)
    w.resize(*size)
    w.set_profile(profile, "sample-site.bhprofile")
    w.show()
    shot(w, "home")

    w.show_wizard()
    wz = w.wizard
    wz.site.edits["authorised_by"].setText("B. Facility Manager")
    wz.site.notified.setChecked(True)
    shot(w, "1-site")
    wz.next()
    wait(lambda: wz.network.loaded)
    wz.network.combo.setCurrentIndex(1)
    shot(w, "2-network-wifi-warning")
    wz.network.combo.setCurrentIndex(0)
    wz.network.confirm.setChecked(True)
    shot(w, "2-network")
    wz.next()
    wait(lambda: wz.preflight.items and not wz.preflight.running)
    shot(w, "3-preflight")
    wz.next()
    wait(lambda: wz.plan.session is not None)
    wz.plan.show_packets.setChecked(True)
    shot(w, "4-plan")
    wz.plan.show_packets.setChecked(False)
    wz.next()
    wait(lambda: int(wz.running.dev_count.text() or 0) >= 4)
    shot(w, "5-running")
    wait(lambda: w.stack.currentWidget() is w.report, 30)
    shot(w, "6-done")

    d = AdvancedDialog(w.profile, w, tab="scan")
    d.resize(680, 560)
    d.show()
    shot(d, "advanced-scan")
    d.tabs.setCurrentIndex(1)
    d.read_remote.setChecked(True)
    shot(d, "advanced-cross-subnet")
    d.tabs.setCurrentIndex(3)
    shot(d, "advanced-branding")
    d.close()
    c = ConfirmTargetDialog("fdr", "192.0.2.2", "Registers this laptop as a foreign device with the BBMD at "
                                                "192.0.2.2. The BBMD keeps an entry for about 60 seconds.", w)
    c.edit.setText("192.0.2.")
    c.show()
    shot(c, "confirm-target")
    c.close()

    w.show_analyse()
    shot(w, "analyse")
    w.analyse.analyse(demo_path())
    wait(lambda: w.stack.currentWidget() is w.report)
    shot(w, "analyse-done")
    w.show_compare()
    shot(w, "compare")

    pre = FakeRunner(preflight_items=[
        {"name": "UDP port free", "status": "error",
         "message": "UDP port 47808 is already in use by another program (YABE, yabe.exe). Close it and try again."},
        {"name": "Firewall", "status": "warning",
         "message": "Windows Firewall may block replies. Allow bacnet-health on private networks."},
        {"name": "Clock", "status": "unknown", "message": "No time server reachable."},
        {"name": "Interface up", "status": "ok", "message": "en7 is up."}])
    w2 = gapp.create_window(runner=pre, use_real_runner=False)
    w2.resize(*size)
    w2.show()
    w2.show_wizard()
    w2.wizard.site.edits["authorised_by"].setText("B. Facility Manager")
    w2.wizard.site.notified.setChecked(True)
    w2.wizard.next()
    wait(lambda: w2.wizard.network.loaded)
    w2.wizard.network.confirm.setChecked(True)
    w2.wizard.next()
    wait(lambda: w2.wizard.preflight.items and not w2.wizard.preflight.running)
    w2.wizard.next()
    shot(w2, "3-preflight-error")
    for x in (w, w2):
        x._force_close = True
        x.close()
    QTimer.singleShot(0, QApplication.quit)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
