"""GUI tests (offscreen, no pytest-qt). Run: QT_QPA_PLATFORM=offscreen pytest -m gui tests/test_gui_app.py"""

from __future__ import annotations

import os
import sys
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PySide6.QtWidgets")

from PySide6.QtCore import QTimer  # noqa: E402
from PySide6.QtWidgets import QApplication, QLabel  # noqa: E402

sys.path.insert(0, os.path.dirname(__file__))
from gui_fake_runner import FakeRunner, demo_path  # noqa: E402

from bacnet_health.gui import app as gapp  # noqa: E402
from bacnet_health.gui import report_view, widgets  # noqa: E402
from bacnet_health.gui.advanced import AdvancedDialog, ConfirmTargetDialog  # noqa: E402
from bacnet_health.gui.analyse import VantageBar  # noqa: E402
from bacnet_health.model import Vantage  # noqa: E402
from bacnet_health.profile import Profile  # noqa: E402

pytestmark = pytest.mark.gui


@pytest.fixture(scope="module")
def qapp():
    return gapp.ensure_app()


@pytest.fixture
def win(qapp):
    windows = []

    def make(runner=None, profile=None, profile_path=None):
        w = gapp.create_window(runner=runner or FakeRunner(), profile_path=profile_path, use_real_runner=False)
        if profile is not None:
            w.set_profile(profile)
        w.show()
        windows.append(w)
        return w

    yield make
    for w in windows:
        w._force_close = True
        w.close()
        w.deleteLater()
    wait_until(lambda: not widgets.Task._live, 5)
    QApplication.processEvents()


def wait_until(cond, timeout: float = 10.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.005)
    QApplication.processEvents()
    return bool(cond())


def drive_to_plan(w) -> None:
    w.show_wizard()
    wz = w.wizard
    wz.site.edits["authorised_by"].setText("A. Facility Manager")
    wz.site.notified.setChecked(True)
    wz.next()
    assert wz.index == 1
    assert wait_until(lambda: wz.network.loaded)
    assert "Will broadcast on 192.0.2.255 via en7 (192.0.2.50/24)" == wz.network.sentence.text()
    wz.network.confirm.setChecked(True)
    wz.next()
    assert wz.index == 2
    assert wait_until(lambda: wz.preflight.items and not wz.preflight.running)
    wz.next()
    assert wz.index == 3
    assert wait_until(lambda: wz.plan.session is not None)


# --------------------------------------------------------------------------------------------- tests
def test_app_starts_on_home_with_prerelease_badge(win):
    w = win()
    assert w.stack.currentWidget() is w.home
    texts = [lb.text() for lb in w.findChildren(QLabel)]
    assert "Pre-release" in texts
    assert any(t.startswith("v0.") for t in texts)


def test_home_buttons_navigate(win):
    w = win()
    w.home.run_btn.click()
    assert w.stack.currentWidget() is w.wizard
    w.show_home()
    w.home.analyse_btn.click()
    assert w.stack.currentWidget() is w.analyse
    w.show_home()
    w.home.compare_btn.click()
    assert w.stack.currentWidget() is w.compare


def test_site_step_requires_authorisation_and_notice(win):
    w = win()
    w.show_wizard()
    wz = w.wizard
    wz.next()
    assert wz.index == 0 and "authorised" in wz.site.error.text.text()
    wz.site.edits["authorised_by"].setText("Someone")
    wz.next()
    assert wz.index == 0 and "Tick the box" in wz.site.error.text.text()


def test_network_step_warns_about_default_route_wifi(win):
    w = win()
    drive = w.wizard
    w.show_wizard()
    drive.site.edits["authorised_by"].setText("X")
    drive.site.notified.setChecked(True)
    drive.next()
    assert wait_until(lambda: drive.network.loaded)
    assert not drive.network.warn.isVisibleTo(drive.network)
    drive.network.combo.setCurrentIndex(1)  # Wi-Fi with default route
    assert drive.network.warn.isVisibleTo(drive.network)
    assert "default route" in drive.network.warn.text.text()
    assert drive.network.sentence.text() == "Will broadcast on 198.51.100.255 via en0 (198.51.100.23/24)"
    assert not drive.network.confirm.isChecked()  # changing the interface clears the confirmation


def test_wizard_runs_to_done_and_saves(win, tmp_path):
    runner = FakeRunner()
    w = win(runner)
    drive_to_plan(w)
    assert "Will broadcast on 192.0.2.255" in w.wizard.plan.plan_text.text()
    w.wizard.plan.show_packets.setChecked(True)
    assert "81 0b" in w.wizard.plan.packets.toPlainText()
    w.wizard.next()  # Start
    assert wait_until(lambda: w.stack.currentWidget() is w.report)
    res = w.report.result
    assert res is not None and res.devices and not res.run.incomplete
    assert res.run.authorised_by == "A. Facility Manager"
    assert int(w.wizard.running.dev_count.text()) == runner.n_devices
    assert w.report.tree.topLevelItemCount() == len(res.findings)
    s = runner.sessions[-1]
    assert s.ran and s.closed
    assert runner.prepared_opts[-1].interface == "en7"
    w.report.save_html(str(tmp_path / "r.html"))
    w.report.save_json(str(tmp_path / "r.json"))
    assert "<!DOCTYPE html>" in (tmp_path / "r.html").read_text(encoding="utf-8")
    assert (tmp_path / "r.json").stat().st_size > 100


def test_open_in_browser_writes_file(win, monkeypatch):
    opened = []
    monkeypatch.setattr(report_view, "open_url", lambda url: opened.append(url.toLocalFile()) or True)
    w = win()
    drive_to_plan(w)
    w.wizard.next()
    assert wait_until(lambda: w.stack.currentWidget() is w.report)
    w.report.open_btn.click()
    assert opened and os.path.isfile(opened[0])


def test_stop_cancels_and_keeps_partial(win):
    runner = FakeRunner(step_delay=0.05, steps=100)
    w = win(runner)
    drive_to_plan(w)
    w.wizard.next()
    assert wait_until(lambda: w.wizard.running.running)
    t0 = time.monotonic()
    w.wizard.running.stop.click()
    assert w.wizard.running.stop.text() == "Stopping…"
    assert wait_until(lambda: w.stack.currentWidget() is w.report, 5)
    assert time.monotonic() - t0 < 2.0
    assert w.report.result.run.incomplete
    assert w.report.incomplete.isVisibleTo(w.report)
    assert runner.sessions[-1].closed


def test_preflight_error_blocks_next(win):
    runner = FakeRunner(preflight_items=[
        {"name": "UDP port free", "status": "error", "message": "Port 47808 is used by YABE (yabe.exe)."},
        {"name": "Clock", "status": "ok", "message": "ok"}])
    w = win(runner)
    w.show_wizard()
    wz = w.wizard
    wz.site.edits["authorised_by"].setText("X")
    wz.site.notified.setChecked(True)
    wz.next()
    assert wait_until(lambda: wz.network.loaded)
    wz.network.confirm.setChecked(True)
    wz.next()
    assert wait_until(lambda: wz.preflight.items and not wz.preflight.running)
    assert "yabe.exe" in wz.preflight.error.text.text()
    wz.next()
    assert wz.index == 2


def test_prepare_error_is_shown(win):
    w = win(FakeRunner(prepare_error="UDP port 47808 is already in use by another program (yabe.exe)."))
    w.show_wizard()
    wz = w.wizard
    wz.site.edits["authorised_by"].setText("X")
    wz.site.notified.setChecked(True)
    wz.next()
    assert wait_until(lambda: wz.network.loaded)
    wz.network.confirm.setChecked(True)
    wz.next()
    assert wait_until(lambda: wz.preflight.items and not wz.preflight.running)
    wz.next()
    assert wait_until(lambda: not wz.plan.preparing)
    assert "yabe.exe" in wz.plan.error.text.text()
    wz.next()
    assert wz.index == 3


def test_confirm_dialog_requires_exact_ip(qapp):
    d = ConfirmTargetDialog("fdr", "192.0.2.2", "risk")
    d.edit.setText("192.0.2.20")
    assert not d.ok.isEnabled()
    d.accept()
    assert d.result() != ConfirmTargetDialog.Accepted
    d.edit.setText("192.0.2.")
    assert not d.ok.isEnabled()
    d.edit.setText("192.0.2.2")
    assert d.ok.isEnabled()


def test_cross_subnet_confirmation_flow(win):
    runner = FakeRunner()
    w = win(runner, profile=Profile(read_remote=True, fdr_bbmd="192.0.2.2"))
    drive_to_plan(w)
    wz = w.wizard
    assert wz.plan.cross.isVisibleTo(wz.plan) and "192.0.2.40" in wz.plan.cross.text.text()
    # declining blocks the start
    wz.ask_confirmation = lambda a, t, r: False
    wz.next()
    assert wz.index == 3 and "not confirmed" in wz.plan.error.text.text()
    assert not runner.sessions[-1].confirmations
    # the real dialog: a wrong address is refused, the exact address is accepted
    seen = []

    def answer():
        dlg = QApplication.activeModalWidget()
        if not isinstance(dlg, ConfirmTargetDialog):
            QTimer.singleShot(10, answer)
            return
        dlg.edit.setText(dlg.target + "1")
        seen.append(dlg.ok.isEnabled())
        dlg.edit.setText(dlg.target)
        seen.append(dlg.ok.isEnabled())
        dlg.ok.click()
        QTimer.singleShot(10, answer)

    wz.ask_confirmation = wz._ask_confirmation
    QTimer.singleShot(10, answer)
    sess = runner.sessions[-1]
    wz.next()
    assert wait_until(lambda: w.stack.currentWidget() is w.report)
    assert [c["target"] for c in sess.confirmations] == ["192.0.2.40", "192.0.2.2"]
    assert all(c["user"] for c in sess.confirmations)
    assert seen == [False, True, False, True]
    assert w.report.result.run.confirmations


def test_locked_profile_options_are_read_only(win, qapp):
    p = Profile(site="Sample Site", port=47809, read_remote=False, locked=["site", "port", "read_remote", "accent"])
    w = win(profile=p)
    w.show_wizard()
    site = w.wizard.site.edits["site"]
    assert site.isReadOnly() and site.toolTip() == "Set by your consultant's profile"
    assert not w.wizard.site.edits["client"].isReadOnly()
    d = AdvancedDialog(w.profile, w)
    assert not d.port.isEnabled() and d.port.toolTip() == "Set by your consultant's profile"
    assert not d.read_remote.isEnabled()
    assert d.gap.isEnabled()
    assert d.findChildren(QLabel, "LockIcon")
    d.port.setValue(47810)  # even if changed programmatically, the locked value is kept
    d.gap.setValue(2.0)
    out = d.profile()
    assert out.port == 47809 and out.whois_gap_s == 2.0
    d.deleteLater()


def test_advanced_validation(qapp):
    d = AdvancedDialog(Profile())
    d.fdr_on.setChecked(True)
    d.fdr_ip.setText("not-an-ip")
    d.accept()
    assert d.result() != AdvancedDialog.Accepted and "BBMD" in d.error.text.text()
    d.fdr_ip.setText("192.0.2.2")
    d.accept()
    assert d.result() == AdvancedDialog.Accepted
    assert d.profile().fdr_bbmd == "192.0.2.2"


def test_analyse_demo_capture_and_vantage_override(win):
    w = win()
    w.show_analyse()
    w.analyse.analyse(demo_path())
    assert wait_until(lambda: w.stack.currentWidget() is w.report)
    res = w.report.result
    assert res.run.kind == "analyze" and res.findings
    bars = w.report.findChildren(VantageBar)
    assert bars
    first = res
    bars[-1].combo.setCurrentIndex(2)  # SPAN
    assert wait_until(lambda: w.stack.currentWidget() is w.report and w.report.result is not first)
    assert w.report.result.run.vantage == Vantage.SPAN
    assert w.report.result.run.vantage_source == "user"


def test_analyse_bad_file_is_friendly(win, tmp_path):
    bad = tmp_path / "x.pcap"
    bad.write_bytes(b"this is not a capture")
    w = win()
    w.show_analyse()
    w.analyse.analyse(str(bad))
    assert wait_until(lambda: not w.analyse.busy)
    assert w.stack.currentWidget() is w.analyse
    assert "could not be analysed" in w.analyse.error.text.text()


def test_compare_merges_and_diffs(win, tmp_path):
    from bacnet_health.analysis.analyze import analyze_file

    a = analyze_file(demo_path())
    p1, p2 = tmp_path / "a.json", tmp_path / "b.json"
    a.save(str(p1))
    a.save(str(p2))
    w = win()
    w.show_compare()
    w.compare.add_paths([str(p1), str(p2)])
    w.compare.prev.setText(str(p1))
    w.compare.build()
    assert wait_until(lambda: w.stack.currentWidget() is w.report)
    assert w.report.diff is not None
    assert "compared with the previous visit" in w.report.subtitle.text()


def test_profile_path_opens_wizard(win, tmp_path):
    path = tmp_path / "site.bhprofile"
    Profile(site="Sample Site", authorised_by="A. Manager", locked=["authorised_by"]).save(str(path))
    w = win(profile_path=str(path))
    assert w.stack.currentWidget() is w.wizard
    assert w.wizard.site.edits["site"].text() == "Sample Site"
    assert w.wizard.site.edits["authorised_by"].isReadOnly()


def test_bad_profile_is_friendly(win, tmp_path):
    path = tmp_path / "bad.bhprofile"
    path.write_text("{}", encoding="utf-8")
    n = len(widgets._last_errors)
    w = win(profile_path=str(path))
    assert w.stack.currentWidget() is w.home
    assert len(widgets._last_errors) == n + 1


def test_close_during_scan_cancels_cleanly(win):
    runner = FakeRunner(step_delay=0.05, steps=100)
    w = win(runner)
    drive_to_plan(w)
    w.wizard.next()
    assert wait_until(lambda: w.wizard.running.running)
    w.ask_yes_no = lambda *a: True
    w.close()
    assert w.isVisible()  # waits for the run to stop first
    assert wait_until(lambda: not w.isVisible(), 5)
    s = runner.sessions[-1]
    assert s._cancel.is_set() and s.closed


def test_worker_exception_shows_dialog(qapp):
    n = len(widgets._last_errors)
    parent = widgets.QWidget()

    def boom(_p):
        raise RuntimeError("kaboom")

    widgets.run_task(parent, boom)
    assert wait_until(lambda: len(widgets._last_errors) > n)
    assert "kaboom" in widgets._last_errors[-1]


def test_redacted_html_hides_site_and_addresses(win, tmp_path):
    pytest.importorskip("bacnet_health.report.redact")
    w = win(profile=Profile(site="Secret Tower", org="Sample Consulting"))
    w.show_analyse()
    w.analyse.analyse(demo_path())
    assert wait_until(lambda: w.stack.currentWidget() is w.report)
    assert w.report.save_red_btn.isEnabled()
    full, red = tmp_path / "full.html", tmp_path / "red.html"
    w.report.save_html(str(full))
    w.report.save_html(str(red), redact=True)
    assert "Secret Tower" in full.read_text(encoding="utf-8")
    text = red.read_text(encoding="utf-8")
    assert "Secret Tower" not in text  # addresses are pseudonymised too, but may collide by chance


def test_gui_does_not_import_webengine(qapp):
    assert not [m for m in sys.modules if m.startswith("PySide6.QtWebEngine")]
