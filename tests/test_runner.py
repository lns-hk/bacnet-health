"""The runner end to end against the localhost simulator (127.0.0.1 only)."""

from __future__ import annotations

import threading
import time

import pytest

from bacnet_health import runner
from bacnet_health.active.iface import iface_from_cidr
from bacnet_health.testing.sim import SimDevice, Simulator

pytestmark = pytest.mark.network

FAST = dict(whois_high=5000, whois_window_s=0.08, whois_gap_s=0.01, apdu_timeout_s=0.25, settle_s=0.05,
            bvlc_rate_per_s=200, subnet="127.0.0.0/8")


@pytest.fixture
def loopback(monkeypatch):
    lo = iface_from_cidr("127.0.0.1/8", name="lo-test")
    monkeypatch.setattr(runner, "_resolve_iface", lambda opts: lo)
    return lo


def _session(kind, sim, **opt):
    base = dict(port=0, listen_s=0.3, clock_synced=True, site="Sample Site", authorised_by="Test")
    o = runner.RunnerOptions(kind=kind, **{**base, **opt})
    hooks = {"transport": {"broadcast_targets": sim.addresses, "test_mode": True}, "scan_options": dict(FAST)}
    return runner.prepare(kind, o, test_hooks=hooks)


def test_audit_runs_listen_then_scan(loopback):
    with Simulator([SimDevice(1001), SimDevice(1002)]) as sim:
        s = _session("audit", sim)
        assert "Will broadcast on" in s.describe() and "Nothing is written" in s.describe()
        assert "Who-Is" in s.dry_run_text()
        events = []
        try:
            res = s.run(progress=events.append)
        finally:
            s.close()
    assert res.run.kind == "audit" and res.run.site == "Sample Site"
    assert sorted(d.instance for d in res.devices) == [1001, 1002]
    phases = [e.get("phase") for e in events if e.get("type") == "phase"]
    assert phases[0] == "listen" and phases[-1] == "done"
    assert all(e["type"] in {"phase", "progress", "device", "log", "budget-exceeded"} for e in events)
    assert all(runner.progress_line(e) for e in events)


def test_cross_subnet_needs_typed_confirmation(loopback):
    with Simulator([SimDevice(1001)]) as sim:
        s = _session("scan", sim, follow_bdt=True)
        try:
            [(action, target, risk)] = s.required_confirmations()
            assert action == "follow_bdt" and risk
            with pytest.raises(runner.RunnerError):
                s.run()
            s.confirm(action, target, user="tester")
            res = s.run()
        finally:
            s.close()
    assert any(c["action"] == "follow_bdt" and c["user"] == "tester" for c in res.run.confirmations)


def test_cancel_keeps_partial_result(loopback):
    with Simulator([SimDevice(1001)]) as sim:
        s = _session("listen", sim, listen_s=30)
        t = threading.Thread(target=s.run)
        t.start()
        time.sleep(0.3)
        t0 = time.monotonic()
        s.cancel()
        t.join(5)
        s.close()
    assert time.monotonic() - t0 < 2.5
    res = s.result()
    assert res.run.incomplete


def test_invalid_target_is_a_plain_error(loopback):
    with pytest.raises(runner.RunnerError, match="not a valid IPv4"):
        runner.prepare("scan", runner.RunnerOptions(targets=["building-7"]))


def test_options_from_profile():
    from bacnet_health.profile import Profile

    p = Profile(site="Sample Site", listen_minutes=2, targets=["192.0.2.5"], known_writers=["192.0.2.10"])
    o = runner.RunnerOptions.from_profile(p, "audit")
    assert o.listen_s == 120 and o.targets == ["192.0.2.5"] and o.site == "Sample Site"
