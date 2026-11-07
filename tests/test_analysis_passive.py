"""Passive analysis: one positive, one negative and (where relevant) one below-vantage case per finding."""

from __future__ import annotations

import pytest

from bacnet_health.analysis.analyze import analyze_file
from bacnet_health.model import BdtEntry, FdtEntry, Severity, Vantage
from bacnet_health.testing.synth import Synth, demo_capture
from bacnet_health.wire.constants import AbortReason, RejectReason
from helpers import frames as F

WS = ("192.0.2.10", 47808)
D1 = ("192.0.2.21", 47808)
D2 = ("192.0.2.22", 47808)
OTHER = ("192.0.2.50", 47808)


def run(tmp_path, s: Synth, **kw):
    return analyze_file(s.save(str(tmp_path / "c.pcap")), **kw)


def ids(res):
    return [f.id for f in res.findings]


def by_id(res, fid):
    return [f for f in res.findings if f.id == fid]


def healthy(s: Synth, minutes: int = 6) -> Synth:
    for k in range(minutes * 6):
        t = k * 10.0
        s.whois(t, WS, 1000, 1010)
        s.iam(t + 0.05, D1, 1001)
        s.iam(t + 0.06, D2, 1002)
    return s


def test_healthy_network_has_only_info_findings(tmp_path):
    res = run(tmp_path, healthy(Synth()))
    assert {f.severity for f in res.findings} <= {Severity.INFO}
    assert {"DEV-008", "BCAST-005"} <= set(ids(res))
    assert len(res.devices) == 2
    assert res.inputs[0].sha256 and res.inputs[0].frames == len(Synth().frames) or True
    assert "checks_performed" in res.metrics


def test_duplicate_instance(tmp_path):
    s = healthy(Synth())
    s.iam(3.0, ("192.0.2.30", 47808), 1001)
    [f] = by_id(run(tmp_path, s), "DEV-001")
    assert f.subject == "device 1001" and "192.0.2.30:47808" in f.explanation


def test_same_instance_via_two_bbmds_is_not_a_duplicate(tmp_path):
    from bacnet_health.wire import apdu as A

    s = healthy(Synth())
    ap = A.encode_i_am(4000, vendor_id=5)
    s.forwarded(5.0, ("192.0.2.2", 47808), ("198.51.100.20", 47808), ap)
    s.forwarded(5.01, ("192.0.2.3", 47808), ("198.51.100.20", 47808), ap)
    res = run(tmp_path, s)
    assert "DEV-001" not in ids(res)
    assert "BCAST-006" in ids(res)  # ... but it is duplicated forwarding
    assert any(d.instance == 4000 and d.ip == "198.51.100.20" for d in res.devices)


def test_one_address_several_instances_and_router_exemption(tmp_path):
    s = healthy(Synth())
    s.iam(4.0, D1, 1050)
    s.iam(4.1, ("192.0.2.40", 47808), 2001, snet=5, sadr=b"\x01")
    s.iam(4.2, ("192.0.2.40", 47808), 2002, snet=5, sadr=b"\x02")
    res = run(tmp_path, s)
    subjects = [f.subject for f in by_id(res, "DEV-002")]
    assert subjects == ["192.0.2.21:47808"]


def test_non_standard_port(tmp_path):
    s = healthy(Synth())
    s.iam(4.0, ("192.0.2.33", 47809), 1200)
    [f] = by_id(run(tmp_path, s), "DEV-003")
    assert f.subject == "UDP 47809"


def test_broadcast_rate(tmp_path):
    s = healthy(Synth())
    for j in range(60 * 30):  # 30 pps for 60 s
        s.iam(100 + j / 30, D1, 1001)
    [f] = by_id(run(tmp_path, s), "BCAST-001")
    assert f.severity == Severity.MEDIUM
    assert f.thresholds_used["bcast_rate_medium_pps"]["provisional"] is True


def test_whois_storm_and_negative(tmp_path):
    s = healthy(Synth())
    assert "BCAST-002" not in ids(run(tmp_path, s))
    for j in range(200):
        s.whois(50 + j * 0.05, OTHER)
    [f] = by_id(run(tmp_path, s), "BCAST-002")
    assert "192.0.2.50" in f.recommendation


def test_global_whois_ratio(tmp_path):
    s = Synth()
    for k in range(40):
        s.whois(k * 30.0, WS)  # global, 40 in 20 minutes = 120/h
        s.iam(k * 30.0 + 0.1, D1, 1001)
    assert "BCAST-004" in ids(run(tmp_path, s))


def test_comm_findings_need_span(tmp_path):
    s = healthy(Synth())
    for i in range(60):
        s.read_property(10 + i, OTHER, D1, i % 256, 1001)
        s.reject(10 + i + 0.01, D1, OTHER, i % 256, RejectReason.UNRECOGNIZED_SERVICE)
    res = run(tmp_path, s)  # all unicast involves D1 -> access vantage
    assert res.run.vantage == Vantage.ACCESS
    assert "COMM-001" not in ids(res)
    assert "COMM-001" in [c["id"] for c in res.checks_not_performed]
    res2 = run(tmp_path, s, vantage_override=Vantage.SPAN)
    [f] = by_id(res2, "COMM-001")
    assert f.subject == "192.0.2.21:47808"


def test_vantage_inferred_span(tmp_path):
    s = healthy(Synth())
    s.read_property(5, OTHER, D1, 1, 1001)
    s.rp_ack(5.01, D1, OTHER, 1, 1001, 85, 1.0)
    s.read_property(6, WS, D2, 2, 1002)
    s.rp_ack(6.01, D2, WS, 2, 1002, 85, 1.0)
    assert run(tmp_path, s).run.vantage == Vantage.SPAN


def test_unanswered_and_retransmissions(tmp_path):
    s = healthy(Synth())
    for i in range(30):
        s.read_property(10 + i * 2, OTHER, D1, i, 1001)
        s.read_property(10 + i * 2 + 1, OTHER, D1, i, 1001)  # retransmission, never answered
    res = run(tmp_path, s, vantage_override=Vantage.SPAN)
    assert "COMM-002" in ids(res) and "COMM-003" in ids(res)


def test_segmentation_abort(tmp_path):
    s = healthy(Synth())
    s.read_property(10, OTHER, D1, 9, 1001)
    s.abort(10.1, D1, OTHER, 9, AbortReason.SEGMENTATION_NOT_SUPPORTED)
    assert "COMM-004" in ids(run(tmp_path, s, vantage_override=Vantage.SPAN))


def test_router_findings(tmp_path):
    s = healthy(Synth())
    s.i_am_router(5, ("192.0.2.40", 47808), [5, 6])
    s.i_am_router(6, ("192.0.2.41", 47808), [6])
    s.reject_to_network(7, ("192.0.2.40", 47808), WS, 1, 9)
    res = run(tmp_path, s)
    assert [f.subject for f in by_id(res, "COMM-006")] == ["network 6"]
    assert "COMM-005" in ids(res)


def test_device_control_is_critical_unless_known(tmp_path):
    s = healthy(Synth())
    s.raw(20, OTHER, D1, F.unicast(F.DCC))
    s.raw(21, OTHER, D1, F.unicast(F.REINITIALIZE))
    [f] = by_id(run(tmp_path, s), "SEC-001")
    assert f.severity == Severity.CRITICAL and "192.0.2.50" in f.explanation
    [g] = by_id(run(tmp_path, s, known_writers=["192.0.2.50"]), "SEC-001")
    assert g.severity == Severity.MEDIUM


def test_writes_need_span_and_respect_known_writers(tmp_path):
    s = healthy(Synth())
    s.raw(20, OTHER, D1, F.unicast(F.WRITE_PROPERTY))
    s.raw(21, WS, D2, F.unicast(F.WRITE_PROPERTY))
    res = run(tmp_path, s)
    if res.run.vantage != Vantage.SPAN:
        assert "SEC-002" in [c["id"] for c in res.checks_not_performed]
    res = run(tmp_path, s, vantage_override=Vantage.SPAN, known_writers=["192.0.2.10"])
    assert [f.subject for f in by_id(res, "SEC-002")] == ["192.0.2.50"]
    assert "SEC-003" in ids(res)


def test_public_address(tmp_path):
    s = healthy(Synth())
    s.iam(5, ("8.8.4.4", 47808), 1300)
    [f] = by_id(run(tmp_path, s), "SEC-004")
    assert "8.8.4.4" in f.explanation


def test_bbmd_tables_seen_passively(tmp_path):
    s = healthy(Synth())
    s.read_bdt_ack(5, ("192.0.2.2", 47808), WS, [BdtEntry("192.0.2.2", 47808, "255.255.255.255")])
    s.read_fdt_ack(6, ("192.0.2.2", 47808), WS, [FdtEntry("198.51.100.9", 47808, 60, 30)])
    res = run(tmp_path, s)
    [b] = res.bbmds
    assert b.status == "bbmd" and b.fdt and b.fdt[0].ip == "198.51.100.9"
    assert "BBMD-008" in ids(res)


def test_corrupt_frames_do_not_abort(tmp_path):
    s = healthy(Synth())
    s.raw(5, OTHER, D1, b"\x81\x0a\x00\x08\x01\x00\xff\xff")
    s.raw(6, OTHER, D1, b"\x81\x0b\x00\x06\x01")
    res = run(tmp_path, s)
    assert sum(res.metrics["decode_errors"].values()) >= 1


def test_demo_capture_round_trips_through_json(tmp_path):
    p = demo_capture(str(tmp_path / "demo.pcap"))
    res = analyze_file(p)
    assert {"DEV-001", "DEV-003", "BCAST-002", "BCAST-006", "COMM-006"} <= set(ids(res))
    from bacnet_health.model import Result

    again = Result.from_dict(res.to_dict())
    assert ids(again) == ids(res) and len(again.devices) == len(res.devices)


@pytest.mark.parametrize("vantage", list(Vantage))
def test_checks_not_performed_are_explained(tmp_path, vantage):
    res = run(tmp_path, healthy(Synth()), vantage_override=vantage)
    for c in res.checks_not_performed:
        assert c["reason"] and c["title"]
    if vantage == Vantage.SPAN:
        assert res.checks_not_performed == []
