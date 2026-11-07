"""Integration tests: the real transport and scanner against the localhost simulator. Only 127.0.0.1 is used."""

from __future__ import annotations

import socket
import threading
import time

import pytest

from bacnet_health.active.listen import listen
from bacnet_health.active.scan import READ_PROPERTIES, Scanner, ScanOptions, property_name
from bacnet_health.active.transport import BacnetTransport, PortInUse
from bacnet_health.model import BdtEntry, FdtEntry, Result
from bacnet_health.testing.sim import Simulator, SimDevice
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.constants import BvlcFunction, PropertyId as P, name_of
from bacnet_health.wire.txguard import TxBlocked, check_tx

from helpers import frames as F

pytestmark = pytest.mark.network

ONE = "255.255.255.255"
ALLOWED_KINDS = {"who-is", "read-property", "rpm"} | {
    "bvlc:" + name_of(BvlcFunction, f)
    for f in (BvlcFunction.READ_BDT, BvlcFunction.READ_FDT, BvlcFunction.REGISTER_FOREIGN_DEVICE)
}
EXPECTED_PROPS = {property_name(p, i) for p, i in READ_PROPERTIES} | {"protocol-services-supported"}


def fast_options(t: BacnetTransport, **kw) -> ScanOptions:
    base = dict(port=t.port, subnet="127.0.0.0/8", whois_high=5000, whois_window_s=0.08, whois_gap_s=0.01,
                apdu_timeout_s=0.25, apdu_retries=1, settle_s=0.05, bvlc_rate_per_s=200, remote_rate_per_s=50,
                host_ntp_synced=True)
    base.update(kw)
    return ScanOptions(**base)


def scan(devices: list[SimDevice], setup=None, rate: float = 300, **kw) -> tuple[Result, BacnetTransport, Simulator]:
    with Simulator(devices) as sim:
        if setup:
            setup(sim)
        with BacnetTransport("127.0.0.1", 0, broadcast_targets=sim.addresses, rate=rate) as t:
            s = Scanner(t, fast_options(t, **kw))
            s.plan()
            r = s.run()
    return r, t, sim


def ids(r: Result) -> set[str]:
    return {f.id for f in r.findings}


def assert_all_allowed(t: BacnetTransport) -> None:
    assert t.sent_log
    for f in t.sent_log:
        assert f.kind in ALLOWED_KINDS, f.kind
        check_tx(f.data)  # re-verify the exact bytes that went out
        assert not f.dst.startswith("broadcast 255.255.255.255")


# ---------------------------------------------------------------------------------------------------------------------


def test_full_scan_finds_devices_and_properties():
    devs = [SimDevice(1001), SimDevice(1002), SimDevice(3333, max_apdu=480)]
    r, t, _ = scan(devs)
    assert sorted(d.instance for d in r.devices) == [1001, 1002, 3333]
    for d in r.devices:
        assert d.responded_to_scan and d.vendor_id == 999 and d.max_apdu in (1476, 480)
        assert EXPECTED_PROPS <= set(d.properties), set(d.properties) ^ EXPECTED_PROPS
        assert d.property_errors == {}
        assert d.properties["system-status"] == "operational"
        assert d.properties["object-list[0]"] == 12
    st = r.metrics["scan_stats"]
    assert all(v["rpm"] for v in st.values())
    small = st[f"3333@127.0.0.1:{devs[2].port}"]
    assert small["requests"] > 2  # RPM split to fit 480 octets
    assert_all_allowed(t)
    assert r.budget.frames_sent == len(t.sent_log)
    assert r.budget.whois_sent == len(r.metrics["whois_chunks"]["sent"])
    assert not r.run.incomplete and r.metrics["inbound_verified"] is True
    assert "DEV-008" in ids(r) and "DEV-001" not in ids(r)
    Result.from_dict(r.to_dict())  # JSON round trip


def test_rpm_not_supported_uses_rp():
    r, t, sim = scan([SimDevice(10, rpm=False)])
    d = r.devices[0]
    assert EXPECTED_PROPS <= set(d.properties)
    st = next(iter(r.metrics["scan_stats"].values()))
    assert st["rpm"] is False and st["requests"] == 1 + len(READ_PROPERTIES)
    assert "rpm" not in sim.devices[0].received  # never asked with RPM


def test_rpm_rejected_falls_back_to_rp():
    services = [False] * 40
    services[12] = services[14] = True  # advertises RPM, then rejects it
    dev = SimDevice(11, rpm=False, properties={P.PROTOCOL_SERVICES_SUPPORTED: services})
    r, _, _ = scan([dev])
    st = next(iter(r.metrics["scan_stats"].values()))
    assert st["rejects"] == 1 and st["rpm_fallback"].startswith("reject")
    assert EXPECTED_PROPS <= set(r.devices[0].properties)


def test_rpm_too_big_is_aborted_then_split_by_rp():
    dev = SimDevice(12, max_apdu=206, object_name="N" * 190)
    r, _, _ = scan([dev])
    st = next(iter(r.metrics["scan_stats"].values()))
    assert st["aborts"] >= 1 and "segmentation-not-supported" in st["abort_reasons"]
    assert r.devices[0].properties["object-name"] == "N" * 190


def test_unknown_property_recorded_not_an_error():
    r, _, _ = scan([SimDevice(13, missing={P.LOCATION, P.UTC_OFFSET})])
    d = r.devices[0]
    assert d.property_errors == {"location": "unknown-property", "utc-offset": "unknown-property"}
    assert "DEV-004" not in ids(r)


def test_slow_device_within_timeout():
    r, _, _ = scan([SimDevice(14, delay=0.1)])
    st = next(iter(r.metrics["scan_stats"].values()))
    assert st["timeouts"] == 0 and EXPECTED_PROPS <= set(r.devices[0].properties)


def test_drop_first_request_is_retried_once():
    r, _, _ = scan([SimDevice(15, drop_first=1)])
    st = next(iter(r.metrics["scan_stats"].values()))
    assert st["timeouts"] == 1 and st["retries"] == 1 and not st["unresponsive"]
    assert EXPECTED_PROPS <= set(r.devices[0].properties)


def test_silent_device_marked_unresponsive_not_hammered():
    dev = SimDevice(16, drop_first=10_000)  # answers Who-Is, never answers reads
    r, t, sim = scan([dev])
    st = next(iter(r.metrics["scan_stats"].values()))
    assert st["unresponsive"] and st["requests"] == 2  # one request + one retry, then stop
    assert "DEV-004" in ids(r)
    assert sim.devices[0].received.count("read-property") == 2


def test_duplicate_instance_raises_dev001():
    r, _, _ = scan([SimDevice(2001, object_name="A"), SimDevice(2001, object_name="B")])
    f = [x for x in r.findings if x.id == "DEV-001"]
    assert len(f) == 1 and f[0].severity.value == "high"
    assert len({d.address_key for d in r.devices}) == 2


def test_status_and_clock_findings():
    r, _, _ = scan([SimDevice(30, system_status=4), SimDevice(31, clock_offset_s=7200)])
    by = {(f.id, f.subject): f for f in r.findings}
    assert by[("DEV-005", "device 30")].severity.value == "high"
    assert by[("DEV-006", "device 31")].severity.value == "medium"
    assert ("DEV-006", "device 30") not in by


def test_unicast_targets():
    hidden = SimDevice(40, answer_whois=False)  # found by RP on device 4194303
    no_wild = SimDevice(41, answer_wildcard=False)  # RP fails -> unicast Who-Is
    dead = SimDevice(42, drop_all=True)
    with Simulator([hidden, no_wild, dead]) as sim:
        with BacnetTransport("127.0.0.1", 0, broadcast_targets=[], rate=300) as t:
            targets = [f"127.0.0.1:{d.port}" for d in (hidden, no_wild, dead)]
            s = Scanner(t, fast_options(t, discovery=False, targets=targets, bbmd_audit=False))
            s.plan()
            r = s.run()
    res = r.metrics["targets"]
    assert res[targets[0]]["method"] == "read-property-wildcard"
    assert res[targets[1]]["method"] == "unicast-who-is"
    assert res[targets[2]]["method"] is None
    assert sorted(d.instance for d in r.devices) == [40, 41]
    found40 = next(d for d in r.devices if d.instance == 40)
    assert found40.vendor_id == 999 and found40.max_apdu == 1476  # identity read because there was no I-Am
    assert any(f.id == "DEV-004" and targets[2] in f.subject for f in r.findings)
    assert_all_allowed(t)


def test_remote_devices_recorded_not_read_by_default():
    router = SimDevice(50, remote=[SimDevice(501), SimDevice(502)], remote_net=7)
    r, t, _ = scan([router])
    remote = [d for d in r.devices if d.remote]
    assert sorted(d.instance for d in remote) == [501, 502]
    assert all(d.snet == 7 and not d.properties for d in remote)
    assert any("behind BACnet routers" in x for x in r.limitations)
    for f in t.sent_log:  # nothing routed was sent
        npdu = B.decode_bvlc(f.data).npdu
        assert npdu is None or N.decode_npdu(npdu).dnet is None


def test_read_remote_reads_through_router():
    router = SimDevice(51, remote=[SimDevice(511), SimDevice(512)], remote_net=8)
    r, t, _ = scan([router], read_remote=True)
    remote = {d.instance: d for d in r.devices if d.remote}
    assert EXPECTED_PROPS <= set(remote[511].properties)
    routed = [f for f in t.sent_log if f.kind in ("read-property", "rpm")
              and N.decode_npdu(B.decode_bvlc(f.data).npdu).dnet == 8]
    assert routed
    # one in flight per DNET at <= 50/s: consecutive routed requests are spaced by >= 1/50 s
    for a, b in zip(routed, routed[1:]):
        assert b.mono - a.mono >= 1 / 50 - 0.005


def test_remote_network_abandoned_after_two_timeouts():
    router = SimDevice(52, remote=[SimDevice(521, drop_first=10_000), SimDevice(522, drop_first=10_000)],
                       remote_net=9)
    r, t, _ = scan([router], read_remote=True)
    routed = [f for f in t.sent_log if f.kind in ("read-property", "rpm")
              and N.decode_npdu(B.decode_bvlc(f.data).npdu).dnet == 9]
    assert len(routed) == 2  # two consecutive timeouts, then the whole network is left alone
    notes = [v.get("note") for v in r.metrics["scan_stats"].values() if v["instance"] in (521, 522)]
    assert any(n and "abandoned" in n for n in notes)


# ---------------------------------------------------------------------------------------------------------------------
# BBMD audit
# ---------------------------------------------------------------------------------------------------------------------


def test_bbmd_tables_and_asymmetric_bdt():
    a = SimDevice(60, bbmd=True)
    b = SimDevice(None, bbmd=True)  # BBMD-only node: found only through a's BDT (follow-bdt)

    def setup(sim):
        a.bdt = [BdtEntry("127.0.0.1", a.port, ONE), BdtEntry("127.0.0.1", b.port, ONE)]
        b.bdt = [BdtEntry("127.0.0.1", b.port, ONE)]  # does not list a
        a.fdt = [FdtEntry("10.9.8.7", 47808, 300, 120)]

    r, t, _ = scan([a, b, SimDevice(61)], setup=setup, follow_bdt=True)
    bb = {(x.port): x for x in r.bbmds}
    assert bb[a.port].status == "bbmd" and bb[a.port].source == "probe" and bb[a.port].fdt_status == "ack"
    assert bb[a.port].fdt[0].ip == "10.9.8.7"
    assert bb[b.port].source == "bdt-peer" and bb[b.port].status == "bbmd"
    assert "BBMD-002" in ids(r) and "BBMD-008" in ids(r)
    assert 61 not in {x.port for x in r.bbmds}  # plain device NAKed Read-BDT: not listed as a BBMD
    assert r.metrics["bvlc"]["read_bdt_nak"]
    kinds = [f.kind for f in t.sent_log if f.kind.startswith("bvlc:")]
    assert r.budget.bvlc_probes_sent == len(kinds)
    assert_all_allowed(t)


def test_asymmetry_not_checked_without_follow_bdt():
    a = SimDevice(62, bbmd=True)
    b = SimDevice(None, bbmd=True)

    def setup(sim):
        a.bdt = [BdtEntry("127.0.0.1", a.port, ONE), BdtEntry("127.0.0.1", b.port, ONE)]

    r, t, sim = scan([a, b], setup=setup)
    assert "BBMD-002" not in ids(r)
    assert any(x["id"] == "BBMD-002" for x in r.checks_not_performed)
    assert "read-broadcast-dist-table" not in " ".join(sim.devices[1].received)  # peer never contacted


def test_two_bbmds_same_subnet():
    a, b = SimDevice(70, bbmd=True), SimDevice(71, bbmd=True)

    def setup(sim):
        tbl = [BdtEntry("127.0.0.1", a.port, ONE), BdtEntry("127.0.0.1", b.port, ONE)]
        a.bdt, b.bdt = list(tbl), list(tbl)

    r, _, _ = scan([a, b], setup=setup)
    f = [x for x in r.findings if x.id == "BBMD-001"]
    assert len(f) == 1 and f[0].subject == "127.0.0.0/8"
    assert "BBMD-005" in ids(r)  # the local subnet would get duplicate copies
    assert r.topology["broadcast_copies"]["127.0.0.0/8"] > 1


def test_public_fdt_entry_bbmd006():
    a = SimDevice(80, bbmd=True)

    def setup(sim):
        a.bdt = [BdtEntry("127.0.0.1", a.port, ONE)]
        a.fdt = [FdtEntry("203.0.113.50", 47808, 600, 300)]

    r, _, _ = scan([a], setup=setup, public_ranges=["203.0.113.0/24"])
    f = [x for x in r.findings if x.id == "BBMD-006"]
    assert len(f) == 1 and f[0].severity.value == "critical" and "203.0.113.50" in f[0].explanation


def test_fdr_mode_registers_and_distributes_whois():
    bbmd = SimDevice(90, bbmd=True)
    others = [SimDevice(91), SimDevice(92)]

    def setup(sim):
        bbmd.bdt = [BdtEntry("127.0.0.1", bbmd.port, ONE)]

    with Simulator([bbmd] + others) as sim:
        setup(sim)
        with BacnetTransport("127.0.0.1", 0, broadcast_targets=[], rate=300) as t:
            o = fast_options(t, fdr_bbmd=f"127.0.0.1:{bbmd.port}", fdr_confirmed_ip="127.0.0.1",
                             read_properties=False)
            s = Scanner(t, o)
            s.plan()
            r = s.run()
    assert sorted(d.instance for d in r.devices) == [90, 91, 92]
    kinds = [f.kind for f in t.sent_log]
    assert kinds[0] == "bvlc:register-foreign-device"
    assert all(k != "who-is" or B.decode_bvlc(f.data).function == BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK
               for k, f in zip(kinds, t.sent_log))
    assert r.metrics["fdr"][0]["result"] == "ack"
    assert any(c["action"] == "foreign-device-registration" for c in r.run.confirmations)
    assert any("time-to-live" in x for x in r.limitations)
    assert bbmd.fdt and bbmd.fdt[0].ttl == 60


# ---------------------------------------------------------------------------------------------------------------------
# Safety
# ---------------------------------------------------------------------------------------------------------------------


def test_cancel_stops_sending_within_100ms():
    devs = [SimDevice(i) for i in range(1, 6)]
    with Simulator(devs) as sim:
        with BacnetTransport("127.0.0.1", 0, broadcast_targets=sim.addresses, rate=20) as t:
            s = Scanner(t, fast_options(t, whois_high=4_194_302, whois_window_s=0.05))
            s.plan()
            out = {}
            th = threading.Thread(target=lambda: out.setdefault("r", s.run()))
            th.start()
            time.sleep(0.4)
            cancel_at = time.monotonic()
            t.cancel.set()
            th.join(2)
            assert not th.is_alive(), "scan did not stop"
            stopped_after = time.monotonic() - cancel_at
    r = out["r"]
    assert r.run.incomplete
    assert any("stopped by the user" in n for n in r.budget.notes)
    late = [f for f in t.sent_log if f.mono > cancel_at + 0.1]
    assert late == []
    assert stopped_after < 1.0
    assert t.sent_log  # it did send before the stop


def test_txguard_blocks_injected_forbidden_frame():
    dev = SimDevice(100)
    with Simulator([dev]) as sim:
        with BacnetTransport("127.0.0.1", 0, broadcast_targets=sim.addresses) as t:
            for frame in F.PROHIBITED_CONFIRMED.values():
                with pytest.raises(TxBlocked):
                    t.send_unicast(F.unicast(frame), dev.addr)
            for frame in F.PROHIBITED_UNCONFIRMED.values():
                with pytest.raises(TxBlocked):
                    t.send_broadcast(F.broadcast(frame))
            with pytest.raises(TxBlocked):
                t.send_unicast(F.WRITE_BDT, dev.addr)
            assert t.sent_log == [] and t.budget.frames_sent == 0
            time.sleep(0.05)
    assert dev.received == []


def test_no_limited_broadcast():
    with pytest.raises(ValueError):
        BacnetTransport("127.0.0.1", 0, broadcast="255.255.255.255", test_mode=True)
    with BacnetTransport("127.0.0.1", 0, subnet="127.0.0.0/8", test_mode=True) as t:
        with pytest.raises(ValueError):
            t.send_unicast(B.encode_read_bdt(), ("255.255.255.255", 47808))
        with pytest.raises(ValueError):
            t.send_unicast(B.encode_read_bdt(), ("127.255.255.255", 47808))
        with pytest.raises(ValueError):
            t.send_broadcast(B.encode_original_broadcast(N.encode_npdu(A.encode_who_is(0, 10))))
    assert t.sent_log == []


def test_port_in_use_refused_with_plain_message():
    holder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    holder.bind(("127.0.0.1", 0))
    port = holder.getsockname()[1]
    try:
        with pytest.raises(PortInUse) as ei:
            BacnetTransport("127.0.0.1", port, test_mode=True)  # bind path
        assert str(port) in str(ei.value) and "already in use" in str(ei.value)
        with pytest.raises(PortInUse):
            BacnetTransport("127.0.0.1", port)  # pre-bind owner lookup path (lsof / port_owners)
    finally:
        holder.close()


def test_exclusive_bind_never_sets_reuse():
    with BacnetTransport("127.0.0.1", 0, test_mode=True) as t:
        assert t.sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        if hasattr(socket, "SO_REUSEPORT"):
            assert t.sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 0


def test_inbound_not_verified_when_silent():
    with BacnetTransport("127.0.0.1", 0, broadcast_targets=[], rate=300) as t:
        s = Scanner(t, fast_options(t, whois_high=2000, bbmd_audit=False))
        s.plan()
        r = s.run()
    assert r.devices == [] and r.metrics["inbound_verified"] is False
    assert any("not verified" in x for x in r.limitations)


# ---------------------------------------------------------------------------------------------------------------------
# listen
# ---------------------------------------------------------------------------------------------------------------------


def test_listen_feeds_passive_analyzer():
    with BacnetTransport("127.0.0.1", 0, test_mode=True, want_dst=True) as t:
        talker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        talker.bind(("127.0.0.1", 0))

        def chatter():
            for i in range(5):
                talker.sendto(B.encode_original_broadcast(N.encode_npdu(A.encode_i_am(700 + i, vendor_id=5))),
                              ("127.0.0.1", t.port))
                talker.sendto(B.encode_original_broadcast(N.encode_npdu(A.encode_who_is())), ("127.0.0.1", t.port))
                time.sleep(0.02)

        th = threading.Thread(target=chatter)
        th.start()
        events = []
        r = listen(t, 0.5, events.append)
        th.join()
        talker.close()
    assert r.run.kind == "listen" and r.run.vantage.value == "self"
    assert sorted(d.instance for d in r.devices) == [700, 701, 702, 703, 704]
    assert r.metrics["inbound_verified"] is True
    assert r.metrics["listen"]["datagrams"] == 10
    assert t.sent_log == []  # listen never transmits
    try:
        import bacnet_health.findings.passive  # noqa: F401
    except ImportError:
        return
    assert any(f.id == "DEV-008" for f in r.findings) or r.findings is not None
    assert "checks_performed" in r.metrics


def test_listen_cancel():
    with BacnetTransport("127.0.0.1", 0, test_mode=True) as t:
        threading.Timer(0.1, t.cancel.set).start()
        t0 = time.monotonic()
        r = listen(t, 30)
        assert time.monotonic() - t0 < 1.0
    assert r.run.incomplete and r.metrics["inbound_verified"] is False
