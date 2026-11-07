"""Unit tests for the active side that need no sockets: rate limiter, interface ranking, budget plan, Who-Is chunking
(with a fake clock and a fake transport), RPM splitting, topology simulation and active findings."""

from __future__ import annotations

import threading

import pytest

from bacnet_health.active.iface import auto_pick, iface_from_cidr
from bacnet_health.active.scan import (
    READ_PROPERTIES,
    WHOIS_HIGH,
    Scanner,
    ScanOptions,
    ScanRefused,
    WhoisChunker,
    split_rpm,
)
from bacnet_health.active.transport import RateLimiter, Received, SentFrame
from bacnet_health.findings.active import active_not_performed, evaluate_active
from bacnet_health.model import Bbmd, BdtEntry, Budget, Device, FdtEntry, Result, RunInfo
from bacnet_health.topology import build_topology
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.message import decode_message
from bacnet_health.wire.txguard import check_tx


class FakeClock:
    def __init__(self, t: float = 1000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


# ---------------------------------------------------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------------------------------------------------


def test_rate_limiter_spacing_with_fake_clock():
    clk = FakeClock()
    rl = RateLimiter(5.0, 1.0, clk)
    assert rl.try_acquire()
    assert not rl.try_acquire()
    assert rl.wait_time() == pytest.approx(0.2)
    clk.t += 0.1
    assert not rl.try_acquire()
    clk.t += 0.1
    assert rl.try_acquire()
    # tokens never accumulate beyond capacity 1, even after a long idle period
    clk.t += 100
    assert rl.try_acquire() and not rl.try_acquire()


def test_rate_limiter_rejects_nonpositive_rate():
    with pytest.raises(ValueError):
        RateLimiter(0)


# ---------------------------------------------------------------------------------------------------------------------
# Interface ranking
# ---------------------------------------------------------------------------------------------------------------------


def _if(name, cidr, **kw):
    i = iface_from_cidr(cidr, name)
    for k, v in kw.items():
        setattr(i, k, v)
    return i


def test_auto_pick_prefers_wired_private_no_default_route():
    ifaces = [
        _if("lo0", "127.0.0.1/8", is_loopback=True),
        _if("en0", "192.168.1.20/24", wireless_guess=True, has_default_route=True),
        _if("en5", "10.20.30.40/24"),
        _if("utun3", "100.100.1.2/32"),
        _if("en7", "169.254.10.10/16"),
    ]
    best, ranked, reasons = auto_pick(ifaces)
    assert best.name == "en5"
    assert all(not i.is_loopback for i in ranked)
    assert ranked[0].name == "en5"
    text = " ".join(reasons)
    assert "10.20.30.255" in text and "255.255.255.255" in text
    assert "utun3" in text and "en7" in text  # explained as not considered


def test_auto_pick_never_loopback_tunnel_or_link_local():
    best, ranked, reasons = auto_pick([
        _if("lo0", "127.0.0.1/8", is_loopback=True),
        _if("utun1", "10.8.0.2/24"),
        _if("en9", "169.254.1.1/16"),
        _if("Ethernet 3", "10.1.1.5/24", if_type=53, description="Wintun Userspace Tunnel"),
    ])
    assert best is None
    assert any("No usable interface" in r for r in reasons)


def test_auto_pick_wifi_only_warns():
    best, _, reasons = auto_pick([_if("en0", "192.168.1.20/24", wireless_guess=True, has_default_route=True)])
    assert best.name == "en0"
    assert any(r.startswith("Warning") for r in reasons)


def test_auto_pick_down_interface_not_picked():
    best, _, _ = auto_pick([_if("en5", "10.0.0.5/24", is_up=False), _if("en6", "10.0.1.5/24")])
    assert best.name == "en6"


# ---------------------------------------------------------------------------------------------------------------------
# Who-Is chunking (pure)
# ---------------------------------------------------------------------------------------------------------------------


def test_chunker_rules():
    c = WhoisChunker(0, WHOIS_HIGH, 1024)
    assert c.next_range() == (0, 1023)
    c.record(100)  # > 64: shrink 4x
    assert c.next_range() == (1024, 1024 + 256 - 1)
    c.record(40)  # > 32: shrink 2x
    assert c.next_range() == (1280, 1280 + 128 - 1)
    c.record(10)  # 8..32: unchanged
    assert c.next_range() == (1408, 1408 + 128 - 1)
    c.record(0)  # < 8: grow 2x
    assert c.next_range()[1] - c.next_range()[0] + 1 == 256


def test_chunker_bounds_and_coverage():
    c = WhoisChunker(0, WHOIS_HIGH, 1024, minimum=16, maximum=262_144)
    ranges = []
    n = 0
    while (r := c.next_range()) is not None:
        ranges.append(r)
        n += 1
        c.record(1000 if n < 10 else 0)
        assert 16 <= c.chunk <= 262_144
    assert ranges[0][0] == 0 and ranges[-1][1] == WHOIS_HIGH  # the wildcard 4194303 is never in a range
    for a, b in zip(ranges, ranges[1:]):
        assert b[0] == a[1] + 1


def test_sparse_plan_length():
    plan = WhoisChunker.sparse_plan(0, WHOIS_HIGH, 1024, 16, 262_144)
    # 1024 .. 131072 (8 doublings) then 262144-sized chunks up to 4194302
    assert len(plan) == 24
    assert plan[-1][1] == WHOIS_HIGH


def test_split_rpm_respects_max_apdu():
    assert len(split_rpm(READ_PROPERTIES, 1476)) == 1
    small = split_rpm(READ_PROPERTIES, 206)
    assert len(small) > 2
    assert [p for b in small for p in b] == READ_PROPERTIES


# ---------------------------------------------------------------------------------------------------------------------
# Fake transport: drives the scanner on a fake clock
# ---------------------------------------------------------------------------------------------------------------------


class FakeTransport:
    """Same interface the Scanner uses. Who-Is broadcasts produce I-Ams from ``instances``; recv advances the clock."""

    def __init__(self, instances, clock: FakeClock, rate: float = 5.0):
        self.instances = sorted(instances)
        self.clock = clock
        self.wall = clock
        self.budget = Budget()
        self.cancel = threading.Event()
        self.port = 47808
        self.sent_log: list[SentFrame] = []
        self.stats: dict = {}
        self.own_addrs = {("192.0.2.5", 47808)}
        self.limiter = RateLimiter(rate, 1.0, clock)
        self.inbox: list[tuple[float, bytes, tuple[str, int]]] = []
        self.inbound_verified = False

    def ready_in(self):
        return self.limiter.wait_time()

    def allow_source(self, ip):
        pass

    def _send(self, frame, dst):
        check_tx(frame)
        assert self.limiter.try_acquire(), "scanner sent faster than the rate limiter allows"
        kind = decode_message(frame).kind
        self.budget.frames_sent += 1
        if kind == "who-is":
            self.budget.whois_sent += 1
        self.sent_log.append(SentFrame(self.clock(), self.clock(), dst, kind, len(frame), "x", frame))
        msg = decode_message(frame)
        if kind == "who-is":
            lo, hi = msg.decoded
            for i, inst in enumerate(x for x in self.instances if lo <= x <= hi):
                iam = B.encode_original_broadcast(N.encode_npdu(A.encode_i_am(inst, vendor_id=7)))
                self.inbox.append((self.clock() + 0.01 + i * 0.001, iam, (f"192.0.2.{10 + inst % 200}", 47808)))
        return True

    def send_broadcast(self, frame, port=None):
        return self._send(frame, "broadcast 192.0.2.255:47808")

    def send_unicast(self, frame, addr):
        return self._send(frame, f"{addr[0]}:{addr[1]}")

    def recv_datagram(self, timeout):
        self.inbox.sort(key=lambda x: x[0])
        if self.inbox and self.inbox[0][0] <= self.clock() + timeout:
            ts, data, src = self.inbox.pop(0)
            self.clock.t = max(self.clock.t, ts)
            self.inbound_verified = True
            return Received(data, src, None, ts)
        self.clock.t += timeout
        return None


def _fake_scan(instances, **kw):
    clk = FakeClock()
    t = FakeTransport(instances, clk)
    opts = ScanOptions(read_properties=False, bbmd_audit=False, whois_window_s=3.0, whois_gap_s=1.0, **kw)
    s = Scanner(t, opts)
    s.plan()
    return s, t, s.run()


def test_whois_adapts_on_dense_network_with_fake_clock():
    # 100 devices in 0..99 make the first window dense, the rest of the space is empty
    s, t, r = _fake_scan(range(100), whois_high=20_000)
    sent = r.metrics["whois_chunks"]["sent"]
    assert sent[0]["low"] == 0 and sent[0]["high"] == 1023 and sent[0]["replies"] == 100
    assert sent[1]["high"] - sent[1]["low"] + 1 == 256  # shrunk 4x after > 64 replies
    assert sent[2]["high"] - sent[2]["low"] + 1 == 512  # sparse again: grows
    for a, b in zip(sent, sent[1:]):
        assert b["low"] == a["high"] + 1
    whois = [f for f in t.sent_log if f.kind == "who-is"]
    for a, b in zip(whois, whois[1:]):
        assert b.mono - a.mono >= 3.0 - 1e-9  # window (3 s) >= gap (1 s)
    assert len(r.devices) == 100
    assert r.budget.whois_sent == len(sent)
    # no global Who-Is ever
    assert all(decode_message(f.data).decoded is not None for f in whois)


def test_late_iam_is_kept_and_attributed():
    clk = FakeClock()
    t = FakeTransport([], clk)
    s = Scanner(t, ScanOptions(read_properties=False, bbmd_audit=False, whois_window_s=1.0, whois_gap_s=1.0,
                               whois_high=3000, settle_s=5.0))
    s.plan()
    late = B.encode_original_broadcast(N.encode_npdu(A.encode_i_am(500, vendor_id=7)))
    t.inbox.append((clk.t + 2.5, late, ("192.0.2.77", 47808)))  # chunk 0..1023's window closes at +1 s
    r = s.run()
    assert [d.instance for d in r.devices] == [500]
    sent = r.metrics["whois_chunks"]["sent"]
    assert sent[0]["replies"] == 0 and sent[0]["late_replies"] == 1


def test_budget_exceeded_stops_unless_approved():
    clk = FakeClock()
    t = FakeTransport(range(300), clk)
    events = []
    s = Scanner(t, ScanOptions(read_properties=False, bbmd_audit=False, whois_high=WHOIS_HIGH),
                progress=events.append)
    s.plan()
    s.budget.whois_planned = 2  # pretend the preview promised 2 Who-Is
    r = s.run()
    assert r.run.incomplete
    assert r.budget.whois_sent == 2
    assert any(e["type"] == "budget-exceeded" for e in events)
    assert any("budget" in n for n in r.budget.notes)

    clk2 = FakeClock()
    t2 = FakeTransport(range(3), clk2)
    s2 = Scanner(t2, ScanOptions(read_properties=False, bbmd_audit=False, whois_high=10_000),
                 on_budget_exceeded=lambda info: True)
    s2.plan()
    s2.budget.whois_planned = 1
    r2 = s2.run()
    assert not r2.run.incomplete and r2.budget.whois_sent > 1


def test_plan_budget_preview():
    clk = FakeClock()
    t = FakeTransport([], clk)
    s = Scanner(t, ScanOptions(targets=["192.0.2.50", "192.0.2.51:47809"], expected_devices=10,
                               bbmd_candidates=["192.0.2.1"]))
    b = s.plan()
    assert b.whois_planned == 24 + 2
    assert b.reads_planned == 2 * 2 + 17 * 10
    assert b.bvlc_probes_planned == 10 + 1
    assert b.peak_pps_planned == 5.0
    assert b.est_duration_s > 24 * 3
    assert any("Who-Is plan" in n for n in b.notes)
    assert t.sent_log == []  # planning sends nothing

    s4 = Scanner(FakeTransport([], FakeClock()), ScanOptions(local_bbmd_known=True))
    assert s4.plan().whois_planned > 24  # F2: 4x smaller chunks


def test_fdr_requires_typed_confirmation():
    t = FakeTransport([], FakeClock())
    with pytest.raises(ScanRefused):
        Scanner(t, ScanOptions(fdr_bbmd="192.0.2.1"))
    with pytest.raises(ScanRefused):
        Scanner(t, ScanOptions(fdr_bbmd="192.0.2.1", fdr_confirmed_ip="192.0.2.2"))
    s = Scanner(t, ScanOptions(fdr_bbmd="192.0.2.1", fdr_confirmed_ip="192.0.2.1"))
    assert s.plan().bvlc_probes_planned >= 1
    assert t.sent_log == []


# ---------------------------------------------------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------------------------------------------------

ONE = "255.255.255.255"


def _b(ip, entries, source="probe", fdt=None):
    return Bbmd(ip=ip, port=47808, status="bbmd", source=source,
                bdt=[BdtEntry(e, 47808, m) for e, m in entries], fdt=fdt, fdt_status="ack" if fdt else None)


def test_topology_healthy_one_hop():
    a = _b("192.0.2.1", [("192.0.2.1", ONE), ("198.51.100.1", ONE)])
    b = _b("198.51.100.1", [("192.0.2.1", ONE), ("198.51.100.1", ONE)], source="bdt-peer")
    topo = build_topology([a, b], "192.0.2.0/24")
    assert topo["broadcast_copies"] == {"192.0.2.0/24": 1, "subnet of 198.51.100.1": 1}
    assert all(v == 1 for row in topo["broadcast_matrix"].values() for v in row.values())


def test_topology_duplicate_and_two_hop():
    # two BBMDs on the local subnet both forward to the same peer -> the peer subnet gets 2 copies
    a = _b("192.0.2.1", [("192.0.2.1", ONE), ("198.51.100.1", "255.255.255.0")])
    c = _b("192.0.2.2", [("192.0.2.2", ONE), ("198.51.100.1", "255.255.255.0")])
    topo = build_topology([a, c], "192.0.2.0/24")
    assert topo["broadcast_copies"]["198.51.100.0/24"] == 2
    assert topo["broadcast_copies"]["192.0.2.0/24"] == 1
    assert "198.51.100.1:47808" in " ".join(topo["notes"])  # peer not read


# ---------------------------------------------------------------------------------------------------------------------
# Active findings
# ---------------------------------------------------------------------------------------------------------------------


def _result(devices=(), bbmds=(), steps=("discovery", "device-reads", "bbmd-audit"), stats=None, subnet=None):
    r = Result(run=RunInfo(kind="scan"))
    r.devices, r.bbmds = list(devices), list(bbmds)
    r.metrics = {"scan_steps": list(steps), "scan_stats": stats or {}}
    r.topology = build_topology(r.bbmds, subnet)
    return r


def _ids(findings):
    return {f.id for f in findings}


def test_dev001_downgraded_when_same_identity():
    p = {"object-name": "AHU-1", "model-name": "X"}
    devs = [Device(5, "192.0.2.10", 47808, vendor_id=1, properties=dict(p)),
            Device(5, "192.0.2.11", 47808, vendor_id=1, properties=dict(p))]
    f = [x for x in evaluate_active(_result(devs)) if x.id == "DEV-001"][0]
    assert f.severity.value == "info"
    devs[1].properties["object-name"] = "AHU-2"
    f = [x for x in evaluate_active(_result(devs)) if x.id == "DEV-001"][0]
    assert f.severity.value == "high" and "192.0.2.10:47808" in f.explanation


def test_dev006_needs_ntp_and_threshold():
    d = Device(9, "192.0.2.10", 47808, properties={"object-name": "x"})
    stats = {f"9@{d.address_key}": {"clock": {"skew_s": 7200.0, "device_local": "a", "host_local": "b",
                                              "host_ts": 1.0}}}
    r = _result([d], stats=stats)
    assert "DEV-006" not in _ids(evaluate_active(r, stats, host_ntp_synced=False))
    assert any(x["id"] == "DEV-006" for x in active_not_performed(r, False))
    f = [x for x in evaluate_active(r, stats, host_ntp_synced=True) if x.id == "DEV-006"][0]
    assert f.severity.value == "medium" and "ahead" in f.explanation
    stats[f"9@{d.address_key}"]["clock"]["skew_s"] = 60.0
    assert "DEV-006" not in _ids(evaluate_active(r, stats, host_ntp_synced=True))


def test_bbmd_findings_from_tables():
    a = _b("192.0.2.1", [("192.0.2.1", ONE), ("198.51.100.1", ONE), ("203.0.113.9", "255.255.255.0")],
           fdt=[FdtEntry("203.0.113.50", 47808, 7200, 100), FdtEntry("10.0.0.5", 47808, 60, 30)])
    b = _b("198.51.100.1", [("198.51.100.1", ONE)], source="bdt-peer")
    c = _b("192.0.2.2", [("198.51.100.1", ONE)])  # second local BBMD, overlapping peer, missing itself
    r = _result(bbmds=[a, b, c], subnet="192.0.2.0/24")
    f = evaluate_active(r, treat_as_public=["203.0.113.0/24"])
    ids = _ids(f)
    assert {"BBMD-001", "BBMD-002", "BBMD-003", "BBMD-004", "BBMD-005", "BBMD-006", "BBMD-007", "BBMD-008",
            "SEC-004"} <= ids
    b6 = [x for x in f if x.id == "BBMD-006"]
    assert len(b6) == 1 and "203.0.113.50" in b6[0].explanation and b6[0].severity.value == "critical"
    # without the lab override, documentation ranges are private: no BBMD-006
    assert "BBMD-006" not in _ids(evaluate_active(r))


def test_not_performed_without_bbmd_audit():
    r = _result(steps=("discovery",))
    np = {x["id"] for x in active_not_performed(r, True)}
    assert {"BBMD-001", "BBMD-008", "DEV-005"} <= np
    assert not any(f.id.startswith("BBMD") for f in evaluate_active(r))


def test_preflight_refuses_before_sending_when_egress_differs():
    from bacnet_health.active.iface import EgressMismatch

    t = FakeTransport([], FakeClock())

    def verify(ip):
        if ip == "198.51.100.7":
            raise EgressMismatch("Traffic to 198.51.100.7 would leave via utun3 (VPN/tunnel), not en5.")

    t.verify_egress = verify
    s = Scanner(t, ScanOptions(targets=["192.0.2.50", "198.51.100.7"]))
    with pytest.raises(EgressMismatch, match="utun3"):
        s.run()
    assert t.sent_log == []
