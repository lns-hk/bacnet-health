"""Active scan: adaptive Who-Is discovery, unicast targets, device property reads, BBMD audit (design §1.2, §3).

The scanner is a single-threaded event loop on top of :class:`~bacnet_health.active.transport.BacnetTransport`. The
transport enforces the allow-list, the global rate limit and the kill switch for every frame; the scanner adds the
per-category rules of design §1.2:

* Who-Is: ranged only (never global), adaptive chunks (§3.2), at least ``whois_gap_s`` apart;
* confirmed requests: one in flight per device, ``apdu_timeout_s`` / ``apdu_retries``, a device that fails twice is
  marked unresponsive and not asked again;
* routed (remote) devices are read only with ``read_remote``: one request in flight per DNET, at most
  ``remote_rate_per_s`` per DNET, and the DNET is abandoned after 2 consecutive timeouts;
* Read-BDT / Read-FDT: once per target, at most ``bvlc_rate_per_s``, no retry;
* budget: if a category would exceed its preview by more than ``budget_tolerance`` the run stops unless
  ``on_budget_exceeded`` returns True.

Per-device reads are written as small generators that yield requests and receive responses; the loop interleaves
them under the rate limits.
"""

from __future__ import annotations

import ipaddress
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Generator, Iterable

from bacnet_health.active.iface import EgressMismatch
from bacnet_health.active.transport import BacnetTransport, RateLimiter
from bacnet_health.model import Bbmd, Budget, Device, Result, RunInfo, Vantage, utcnow_iso
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.constants import (
    MAX_INSTANCE,
    AbortReason,
    BvlcFunction as BF,
    BvlcResult,
    ConfirmedService as CS,
    DeviceStatus,
    ErrorClass,
    ErrorCode,
    ObjectType,
    PduType,
    PropertyId as P,
    RejectReason,
    Segmentation,
    name_of,
)
from bacnet_health.wire.message import BacnetMessage, decode_message

__all__ = ["ScanOptions", "Scanner", "WhoisChunker", "ScanRefused", "READ_PROPERTIES"]

WHOIS_HIGH = MAX_INSTANCE - 1  # 4194302; 4194303 is the wildcard and never part of a range
OUR_MAX_APDU = 1476
STANDARD_PORT = 47808

# Design §3.3, in order. (property, array index)
READ_PROPERTIES: list[tuple[int, int | None]] = [
    (P.OBJECT_NAME, None), (P.VENDOR_NAME, None), (P.MODEL_NAME, None), (P.FIRMWARE_REVISION, None),
    (P.APPLICATION_SOFTWARE_VERSION, None), (P.PROTOCOL_VERSION, None), (P.PROTOCOL_REVISION, None),
    (P.LOCATION, None), (P.DESCRIPTION, None), (P.SYSTEM_STATUS, None), (P.LOCAL_DATE, None), (P.LOCAL_TIME, None),
    (P.UTC_OFFSET, None), (P.DATABASE_REVISION, None), (P.MAX_SEGMENTS_ACCEPTED, None), (P.OBJECT_LIST, 0),
]
# Read only for devices found by unicast RP (no I-Am, so these were not "free").
IDENTITY_PROPERTIES: list[tuple[int, int | None]] = [
    (P.VENDOR_IDENTIFIER, None), (P.MAX_APDU_LENGTH_ACCEPTED, None), (P.SEGMENTATION_SUPPORTED, None),
]
_STRING_PROPS = {P.OBJECT_NAME, P.VENDOR_NAME, P.MODEL_NAME, P.FIRMWARE_REVISION, P.APPLICATION_SOFTWARE_VERSION,
                 P.LOCATION, P.DESCRIPTION}
_PER_DEVICE_READS = 1 + len(READ_PROPERTIES)  # worst case: protocol-services-supported + one RP per property


class ScanRefused(ValueError):
    """The requested scan is not allowed (e.g. FDR without the typed confirmation). Nothing was sent."""


@dataclass
class ScanOptions:
    # network
    port: int = STANDARD_PORT
    interface: str | None = None
    local_ip: str | None = None
    netmask: str | None = None
    broadcast: str | None = None
    subnet: str | None = None  # CIDR of the local subnet, e.g. "192.0.2.0/24"
    targets: list[str] = field(default_factory=list)  # "ip" or "ip:port"
    # rate limits and timeouts (design §1.2, [PROVISIONAL])
    whois_gap_s: float = 1.0
    max_req_per_s: float = 5.0
    apdu_timeout_s: float = 3.0
    apdu_retries: int = 1
    bvlc_rate_per_s: float = 2.0
    remote_rate_per_s: float = 1.0
    # what to do
    discovery: bool = True
    read_properties: bool = True
    bbmd_audit: bool = True
    read_remote: bool = False
    follow_bdt: bool = False
    fdr_bbmd: str | None = None  # "ip" or "ip:port"
    fdr_confirmed_ip: str | None = None  # the IP the user typed; must equal fdr_bbmd
    fdr_ttl_s: int = 60
    bbmd_candidates: list[str] = field(default_factory=list)  # user-given BBMD addresses
    passive_bbmd_candidates: list[str] = field(default_factory=list)  # from an earlier listen/pcap
    # Who-Is chunking (design §3.2, [PROVISIONAL])
    whois_window_s: float = 3.0
    whois_initial_chunk: int = 1024
    whois_min_chunk: int = 16
    whois_max_chunk: int = 262_144
    whois_low: int = 0
    whois_high: int = WHOIS_HIGH
    local_bbmd_known: bool = False  # F2: a local BBMD may forward our Who-Is; chunk sizes drop 4x
    settle_s: float | None = None  # wait for late I-Ams after the last Who-Is (default: one window)
    # budget and run control
    expected_devices: int | None = None
    budget_tolerance: float = 0.2
    max_parallel_devices: int = 16
    # reporting
    host_ntp_synced: bool | None = None
    confirmations: list[dict[str, Any]] = field(default_factory=list)
    evaluate: bool = True  # fill topology + findings in run()
    public_ranges: list[str] = field(default_factory=list)  # extra ranges treated as public (tests / lab)

    @classmethod
    def from_profile(cls, profile: Any, iface: Any = None, **overrides: Any) -> "ScanOptions":
        """Build options from a :class:`bacnet_health.profile.Profile` and an optional selected Iface."""
        o = cls(
            port=profile.port, targets=list(profile.targets), whois_gap_s=profile.whois_gap_s,
            max_req_per_s=profile.max_req_per_s, apdu_timeout_s=profile.apdu_timeout_s,
            apdu_retries=profile.apdu_retries, discovery=profile.do_scan, read_properties=profile.read_properties,
            bbmd_audit=profile.bbmd_audit, read_remote=profile.read_remote, follow_bdt=profile.follow_bdt,
            fdr_bbmd=profile.fdr_bbmd,
        )
        if iface is not None:
            o.interface, o.local_ip, o.netmask = iface.name, iface.ip, iface.netmask
            o.broadcast, o.subnet = iface.broadcast, iface.network
        for k, v in overrides.items():
            setattr(o, k, v)
        return o


# ---------------------------------------------------------------------------------------------------------------------
# Who-Is chunking (pure; unit-tested without sockets)
# ---------------------------------------------------------------------------------------------------------------------


class WhoisChunker:
    """Adaptive instance-range segmentation, exactly as design §3.2."""

    def __init__(self, low: int = 0, high: int = WHOIS_HIGH, initial: int = 1024, minimum: int = 16,
                 maximum: int = 262_144) -> None:
        if not 0 <= low <= high <= WHOIS_HIGH:
            raise ValueError("Who-Is range out of bounds")
        self.low, self.high = low, high
        self.minimum, self.maximum = max(1, minimum), max(minimum, maximum)
        self.chunk = max(self.minimum, min(initial, self.maximum))
        self.cursor = low
        self._current: tuple[int, int] | None = None

    def next_range(self) -> tuple[int, int] | None:
        if self.cursor > self.high:
            return None
        self._current = (self.cursor, min(self.cursor + self.chunk - 1, self.high))
        return self._current

    def record(self, replies: int) -> None:
        """Record the I-Am count of the window for the range just sent and adapt the next chunk size."""
        assert self._current is not None, "record() without next_range()"
        used = self.chunk
        if replies > 64:
            self.chunk = max(self.chunk // 4, self.minimum)
        elif replies > 32:
            self.chunk = max(self.chunk // 2, self.minimum)
        elif replies < 8:
            self.chunk = min(self.chunk * 2, self.maximum)
        self.cursor += used
        self._current = None

    @classmethod
    def sparse_plan(cls, low: int, high: int, initial: int, minimum: int, maximum: int) -> list[tuple[int, int]]:
        """The chunk sequence if every window is sparse (< 8 replies): the budget preview's plan."""
        c = cls(low, high, initial, minimum, maximum)
        out = []
        while (r := c.next_range()) is not None:
            out.append(r)
            c.record(0)
        return out


# ---------------------------------------------------------------------------------------------------------------------
# Requests, responses, jobs
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class _Req:
    kind: str  # "rp" | "rpm" | "whois-unicast"
    addr: tuple[str, int]
    instance: int = MAX_INSTANCE
    props: list[tuple[int, int | None]] = field(default_factory=list)
    dnet: int | None = None
    dadr: bytes | None = None


@dataclass
class _Resp:
    status: str  # "ack" | "error" | "reject" | "abort" | "timeout" | "segmented" | "iam" | "no-iam"
    value: Any = None
    sent: float | None = None  # wall clock of the last attempt
    received: float | None = None


@dataclass
class _Job:
    key: str
    gen: Generator[_Req, _Resp, None]
    dnet: int | None = None
    req: _Req | None = None
    tries: int = 0
    invoke_id: int | None = None
    deadline: float = 0.0  # monotonic
    in_flight: bool = False
    sent_wall: float | None = None


def _parse_addr(s: str, default_port: int) -> tuple[str, int]:
    s = s.strip()
    if ":" in s:
        ip, port = s.rsplit(":", 1)
        return str(ipaddress.IPv4Address(ip)), int(port)
    return str(ipaddress.IPv4Address(s)), default_port


def _dev_key(d: Device) -> str:
    return f"{d.instance}@{d.address_key}"


def _date_str(v: Any) -> str | None:
    if not isinstance(v, dict):
        return None
    y, m, d = v.get("year"), v.get("month"), v.get("day")
    return f"{y if y is not None else '????'}-{m if m is not None else 0:02d}-{d if d is not None else 0:02d}"


def _time_str(v: Any) -> str | None:
    if not isinstance(v, dict):
        return None
    parts = [v.get(k) for k in ("hour", "minute", "second", "hundredths")]
    if any(p is None for p in parts[:3]):
        return None
    return f"{parts[0]:02d}:{parts[1]:02d}:{parts[2]:02d}.{(parts[3] or 0):02d}"


def property_name(pid: int, index: int | None) -> str:
    name = name_of(P, pid)
    return f"{name}[{index}]" if index is not None else name


def _display_value(pid: int, value: Any) -> Any:
    """Turn decoded values into readable JSON values (enumerations by name, dates as strings)."""
    if pid == P.SYSTEM_STATUS and isinstance(value, int):
        return name_of(DeviceStatus, value)
    if pid == P.SEGMENTATION_SUPPORTED and isinstance(value, int):
        return name_of(Segmentation, value)
    if pid == P.PROTOCOL_SERVICES_SUPPORTED and isinstance(value, list):
        return [i for i, bit in enumerate(value) if bit is True]  # BACnetServicesSupported bit numbers
    if pid == P.LOCAL_DATE:
        return _date_str(value) or value
    if pid == P.LOCAL_TIME:
        return _time_str(value) or value
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).hex()
    return value


def _estimate_ack_size(props: Iterable[tuple[int, int | None]]) -> int:
    size = 3 + 5 + 2  # ComplexACK header, object id, opening/closing [1]
    for pid, idx in props:
        size += 3 + 2 + (2 if idx is not None else 0) + (64 if pid in _STRING_PROPS else 8)
    return size


def split_rpm(props: list[tuple[int, int | None]], max_apdu: int) -> list[list[tuple[int, int | None]]]:
    """Split a property list into RPM batches whose estimated ACK fits ``max_apdu`` (no segmentation, ever)."""
    batches: list[list[tuple[int, int | None]]] = []
    cur: list[tuple[int, int | None]] = []
    for p in props:
        if cur and _estimate_ack_size(cur + [p]) > max_apdu:
            batches.append(cur)
            cur = []
        cur.append(p)
    if cur:
        batches.append(cur)
    return batches


# ---------------------------------------------------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------------------------------------------------


class Scanner:
    def __init__(
        self,
        transport: BacnetTransport,
        options: ScanOptions,
        progress: Callable[[dict[str, Any]], None] | None = None,
        cancel: threading.Event | None = None,
        on_budget_exceeded: Callable[[dict[str, Any]], bool] | None = None,
    ) -> None:
        self.t = transport
        self.o = options
        self.progress = progress or (lambda ev: None)
        self.cancel = cancel or transport.cancel
        self.on_budget_exceeded = on_budget_exceeded or (lambda info: False)
        self.clock: Callable[[], float] = getattr(transport, "clock", time.monotonic)
        self.wall: Callable[[], float] = getattr(transport, "wall", time.time)
        self.budget: Budget = transport.budget
        self.fdr_addr: tuple[str, int] | None = None
        if options.fdr_bbmd:
            self.fdr_addr = _parse_addr(options.fdr_bbmd, options.port)
            confirmed = (options.fdr_confirmed_ip or "").strip()
            if confirmed != self.fdr_addr[0] and confirmed != options.fdr_bbmd.strip():
                raise ScanRefused(
                    f"Foreign-device registration with {self.fdr_addr[0]} needs the BBMD address typed in as "
                    "confirmation. It was not confirmed, so the scan was not started."
                )
        self.targets = [_parse_addr(t, options.port) for t in options.targets]
        self.devices: dict[str, Device] = {}
        self.scan_stats: dict[str, dict[str, Any]] = {}
        self.whois_chunks: list[dict[str, Any]] = []
        self.target_results: dict[str, dict[str, Any]] = {}
        self.bbmds: dict[tuple[str, int], Bbmd] = {}
        self.fdr_log: list[dict[str, Any]] = []
        self.limitations: list[str] = []
        self.unsolicited = Counter()
        self._stop_reason: str | None = None
        self._approved: set[str] = set()
        self._pending_bvlc: dict[tuple[tuple[str, int], str], dict[str, Any]] = {}
        self._jobs_by_match: dict[tuple, _Job] = {}
        self._whois_waits: dict[str, _Job] = {}
        self._invoke = 0
        self._dnet_limiters: dict[int, RateLimiter] = {}
        self._dnet_timeouts: Counter = Counter()
        self._dnet_aborted: set[int] = set()
        self._bvlc_limiter = RateLimiter(options.bvlc_rate_per_s, 1.0, self.clock)
        self._last_whois: float | None = None
        self._fdr_registered_at: float | None = None
        self._started_wall = self.wall()
        self._planned = False
        self._chunk_plan: list[tuple[int, int]] = []

    # ================================================================== budget
    def _chunk_params(self) -> tuple[int, int, int]:
        o = self.o
        div = 4 if o.local_bbmd_known else 1
        return max(o.whois_min_chunk, o.whois_initial_chunk // div), o.whois_min_chunk, max(
            o.whois_min_chunk, o.whois_max_chunk // div)

    def plan(self) -> Budget:
        """Budget preview (design §1.2). Read and BBMD counts are estimates until discovery has finished."""
        o = self.o
        init, mn, mx = self._chunk_params()
        chunks = (WhoisChunker.sparse_plan(o.whois_low, o.whois_high, init, mn, mx) if o.discovery else [])
        n_dev = o.expected_devices or 0
        b = self.budget
        b.whois_planned = len(chunks) + len(self.targets)  # + one unicast Who-Is fallback per target
        b.reads_planned = len(self.targets) * (1 + max(0, o.apdu_retries)) + (_PER_DEVICE_READS * n_dev if o.read_properties else 0)
        n_cand = len(set(o.bbmd_candidates) | set(o.passive_bbmd_candidates))
        b.bvlc_probes_planned = (n_dev + n_cand) if o.bbmd_audit else 0
        if self.fdr_addr:
            b.bvlc_probes_planned += self._fdr_registrations_planned(len(chunks))
        b.peak_pps_planned = float(o.max_req_per_s)
        window = max(o.whois_window_s, o.whois_gap_s)
        b.est_duration_s = round(
            len(chunks) * window + (o.settle_s if o.settle_s is not None else o.whois_window_s)
            + len(self.targets) * (o.apdu_timeout_s + o.whois_window_s)
            + b.reads_planned / max(o.max_req_per_s, 0.1)
            + b.bvlc_probes_planned / max(o.bvlc_rate_per_s, 0.1) + o.apdu_timeout_s, 1)
        b.notes = [
            f"Who-Is plan: {len(chunks)} ranged Who-Is covering instances {o.whois_low}-{o.whois_high}, starting "
            f"with {init} instances per request, at least {max(o.whois_gap_s, o.whois_window_s):g} s apart. "
            "Chunks shrink automatically on dense networks.",
            f"Expected I-Am replies: at most {init} for the first request (bounded by the chunk size).",
            f"Reads: up to {_PER_DEVICE_READS} requests per device"
            + (f" x {n_dev} expected devices" if n_dev else "; the total is known after discovery") + ".",
            f"Rate limits: <= {o.max_req_per_s:g} frames/s overall, 1 request in flight per device, timeout "
            f"{o.apdu_timeout_s:g} s, {o.apdu_retries} retry; BVLC probes <= {o.bvlc_rate_per_s:g}/s, no retry.",
        ]
        if o.local_bbmd_known:
            b.notes.append("A BBMD is known on this subnet: Who-Is chunks are 4x smaller because broadcasts may be "
                           "forwarded to other subnets.")
        if self.fdr_addr:
            b.notes.append(f"Foreign-device mode via {self.fdr_addr[0]}:{self.fdr_addr[1]} (TTL {o.fdr_ttl_s} s): "
                           "Who-Is is distributed by that BBMD to every subnet it serves.")
        self._chunk_plan = chunks
        self._planned = True
        return b

    def _fdr_registrations_planned(self, n_chunks: int) -> int:
        dur = n_chunks * max(self.o.whois_window_s, self.o.whois_gap_s)
        return 1 + int(dur // max(self.o.fdr_ttl_s, 1))

    def _replan(self, reads: int | None = None, bvlc: int | None = None, why: str = "") -> None:
        b = self.budget
        if reads is not None and reads > b.reads_planned:
            b.reads_planned = reads
        if bvlc is not None and bvlc > b.bvlc_probes_planned:
            b.bvlc_probes_planned = bvlc
        if why:
            b.notes.append(why)
        self.progress({"type": "budget-update", "budget": {
            "whois_planned": b.whois_planned, "reads_planned": b.reads_planned,
            "bvlc_probes_planned": b.bvlc_probes_planned}})

    def _budget_ok(self, category: str) -> bool:
        """False if sending one more frame of ``category`` exceeds the preview by > tolerance and nobody approved."""
        if category in self._approved:
            return True
        b = self.budget
        planned, sent = {
            "whois": (b.whois_planned, b.whois_sent),
            "read": (b.reads_planned, b.reads_sent),
            "bvlc": (b.bvlc_probes_planned, b.bvlc_probes_sent),
        }[category]
        if sent + 1 <= planned * (1.0 + self.o.budget_tolerance):
            return True
        info = {"type": "budget-exceeded", "category": category, "planned": planned, "sent": sent,
                "tolerance": self.o.budget_tolerance}
        self.progress(info)
        if self.on_budget_exceeded(info):
            self._approved.add(category)
            b.notes.append(f"{category} budget exceeded ({sent} sent, {planned} planned); the user chose to continue.")
            return True
        self._stop(f"stopped: {category} traffic would exceed the budget preview by more than "
                   f"{self.o.budget_tolerance:.0%} ({sent} sent, {planned} planned)")
        return False

    def _stop(self, reason: str) -> None:
        if self._stop_reason is None:
            self._stop_reason = reason
            self.budget.notes.append(reason)

    @property
    def stopped(self) -> bool:
        if self.cancel.is_set() and self._stop_reason is None:
            self._stop("stopped by the user")
        return self._stop_reason is not None

    # ================================================================== sending helpers
    def _npdu_frame(self, apdu: bytes, addr: tuple[str, int], dnet: int | None, dadr: bytes | None,
                    expecting_reply: bool) -> bytes:
        kw: dict[str, Any] = {"expecting_reply": expecting_reply}
        if dnet is not None:
            kw.update(dnet=dnet, dadr=dadr)
        return B.encode_original_unicast(N.encode_npdu(apdu, **kw))

    def _send_unicast(self, frame: bytes, addr: tuple[str, int], category: str) -> bool:
        if self.stopped or not self._budget_ok(category):
            return False
        ok = self.t.send_unicast(frame, addr)
        if not ok:
            self.stopped  # noqa: B018 - records the cancel reason
        return ok

    def _send_broadcast(self, frame: bytes) -> bool:
        if self.stopped or not self._budget_ok("whois"):
            return False
        return self.t.send_broadcast(frame)

    def _next_invoke(self) -> int:
        self._invoke = (self._invoke + 1) % 256
        return self._invoke

    # ================================================================== receiving
    def _pump(self, timeout: float) -> None:
        """Receive and dispatch datagrams for up to ``timeout`` seconds (returns early after one datagram)."""
        rec = self.t.recv_datagram(max(0.0, timeout))
        if rec is not None:
            self._dispatch(rec.data, rec.src, rec.ts)

    def _dispatch(self, data: bytes, src: tuple[str, int], ts: float) -> None:
        msg = decode_message(data)
        if msg.bvlc is None:
            self.unsolicited["undecodable"] += 1
            return
        f = msg.bvlc.function
        if f in (BF.RESULT, BF.READ_BDT_ACK, BF.READ_FDT_ACK):
            self._on_bvlc(msg, src, ts)
            return
        if msg.apdu is None:
            self.unsolicited[msg.kind] += 1
            return
        addr = msg.bvlc.origin if f == BF.FORWARDED_NPDU and msg.bvlc.origin else src
        n = msg.npdu
        snet = n.snet if n is not None else None
        sadr = n.sadr if n is not None else None
        ap = msg.apdu
        if msg.kind == "i-am" and msg.decoded is not None:
            self._on_iam(msg, addr, snet, sadr, ts)
            return
        if ap.pdu_type in (PduType.COMPLEX_ACK, PduType.ERROR, PduType.REJECT, PduType.ABORT, PduType.SIMPLE_ACK):
            job = self._jobs_by_match.pop((addr, snet, sadr, ap.invoke_id), None)
            if job is None:
                self.unsolicited["unmatched-response"] += 1
                return
            self._on_response(job, msg, ts)
            return
        self.unsolicited[msg.kind] += 1

    def _on_iam(self, msg: BacnetMessage, addr: tuple[str, int], snet: int | None, sadr: bytes | None,
                ts: float) -> None:
        iam = msg.decoded
        if iam.object_type != ObjectType.DEVICE:
            return
        d = self._add_device(iam.device_instance, addr, snet, sadr.hex() if sadr else None, ts)
        d.vendor_id, d.max_apdu, d.segmentation = iam.vendor_id, iam.max_apdu, iam.segmentation_name
        d.iam_count += 1
        # attribute to the most recent Who-Is chunk covering this instance
        for ch in reversed(self.whois_chunks):
            if ch["low"] <= iam.device_instance <= ch["high"]:
                if ch.get("window_closed"):
                    ch["late_replies"] += 1
                else:
                    ch["replies"] += 1
                break
        if snet is None:
            job = self._whois_waits.pop(addr[0], None)
            if job is not None:
                self._deliver(job, _Resp("iam", d, job.sent_wall, ts))

    def _add_device(self, instance: int, addr: tuple[str, int], snet: int | None, sadr: str | None,
                    ts: float) -> Device:
        probe = Device(instance=instance, ip=addr[0], port=addr[1], snet=snet, sadr=sadr)
        key = _dev_key(probe)
        d = self.devices.get(key)
        if d is None:
            d = probe
            d.first_seen = ts
            self.devices[key] = d
            self.scan_stats[key] = {"instance": instance, "address": d.address_key, "requests": 0, "timeouts": 0,
                                    "retries": 0, "rejects": 0, "aborts": 0, "errors": 0, "unresponsive": False}
            self.progress({"type": "device", "instance": instance, "address": d.address_key,
                           "count": len(self.devices)})
            if self.fdr_addr and snet is None:
                self.t.allow_source(addr[0])
        d.responded_to_scan = True
        d.last_seen = ts
        return d

    # ================================================================== discovery (§3.2)
    def _discover(self) -> None:
        o = self.o
        init, mn, mx = self._chunk_params()
        chunker = WhoisChunker(o.whois_low, o.whois_high, init, mn, mx)
        self.progress({"type": "phase", "phase": "discovery", "planned": len(self._chunk_plan)})
        while not self.stopped and (rng := chunker.next_range()) is not None:
            # spacing: at least whois_gap_s after the previous Who-Is (the window normally already covers it)
            if self._last_whois is not None:
                self._wait_until(self._last_whois + o.whois_gap_s)
                if self.stopped:
                    break
            if self.fdr_addr and not self._fdr_keepalive():
                break
            apdu = A.encode_who_is(*rng)
            if self.fdr_addr:
                frame = B.encode_distribute_broadcast(N.encode_npdu(apdu))
                ok = self._send_unicast(frame, self.fdr_addr, "whois")
            else:
                ok = self._send_broadcast(B.encode_original_broadcast(N.encode_npdu(apdu)))
            if not ok:
                break
            self._last_whois = self.clock()
            ch = {"low": rng[0], "high": rng[1], "chunk": chunker.chunk, "sent_at": self.wall(), "replies": 0,
                  "late_replies": 0, "via": "fdr" if self.fdr_addr else "broadcast"}
            self.whois_chunks.append(ch)
            self.progress({"type": "whois", "low": rng[0], "high": rng[1], "sent": len(self.whois_chunks),
                           "planned": self.budget.whois_planned, "devices": len(self.devices)})
            self._wait_until(self._last_whois + o.whois_window_s)
            ch["window_closed"] = True
            chunker.record(ch["replies"])
        settle = o.settle_s if o.settle_s is not None else o.whois_window_s
        if self.whois_chunks and not self.stopped:
            self._wait_until(self.clock() + settle)

    def _wait_until(self, deadline: float) -> None:
        """Receive and dispatch until ``deadline`` (monotonic), in short slices so Stop is honoured quickly."""
        while not self.stopped:
            now = self.clock()
            if now >= deadline:
                return
            self._pump(min(0.05, deadline - now))

    def _fdr_keepalive(self) -> bool:
        """Register (or re-register before expiry) as a foreign device. Returns False if registration failed."""
        now = self.clock()
        if self._fdr_registered_at is not None and now - self._fdr_registered_at < self.o.fdr_ttl_s:
            return True
        assert self.fdr_addr is not None
        self.t.allow_source(self.fdr_addr[0])
        res = self._bvlc_round([(self.fdr_addr, "register")])[(self.fdr_addr, "register")]
        self.fdr_log.append({"at": self.wall(), "bbmd": f"{self.fdr_addr[0]}:{self.fdr_addr[1]}",
                             "ttl": self.o.fdr_ttl_s, "result": res["status"], "code": res.get("code")})
        if res["status"] != "ack":
            self.limitations.append(
                f"Foreign-device registration with {self.fdr_addr[0]} failed ({res['status']}); remote discovery "
                "through that BBMD was not performed.")
            return False
        self._fdr_registered_at = self.clock()
        return True

    # ================================================================== confirmed-request scheduler
    def _run_jobs(self, jobs: list[_Job]) -> None:
        queue = deque(jobs)
        active: list[_Job] = []
        o = self.o
        while (queue or active) and not self.stopped:
            while queue and len(active) < o.max_parallel_devices:
                job = queue.popleft()
                if self._advance(job, None):
                    active.append(job)
            now = self.clock()
            # timeouts
            for job in active:
                if job.in_flight and now >= job.deadline:
                    self._on_timeout(job)
            active = [j for j in active if j.req is not None]
            # sends (round robin; stop at the first that the rate limiter or a per-DNET rule holds back)
            for job in active:
                if self.stopped:
                    break
                if job.in_flight or job.req is None:
                    continue
                if job.dnet is not None:
                    if job.dnet in self._dnet_aborted:
                        self._abandon(job, "network abandoned after 2 consecutive timeouts")
                        continue
                    if any(j.in_flight and j.dnet == job.dnet for j in active):
                        continue
                    if self._dnet_limiter(job.dnet).wait_time() > 0:
                        continue
                if self.t.ready_in() > 0:
                    break
                if job.dnet is not None and not self._dnet_limiter(job.dnet).try_acquire():
                    continue
                self._send_job(job)
            active = [j for j in active if j.req is not None]
            if not active and not queue:
                break
            deadlines = [j.deadline for j in active if j.in_flight]
            wait = 0.05
            if deadlines:
                wait = min(wait, max(0.0, min(deadlines) - self.clock()))
            if any(not j.in_flight for j in active):
                wait = min(wait, max(0.002, self.t.ready_in()))
            self._pump(wait)
        for job in active + list(queue):
            if job.req is not None:
                self._abandon(job, None)

    def _dnet_limiter(self, dnet: int) -> RateLimiter:
        lim = self._dnet_limiters.get(dnet)
        if lim is None:
            lim = self._dnet_limiters[dnet] = RateLimiter(self.o.remote_rate_per_s, 1.0, self.clock)
        return lim

    def _advance(self, job: _Job, resp: _Resp | None) -> bool:
        """Feed ``resp`` to the job's generator; store its next request. Returns False when the job finished."""
        try:
            job.req = next(job.gen) if resp is None else job.gen.send(resp)
        except StopIteration:
            job.req = None
            return False
        job.tries = 0
        job.in_flight = False
        return True

    def _send_job(self, job: _Job) -> None:
        try:
            self._send_job_inner(job)
        except EgressMismatch as exc:  # destination learnt mid-run (e.g. FDR discovery) routes elsewhere
            self._egress_refused(exc)
            self._abandon(job, None)
            if (st := self.scan_stats.get(job.key)) is not None:
                st["skipped"] = "not contacted: its address routes through another interface"

    def _send_job_inner(self, job: _Job) -> None:
        req = job.req
        assert req is not None
        if req.kind == "whois-unicast":
            frame = B.encode_original_unicast(N.encode_npdu(A.encode_who_is(0, WHOIS_HIGH)))
            if not self._send_unicast(frame, req.addr, "whois"):
                return
            job.in_flight, job.tries = True, 1
            job.deadline = self.clock() + self.o.whois_window_s
            job.sent_wall = self.wall()
            self._whois_waits[req.addr[0]] = job
            return
        inv = self._next_invoke()
        if req.kind == "rpm":
            apdu = A.encode_rpm(inv, ObjectType.DEVICE, req.instance, req.props, max_apdu=OUR_MAX_APDU)
        else:
            pid, idx = req.props[0]
            apdu = A.encode_read_property(inv, ObjectType.DEVICE, req.instance, pid, idx, max_apdu=OUR_MAX_APDU)
        frame = self._npdu_frame(apdu, req.addr, req.dnet, req.dadr, True)
        if not self._send_unicast(frame, req.addr, "read"):
            return
        st = self.scan_stats.get(job.key)
        if st is not None:
            st["requests"] += 1
            if job.tries:
                st["retries"] += 1
        job.tries += 1
        job.invoke_id = inv
        job.in_flight = True
        job.deadline = self.clock() + self.o.apdu_timeout_s
        job.sent_wall = self.wall()
        self._jobs_by_match[(req.addr, req.dnet, req.dadr, inv)] = job

    def _on_timeout(self, job: _Job) -> None:
        req = job.req
        assert req is not None
        job.in_flight = False
        if req.kind == "whois-unicast":
            self._whois_waits.pop(req.addr[0], None)
            self._deliver(job, _Resp("no-iam", None, job.sent_wall, None))
            return
        self._jobs_by_match.pop((req.addr, req.dnet, req.dadr, job.invoke_id), None)
        st = self.scan_stats.get(job.key)
        if st is not None:
            st["timeouts"] += 1
        if req.dnet is not None:
            self._dnet_timeouts[req.dnet] += 1
            if self._dnet_timeouts[req.dnet] >= 2:
                self._dnet_aborted.add(req.dnet)
                self._abandon(job, "network abandoned after 2 consecutive timeouts")
                return
        if job.tries <= self.o.apdu_retries:
            return  # resend on the next scheduler pass (same request, new invoke id)
        self._deliver(job, _Resp("timeout", None, job.sent_wall, None))

    def _abandon(self, job: _Job, why: str | None) -> None:
        st = self.scan_stats.get(job.key)
        if st is not None and why:
            st["unresponsive"] = True
            st["note"] = why
        job.gen.close()
        job.req = None
        job.in_flight = False

    def _deliver(self, job: _Job, resp: _Resp) -> None:
        self._advance(job, resp)

    def _on_response(self, job: _Job, msg: BacnetMessage, ts: float) -> None:
        ap = msg.apdu
        assert ap is not None and job.req is not None
        job.in_flight = False
        if job.req.dnet is not None:
            self._dnet_timeouts[job.req.dnet] = 0
        st = self.scan_stats.get(job.key)
        if ap.pdu_type == PduType.COMPLEX_ACK:
            if ap.segmented or msg.decoded is None:
                resp = _Resp("segmented" if ap.segmented else "error", msg.decode_error, job.sent_wall, ts)
            else:
                resp = _Resp("ack", msg.decoded, job.sent_wall, ts)
        elif ap.pdu_type == PduType.ERROR:
            resp = _Resp("error", msg.decoded, job.sent_wall, ts)
            if st is not None:
                st["errors"] += 1
        elif ap.pdu_type == PduType.REJECT:
            resp = _Resp("reject", ap.reason, job.sent_wall, ts)
            if st is not None:
                st["rejects"] += 1
                st.setdefault("reject_reasons", []).append(name_of(RejectReason, ap.reason))
        elif ap.pdu_type == PduType.ABORT:
            resp = _Resp("abort", ap.reason, job.sent_wall, ts)
            if st is not None:
                st["aborts"] += 1
                st.setdefault("abort_reasons", []).append(name_of(AbortReason, ap.reason))
        else:
            resp = _Resp("error", None, job.sent_wall, ts)
        self._deliver(job, resp)

    # ================================================================== jobs
    def _target_job(self, addr: tuple[str, int]) -> Generator[_Req, _Resp, None]:
        """Unicast discovery (§3.2): RP object-identifier of device 4194303, else a unicast ranged Who-Is."""
        label = f"{addr[0]}:{addr[1]}"
        r = yield _Req("rp", addr, MAX_INSTANCE, [(P.OBJECT_IDENTIFIER, None)])
        if r.status == "ack" and isinstance(r.value.value, dict) and r.value.value.get("type") == "device":
            inst = int(r.value.value["instance"])
            self._add_device(inst, addr, None, None, r.received or self.wall())
            self.target_results[label] = {"method": "read-property-wildcard", "instance": inst}
            return
        first = r.status if r.status != "error" else f"error {self._error_name(r.value)}"
        r2 = yield _Req("whois-unicast", addr)
        if r2.status == "iam":
            self.target_results[label] = {"method": "unicast-who-is", "instance": r2.value.instance,
                                          "wildcard_read": first}
        else:
            self.target_results[label] = {"method": None, "result": "no answer", "wildcard_read": first}

    @staticmethod
    def _error_name(v: Any) -> str:
        if isinstance(v, tuple) and len(v) == 2:
            return f"{name_of(ErrorClass, v[0])}/{name_of(ErrorCode, v[1])}"
        return "unknown"

    def _device_job(self, d: Device, key: str) -> Generator[_Req, _Resp, None]:
        """Read the §3.3 property set: protocol-services-supported first, then RPM if supported, else RP."""
        st = self.scan_stats[key]
        addr = (d.ip or "", d.port or self.o.port)
        dnet = d.snet
        dadr = bytes.fromhex(d.sadr) if d.sadr else None
        props = (IDENTITY_PROPERTIES if d.vendor_id is None else []) + list(READ_PROPERTIES)

        def rp(pid: int, idx: int | None = None) -> _Req:
            return _Req("rp", addr, d.instance, [(pid, idx)], dnet, dadr)

        r = yield rp(P.PROTOCOL_SERVICES_SUPPORTED)
        if r.status == "timeout":
            st["unresponsive"] = True
            return
        self._record_rp(d, st, [(P.PROTOCOL_SERVICES_SUPPORTED, None)], r)
        use_rpm = r.status == "ack" and A.supports_service(r.value.value, CS.READ_PROPERTY_MULTIPLE)
        max_apdu = min(d.max_apdu or 480, OUR_MAX_APDU)
        st["rpm"] = bool(use_rpm)
        remaining = props
        if use_rpm and max_apdu >= 206:
            remaining = []
            batches = split_rpm(props, max_apdu)
            for i, batch in enumerate(batches):
                r = yield _Req("rpm", addr, d.instance, batch, dnet, dadr)
                if r.status == "timeout":
                    st["unresponsive"] = True
                    return
                if r.status == "ack":
                    self._record_rpm(d, st, batch, r)
                    continue
                st["rpm_fallback"] = f"{r.status}" + (f" ({self._reason(r)})" if self._reason(r) else "")
                remaining = [p for b in batches[i:] for p in b]
                break
        for pid, idx in remaining:
            r = yield rp(pid, idx)
            if r.status == "timeout":
                st["unresponsive"] = True
                return
            self._record_rp(d, st, [(pid, idx)], r)

    @staticmethod
    def _reason(r: _Resp) -> str:
        if r.status == "reject" and isinstance(r.value, int):
            return name_of(RejectReason, r.value)
        if r.status == "abort" and isinstance(r.value, int):
            return name_of(AbortReason, r.value)
        if r.status == "error" and isinstance(r.value, tuple):
            return name_of(ErrorCode, r.value[1])
        return ""

    def _store(self, d: Device, st: dict[str, Any], pid: int, idx: int | None, value: Any, when: float | None) -> None:
        name = property_name(pid, idx)
        d.properties[name] = _display_value(pid, value)
        d.property_errors.pop(name, None)
        if pid == P.VENDOR_IDENTIFIER and isinstance(value, int):
            d.vendor_id = value
        elif pid == P.MAX_APDU_LENGTH_ACCEPTED and isinstance(value, int):
            d.max_apdu = value
        elif pid == P.SEGMENTATION_SUPPORTED and isinstance(value, int):
            d.segmentation = name_of(Segmentation, value)
        elif pid in (P.LOCAL_DATE, P.LOCAL_TIME):
            clk = st.setdefault("clock", {})
            clk["date" if pid == P.LOCAL_DATE else "time"] = value
            if pid == P.LOCAL_TIME and when is not None:
                clk["host_ts"] = when  # host clock at the moment local-time was read (design §3.3)
            self._skew(st)

    @staticmethod
    def _skew(st: dict[str, Any]) -> None:
        clk = st.get("clock", {})
        dv, tv, host = clk.get("date"), clk.get("time"), clk.get("host_ts")
        if not (isinstance(dv, dict) and isinstance(tv, dict) and host is not None):
            return
        try:
            dev = datetime(dv["year"], dv["month"], dv["day"], tv["hour"], tv["minute"], tv["second"],
                           (tv.get("hundredths") or 0) * 10_000)
        except (TypeError, ValueError, KeyError):
            clk["skew_s"] = None
            return
        hdt = datetime.fromtimestamp(host)
        clk["device_local"] = dev.isoformat(timespec="seconds")
        clk["host_local"] = hdt.isoformat(timespec="seconds")
        clk["skew_s"] = round((dev - hdt).total_seconds(), 2)

    def _record_error(self, d: Device, pid: int, idx: int | None, err: str) -> None:
        name = property_name(pid, idx)
        if name not in d.properties:
            d.property_errors[name] = err

    def _record_rp(self, d: Device, st: dict[str, Any], props: list[tuple[int, int | None]], r: _Resp) -> None:
        pid, idx = props[0]
        if r.status == "ack":
            self._store(d, st, pid, idx, r.value.value, self._mid(r))
        else:
            self._record_error(d, pid, idx, self._reason(r) or r.status)

    def _record_rpm(self, d: Device, st: dict[str, Any], batch: list[tuple[int, int | None]], r: _Resp) -> None:
        got = set()
        for res in r.value:
            got.add((res.property_id, res.index))
            if res.ok:
                self._store(d, st, res.property_id, res.index, res.value, self._mid(r))
            else:
                self._record_error(d, res.property_id, res.index, name_of(ErrorCode, res.error[1]))
        for pid, idx in batch:
            if (pid, idx) not in got:
                self._record_error(d, pid, idx, "missing-from-rpm-ack")

    @staticmethod
    def _mid(r: _Resp) -> float | None:
        if r.sent is not None and r.received is not None:
            return (r.sent + r.received) / 2
        return r.received

    # ================================================================== BBMD audit (§3.4)
    def _bvlc_round(self, probes: list[tuple[tuple[str, int], str]]) -> dict[tuple[tuple[str, int], str], dict]:
        """Send each probe once (<= bvlc_rate_per_s, no retry) and collect ack / nak / timeout."""
        results: dict[tuple[tuple[str, int], str], dict] = {}
        todo = deque(dict.fromkeys(probes))
        while (todo or self._pending_bvlc) and not self.stopped:
            now = self.clock()
            for k, p in list(self._pending_bvlc.items()):
                if now >= p["deadline"]:
                    del self._pending_bvlc[k]
                    results[k] = {"status": "timeout"}
            if todo and self._bvlc_limiter.wait_time() <= 0 and self.t.ready_in() <= 0:
                addr, kind = todo[0]
                frame = {"bdt": B.encode_read_bdt, "fdt": B.encode_read_fdt}.get(kind)
                frame_b = frame() if frame else B.encode_register_foreign_device(self.o.fdr_ttl_s)
                if not self._budget_ok("bvlc"):
                    break
                self._bvlc_limiter.try_acquire()
                try:
                    sent = self.t.send_unicast(frame_b, addr)
                except EgressMismatch as exc:  # e.g. a follow-bdt peer that routes through a VPN
                    self._egress_refused(exc)
                    results[todo.popleft()] = {"status": "egress-refused"}
                    continue
                if not sent:
                    break
                todo.popleft()
                self._pending_bvlc[(addr, kind)] = {"deadline": self.clock() + self.o.apdu_timeout_s,
                                                    "results": results}
            waits = [p["deadline"] - self.clock() for p in self._pending_bvlc.values()]
            if todo:
                waits.append(max(0.002, self._bvlc_limiter.wait_time(), self.t.ready_in()))
            self._pump(min([0.05] + [max(0.0, w) for w in waits]))
        for k in list(self._pending_bvlc):
            del self._pending_bvlc[k]
            results.setdefault(k, {"status": "cancelled"})
        for k in todo:
            results.setdefault(k, {"status": "not-sent"})
        return results

    def _on_bvlc(self, msg: BacnetMessage, src: tuple[str, int], ts: float) -> None:
        b = msg.bvlc
        assert b is not None
        if b.function == BF.READ_BDT_ACK:
            key, res = (src, "bdt"), {"status": "ack", "bdt": b.bdt or [], "ts": ts}
        elif b.function == BF.READ_FDT_ACK:
            key, res = (src, "fdt"), {"status": "ack", "fdt": b.fdt or [], "ts": ts}
        else:
            code = b.result_code
            kind = {BvlcResult.READ_BDT_NAK: "bdt", BvlcResult.READ_FDT_NAK: "fdt",
                    BvlcResult.REGISTER_FOREIGN_DEVICE_NAK: "register",
                    BvlcResult.SUCCESSFUL_COMPLETION: "register"}.get(code)  # type: ignore[call-overload]
            if kind is None:
                for k in ("bdt", "fdt", "register"):  # other NAK codes: attribute to whatever is pending
                    if (src, k) in self._pending_bvlc:
                        kind = k
                        break
            if kind is None:
                self.unsolicited["bvlc-result"] += 1
                return
            ok = code == BvlcResult.SUCCESSFUL_COMPLETION and kind == "register"
            key, res = (src, kind), {"status": "ack" if ok else "nak", "code": code, "ts": ts}
        pending = self._pending_bvlc.pop(key, None)
        if pending is None:
            self.unsolicited["unmatched-bvlc"] += 1
            return
        pending["results"][key] = res

    def _audit_bbmds(self) -> None:
        self.progress({"type": "phase", "phase": "bbmd-audit"})
        probes: dict[tuple[str, int], str] = {}
        for d in self.devices.values():
            if not d.remote and d.ip and d.port:
                probes.setdefault((d.ip, d.port), "probe")
        for s in self.o.bbmd_candidates:
            probes.setdefault(_parse_addr(s, self.o.port), "user")
        for s in self.o.passive_bbmd_candidates:
            probes.setdefault(_parse_addr(s, self.o.port), "passive")
        if self.fdr_addr:
            probes.setdefault(self.fdr_addr, "user")
        for addr, source in probes.items():
            if source != "probe":
                self.t.allow_source(addr[0])
        self._replan(bvlc=self.budget.bvlc_probes_sent + len(probes),
                     why=f"BBMD audit: Read-BDT to {len(probes)} address(es).")
        res = self._bvlc_round([(a, "bdt") for a in probes])
        for addr, source in probes.items():
            self._apply_bdt(addr, source, res.get((addr, "bdt"), {"status": "not-sent"}))
        if self.stopped:
            return
        found = [a for a, b in self.bbmds.items() if b.status == "bbmd"]
        peers: list[tuple[str, int]] = []
        if self.o.follow_bdt:
            for a in found:
                for e in self.bbmds[a].bdt or []:
                    p = (e.ip, e.port)
                    if p not in self.bbmds and p not in peers:
                        peers.append(p)
        self._replan(bvlc=self.budget.bvlc_probes_sent + len(found) + len(peers),
                     why=f"BBMD audit: {len(found)} BBMD(s) found; Read-FDT to each"
                     + (f", Read-BDT to {len(peers)} peer(s) (follow-bdt)." if peers else "."))
        for p in peers:
            self.t.allow_source(p[0])
        res = self._bvlc_round([(a, "fdt") for a in found] + [(p, "bdt") for p in peers])
        for a in found:
            r = res.get((a, "fdt"), {"status": "not-sent"})
            b = self.bbmds[a]
            b.fdt_status = r["status"] if r["status"] in ("ack", "nak", "timeout") else None
            b.fdt = r.get("fdt") if r["status"] == "ack" else None
        for p in peers:
            self._apply_bdt(p, "bdt-peer", res.get((p, "bdt"), {"status": "not-sent"}))

    def _apply_bdt(self, addr: tuple[str, int], source: str, r: dict[str, Any]) -> None:
        status = {"ack": "bbmd", "nak": "not-bbmd", "timeout": "timeout"}.get(r["status"])
        if status is None:
            return  # cancelled / not sent: nothing known
        if source == "probe" and status != "bbmd":
            # Plain devices: a NAK is the normal answer and a silent device is common; keep them out of the BBMD
            # list but record the facts.
            key = "read_bdt_nak" if status == "not-bbmd" else "read_bdt_timeout"
            self.scan_stats.setdefault("_bvlc", {}).setdefault(key, []).append(f"{addr[0]}:{addr[1]}")
            return
        self.bbmds[addr] = Bbmd(ip=addr[0], port=addr[1], status=status, source=source,
                                bdt=r.get("bdt") if status == "bbmd" else None)

    # ================================================================== run
    def preflight(self) -> None:
        """Check, before anything is sent, that every destination known now routes out of the chosen interface.

        Raises :class:`~bacnet_health.active.iface.EgressMismatch` with a plain-English message. (The transport
        already checked the broadcast address when it was opened.)
        """
        verify = getattr(self.t, "verify_egress", None)
        if verify is None:
            return
        dests = [a[0] for a in self.targets]
        dests += [_parse_addr(x, self.o.port)[0] for x in self.o.bbmd_candidates + self.o.passive_bbmd_candidates]
        if self.fdr_addr:
            dests.append(self.fdr_addr[0])
        for ip in dict.fromkeys(dests):
            verify(ip)

    def _egress_refused(self, exc: EgressMismatch) -> None:
        msg = f"Not sent: {exc}"
        if msg not in self.limitations:
            self.limitations.append(msg)

    def run(self) -> Result:
        """Execute the scan and return a Result (kind ``"scan"``). Partial results are kept if stopped.

        Raises EgressMismatch (from :meth:`preflight`) before any transmission if a destination would leave through
        another interface.
        """
        o = self.o
        if not self._planned:
            self.plan()
        self.preflight()
        run = RunInfo(kind="scan", interface=o.interface, local_ip=o.local_ip, netmask=o.netmask,
                      broadcast=o.broadcast, port=self.t.port, vantage=Vantage.SELF, vantage_source="scan",
                      ntp_synced=o.host_ntp_synced, confirmations=list(o.confirmations))
        steps: list[str] = []
        if self.fdr_addr:
            run.confirmations.append({"action": "foreign-device-registration",
                                      "target": f"{self.fdr_addr[0]}:{self.fdr_addr[1]}",
                                      "user": o.fdr_confirmed_ip and "typed confirmation", "at": utcnow_iso()})
        try:
            if o.discovery and not self.stopped:
                self._discover()
                steps.append("discovery")
            if self.targets and not self.stopped:
                self.progress({"type": "phase", "phase": "targets", "count": len(self.targets)})
                for addr in self.targets:
                    self.t.allow_source(addr[0])
                self._run_jobs([_Job(f"target {a[0]}:{a[1]}", self._target_job(a)) for a in self.targets])
                steps.append("unicast-targets")
            if o.read_properties and not self.stopped:
                self._read_all()
                steps.append("device-reads")
            if o.bbmd_audit and not self.stopped:
                self._audit_bbmds()
                steps.append("bbmd-audit")
        finally:
            # Nothing else will be sent; drain briefly so late replies (I-Ams, acks) are still recorded.
            if not self.cancel.is_set():
                end = self.clock() + min(0.2, o.apdu_timeout_s)
                while self.clock() < end:
                    self._pump(end - self.clock())
        run.finished = utcnow_iso()
        run.incomplete = self._stop_reason is not None
        return self._result(run, steps)

    def _read_all(self) -> None:
        local = [(k, d) for k, d in self.devices.items() if not d.remote]
        remote = [(k, d) for k, d in self.devices.items() if d.remote]
        chosen = local + (remote if self.o.read_remote else [])
        self._replan(reads=self.budget.reads_sent + _PER_DEVICE_READS * len(chosen),
                     why=f"Reads re-estimated after discovery: {len(chosen)} device(s) x up to {_PER_DEVICE_READS} "
                     "requests.")
        self.progress({"type": "phase", "phase": "reads", "count": len(chosen)})
        jobs = [_Job(k, self._device_job(d, k), dnet=d.snet) for k, d in chosen]
        self._run_jobs(jobs)

    def _result(self, run: RunInfo, steps: list[str]) -> Result:
        o = self.o
        r = Result(run=run, budget=self.budget)
        r.devices = sorted(self.devices.values(), key=lambda d: (d.instance, d.address_key))
        r.bbmds = sorted(self.bbmds.values(), key=lambda b: (b.status != "bbmd", b.ip, b.port))
        stats = {k: v for k, v in self.scan_stats.items() if not k.startswith("_")}
        log = self.t.sent_log
        r.metrics = {
            "whois_chunks": {
                "plan": [list(x) for x in self._chunk_plan],
                "sent": [{k: v for k, v in ch.items() if k != "window_closed"} for ch in self.whois_chunks],
                "window_s": o.whois_window_s, "gap_s": o.whois_gap_s,
            },
            "scan_stats": stats,
            "targets": self.target_results,
            "sent_log": {
                "frames": len(log),
                "by_kind": dict(Counter(f.kind for f in log)),
                "by_category": dict(Counter(f.category for f in log)),
                "first_ts": log[0].ts if log else None,
                "last_ts": log[-1].ts if log else None,
                "log": [{"ts": round(f.ts, 4), "dst": f.dst, "kind": f.kind, "size": f.size} for f in log[:5000]],
            },
            "unsolicited": dict(self.unsolicited),
            "inbound_verified": bool(getattr(self.t, "inbound_verified", False)),
            "scan_steps": steps,
        }
        if self.fdr_log:
            r.metrics["fdr"] = self.fdr_log
        if (nak := self.scan_stats.get("_bvlc")) is not None:
            r.metrics["bvlc"] = nak
        r.limitations = list(self.limitations) + [
            "BACnet/IPv6 (Annex U) and BACnet/SC are out of scope for this version.",
        ]
        remote = [d for d in r.devices if d.remote]
        if remote and not o.read_remote:
            r.limitations.append(f"{len(remote)} device(s) behind BACnet routers were recorded from their I-Am but "
                                 "not read (read-remote was off).")
        if any(b.status == "bbmd" and b.source == "probe" for b in r.bbmds) and not self.fdr_addr:
            r.limitations.append("A BBMD answers on this subnet, so the tool's Who-Is broadcasts may have been "
                                 "distributed to other subnets.")
        if self.fdr_addr and self.fdr_log:
            r.limitations.append(
                f"Foreign-device registration with {self.fdr_addr[0]} created an FDT entry for this computer with a "
                f"{o.fdr_ttl_s} s time-to-live. It was left to expire (no Delete-FDT-Entry is ever sent).")
        if not r.metrics["inbound_verified"]:
            r.limitations.append("No BACnet datagram from another host was received, so inbound UDP delivery to "
                                 "this computer (firewall) was not verified. '0 devices' may not mean 'no devices'.")
        if self._stop_reason:
            r.limitations.append(f"The scan was incomplete: {self._stop_reason}.")
        if o.evaluate:
            from bacnet_health.findings.active import active_not_performed, evaluate_active, performed_active
            from bacnet_health.topology import build_topology

            r.topology = build_topology(r.bbmds, o.subnet)
            r.findings = evaluate_active(r, stats, o.host_ntp_synced, treat_as_public=o.public_ranges)
            r.checks_not_performed = active_not_performed(r, o.host_ntp_synced)
            r.metrics["checks_performed"] = performed_active(r.checks_not_performed)
        self.progress({"type": "done", "devices": len(r.devices), "frames": self.budget.frames_sent,
                       "incomplete": run.incomplete})
        return r
