"""Passive traffic analysis: turns a stream of decoded BACnet/IP datagrams into counters and state.

Used by ``analyze`` (pcap files) and ``listen`` (live UDP socket). The analyzer only accumulates facts; deciding what
is a finding happens in :mod:`bacnet_health.findings.passive`.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from bacnet_health.capture.link import UdpDatagram
from bacnet_health.model import BdtEntry, Device, FdtEntry
from bacnet_health.wire.constants import AbortReason, BvlcFunction, BvlcResult, PduType, name_of
from bacnet_health.wire.message import BacnetMessage

STANDARD_PORT = 47808
WRITE_KINDS = {
    "write-property", "write-property-multiple", "create-object", "delete-object", "atomic-write-file",
    "add-list-element", "remove-list-element", "write-group",
}
CONTROL_KINDS = {"dcc", "reinitialize"}
CONFIRMED_REQ = PduType.CONFIRMED_REQUEST
RESPONSE_TYPES = {PduType.SIMPLE_ACK, PduType.COMPLEX_ACK, PduType.ERROR, PduType.REJECT, PduType.ABORT}
_SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")


def is_private_or_special(ip: str) -> bool:
    """True for addresses that are not 'public' for SEC-004 purposes."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_unspecified
        or a in _SHARED_ADDRESS_SPACE or str(a) == "255.255.255.255" or a.is_reserved
    )


def _is_broadcast(udp: UdpDatagram, msg: BacnetMessage) -> bool:
    if msg.bvlc is not None and msg.bvlc.function == BvlcFunction.ORIGINAL_BROADCAST_NPDU:
        return True
    if udp.eth_dst and udp.eth_dst.lower() == "ff:ff:ff:ff:ff:ff":
        return True
    return udp.dst_ip == "255.255.255.255" or udp.dst_ip.endswith(".255")


@dataclass
class Txn:
    ts: float
    client: tuple[str, int]
    server: tuple[str, int]
    invoke_id: int
    service: str
    frame_no: int
    payload_hash: str
    response: str | None = None  # "ack" | "error" | "reject" | "abort"
    response_ts: float | None = None
    reason: str | None = None
    retransmits: int = 0


@dataclass
class PassiveState:
    first_ts: float | None = None
    last_ts: float | None = None
    frames: int = 0
    bacnet_frames: int = 0
    decode_errors: Counter = field(default_factory=Counter)
    kinds: Counter = field(default_factory=Counter)
    bcast_per_sec: Counter = field(default_factory=Counter)
    bcast_sources: Counter = field(default_factory=Counter)
    whois_per_sec: Counter = field(default_factory=Counter)
    whois_sources: Counter = field(default_factory=Counter)
    whois_global_sources: Counter = field(default_factory=Counter)
    whois_global: int = 0
    whois_total: int = 0
    iam_per_sec: Counter = field(default_factory=Counter)
    iam_times: dict[int, list[float]] = field(default_factory=lambda: defaultdict(list))
    devices: dict[tuple, Device] = field(default_factory=dict)  # (instance, address_key) -> Device
    device_ports: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))  # port -> addresses
    dup_broadcasts: list[dict[str, Any]] = field(default_factory=list)
    txns: list[Txn] = field(default_factory=list)
    open_txns: dict[tuple, Txn] = field(default_factory=dict)
    unmatched_responses: int = 0
    reject_to_network: list[dict[str, Any]] = field(default_factory=list)
    router_networks: dict[int, set[str]] = field(default_factory=lambda: defaultdict(set))
    low_hop: list[dict[str, Any]] = field(default_factory=list)
    writes: list[dict[str, Any]] = field(default_factory=list)
    controls: list[dict[str, Any]] = field(default_factory=list)
    public_addrs: Counter = field(default_factory=Counter)
    bbmd_candidates: dict[tuple[str, int], str] = field(default_factory=dict)  # addr -> reason
    bdt_seen: dict[tuple[str, int], list[BdtEntry]] = field(default_factory=dict)
    fdt_seen: dict[tuple[str, int], list[FdtEntry]] = field(default_factory=dict)
    unicast_pairs: set[frozenset] = field(default_factory=set)
    own_frames: int = 0

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return max(0.0, self.last_ts - self.first_ts)


class PassiveAnalyzer:
    def __init__(self, own_addrs: set[tuple[str, int]] | None = None, txn_timeout: float = 10.0) -> None:
        self.s = PassiveState()
        self.own_addrs = own_addrs or set()
        self.txn_timeout = txn_timeout
        self._recent_bcast: dict[str, list[tuple[float, str, int]]] = {}

    # ------------------------------------------------------------------ feeding
    def feed(self, udp: UdpDatagram, msg: BacnetMessage, own: bool = False) -> None:
        s = self.s
        s.frames += 1
        ts = udp.ts
        if s.first_ts is None or ts < s.first_ts:
            s.first_ts = ts
        if s.last_ts is None or ts > s.last_ts:
            s.last_ts = ts
        src = (udp.src_ip, udp.src_port)
        if own or src in self.own_addrs:
            s.own_frames += 1
            # Our own requests are still matched to responses (for the tool's own COMM evidence) but excluded
            # from broadcast/discovery metrics.
            self._track_txn(udp, msg, ts)
            return
        if msg.decode_error:
            s.decode_errors[msg.error_layer or "unknown"] += 1
            if msg.bvlc is None:
                return
        s.bacnet_frames += 1
        s.kinds[msg.kind] += 1
        sec = int(ts)
        bcast = _is_broadcast(udp, msg)
        for ip in (udp.src_ip, udp.dst_ip):
            if not is_private_or_special(ip):
                s.public_addrs[ip] += 1
        if bcast:
            s.bcast_per_sec[sec] += 1
            origin = msg.bvlc.origin if msg.bvlc and msg.bvlc.origin else src
            s.bcast_sources[f"{origin[0]}:{origin[1]}"] += 1
            self._dup_check(udp, msg, ts)
        else:
            s.unicast_pairs.add(frozenset((udp.src_ip, udp.dst_ip)))
        self._bvlc(udp, msg)
        if msg.npdu is not None:
            n = msg.npdu
            if n.dnet is not None and n.hop_count is not None and n.hop_count <= 1:
                s.low_hop.append({"ts": ts, "frame": udp.frame_no, "src": f"{udp.src_ip}", "hop": n.hop_count})
            if n.network_message is not None:
                self._network_message(udp, msg, ts)
        if msg.apdu is None:
            return
        kind = msg.kind
        if kind == "who-is":
            s.whois_total += 1
            s.whois_per_sec[sec] += 1
            s.whois_sources[udp.src_ip] += 1
            if msg.decoded is None:
                s.whois_global += 1
                s.whois_global_sources[udp.src_ip] += 1
        elif kind == "i-am" and msg.decoded is not None:
            s.iam_per_sec[sec] += 1
            self._iam(udp, msg, ts)
        elif kind in WRITE_KINDS:
            s.writes.append(self._sec_record(udp, msg, ts))
        elif kind in CONTROL_KINDS:
            s.controls.append(self._sec_record(udp, msg, ts))
        self._track_txn(udp, msg, ts)

    # ------------------------------------------------------------------ helpers
    def _sec_record(self, udp: UdpDatagram, msg: BacnetMessage, ts: float) -> dict[str, Any]:
        return {
            "ts": ts, "frame": udp.frame_no, "src": udp.src_ip, "dst": udp.dst_ip, "kind": msg.kind,
            "service": msg.service_name, "detail": msg.decoded if isinstance(msg.decoded, dict) else None,
        }

    def _iam(self, udp: UdpDatagram, msg: BacnetMessage, ts: float) -> None:
        s = self.s
        iam = msg.decoded
        n = msg.npdu
        snet = n.snet if n is not None else None
        sadr = n.sadr.hex() if n is not None and n.sadr else None
        dev = Device(instance=iam.device_instance, ip=udp.src_ip, port=udp.src_port, snet=snet, sadr=sadr)
        key = (iam.device_instance, dev.address_key)
        d = s.devices.get(key)
        if d is None:
            d = dev
            d.vendor_id = iam.vendor_id
            d.max_apdu = iam.max_apdu
            d.segmentation = iam.segmentation_name
            d.first_seen = ts
            s.devices[key] = d
        d.seen_passively = True
        d.last_seen = ts
        d.iam_count += 1
        s.iam_times[iam.device_instance].append(ts)
        if snet is None:
            s.device_ports[udp.src_port].add(f"{udp.src_ip}:{udp.src_port}")

    def _dup_check(self, udp: UdpDatagram, msg: BacnetMessage, ts: float) -> None:
        if msg.bvlc is None or msg.bvlc.npdu is None:
            return
        origin = msg.bvlc.origin or (udp.src_ip, udp.src_port)
        key = f"{origin[0]}:{origin[1]}|" + hashlib.blake2b(msg.bvlc.npdu, digest_size=8).hexdigest()
        window = 0.05
        recent = [r for r in self._recent_bcast.get(key, []) if ts - r[0] <= window]
        via = f"{udp.src_ip}:{udp.src_port}"
        for r_ts, r_via, r_frame in recent:
            if r_via != via:
                self.s.dup_broadcasts.append({
                    "ts": ts, "frame": udp.frame_no, "first_frame": r_frame, "origin": f"{origin[0]}:{origin[1]}",
                    "via": [r_via, via], "kind": msg.kind,
                })
                break
        recent.append((ts, via, udp.frame_no))
        self._recent_bcast[key] = recent
        if len(self._recent_bcast) > 20000:  # bound memory on long captures
            cutoff = ts - window
            self._recent_bcast = {k: v for k, v in self._recent_bcast.items() if v and v[-1][0] >= cutoff}

    def _bvlc(self, udp: UdpDatagram, msg: BacnetMessage) -> None:
        b = msg.bvlc
        if b is None:
            return
        s = self.s
        src = (udp.src_ip, udp.src_port)
        dst = (udp.dst_ip, udp.dst_port)
        if b.function == BvlcFunction.FORWARDED_NPDU:
            s.bbmd_candidates.setdefault(src, "sent Forwarded-NPDU")
        elif b.function in (BvlcFunction.REGISTER_FOREIGN_DEVICE, BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK):
            s.bbmd_candidates.setdefault(dst, "received foreign-device traffic")
        elif b.function == BvlcFunction.READ_BDT_ACK and b.bdt is not None:
            s.bdt_seen[src] = b.bdt
            s.bbmd_candidates[src] = "answered Read-BDT"
        elif b.function == BvlcFunction.READ_FDT_ACK and b.fdt is not None:
            s.fdt_seen[src] = b.fdt
            s.bbmd_candidates.setdefault(src, "answered Read-FDT")

    def _network_message(self, udp: UdpDatagram, msg: BacnetMessage, ts: float) -> None:
        s = self.s
        d = msg.decoded or {}
        if msg.kind == "net:reject-message-to-network":
            s.reject_to_network.append({"ts": ts, "frame": udp.frame_no, "src": udp.src_ip, **d})
        elif msg.kind == "net:i-am-router-to-network":
            for net in d.get("networks", []):
                s.router_networks[net].add(f"{udp.src_ip}:{udp.src_port}")

    def _track_txn(self, udp: UdpDatagram, msg: BacnetMessage, ts: float) -> None:
        ap = msg.apdu
        if ap is None or ap.invoke_id is None:
            return
        s = self.s
        a, b = (udp.src_ip, udp.src_port), (udp.dst_ip, udp.dst_port)
        if ap.pdu_type == CONFIRMED_REQ:
            if ap.segmented and ap.sequence not in (None, 0):
                return
            key = (a, b, ap.invoke_id)
            ph = hashlib.blake2b(ap.payload, digest_size=8).hexdigest()
            prev = s.open_txns.get(key)
            if prev is not None and prev.response is None and ts - prev.ts <= self.txn_timeout:
                if prev.payload_hash == ph:
                    prev.retransmits += 1
                    return
            t = Txn(ts, a, b, ap.invoke_id, msg.kind, udp.frame_no, ph)
            s.open_txns[key] = t
            s.txns.append(t)
        elif ap.pdu_type in RESPONSE_TYPES:
            server_is_src = not (ap.pdu_type == PduType.ABORT and not ap.server)
            client, server = (b, a) if server_is_src else (a, b)
            t = s.open_txns.get((client, server, ap.invoke_id))
            if t is None or t.response is not None:
                s.unmatched_responses += 1
                return
            if ap.pdu_type == PduType.COMPLEX_ACK and ap.more_follows:
                return  # wait for the last segment; the response is not complete yet
            t.response_ts = ts
            if ap.pdu_type in (PduType.SIMPLE_ACK, PduType.COMPLEX_ACK):
                t.response = "ack"
            elif ap.pdu_type == PduType.ERROR:
                t.response = "error"
                if isinstance(msg.decoded, tuple):
                    t.reason = f"{msg.decoded[0]}/{msg.decoded[1]}"
            elif ap.pdu_type == PduType.REJECT:
                t.response = "reject"
                t.reason = name_of_reject(ap.reason)
            else:
                t.response = "abort"
                t.reason = name_of(AbortReason, ap.reason) if ap.reason is not None else None

    # ------------------------------------------------------------------ finishing
    def finish(self) -> PassiveState:
        return self.s


def name_of_reject(reason: int | None) -> str | None:
    from bacnet_health.wire.constants import RejectReason

    return None if reason is None else name_of(RejectReason, reason)


def infer_vantage(s: PassiveState) -> tuple[str, str]:
    """Return (vantage, reason). 'span' if unicast BACnet between unrelated host pairs is visible."""
    pairs = [tuple(p) for p in s.unicast_pairs if len(p) == 2]
    if not pairs:
        return "access", "no device-to-device unicast BACnet traffic was visible"
    hosts = Counter(h for p in pairs for h in p)
    common = [h for h, c in hosts.items() if c == len(pairs)]
    if common:
        return "access", f"all unicast BACnet traffic involved one host ({common[0]}), probably the capturing host"
    return "span", f"unicast BACnet traffic between {len(hosts)} different hosts was visible"


def bbmd_result_name(code: int | None) -> str:
    return "unknown" if code is None else name_of(BvlcResult, code)
