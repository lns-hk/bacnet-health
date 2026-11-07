"""Stdlib BACnet/IP device and BBMD simulator for tests and demos (design §9.1).

Each :class:`SimDevice` gets its own UDP socket on ``127.0.0.1`` with its own port. One background thread serves all
of them. Localhost has no broadcast, so a "broadcast" Who-Is reaches the simulator through the transport's
``broadcast_targets`` test hook, and I-Am replies go unicast to the requester.

This module is the *responder* side. Its frames do not pass through ``txguard`` (they are what devices send, not what
the tool sends) and it must never be used by the scanner itself.

Fault injection per device: ``drop_all`` (no response at all), ``drop_first`` (ignore the first N confirmed requests),
``delay`` (seconds before every answer), ``rpm=False`` (Reject unrecognized-service for RPM and the RPM bit cleared in
protocol-services-supported), ``system_status``, ``clock_offset_s``, ``answer_whois=False``, ``answer_wildcard=False``
(Error for RP on instance 4194303), ``silent_bvlc=True`` (ignore Read-BDT/Read-FDT). Duplicate instances are simply two
devices with the same ``instance``.
"""

from __future__ import annotations

import heapq
import itertools
import select
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.constants import (
    MAX_INSTANCE,
    AbortReason,
    BvlcFunction as BF,
    BvlcResult,
    ConfirmedService as CS,
    ErrorClass,
    ErrorCode,
    ObjectType,
    PduType,
    PropertyId as P,
    RejectReason,
    Segmentation,
    UnconfirmedService as US,
)
from bacnet_health.wire.message import decode_message
from bacnet_health.wire.tags import Enumerated, Signed

__all__ = ["SimDevice", "Simulator"]

HOST = "127.0.0.1"


@dataclass
class SimDevice:
    instance: int | None  # None: a BBMD-only node that is not a BACnet device (answers BVLC only)
    vendor_id: int = 999
    max_apdu: int = 1476
    segmentation: int = Segmentation.NONE
    object_name: str | None = None
    properties: dict[int, Any] = field(default_factory=dict)  # overrides / additions (property id -> value)
    missing: set[int] = field(default_factory=set)  # property ids answered with unknown-property
    rpm: bool = True
    delay: float = 0.0
    drop_all: bool = False
    drop_first: int = 0
    answer_whois: bool = True
    answer_wildcard: bool = True
    system_status: int = 0
    clock_offset_s: float = 0.0
    protocol_revision: int = 22
    object_count: int = 12
    # BBMD role
    bbmd: bool = False
    bdt: list[BdtEntry] = field(default_factory=list)
    fdt: list[FdtEntry] = field(default_factory=list)
    silent_bvlc: bool = False
    # routed children: devices on network ``remote_net`` behind this node (which then acts as a router)
    remote: list["SimDevice"] = field(default_factory=list)
    remote_net: int = 5
    # filled in by the simulator
    port: int = 0
    received: list[str] = field(default_factory=list)  # decoded kinds of every frame received
    _confirmed_seen: int = 0

    @property
    def addr(self) -> tuple[str, int]:
        return (HOST, self.port)

    def property_table(self) -> dict[int, Any]:
        now = time.localtime(time.time() + self.clock_offset_s)
        services = [False] * 40
        for s in (CS.READ_PROPERTY,) + ((CS.READ_PROPERTY_MULTIPLE,) if self.rpm else ()):
            services[s] = True
        objs = [{"type": "device", "instance": self.instance or 0}] + [
            {"type": "analog-input", "instance": i} for i in range(1, self.object_count)
        ]
        t: dict[int, Any] = {
            P.OBJECT_IDENTIFIER: {"type": "device", "instance": self.instance or 0},
            P.OBJECT_NAME: self.object_name or f"SIM-{self.instance}",
            P.VENDOR_NAME: "Simulated Controls",
            P.VENDOR_IDENTIFIER: self.vendor_id,
            P.MODEL_NAME: "SIM-100",
            P.FIRMWARE_REVISION: "1.2.3",
            P.APPLICATION_SOFTWARE_VERSION: "4.5",
            P.PROTOCOL_VERSION: 1,
            P.PROTOCOL_REVISION: self.protocol_revision,
            P.LOCATION: "Lab",
            P.DESCRIPTION: "Simulated device",
            P.SYSTEM_STATUS: Enumerated(self.system_status),
            P.LOCAL_DATE: {"year": now.tm_year, "month": now.tm_mon, "day": now.tm_mday,
                           "weekday": now.tm_wday + 1},
            P.LOCAL_TIME: {"hour": now.tm_hour, "minute": now.tm_min, "second": now.tm_sec, "hundredths": 0},
            P.UTC_OFFSET: Signed(0),
            P.DATABASE_REVISION: 7,
            P.MAX_SEGMENTS_ACCEPTED: 1,
            P.MAX_APDU_LENGTH_ACCEPTED: self.max_apdu,
            P.SEGMENTATION_SUPPORTED: Enumerated(self.segmentation),
            P.PROTOCOL_SERVICES_SUPPORTED: services,
            P.OBJECT_LIST: objs,
        }
        t.update(self.properties)
        for pid in self.missing:
            t.pop(pid, None)
        return t


class Simulator:
    """Run ``devices`` on 127.0.0.1 in a background thread. Use as a context manager."""

    def __init__(self, devices: list[SimDevice]) -> None:
        self.devices = devices
        self._socks: dict[socket.socket, SimDevice] = {}
        self._queue: list[tuple[float, int, socket.socket, bytes, tuple[str, int]]] = []
        self._seq = itertools.count()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        for d in devices:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((HOST, d.port))
            s.setblocking(False)
            d.port = s.getsockname()[1]
            self._socks[s] = d

    @property
    def addresses(self) -> list[tuple[str, int]]:
        return [d.addr for d in self.devices]

    def start(self) -> "Simulator":
        self._thread = threading.Thread(target=self._loop, name="bacnet-sim", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(2)
        for s in self._socks:
            s.close()

    def __enter__(self) -> "Simulator":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ loop
    def _loop(self) -> None:
        socks = list(self._socks)
        while not self._stop.is_set():
            now = time.monotonic()
            while self._queue and self._queue[0][0] <= now:
                _, _, s, data, dst = heapq.heappop(self._queue)
                try:
                    s.sendto(data, dst)
                except OSError:
                    pass
            timeout = 0.02 if not self._queue else max(0.0, min(0.02, self._queue[0][0] - now))
            try:
                ready, _, _ = select.select(socks, [], [], timeout)
            except (OSError, ValueError):
                return
            for s in ready:
                try:
                    data, src = s.recvfrom(65535)
                except OSError:
                    continue
                dev = self._socks[s]
                try:
                    for reply, dst in self._handle(dev, data, src):
                        self._reply(s, dev, reply, dst)
                except Exception:  # noqa: BLE001 - a simulator bug must not kill the thread mid-test
                    continue

    def _reply(self, s: socket.socket, dev: SimDevice, data: bytes, dst: tuple[str, int]) -> None:
        heapq.heappush(self._queue, (time.monotonic() + dev.delay, next(self._seq), s, data, dst))

    # ------------------------------------------------------------------ protocol
    def _handle(self, dev: SimDevice, data: bytes, src: tuple[str, int]) -> list[tuple[bytes, tuple[str, int]]]:
        msg = decode_message(data)
        dev.received.append(msg.kind)
        if dev.drop_all or msg.bvlc is None:
            return []
        f = msg.bvlc.function
        if f == BF.READ_BDT:
            if dev.silent_bvlc:
                return []
            return [(B.encode_read_bdt_ack(dev.bdt) if dev.bbmd else B.encode_result(BvlcResult.READ_BDT_NAK), src)]
        if f == BF.READ_FDT:
            if dev.silent_bvlc:
                return []
            return [(B.encode_read_fdt_ack(dev.fdt) if dev.bbmd else B.encode_result(BvlcResult.READ_FDT_NAK), src)]
        if f == BF.REGISTER_FOREIGN_DEVICE:
            if not dev.bbmd:
                return [(B.encode_result(BvlcResult.REGISTER_FOREIGN_DEVICE_NAK), src)]
            dev.fdt = [e for e in dev.fdt if (e.ip, e.port) != src]
            dev.fdt.append(FdtEntry(src[0], src[1], msg.bvlc.ttl or 0, (msg.bvlc.ttl or 0) + 30))
            return [(B.encode_result(BvlcResult.SUCCESSFUL_COMPLETION), src)]
        if f == BF.DISTRIBUTE_BROADCAST_TO_NETWORK:
            if not dev.bbmd or all((e.ip, e.port) != src for e in dev.fdt):
                return [(B.encode_result(BvlcResult.DISTRIBUTE_BROADCAST_TO_NETWORK_NAK), src)]
            fwd = B.encode_forwarded_npdu(src[0], src[1], msg.bvlc.npdu or b"")
            out = [(fwd, d.addr) for d in self.devices if d is not dev]
            return out + self._npdu(dev, msg, src)
        if f == BF.FORWARDED_NPDU and msg.bvlc.origin:
            return self._npdu(dev, msg, msg.bvlc.origin)
        if f in (BF.ORIGINAL_UNICAST_NPDU, BF.ORIGINAL_BROADCAST_NPDU):
            return self._npdu(dev, msg, src)
        return []

    def _npdu(self, dev: SimDevice, msg: Any, reply_to: tuple[str, int]) -> list[tuple[bytes, tuple[str, int]]]:
        if msg.npdu is None or msg.apdu is None:
            return []
        n, ap = msg.npdu, msg.apdu
        targets: list[tuple[SimDevice, int | None, bytes | None]] = []
        if n.dnet is None:
            if dev.instance is not None:
                targets.append((dev, None, None))
            if ap.pdu_type == PduType.UNCONFIRMED_REQUEST:  # local broadcast also reaches routed children
                targets += [(c, dev.remote_net, bytes([i + 1])) for i, c in enumerate(dev.remote)]
        elif n.dnet in (dev.remote_net, 0xFFFF):
            for i, c in enumerate(dev.remote):
                if not n.dadr or n.dadr == bytes([i + 1]):
                    targets.append((c, dev.remote_net, bytes([i + 1])))
        out = []
        for target, snet, sadr in targets:
            apdu = self._apdu(target, ap, msg)
            if apdu is not None:
                npdu = N.encode_npdu(apdu, snet=snet, sadr=sadr) if snet is not None else N.encode_npdu(apdu)
                out.append((B.encode_original_unicast(npdu), reply_to))
        return out

    def _apdu(self, dev: SimDevice, ap: A.Apdu, msg: Any) -> bytes | None:
        if dev.drop_all:
            return None
        if ap.pdu_type == PduType.UNCONFIRMED_REQUEST and ap.service == US.WHO_IS:
            if not dev.answer_whois or dev.instance is None:
                return None
            rng = msg.decoded
            if rng is not None and not rng[0] <= dev.instance <= rng[1]:
                return None
            return A.encode_i_am(dev.instance, dev.max_apdu, dev.segmentation, dev.vendor_id)
        if ap.pdu_type != PduType.CONFIRMED_REQUEST or dev.instance is None:
            return None
        dev._confirmed_seen += 1
        if dev._confirmed_seen <= dev.drop_first:
            return None
        inv = ap.invoke_id or 0
        if ap.service == CS.READ_PROPERTY:
            req = msg.decoded
            err = self._object_error(dev, req.object_type, req.instance)
            if err:
                return A.encode_error(inv, CS.READ_PROPERTY, *err)
            ok, val = self._value(dev, req.property_id, req.index)
            if not ok:
                return A.encode_error(inv, CS.READ_PROPERTY, *val)
            return A.encode_read_property_ack(inv, ObjectType.DEVICE, dev.instance, req.property_id, val, req.index)
        if ap.service == CS.READ_PROPERTY_MULTIPLE:
            if not dev.rpm:
                return A.encode_reject(inv, RejectReason.UNRECOGNIZED_SERVICE)
            results = []
            for spec in msg.decoded:
                err = self._object_error(dev, spec.object_type, spec.instance)
                if err:
                    return A.encode_error(inv, CS.READ_PROPERTY_MULTIPLE, *err)
                for pid, idx in spec.properties:
                    ok, val = self._value(dev, pid, idx)
                    results.append(A.RpmResult(ObjectType.DEVICE, dev.instance, pid, idx,
                                               val if ok else None, None if ok else val))
            ack = A.encode_rpm_ack(inv, results)
            if len(ack) > dev.max_apdu:
                return A.encode_abort(inv, AbortReason.SEGMENTATION_NOT_SUPPORTED)
            return ack
        return A.encode_reject(inv, RejectReason.UNRECOGNIZED_SERVICE)

    @staticmethod
    def _object_error(dev: SimDevice, otype: int, inst: int) -> tuple[int, int] | None:
        if otype != ObjectType.DEVICE:
            return (ErrorClass.OBJECT, ErrorCode.UNKNOWN_OBJECT)
        if inst == MAX_INSTANCE and not dev.answer_wildcard:
            return (ErrorClass.OBJECT, ErrorCode.UNKNOWN_OBJECT)
        if inst not in (dev.instance, MAX_INSTANCE):
            return (ErrorClass.OBJECT, ErrorCode.UNKNOWN_OBJECT)
        return None

    @staticmethod
    def _value(dev: SimDevice, pid: int, index: int | None) -> tuple[bool, Any]:
        table = dev.property_table()
        if pid not in table:
            return False, (ErrorClass.PROPERTY, ErrorCode.UNKNOWN_PROPERTY)
        val = table[pid]
        if index is not None:
            if not isinstance(val, list) or isinstance(val, list) and val and isinstance(val[0], bool):
                return False, (ErrorClass.PROPERTY, ErrorCode.PROPERTY_IS_NOT_AN_ARRAY)
            if index == 0:
                return True, len(val)
            if index > len(val):
                return False, (ErrorClass.PROPERTY, ErrorCode.INVALID_ARRAY_INDEX)
            return True, val[index - 1]
        return True, val
