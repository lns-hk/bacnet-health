"""Synthetic BACnet/IP captures for tests and demos.

Only responder/observer frames that the package can encode are available here. Frames for prohibited client services
(WriteProperty, DCC, ...) are built by hand in ``tests/helpers/frames.py`` and passed in with :meth:`Synth.raw`.
All addresses must be from documentation or private ranges.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from bacnet_health.capture.link import build_udp_frame
from bacnet_health.capture.pcap import PcapWriter
from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire.constants import ConfirmedService as CS
from bacnet_health.wire.constants import NetworkMessage, PropertyId, Segmentation
from bacnet_health.wire.npdu import encode_network_list, encode_network_message, encode_npdu

PORT = 47808
Addr = tuple[str, int]


def _bcast_of(ip: str) -> str:
    return ip.rsplit(".", 1)[0] + ".255"


@dataclass
class Synth:
    t0: float = 1_767_225_600.0  # 2026-01-01T00:00:00Z
    frames: list[tuple[float, bytes]] = field(default_factory=list)

    # ---- generic ------------------------------------------------------------------------------------------------
    def raw(self, t: float, src: Addr, dst: Addr, payload: bytes) -> None:
        self.frames.append((self.t0 + t, build_udp_frame(src[0], src[1], dst[0], dst[1], payload)))

    def save(self, path: str) -> str:
        with PcapWriter(path) as w:
            for ts, frame in sorted(self.frames, key=lambda x: x[0]):
                w.write(ts, frame)
        return path

    def _uni(self, t: float, src: Addr, dst: Addr, apdu: bytes, **npdu_kw) -> None:
        self.raw(t, src, dst, B.encode_original_unicast(encode_npdu(apdu, **npdu_kw)))

    def _bc(self, t: float, src: Addr, apdu: bytes, **npdu_kw) -> None:
        self.raw(t, src, (_bcast_of(src[0]), PORT), B.encode_original_broadcast(encode_npdu(apdu, **npdu_kw)))

    # ---- discovery ----------------------------------------------------------------------------------------------
    def whois(self, t: float, src: Addr, low: int | None = None, high: int | None = None) -> None:
        self._bc(t, src, A.encode_who_is(low, high))

    def iam(self, t: float, src: Addr, instance: int, vendor_id: int = 5, *, snet: int | None = None,
            sadr: bytes | None = None, max_apdu: int = 1476, segmentation: int = Segmentation.NONE,
            broadcast: bool = True, dst: Addr | None = None) -> None:
        ap = A.encode_i_am(instance, max_apdu=max_apdu, segmentation=segmentation, vendor_id=vendor_id)
        kw = {"snet": snet, "sadr": sadr} if snet is not None else {}
        if broadcast:
            self._bc(t, src, ap, **kw)
        else:
            self._uni(t, src, dst or (_bcast_of(src[0]), PORT), ap, **kw)

    # ---- confirmed transactions ---------------------------------------------------------------------------------
    def read_property(self, t: float, client: Addr, server: Addr, invoke_id: int, instance: int,
                      prop: int = PropertyId.PRESENT_VALUE, obj_type: str = "device") -> None:
        self._uni(t, client, server, A.encode_read_property(invoke_id, obj_type, instance, prop),
                  expecting_reply=True)

    def rp_ack(self, t: float, server: Addr, client: Addr, invoke_id: int, instance: int, prop: int, value,
               obj_type: str = "device") -> None:
        self._uni(t, server, client, A.encode_read_property_ack(invoke_id, obj_type, instance, prop, value))

    def reject(self, t: float, server: Addr, client: Addr, invoke_id: int, reason: int) -> None:
        self._uni(t, server, client, A.encode_reject(invoke_id, reason))

    def abort(self, t: float, server: Addr, client: Addr, invoke_id: int, reason: int) -> None:
        self._uni(t, server, client, A.encode_abort(invoke_id, reason, server=True))

    def error(self, t: float, server: Addr, client: Addr, invoke_id: int, error_class: int, error_code: int,
              service: int = CS.READ_PROPERTY) -> None:
        self._uni(t, server, client, A.encode_error(invoke_id, service, error_class, error_code))

    # ---- BBMD / network layer -----------------------------------------------------------------------------------
    def forwarded(self, t: float, bbmd: Addr, origin: Addr, apdu: bytes, dst: Addr | None = None) -> None:
        self.raw(t, bbmd, dst or (_bcast_of(bbmd[0]), PORT),
                 B.encode_forwarded_npdu(origin[0], origin[1], encode_npdu(apdu)))

    def read_bdt_ack(self, t: float, bbmd: Addr, client: Addr, entries: list[BdtEntry]) -> None:
        self.raw(t, bbmd, client, B.encode_read_bdt_ack(entries))

    def read_fdt_ack(self, t: float, bbmd: Addr, client: Addr, entries: list[FdtEntry]) -> None:
        self.raw(t, bbmd, client, B.encode_read_fdt_ack(entries))

    def i_am_router(self, t: float, router: Addr, networks: list[int]) -> None:
        self.raw(t, router, (_bcast_of(router[0]), PORT), B.encode_original_broadcast(
            encode_network_message(NetworkMessage.I_AM_ROUTER_TO_NETWORK, encode_network_list(networks))))

    def reject_to_network(self, t: float, router: Addr, dst: Addr, reason: int, network: int) -> None:
        payload = bytes([reason]) + network.to_bytes(2, "big")
        self.raw(t, router, dst, B.encode_original_unicast(
            encode_network_message(NetworkMessage.REJECT_MESSAGE_TO_NETWORK, payload)))


def demo_capture(path: str) -> str:
    """A ~10-minute capture of a small, unhealthy network: used for docs/samples and the GUI demo button."""
    s = Synth()
    ws = ("192.0.2.10", 47808)  # BMS workstation
    devs = [("192.0.2.%d" % (20 + i), 47808) for i in range(8)]
    router = ("192.0.2.40", 47808)
    # periodic global Who-Is from the workstation every 5 s and every device answering
    for k in range(120):
        t = k * 5.0
        s.whois(t, ws)
        for i, d in enumerate(devs):
            s.iam(t + 0.01 * (i + 1), d, 1000 + i, vendor_id=5)
        s.iam(t + 0.2, router, 2001, vendor_id=24, snet=5, sadr=b"\x07")
        s.iam(t + 0.21, router, 2002, vendor_id=24, snet=5, sadr=b"\x08")
    # duplicate device instance: a second controller also claims 1003
    for k in range(0, 120, 2):
        s.iam(k * 5.0 + 0.3, ("192.0.2.31", 47808), 1003, vendor_id=8)
    # non-standard port device
    for k in range(0, 120, 3):
        s.iam(k * 5.0 + 0.35, ("192.0.2.32", 47809), 1100, vendor_id=8)
    # a burst of Who-Is from a misbehaving controller (storm)
    for j in range(300):
        s.whois(200.0 + j * 0.03, ("192.0.2.25", 47808), 0, 4194302)
    # duplicated forwarded broadcasts via two BBMDs into this subnet
    for k in range(30):
        j = k % 6
        remote_origin = ("198.51.100.%d" % (20 + j), 47808)
        ap = A.encode_i_am(3000 + j, vendor_id=5)
        s.forwarded(k * 10.0 + 1.0, ("192.0.2.2", 47808), remote_origin, ap)
        s.forwarded(k * 10.0 + 1.01, ("192.0.2.3", 47808), remote_origin, ap)
    # two routers announcing the same network
    s.i_am_router(50.0, router, [5])
    s.i_am_router(51.0, ("192.0.2.41", 47808), [5])
    s.reject_to_network(52.0, router, ws, 1, 9)
    return s.save(path)
