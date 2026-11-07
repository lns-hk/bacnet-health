"""BACnet Virtual Link Control for BACnet/IP (ASHRAE 135 Annex J)."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire.constants import BVLC_TYPE_BIP, BvlcFunction
from bacnet_health.wire.errors import DecodeError

_NPDU_FUNCTIONS = {
    BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK,
    BvlcFunction.ORIGINAL_UNICAST_NPDU,
    BvlcFunction.ORIGINAL_BROADCAST_NPDU,
}
_EMPTY_FUNCTIONS = {BvlcFunction.READ_BDT, BvlcFunction.READ_FDT}


@dataclass
class Bvlc:
    function: int
    length: int
    npdu: bytes | None = None
    origin: tuple[str, int] | None = None  # Forwarded-NPDU originator, or Delete-FDT-Entry target
    result_code: int | None = None
    bdt: list[BdtEntry] | None = None  # Read-BDT-Ack and Write-BDT
    fdt: list[FdtEntry] | None = None  # Read-FDT-Ack
    ttl: int | None = None  # Register-Foreign-Device


def _ip(b: bytes) -> str:
    return str(ipaddress.IPv4Address(b))


def _ip_bytes(ip: str) -> bytes:
    return ipaddress.IPv4Address(ip).packed


def decode_bvlc(data: bytes) -> Bvlc:
    """Decode a BVLL header and its function-specific body. Trailing octets past the BVLC length are ignored."""
    if len(data) < 4:
        raise DecodeError("bvlc: shorter than 4 octets")
    if data[0] != BVLC_TYPE_BIP:
        raise DecodeError(f"bvlc: type 0x{data[0]:02x} is not BACnet/IP (0x81)")
    function = data[1]
    length = int.from_bytes(data[2:4], "big")
    if length < 4:
        raise DecodeError("bvlc: length field < 4")
    if length > len(data):
        raise DecodeError(f"bvlc: length field {length} exceeds datagram ({len(data)})")
    body = bytes(data[4:length])
    out = Bvlc(function=function, length=length)

    if function in _NPDU_FUNCTIONS:
        out.npdu = body
    elif function == BvlcFunction.FORWARDED_NPDU:
        if len(body) < 6:
            raise DecodeError("bvlc: Forwarded-NPDU shorter than originator address")
        out.origin = (_ip(body[:4]), int.from_bytes(body[4:6], "big"))
        out.npdu = body[6:]
    elif function == BvlcFunction.RESULT:
        if len(body) != 2:
            raise DecodeError("bvlc: BVLC-Result must carry a 2-octet code")
        out.result_code = int.from_bytes(body, "big")
    elif function in (BvlcFunction.READ_BDT_ACK, BvlcFunction.WRITE_BDT):
        if len(body) % 10:
            raise DecodeError("bvlc: BDT length not a multiple of 10")
        out.bdt = [
            BdtEntry(ip=_ip(body[i : i + 4]), port=int.from_bytes(body[i + 4 : i + 6], "big"), mask=_ip(body[i + 6 : i + 10]))
            for i in range(0, len(body), 10)
        ]
    elif function == BvlcFunction.READ_FDT_ACK:
        if len(body) % 10:
            raise DecodeError("bvlc: FDT length not a multiple of 10")
        out.fdt = [
            FdtEntry(
                ip=_ip(body[i : i + 4]),
                port=int.from_bytes(body[i + 4 : i + 6], "big"),
                ttl=int.from_bytes(body[i + 6 : i + 8], "big"),
                remaining=int.from_bytes(body[i + 8 : i + 10], "big"),
            )
            for i in range(0, len(body), 10)
        ]
    elif function == BvlcFunction.REGISTER_FOREIGN_DEVICE:
        if len(body) != 2:
            raise DecodeError("bvlc: Register-Foreign-Device must carry a 2-octet TTL")
        out.ttl = int.from_bytes(body, "big")
    elif function == BvlcFunction.DELETE_FDT_ENTRY:
        if len(body) != 6:
            raise DecodeError("bvlc: Delete-FDT-Entry must carry a 6-octet address")
        out.origin = (_ip(body[:4]), int.from_bytes(body[4:6], "big"))
    elif function in _EMPTY_FUNCTIONS:
        if body:
            raise DecodeError("bvlc: unexpected payload")
    # Secure-BVLL (0x0C) and unknown functions: header only, body not interpreted.
    return out


def _frame(function: int, body: bytes = b"") -> bytes:
    length = 4 + len(body)
    if length > 0xFFFF:
        raise ValueError("BVLC frame too long")
    return bytes([BVLC_TYPE_BIP, function]) + length.to_bytes(2, "big") + body


# ---- client side -----------------------------------------------------------------------------------------------------


def encode_original_unicast(npdu: bytes) -> bytes:
    return _frame(BvlcFunction.ORIGINAL_UNICAST_NPDU, npdu)


def encode_original_broadcast(npdu: bytes) -> bytes:
    return _frame(BvlcFunction.ORIGINAL_BROADCAST_NPDU, npdu)


def encode_distribute_broadcast(npdu: bytes) -> bytes:
    return _frame(BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK, npdu)


def encode_read_bdt() -> bytes:
    return _frame(BvlcFunction.READ_BDT)


def encode_read_fdt() -> bytes:
    return _frame(BvlcFunction.READ_FDT)


def encode_register_foreign_device(ttl: int) -> bytes:
    if not 0 <= ttl <= 0xFFFF:
        raise ValueError("ttl out of range")
    return _frame(BvlcFunction.REGISTER_FOREIGN_DEVICE, ttl.to_bytes(2, "big"))


# ---- responder side (simulator / synthetic captures only) ------------------------------------------------------------


def encode_result(code: int) -> bytes:
    return _frame(BvlcFunction.RESULT, code.to_bytes(2, "big"))


def encode_read_bdt_ack(entries: list[BdtEntry]) -> bytes:
    body = b"".join(_ip_bytes(e.ip) + e.port.to_bytes(2, "big") + _ip_bytes(e.mask) for e in entries)
    return _frame(BvlcFunction.READ_BDT_ACK, body)


def encode_read_fdt_ack(entries: list[FdtEntry]) -> bytes:
    body = b"".join(
        _ip_bytes(e.ip) + e.port.to_bytes(2, "big") + e.ttl.to_bytes(2, "big") + e.remaining.to_bytes(2, "big")
        for e in entries
    )
    return _frame(BvlcFunction.READ_FDT_ACK, body)


def encode_forwarded_npdu(origin_ip: str, origin_port: int, npdu: bytes) -> bytes:
    return _frame(BvlcFunction.FORWARDED_NPDU, _ip_bytes(origin_ip) + origin_port.to_bytes(2, "big") + npdu)
