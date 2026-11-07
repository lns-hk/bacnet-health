"""BACnet network layer PDU (ASHRAE 135 clause 6.2)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from bacnet_health.wire.constants import BACNET_PROTOCOL_VERSION, NetworkMessage
from bacnet_health.wire.errors import DecodeError

CTRL_NETWORK_MESSAGE = 0x80
CTRL_DNET = 0x20
CTRL_SNET = 0x08
CTRL_EXPECTING_REPLY = 0x04
CTRL_PRIORITY_MASK = 0x03


@dataclass
class Npdu:
    control: int
    dnet: int | None = None
    dadr: bytes | None = None  # b"" means broadcast on DNET
    snet: int | None = None
    sadr: bytes | None = None
    hop_count: int | None = None  # present only with DNET
    expecting_reply: bool = False
    priority: int = 0  # 0 normal, 1 urgent, 2 critical-equipment, 3 life-safety
    network_message: int | None = None
    network_payload: bytes | None = None
    apdu: bytes | None = None
    vendor_id: int | None = None  # proprietary network messages (type >= 0x80)

    @property
    def is_network_message(self) -> bool:
        return self.network_message is not None


def decode_npdu(data: bytes) -> Npdu:
    n = len(data)
    if n < 2:
        raise DecodeError("npdu: shorter than 2 octets")
    if data[0] != BACNET_PROTOCOL_VERSION:
        raise DecodeError(f"npdu: protocol version {data[0]} != 1")
    control = data[1]
    pos = 2
    out = Npdu(
        control=control,
        expecting_reply=bool(control & CTRL_EXPECTING_REPLY),
        priority=control & CTRL_PRIORITY_MASK,
    )

    def need(k: int, what: str) -> None:
        if pos + k > n:
            raise DecodeError(f"npdu: truncated {what}")

    if control & CTRL_DNET:
        need(3, "DNET/DLEN")
        out.dnet = int.from_bytes(data[pos : pos + 2], "big")
        dlen = data[pos + 2]
        pos += 3
        need(dlen, "DADR")
        out.dadr = bytes(data[pos : pos + dlen])
        pos += dlen
    if control & CTRL_SNET:
        need(3, "SNET/SLEN")
        out.snet = int.from_bytes(data[pos : pos + 2], "big")
        slen = data[pos + 2]
        pos += 3
        if slen == 0:
            raise DecodeError("npdu: SLEN of 0 is invalid")
        need(slen, "SADR")
        out.sadr = bytes(data[pos : pos + slen])
        pos += slen
    if control & CTRL_DNET:
        need(1, "hop count")
        out.hop_count = data[pos]
        pos += 1
    if control & CTRL_NETWORK_MESSAGE:
        need(1, "network message type")
        out.network_message = data[pos]
        pos += 1
        if out.network_message >= 0x80:
            need(2, "vendor id")
            out.vendor_id = int.from_bytes(data[pos : pos + 2], "big")
            pos += 2
        out.network_payload = bytes(data[pos:])
    else:
        if pos >= n:
            raise DecodeError("npdu: no APDU")
        out.apdu = bytes(data[pos:])
    return out


def _header(
    control: int,
    dnet: int | None,
    dadr: bytes | None,
    snet: int | None,
    sadr: bytes | None,
    hop_count: int,
) -> bytes:
    out = bytearray()
    if dnet is not None:
        control |= CTRL_DNET
        dadr = dadr or b""
        out += dnet.to_bytes(2, "big") + bytes([len(dadr)]) + dadr
    if snet is not None:
        if not sadr:
            raise ValueError("SNET requires a non-empty SADR")
        control |= CTRL_SNET
        out += snet.to_bytes(2, "big") + bytes([len(sadr)]) + sadr
    if dnet is not None:
        out.append(hop_count)
    return bytes([BACNET_PROTOCOL_VERSION, control]) + bytes(out)


def encode_npdu(
    apdu: bytes,
    *,
    dnet: int | None = None,
    dadr: bytes | None = None,
    snet: int | None = None,
    sadr: bytes | None = None,
    expecting_reply: bool = False,
    hop_count: int = 255,
    priority: int = 0,
) -> bytes:
    control = (CTRL_EXPECTING_REPLY if expecting_reply else 0) | (priority & CTRL_PRIORITY_MASK)
    return _header(control, dnet, dadr, snet, sadr, hop_count) + apdu


def encode_network_message(
    msg_type: int,
    payload: bytes = b"",
    *,
    vendor_id: int | None = None,
    dnet: int | None = None,
    dadr: bytes | None = None,
    snet: int | None = None,
    sadr: bytes | None = None,
    hop_count: int = 255,
) -> bytes:
    """Network-layer message (synthetic captures / simulator only; ``txguard`` blocks these on transmit)."""
    body = bytes([msg_type])
    if msg_type >= 0x80:
        body += (vendor_id or 0).to_bytes(2, "big")
    return _header(CTRL_NETWORK_MESSAGE, dnet, dadr, snet, sadr, hop_count) + body + payload


def encode_network_list(networks: list[int]) -> bytes:
    """Payload of I-Am-Router-To-Network / Router-Busy / Router-Available: 2-octet network numbers."""
    return b"".join(n.to_bytes(2, "big") for n in networks)


def decode_network_message(msg_type: int, payload: bytes) -> dict[str, Any]:
    """Summarise the payload of the network messages the analysis needs. Unknown types -> ``{"raw": hex}``."""
    if msg_type == NetworkMessage.WHO_IS_ROUTER_TO_NETWORK:
        if len(payload) not in (0, 2):
            raise DecodeError("Who-Is-Router-To-Network: bad length")
        return {"network": int.from_bytes(payload, "big") if payload else None}
    if msg_type in (
        NetworkMessage.I_AM_ROUTER_TO_NETWORK,
        NetworkMessage.ROUTER_BUSY_TO_NETWORK,
        NetworkMessage.ROUTER_AVAILABLE_TO_NETWORK,
    ):
        if len(payload) % 2:
            raise DecodeError("network list: odd length")
        return {"networks": [int.from_bytes(payload[i : i + 2], "big") for i in range(0, len(payload), 2)]}
    if msg_type == NetworkMessage.I_COULD_BE_ROUTER_TO_NETWORK:
        if len(payload) != 3:
            raise DecodeError("I-Could-Be-Router-To-Network: bad length")
        return {"network": int.from_bytes(payload[:2], "big"), "performance": payload[2]}
    if msg_type == NetworkMessage.REJECT_MESSAGE_TO_NETWORK:
        if len(payload) != 3:
            raise DecodeError("Reject-Message-To-Network: bad length")
        return {"reason": payload[0], "network": int.from_bytes(payload[1:3], "big")}
    if msg_type == NetworkMessage.NETWORK_NUMBER_IS:
        if len(payload) != 3:
            raise DecodeError("Network-Number-Is: bad length")
        return {"network": int.from_bytes(payload[:2], "big"), "configured": bool(payload[2])}
    return {"raw": payload.hex()}
