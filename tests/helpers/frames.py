"""Hand-built frames for tests, including PROHIBITED services that must never be encodable from ``src/``.

Everything here is raw bytes assembled by hand from ASHRAE 135, deliberately without using the package encoders for the
service payloads, so the tests also act as independent vectors.
"""

from __future__ import annotations

import struct

# ---- generic wrappers ------------------------------------------------------------------------------------------------


def bvlc(function: int, body: bytes = b"") -> bytes:
    return bytes([0x81, function]) + (4 + len(body)).to_bytes(2, "big") + body


def npdu(apdu: bytes, control: int = 0x00) -> bytes:
    return bytes([0x01, control]) + apdu


def unicast(apdu: bytes, control: int = 0x04) -> bytes:
    return bvlc(0x0A, npdu(apdu, control))


def broadcast(apdu: bytes) -> bytes:
    return bvlc(0x0B, npdu(apdu))


def confirmed(service: int, payload: bytes = b"", invoke_id: int = 1) -> bytes:
    return bytes([0x00, 0x05, invoke_id, service]) + payload


def unconfirmed(service: int, payload: bytes = b"") -> bytes:
    return bytes([0x10, service]) + payload


# ---- hand-encoded primitives --------------------------------------------------------------------------------------

AV1_CTX0 = bytes.fromhex("0c00800001")  # [0] object-identifier analog-value 1
DEV5_APP = bytes.fromhex("c402000005")  # application object-identifier device 5
REAL_PV = bytes.fromhex("3e4442c800003f")  # [3]{ REAL 100.0 }

# ---- prohibited / security-relevant requests (confirmed) -------------------------------------------------------------

WRITE_PROPERTY = confirmed(15, AV1_CTX0 + b"\x19\x55" + REAL_PV + b"\x49\x08")  # PV, priority 8
WRITE_PROPERTY_MULTIPLE = confirmed(16, AV1_CTX0 + b"\x1e\x09\x55" + b"\x2e\x44\x42\xc8\x00\x00\x2f" + b"\x1f")
DCC = confirmed(17, b"\x09\x05" + b"\x19\x01" + b"\x2d\x05\x00pass")  # 5 min, disable, password
REINITIALIZE = confirmed(20, b"\x09\x01" + b"\x1d\x05\x00pass")  # warmstart, password
CREATE_OBJECT = confirmed(10, b"\x0e\x09\x02\x0f")  # [0]{ [0] object-type analog-value }
DELETE_OBJECT = confirmed(11, b"\xc4\x00\x80\x00\x01")
ATOMIC_WRITE_FILE = confirmed(7, b"\xc4\x02\x80\x00\x01" + b"\x0e\x31\x00\x62\x01\x02\x0f")
ADD_LIST_ELEMENT = confirmed(8, AV1_CTX0 + b"\x19\x35" + b"\x3e\xc4\x00\x80\x00\x02\x3f")
REMOVE_LIST_ELEMENT = confirmed(9, AV1_CTX0 + b"\x19\x35" + b"\x3e\xc4\x00\x80\x00\x02\x3f")
SUBSCRIBE_COV = confirmed(5, b"\x09\x01" + AV1_CTX0.replace(b"\x0c", b"\x1c", 1) + b"\x29\x01" + b"\x39\x3c")
CONFIRMED_COV_NOTIFICATION = confirmed(1, b"\x09\x01\x1c\x02\x00\x00\x05\x2c\x00\x80\x00\x01\x39\x3c\x4e\x09\x55\x2e\x44\x42\xc8\x00\x00\x2f\x4f")
CONFIRMED_EVENT_NOTIFICATION = confirmed(2, b"\x09\x01\x1c\x02\x00\x00\x05")
CONFIRMED_PRIVATE_TRANSFER = confirmed(18, b"\x09\x07\x19\x01")
SEGMENTED_READ_PROPERTY = bytes([0x08, 0x05, 0x01, 0x00, 0x01, 0x0C]) + AV1_CTX0 + b"\x19\x55"

# ---- unconfirmed -------------------------------------------------------------------------------------------------

UNCONFIRMED_COV_NOTIFICATION = unconfirmed(2, b"\x09\x00\x1c\x02\x00\x00\x05\x2c\x00\x80\x00\x01\x39\x00\x4e\x4f")
UNCONFIRMED_EVENT_NOTIFICATION = unconfirmed(3, b"\x09\x01\x1c\x02\x00\x00\x05")
UNCONFIRMED_PRIVATE_TRANSFER = unconfirmed(4, b"\x09\x07\x19\x01")
TIME_SYNC = unconfirmed(6, b"\xa4\x7e\x0b\x08\x07" + b"\xb4\x0c\x00\x00\x00")  # 2026-11-08 Sun 12:00
UTC_TIME_SYNC = unconfirmed(9, b"\xa4\x7e\x0b\x08\x07" + b"\xb4\x04\x00\x00\x00")
WHO_HAS_BY_NAME = unconfirmed(7, b"\x3d\x05\x00Zone")
WHO_HAS_BY_ID = unconfirmed(7, b"\x09\x00\x1a\x03\xe8" + b"\x2c\x00\x80\x00\x01")
I_HAVE = unconfirmed(1, DEV5_APP + b"\xc4\x00\x80\x00\x01" + b"\x75\x05\x00Zone")

# ---- other things the tool must not send -------------------------------------------------------------------------

SIMPLE_ACK = bytes([0x20, 0x01, 0x0F])
SEGMENT_ACK = bytes([0x40, 0x01, 0x00, 0x01])
NET_WHO_IS_ROUTER = bvlc(0x0B, bytes([0x01, 0x80, 0x00]))
NET_PROPRIETARY = bvlc(0x0B, bytes([0x01, 0x80, 0xC0, 0x01, 0x04, 0xAA]))  # type 0xC0, vendor 260
WRITE_BDT = bvlc(0x01, bytes([192, 0, 2, 1, 0xBA, 0xC0, 255, 255, 255, 255]))
DELETE_FDT_ENTRY = bvlc(0x08, bytes([192, 0, 2, 9, 0xBA, 0xC0]))
FORWARDED_WHO_IS = bvlc(0x04, bytes([192, 0, 2, 9, 0xBA, 0xC0]) + npdu(b"\x10\x08"))
BVLC_RESULT = bvlc(0x00, b"\x00\x00")

PROHIBITED_CONFIRMED = {
    "write-property": WRITE_PROPERTY,
    "write-property-multiple": WRITE_PROPERTY_MULTIPLE,
    "dcc": DCC,
    "reinitialize": REINITIALIZE,
    "create-object": CREATE_OBJECT,
    "delete-object": DELETE_OBJECT,
    "atomic-write-file": ATOMIC_WRITE_FILE,
    "add-list-element": ADD_LIST_ELEMENT,
    "remove-list-element": REMOVE_LIST_ELEMENT,
    "subscribe-cov": SUBSCRIBE_COV,
    "confirmed-cov-notification": CONFIRMED_COV_NOTIFICATION,
    "confirmed-event-notification": CONFIRMED_EVENT_NOTIFICATION,
    "confirmed-private-transfer": CONFIRMED_PRIVATE_TRANSFER,
}
PROHIBITED_UNCONFIRMED = {
    "unconfirmed-cov-notification": UNCONFIRMED_COV_NOTIFICATION,
    "unconfirmed-event-notification": UNCONFIRMED_EVENT_NOTIFICATION,
    "unconfirmed-private-transfer": UNCONFIRMED_PRIVATE_TRANSFER,
    "time-synchronization": TIME_SYNC,
    "utc-time-synchronization": UTC_TIME_SYNC,
    "who-has": WHO_HAS_BY_NAME,
    "i-have": I_HAVE,
}


# ---- minimal pcap writer (Ethernet/IPv4/UDP built by hand) ---------------------------------------------------------


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def udp_frame(src: str, sport: int, dst: str, dport: int, payload: bytes) -> bytes:
    sip = bytes(int(x) for x in src.split("."))
    dip = bytes(int(x) for x in dst.split("."))
    ulen = 8 + len(payload)
    pseudo = sip + dip + struct.pack("!BBH", 0, 17, ulen)
    udp = struct.pack("!HHHH", sport, dport, ulen, 0) + payload
    csum = _checksum(pseudo + udp) or 0xFFFF
    udp = udp[:6] + struct.pack("!H", csum) + udp[8:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + ulen, 0, 0x4000, 64, 17, 0, sip, dip)
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    eth = bytes.fromhex("ffffffffffff" if dst.endswith(".255") else "020000000002") + bytes.fromhex("020000000001")
    return eth + b"\x08\x00" + ip + udp


def write_pcap(path: str, payloads: list[bytes], src: str = "192.0.2.10", dst: str = "192.0.2.20") -> None:
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(payloads):
            frame = udp_frame(src, 47808, dst, 47808, p)
            fh.write(struct.pack("<IIII", 1_700_000_000 + i, 0, len(frame), len(frame)))
            fh.write(frame)
