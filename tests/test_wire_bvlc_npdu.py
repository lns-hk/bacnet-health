from __future__ import annotations

import pytest

from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire import DecodeError
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.constants import BvlcFunction, BvlcResult, NetworkMessage, name_of

from helpers import frames as F

# ---- BVLC ------------------------------------------------------------------------------------------------------------


def test_bvlc_known_vectors():
    assert B.encode_read_bdt().hex() == "81020004"
    assert B.encode_read_fdt().hex() == "81060004"
    assert B.encode_register_foreign_device(60).hex() == "81050006003c"
    assert B.encode_result(BvlcResult.READ_FDT_NAK).hex() == "810000060040"
    assert B.encode_original_broadcast(b"\x01\x00\x10\x08").hex() == "810b000801001008"
    assert B.encode_forwarded_npdu("192.0.2.9", 47808, b"\x01\x00\x10\x08").hex() == "8104000ec0000209bac001001008"


@pytest.mark.parametrize(
    "enc,func",
    [
        (B.encode_original_unicast, BvlcFunction.ORIGINAL_UNICAST_NPDU),
        (B.encode_original_broadcast, BvlcFunction.ORIGINAL_BROADCAST_NPDU),
        (B.encode_distribute_broadcast, BvlcFunction.DISTRIBUTE_BROADCAST_TO_NETWORK),
    ],
)
def test_npdu_carriers_round_trip(enc, func):
    b = B.decode_bvlc(enc(b"\x01\x00\x10\x08"))
    assert (b.function, b.length, b.npdu) == (func, 8, b"\x01\x00\x10\x08")


def test_bdt_fdt_round_trip():
    bdt = [BdtEntry("192.0.2.1", 47808, "255.255.255.255"), BdtEntry("198.51.100.1", 47809, "255.255.255.0")]
    fdt = [FdtEntry("203.0.113.5", 47808, 60, 75), FdtEntry("10.0.0.1", 1, 65535, 0)]
    assert B.decode_bvlc(B.encode_read_bdt_ack(bdt)).bdt == bdt
    assert B.decode_bvlc(B.encode_read_fdt_ack(fdt)).fdt == fdt
    assert B.decode_bvlc(B.encode_read_bdt_ack([])).bdt == []
    assert B.decode_bvlc(F.WRITE_BDT).bdt == [BdtEntry("192.0.2.1", 47808, "255.255.255.255")]


def test_other_functions():
    assert B.decode_bvlc(B.encode_register_foreign_device(300)).ttl == 300
    assert B.decode_bvlc(B.encode_result(0x30)).result_code == BvlcResult.REGISTER_FOREIGN_DEVICE_NAK
    fwd = B.decode_bvlc(B.encode_forwarded_npdu("192.0.2.9", 47809, b"\x01\x00\x10\x08"))
    assert fwd.origin == ("192.0.2.9", 47809) and fwd.npdu == b"\x01\x00\x10\x08"
    assert B.decode_bvlc(F.DELETE_FDT_ENTRY).origin == ("192.0.2.9", 47808)
    assert B.decode_bvlc(bytes.fromhex("810c0006aabb")).npdu is None  # Secure-BVLL: header only
    assert name_of(BvlcFunction, 0x0D) == "unknown-13"


def test_trailing_bytes_ignored():
    b = B.decode_bvlc(B.encode_read_bdt() + b"\x00\x00")
    assert b.function == BvlcFunction.READ_BDT and b.length == 4


@pytest.mark.parametrize(
    "bad",
    ["", "810a00", "820a0004", "810a0003", "810a0010", "8100000500", "8103000eC0000201bac0ffff", "81020006aaaa",
     "8104000ac00002010000"[:16], "81050005ff", "810800080102"],
)
def test_bvlc_malformed(bad):
    with pytest.raises(DecodeError):
        B.decode_bvlc(bytes.fromhex(bad))


# ---- NPDU ------------------------------------------------------------------------------------------------------------


def test_npdu_local():
    n = N.decode_npdu(N.encode_npdu(b"\x10\x08"))
    assert (n.control, n.dnet, n.snet, n.hop_count, n.apdu) == (0, None, None, None, b"\x10\x08")


def test_npdu_global_broadcast_vector():
    data = N.encode_npdu(b"\x10\x08", dnet=0xFFFF)
    assert data.hex() == "0120ffff00ff1008"
    n = N.decode_npdu(data)
    assert (n.dnet, n.dadr, n.hop_count) == (0xFFFF, b"", 255)


def test_npdu_full_round_trip():
    data = N.encode_npdu(
        b"\x00\x05\x01\x0c", dnet=5, dadr=b"\x07", snet=9, sadr=b"\x0a\x0b", expecting_reply=True, hop_count=3,
        priority=3,
    )
    n = N.decode_npdu(data)
    assert n.control == 0x20 | 0x08 | 0x04 | 0x03
    assert (n.dnet, n.dadr, n.snet, n.sadr, n.hop_count, n.expecting_reply, n.priority) == (
        5, b"\x07", 9, b"\x0a\x0b", 3, True, 3)
    assert n.apdu == b"\x00\x05\x01\x0c" and n.network_message is None


def test_network_messages():
    data = N.encode_network_message(NetworkMessage.I_AM_ROUTER_TO_NETWORK, N.encode_network_list([1, 2, 300]))
    assert data.hex() == "018001000100020" + "12c"
    n = N.decode_npdu(data)
    assert n.is_network_message and n.network_message == 1 and n.apdu is None
    assert N.decode_network_message(n.network_message, n.network_payload) == {"networks": [1, 2, 300]}

    n = N.decode_npdu(N.encode_network_message(0xC0, b"\xaa", vendor_id=260))
    assert (n.network_message, n.vendor_id, n.network_payload) == (0xC0, 260, b"\xaa")

    rej = N.encode_network_message(NetworkMessage.REJECT_MESSAGE_TO_NETWORK, b"\x01\x00\x07", dnet=7, dadr=b"")
    n = N.decode_npdu(rej)
    assert n.dnet == 7 and n.hop_count == 255
    assert N.decode_network_message(3, n.network_payload) == {"reason": 1, "network": 7}
    assert N.decode_network_message(0, b"") == {"network": None}
    assert N.decode_network_message(0, b"\x00\x05") == {"network": 5}
    assert N.decode_network_message(0x12, b"") == {"raw": ""}


@pytest.mark.parametrize("bad", ["", "01", "0200", "0100", "0120ff", "0120ffff05aa", "0108000500", "0120ffff00",
                                 "0180", "0180c001"])
def test_npdu_malformed(bad):
    with pytest.raises(DecodeError):
        N.decode_npdu(bytes.fromhex(bad))


@pytest.mark.parametrize("msg,payload", [(1, b"\x00"), (3, b"\x01"), (0, b"\x01"), (2, b""), (0x13, b"")])
def test_network_payload_malformed(msg, payload):
    with pytest.raises(DecodeError):
        N.decode_network_message(msg, payload)
