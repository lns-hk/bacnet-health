from __future__ import annotations

import pytest

from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.message import decode_message, looks_like_bacnet

from helpers import frames as F


def uni(apdu: bytes) -> bytes:
    return B.encode_original_unicast(N.encode_npdu(apdu))


@pytest.mark.parametrize(
    "frame,kind,service",
    [
        (B.encode_original_broadcast(N.encode_npdu(A.encode_who_is())), "who-is", "who-is"),
        (uni(A.encode_i_am(5)), "i-am", "i-am"),
        (uni(A.encode_read_property(1, 8, 5, 77)), "read-property", "read-property"),
        (uni(A.encode_rpm(1, 8, 5, [(77, None)])), "rpm", "read-property-multiple"),
        (uni(A.encode_read_property_ack(1, 8, 5, 77, "x")), "rp-ack", "read-property"),
        (uni(A.encode_rpm_ack(1, [A.RpmResult(8, 5, 77, None, "x")])), "rpm-ack", "read-property-multiple"),
        (uni(A.encode_error(1, 12, 2, 32)), "error", "read-property"),
        (uni(A.encode_reject(1, 9)), "reject", None),
        (uni(A.encode_abort(1, 4)), "abort", None),
        (uni(A.encode_simple_ack(1, 15)), "simple-ack", "write-property"),
        (uni(F.SEGMENT_ACK), "segment-ack", None),
        (uni(A.encode_complex_ack(1, 6, b"")), "complex-ack", "atomic-read-file"),
        (B.encode_read_bdt(), "bvlc:read-bdt", None),
        (B.encode_read_fdt(), "bvlc:read-fdt", None),
        (B.encode_result(0), "bvlc:result", None),
        (B.encode_register_foreign_device(60), "bvlc:register-foreign-device", None),
        (B.encode_read_bdt_ack([BdtEntry("192.0.2.1", 47808, "255.255.255.255")]), "bvlc:read-bdt-ack", None),
        (B.encode_read_fdt_ack([FdtEntry("192.0.2.1", 47808, 60, 30)]), "bvlc:read-fdt-ack", None),
        (F.WRITE_BDT, "bvlc:write-bdt", None),
        (F.DELETE_FDT_ENTRY, "bvlc:delete-fdt-entry", None),
        (F.FORWARDED_WHO_IS, "who-is", "who-is"),
        (F.NET_WHO_IS_ROUTER, "net:who-is-router-to-network", "who-is-router-to-network"),
        (F.NET_PROPRIETARY, "net:unknown-192", "unknown-192"),
        (uni(F.SEGMENTED_READ_PROPERTY), "read-property", "read-property"),
    ],
)
def test_kinds(frame, kind, service):
    m = decode_message(frame)
    assert m.decode_error is None, m.decode_error
    assert (m.kind, m.service_name) == (kind, service)


@pytest.mark.parametrize("kind", sorted(F.PROHIBITED_CONFIRMED))
def test_prohibited_confirmed_kinds(kind):
    m = decode_message(F.unicast(F.PROHIBITED_CONFIRMED[kind]))
    assert m.kind == kind and m.decode_error is None


@pytest.mark.parametrize("kind", sorted(F.PROHIBITED_UNCONFIRMED))
def test_prohibited_unconfirmed_kinds(kind):
    m = decode_message(F.broadcast(F.PROHIBITED_UNCONFIRMED[kind]))
    assert m.kind == kind and m.decode_error is None


def test_decoded_objects():
    m = decode_message(uni(A.encode_i_am(77, vendor_id=9)))
    assert isinstance(m.decoded, A.IAm) and m.decoded.device_instance == 77
    m = decode_message(F.unicast(F.WRITE_PROPERTY))
    assert m.decoded["property_id"] == 85
    m = decode_message(F.unicast(F.DCC))
    assert m.decoded["enable_disable"] == 1
    m = decode_message(F.NET_WHO_IS_ROUTER)
    assert m.decoded == {"network": None}
    m = decode_message(F.FORWARDED_WHO_IS)
    assert m.bvlc.origin == ("192.0.2.9", 47808) and m.decoded is None
    m = decode_message(uni(F.SEGMENTED_READ_PROPERTY))
    assert m.decoded is None  # segments are not decoded


def test_routed_i_am():
    m = decode_message(B.encode_original_unicast(N.encode_npdu(A.encode_i_am(3), snet=10, sadr=b"\x05")))
    assert m.kind == "i-am" and m.npdu.snet == 10 and m.npdu.sadr == b"\x05"


@pytest.mark.parametrize(
    "frame,kind,layer",
    [
        (b"", "malformed", "bvlc"),
        (b"\x81\x0a\x00\x05\x02", "malformed-npdu", "npdu"),
        (b"\x81\x0a\x00\x06\x01\x00", "malformed-npdu", "npdu"),
        (b"\x81\x0a\x00\x07\x01\x00\x80", "malformed-apdu", "apdu"),
        (b"\x81\x0a\x00\x08\x01\x00\x10\x00", "i-am", "service"),
        (b"\x81\x0b\x00\x08\x01\x80\x03\x01", "net:reject-message-to-network", "service"),
    ],
)
def test_errors_reported_per_layer(frame, kind, layer):
    m = decode_message(frame)
    assert (m.kind, m.error_layer) == (kind, layer) and m.decode_error


def test_looks_like_bacnet():
    assert looks_like_bacnet(B.encode_read_bdt())
    assert not looks_like_bacnet(B.encode_read_bdt() + b"\x00")
    assert not looks_like_bacnet(b"\x81\x20\x00\x04")
    assert not looks_like_bacnet(b"\x45\x00\x00\x04")
    assert not looks_like_bacnet(b"\x81")
