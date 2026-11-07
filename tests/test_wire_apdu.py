from __future__ import annotations

import pytest

from bacnet_health.wire import DecodeError
from bacnet_health.wire import apdu as A
from bacnet_health.wire.constants import (
    AbortReason,
    ConfirmedService,
    ErrorClass,
    ErrorCode,
    ObjectType,
    PduType,
    PropertyId as P,
    RejectReason,
    Segmentation,
)

from helpers import frames as F


def test_who_is_vectors():
    assert A.encode_who_is().hex() == "1008"
    assert A.encode_who_is(3, 3).hex() == "100809031903"
    assert A.encode_who_is(0, 4194303).hex() == "10080900" + "1b3fffff"
    assert A.decode_who_is(b"") is None
    assert A.decode_who_is(bytes.fromhex("09031903")) == (3, 3)
    with pytest.raises(ValueError):
        A.encode_who_is(5, None)
    with pytest.raises(ValueError):
        A.encode_who_is(10, 5)


def test_i_am_vector_and_round_trip():
    data = A.encode_i_am(1234, 1476, Segmentation.NONE, 5)
    assert data.hex() == "1000c4020004d2220" + "5c4910321" + "05"
    ap = A.decode_apdu(data)
    assert (ap.pdu_type, ap.service) == (PduType.UNCONFIRMED_REQUEST, 0)
    iam = A.decode_i_am(ap.payload)
    assert (iam.device_instance, iam.max_apdu, iam.segmentation, iam.vendor_id) == (1234, 1476, 3, 5)
    assert iam.segmentation_name == "none" and iam.object_type == ObjectType.DEVICE


def test_read_property_vector_and_round_trip():
    data = A.encode_read_property(1, "device", 1234, P.PROTOCOL_SERVICES_SUPPORTED)
    assert data.hex() == "0005010c0c020004d21961"
    ap = A.decode_apdu(data)
    assert (ap.pdu_type, ap.invoke_id, ap.service, ap.max_apdu, ap.max_segments, ap.segmented_accepted) == (
        0, 1, 12, 1476, None, False)
    assert A.decode_read_property_request(ap.payload) == A.RpRequest(8, 1234, 97, None)
    ap = A.decode_apdu(A.encode_read_property(255, ObjectType.DEVICE, 7, P.OBJECT_LIST, index=0, max_apdu=480))
    assert ap.max_apdu == 480 and ap.invoke_id == 255
    assert A.decode_read_property_request(ap.payload) == A.RpRequest(8, 7, 76, 0)


def test_rpm_round_trip():
    props = [(P.OBJECT_NAME, None), (P.OBJECT_LIST, 0), (P.LOCAL_TIME, None), (300, None)]
    data = A.encode_rpm(9, "device", 42, props)
    assert data[:4].hex() == "00050" + "90e"
    specs = A.decode_rpm_request(A.decode_apdu(data).payload)
    assert specs == [A.ReadAccessSpec(8, 42, props)]
    with pytest.raises(ValueError):
        A.encode_rpm(1, 8, 1, [])


VALUES = [None, True, 7, -3, 21.5, "Main plant", b"\x01\x02", [True] * 14 + [False] * 26,
          {"type": "device", "instance": 5}, {"year": 2026, "month": 11, "day": 8, "weekday": 7},
          {"hour": 12, "minute": 30, "second": 0, "hundredths": 0}, [{"type": "device", "instance": 5},
                                                                      {"type": "analog-input", "instance": 1}]]


@pytest.mark.parametrize("value", VALUES)
def test_rp_ack_round_trip(value):
    data = A.encode_read_property_ack(4, "device", 5, P.PRESENT_VALUE, value)
    ap = A.decode_apdu(data)
    assert (ap.pdu_type, ap.invoke_id, ap.service) == (PduType.COMPLEX_ACK, 4, ConfirmedService.READ_PROPERTY)
    ack = A.decode_read_property_ack(ap.payload)
    assert (ack.object_type, ack.instance, ack.property_id, ack.index) == (8, 5, 85, None)
    assert ack.value == value


def test_rp_ack_vector():
    # RP-ACK analog-input 5 present-value REAL 72.3 (spec style example)
    data = A.encode_read_property_ack(1, "analog-input", 5, P.PRESENT_VALUE, 72.0, index=None)
    assert data.hex() == "30010c0c00000005195" + "53e44429000003f"


def test_rpm_ack_round_trip_and_rpm_support():
    pss = [False] * 40
    pss[14] = pss[12] = True
    results = [
        A.RpmResult(8, 5, P.OBJECT_NAME, None, "dev-5"),
        A.RpmResult(8, 5, P.PROTOCOL_SERVICES_SUPPORTED, None, pss),
        A.RpmResult(8, 5, P.OBJECT_LIST, 0, 12),
        A.RpmResult(8, 5, P.LOCATION, None, None, (ErrorClass.PROPERTY, ErrorCode.UNKNOWN_PROPERTY)),
        A.RpmResult(2, 1, P.PRESENT_VALUE, None, 1.5),
        A.RpmResult(8, 5, P.LOCAL_DATE, None, {"year": None, "month": 1, "day": 2, "weekday": None}),
    ]
    decoded = A.decode_rpm_ack(A.decode_apdu(A.encode_rpm_ack(3, results)).payload)
    assert decoded == results
    assert A.supports_service(decoded[1].value, ConfirmedService.READ_PROPERTY_MULTIPLE)
    assert not A.supports_service(decoded[1].value, ConfirmedService.WRITE_PROPERTY)
    assert not A.supports_service(None, 14) and not A.supports_service([True], 14)
    assert decoded[3].error == (2, 32) and not decoded[3].ok


def test_error_reject_abort_simple_ack():
    ap = A.decode_apdu(A.encode_error(7, 12, ErrorClass.PROPERTY, ErrorCode.UNKNOWN_PROPERTY))
    assert (ap.pdu_type, ap.invoke_id, ap.service) == (5, 7, 12)
    assert A.decode_error(ap.payload) == (2, 32)
    assert A.encode_error(7, 12, 2, 32).hex() == "50070c91029120"
    assert A.decode_error(bytes.fromhex("0e910191200f")) == (1, 32)  # constructed form [0]{class code}

    ap = A.decode_apdu(A.encode_reject(8, RejectReason.UNRECOGNIZED_SERVICE))
    assert (ap.pdu_type, ap.invoke_id, ap.reason) == (6, 8, 9)
    ap = A.decode_apdu(A.encode_abort(9, AbortReason.SEGMENTATION_NOT_SUPPORTED))
    assert (ap.pdu_type, ap.invoke_id, ap.reason, ap.server) == (7, 9, 4, True)
    assert A.encode_abort(9, 4, server=False).hex() == "700904"
    ap = A.decode_apdu(A.encode_simple_ack(10, 15))
    assert (ap.pdu_type, ap.invoke_id, ap.service) == (2, 10, 15)


def test_segmented_headers():
    seg = A.encode_complex_ack(5, 14, b"\xaa\xbb", segmented=True, more_follows=True, sequence=2, window=4)
    ap = A.decode_apdu(seg)
    assert (ap.segmented, ap.more_follows, ap.sequence, ap.window, ap.service, ap.payload) == (
        True, True, 2, 4, 14, b"\xaa\xbb")
    ap = A.decode_apdu(F.SEGMENTED_READ_PROPERTY)
    assert (ap.segmented, ap.sequence, ap.window, ap.service) == (True, 0, 1, 12)
    ap = A.decode_apdu(bytes([0x02 | 0x00, 0x75, 0x01, 0x0C]))  # SA=1, max-seg 7 (>64), max-apdu 5
    assert (ap.segmented_accepted, ap.max_segments, ap.max_apdu) == (True, 65, 1476)
    ap = A.decode_apdu(F.SEGMENT_ACK)
    assert (ap.pdu_type, ap.invoke_id, ap.sequence, ap.window, ap.nak, ap.server) == (4, 1, 0, 1, False, False)


def test_who_has_i_have():
    w = A.decode_who_has(F.WHO_HAS_BY_NAME[2:])
    assert (w.low, w.high, w.object, w.object_name) == (None, None, None, "Zone")
    w = A.decode_who_has(F.WHO_HAS_BY_ID[2:])
    assert (w.low, w.high, w.object) == (0, 1000, {"type": "analog-value", "instance": 1})
    h = A.decode_i_have(F.I_HAVE[2:])
    assert (h.device_instance, h.object, h.object_name) == (5, {"type": "analog-value", "instance": 1}, "Zone")


def test_security_summaries():
    assert A.decode_write_property_summary(F.WRITE_PROPERTY[4:]) == {
        "object": {"type": "analog-value", "instance": 1}, "property_id": 85, "index": None, "priority": 8}
    assert A.decode_write_property_multiple_summary(F.WRITE_PROPERTY_MULTIPLE[4:]) == {
        "objects": [{"type": "analog-value", "instance": 1}]}
    assert A.decode_dcc_summary(F.DCC[4:]) == {"duration": 5, "enable_disable": 1, "password": True}
    assert A.decode_reinitialize_summary(F.REINITIALIZE[4:]) == {"state": 1, "password": True}


@pytest.mark.parametrize("bad", ["", "00", "000501", "0805010001", "10", "2001", "200102ff", "3001", "380102",
                                 "400102", "5001", "60", "7001", "80", "f0"])
def test_apdu_malformed(bad):
    with pytest.raises(DecodeError):
        A.decode_apdu(bytes.fromhex(bad))


@pytest.mark.parametrize(
    "fn,bad",
    [
        (A.decode_who_is, "0903"),
        (A.decode_who_is, "09031903aa"),
        (A.decode_who_is, "0b4000001b400000"),  # > 4194303
        (A.decode_i_am, "c4020004d2"),
        (A.decode_i_am, "c4020004d22205c49103210500"),
        (A.decode_read_property_request, "0c020004d2"),
        (A.decode_read_property_request, "0c020004d2196129"),
        (A.decode_read_property_ack, "0c020004d219613e21"),
        (A.decode_rpm_request, ""),
        (A.decode_rpm_request, "0c020004d21e1f"),
        (A.decode_rpm_ack, "0c020004d21e29553e"),
        (A.decode_error, "9102"),
        (A.decode_i_have, "c402000005"),
    ],
)
def test_service_malformed(fn, bad):
    with pytest.raises(DecodeError):
        fn(bytes.fromhex(bad))
