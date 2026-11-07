from __future__ import annotations

import math

import pytest

from bacnet_health.wire import DecodeError
from bacnet_health.wire.constants import ObjectType, PropertyId, name_of, value_of
from bacnet_health.wire.tags import (
    Double,
    Enumerated,
    Raw,
    Signed,
    TagReader,
    closing_tag,
    decode_any_application,
    decode_tag,
    decode_values,
    encode_application,
    encode_context,
    encode_tag,
    encode_value,
    opening_tag,
)

# Known vectors (ASHRAE 135 clause 20.2 encoding examples).
VECTORS = [
    (None, "00"),
    (False, "10"),
    (True, "11"),
    (72, "2148"),
    (Signed(72), "3148"),
    (-72, "31b8"),
    (72.0, "4442900000"),
    (Double(72.0), "55084052000000000000"),
    (b"\x12\x34\xff", "631234ff"),
    ("This is a BACnet string!", "751900546869732069732061204241436e657420737472696e6721"),
    ([True, False, True, False, True], "8203a8"),
    (Enumerated(0), "9100"),
    ({"year": 1991, "month": 1, "day": 24, "weekday": 4}, "a45b011804"),
    ({"hour": 17, "minute": 35, "second": 45, "hundredths": 17}, "b411232d11"),
    ({"type": "analog-input", "instance": 15}, "c40000000f"),
]


@pytest.mark.parametrize("value,hexstr", VECTORS)
def test_application_vectors(value, hexstr):
    assert encode_application(value).hex() == hexstr
    decoded, end = decode_any_application(bytes.fromhex(hexstr))
    assert end == len(hexstr) // 2
    assert decoded == value


def test_context_vectors():
    assert encode_context(0, 72).hex() == "0948"
    assert encode_context(1, False).hex() == "1900"
    assert encode_context(33, 72).hex() == "f92148"  # extended tag number
    assert opening_tag(0).hex() == "0e" and closing_tag(0).hex() == "0f"
    assert opening_tag(20).hex() == "fe14" and closing_tag(20).hex() == "ff14"
    tag = decode_tag(bytes.fromhex("f92148"), 0)
    assert (tag.number, tag.context, tag.length) == (33, True, 1)


@pytest.mark.parametrize("length", [0, 4, 5, 253, 254, 65535, 65536])
def test_extended_length_round_trip(length):
    hdr = encode_tag(6, False, length)
    tag = decode_tag(hdr + b"\x00" * length, 0)
    assert tag.length == length and tag.start == len(hdr)


def test_extended_length_vector():
    assert encode_tag(6, False, 300).hex() == "65fe012c"


@pytest.mark.parametrize(
    "value",
    [0, 1, 255, 256, 65535, 4194303, 2**32 - 1, -1, -128, -129, 2**31 - 1, -(2**31), "", "ünïcødé ✓", b"", [False] * 9,
     [True] * 40, {"type": "device", "instance": 4194303}, {"year": None, "month": None, "day": None, "weekday": None},
     {"hour": None, "minute": 0, "second": 0, "hundredths": None}],
)
def test_round_trip(value):
    data = encode_application(value)
    assert decode_any_application(data) == (value, len(data))


def test_float_round_trip():
    v, _ = decode_any_application(encode_application(3.25))
    assert v == 3.25
    v, _ = decode_any_application(encode_application(Double(math.pi)))
    assert v == math.pi


def test_charsets():
    assert decode_any_application(b"\x75\x05\x04" + "ab".encode("utf-16-be"))[0] == "ab"
    assert decode_any_application(b"\x74\x05\xe9t\xe9")[0] == "été"
    assert decode_any_application(b"\x73\x01\x41\x42")[0] == repr(b"AB")  # IBM/DBCS -> repr
    assert decode_any_application(b"\x73\x00\xff\xfe")[0] == "��"  # invalid UTF-8 never raises


def test_values_list_and_constructed():
    data = encode_value([1, 2, 3])
    assert decode_values(data, 0, len(data)) == [1, 2, 3]
    data = encode_value([])
    assert decode_values(data, 0, len(data)) == []
    nested = opening_tag(0) + encode_application(5) + closing_tag(0) + encode_context(1, 7)
    assert decode_values(nested, 0, len(nested)) == [{"context": 0, "value": 5}, {"context": 1, "hex": "07"}]
    assert encode_value(Raw(b"\x81\x00")) == b"\x81\x00"
    assert decode_any_application(b"\x81\x00")[0] == []


def test_deep_nesting_is_decode_error():
    data = opening_tag(1) * 200 + closing_tag(1) * 200
    with pytest.raises(DecodeError):
        decode_values(data, 0, len(data))


@pytest.mark.parametrize(
    "bad",
    ["", "21", "f9", "65", "65fe00", "65ff0000", "12", "2e", "4441", "a4010203", "c4000000", "820801", "8107",
     "8201", "9900", "d0"],
)
def test_malformed_raise_decode_error(bad):
    with pytest.raises(DecodeError):
        decode_any_application(bytes.fromhex(bad))


def test_tag_reader():
    data = encode_context(0, 9) + opening_tag(3) + encode_application(1.5) + closing_tag(3) + encode_context(4, 8)
    r = TagReader(data)
    assert r.context(0, 2) == 9
    s, e = r.enclosed(3)
    assert decode_values(data, s, e) == 1.5
    assert r.optional_context(5, 2) is None
    assert r.context(4, 2) == 8
    r.expect_end()
    with pytest.raises(DecodeError):
        r.context(0, 2)


def test_names():
    assert name_of(ObjectType, 8) == "device"
    assert name_of(PropertyId, 97) == "protocol-services-supported"
    assert name_of(PropertyId, 5000) == "unknown-5000"
    assert value_of(ObjectType, "analog-value") == 2
    assert value_of(ObjectType, "unknown-300") == 300
    for pid in (75, 79, 120, 62, 107, 96, 85, 97, 77, 121, 70, 44, 12, 98, 139, 58, 28, 112, 56, 57, 119, 155, 167, 76):
        assert not name_of(PropertyId, pid).startswith("unknown")
