"""BACnet application layer PDUs (ASHRAE 135 clause 20.1) and the service payloads the tool needs (clause 21).

Client encoders here build only what the transmit allow-list permits (Who-Is, ReadProperty, ReadPropertyMultiple).
Responder encoders exist for the simulator and synthetic captures. Encoders for write/control services deliberately do
not exist in this package.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from bacnet_health.wire.constants import (
    MAX_APDU_CODES,
    MAX_INSTANCE,
    MAX_SEGMENTS_CODES,
    ApplicationTag as AT,
    ConfirmedService,
    ObjectType,
    PduType,
    Segmentation,
    UnconfirmedService,
    name_of,
    value_of,
)
from bacnet_health.wire.errors import DecodeError
from bacnet_health.wire.tags import (
    Enumerated,
    TagReader,
    closing_tag,
    decode_values,
    encode_application,
    encode_context,
    encode_value,
    opening_tag,
)

# ---------------------------------------------------------------------------------------------------------------------
# APDU header
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class Apdu:
    pdu_type: int
    service: int | None = None
    invoke_id: int | None = None
    segmented: bool = False
    more_follows: bool = False
    sequence: int | None = None
    window: int | None = None
    max_segments: int | None = None  # decoded count; None = unspecified, 65 = "more than 64"
    max_apdu: int | None = None  # decoded octets; None for reserved codes
    reason: int | None = None  # Reject / Abort reason
    payload: bytes = b""
    segmented_accepted: bool = False  # Confirmed-Request SA bit
    server: bool = False  # Segment-ACK / Abort SRV bit
    nak: bool = False  # Segment-ACK NAK bit


def decode_apdu(data: bytes) -> Apdu:
    n = len(data)
    if n < 1:
        raise DecodeError("apdu: empty")
    b0 = data[0]
    ptype = b0 >> 4
    out = Apdu(pdu_type=ptype)

    def need(k: int) -> None:
        if n < k:
            raise DecodeError(f"apdu: truncated {name_of(PduType, ptype)}")

    if ptype == PduType.CONFIRMED_REQUEST:
        out.segmented, out.more_follows = bool(b0 & 0x08), bool(b0 & 0x04)
        out.segmented_accepted = bool(b0 & 0x02)
        pos = 5 if out.segmented else 3
        need(pos + 1)
        out.max_segments = MAX_SEGMENTS_CODES[(data[1] >> 4) & 0x07]
        out.max_apdu = MAX_APDU_CODES.get(data[1] & 0x0F)
        out.invoke_id = data[2]
        if out.segmented:
            out.sequence, out.window = data[3], data[4]
        out.service = data[pos]
        out.payload = bytes(data[pos + 1 :])
    elif ptype == PduType.UNCONFIRMED_REQUEST:
        need(2)
        out.service = data[1]
        out.payload = bytes(data[2:])
    elif ptype == PduType.SIMPLE_ACK:
        need(3)
        out.invoke_id, out.service = data[1], data[2]
        if n != 3:
            raise DecodeError("apdu: SimpleACK with trailing data")
    elif ptype == PduType.COMPLEX_ACK:
        out.segmented, out.more_follows = bool(b0 & 0x08), bool(b0 & 0x04)
        pos = 4 if out.segmented else 2
        need(pos + 1)
        out.invoke_id = data[1]
        if out.segmented:
            out.sequence, out.window = data[2], data[3]
        out.service = data[pos]
        out.payload = bytes(data[pos + 1 :])
    elif ptype == PduType.SEGMENT_ACK:
        need(4)
        out.nak, out.server = bool(b0 & 0x02), bool(b0 & 0x01)
        out.invoke_id, out.sequence, out.window = data[1], data[2], data[3]
    elif ptype == PduType.ERROR:
        need(3)
        out.invoke_id, out.service = data[1], data[2]
        out.payload = bytes(data[3:])
    elif ptype in (PduType.REJECT, PduType.ABORT):
        need(3)
        out.server = bool(b0 & 0x01) if ptype == PduType.ABORT else False
        out.invoke_id, out.reason = data[1], data[2]
    else:
        raise DecodeError(f"apdu: reserved PDU type {ptype}")
    return out


def _max_apdu_code(max_apdu: int) -> int:
    for code, octets in sorted(MAX_APDU_CODES.items(), reverse=True):
        if max_apdu >= octets:
            return code
    raise ValueError("max_apdu must be >= 50")


def _confirmed_header(invoke_id: int, service: int, max_apdu: int) -> bytes:
    # Not segmented, segmented-response NOT accepted (SA=0): the tool never sends Segment-ACK, so it must not invite
    # segmented responses. Max-segments 0 (unspecified).
    if not 0 <= invoke_id <= 255:
        raise ValueError("invoke_id out of range")
    return bytes([PduType.CONFIRMED_REQUEST << 4, _max_apdu_code(max_apdu), invoke_id, service])


def _ctx_objid(tag: int, obj_type: int | str, instance: int) -> bytes:
    return encode_context(tag, {"type": obj_type, "instance": instance})


def _otype(obj_type: int | str) -> int:
    return value_of(ObjectType, obj_type)


# ---------------------------------------------------------------------------------------------------------------------
# Service objects
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class IAm:
    device_instance: int
    max_apdu: int
    segmentation: int
    vendor_id: int
    object_type: int = ObjectType.DEVICE

    @property
    def segmentation_name(self) -> str:
        return name_of(Segmentation, self.segmentation)


@dataclass
class RpRequest:
    object_type: int
    instance: int
    property_id: int
    index: int | None = None


@dataclass
class RpAck:
    object_type: int
    instance: int
    property_id: int
    index: int | None
    value: Any
    raw: bytes = b""  # encoded value octets between [3] and [/3]


@dataclass
class ReadAccessSpec:
    object_type: int
    instance: int
    properties: list[tuple[int, int | None]] = field(default_factory=list)


@dataclass
class RpmResult:
    """One property result of a ReadPropertyMultiple-ACK (flattened per property)."""

    object_type: int
    instance: int
    property_id: int
    index: int | None = None
    value: Any = None
    error: tuple[int, int] | None = None  # (error class, error code) when the property read failed

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class WhoHas:
    low: int | None
    high: int | None
    object: dict[str, Any] | None = None
    object_name: str | None = None


@dataclass
class IHave:
    device_instance: int
    object: dict[str, Any]
    object_name: str


def _objid_parts(v: dict[str, Any]) -> tuple[int, int]:
    return value_of(ObjectType, v["type"]), v["instance"]


# ---------------------------------------------------------------------------------------------------------------------
# Service decoders (each takes the APDU payload after the service choice)
# ---------------------------------------------------------------------------------------------------------------------


def decode_who_is(payload: bytes) -> tuple[int, int] | None:
    if not payload:
        return None
    r = TagReader(payload)
    low = r.context(0, AT.UNSIGNED)
    high = r.context(1, AT.UNSIGNED)
    r.expect_end()
    if low > MAX_INSTANCE or high > MAX_INSTANCE:
        raise DecodeError("who-is: limit out of range")
    return low, high


def decode_i_am(payload: bytes) -> IAm:
    r = TagReader(payload)
    otype, inst = _objid_parts(r.application(AT.OBJECT_IDENTIFIER))
    max_apdu = r.application(AT.UNSIGNED)
    seg = r.application(AT.ENUMERATED)
    vendor = r.application(AT.UNSIGNED)
    r.expect_end()
    return IAm(device_instance=inst, max_apdu=max_apdu, segmentation=seg, vendor_id=vendor, object_type=otype)


def decode_read_property_request(payload: bytes) -> RpRequest:
    r = TagReader(payload)
    otype, inst = _objid_parts(r.context(0, AT.OBJECT_IDENTIFIER))
    prop = r.context(1, AT.ENUMERATED)
    index = r.optional_context(2, AT.UNSIGNED)
    r.expect_end()
    return RpRequest(otype, inst, prop, index)


def decode_read_property_ack(payload: bytes) -> RpAck:
    r = TagReader(payload)
    otype, inst = _objid_parts(r.context(0, AT.OBJECT_IDENTIFIER))
    prop = r.context(1, AT.ENUMERATED)
    index = r.optional_context(2, AT.UNSIGNED)
    start, end = r.enclosed(3)
    r.expect_end()
    return RpAck(otype, inst, prop, index, decode_values(r.data, start, end), r.data[start:end])


def decode_rpm_request(payload: bytes) -> list[ReadAccessSpec]:
    r = TagReader(payload)
    specs: list[ReadAccessSpec] = []
    while not r.at_end():
        otype, inst = _objid_parts(r.context(0, AT.OBJECT_IDENTIFIER))
        spec = ReadAccessSpec(otype, inst)
        r.opening(1)
        while not r.peek_closing(1):
            prop = r.context(0, AT.ENUMERATED)
            spec.properties.append((prop, r.optional_context(1, AT.UNSIGNED)))
        r.closing(1)
        if not spec.properties:
            raise DecodeError("rpm: empty property list")
        specs.append(spec)
    if not specs:
        raise DecodeError("rpm: no read access specification")
    return specs


def decode_rpm_ack(payload: bytes) -> list[RpmResult]:
    r = TagReader(payload)
    results: list[RpmResult] = []
    while not r.at_end():
        otype, inst = _objid_parts(r.context(0, AT.OBJECT_IDENTIFIER))
        r.opening(1)
        while not r.peek_closing(1):
            prop = r.context(2, AT.ENUMERATED)
            index = r.optional_context(3, AT.UNSIGNED)
            res = RpmResult(otype, inst, prop, index)
            if r.peek_opening(4):
                start, end = r.enclosed(4)
                res.value = decode_values(r.data, start, end)
            else:
                r.opening(5)
                res.error = (r.application(AT.ENUMERATED), r.application(AT.ENUMERATED))
                r.closing(5)
            results.append(res)
        r.closing(1)
    return results


def decode_error(payload: bytes) -> tuple[int, int]:
    """Return (error class, error code). Handles plain Error and the constructed forms that wrap the
    error in context tag [0] (e.g. CreateObject, WritePropertyMultiple, ConfirmedPrivateTransfer)."""
    r = TagReader(payload)
    tag = r.peek()
    if tag is not None and tag.opening:
        r.opening(tag.number)
    return r.application(AT.ENUMERATED), r.application(AT.ENUMERATED)


def decode_who_has(payload: bytes) -> WhoHas:
    r = TagReader(payload)
    low = high = None
    if r.peek_context(0):
        low = r.context(0, AT.UNSIGNED)
        high = r.context(1, AT.UNSIGNED)
    if r.peek_context(2):
        out = WhoHas(low, high, object=r.context(2, AT.OBJECT_IDENTIFIER))
    else:
        out = WhoHas(low, high, object_name=r.context(3, AT.CHARACTER_STRING))
    r.expect_end()
    return out


def decode_i_have(payload: bytes) -> IHave:
    r = TagReader(payload)
    dev = r.application(AT.OBJECT_IDENTIFIER)
    obj = r.application(AT.OBJECT_IDENTIFIER)
    name = r.application(AT.CHARACTER_STRING)
    r.expect_end()
    return IHave(dev["instance"], obj, name)


# -- summaries of security-relevant requests seen passively (decode only) --------------------------------------------


def decode_write_property_summary(payload: bytes) -> dict[str, Any]:
    """WriteProperty: target object, property, index and priority (the value is not decoded)."""
    r = TagReader(payload)
    obj = r.context(0, AT.OBJECT_IDENTIFIER)
    prop = r.context(1, AT.ENUMERATED)
    index = r.optional_context(2, AT.UNSIGNED)
    r.enclosed(3)
    priority = r.optional_context(4, AT.UNSIGNED)
    return {"object": obj, "property_id": prop, "index": index, "priority": priority}


def decode_write_property_multiple_summary(payload: bytes) -> dict[str, Any]:
    """WritePropertyMultiple: list of target objects."""
    r = TagReader(payload)
    objects = []
    while not r.at_end():
        objects.append(r.context(0, AT.OBJECT_IDENTIFIER))
        r.enclosed(1)
    return {"objects": objects}


def decode_dcc_summary(payload: bytes) -> dict[str, Any]:
    """DeviceCommunicationControl: duration (minutes), enable/disable, whether a password was sent."""
    r = TagReader(payload)
    duration = r.optional_context(0, AT.UNSIGNED)
    state = r.context(1, AT.ENUMERATED)
    password = r.peek_context(2)
    return {"duration": duration, "enable_disable": state, "password": password}


def decode_reinitialize_summary(payload: bytes) -> dict[str, Any]:
    """ReinitializeDevice: reinitialized-state-of-device and whether a password was sent."""
    r = TagReader(payload)
    state = r.context(0, AT.ENUMERATED)
    return {"state": state, "password": r.peek_context(1)}


# ---------------------------------------------------------------------------------------------------------------------
# Client encoders (allow-listed)
# ---------------------------------------------------------------------------------------------------------------------


def encode_who_is(low: int | None = None, high: int | None = None) -> bytes:
    if (low is None) != (high is None):
        raise ValueError("who-is limits must both be given or both omitted")
    out = bytes([PduType.UNCONFIRMED_REQUEST << 4, UnconfirmedService.WHO_IS])
    if low is None:
        return out
    assert high is not None
    if not 0 <= low <= high <= MAX_INSTANCE:
        raise ValueError("who-is limits out of range")
    return out + encode_context(0, low) + encode_context(1, high)


def _prop_ref(prop: int, index: int | None, prop_tag: int, index_tag: int) -> bytes:
    out = encode_context(prop_tag, Enumerated(prop))
    return out + (encode_context(index_tag, index) if index is not None else b"")


def encode_read_property(
    invoke_id: int, obj_type: int | str, instance: int, prop: int, index: int | None = None, max_apdu: int = 1476
) -> bytes:
    return (
        _confirmed_header(invoke_id, ConfirmedService.READ_PROPERTY, max_apdu)
        + _ctx_objid(0, obj_type, instance)
        + _prop_ref(prop, index, 1, 2)
    )


def encode_rpm(
    invoke_id: int,
    obj_type: int | str,
    instance: int,
    props: list[tuple[int, int | None]],
    max_apdu: int = 1476,
) -> bytes:
    if not props:
        raise ValueError("rpm needs at least one property")
    body = b"".join(_prop_ref(p, i, 0, 1) for p, i in props)
    return (
        _confirmed_header(invoke_id, ConfirmedService.READ_PROPERTY_MULTIPLE, max_apdu)
        + _ctx_objid(0, obj_type, instance)
        + opening_tag(1)
        + body
        + closing_tag(1)
    )


# ---------------------------------------------------------------------------------------------------------------------
# Responder encoders (simulator / synthetic captures)
# ---------------------------------------------------------------------------------------------------------------------


def encode_i_am(
    instance: int, max_apdu: int = 1476, segmentation: int = Segmentation.NONE, vendor_id: int = 0
) -> bytes:
    return (
        bytes([PduType.UNCONFIRMED_REQUEST << 4, UnconfirmedService.I_AM])
        + encode_application({"type": ObjectType.DEVICE, "instance": instance})
        + encode_application(max_apdu)
        + encode_application(Enumerated(segmentation))
        + encode_application(vendor_id)
    )


def encode_complex_ack(
    invoke_id: int,
    service: int,
    payload: bytes,
    *,
    segmented: bool = False,
    more_follows: bool = False,
    sequence: int = 0,
    window: int = 1,
) -> bytes:
    """ComplexACK header + payload. Set ``segmented`` to build individual segments for synthetic captures."""
    if segmented:
        b0 = (PduType.COMPLEX_ACK << 4) | 0x08 | (0x04 if more_follows else 0)
        return bytes([b0, invoke_id, sequence, window, service]) + payload
    return bytes([PduType.COMPLEX_ACK << 4, invoke_id, service]) + payload


def encode_read_property_ack(
    invoke_id: int, obj_type: int | str, instance: int, prop: int, value: Any, index: int | None = None
) -> bytes:
    body = _ctx_objid(0, obj_type, instance) + _prop_ref(prop, index, 1, 2)
    body += opening_tag(3) + encode_value(value) + closing_tag(3)
    return encode_complex_ack(invoke_id, ConfirmedService.READ_PROPERTY, body)


def encode_rpm_ack(invoke_id: int, results: list[RpmResult]) -> bytes:
    """Encode results; consecutive results for the same object are grouped into one ReadAccessResult."""
    body = bytearray()
    current: tuple[int, int] | None = None
    for res in results:
        key = (_otype(res.object_type), res.instance)
        if key != current:
            if current is not None:
                body += closing_tag(1)
            body += _ctx_objid(0, *key) + opening_tag(1)
            current = key
        body += _prop_ref(res.property_id, res.index, 2, 3)
        if res.error is None:
            body += opening_tag(4) + encode_value(res.value) + closing_tag(4)
        else:
            body += opening_tag(5)
            body += encode_application(Enumerated(res.error[0])) + encode_application(Enumerated(res.error[1]))
            body += closing_tag(5)
    if current is not None:
        body += closing_tag(1)
    return encode_complex_ack(invoke_id, ConfirmedService.READ_PROPERTY_MULTIPLE, bytes(body))


def encode_error(invoke_id: int, service: int, error_class: int, error_code: int) -> bytes:
    return bytes([PduType.ERROR << 4, invoke_id, service]) + (
        encode_application(Enumerated(error_class)) + encode_application(Enumerated(error_code))
    )


def encode_reject(invoke_id: int, reason: int) -> bytes:
    return bytes([PduType.REJECT << 4, invoke_id, reason])


def encode_abort(invoke_id: int, reason: int, server: bool = True) -> bytes:
    return bytes([(PduType.ABORT << 4) | (0x01 if server else 0), invoke_id, reason])


def encode_simple_ack(invoke_id: int, service: int) -> bytes:
    return bytes([PduType.SIMPLE_ACK << 4, invoke_id, service])


# ---------------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------------


def supports_service(services_supported: Any, service: int) -> bool:
    """True if a decoded protocol-services-supported bit-string has ``service``'s bit set (e.g. 14 = RPM)."""
    return isinstance(services_supported, list) and 0 <= service < len(services_supported) and bool(
        services_supported[service]
    )


__all__ = [
    "Apdu",
    "IAm",
    "IHave",
    "ReadAccessSpec",
    "RpAck",
    "RpRequest",
    "RpmResult",
    "WhoHas",
    "decode_apdu",
    "decode_dcc_summary",
    "decode_error",
    "decode_i_am",
    "decode_i_have",
    "decode_read_property_ack",
    "decode_read_property_request",
    "decode_reinitialize_summary",
    "decode_rpm_ack",
    "decode_rpm_request",
    "decode_who_has",
    "decode_who_is",
    "decode_write_property_multiple_summary",
    "decode_write_property_summary",
    "encode_abort",
    "encode_complex_ack",
    "encode_error",
    "encode_i_am",
    "encode_read_property",
    "encode_read_property_ack",
    "encode_reject",
    "encode_rpm",
    "encode_rpm_ack",
    "encode_simple_ack",
    "encode_who_is",
    "supports_service",
]
