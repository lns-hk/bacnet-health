"""Whole-message decoding: BVLC -> NPDU -> APDU -> service payload, with a ``kind`` classification.

:func:`decode_message` never raises. Each layer that fails sets ``decode_error`` and ``error_layer`` and leaves the
deeper layers ``None``; ``kind`` still reflects everything that could be classified.

``kind`` values:

* BVLC without NPDU: ``"bvlc:<function>"`` e.g. ``"bvlc:result"``, ``"bvlc:read-bdt-ack"``, ``"bvlc:register-foreign-device"``
* network layer: ``"net:<message>"`` e.g. ``"net:i-am-router-to-network"``, ``"net:unknown-200"`` (proprietary)
* unconfirmed: ``"who-is"``, ``"i-am"``, ``"who-has"``, ``"i-have"``, ``"time-synchronization"``,
  ``"utc-time-synchronization"``, ``"unconfirmed-cov-notification"``, ``"unconfirmed-private-transfer"``, ...
* confirmed: ``"read-property"``, ``"rpm"``, ``"write-property"``, ``"write-property-multiple"``, ``"dcc"``,
  ``"reinitialize"``, ``"subscribe-cov"``, ``"create-object"``, ``"atomic-write-file"``, ...
  (other services use their hyphenated service name)
* responses: ``"rp-ack"``, ``"rpm-ack"``, ``"complex-ack"`` (other services), ``"simple-ack"``, ``"segment-ack"``,
  ``"error"``, ``"reject"``, ``"abort"``
* failures: ``"malformed"`` (BVLC undecodable), ``"malformed-npdu"``, ``"malformed-apdu"``
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from bacnet_health.wire import apdu as A
from bacnet_health.wire.bvlc import Bvlc, decode_bvlc
from bacnet_health.wire.constants import (
    BVLC_TYPE_BIP,
    BvlcFunction,
    ConfirmedService as CS,
    NetworkMessage,
    PduType,
    UnconfirmedService as US,
    name_of,
)
from bacnet_health.wire.errors import DecodeError
from bacnet_health.wire.npdu import Npdu, decode_network_message, decode_npdu


@dataclass
class BacnetMessage:
    bvlc: Bvlc | None = None
    npdu: Npdu | None = None
    apdu: A.Apdu | None = None
    kind: str = "malformed"
    service_name: str | None = None
    decoded: Any = None
    decode_error: str | None = None
    error_layer: str | None = None  # "bvlc" | "npdu" | "apdu" | "service"


_CONFIRMED_KIND = {
    CS.READ_PROPERTY: "read-property",
    CS.READ_PROPERTY_MULTIPLE: "rpm",
    CS.DEVICE_COMMUNICATION_CONTROL: "dcc",
    CS.REINITIALIZE_DEVICE: "reinitialize",
}
_ACK_KIND = {CS.READ_PROPERTY: "rp-ack", CS.READ_PROPERTY_MULTIPLE: "rpm-ack"}

_CONFIRMED_DECODERS: dict[int, Callable[[bytes], Any]] = {
    CS.READ_PROPERTY: A.decode_read_property_request,
    CS.READ_PROPERTY_MULTIPLE: A.decode_rpm_request,
    CS.WRITE_PROPERTY: A.decode_write_property_summary,
    CS.WRITE_PROPERTY_MULTIPLE: A.decode_write_property_multiple_summary,
    CS.DEVICE_COMMUNICATION_CONTROL: A.decode_dcc_summary,
    CS.REINITIALIZE_DEVICE: A.decode_reinitialize_summary,
}
_UNCONFIRMED_DECODERS: dict[int, Callable[[bytes], Any]] = {
    US.WHO_IS: A.decode_who_is,
    US.I_AM: A.decode_i_am,
    US.WHO_HAS: A.decode_who_has,
    US.I_HAVE: A.decode_i_have,
}
_ACK_DECODERS: dict[int, Callable[[bytes], Any]] = {
    CS.READ_PROPERTY: A.decode_read_property_ack,
    CS.READ_PROPERTY_MULTIPLE: A.decode_rpm_ack,
}


def looks_like_bacnet(payload: bytes) -> bool:
    """Cheap pre-filter: BACnet/IP BVLC type, known function and a length field equal to the datagram size."""
    return (
        len(payload) >= 4
        and payload[0] == BVLC_TYPE_BIP
        and payload[1] <= max(BvlcFunction)
        and int.from_bytes(payload[2:4], "big") == len(payload)
    )


def decode_message(udp_payload: bytes) -> BacnetMessage:
    msg = BacnetMessage()
    try:
        _decode_into(msg, bytes(udp_payload))
    except DecodeError as exc:
        msg.decode_error = str(exc)
    except Exception as exc:  # pragma: no cover - defensive: a decoder bug must never abort a run
        msg.decode_error = f"internal decoder error: {type(exc).__name__}: {exc}"
        msg.error_layer = msg.error_layer or "internal"
    return msg


def _decode_into(msg: BacnetMessage, data: bytes) -> None:
    msg.error_layer = "bvlc"
    msg.bvlc = decode_bvlc(data)
    if msg.bvlc.npdu is None:
        msg.kind = "bvlc:" + name_of(BvlcFunction, msg.bvlc.function)
        msg.error_layer = None
        return

    msg.kind, msg.error_layer = "malformed-npdu", "npdu"
    msg.npdu = decode_npdu(msg.bvlc.npdu)
    if msg.npdu.network_message is not None:
        msg.kind = "net:" + name_of(NetworkMessage, msg.npdu.network_message)
        msg.service_name = name_of(NetworkMessage, msg.npdu.network_message)
        msg.error_layer = "service"
        msg.decoded = decode_network_message(msg.npdu.network_message, msg.npdu.network_payload or b"")
        msg.error_layer = None
        return

    msg.kind, msg.error_layer = "malformed-apdu", "apdu"
    assert msg.npdu.apdu is not None
    ap = msg.apdu = A.decode_apdu(msg.npdu.apdu)
    decoder: Callable[[bytes], Any] | None = None
    t = ap.pdu_type
    if t == PduType.CONFIRMED_REQUEST:
        msg.service_name = name_of(CS, ap.service)
        msg.kind = _CONFIRMED_KIND.get(ap.service, msg.service_name)  # type: ignore[arg-type]
        decoder = None if ap.segmented else _CONFIRMED_DECODERS.get(ap.service)  # type: ignore[arg-type]
    elif t == PduType.UNCONFIRMED_REQUEST:
        msg.service_name = msg.kind = name_of(US, ap.service)
        decoder = _UNCONFIRMED_DECODERS.get(ap.service)  # type: ignore[arg-type]
    elif t == PduType.COMPLEX_ACK:
        msg.service_name = name_of(CS, ap.service)
        msg.kind = _ACK_KIND.get(ap.service, "complex-ack")  # type: ignore[arg-type]
        decoder = None if ap.segmented else _ACK_DECODERS.get(ap.service)  # type: ignore[arg-type]
    elif t == PduType.ERROR:
        msg.service_name, msg.kind, decoder = name_of(CS, ap.service), "error", A.decode_error
    elif t in (PduType.SIMPLE_ACK,):
        msg.service_name, msg.kind = name_of(CS, ap.service), "simple-ack"
    else:
        msg.kind = name_of(PduType, t)  # segment-ack, reject, abort
    msg.error_layer = "service"
    if decoder is not None:
        msg.decoded = decoder(ap.payload)
    msg.error_layer = None
