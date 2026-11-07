"""BACnet/IP wire codec: BVLC (Annex J), NPDU (clause 6), APDU (clause 20) and tag encoding (clause 20.2).

Decoders raise :class:`DecodeError`; :func:`decode_message` never raises. Every outgoing frame must pass
:func:`check_tx`.
"""

from __future__ import annotations

from bacnet_health.wire.errors import DecodeError
from bacnet_health.wire.constants import name_of
from bacnet_health.wire.bvlc import Bvlc, decode_bvlc
from bacnet_health.wire.npdu import Npdu, decode_npdu, encode_npdu
from bacnet_health.wire.apdu import Apdu, IAm, RpAck, RpmResult, RpRequest, decode_apdu, supports_service
from bacnet_health.wire.message import BacnetMessage, decode_message, looks_like_bacnet
from bacnet_health.wire.txguard import TxBlocked, check_tx

__all__ = [
    "Apdu",
    "BacnetMessage",
    "Bvlc",
    "DecodeError",
    "IAm",
    "Npdu",
    "RpAck",
    "RpRequest",
    "RpmResult",
    "TxBlocked",
    "check_tx",
    "decode_apdu",
    "decode_bvlc",
    "decode_message",
    "decode_npdu",
    "encode_npdu",
    "looks_like_bacnet",
    "name_of",
    "supports_service",
]
