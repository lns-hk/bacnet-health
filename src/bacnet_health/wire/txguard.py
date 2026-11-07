"""Transmit allow-list: the single choke point every outgoing frame passes before ``sendto()`` (design §1.1).

Allowed, and nothing else:

* BVLC Read-BDT, Read-FDT (header only) and Register-Foreign-Device (TTL only);
* BVLC Original-Unicast-NPDU carrying Who-Is, ReadProperty or ReadPropertyMultiple;
* BVLC Original-Broadcast-NPDU and Distribute-Broadcast-To-Network carrying Who-Is only.

The NPDU must not be a network-layer message and must not carry SNET/SADR. Confirmed requests must not be segmented and
their payload must decode cleanly; global/remote broadcasts (DNET 0xFFFF or empty DADR) may only carry Who-Is.
"""

from __future__ import annotations

from bacnet_health.wire.apdu import decode_apdu, decode_read_property_request, decode_rpm_request, decode_who_is
from bacnet_health.wire.bvlc import decode_bvlc
from bacnet_health.wire.constants import BvlcFunction as BF, ConfirmedService as CS, PduType, UnconfirmedService as US
from bacnet_health.wire.errors import DecodeError
from bacnet_health.wire.npdu import decode_npdu


class TxBlocked(Exception):
    """Raised when a frame is not on the transmit allow-list. Never catch this to retry with the same frame."""


_HEADER_ONLY = {BF.READ_BDT, BF.READ_FDT, BF.REGISTER_FOREIGN_DEVICE}
_BROADCAST = {BF.ORIGINAL_BROADCAST_NPDU, BF.DISTRIBUTE_BROADCAST_TO_NETWORK}


def check_tx(frame: bytes) -> None:
    try:
        _check(bytes(frame))
    except DecodeError as exc:
        raise TxBlocked(f"undecodable frame: {exc}") from None


def _check(frame: bytes) -> None:
    bvlc = decode_bvlc(frame)
    if bvlc.length != len(frame):
        raise TxBlocked("BVLC length does not match frame size")
    if bvlc.function in _HEADER_ONLY:
        return  # decode_bvlc already enforced the exact body size
    if bvlc.function not in _BROADCAST and bvlc.function != BF.ORIGINAL_UNICAST_NPDU:
        raise TxBlocked(f"BVLC function 0x{bvlc.function:02x} not allowed")

    assert bvlc.npdu is not None
    npdu = decode_npdu(bvlc.npdu)
    if npdu.network_message is not None:
        raise TxBlocked("network-layer messages are never sent")
    if npdu.snet is not None:
        raise TxBlocked("SNET/SADR must not be set by the tool")
    assert npdu.apdu is not None
    apdu = decode_apdu(npdu.apdu)

    if apdu.pdu_type == PduType.UNCONFIRMED_REQUEST and apdu.service == US.WHO_IS:
        decode_who_is(apdu.payload)
        return
    if bvlc.function in _BROADCAST or npdu.dnet == 0xFFFF or npdu.dadr == b"":
        raise TxBlocked("broadcasts may only carry Who-Is")
    if apdu.pdu_type != PduType.CONFIRMED_REQUEST:
        raise TxBlocked(f"APDU type {apdu.pdu_type} not allowed")
    if apdu.segmented:
        raise TxBlocked("segmented requests are not allowed")
    if apdu.service == CS.READ_PROPERTY:
        decode_read_property_request(apdu.payload)
    elif apdu.service == CS.READ_PROPERTY_MULTIPLE:
        decode_rpm_request(apdu.payload)
    else:
        raise TxBlocked(f"confirmed service {apdu.service} not allowed")
