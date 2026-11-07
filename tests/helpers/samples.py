"""Valid sample frames built with the package encoders plus the hand-built frames (fuzz seeds, tshark corpus)."""

from __future__ import annotations

from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N

from helpers import frames as F


def sample_frames() -> list[bytes]:
    u = lambda apdu: B.encode_original_unicast(N.encode_npdu(apdu, expecting_reply=True))  # noqa: E731
    pss = [True] * 15 + [False] * 25
    seeds = [
        B.encode_original_broadcast(N.encode_npdu(A.encode_who_is(1, 1000), dnet=0xFFFF)),
        u(A.encode_i_am(1234, vendor_id=5)),
        u(A.encode_read_property(1, 8, 5, 97)),
        u(A.encode_rpm(2, 8, 5, [(77, None), (76, 0), (57, None)])),
        u(A.encode_read_property_ack(1, 8, 5, 76, [{"type": "device", "instance": 5}, {"type": "analog-input",
                                                                                     "instance": 1}])),
        u(A.encode_rpm_ack(2, [A.RpmResult(8, 5, 77, None, "name"), A.RpmResult(8, 5, 97, None, pss),
                               A.RpmResult(8, 5, 58, None, None, (2, 32)),
                               A.RpmResult(8, 5, 56, None, {"year": 2026, "month": 1, "day": 2, "weekday": 5})])),
        u(A.encode_error(3, 12, 2, 32)),
        u(A.encode_reject(3, 9)),
        u(A.encode_abort(3, 4)),
        u(A.encode_complex_ack(4, 14, b"\x0c\x02", segmented=True, more_follows=True, sequence=1, window=2)),
        B.encode_read_bdt_ack([BdtEntry("192.0.2.1", 47808, "255.255.255.255")] * 3),
        B.encode_read_fdt_ack([FdtEntry("192.0.2.1", 47808, 60, 20)] * 2),
        B.encode_forwarded_npdu("192.0.2.9", 47808, N.encode_npdu(A.encode_i_am(9), snet=4, sadr=b"\x01")),
        B.encode_original_broadcast(N.encode_network_message(1, N.encode_network_list([1, 2]))),
        B.encode_result(0x30),
        F.NET_PROPRIETARY,
        F.WRITE_BDT,
        B.encode_read_bdt(),
        B.encode_read_fdt(),
        B.encode_register_foreign_device(60),
        B.encode_distribute_broadcast(N.encode_npdu(A.encode_who_is())),
        u(A.encode_read_property(7, 2, 3, 85, index=1, max_apdu=480)),
        B.encode_original_unicast(
            N.encode_npdu(A.encode_rpm(8, 8, 9, [(70, None)]), dnet=10, dadr=b"\x07", hop_count=7, expecting_reply=True)
        ),
        B.encode_original_unicast(N.encode_npdu(A.encode_i_am(42, 480, 0, 260), snet=10, sadr=b"\x07")),
        u(A.encode_simple_ack(9, 15)),
        u(A.encode_read_property_ack(10, 8, 42, 120, 260)),
    ]
    seeds += [F.unicast(v) for v in F.PROHIBITED_CONFIRMED.values()]
    seeds += [F.broadcast(v) for v in F.PROHIBITED_UNCONFIRMED.values()]
    return seeds
