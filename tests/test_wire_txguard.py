from __future__ import annotations

import ast
import pathlib

import pytest

from bacnet_health.model import BdtEntry, FdtEntry
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.txguard import TxBlocked, check_tx

from helpers import frames as F

PROPS = [(77, None), (121, None), (70, None), (44, None), (12, None), (98, None), (139, None), (58, None), (28, None),
         (112, None), (56, None), (57, None), (119, None), (155, None), (167, None), (76, 0)]

ALLOWED = [
    B.encode_original_broadcast(N.encode_npdu(A.encode_who_is())),
    B.encode_original_broadcast(N.encode_npdu(A.encode_who_is(0, 4194303))),
    B.encode_original_broadcast(N.encode_npdu(A.encode_who_is(100, 199), dnet=0xFFFF)),
    B.encode_original_unicast(N.encode_npdu(A.encode_who_is(5, 5))),
    B.encode_distribute_broadcast(N.encode_npdu(A.encode_who_is(1, 1000))),
    B.encode_original_unicast(N.encode_npdu(A.encode_read_property(1, 8, 5, 97), expecting_reply=True)),
    B.encode_original_unicast(N.encode_npdu(A.encode_read_property(2, 8, 5, 76, index=0), expecting_reply=True)),
    B.encode_original_unicast(N.encode_npdu(A.encode_rpm(3, 8, 5, PROPS), expecting_reply=True)),
    B.encode_original_unicast(N.encode_npdu(A.encode_rpm(4, 8, 9, PROPS[:3]), dnet=10, dadr=b"\x07",
                                            expecting_reply=True)),
    B.encode_read_bdt(),
    B.encode_read_fdt(),
    B.encode_register_foreign_device(60),
]


@pytest.mark.parametrize("frame", ALLOWED, ids=lambda f: f.hex())
def test_allowed(frame):
    check_tx(frame)


def _u(apdu: bytes) -> bytes:
    return B.encode_original_unicast(N.encode_npdu(apdu, expecting_reply=True))


BLOCKED = {
    **{f"confirmed:{k}": F.unicast(v) for k, v in F.PROHIBITED_CONFIRMED.items()},
    **{f"unconfirmed:{k}": F.broadcast(v) for k, v in F.PROHIBITED_UNCONFIRMED.items()},
    "i-am": B.encode_original_broadcast(N.encode_npdu(A.encode_i_am(5))),
    "rp-ack": _u(A.encode_read_property_ack(1, 8, 5, 77, "x")),
    "rpm-ack": _u(A.encode_rpm_ack(1, [A.RpmResult(8, 5, 77, None, "x")])),
    "error": _u(A.encode_error(1, 12, 2, 32)),
    "reject": _u(A.encode_reject(1, 9)),
    "abort": _u(A.encode_abort(1, 4, server=False)),
    "simple-ack": _u(A.encode_simple_ack(1, 15)),
    "segment-ack": _u(F.SEGMENT_ACK),
    "segmented-rp": _u(F.SEGMENTED_READ_PROPERTY),
    "rp-broadcast": B.encode_original_broadcast(N.encode_npdu(A.encode_read_property(1, 8, 5, 77))),
    "rp-distribute": B.encode_distribute_broadcast(N.encode_npdu(A.encode_read_property(1, 8, 5, 77))),
    "rp-global-dnet": B.encode_original_unicast(N.encode_npdu(A.encode_read_property(1, 8, 5, 77), dnet=0xFFFF)),
    "rp-remote-bcast": B.encode_original_unicast(N.encode_npdu(A.encode_read_property(1, 8, 5, 77), dnet=7)),
    "rp-trailing": _u(A.encode_read_property(1, 8, 5, 77) + b"\x00"),
    "rp-with-snet": B.encode_original_unicast(N.encode_npdu(A.encode_read_property(1, 8, 5, 77), snet=3,
                                                            sadr=b"\x01")),
    "who-is-bad-payload": B.encode_original_broadcast(N.encode_npdu(b"\x10\x08\x09")),
    "net:who-is-router": F.NET_WHO_IS_ROUTER,
    "net:proprietary": F.NET_PROPRIETARY,
    "net:i-am-router": B.encode_original_broadcast(N.encode_network_message(1, N.encode_network_list([1]))),
    "bvlc:write-bdt": F.WRITE_BDT,
    "bvlc:delete-fdt": F.DELETE_FDT_ENTRY,
    "bvlc:forwarded": F.FORWARDED_WHO_IS,
    "bvlc:result": F.BVLC_RESULT,
    "bvlc:bdt-ack": B.encode_read_bdt_ack([BdtEntry("192.0.2.1", 47808, "255.255.255.255")]),
    "bvlc:fdt-ack": B.encode_read_fdt_ack([FdtEntry("192.0.2.1", 47808, 60, 1)]),
    "bvlc:secure": bytes.fromhex("810c0004"),
    "bvlc:read-bdt-trailing": B.encode_read_bdt() + b"\x00",
    "bvlc:read-bdt-body": F.bvlc(0x02, b"\x00"),
    "garbage": b"\x00\x01\x02",
    "empty": b"",
    "wrong-type": bytes.fromhex("82020004"),
}


@pytest.mark.parametrize("name", sorted(BLOCKED))
def test_blocked(name):
    with pytest.raises(TxBlocked):
        check_tx(BLOCKED[name])


PROHIBITED_NAMES = {
    "WRITE_PROPERTY", "WRITE_PROPERTY_MULTIPLE", "DEVICE_COMMUNICATION_CONTROL", "REINITIALIZE_DEVICE",
    "CREATE_OBJECT", "DELETE_OBJECT", "ADD_LIST_ELEMENT", "REMOVE_LIST_ELEMENT", "ATOMIC_WRITE_FILE", "SUBSCRIBE_COV",
    "SUBSCRIBE_COV_PROPERTY", "CONFIRMED_PRIVATE_TRANSFER", "UNCONFIRMED_PRIVATE_TRANSFER", "TIME_SYNCHRONIZATION",
    "UTC_TIME_SYNCHRONIZATION", "WRITE_BDT", "DELETE_FDT_ENTRY", "WRITE_GROUP",
}


def test_no_prohibited_constants_in_encoders():
    """Static check (design §9.1): no encode_* function under src/ references a prohibited service constant."""
    root = pathlib.Path(A.__file__).parent
    for path in root.glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name.startswith("encode"):
                names = {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
                assert not names & PROHIBITED_NAMES, f"{path.name}:{fn.name} uses {names & PROHIBITED_NAMES}"
                assert "write" not in fn.name and "dcc" not in fn.name and "reinit" not in fn.name
