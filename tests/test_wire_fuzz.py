"""Mutation fuzzing: decode_message never raises; every layer decoder raises only DecodeError."""

from __future__ import annotations

import random

from bacnet_health.wire import DecodeError
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire import tags as T
from bacnet_health.wire.message import decode_message
from bacnet_health.wire.txguard import TxBlocked, check_tx

from helpers.samples import sample_frames

ITERATIONS = 20_000


def _mutate(rng: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(rng.randint(1, 4)):
        op = rng.randrange(6)
        if op == 0 and b:  # flip a byte
            b[rng.randrange(len(b))] = rng.randrange(256)
        elif op == 1:  # truncate
            b = b[: rng.randrange(len(b) + 1)]
        elif op == 2:  # insert
            b.insert(rng.randrange(len(b) + 1), rng.randrange(256))
        elif op == 3 and b:  # delete
            del b[rng.randrange(len(b))]
        elif op == 4 and b:  # bit flip
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif op == 5:  # append junk
            b += bytes(rng.randrange(256) for _ in range(rng.randint(1, 8)))
    if len(b) >= 4 and rng.random() < 0.7:  # usually keep the BVLC length consistent so deeper layers are reached
        b[2:4] = len(b).to_bytes(2, "big")
    return bytes(b)


def _must_be_decode_error(fn, data: bytes) -> None:
    try:
        fn(data)
    except DecodeError:
        pass


def test_fuzz_never_raises():
    rng = random.Random(0xBAC0)
    seeds = sample_frames()
    layer_fns = [B.decode_bvlc, N.decode_npdu, A.decode_apdu, A.decode_i_am, A.decode_read_property_ack,
                 A.decode_rpm_ack, A.decode_rpm_request, A.decode_error, A.decode_who_has, A.decode_who_is,
                 A.decode_i_have, A.decode_write_property_summary, A.decode_dcc_summary, T.decode_any_application]
    for _ in range(ITERATIONS):
        data = _mutate(rng, rng.choice(seeds))
        msg = decode_message(data)
        assert msg.kind
        assert not (msg.decode_error or "").startswith("internal"), (data.hex(), msg.decode_error)
        try:
            check_tx(data)
        except TxBlocked:
            pass
        # Feed the layer decoders their own slice of the frame as well as the raw bytes.
        for fn in layer_fns:
            _must_be_decode_error(fn, data[rng.randrange(min(len(data), 12) + 1):])
        _must_be_decode_error(
            lambda d: T.decode_values(d, 0, len(d)), data)
