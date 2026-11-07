"""Tests for capture/pcap.py: classic pcap and pcapng reading, writing, robustness."""

from __future__ import annotations

import gzip
import hashlib
import struct
import time
from pathlib import Path

import pytest

from bacnet_health.capture.pcap import (
    CaptureFormatError,
    PcapWriter,
    detect_format,
    iter_packets,
    sha256_file,
)

TS0 = 1_700_000_000.0


# -- helpers -----------------------------------------------------------------------------------------------------------
def classic_pcap(packets: list[tuple[int, int, bytes]], *, endian: str = "<", nano: bool = False,
                 linktype: int = 1, snaplen: int = 65535) -> bytes:
    """Hand-built classic pcap. packets: (sec, frac, data)."""
    magic = 0xA1B23C4D if nano else 0xA1B2C3D4
    out = [struct.pack(endian + "IHHiIII", magic, 2, 4, 0, 0, snaplen, linktype)]
    for sec, frac, data in packets:
        out.append(struct.pack(endian + "IIII", sec, frac, len(data), len(data)) + data)
    return b"".join(out)


def _pad(b: bytes) -> bytes:
    return b + b"\x00" * (-len(b) % 4)


class PcapngBuilder:
    """Tiny pcapng writer for tests (one or more sections, either endianness)."""

    def __init__(self) -> None:
        self.parts: list[bytes] = []
        self.e = "<"

    def block(self, btype: int, body: bytes) -> PcapngBuilder:
        body = _pad(body)
        length = 12 + len(body)
        self.parts.append(struct.pack(self.e + "II", btype, length) + body + struct.pack(self.e + "I", length))
        return self

    def option(self, code: int, value: bytes) -> bytes:
        return struct.pack(self.e + "HH", code, len(value)) + _pad(value)

    def shb(self, endian: str = "<") -> PcapngBuilder:
        self.e = endian
        body = struct.pack(endian + "IHHq", 0x1A2B3C4D, 1, 0, -1)
        return self.block(0x0A0D0D0A, body)

    def idb(self, linktype: int = 1, snaplen: int = 0, tsresol: int | None = None,
            tsoffset: int | None = None) -> PcapngBuilder:
        opts = b""
        opts += self.option(2, b"eth0")  # if_name, must be skipped
        if tsresol is not None:
            opts += self.option(9, bytes([tsresol]))
        if tsoffset is not None:
            opts += self.option(14, struct.pack(self.e + "q", tsoffset))
        opts += struct.pack(self.e + "HH", 0, 0)
        return self.block(1, struct.pack(self.e + "HHI", linktype, 0, snaplen) + opts)

    def epb(self, iface: int, ticks: int, data: bytes, orig_len: int | None = None) -> PcapngBuilder:
        body = struct.pack(self.e + "IIIII", iface, ticks >> 32, ticks & 0xFFFFFFFF, len(data),
                           len(data) if orig_len is None else orig_len)
        return self.block(6, body + _pad(data) + self.option(1, b"comment") + struct.pack(self.e + "HH", 0, 0))

    def spb(self, data: bytes) -> PcapngBuilder:
        return self.block(3, struct.pack(self.e + "I", len(data)) + data)

    def pb(self, iface: int, ticks: int, data: bytes) -> PcapngBuilder:
        body = struct.pack(self.e + "HHIIII", iface, 0, ticks >> 32, ticks & 0xFFFFFFFF, len(data), len(data))
        return self.block(2, body + data)

    def bytes(self) -> bytes:
        return b"".join(self.parts)


def frame(i: int) -> bytes:
    return bytes([i & 0xFF]) * (60 + i % 7)


# -- classic pcap ------------------------------------------------------------------------------------------------------
def test_writer_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "rt.pcap"
    with PcapWriter(p) as w:
        for i in range(10):
            w.write(TS0 + i * 0.123457, frame(i))
    assert detect_format(p) == "pcap"
    pkts = list(iter_packets(p))
    assert [pk.frame_no for pk in pkts] == list(range(1, 11))
    for i, pk in enumerate(pkts):
        assert pk.data == frame(i)
        assert pk.orig_len == len(frame(i))
        assert pk.linktype == 1 and pk.iface == 0
        assert pk.ts == pytest.approx(TS0 + i * 0.123457, abs=1e-6)


def test_writer_truncates_to_snaplen_and_rounds_us(tmp_path: Path) -> None:
    p = tmp_path / "snap.pcap"
    with PcapWriter(p, linktype=101, snaplen=32) as w:
        w.write(5.9999996, b"x" * 100)  # rounds up into the next second
    (pk,) = iter_packets(p)
    assert pk.linktype == 101
    assert pk.data == b"x" * 32 and pk.orig_len == 100
    assert pk.ts == 6.0


@pytest.mark.parametrize("endian", ["<", ">"])
@pytest.mark.parametrize("nano", [False, True])
def test_classic_endian_and_resolution(tmp_path: Path, endian: str, nano: bool) -> None:
    frac = 123456789 if nano else 123456
    p = tmp_path / "c.pcap"
    p.write_bytes(classic_pcap([(1_700_000_000, frac, b"abc"), (1_700_000_001, 0, b"defg")], endian=endian,
                               nano=nano, linktype=113))
    reader = iter_packets(p)
    pkts = list(reader)
    assert reader.warnings == []
    assert reader.linktypes == {113}
    assert [pk.data for pk in pkts] == [b"abc", b"defg"]
    expected = 1_700_000_000 + (0.123456789 if nano else 0.123456)
    assert pkts[0].ts == pytest.approx(expected, abs=1e-7)
    assert pkts[1].ts == 1_700_000_001


def test_linktype_fcs_bits_masked(tmp_path: Path) -> None:
    p = tmp_path / "fcs.pcap"
    p.write_bytes(classic_pcap([(1, 0, b"z")], linktype=1 | 0x14000000))
    (pk,) = iter_packets(p)
    assert pk.linktype == 1


@pytest.mark.parametrize("cut", [3, 10, 8])
def test_truncated_classic(tmp_path: Path, cut: int) -> None:
    data = classic_pcap([(1, 0, b"a" * 50), (2, 0, b"b" * 50), (3, 0, b"c" * 50)])
    p = tmp_path / "t.pcap"
    p.write_bytes(data[:-cut] if cut != 8 else data[: 24 + 66 + 8])  # 8: cut inside the 2nd record header
    reader = iter_packets(p)
    pkts = list(reader)
    assert len(pkts) == (2 if cut != 8 else 1)
    assert len(reader.warnings) == 1 and "truncated" in reader.warnings[0]


def test_truncated_global_header(tmp_path: Path) -> None:
    p = tmp_path / "h.pcap"
    p.write_bytes(classic_pcap([])[:12])
    reader = iter_packets(p)
    assert list(reader) == []
    assert reader.warnings


def test_corrupt_caplen_stops(tmp_path: Path) -> None:
    good = classic_pcap([(1, 0, b"a" * 20)])
    bad = struct.pack("<IIII", 2, 0, 0x7FFFFFFF, 10) + b"junk"
    p = tmp_path / "corrupt.pcap"
    p.write_bytes(good + bad)
    reader = iter_packets(p)
    assert len(list(reader)) == 1
    assert "corrupt" in reader.warnings[0]


def test_not_a_capture(tmp_path: Path) -> None:
    p = tmp_path / "x.txt"
    p.write_bytes(b"hello world, not a pcap")
    with pytest.raises(CaptureFormatError):
        detect_format(p)
    with pytest.raises(CaptureFormatError):
        list(iter_packets(p))
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(CaptureFormatError):
        list(iter_packets(empty))


def test_empty_capture_has_no_warnings(tmp_path: Path) -> None:
    p = tmp_path / "e.pcap"
    PcapWriter(p).close()
    reader = iter_packets(p)
    assert list(reader) == [] and reader.warnings == []


# -- gzip --------------------------------------------------------------------------------------------------------------
def test_gzip_transparent(tmp_path: Path) -> None:
    raw = classic_pcap([(1, 0, b"a"), (2, 0, b"b")])
    p = tmp_path / "c.pcap.gz"
    p.write_bytes(gzip.compress(raw))
    assert detect_format(p) == "pcap"
    assert [pk.data for pk in iter_packets(p)] == [b"a", b"b"]
    # sha256 is of the file on disk, not the decompressed content
    assert sha256_file(p) == hashlib.sha256(p.read_bytes()).hexdigest()
    # gzip detection by magic, not by extension
    q = tmp_path / "noext"
    q.write_bytes(gzip.compress(PcapngBuilder().shb().idb().epb(0, 5, b"q").bytes()))
    assert detect_format(q) == "pcapng"
    assert [pk.data for pk in iter_packets(q)] == [b"q"]


def test_gzip_truncated(tmp_path: Path) -> None:
    raw = classic_pcap([(i, 0, bytes([i]) * 200) for i in range(50)])
    blob = gzip.compress(raw)
    p = tmp_path / "t.pcap.gz"
    p.write_bytes(blob[: len(blob) // 2])
    reader = iter_packets(p)
    pkts = list(reader)
    assert 0 < len(pkts) < 50
    assert reader.warnings


# -- pcapng ------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("endian", ["<", ">"])
def test_pcapng_basic(tmp_path: Path, endian: str) -> None:
    b = PcapngBuilder().shb(endian)
    b.idb(linktype=1)  # default microseconds
    b.block(4, b"\x00" * 8)  # NRB: skipped
    b.epb(0, int(TS0 * 1e6) + 250_000, b"one")
    b.block(5, b"\x00" * 16)  # ISB: skipped
    b.block(0x00000BAD, b"custom!!")  # custom block: skipped
    b.block(0x0000000A, b"\x00" * 8)  # DSB: skipped
    b.epb(0, int(TS0 * 1e6) + 500_000, b"two", orig_len=1000)
    p = tmp_path / "a.pcapng"
    p.write_bytes(b.bytes())
    assert detect_format(p) == "pcapng"
    reader = iter_packets(p)
    pkts = list(reader)
    assert reader.warnings == []
    assert reader.format == "pcapng"
    assert [pk.data for pk in pkts] == [b"one", b"two"]
    assert [pk.frame_no for pk in pkts] == [1, 2]
    assert pkts[0].ts == pytest.approx(TS0 + 0.25, abs=1e-6)
    assert pkts[1].orig_len == 1000


def test_pcapng_tsresol_and_offset(tmp_path: Path) -> None:
    b = PcapngBuilder().shb()
    b.idb(linktype=1, tsresol=9)  # nanoseconds
    b.idb(linktype=228, tsresol=0x80 | 10, tsoffset=1_000_000)  # 2^-10 s ticks, +1e6 s offset
    b.idb(linktype=113, tsresol=3)  # milliseconds
    b.epb(0, int(TS0) * 10**9 + 123_456_789, b"ns")
    b.epb(1, 5 * 1024 + 512, b"p2")
    b.epb(2, int(TS0) * 1000 + 7, b"ms")
    p = tmp_path / "r.pcapng"
    p.write_bytes(b.bytes())
    pkts = list(iter_packets(p))
    assert [(pk.linktype, pk.iface) for pk in pkts] == [(1, 0), (228, 1), (113, 2)]
    assert pkts[0].ts == pytest.approx(TS0 + 0.123456789, abs=1e-6)
    assert pkts[1].ts == 1_000_000 + 5.5
    assert pkts[2].ts == pytest.approx(TS0 + 0.007, abs=1e-9)


def test_pcapng_section_change(tmp_path: Path) -> None:
    b = PcapngBuilder().shb("<").idb(linktype=1).epb(0, 1_000_000, b"s1")
    b.shb(">").idb(linktype=101, tsresol=9).epb(0, 2 * 10**9, b"s2")
    b.shb("<").idb(linktype=276).epb(0, 3_000_000, b"s3")
    p = tmp_path / "s.pcapng"
    p.write_bytes(b.bytes())
    reader = iter_packets(p)
    pkts = list(reader)
    assert reader.warnings == []
    assert [(pk.frame_no, pk.data, pk.linktype, pk.ts) for pk in pkts] == [
        (1, b"s1", 1, 1.0), (2, b"s2", 101, 2.0), (3, b"s3", 276, 3.0)]
    # interface ids restart per section; iface is file-global
    assert [pk.iface for pk in pkts] == [0, 1, 2]
    assert reader.linktypes == {1, 101, 276}


def test_pcapng_spb_and_obsolete_pb(tmp_path: Path) -> None:
    b = PcapngBuilder().shb(">").idb(linktype=1, snaplen=4)
    b.spb(b"simple-packet")  # snaplen 4 -> truncated to 4 bytes
    b.pb(0, 7_000_000, b"old")
    p = tmp_path / "spb.pcapng"
    p.write_bytes(b.bytes())
    pkts = list(iter_packets(p))
    assert pkts[0].data == b"simp" and pkts[0].orig_len == len(b"simple-packet")
    assert pkts[1].data == b"old" and pkts[1].ts == 7.0
    assert [pk.frame_no for pk in pkts] == [1, 2]


def test_pcapng_undefined_interface_skipped(tmp_path: Path) -> None:
    b = PcapngBuilder().shb().idb().epb(3, 0, b"bad").epb(0, 0, b"ok")
    p = tmp_path / "u.pcapng"
    p.write_bytes(b.bytes())
    reader = iter_packets(p)
    assert [pk.data for pk in reader] == [b"ok"]
    assert reader.warnings and "undefined interface" in reader.warnings[0]


@pytest.mark.parametrize("cut", [1, 4, 6, 30])
def test_pcapng_truncated(tmp_path: Path, cut: int) -> None:
    b = PcapngBuilder().shb().idb()
    for i in range(5):
        b.epb(0, i, frame(i))
    data = b.bytes()
    p = tmp_path / "t.pcapng"
    p.write_bytes(data[:-cut])
    reader = iter_packets(p)
    assert len(list(reader)) == 4
    assert len(reader.warnings) == 1


def test_pcapng_trailer_mismatch(tmp_path: Path) -> None:
    b = PcapngBuilder().shb().idb().epb(0, 0, b"good").epb(0, 0, b"bad!")
    data = bytearray(b.bytes())
    data[-1] ^= 0xFF  # corrupt the last block's trailing length
    p = tmp_path / "m.pcapng"
    p.write_bytes(bytes(data))
    reader = iter_packets(p)
    assert [pk.data for pk in reader] == [b"good"]
    assert "mismatch" in reader.warnings[0]


def test_pcapng_bad_block_length(tmp_path: Path) -> None:
    b = PcapngBuilder().shb().idb().epb(0, 0, b"good")
    data = b.bytes() + struct.pack("<II", 6, 7) + b"\x00" * 20
    p = tmp_path / "l.pcapng"
    p.write_bytes(data)
    reader = iter_packets(p)
    assert len(list(reader)) == 1
    assert "corrupt block" in reader.warnings[0]


def test_reader_close_mid_iteration(tmp_path: Path) -> None:
    p = tmp_path / "c.pcap"
    with PcapWriter(p) as w:
        for i in range(5):
            w.write(i, b"x")
    with iter_packets(p) as reader:
        assert next(reader).frame_no == 1
    assert reader._stream is None


def test_sha256(tmp_path: Path) -> None:
    p = tmp_path / "h.bin"
    p.write_bytes(b"abc")
    assert sha256_file(p) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# -- performance sanity --------------------------------------------------------------------------------------------
def test_read_throughput(tmp_path: Path) -> None:
    n = 100_000
    rec = struct.pack("<IIII", 1, 0, 60, 60) + b"\x00" * 60
    p = tmp_path / "big.pcap"
    p.write_bytes(classic_pcap([]) + rec * n)
    t = time.perf_counter()
    count = sum(1 for _ in iter_packets(p))
    elapsed = time.perf_counter() - t
    assert count == n
    rate = n / elapsed
    assert rate > 200_000, f"{rate:.0f} packets/s"
