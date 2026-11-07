"""Tests for capture/link.py: link layers, IPv4 reassembly, UDP extraction and the frame builder."""

from __future__ import annotations

import socket
import struct
import time
from pathlib import Path

import pytest

from bacnet_health.capture.link import UdpExtractor, build_udp_frame, ip_checksum
from bacnet_health.capture.pcap import PcapWriter, RawPacket, iter_packets

SRC, DST = "192.0.2.10", "192.0.2.20"
BVLC = b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"  # Original-Broadcast Who-Is


def pkt(data: bytes, linktype: int = 1, frame_no: int = 1, ts: float = 100.0) -> RawPacket:
    return RawPacket(frame_no, ts, linktype, data, len(data), 0)


def ip_udp(payload: bytes = BVLC, src: str = SRC, dst: str = DST, sport: int = 47808, dport: int = 47808) -> bytes:
    """IPv4+UDP part of a built frame (strip the 14-byte Ethernet header)."""
    return build_udp_frame(src, sport, dst, dport, payload)[14:]


def ipv4_fragments(payload: bytes, size: int, ident: int = 0x1234, proto: int = 17) -> list[bytes]:
    """Split the UDP datagram (header + payload) into IPv4 fragments of *size* payload bytes (multiple of 8)."""
    udp = ip_udp(payload)[20:]
    src, dst = socket.inet_aton(SRC), socket.inet_aton(DST)
    out = []
    for off in range(0, len(udp), size):
        chunk = udp[off:off + size]
        more = off + size < len(udp)
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk), ident, (0x2000 if more else 0) | off // 8,
                          64, proto, 0, src, dst)
        hdr = hdr[:10] + struct.pack(">H", ip_checksum(hdr)) + hdr[12:]
        out.append(hdr + chunk)
    return out


ETH_HDR = bytes.fromhex("ffffffffffff" "020000000001")


# -- builder -----------------------------------------------------------------------------------------------------
def test_build_udp_frame_checksums() -> None:
    f = build_udp_frame(SRC, 47808, "192.0.2.255", 47809, BVLC)
    assert f[:6] == b"\xff" * 6 and f[6:12] == bytes.fromhex("020000000001")
    assert f[12:14] == b"\x08\x00"
    ip = f[14:34]
    assert ip_checksum(ip) == 0  # header checksum verifies
    udp = f[34:]
    pseudo = ip[12:20] + struct.pack(">BBH", 0, 17, len(udp))
    assert ip_checksum(pseudo + udp) == 0
    assert struct.unpack(">HHH", udp[:6]) == (47808, 47809, 8 + len(BVLC))
    assert udp[8:] == BVLC


def test_build_udp_frame_macs() -> None:
    assert build_udp_frame(SRC, 1, "255.255.255.255", 2, b"")[:6] == b"\xff" * 6
    assert build_udp_frame(SRC, 1, DST, 2, b"")[:6] == bytes.fromhex("020000000002")
    f = build_udp_frame(SRC, 1, DST, 2, b"", src_mac="aa-bb-cc-dd-ee-ff", dst_mac="00:11:22:33:44:55")
    assert f[:12] == bytes.fromhex("001122334455aabbccddeeff")
    with pytest.raises(ValueError):
        build_udp_frame(SRC, 1, DST, 2, b"", src_mac="zz")


# -- link layers -------------------------------------------------------------------------------------------------
def test_ethernet() -> None:
    ex = UdpExtractor()
    (d,) = ex.feed(pkt(build_udp_frame(SRC, 47808, DST, 47809, BVLC), frame_no=7, ts=1.5))
    assert (d.frame_no, d.ts, d.src_ip, d.src_port, d.dst_ip, d.dst_port) == (7, 1.5, SRC, 47808, DST, 47809)
    assert d.payload == BVLC
    assert d.eth_src == "02:00:00:00:00:01" and d.eth_dst == "02:00:00:00:00:02"
    assert ex.stats["udp"] == 1 and ex.stats["frames"] == 1


def test_ethernet_trailer_padding_ignored() -> None:
    frame = build_udp_frame(SRC, 1, DST, 2, b"ab") + b"\x00" * 16 + b"FCS!"
    (d,) = UdpExtractor().feed(pkt(frame))
    assert d.payload == b"ab"


@pytest.mark.parametrize("tags", [[0x8100], [0x88A8, 0x8100], [0x9100, 0x8100]])
def test_vlan(tags: list[int]) -> None:
    f = build_udp_frame(SRC, 47808, DST, 47808, BVLC)
    vlan = b"".join(struct.pack(">HH", t, 100 + i) for i, t in enumerate(tags))
    tagged = f[:12] + vlan + f[12:]
    (d,) = UdpExtractor().feed(pkt(tagged))
    assert d.payload == BVLC and d.eth_dst == "02:00:00:00:00:02"


def test_non_ip_and_ipv6_counted() -> None:
    ex = UdpExtractor()
    assert ex.feed(pkt(ETH_HDR + b"\x08\x06" + b"\x00" * 28)) == []  # ARP
    assert ex.feed(pkt(ETH_HDR + b"\x86\xdd" + b"\x60" + b"\x00" * 39)) == []
    assert ex.feed(pkt(ETH_HDR + b"\x00\x30" + b"\x00" * 48)) == []  # 802.3 length field
    assert ex.feed(pkt(b"\x00" * 10)) == []
    assert ex.feed(pkt(b"\x00" * 40, linktype=147)) == []
    assert ex.stats["non_ip"] == 2 and ex.stats["ipv6"] == 1
    assert ex.stats["malformed"] == 1 and ex.stats["unsupported_linktype"] == 1


def test_non_udp_counted() -> None:
    ip = bytearray(ip_udp())
    ip[9] = 6  # TCP
    ex = UdpExtractor()
    assert ex.feed(pkt(ETH_HDR + b"\x08\x00" + bytes(ip))) == []
    assert ex.stats["non_udp"] == 1


@pytest.mark.parametrize("linktype,prefix", [
    (0, struct.pack("<I", 2)),
    (0, struct.pack(">I", 2)),
    (108, struct.pack(">I", 2)),
    (101, b""),
    (228, b""),
])
def test_null_loop_raw(linktype: int, prefix: bytes) -> None:
    (d,) = UdpExtractor().feed(pkt(prefix + ip_udp(), linktype=linktype))
    assert d.payload == BVLC and d.eth_src is None and d.eth_dst is None


@pytest.mark.parametrize("af", [24, 28, 30])
def test_null_ipv6(af: int) -> None:
    ex = UdpExtractor()
    ex.feed(pkt(struct.pack("<I", af) + b"\x60" + b"\x00" * 39, linktype=0))
    ex.feed(pkt(b"\x60" + b"\x00" * 39, linktype=101))
    assert ex.stats["ipv6"] == 2


def test_linux_sll() -> None:
    hdr = struct.pack(">HHH", 0, 1, 6) + bytes.fromhex("02000000aa01") + b"\x00\x00" + b"\x08\x00"
    (d,) = UdpExtractor().feed(pkt(hdr + ip_udp(), linktype=113))
    assert d.payload == BVLC and d.eth_src == "02:00:00:00:aa:01" and d.eth_dst is None


def test_linux_sll2() -> None:
    hdr = struct.pack(">HHIHBB", 0x0800, 0, 3, 1, 4, 6) + bytes.fromhex("02000000aa02") + b"\x00\x00"
    assert len(hdr) == 20
    (d,) = UdpExtractor().feed(pkt(hdr + ip_udp(), linktype=276))
    assert d.payload == BVLC and d.eth_src == "02:00:00:00:aa:02"


# -- IPv4 / UDP checks -------------------------------------------------------------------------------------------
def test_ip_options() -> None:
    ip = ip_udp()
    opts = b"\x01\x01\x01\x00"  # NOP NOP NOP EOL
    total = len(ip) + 4
    hdr = bytes([0x46]) + ip[1:2] + struct.pack(">H", total) + ip[4:20] + opts
    (d,) = UdpExtractor().feed(pkt(hdr + ip[20:], linktype=101))
    assert d.payload == BVLC


@pytest.mark.parametrize("mutate,key", [
    (lambda b: b[:10], "malformed"),  # short header
    (lambda b: b"\x44" + b[1:], "malformed"),  # IHL < 5
    (lambda b: b"\x55" + b[1:], "non_ip"),  # wrong version under raw-IPv4 linktype 228
    (lambda b: b[:-3], "truncated"),  # total length > captured
    (lambda b: b[:2] + struct.pack(">H", 10) + b[4:], "malformed"),  # total length < IHL
    (lambda b: b[:24] + struct.pack(">H", 4) + b[26:], "malformed"),  # UDP length < 8
    (lambda b: b[:24] + struct.pack(">H", 500) + b[26:], "malformed"),  # UDP length > IP payload
])
def test_ipv4_udp_malformed(mutate, key) -> None:  # type: ignore[no-untyped-def]
    ex = UdpExtractor()
    assert ex.feed(pkt(mutate(ip_udp()), linktype=228)) == []
    assert ex.stats[key] == 1


# -- fragment reassembly ----------------------------------------------------------------------------------------
PAYLOAD = bytes(range(256)) * 12  # 3072 bytes


def _feed_all(ex: UdpExtractor, frags: list[bytes], order: list[int] | None = None, ts_step: float = 0.001):
    out = []
    for n, i in enumerate(order or range(len(frags))):
        out += ex.feed(pkt(ETH_HDR + b"\x08\x00" + frags[i], frame_no=n + 1, ts=100 + n * ts_step))
    return out


def test_reassembly_in_order() -> None:
    frags = ipv4_fragments(PAYLOAD, 1480)
    assert len(frags) == 3
    ex = UdpExtractor()
    (d,) = _feed_all(ex, frags)
    assert d.payload == PAYLOAD and d.frame_no == 3
    assert d.eth_dst == "ff:ff:ff:ff:ff:ff"
    assert ex.stats["fragments"] == 3 and ex.stats["reassembled"] == 1 and ex.stats["udp"] == 1


def test_reassembly_out_of_order_and_duplicates() -> None:
    frags = ipv4_fragments(PAYLOAD, 504)
    order = list(reversed(range(len(frags))))
    order.insert(2, order[1])  # duplicate fragment
    ex = UdpExtractor()
    (d,) = _feed_all(ex, frags, order)
    assert d.payload == PAYLOAD and d.src_port == 47808


def test_interleaved_datagrams() -> None:
    a = ipv4_fragments(PAYLOAD, 1480, ident=1)
    b = ipv4_fragments(PAYLOAD[::-1], 1480, ident=2)
    ex = UdpExtractor()
    got = _feed_all(ex, [a[0], b[0], b[1], a[1], a[2], b[2]])
    assert [d.payload for d in got] == [PAYLOAD, PAYLOAD[::-1]]


def test_fragment_timeout() -> None:
    frags = ipv4_fragments(PAYLOAD, 1480)
    ex = UdpExtractor()
    assert _feed_all(ex, frags, [0, 1, 2], ts_step=20.0) == []  # last fragment arrives 40 s later
    assert ex.stats["fragments_expired"] == 1
    ex.finish()
    assert ex.stats["fragments_incomplete"] == 1  # the late last fragment started a new buffer


def test_fragment_buffer_limit_and_finish() -> None:
    ex = UdpExtractor(max_fragment_buffers=4)
    for ident in range(10):
        _feed_all(ex, ipv4_fragments(PAYLOAD, 1480, ident=ident)[:1])
    assert ex.stats["fragments_dropped"] == 6
    ex.finish()
    assert ex.stats["fragments_incomplete"] == 4


def test_non_udp_fragments_not_buffered() -> None:
    ex = UdpExtractor()
    _feed_all(ex, ipv4_fragments(PAYLOAD, 1480, proto=6))
    assert ex.stats["non_udp"] == 3 and ex.stats["fragments"] == 0
    ex.finish()
    assert ex.stats["fragments_incomplete"] == 0


def test_bad_fragment_length() -> None:
    frags = ipv4_fragments(PAYLOAD, 1480)
    bad = bytearray(frags[0][:-1])  # MF set but length not a multiple of 8
    bad[2:4] = struct.pack(">H", len(bad))
    ex = UdpExtractor()
    assert ex.feed(pkt(ETH_HDR + b"\x08\x00" + bytes(bad))) == []
    assert ex.stats["malformed"] == 1


# -- end to end ----------------------------------------------------------------------------------------------------
def test_pcap_round_trip_through_extractor(tmp_path: Path) -> None:
    p = tmp_path / "e2e.pcap"
    with PcapWriter(p) as w:
        for i in range(20):
            w.write(1000 + i, build_udp_frame(f"198.51.100.{i + 1}", 47808, "198.51.100.255", 47808, BVLC))
    ex = UdpExtractor()
    got = [d for pk in iter_packets(p) for d in ex.feed(pk)]
    assert [d.src_ip for d in got] == [f"198.51.100.{i + 1}" for i in range(20)]
    assert all(d.payload == BVLC for d in got)


def test_extract_throughput(tmp_path: Path) -> None:
    n = 50_000
    p = tmp_path / "perf.pcap"
    frame = build_udp_frame(SRC, 47808, DST, 47808, BVLC)
    with PcapWriter(p) as w:
        for i in range(n):
            w.write(i * 0.001, frame)
    t = time.perf_counter()
    ex = UdpExtractor()
    count = sum(len(ex.feed(pk)) for pk in iter_packets(p))
    elapsed = time.perf_counter() - t
    assert count == n
    assert n / elapsed > 100_000, f"{n / elapsed:.0f} frames/s read+extract"
