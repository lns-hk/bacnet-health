"""Differential tests: our capture layer against Wireshark's tshark/editcap.

Skipped automatically when Wireshark is not installed. Run only these with ``pytest -m tshark``.
"""

from __future__ import annotations

import shutil
import socket
import struct
import subprocess
from pathlib import Path

import pytest

from bacnet_health.capture.link import UdpExtractor, build_udp_frame, ip_checksum
from bacnet_health.capture.pcap import PcapWriter, iter_packets

_APP = Path("/Applications/Wireshark.app/Contents/MacOS")


def _tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    candidate = _APP / name
    return str(candidate) if candidate.exists() else None


TSHARK = _tool("tshark")
EDITCAP = _tool("editcap")

pytestmark = [
    pytest.mark.tshark,
    pytest.mark.skipif(TSHARK is None or EDITCAP is None, reason="tshark/editcap not installed"),
]

TS0 = 1_700_000_000.0
BVLC = b"\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08"


def _fragments(src: str, dst: str, payload: bytes, size: int, ident: int) -> list[bytes]:
    """Ethernet frames carrying one UDP datagram split into IPv4 fragments."""
    full = build_udp_frame(src, 47808, dst, 47808, payload)
    eth, udp = full[:14], full[34:]
    out = []
    for off in range(0, len(udp), size):
        chunk = udp[off:off + size]
        more = off + size < len(udp)
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk), ident, (0x2000 if more else 0) | off // 8,
                          64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
        hdr = hdr[:10] + struct.pack(">H", ip_checksum(hdr)) + hdr[12:]
        out.append(eth + hdr + chunk)
    return out


def _write_mixed(path: Path) -> list[tuple[float, bytes]]:
    frames: list[bytes] = []
    for i in range(30):
        frames.append(build_udp_frame(f"192.0.2.{i + 1}", 47808, "192.0.2.255", 47808 + i % 3, BVLC + bytes(i)))
    tagged = build_udp_frame("198.51.100.7", 50000, "198.51.100.8", 47808, BVLC)
    frames.append(tagged[:12] + b"\x81\x00\x00\x64" + tagged[12:])  # 802.1Q VLAN 100
    frames.append(tagged[:12] + b"\x88\xa8\x00\x0a\x81\x00\x00\x64" + tagged[12:])  # QinQ
    frames.extend(_fragments("203.0.113.5", "203.0.113.6", bytes(range(256)) * 10, 1480, ident=77))
    frames.append(b"\xff" * 6 + b"\x02\x00\x00\x00\x00\x09" + b"\x08\x06" + b"\x00" * 28)  # ARP
    written = []
    with PcapWriter(path) as w:
        for i, f in enumerate(frames):
            ts = TS0 + i * 0.010101 + 0.000001
            w.write(ts, f)
            written.append((ts, f))
    return written


def _tshark_fields(path: Path, *fields: str) -> list[list[str]]:
    cmd = [TSHARK, "-r", str(path), "-n", "--disable-protocol", "bvlc",
           "-o", "ip.check_checksum:TRUE", "-o", "udp.check_checksum:TRUE",
           "-T", "fields", "-E", "separator=|", "-E", "occurrence=l"]
    for f in fields:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=60).stdout
    return [line.split("|") for line in out.splitlines()]


def test_tshark_reads_our_pcap(tmp_path: Path) -> None:
    p = tmp_path / "mixed.pcap"
    written = _write_mixed(p)
    rows = _tshark_fields(p, "frame.number", "frame.time_epoch", "ip.checksum.status", "udp.srcport",
                          "udp.dstport", "udp.checksum.status", "udp.length")
    assert len(rows) == len(written)

    ex = UdpExtractor()
    ours = {d.frame_no: d for pk in iter_packets(p) for d in ex.feed(pk)}
    theirs = {int(r[0]): r for r in rows if r[3]}
    assert sorted(ours) == sorted(theirs)  # same frames carry a (reassembled) UDP datagram
    for frame_no, d in ours.items():
        r = theirs[frame_no]
        assert (int(r[3]), int(r[4])) == (d.src_port, d.dst_port)
        assert int(r[6]) == len(d.payload) + 8
        assert r[5] == "1", f"frame {frame_no}: tshark says UDP checksum is not good"
    for r, (ts, _f) in zip(rows, written):
        assert float(r[1]) == pytest.approx(ts, abs=1e-6)
        if r[2]:
            assert r[2] == "1", f"frame {r[0]}: tshark says IP checksum is not good"
    assert ex.stats["reassembled"] == 1 and ex.stats["non_ip"] == 1


@pytest.mark.parametrize("ftype", ["pcapng", "nsecpcap"])
def test_we_read_editcap_conversion(tmp_path: Path, ftype: str) -> None:
    src = tmp_path / "mixed.pcap"
    written = _write_mixed(src)
    out = tmp_path / f"conv.{ftype}"
    subprocess.run([EDITCAP, "-F", ftype, str(src), str(out)], check=True, capture_output=True, timeout=60)
    reader = iter_packets(out)
    pkts = list(reader)
    assert reader.warnings == []
    assert reader.format == ("pcapng" if ftype == "pcapng" else "pcap")
    assert len(pkts) == len(written)
    for pk, (ts, f) in zip(pkts, written):
        assert pk.data == f
        assert pk.ts == pytest.approx(ts, abs=1e-6)
        assert pk.linktype == 1


def test_timestamps_match_tshark_on_nanosecond_pcapng(tmp_path: Path) -> None:
    """A nanosecond-resolution pcapng (if_tsresol=9) produced by editcap: our times equal tshark's."""
    src = tmp_path / "mixed.pcap"
    _write_mixed(src)
    nsec = tmp_path / "ns.pcap"
    ng = tmp_path / "ns.pcapng"
    subprocess.run([EDITCAP, "-F", "nsecpcap", "-t", "0.000000123", str(src), str(nsec)], check=True,
                   capture_output=True, timeout=60)
    subprocess.run([EDITCAP, "-F", "pcapng", str(nsec), str(ng)], check=True, capture_output=True, timeout=60)
    for path in (nsec, ng):
        rows = _tshark_fields(path, "frame.time_epoch")
        pkts = list(iter_packets(path))
        assert len(rows) == len(pkts)
        for r, pk in zip(rows, pkts):
            assert r[0].split(".")[1].endswith("123")  # the nanosecond shift survived
            assert pk.ts == pytest.approx(float(r[0]), abs=5e-7)


@pytest.mark.parametrize("linktype", [0, 101, 108, 113, 228, 276])
def test_other_linktypes_agree_with_tshark(tmp_path: Path, linktype: int) -> None:
    """Our link-layer headers for non-Ethernet link types decode the same way in tshark."""
    ip = build_udp_frame("192.0.2.1", 47808, "192.0.2.2", 47809, BVLC)[14:]
    prefix = {
        0: struct.pack("<I", 2),
        108: struct.pack(">I", 2),
        113: struct.pack(">HHH", 0, 1, 6) + bytes.fromhex("02000000aa01") + b"\x00\x00\x08\x00",
        276: struct.pack(">HHIHBB", 0x0800, 0, 3, 1, 4, 6) + bytes.fromhex("02000000aa02") + b"\x00\x00",
    }.get(linktype, b"")
    p = tmp_path / f"lt{linktype}.pcap"
    with PcapWriter(p, linktype=linktype) as w:
        w.write(TS0, prefix + ip)
    (row,) = _tshark_fields(p, "ip.src", "udp.srcport", "udp.dstport", "udp.length")
    (d,) = [d for pk in iter_packets(p) for d in UdpExtractor().feed(pk)]
    assert row == [d.src_ip, str(d.src_port), str(d.dst_port), str(len(d.payload) + 8)]
