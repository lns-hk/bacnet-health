"""Streaming readers for classic pcap and pcapng, plus a minimal classic-pcap writer.

Written from the format specifications (libpcap file format; IETF draft-ietf-opsawg-pcapng). The reader never loads
the whole file: it reads one record at a time from a buffered stream. gzip-compressed captures are decompressed
transparently.

A damaged file never raises out of the iterator. Reading stops at the first record that cannot be trusted and a
human-readable message is appended to ``reader.warnings``. Only a file that is not a capture at all (unknown magic)
raises :class:`CaptureFormatError` when iteration starts.
"""

from __future__ import annotations

import gzip
import hashlib
import os
import struct
import zlib
from dataclasses import dataclass
from typing import BinaryIO, Iterator

__all__ = [
    "CaptureFormatError",
    "RawPacket",
    "PcapReader",
    "PcapWriter",
    "iter_packets",
    "sha256_file",
    "detect_format",
]

# Classic pcap magic numbers as they appear when read little-endian.
_MAGIC_US = 0xA1B2C3D4
_MAGIC_NS = 0xA1B23C4D
_MAGIC_US_SWAPPED = 0xD4C3B2A1
_MAGIC_NS_SWAPPED = 0x4D3CB2A1

# pcapng block types.
_BT_SHB = 0x0A0D0D0A
_BT_IDB = 0x00000001
_BT_PB = 0x00000002  # obsolete Packet Block
_BT_SPB = 0x00000003
_BT_EPB = 0x00000006
_BYTE_ORDER_MAGIC = 0x1A2B3C4D

_OPT_ENDOFOPT = 0
_OPT_IF_TSRESOL = 9
_OPT_IF_TSOFFSET = 14

_GZIP_MAGIC = b"\x1f\x8b"

# Sanity limits: anything larger is treated as corruption rather than allocated.
_MAX_RECORD = 64 * 1024 * 1024
_MAX_PCAP_CAPLEN = 262144  # libpcap's MAXIMUM_SNAPLEN; used unless the header's snaplen is larger

_READ_ERRORS = (EOFError, OSError, zlib.error)


class CaptureFormatError(ValueError):
    """The file is not a recognised pcap/pcapng capture."""


@dataclass(slots=True)
class RawPacket:
    """One captured frame as stored in the file."""

    frame_no: int  # 1-based, counted across the whole file (all sections, all interfaces)
    ts: float  # seconds since the Unix epoch
    linktype: int  # LINKTYPE_* value of the interface the frame was captured on
    data: bytes  # captured bytes (may be shorter than orig_len)
    orig_len: int  # length of the frame on the wire
    iface: int  # interface index; 0 for classic pcap, file-global running index for pcapng


def _open_stream(path: str | os.PathLike[str]) -> BinaryIO:
    """Open *path* for reading, transparently decompressing gzip."""
    raw = open(path, "rb")
    try:
        head = raw.read(2)
        raw.seek(0)
    except OSError:
        raw.close()
        raise
    if head == _GZIP_MAGIC:
        raw.close()
        return gzip.open(path, "rb")  # type: ignore[return-value]  # owns (and closes) its file
    return raw


def detect_format(path: str | os.PathLike[str]) -> str:
    """Return ``"pcap"`` or ``"pcapng"`` (looking through gzip). Raise :class:`CaptureFormatError` otherwise."""
    with _open_stream(path) as f:
        try:
            head = f.read(4)
        except _READ_ERRORS as exc:
            raise CaptureFormatError(f"cannot read capture header: {exc}") from exc
    return _format_from_magic(head)


def _format_from_magic(head: bytes) -> str:
    if len(head) < 4:
        raise CaptureFormatError("file too short to be a capture")
    (magic,) = struct.unpack("<I", head)
    if magic in (_MAGIC_US, _MAGIC_NS, _MAGIC_US_SWAPPED, _MAGIC_NS_SWAPPED):
        return "pcap"
    if magic == _BT_SHB:
        return "pcapng"
    raise CaptureFormatError(f"unrecognised capture magic 0x{head.hex()}")


def sha256_file(path: str | os.PathLike[str]) -> str:
    """SHA-256 (hex) of the file bytes as stored on disk (i.e. of the compressed file if gzipped)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass
class _Iface:
    linktype: int
    snaplen: int
    units_per_sec: int  # timestamp ticks per second (from if_tsresol; default 10**6)
    offset: int  # if_tsoffset seconds
    index: int  # file-global index


class PcapReader:
    """Iterator over the frames of a pcap or pcapng file.

    Use as ``for pkt in PcapReader(path)`` (or via :func:`iter_packets`). After iteration, ``warnings`` lists any
    problem that stopped reading early or was tolerated; ``format`` is ``"pcap"`` or ``"pcapng"``;
    ``linktypes`` is the set of link types seen. ``frames`` is the number of frames yielded.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = path
        self.warnings: list[str] = []
        self.format: str | None = None
        self.linktypes: set[int] = set()
        self.frames = 0
        self._stream: BinaryIO | None = None
        self._gen: Iterator[RawPacket] | None = None

    # -- iterator protocol -------------------------------------------------------------------------------------
    def __iter__(self) -> PcapReader:
        return self

    def __next__(self) -> RawPacket:
        if self._gen is None:
            self._gen = self._run()
        return next(self._gen)

    def close(self) -> None:
        if self._gen is not None:
            self._gen.close()  # type: ignore[attr-defined]
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> PcapReader:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- reading -----------------------------------------------------------------------------------------------
    def _warn(self, msg: str) -> None:
        self.warnings.append(msg)

    def _run(self) -> Iterator[RawPacket]:
        self._stream = _open_stream(self.path)
        f = self._stream
        try:
            try:
                head = f.read(4)
            except _READ_ERRORS as exc:
                raise CaptureFormatError(f"cannot read capture header: {exc}") from exc
            self.format = _format_from_magic(head)
            if self.format == "pcap":
                yield from self._read_pcap(f, head)
            else:
                yield from self._read_pcapng(f, head)
        finally:
            f.close()
            self._stream = None

    def _read(self, f: BinaryIO, n: int) -> bytes | None:
        """Read exactly *n* bytes; on a short read or a decompression error, warn and return None."""
        try:
            data = f.read(n)
        except _READ_ERRORS as exc:
            self._warn(f"read error after frame {self.frames}: {exc}")
            return None
        if len(data) != n:
            self._warn(f"file truncated after frame {self.frames} (needed {n} bytes, got {len(data)})")
            return None
        return data

    def _read_pcap(self, f: BinaryIO, magic_bytes: bytes) -> Iterator[RawPacket]:
        (magic,) = struct.unpack("<I", magic_bytes)
        if magic in (_MAGIC_US, _MAGIC_NS):
            endian = "<"
        else:
            endian = ">"
        divisor = 1e9 if magic in (_MAGIC_NS, _MAGIC_NS_SWAPPED) else 1e6
        rest = self._read(f, 20)
        if rest is None:
            return
        _vmaj, _vmin, _zone, _sigfigs, snaplen, linktype_field = struct.unpack(endian + "HHiIII", rest)
        linktype = linktype_field & 0xFFFF  # upper bits carry FCS information
        self.linktypes.add(linktype)
        max_caplen = max(snaplen, _MAX_PCAP_CAPLEN)

        rec_hdr = struct.Struct(endian + "IIII")
        read = f.read
        frame_no = 0
        while True:
            try:
                hdr = read(16)
            except _READ_ERRORS as exc:
                self._warn(f"read error after frame {frame_no}: {exc}")
                return
            if len(hdr) < 16:
                if hdr:
                    self._warn(f"file truncated after frame {frame_no} (partial record header)")
                return
            sec, frac, caplen, orig_len = rec_hdr.unpack(hdr)
            if caplen > max_caplen:
                self._warn(f"corrupt record header after frame {frame_no} (caplen {caplen}); stopped reading")
                return
            try:
                data = read(caplen)
            except _READ_ERRORS as exc:
                self._warn(f"read error after frame {frame_no}: {exc}")
                return
            if len(data) < caplen:
                self._warn(f"file truncated after frame {frame_no} (partial packet data)")
                return
            frame_no += 1
            self.frames = frame_no
            yield RawPacket(frame_no, sec + frac / divisor, linktype, data, orig_len, 0)

    def _read_pcapng(self, f: BinaryIO, first: bytes) -> Iterator[RawPacket]:
        endian = "<"
        ifaces: list[_Iface] = []
        iface_count = 0
        frame_no = 0
        pending_type: bytes | None = first

        while True:
            if pending_type is not None:
                type_bytes = pending_type
                pending_type = None
            else:
                try:
                    type_bytes = f.read(4)
                except _READ_ERRORS as exc:
                    self._warn(f"read error after frame {frame_no}: {exc}")
                    return
                if len(type_bytes) < 4:
                    if type_bytes:
                        self._warn(f"file truncated after frame {frame_no} (partial block header)")
                    return

            if type_bytes == b"\x0a\x0d\x0d\x0a":
                # Section Header Block: the byte-order magic decides the endianness of this section.
                hdr = self._read(f, 8)
                if hdr is None:
                    return
                if struct.unpack("<I", hdr[4:])[0] == _BYTE_ORDER_MAGIC:
                    endian = "<"
                elif struct.unpack(">I", hdr[4:])[0] == _BYTE_ORDER_MAGIC:
                    endian = ">"
                else:
                    self._warn(f"bad byte-order magic in section header after frame {frame_no}; stopped reading")
                    return
                (block_len,) = struct.unpack(endian + "I", hdr[:4])
                if block_len < 28 or block_len % 4 or block_len > _MAX_RECORD:
                    self._warn(f"bad section header length {block_len}; stopped reading")
                    return
                body = self._read(f, block_len - 12)
                if body is None:
                    return
                if struct.unpack(endian + "I", body[-4:])[0] != block_len:
                    self._warn(f"section header trailer mismatch after frame {frame_no}; stopped reading")
                    return
                major = struct.unpack(endian + "H", body[:2])[0]
                if major != 1:
                    self._warn(f"unsupported pcapng major version {major}; stopped reading")
                    return
                ifaces = []  # interface IDs are per section
                continue

            (btype,) = struct.unpack(endian + "I", type_bytes)
            len_bytes = self._read(f, 4)
            if len_bytes is None:
                return
            (block_len,) = struct.unpack(endian + "I", len_bytes)
            if block_len < 12 or block_len % 4 or block_len > _MAX_RECORD:
                self._warn(f"corrupt block (type 0x{btype:08x}, length {block_len}) after frame {frame_no}; "
                           "stopped reading")
                return
            body = self._read(f, block_len - 8)
            if body is None:
                return
            if struct.unpack(endian + "I", body[-4:])[0] != block_len:
                self._warn(f"block trailer mismatch (type 0x{btype:08x}) after frame {frame_no}; stopped reading")
                return
            body = body[:-4]

            if btype == _BT_IDB:
                iface = self._parse_idb(body, endian, iface_count)
                if iface is None:
                    return
                ifaces.append(iface)
                iface_count += 1
                self.linktypes.add(iface.linktype)
                continue

            if btype == _BT_EPB or btype == _BT_PB:
                if len(body) < 20:
                    self._warn(f"short packet block after frame {frame_no}; stopped reading")
                    return
                if btype == _BT_EPB:
                    iface_id, ts_hi, ts_lo, caplen, orig_len = struct.unpack_from(endian + "IIIII", body)
                else:
                    iface_id, _drops, ts_hi, ts_lo, caplen, orig_len = struct.unpack_from(endian + "HHIIII", body)
                if caplen > len(body) - 20:
                    self._warn(f"packet block caplen exceeds block after frame {frame_no}; stopped reading")
                    return
                if iface_id >= len(ifaces):
                    self._warn(f"packet references undefined interface {iface_id}; frame skipped")
                    continue
                iface = ifaces[iface_id]
                ticks = (ts_hi << 32) | ts_lo
                ts = iface.offset + ticks / iface.units_per_sec
                frame_no += 1
                self.frames = frame_no
                yield RawPacket(frame_no, ts, iface.linktype, body[20:20 + caplen], orig_len, iface.index)
                continue

            if btype == _BT_SPB:
                if len(body) < 4 or not ifaces:
                    self._warn(f"simple packet block without interface after frame {frame_no}; frame skipped")
                    continue
                (orig_len,) = struct.unpack_from(endian + "I", body)
                iface = ifaces[0]
                caplen = min(orig_len, len(body) - 4)
                if iface.snaplen:
                    caplen = min(caplen, iface.snaplen)
                frame_no += 1
                self.frames = frame_no
                # SPB carries no timestamp.
                yield RawPacket(frame_no, 0.0, iface.linktype, body[4:4 + caplen], orig_len, iface.index)
                continue

            # NRB, ISB, DSB, custom and unknown blocks carry no frames: skip.

    def _parse_idb(self, body: bytes, endian: str, index: int) -> _Iface | None:
        if len(body) < 8:
            self._warn("interface description block too short; stopped reading")
            return None
        linktype, _reserved, snaplen = struct.unpack_from(endian + "HHI", body)
        units = 10**6
        offset = 0
        pos = 8
        while pos + 4 <= len(body):
            code, olen = struct.unpack_from(endian + "HH", body, pos)
            pos += 4
            if code == _OPT_ENDOFOPT:
                break
            value = body[pos:pos + olen]
            pos += (olen + 3) & ~3
            if len(value) < olen:
                self._warn(f"interface {index}: truncated option {code}; options ignored")
                break
            if code == _OPT_IF_TSRESOL and olen >= 1:
                v = value[0]
                exp = v & 0x7F
                if exp > 63:
                    self._warn(f"interface {index}: implausible if_tsresol 0x{v:02x}; using microseconds")
                    continue
                units = (2**exp) if v & 0x80 else (10**exp)
            elif code == _OPT_IF_TSOFFSET and olen >= 8:
                (offset,) = struct.unpack(endian + "q", value[:8])
        return _Iface(linktype, snaplen, units, offset, index)


def iter_packets(path: str | os.PathLike[str]) -> PcapReader:
    """Iterate over the frames of a pcap/pcapng file (optionally gzipped).

    Returns a :class:`PcapReader`, which is an iterator of :class:`RawPacket` and exposes ``.warnings`` once
    iteration has run.
    """
    return PcapReader(path)


class PcapWriter:
    """Write a classic little-endian microsecond pcap file.

    ``with PcapWriter(path) as w: w.write(ts, frame)``
    """

    def __init__(self, path: str | os.PathLike[str], linktype: int = 1, snaplen: int = 65535) -> None:
        self.linktype = linktype
        self.snaplen = snaplen
        self.count = 0
        self._f: BinaryIO | None = open(path, "wb")
        self._f.write(struct.pack("<IHHiIII", _MAGIC_US, 2, 4, 0, 0, snaplen, linktype))
        self._rec = struct.Struct("<IIII")

    def write(self, ts: float, data: bytes, orig_len: int | None = None) -> None:
        """Append one frame. Frames longer than ``snaplen`` are truncated (orig_len keeps the full length)."""
        if self._f is None:
            raise ValueError("PcapWriter is closed")
        if ts < 0:
            raise ValueError("timestamp must be non-negative")
        usec_total = round(ts * 1_000_000)
        sec, usec = divmod(usec_total, 1_000_000)
        if orig_len is None:
            orig_len = len(data)
        cap = data[: self.snaplen]
        self._f.write(self._rec.pack(sec, usec, len(cap), orig_len))
        self._f.write(cap)
        self.count += 1

    def close(self) -> None:
        if self._f is not None:
            self._f.close()
            self._f = None

    def __enter__(self) -> PcapWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
