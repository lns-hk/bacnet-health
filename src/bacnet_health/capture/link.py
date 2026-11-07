"""Link-layer and IPv4/UDP extraction for captured frames, and a frame builder for synthetic traffic.

:class:`UdpExtractor` turns :class:`~bacnet_health.capture.pcap.RawPacket` objects into :class:`UdpDatagram` objects.
It understands the link types BACnet/IP captures realistically come in, strips 802.1Q / QinQ tags, reassembles
fragmented IPv4 UDP datagrams, and counts everything it discards in ``stats`` so the report can say what was not
analysed. It never raises on bad input.

Checksums are not verified on input: captures taken on the sending host routinely carry bad checksums because of
NIC offload, and a BACnet health check gains nothing by dropping those frames.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field

from bacnet_health.capture.pcap import RawPacket

__all__ = ["UdpDatagram", "UdpExtractor", "build_udp_frame", "ip_checksum"]

LINKTYPE_NULL = 0
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_LOOP = 108
LINKTYPE_LINUX_SLL = 113
LINKTYPE_IPV4 = 228
LINKTYPE_LINUX_SLL2 = 276

_ETH_IPV4 = 0x0800
_ETH_IPV6 = 0x86DD
_ETH_VLAN_TAGS = (0x8100, 0x88A8, 0x9100)
_IPPROTO_UDP = 17

# BSD AF_INET is 2 everywhere; AF_INET6 differs per OS (24 NetBSD/OpenBSD, 28 FreeBSD, 30 macOS, 10 Linux).
_AF_INET = 2
_AF_INET6 = (10, 24, 28, 30)

FRAGMENT_TIMEOUT = 30.0  # seconds of capture time
MAX_FRAGMENT_BUFFERS = 1024
_MAX_IP_LEN = 65535


@dataclass(slots=True)
class UdpDatagram:
    """One UDP datagram (reassembled if it was fragmented)."""

    frame_no: int  # frame carrying the datagram (for a reassembled datagram: the frame that completed it)
    ts: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes
    eth_src: str | None = None  # "aa:bb:cc:dd:ee:ff" where the link layer provides it
    eth_dst: str | None = None


@dataclass
class _FragBuffer:
    first_ts: float
    pieces: dict[int, bytes] = field(default_factory=dict)  # byte offset -> data
    total_len: int | None = None  # payload length, known once the last fragment (MF=0) arrived
    eth_src: str | None = None
    eth_dst: str | None = None


def _mac(b: bytes) -> str:
    return b.hex(":")


class UdpExtractor:
    """Stateful UDP extractor. Feed frames in file order; call :meth:`finish` at the end.

    ``stats`` keys: frames, udp, non_ip, ipv6, non_udp, malformed, truncated, unsupported_linktype, fragments,
    reassembled, fragments_expired, fragments_dropped, fragments_incomplete.
    """

    def __init__(self, fragment_timeout: float = FRAGMENT_TIMEOUT,
                 max_fragment_buffers: int = MAX_FRAGMENT_BUFFERS) -> None:
        self.fragment_timeout = fragment_timeout
        self.max_fragment_buffers = max_fragment_buffers
        self.stats: dict[str, int] = dict.fromkeys(
            ("frames", "udp", "non_ip", "ipv6", "non_udp", "malformed", "truncated", "unsupported_linktype",
             "fragments", "reassembled", "fragments_expired", "fragments_dropped", "fragments_incomplete"), 0)
        self._frags: dict[tuple[bytes, bytes, int, int], _FragBuffer] = {}

    # -- link layers -------------------------------------------------------------------------------------------
    def feed(self, pkt: RawPacket) -> list[UdpDatagram]:
        """Return the UDP datagrams completed by this frame (usually zero or one)."""
        stats = self.stats
        stats["frames"] += 1
        data = pkt.data
        lt = pkt.linktype
        eth_src = eth_dst = None

        if lt == LINKTYPE_ETHERNET:
            if len(data) < 14:
                stats["malformed"] += 1
                return []
            etype = (data[12] << 8) | data[13]
            off = 14
            while etype in _ETH_VLAN_TAGS:
                if len(data) < off + 4:
                    stats["malformed"] += 1
                    return []
                etype = (data[off + 2] << 8) | data[off + 3]
                off += 4
            eth_dst = _mac(data[0:6])
            eth_src = _mac(data[6:12])
        elif lt == LINKTYPE_NULL or lt == LINKTYPE_LOOP:
            if len(data) < 4:
                stats["malformed"] += 1
                return []
            af_le = int.from_bytes(data[:4], "little")
            af_be = int.from_bytes(data[:4], "big")
            off = 4
            if af_le == _AF_INET or af_be == _AF_INET:
                etype = _ETH_IPV4
            elif af_le in _AF_INET6 or af_be in _AF_INET6:
                etype = _ETH_IPV6
            else:
                etype = -1
        elif lt == LINKTYPE_RAW or lt == LINKTYPE_IPV4:
            off = 0
            if not data:
                stats["malformed"] += 1
                return []
            version = data[0] >> 4
            etype = _ETH_IPV4 if version == 4 else _ETH_IPV6 if version == 6 and lt == LINKTYPE_RAW else -1
        elif lt == LINKTYPE_LINUX_SLL:
            if len(data) < 16:
                stats["malformed"] += 1
                return []
            arphrd, addr_len = struct.unpack_from(">HH", data, 2)
            etype = (data[14] << 8) | data[15]
            off = 16
            if arphrd == 1 and addr_len == 6:
                eth_src = _mac(data[6:12])
        elif lt == LINKTYPE_LINUX_SLL2:
            if len(data) < 20:
                stats["malformed"] += 1
                return []
            etype = (data[0] << 8) | data[1]
            arphrd = (data[8] << 8) | data[9]
            addr_len = data[11]
            off = 20
            if arphrd == 1 and addr_len == 6:
                eth_src = _mac(data[12:18])
        else:
            stats["unsupported_linktype"] += 1
            return []

        if etype == _ETH_IPV4:
            return self._ipv4(pkt, data, off, eth_src, eth_dst)
        if etype == _ETH_IPV6:
            stats["ipv6"] += 1
        else:
            stats["non_ip"] += 1
        return []

    # -- IPv4 / UDP --------------------------------------------------------------------------------------------
    def _ipv4(self, pkt: RawPacket, data: bytes, off: int, eth_src: str | None,
              eth_dst: str | None) -> list[UdpDatagram]:
        stats = self.stats
        avail = len(data) - off
        if avail < 20:
            stats["malformed"] += 1
            return []
        vihl = data[off]
        ihl = (vihl & 0x0F) * 4
        if vihl >> 4 != 4 or ihl < 20:
            stats["malformed"] += 1
            return []
        total_len, ident, frag_field = struct.unpack_from(">HHH", data, off + 2)
        proto = data[off + 9]
        if total_len < ihl:
            stats["malformed"] += 1
            return []
        if total_len > avail:
            stats["truncated"] += 1  # snapped short or damaged
            return []
        more_frags = frag_field & 0x2000
        frag_off = (frag_field & 0x1FFF) * 8
        if proto != _IPPROTO_UDP:
            stats["non_udp"] += 1
            return []
        src = data[off + 12:off + 16]
        dst = data[off + 16:off + 20]
        body = data[off + ihl:off + total_len]

        if more_frags or frag_off:
            stats["fragments"] += 1
            done = self._reassemble(pkt.ts, src, dst, ident, proto, frag_off, bool(more_frags), body,
                                    eth_src, eth_dst)
            if done is None:
                return []
            body, eth_src, eth_dst = done
            stats["reassembled"] += 1

        if len(body) < 8:
            stats["malformed"] += 1
            return []
        sport, dport, ulen = struct.unpack_from(">HHH", body)
        if ulen < 8 or ulen > len(body):
            stats["malformed"] += 1
            return []
        stats["udp"] += 1
        return [UdpDatagram(pkt.frame_no, pkt.ts, socket.inet_ntoa(src), sport, socket.inet_ntoa(dst), dport,
                            body[8:ulen], eth_src, eth_dst)]

    def _reassemble(self, ts: float, src: bytes, dst: bytes, ident: int, proto: int, frag_off: int,
                    more: bool, piece: bytes, eth_src: str | None,
                    eth_dst: str | None) -> tuple[bytes, str | None, str | None] | None:
        """Store a fragment; when the datagram is complete return (IP payload, eth_src, eth_dst of first fragment)."""
        self._expire(ts)
        key = (src, dst, ident, proto)
        buf = self._frags.get(key)
        if buf is None:
            if len(self._frags) >= self.max_fragment_buffers:
                oldest = min(self._frags, key=lambda k: self._frags[k].first_ts)
                del self._frags[oldest]
                self.stats["fragments_dropped"] += 1
            buf = self._frags[key] = _FragBuffer(ts)
        if frag_off == 0:
            buf.eth_src, buf.eth_dst = eth_src, eth_dst
        if frag_off + len(piece) > _MAX_IP_LEN:
            del self._frags[key]
            self.stats["malformed"] += 1
            return None
        if more and len(piece) % 8:
            # Only the last fragment may have a length that is not a multiple of 8.
            del self._frags[key]
            self.stats["malformed"] += 1
            return None
        buf.pieces[frag_off] = piece
        if not more:
            buf.total_len = frag_off + len(piece)
        if buf.total_len is None:
            return None

        # Check for contiguous coverage of [0, total_len).
        covered = 0
        for start in sorted(buf.pieces):
            if start > covered:
                return None
            covered = max(covered, start + len(buf.pieces[start]))
        if covered < buf.total_len:
            return None
        out = bytearray(buf.total_len)
        for start in sorted(buf.pieces):
            chunk = buf.pieces[start][: max(0, buf.total_len - start)]
            out[start:start + len(chunk)] = chunk
        del self._frags[key]
        return bytes(out), buf.eth_src or eth_src, buf.eth_dst or eth_dst

    def _expire(self, now: float) -> None:
        if not self._frags:
            return
        limit = now - self.fragment_timeout
        stale = [k for k, b in self._frags.items() if b.first_ts < limit]
        for k in stale:
            del self._frags[k]
        self.stats["fragments_expired"] += len(stale)

    def finish(self) -> None:
        """Account for datagrams still waiting for fragments at end of file."""
        self.stats["fragments_incomplete"] += len(self._frags)
        self._frags.clear()


# -- frame builder -------------------------------------------------------------------------------------------------
def ip_checksum(data: bytes) -> int:
    """RFC 1071 Internet checksum of *data*."""
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f">{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _parse_mac(mac: str) -> bytes:
    b = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if len(b) != 6:
        raise ValueError(f"invalid MAC address: {mac!r}")
    return b


def build_udp_frame(src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload: bytes,
                    src_mac: str = "02:00:00:00:00:01", dst_mac: str | None = None, *,
                    ttl: int = 64, ident: int = 0) -> bytes:
    """Build an Ethernet II + IPv4 + UDP frame with correct IP header and UDP checksums.

    *dst_mac* defaults to ``ff:ff:ff:ff:ff:ff`` when *dst_ip* is 255.255.255.255 or ends in ``.255`` (a directed
    broadcast in the common /24 case), otherwise to the locally administered ``02:00:00:00:00:02``.
    """
    if len(payload) > _MAX_IP_LEN - 28:
        raise ValueError("UDP payload too large for one IPv4 datagram")
    src = socket.inet_aton(src_ip)
    dst = socket.inet_aton(dst_ip)
    if dst_mac is None:
        dst_mac = "ff:ff:ff:ff:ff:ff" if dst_ip.endswith(".255") else "02:00:00:00:00:02"
    udp_len = 8 + len(payload)
    pseudo = src + dst + struct.pack(">BBH", 0, _IPPROTO_UDP, udp_len)
    udp_hdr = struct.pack(">HHHH", src_port, dst_port, udp_len, 0)
    csum = ip_checksum(pseudo + udp_hdr + payload) or 0xFFFF
    udp = struct.pack(">HHHH", src_port, dst_port, udp_len, csum) + payload
    ip_hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + udp_len, ident & 0xFFFF, 0, ttl, _IPPROTO_UDP, 0, src, dst)
    ip_hdr = ip_hdr[:10] + struct.pack(">H", ip_checksum(ip_hdr)) + ip_hdr[12:]
    eth = _parse_mac(dst_mac) + _parse_mac(src_mac) + struct.pack(">H", _ETH_IPV4)
    return eth + ip_hdr + udp
