"""The one UDP socket the tool transmits through (design §1.1, §1.2, §3.1, FMEA F5/F8/F10).

Every frame leaves through :meth:`BacnetTransport._sendto`, which in this order:

1. runs :func:`bacnet_health.wire.txguard.check_tx` (allow-list; raises ``TxBlocked``);
2. waits for the global token-bucket :class:`RateLimiter`;
3. checks the cancel ``Event`` immediately before ``sendto()`` (kill switch);
4. records the frame in the :class:`~bacnet_health.model.Budget` counters and the in-memory sent log.

Broadcasts go only to the selected interface's directed broadcast address, never ``255.255.255.255``. The socket is
bound exclusively: ``SO_REUSEADDR``/``SO_REUSEPORT`` are never set; on Windows ``SO_EXCLUSIVEADDRUSE`` is used.

Egress control (validated on Windows: a ``0.0.0.0`` socket leaked traffic into VPN/proxy tunnel adapters):

* Windows binds the interface IP (it then receives directed and limited broadcasts too);
* macOS binds ``0.0.0.0`` (to receive subnet broadcasts) and pins the socket with ``IP_BOUND_IF``;
* Linux tries ``SO_BINDTODEVICE`` (needs privileges) and otherwise relies on the route check;
* on every OS, the broadcast address and each new unicast destination must route out of the chosen interface
  (:func:`bacnet_health.active.iface.check_egress`), otherwise :class:`EgressMismatch` is raised before sending.

Before binding, the port's current owners are looked up (Windows ``port_owners``; ``lsof`` elsewhere) because a
successful bind does not prove that no other program holds the port on another local address.
"""

from __future__ import annotations

import collections
import errno
import ipaddress
import re
import select
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from typing import Callable, Iterable

from bacnet_health._proc import run_hidden
from bacnet_health.active.iface import EgressMismatch, Iface, check_egress
from bacnet_health.model import Budget
from bacnet_health.wire.message import decode_message
from bacnet_health.wire.txguard import check_tx

__all__ = ["BacnetTransport", "EgressMismatch", "PortInUse", "RateLimiter", "Received", "SentFrame", "port_owner",
           "port_owners"]

_IP_RECVDSTADDR = getattr(socket, "IP_RECVDSTADDR", None)  # BSD/macOS: cmsg carries struct in_addr
_IP_PKTINFO = getattr(socket, "IP_PKTINFO", 8 if sys.platform.startswith("linux") else None)  # Linux: in_pktinfo
_SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", ~4)  # Windows: (int)(~SO_REUSEADDR)
_IP_BOUND_IF = 25  # macOS <netinet/in.h>
_SO_BINDTODEVICE = getattr(socket, "SO_BINDTODEVICE", 25)  # Linux
_ADDR_IN_USE = {errno.EADDRINUSE, getattr(errno, "WSAEADDRINUSE", 10048), 10013}  # 10013: WSAEACCES on exclusive


class PortInUse(OSError):
    """The BACnet port is already bound by another program. ``str()`` is a plain-English message for the user."""

    def __init__(self, port: int, owner: str | None = None) -> None:
        who = f" by {owner}" if owner else " by another program"
        super().__init__(
            errno.EADDRINUSE,
            f"UDP port {port} is already in use{who}. BACnet software (a BMS workstation, another scanner or a "
            f"simulator) is probably running on this computer. Close it, or choose another port (47809-47823) and "
            f"try again. bacnet-health never shares the port, so it cannot disturb the other program.",
        )
        self.port = port
        self.owner = owner

    def __str__(self) -> str:
        return str(self.strerror)


class RateLimiter:
    """Token bucket: ``rate`` tokens per second, at most ``capacity`` stored. Capacity 1 = strict spacing 1/rate."""

    def __init__(self, rate: float, capacity: float = 1.0, clock: Callable[[], float] = time.monotonic) -> None:
        if rate <= 0:
            raise ValueError("rate must be > 0")
        self.rate = float(rate)
        self.capacity = max(1.0, float(capacity))
        self.clock = clock
        self._tokens = self.capacity
        self._last = clock()
        self._lock = threading.Lock()

    def _refill(self) -> None:
        now = self.clock()
        self._tokens = min(self.capacity, self._tokens + (now - self._last) * self.rate)
        self._last = now

    def wait_time(self) -> float:
        """Seconds until one token is available (0 if available now)."""
        with self._lock:
            self._refill()
            return 0.0 if self._tokens >= 1.0 else (1.0 - self._tokens) / self.rate

    def try_acquire(self) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False


@dataclass
class SentFrame:
    ts: float  # wall clock (epoch seconds)
    mono: float  # monotonic clock
    dst: str  # "ip:port", or "broadcast ip:port"
    kind: str  # decode_message kind, e.g. "who-is", "read-property", "bvlc:read-broadcast-dist-table"
    size: int
    category: str  # "whois" | "read" | "bvlc" | "other"
    data: bytes = b""  # the frame as sent (kept in memory for the dry-run/packet preview and self-checks)


@dataclass
class Received:
    data: bytes
    src: tuple[str, int]
    dst_ip: str | None  # header destination if the OS reports it (IP_RECVDSTADDR / IP_PKTINFO), else None
    ts: float  # wall clock


def _category(kind: str) -> str:
    if kind == "who-is":
        return "whois"
    if kind in ("read-property", "rpm"):
        return "read"
    if kind.startswith("bvlc:"):
        return "bvlc"
    return "other"


def port_owners(port: int) -> list[str]:
    """Best-effort list of programs holding UDP ``port`` on any local address ("name (PID n) on ip"); [] if free
    or unknown."""
    if sys.platform == "win32":
        try:
            from bacnet_health.active import _win

            return [f"{o.get('name') or 'unknown program'} (PID {o.get('pid')}) on {o.get('local_ip')}"
                    for o in _win.port_owners(port)]
        except Exception:  # noqa: BLE001 - optional helper; any failure means "unknown"
            return []
    try:
        out = run_hidden(["lsof", "-nP", f"-iUDP:{port}"], capture_output=True, text=True, timeout=3).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    owners = []
    for line in out.splitlines()[1:]:
        m = re.match(r"(\S+)\s+(\d+)\s.*?UDP\s+(\S+)", line)
        if m and m.group(3).rsplit(":", 1)[-1] == str(port):
            owners.append(f"{m.group(1)} (PID {m.group(2)}) on {m.group(3).rsplit(':', 1)[0]}")
    return owners


def port_owner(port: int) -> str | None:
    owners = port_owners(port)
    if not owners:
        return None
    return owners[0] + (f" and {len(owners) - 1} other(s)" if len(owners) > 1 else "")


class BacnetTransport:
    """Exclusive UDP socket with an allow-list, rate limit, kill switch and traffic accounting.

    ``local_ip``/``broadcast``/``subnet`` describe the selected interface. ``bind_ip`` defaults to ``0.0.0.0`` on
    macOS/Linux (needed to receive subnet broadcasts) and to ``local_ip`` on Windows. Received frames are filtered to
    ``subnet`` plus addresses added with :meth:`allow_source`, unless ``test_mode`` is set.

    ``iface`` (an :class:`~bacnet_health.active.iface.Iface`) fills ``local_ip``/``broadcast``/``subnet`` and enables
    interface pinning and the egress route check. ``test_mode`` (implied by ``broadcast_targets``) disables subnet
    filtering, the egress check and the pre-bind owner lookup, so tests can run on 127.0.0.1.

    ``broadcast_targets`` (tests only): a list of ``(ip, port)``; a broadcast is fanned out to each of them as unicast
    datagrams (localhost has no broadcast). It is still counted and logged as one broadcast frame.
    """

    def __init__(
        self,
        bind_ip: str | None = None,
        port: int = 47808,
        *,
        iface: Iface | None = None,
        local_ip: str | None = None,
        broadcast: str | None = None,
        subnet: str | None = None,
        broadcast_targets: Iterable[tuple[str, int]] | None = None,
        rate: float = 5.0,
        burst: float = 1.0,
        cancel: threading.Event | None = None,
        budget: Budget | None = None,
        test_mode: bool = False,
        want_dst: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if iface is not None:
            local_ip = local_ip or iface.ip
            broadcast = broadcast or iface.broadcast
            subnet = subnet or iface.network
        if broadcast == "255.255.255.255":
            raise ValueError("limited broadcast 255.255.255.255 is never used; give the interface's directed "
                             "broadcast address")
        self.local_ip = local_ip
        self.iface = iface
        self.broadcast = broadcast
        self.subnet = ipaddress.ip_network(subnet, strict=False) if subnet else None
        self.broadcast_targets = list(broadcast_targets) if broadcast_targets is not None else None
        self.test_mode = test_mode or self.broadcast_targets is not None
        self.cancel = cancel or threading.Event()
        self.budget = budget or Budget()
        self.limiter = RateLimiter(rate, burst, clock)
        self.clock = clock
        self.sent_log: list[SentFrame] = []
        self.stats = collections.Counter()
        self._allowed: set[str] = set()
        self._recent: collections.deque[float] = collections.deque()
        self._lock = threading.Lock()
        if bind_ip is None:
            bind_ip = (local_ip or "0.0.0.0") if sys.platform == "win32" else "0.0.0.0"
        self.bind_ip = bind_ip
        if port and not self.test_mode:
            owners = port_owners(port)
            if owners:
                raise PortInUse(port, ", ".join(owners))
        self.egress: dict[str, str | None] = {}  # destination ip -> egress interface name (None = not verifiable)
        self.pinned: str | None = None  # how the socket is tied to the interface
        self.sock = self._open(bind_ip, port)
        self.port = self.sock.getsockname()[1]
        if iface is not None and not self.test_mode:
            try:
                self._pin(iface)
                if self.broadcast:
                    self._verify_egress(self.broadcast)
            except BaseException:
                self.sock.close()
                raise
        self.want_dst = want_dst and self._enable_dst()
        self.own_addrs: set[tuple[str, int]] = {(bind_ip, self.port)}
        self.own_ips: set[str] = set()
        if local_ip:
            self.own_addrs.add((local_ip, self.port))
            self.own_ips.add(local_ip)

    # ------------------------------------------------------------------ socket setup
    @staticmethod
    def _open(bind_ip: str, port: int) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            if sys.platform == "win32":
                _win_exclusive_bind(sock, bind_ip, port)
            else:
                sock.bind((bind_ip, port))  # no SO_REUSEADDR / SO_REUSEPORT, ever (FMEA F8)
            sock.setblocking(False)
        except OSError as exc:
            sock.close()
            if exc.errno in _ADDR_IN_USE or getattr(exc, "winerror", None) in _ADDR_IN_USE:
                raise PortInUse(port, port_owner(port)) from None
            raise
        return sock

    def _pin(self, iface: Iface) -> None:
        if sys.platform == "darwin":
            try:
                self.sock.setsockopt(socket.IPPROTO_IP, _IP_BOUND_IF, socket.if_nametoindex(iface.name))
                self.pinned = f"IP_BOUND_IF {iface.name}"
            except OSError:
                self.pinned = None
        elif sys.platform.startswith("linux"):
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, _SO_BINDTODEVICE, iface.name.encode() + b"\0")
                self.pinned = f"SO_BINDTODEVICE {iface.name}"
            except OSError:  # EPERM without CAP_NET_RAW: rely on the route check
                self.pinned = None
        elif sys.platform == "win32":
            self.pinned = f"bound to {self.bind_ip}"

    def verify_egress(self, ip: str) -> None:
        """Raise EgressMismatch unless ``ip`` routes out of the chosen interface. Sends nothing (pre-flight)."""
        self._verify_egress(ip)

    def _verify_egress(self, ip: str) -> None:
        """Raise EgressMismatch unless ``ip`` routes out of the chosen interface (cached per destination)."""
        if self.iface is None or self.test_mode or ip in self.egress:
            return
        self.egress[ip] = check_egress(self.iface, ip)
        if self.egress[ip] is None:
            self.stats["egress_unverified"] += 1

    def _enable_dst(self) -> bool:
        if not hasattr(self.sock, "recvmsg"):
            return False
        opt = _IP_RECVDSTADDR if _IP_RECVDSTADDR is not None else _IP_PKTINFO
        if opt is None:
            return False
        try:
            self.sock.setsockopt(socket.IPPROTO_IP, opt, 1)
            return True
        except OSError:
            return False

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self) -> "BacnetTransport":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ------------------------------------------------------------------ sending
    @property
    def cancelled(self) -> bool:
        return self.cancel.is_set()

    def ready_in(self) -> float:
        """Seconds until the rate limiter allows the next frame."""
        return self.limiter.wait_time()

    def allow_source(self, ip: str) -> None:
        """Accept received frames from ``ip`` even though it is outside the local subnet (unicast targets, BBMDs)."""
        self._allowed.add(ip)

    def send_unicast(self, frame: bytes, addr: tuple[str, int]) -> bool:
        """Send ``frame`` to ``addr``. Returns False (nothing sent) if the run was cancelled."""
        if self._is_broadcast_addr(addr[0]):
            raise ValueError(f"{addr[0]} is a broadcast address; use send_broadcast()")
        self._verify_egress(addr[0])
        return self._sendto(frame, [addr], f"{addr[0]}:{addr[1]}")

    def send_broadcast(self, frame: bytes, port: int | None = None) -> bool:
        """Send ``frame`` to the interface's directed broadcast address. Returns False if cancelled."""
        port = port or self.port
        if self.broadcast_targets is not None:
            return self._sendto(frame, self.broadcast_targets, f"broadcast {self.broadcast or 'test'}:{port}")
        if not self.broadcast or self.broadcast == "255.255.255.255":
            raise ValueError("no directed broadcast address configured for this interface")
        return self._sendto(frame, [(self.broadcast, port)], f"broadcast {self.broadcast}:{port}")

    @property
    def inbound_verified(self) -> bool:
        """True once any datagram from a source other than this tool has been received."""
        return self.stats["foreign_received"] > 0

    def _is_broadcast_addr(self, ip: str) -> bool:
        if ip == "255.255.255.255":
            return True
        return self.subnet is not None and self.subnet.prefixlen < 31 and ip == str(self.subnet.broadcast_address)

    def _sendto(self, frame: bytes, dests: list[tuple[str, int]], label: str) -> bool:
        frame = bytes(frame)
        check_tx(frame)  # raises TxBlocked; never caught here
        while True:
            if self.cancel.is_set():
                return False
            wait = self.limiter.wait_time()
            if wait <= 0 and self.limiter.try_acquire():
                break
            self.cancel.wait(min(max(wait, 0.001), 0.02))
        kind = decode_message(frame).kind
        sent_any = False
        with self._lock:
            for dst in dests:
                if self.cancel.is_set():  # kill switch: checked right before every sendto()
                    break
                try:
                    self.sock.sendto(frame, dst)
                    sent_any = True
                except OSError as exc:
                    self.stats["send_errors"] += 1
                    self.stats[f"send_error:{exc.errno}"] += 1
            if not sent_any:
                return False
            self._account(frame, kind, label)
        return True

    def _account(self, frame: bytes, kind: str, label: str) -> None:
        mono = self.clock()
        cat = _category(kind)
        b = self.budget
        b.frames_sent += 1
        if cat == "whois":
            b.whois_sent += 1
        elif cat == "read":
            b.reads_sent += 1
        elif cat == "bvlc":
            b.bvlc_probes_sent += 1
        self._recent.append(mono)
        while self._recent and self._recent[0] <= mono - 1.0:
            self._recent.popleft()
        b.peak_pps_actual = max(b.peak_pps_actual, float(len(self._recent)))
        self.sent_log.append(SentFrame(time.time(), mono, label, kind, len(frame), cat, frame))

    # ------------------------------------------------------------------ receiving
    def recv(self, timeout: float) -> tuple[bytes, tuple[str, int]] | None:
        r = self.recv_datagram(timeout)
        return None if r is None else (r.data, r.src)

    def recv_datagram(self, timeout: float) -> Received | None:
        """Wait up to ``timeout`` s for one accepted datagram. Own frames and off-subnet sources are dropped."""
        deadline = self.clock() + max(0.0, timeout)
        while True:
            remaining = max(0.0, deadline - self.clock())
            try:
                ready, _, _ = select.select([self.sock], [], [], remaining)
            except (OSError, ValueError):
                return None  # socket closed
            if not ready:
                return None
            got = self._read_one()
            if got is not None:
                return got
            if self.clock() >= deadline:
                return None

    def _read_one(self) -> Received | None:
        dst_ip = None
        try:
            if self.want_dst:
                data, anc, _flags, src = self.sock.recvmsg(65535, socket.CMSG_SPACE(64))
                dst_ip = _dst_from_cmsg(anc)
            else:
                data, src = self.sock.recvfrom(65535)
        except (BlockingIOError, InterruptedError):
            return None
        except OSError:
            # Windows reports ICMP port-unreachable as WSAECONNRESET on the next recv; ignore it.
            self.stats["recv_errors"] += 1
            return None
        src = (src[0], src[1])
        self.stats["received"] += 1
        if src in self.own_addrs or (not self.test_mode and src[0] in self.own_ips):
            self.stats["own_dropped"] += 1  # our own broadcasts loop back (all OSes)
            return None
        self.stats["foreign_received"] += 1
        if not self.test_mode and self.subnet is not None and src[0] not in self._allowed:
            try:
                inside = ipaddress.ip_address(src[0]) in self.subnet
            except ValueError:
                inside = False
            if not inside:
                self.stats["off_subnet_dropped"] += 1
                return None
        return Received(bytes(data), src, dst_ip, time.time())


def _dst_from_cmsg(anc: list[tuple[int, int, bytes]]) -> str | None:
    for level, ctype, data in anc:
        if level != socket.IPPROTO_IP:
            continue
        if _IP_RECVDSTADDR is not None and ctype == _IP_RECVDSTADDR and len(data) >= 4:
            return socket.inet_ntoa(data[:4])
        if _IP_PKTINFO is not None and ctype == _IP_PKTINFO and len(data) >= 12:
            return socket.inet_ntoa(data[8:12])  # struct in_pktinfo: ifindex, spec_dst, addr (header dst)
    return None


def _win_exclusive_bind(sock: socket.socket, ip: str, port: int) -> None:
    try:
        from bacnet_health.active import _win  # type: ignore[attr-defined]

        fn = getattr(_win, "exclusive_bind", None)
    except ImportError:
        fn = None
    if fn is not None:
        fn(sock, (ip, port))
        return
    sock.setsockopt(socket.SOL_SOCKET, _SO_EXCLUSIVEADDRUSE, 1)
    sock.bind((ip, port))
