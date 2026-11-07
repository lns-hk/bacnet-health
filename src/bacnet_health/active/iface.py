"""Network interface enumeration and safe automatic selection (design §3.1, FMEA F5).

``list_interfaces()`` returns IPv4 interfaces using ``getifaddrs`` through ``ctypes`` on macOS/Linux and the Windows
helper module ``bacnet_health.active._win`` on Windows. ``auto_pick()`` ranks them so the tool prefers the wired,
private, no-default-route interface a BMS network is normally on, and explains its choice in plain English. The user
always confirms the pick (design D18).
"""

from __future__ import annotations

import ctypes
import ctypes.util
import ipaddress
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "EgressMismatch", "Iface", "auto_pick", "check_egress", "egress_interface", "has_default_route", "iface_from_cidr",
    "list_interfaces",
]

IFF_UP = 0x1
IFF_LOOPBACK = 0x8
_AF_INET = 2
_CGNAT = ipaddress.ip_network("100.64.0.0/10")
_TUNNEL_PREFIXES = ("utun", "tun", "tap", "ppp", "ipsec", "wg", "tailscale", "zt", "gif", "stf")
_WIN_TUNNEL_IFTYPES = {23, 53, 131}  # PPP, proprietary virtual (TUN/TAP, Wintun), tunnel
_WIN_TUNNEL_WORDS = ("tap-", "wintun", "tailscale", "wireguard", "vpn", "tunnel", "zerotier", "openvpn", "clash")


@dataclass
class Iface:
    name: str
    ip: str
    netmask: str
    prefix: int
    broadcast: str
    is_loopback: bool = False
    is_up: bool = True
    has_default_route: bool = False
    wireless_guess: bool = False
    description: str = ""
    if_index: int | None = None
    mac: str | None = None
    if_type: int | None = None  # Windows IfType, when known
    host_virtual: str | None = None  # Windows: virtual switch inside this PC (Hyper-V Default Switch, WSL, ...)

    @property
    def network(self) -> str:
        """CIDR of the attached subnet, e.g. ``"192.0.2.0/24"``."""
        return str(ipaddress.ip_network(f"{self.ip}/{self.prefix}", strict=False))

    @property
    def is_private(self) -> bool:
        a = ipaddress.ip_address(self.ip)
        return a.is_private or a in _CGNAT

    @property
    def is_tunnel(self) -> bool:
        if self.if_type in _WIN_TUNNEL_IFTYPES:
            return True
        text = f"{self.name} {self.description}".lower()
        return self.name.lower().startswith(_TUNNEL_PREFIXES) or any(w in text for w in _WIN_TUNNEL_WORDS)

    @property
    def is_link_local(self) -> bool:
        return self.ip.startswith("169.254.")

    def label(self) -> str:
        kind = ("loopback" if self.is_loopback else "Wi-Fi" if self.wireless_guess
                else "VPN/tunnel" if self.is_tunnel else "virtual (this PC only)" if self.host_virtual else "wired")
        desc = f" ({self.description})" if self.description else ""
        return f"{self.name}{desc}: {self.ip}/{self.prefix}, {kind}"


def iface_from_cidr(cidr: str, name: str = "manual") -> Iface:
    """Build an Iface from ``--bind IP/LEN`` (used when the user names the address directly)."""
    net = ipaddress.ip_interface(cidr)
    n = net.network
    return Iface(name=name, ip=str(net.ip), netmask=str(n.netmask), prefix=n.prefixlen,
                 broadcast=str(n.broadcast_address), is_loopback=net.ip.is_loopback)


# ---------------------------------------------------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------------------------------------------------


def list_interfaces() -> list[Iface]:
    """All IPv4 interfaces. Never raises: on failure it returns what it could collect (possibly an empty list)."""
    if sys.platform == "win32":
        return _list_windows()
    try:
        raw = _getifaddrs()
    except OSError:
        return []
    wireless = _wireless_names()
    default_if = _default_route_iface()
    out: list[Iface] = []
    for name, flags, ip, mask in raw:
        try:
            n = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        except ValueError:
            continue
        loop = bool(flags & IFF_LOOPBACK)
        out.append(Iface(
            name=name, ip=ip, netmask=mask, prefix=n.prefixlen, broadcast=str(n.broadcast_address),
            is_loopback=loop, is_up=bool(flags & IFF_UP), has_default_route=(name == default_if),
            wireless_guess=(name in wireless) if wireless is not None else name.startswith(("wl", "wlan")),
        ))
    return out


def _list_windows() -> list[Iface]:
    try:
        from bacnet_health.active import _win  # type: ignore[attr-defined]
    except ImportError:
        return []
    out = []
    try:
        rows = _win.list_interfaces_windows(include_extra=True)
    except (OSError, NotImplementedError):
        return []
    for d in rows:
        try:
            out.append(_iface_from_dict(d))
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _iface_from_dict(d: dict[str, Any]) -> Iface:
    return Iface(
        name=str(d.get("name", "")), ip=d["ip"], netmask=d["netmask"], prefix=int(d["prefix"]),
        broadcast=d["broadcast"], is_loopback=bool(d.get("is_loopback")), is_up=bool(d.get("is_up", True)),
        has_default_route=bool(d.get("has_default_route")), wireless_guess=bool(d.get("wireless_guess")),
        description=str(d.get("description") or ""), if_index=d.get("if_index"), mac=d.get("mac"),
        if_type=d.get("if_type"), host_virtual=d.get("host_virtual") or None,
    )


class _Ifaddrs(ctypes.Structure):
    pass


_Ifaddrs._fields_ = [
    ("ifa_next", ctypes.POINTER(_Ifaddrs)),
    ("ifa_name", ctypes.c_char_p),
    ("ifa_flags", ctypes.c_uint),
    ("ifa_addr", ctypes.c_void_p),
    ("ifa_netmask", ctypes.c_void_p),
    ("ifa_dstaddr", ctypes.c_void_p),
    ("ifa_data", ctypes.c_void_p),
]


def _sockaddr_ipv4(ptr: int | None) -> str | None:
    """Return the dotted IPv4 address of a sockaddr, or None if it is not AF_INET."""
    if not ptr:
        return None
    raw = ctypes.string_at(ptr, 8)
    family = raw[1] if sys.platform == "darwin" or "bsd" in sys.platform else int.from_bytes(raw[0:2], sys.byteorder)
    if family != _AF_INET:
        return None
    return str(ipaddress.IPv4Address(raw[4:8]))


def _getifaddrs() -> list[tuple[str, int, str, str]]:
    libc = ctypes.CDLL(ctypes.util.find_library("c") or None, use_errno=True)
    head = ctypes.POINTER(_Ifaddrs)()
    if libc.getifaddrs(ctypes.byref(head)) != 0:
        raise OSError(ctypes.get_errno(), "getifaddrs failed")
    out = []
    try:
        node = head
        while node:
            ifa = node.contents
            ip = _sockaddr_ipv4(ifa.ifa_addr)
            if ip is not None:
                mask = _sockaddr_ipv4(ifa.ifa_netmask) or "255.255.255.255"
                out.append((ifa.ifa_name.decode(errors="replace"), int(ifa.ifa_flags), ip, mask))
            node = ifa.ifa_next
    finally:
        libc.freeifaddrs(head)
    return out


def _run(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def _wireless_names() -> set[str] | None:
    """Wi-Fi interface names on macOS (from networksetup), or None to fall back to name patterns."""
    if sys.platform != "darwin":
        return None
    text = _run(["networksetup", "-listallhardwareports"])
    if not text:
        return {"en0"}  # most Mac laptops: en0 is Wi-Fi; a guess, shown to the user for confirmation
    names, port = set(), ""
    for line in text.splitlines():
        if line.startswith("Hardware Port:"):
            port = line.split(":", 1)[1].strip().lower()
        elif line.startswith("Device:") and ("wi-fi" in port or "airport" in port):
            names.add(line.split(":", 1)[1].strip())
    return names


def _default_route_iface() -> str | None:
    if sys.platform == "darwin" or "bsd" in sys.platform:
        m = re.search(r"interface:\s*(\S+)", _run(["route", "-n", "get", "default"]))
        return m.group(1) if m else None
    try:
        with open("/proc/net/route", encoding="ascii") as fh:
            next(fh, None)
            for line in fh:
                parts = line.split()
                if len(parts) >= 8 and parts[1] == "00000000" and parts[7] == "00000000":
                    return parts[0]
    except OSError:
        pass
    return None


def egress_interface(dst_ip: str) -> str | None:
    """Name of the interface the OS would use to send to ``dst_ip``, or None if it cannot be determined.

    macOS/BSD: ``route -n get``; Linux: ``ip route get``; Windows: ``GetBestInterface`` (iphlpapi) mapped to the
    adapter friendly name. Sends nothing.
    """
    if sys.platform == "win32":
        return _egress_windows(dst_ip)
    if sys.platform == "darwin" or "bsd" in sys.platform:
        m = re.search(r"interface:\s*(\S+)", _run(["route", "-n", "get", dst_ip]))
        return m.group(1) if m else None
    m = re.search(r"\bdev\s+(\S+)", _run(["ip", "-4", "route", "get", dst_ip]))
    return m.group(1) if m else None


def _egress_windows(dst_ip: str) -> str | None:
    try:
        lib = ctypes.WinDLL("iphlpapi")  # type: ignore[attr-defined]
        idx = ctypes.c_ulong(0)
        addr = int.from_bytes(ipaddress.IPv4Address(dst_ip).packed, "little")  # IPAddr is network order in memory
        if lib.GetBestInterface(ctypes.c_ulong(addr), ctypes.byref(idx)) != 0:
            return None
    except (OSError, AttributeError, ValueError):
        return None
    for i in _list_windows():
        if i.if_index == idx.value:
            return i.name
    return None


class EgressMismatch(RuntimeError):
    """Traffic to a destination would leave through a different interface than the one the user picked."""


def check_egress(iface: Iface, dst_ip: str) -> str | None:
    """Raise :class:`EgressMismatch` if ``dst_ip`` would not leave via ``iface``. Returns the egress name (or None).

    A None egress (OS tool unavailable) is not treated as a mismatch; callers record it as "not verified".
    """
    out = egress_interface(dst_ip)
    if out is not None and out != iface.name:
        others = {i.name: i for i in list_interfaces()}
        kind = " (VPN/tunnel)" if out in others and others[out].is_tunnel or out.lower().startswith(
            _TUNNEL_PREFIXES) else ""
        raise EgressMismatch(
            f"Traffic to {dst_ip} would leave via {out}{kind}, not {iface.name}. Disconnect the VPN or proxy tunnel, "
            f"or pick another interface, then try again. Nothing was sent."
        )
    return out


def has_default_route(name: str) -> bool:
    """True if the default IPv4 route leaves through interface ``name``."""
    if sys.platform == "win32":
        return any(i.name == name and i.has_default_route for i in _list_windows())
    return _default_route_iface() == name


# ---------------------------------------------------------------------------------------------------------------------
# Automatic selection
# ---------------------------------------------------------------------------------------------------------------------


@dataclass
class _Score:
    iface: Iface
    score: int = 0
    notes: list[str] = field(default_factory=list)


def _score(i: Iface) -> _Score:
    s = _Score(i)
    if not i.is_up:
        s.score -= 100
        s.notes.append("interface is down")
    if i.is_link_local:
        s.score -= 50
        s.notes.append("link-local 169.254.x.x address only (no DHCP or static address)")
    if i.is_private:
        s.score += 20
        s.notes.append("private address")
    else:
        s.score -= 30
        s.notes.append("public address: unusual for a building network")
    if i.wireless_guess:
        s.score -= 25
        s.notes.append("looks like Wi-Fi (usually the office network, not the BMS)")
    elif i.is_tunnel:
        s.score -= 40
        s.notes.append("VPN or tunnel interface")
    elif i.host_virtual:
        s.score -= 40
        s.notes.append(f"{i.host_virtual}: not a building network")
    else:
        s.score += 15
        s.notes.append("wired")
    if i.has_default_route:
        s.score -= 15
        s.notes.append("carries the default route (likely the office or Internet connection)")
    else:
        s.score += 10
        s.notes.append("no default route")
    if i.prefix >= 31:
        s.score -= 40
        s.notes.append("point-to-point or host-only address: no subnet broadcast")
    return s


def _usable(i: Iface) -> bool:
    return i.is_up and not i.is_loopback and not i.is_tunnel and not i.is_link_local and i.prefix < 31


def auto_pick(ifaces: list[Iface]) -> tuple[Iface | None, list[Iface], list[str]]:
    """Rank interfaces and pick the most likely BMS interface.

    Returns ``(best or None, ranked candidates (best first, loopback excluded), human-readable reasons)``. Loopback is
    never picked. ``best`` is None when nothing usable is up; the reasons then say why. The caller must still ask the
    user to confirm (design D18).
    """
    reasons: list[str] = []
    seen: set[tuple[str, str]] = set()
    candidates = []
    for i in ifaces:
        if not i.is_loopback and (i.name, i.ip) not in seen:
            seen.add((i.name, i.ip))
            candidates.append(i)
    if any(i.is_loopback for i in ifaces):
        reasons.append("Loopback interfaces are never used for scanning.")
    scored = sorted((_score(i) for i in candidates), key=lambda s: (-s.score, s.iface.name, s.iface.ip))
    ranked = [s.iface for s in scored]
    usable = [s for s in scored if _usable(s.iface)]
    skipped = [s.iface.name for s in scored if s.iface.is_up and not _usable(s.iface)]
    if skipped:
        reasons.append("Not considered (VPN/tunnel, point-to-point or link-local 169.254.x.x): "
                       + ", ".join(sorted(set(skipped))) + ".")
    if not usable:
        reasons.append("No usable interface is up. Connect the laptop to the BMS network and try again.")
        return None, ranked, reasons
    best = usable[0]
    reasons.append(f"Picked {best.iface.label()}: " + ", ".join(best.notes) + ".")
    reasons.append(f"Broadcasts will go to {best.iface.broadcast} only (never 255.255.255.255).")
    if len(usable) > 1:
        runner = usable[1]
        if runner.score == best.score:
            reasons.append(f"{runner.iface.label()} looks equally suitable; check which one is the BMS network.")
        else:
            reasons.append(f"Not picked: {runner.iface.label()} ({', '.join(runner.notes)}).")
    if best.iface.wireless_guess or best.iface.has_default_route:
        reasons.append("Warning: the picked interface may be the office network. Confirm before scanning.")
    return best.iface, ranked, reasons
