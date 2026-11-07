"""Windows-only platform helpers for bacnet-health.

stdlib + ctypes only. This module imports cleanly on every OS so that the
cross-platform code (``active/iface.py``, the GUI pre-flight) can import it
unconditionally, but every public function raises :class:`NotImplementedError`
when called on a non-Windows platform.

Nothing in this module sends network traffic or changes system state:

* :func:`list_interfaces_windows` - ``GetAdaptersAddresses`` (iphlpapi).
* :func:`exclusive_bind` - ``SO_EXCLUSIVEADDRUSE`` then ``bind`` (design D9/F8).
* :func:`port_owners` / :func:`port_owner` - ``GetExtendedUdpTable``
  (iphlpapi) + ``QueryFullProcessImageNameW``, falling back to ``tasklist``.
* :func:`firewall_inbound_status` - read-only query of the Windows Defender
  Firewall policy (``HNetCfg.FwPolicy2`` COM object, through PowerShell).

Empirical behaviour behind these choices is recorded in
``docs/dev/windows-validation.md``.
"""

from __future__ import annotations

import base64
import ctypes
import ipaddress
import json
import os
import socket
import subprocess
import sys
from typing import Any

IS_WINDOWS = sys.platform == "win32"

__all__ = [
    "IS_WINDOWS",
    "list_interfaces_windows",
    "exclusive_bind",
    "is_addr_in_use_error",
    "port_owners",
    "port_owner",
    "firewall_inbound_status",
]

# --- constants -------------------------------------------------------------

AF_INET = 2
AF_INET6 = 23
AF_UNSPEC = 0

ERROR_SUCCESS = 0
ERROR_INSUFFICIENT_BUFFER = 122
ERROR_BUFFER_OVERFLOW = 111
ERROR_NO_DATA = 232

GAA_FLAG_SKIP_ANYCAST = 0x0002
GAA_FLAG_SKIP_MULTICAST = 0x0004
GAA_FLAG_SKIP_DNS_SERVER = 0x0008
GAA_FLAG_INCLUDE_GATEWAYS = 0x0080

IF_TYPE_ETHERNET_CSMACD = 6
IF_TYPE_SOFTWARE_LOOPBACK = 24
IF_TYPE_PPP = 23
IF_TYPE_TUNNEL = 131
IF_TYPE_IEEE80211 = 71
IF_OPER_STATUS_UP = 1

UDP_TABLE_OWNER_PID = 1
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

# Winsock error codes seen on bind() when a port is taken (see validation doc).
WSAEACCES = 10013
WSAEADDRINUSE = 10048

# SO_EXCLUSIVEADDRUSE is ~SO_REUSEADDR == -5. Python exposes it on Windows.
SO_EXCLUSIVEADDRUSE = getattr(socket, "SO_EXCLUSIVEADDRUSE", ~socket.SO_REUSEADDR)

_CREATE_NO_WINDOW = 0x08000000  # keep the GUI exe from flashing a console


def _require_windows(func: str) -> None:
    if not IS_WINDOWS:
        raise NotImplementedError(f"{func}() is only available on Windows")


# --- ctypes structures (only the leading fields we read) -------------------
#
# The OS allocates and fills these; we only ever read through pointers, so a
# prefix of the real struct layout is sufficient and safe.


class SOCKET_ADDRESS(ctypes.Structure):
    _fields_ = [("lpSockaddr", ctypes.c_void_p), ("iSockaddrLength", ctypes.c_int)]


class IP_ADAPTER_UNICAST_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Next", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
    ("PrefixOrigin", ctypes.c_int),
    ("SuffixOrigin", ctypes.c_int),
    ("DadState", ctypes.c_int),
    ("ValidLifetime", ctypes.c_ulong),
    ("PreferredLifetime", ctypes.c_ulong),
    ("LeaseLifetime", ctypes.c_ulong),
    ("OnLinkPrefixLength", ctypes.c_ubyte),
]


class IP_ADAPTER_GATEWAY_ADDRESS(ctypes.Structure):
    pass


IP_ADAPTER_GATEWAY_ADDRESS._fields_ = [
    ("Length", ctypes.c_ulong),
    ("Reserved", ctypes.c_ulong),
    ("Next", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Address", SOCKET_ADDRESS),
]


class IP_ADAPTER_ADDRESSES(ctypes.Structure):
    pass


IP_ADAPTER_ADDRESSES._fields_ = [
    ("Length", ctypes.c_ulong),
    ("IfIndex", ctypes.c_ulong),
    ("Next", ctypes.POINTER(IP_ADAPTER_ADDRESSES)),
    ("AdapterName", ctypes.c_char_p),
    ("FirstUnicastAddress", ctypes.POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
    ("FirstAnycastAddress", ctypes.c_void_p),
    ("FirstMulticastAddress", ctypes.c_void_p),
    ("FirstDnsServerAddress", ctypes.c_void_p),
    ("DnsSuffix", ctypes.c_wchar_p),
    ("Description", ctypes.c_wchar_p),
    ("FriendlyName", ctypes.c_wchar_p),
    ("PhysicalAddress", ctypes.c_ubyte * 8),
    ("PhysicalAddressLength", ctypes.c_ulong),
    ("Flags", ctypes.c_ulong),
    ("Mtu", ctypes.c_ulong),
    ("IfType", ctypes.c_ulong),
    ("OperStatus", ctypes.c_int),
    ("Ipv6IfIndex", ctypes.c_ulong),
    ("ZoneIndices", ctypes.c_ulong * 16),
    ("FirstPrefix", ctypes.c_void_p),
    ("TransmitLinkSpeed", ctypes.c_uint64),
    ("ReceiveLinkSpeed", ctypes.c_uint64),
    ("FirstWinsServerAddress", ctypes.c_void_p),
    ("FirstGatewayAddress", ctypes.POINTER(IP_ADAPTER_GATEWAY_ADDRESS)),
    ("Ipv4Metric", ctypes.c_ulong),
    ("Ipv6Metric", ctypes.c_ulong),
]


class MIB_UDPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


class MIB_UDP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


def _iphlpapi() -> Any:
    lib = ctypes.WinDLL("iphlpapi", use_last_error=True)  # type: ignore[attr-defined]
    lib.GetAdaptersAddresses.argtypes = [
        ctypes.c_ulong, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
    ]
    lib.GetAdaptersAddresses.restype = ctypes.c_ulong
    lib.GetExtendedUdpTable.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong), ctypes.c_int,
        ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong,
    ]
    lib.GetExtendedUdpTable.restype = ctypes.c_ulong
    return lib


def _sockaddr_ipv4(sa: SOCKET_ADDRESS) -> str | None:
    """Return dotted IPv4 from a SOCKET_ADDRESS, or None if not AF_INET."""
    if not sa.lpSockaddr or sa.iSockaddrLength < 8:
        return None
    raw = ctypes.string_at(sa.lpSockaddr, 8)  # family(2) port(2) addr(4)
    if int.from_bytes(raw[0:2], "little") != AF_INET:
        return None
    return socket.inet_ntoa(raw[4:8])


# --- interfaces -------------------------------------------------------------


def list_interfaces_windows(include_extra: bool = False) -> list[dict]:
    """Enumerate IPv4 unicast addresses of all adapters via GetAdaptersAddresses.

    One dict per IPv4 unicast address (an adapter with two IPv4 addresses
    yields two dicts). Adapters that are down are included with
    ``is_up=False``. Keys (stable contract for ``active/iface.py``):

    ``name`` adapter friendly name (may be localised, e.g. "Ethernet 2"),
    ``description``, ``ip``, ``prefix`` (int), ``netmask``, ``broadcast``
    (directed broadcast computed from ip/prefix), ``is_up`` (OperStatus Up),
    ``is_loopback`` (IfType 24), ``has_default_route`` (adapter has an IPv4
    gateway address), ``wireless_guess`` (IfType 71), ``if_index`` (IPv4
    IfIndex), ``mac`` (``"aa:bb:cc:dd:ee:ff"`` lowercase, or ``None`` for
    adapters without a hardware address such as tunnels).

    With ``include_extra=True`` the dicts also carry ``if_type``,
    ``ipv4_metric``, ``mtu``, ``link_local`` (169.254/16) and ``adapter_id``
    (the GUID name), which help the auto-pick heuristic (design F5).
    """
    _require_windows("list_interfaces_windows")
    lib = _iphlpapi()
    flags = GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER
    size = ctypes.c_ulong(16 * 1024)
    for _ in range(4):  # size can grow between calls if adapters change
        buf = ctypes.create_string_buffer(size.value)
        rc = lib.GetAdaptersAddresses(AF_INET, flags, None, buf, ctypes.byref(size))
        if rc == ERROR_BUFFER_OVERFLOW:
            continue
        break
    if rc == ERROR_NO_DATA:
        return []
    if rc != ERROR_SUCCESS:
        raise OSError(rc, f"GetAdaptersAddresses failed ({rc})")

    out: list[dict] = []
    p = ctypes.cast(buf, ctypes.POINTER(IP_ADAPTER_ADDRESSES))
    while p:
        a = p.contents
        has_gw = False
        g = a.FirstGatewayAddress
        while g:
            gw = _sockaddr_ipv4(g.contents.Address)
            if gw and gw != "0.0.0.0":
                has_gw = True
                break
            g = g.contents.Next
        mac_len = min(int(a.PhysicalAddressLength), 8)
        mac = ":".join(f"{b:02x}" for b in a.PhysicalAddress[:mac_len]) if mac_len else None
        if mac is not None and set(mac.replace(":", "")) == {"0"}:
            mac = None
        u = a.FirstUnicastAddress
        while u:
            ip = _sockaddr_ipv4(u.contents.Address)
            if ip:
                prefix = int(u.contents.OnLinkPrefixLength)
                net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
                d: dict[str, Any] = {
                    "name": a.FriendlyName or "",
                    "description": a.Description or "",
                    "ip": ip,
                    "prefix": prefix,
                    "netmask": str(net.netmask),
                    "broadcast": str(net.broadcast_address),
                    "is_up": a.OperStatus == IF_OPER_STATUS_UP,
                    "is_loopback": a.IfType == IF_TYPE_SOFTWARE_LOOPBACK,
                    "has_default_route": has_gw,
                    "wireless_guess": a.IfType == IF_TYPE_IEEE80211,
                    "if_index": int(a.IfIndex),
                    "mac": mac,
                }
                if include_extra:
                    d.update(
                        if_type=int(a.IfType),
                        ipv4_metric=int(a.Ipv4Metric),
                        mtu=int(a.Mtu),
                        link_local=ipaddress.IPv4Address(ip).is_link_local,
                        adapter_id=(a.AdapterName or b"").decode("ascii", "replace"),
                    )
                out.append(d)
            u = u.contents.Next
        p = a.Next
    return out


# --- exclusive bind --------------------------------------------------------


def exclusive_bind(sock: socket.socket, addr: tuple[str, int]) -> None:
    """Bind ``sock`` to ``addr`` with ``SO_EXCLUSIVEADDRUSE`` (design D9/F8).

    ``SO_REUSEADDR`` is never set; if the caller already set it, this raises
    ``ValueError`` (the two options are mutually exclusive on Windows and a
    reusable socket would let other programs steal our replies).

    ``OSError`` from ``bind`` propagates unchanged; use
    :func:`is_addr_in_use_error` to recognise "port taken". On this platform
    a conflicting bind fails with ``WSAEADDRINUSE`` (10048), or ``WSAEACCES``
    (10013) in some combinations - see docs/dev/windows-validation.md.
    """
    _require_windows("exclusive_bind")
    if sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR):
        raise ValueError("socket has SO_REUSEADDR set; refusing (design F8)")
    sock.setsockopt(socket.SOL_SOCKET, SO_EXCLUSIVEADDRUSE, 1)
    sock.bind(addr)


def is_addr_in_use_error(exc: BaseException) -> bool:
    """True if ``exc`` is the error Windows returns for a bind to a taken port."""
    return isinstance(exc, OSError) and getattr(exc, "winerror", None) in (WSAEADDRINUSE, WSAEACCES)


# --- port owner ------------------------------------------------------------


def _process_image(pid: int) -> tuple[str | None, str | None]:
    """(name, full path) for ``pid`` without admin; path may be None."""
    if pid == 0:
        return "System Idle Process", None
    if pid == 4:
        return "System", None
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        k32.QueryFullProcessImageNameW.argtypes = [
            ctypes.c_void_p, ctypes.c_ulong, ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulong),
        ]
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        h = k32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if h:
            try:
                n = ctypes.c_ulong(32768)
                buf = ctypes.create_unicode_buffer(n.value)
                if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
                    path = buf.value
                    return os.path.basename(path), path
            finally:
                k32.CloseHandle(h)
    except OSError:
        pass
    # Fallback: tasklist usually knows the image name even for protected processes.
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/FO", "CSV", "/NH"],
            capture_output=True, text=True, timeout=10, creationflags=_CREATE_NO_WINDOW,
        )
        line = r.stdout.strip().splitlines()[0] if r.stdout.strip() else ""
        if line.startswith('"'):
            return line.split('","')[0].strip('"'), None
    except (OSError, subprocess.SubprocessError, IndexError):
        pass
    return None, None


def _udp_table(lib: Any, family: int) -> list[tuple[str, int, int]]:
    size = ctypes.c_ulong(0)
    rc = ERROR_INSUFFICIENT_BUFFER
    buf = None
    for _ in range(4):
        buf = ctypes.create_string_buffer(max(size.value, 4))
        rc = lib.GetExtendedUdpTable(buf, ctypes.byref(size), 0, family, UDP_TABLE_OWNER_PID, 0)
        if rc != ERROR_INSUFFICIENT_BUFFER:
            break
    if rc != ERROR_SUCCESS or buf is None:
        raise OSError(rc, f"GetExtendedUdpTable failed ({rc})")
    n = ctypes.c_uint32.from_buffer(buf).value
    rows: list[tuple[str, int, int]] = []
    off = ctypes.sizeof(ctypes.c_uint32)
    if family == AF_INET:
        arr = (MIB_UDPROW_OWNER_PID * n).from_buffer(buf, off)
        for r in arr:
            ip = socket.inet_ntoa(r.dwLocalAddr.to_bytes(4, "little"))
            port = socket.ntohs(r.dwLocalPort & 0xFFFF)
            rows.append((ip, port, int(r.dwOwningPid)))
    else:
        arr6 = (MIB_UDP6ROW_OWNER_PID * n).from_buffer(buf, off)
        for r in arr6:
            ip = socket.inet_ntop(socket.AF_INET6, bytes(r.ucLocalAddr))
            port = socket.ntohs(r.dwLocalPort & 0xFFFF)
            rows.append((ip, port, int(r.dwOwningPid)))
    return rows


def port_owners(port: int) -> list[dict]:
    """All local UDP endpoints on ``port`` with their owning process (no admin).

    Each dict: ``pid``, ``name`` (image name or None), ``path`` (full image
    path or None), ``local_ip``, ``family`` ("ipv4"/"ipv6"). Returns ``[]``
    if nothing is bound to the port.
    """
    _require_windows("port_owners")
    lib = _iphlpapi()
    found: list[dict] = []
    cache: dict[int, tuple[str | None, str | None]] = {}
    for fam, fam_name in ((AF_INET, "ipv4"), (AF_INET6, "ipv6")):
        try:
            rows = _udp_table(lib, fam)
        except OSError:
            continue
        for ip, p, pid in rows:
            if p != port:
                continue
            if pid not in cache:
                cache[pid] = _process_image(pid)
            name, path = cache[pid]
            found.append({"pid": pid, "name": name, "path": path, "local_ip": ip, "family": fam_name})
    return found


def port_owner(port: int) -> dict | None:
    """Best-effort owner of UDP ``port`` for the "port 47808 in use" message.

    Returns the first IPv4 endpoint (else IPv6) as a dict (see
    :func:`port_owners`) plus ``others``: the number of further endpoints on
    the same port. ``None`` if the port is free.
    """
    owners = port_owners(port)
    if not owners:
        return None
    owners.sort(key=lambda o: o["family"] != "ipv4")
    first = dict(owners[0])
    first["others"] = len(owners) - 1
    return first


# --- firewall --------------------------------------------------------------

# Read-only PowerShell script. Inputs arrive through environment variables so
# no user-controlled text is ever spliced into the script.
_FW_PS = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$out = [ordered]@{ ok = $false }
try {
  $p = New-Object -ComObject HNetCfg.FwPolicy2
  $cur = [int]$p.CurrentProfileTypes
  $profiles = @()
  foreach ($t in 1,2,4) {
    $profiles += [ordered]@{
      type = $t; active = [bool]($cur -band $t)
      enabled = [bool]$p.FirewallEnabled($t)
      default_inbound_allow = ([int]$p.DefaultInboundAction($t) -eq 1)
      block_all_inbound = [bool]$p.BlockAllInboundTraffic($t)
      notifications_disabled = [bool]$p.NotificationsDisabled($t)
    }
  }
  $out.current_profile_types = $cur
  $out.profiles = $profiles
  try { $out.local_policy_modify_state = [int]$p.LocalPolicyModifyState } catch { $out.local_policy_modify_state = $null }
  $prog = $env:BH_FW_PROGRAM
  $rules = @()
  foreach ($r in $p.Rules) {
    if ($r.Direction -ne 1) { continue }
    if (-not $r.Enabled) { continue }
    if ($r.Protocol -ne 17 -and $r.Protocol -ne 256) { continue }
    $app = $r.ApplicationName
    if ($app) {
      $app = [Environment]::ExpandEnvironmentVariables($app)
      if (-not $prog -or $app -ine $prog) { continue }
    }
    $rules += [ordered]@{
      name = $r.Name; action = [int]$r.Action; application = $app
      protocol = [int]$r.Protocol; local_ports = $r.LocalPorts
      local_addresses = $r.LocalAddresses; remote_addresses = $r.RemoteAddresses
      interface_types = $r.InterfaceTypes; profiles = [int]$r.Profiles
      service = $r.ServiceName; grouping = $r.Grouping
    }
  }
  $out.rules = $rules
  $out.ok = $true
} catch { $out.error = $_.Exception.Message }
$out | ConvertTo-Json -Depth 5 -Compress
"""

_PROFILE_NAMES = {1: "Domain", 2: "Private", 4: "Public"}


def _port_matches(spec: str | None, port: int) -> bool | None:
    """True/False if a LocalPorts spec matches ``port``; None if undecidable."""
    if spec is None or spec.strip() in ("", "*"):
        return True
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            if lo.isdigit() and hi.isdigit():
                if int(lo) <= port <= int(hi):
                    return True
                continue
            return None
        if part.isdigit():
            if int(part) == port:
                return True
            continue
        return None  # keyword such as "RPC" / "Teredo" / "Ply2Disc"
    return False


def _is_any(v: str | None) -> bool:
    return v is None or v.strip() in ("", "*")


def _run_fw_query(program_path: str) -> dict:
    env = dict(os.environ)
    env["BH_FW_PROGRAM"] = os.path.normcase(os.path.abspath(program_path)) if program_path else ""
    encoded = base64.b64encode(_FW_PS.encode("utf-16-le")).decode("ascii")
    r = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60, env=env,
        stdin=subprocess.DEVNULL, creationflags=_CREATE_NO_WINDOW,
    )
    text = r.stdout.strip()
    if not text:
        return {"ok": False, "error": (r.stderr or "no output from PowerShell").strip()[:500]}
    try:
        return json.loads(text.splitlines()[-1])
    except ValueError:
        return {"ok": False, "error": f"unparseable PowerShell output: {text[:200]}"}


def firewall_inbound_status(program_path: str, port: int, *, _raw: dict | None = None) -> dict:
    """Best-effort, read-only check: may inbound UDP ``port`` reach ``program_path``?

    Never modifies anything and needs no admin. Uses the local firewall
    policy store via ``HNetCfg.FwPolicy2``.

    Result keys:

    * ``verdict``: ``"allowed"`` | ``"blocked"`` | ``"unknown"``
    * ``firewall_enabled``: True if Windows Defender Firewall is on for any
      active profile, False if off for all active profiles, None if unknown
    * ``active_profiles``: e.g. ``["Public"]``
    * ``allow_rules`` / ``block_rules``: matching inbound UDP rules (name,
      application, local_ports, conditional, profiles)
    * ``reasons``: plain-English explanation lines
    * ``unknown``: things this check cannot see
    * ``method``: how the answer was obtained

    ``program_path`` should be the executable that will own the socket. For a
    venv, that is the *base* interpreter (``sys._base_executable``), not the
    venv's ``python.exe`` launcher - see the validation doc.
    """
    _require_windows("firewall_inbound_status")
    raw = _raw if _raw is not None else _run_fw_query(program_path)
    res: dict[str, Any] = {
        "verdict": "unknown",
        "firewall_enabled": None,
        "active_profiles": [],
        "allow_rules": [],
        "block_rules": [],
        "reasons": [],
        "unknown": [
            "Third-party firewalls and endpoint-security products are not inspected.",
            "Rules from Group Policy stores are not included in the local policy view.",
            "Network firewalls/ACLs between the BACnet devices and this PC are not visible.",
        ],
        "method": "HNetCfg.FwPolicy2 (local policy store) via PowerShell, read-only",
        "program": program_path,
        "port": port,
    }
    if not raw.get("ok"):
        res["reasons"].append(f"Could not read the firewall policy: {raw.get('error', 'unknown error')}")
        return res

    cur = int(raw.get("current_profile_types") or 0)
    profiles = raw.get("profiles") or []
    if isinstance(profiles, dict):
        profiles = [profiles]
    active = [p for p in profiles if p.get("active")]
    res["active_profiles"] = [_PROFILE_NAMES.get(int(p["type"]), str(p["type"])) for p in active]
    if raw.get("local_policy_modify_state") not in (None, 0):
        res["unknown"].insert(0, "Group Policy overrides or restricts local firewall rules on this PC "
                                 f"(LocalPolicyModifyState={raw.get('local_policy_modify_state')}).")
    if not active:
        res["reasons"].append("No active firewall profile was reported.")
        return res

    enabled = [p for p in active if p.get("enabled")]
    res["firewall_enabled"] = bool(enabled)
    if not enabled:
        res["verdict"] = "allowed"
        res["reasons"].append(
            "Windows Defender Firewall is off for the active profile(s): " + ", ".join(res["active_profiles"]) + "."
        )
        return res

    rules = raw.get("rules") or []
    if isinstance(rules, dict):
        rules = [rules]
    verdicts: list[str] = []
    for prof in enabled:
        t = int(prof["type"])
        pname = _PROFILE_NAMES.get(t, str(t))
        if prof.get("block_all_inbound"):
            verdicts.append("blocked")
            res["reasons"].append(f"{pname} profile blocks all incoming connections (shields up).")
            continue
        allow = block = False
        allow_cond = block_cond = False
        for r in rules:
            if not (int(r.get("profiles") or 0) & t):
                continue
            m = _port_matches(r.get("local_ports"), port)
            if m is False:
                continue
            conditional = (
                m is None
                or not _is_any(r.get("local_addresses"))
                or not _is_any(r.get("remote_addresses"))
                or (not _is_any(r.get("interface_types")) and (r.get("interface_types") or "").lower() != "all")
                or bool(r.get("service"))
            )
            entry = {
                "name": r.get("name"),
                "application": r.get("application"),
                "local_ports": r.get("local_ports"),
                "remote_addresses": r.get("remote_addresses"),
                "profiles": [n for b, n in _PROFILE_NAMES.items() if int(r.get("profiles") or 0) & b],
                "conditional": conditional,
            }
            if int(r.get("action", 1)) == 0:
                if entry not in res["block_rules"]:
                    res["block_rules"].append(entry)
                block, block_cond = True, block_cond or conditional
            else:
                if entry not in res["allow_rules"]:
                    res["allow_rules"].append(entry)
                allow, allow_cond = True, allow_cond or conditional
        # Windows Firewall: an explicit block rule wins over any allow rule.
        if block and not block_cond:
            verdicts.append("blocked")
            res["reasons"].append(f"{pname} profile: a block rule matches this program/port "
                                  "(often created when someone clicked Cancel on the firewall prompt).")
        elif allow and not allow_cond and not block:
            verdicts.append("allowed")
            res["reasons"].append(f"{pname} profile: an allow rule matches this program/port.")
        elif allow or block:
            verdicts.append("unknown")
            res["reasons"].append(f"{pname} profile: matching rules exist but are limited by address, "
                                  "interface or service conditions.")
        elif prof.get("default_inbound_allow"):
            verdicts.append("allowed")
            res["reasons"].append(f"{pname} profile: default inbound action is Allow.")
        else:
            verdicts.append("blocked")
            res["reasons"].append(
                f"{pname} profile: no rule allows inbound UDP {port} for this program and the default is Block."
                + (" Windows will not ask, because notifications are off." if prof.get("notifications_disabled")
                   else " Windows may show a firewall prompt the first time the program listens.")
            )
    if cur and len(enabled) > 1:
        res["reasons"].append("Several profiles are active (one per network); the strictest result is reported.")
    if "blocked" in verdicts:
        res["verdict"] = "blocked"
    elif "unknown" in verdicts:
        res["verdict"] = "unknown"
    else:
        res["verdict"] = "allowed"
    return res
