"""Tests for bacnet_health.active._win (Windows platform helpers).

Live tests run only on Windows and only touch 127.0.0.1 (no packets are sent).
The firewall verdict logic is tested with canned policy data on every OS.
"""

from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
import sys

import pytest

from bacnet_health.active import _win

on_windows = pytest.mark.skipif(sys.platform != "win32", reason="Windows-only API")

IFACE_KEYS = {
    "name", "description", "ip", "prefix", "netmask", "broadcast", "is_up", "is_loopback",
    "has_default_route", "wireless_guess", "if_index", "mac",
}
# Fields of active/iface.py's Iface dataclass (docs/dev/contracts.md) must all be present.
CONTRACT_KEYS = {"name", "ip", "netmask", "prefix", "broadcast", "is_loopback", "is_up",
                 "has_default_route", "wireless_guess"}


# --- import / non-Windows behaviour ---------------------------------------


def test_module_imports_everywhere() -> None:
    assert callable(_win.list_interfaces_windows)
    assert _win.IS_WINDOWS == (sys.platform == "win32")


@pytest.mark.skipif(sys.platform == "win32", reason="checks the non-Windows guard")
def test_functions_refuse_off_windows() -> None:
    with pytest.raises(NotImplementedError):
        _win.list_interfaces_windows()
    with pytest.raises(NotImplementedError):
        _win.port_owner(47808)
    with pytest.raises(NotImplementedError):
        _win.firewall_inbound_status("x", 47808)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        with pytest.raises(NotImplementedError):
            _win.exclusive_bind(s, ("127.0.0.1", 0))
    finally:
        s.close()


# --- interfaces ------------------------------------------------------------


@on_windows
def test_list_interfaces_shape_and_loopback() -> None:
    ifaces = _win.list_interfaces_windows()
    assert ifaces, "expected at least the loopback interface"
    for d in ifaces:
        assert IFACE_KEYS <= set(d)
        assert CONTRACT_KEYS <= set(d)
        assert isinstance(d["name"], str) and d["name"]
        assert 0 <= d["prefix"] <= 32
        net = ipaddress.IPv4Network(f"{d['ip']}/{d['prefix']}", strict=False)
        assert d["netmask"] == str(net.netmask)
        assert d["broadcast"] == str(net.broadcast_address)
        assert isinstance(d["if_index"], int) and d["if_index"] > 0
        assert d["mac"] is None or len(d["mac"]) == 17
        for k in ("is_up", "is_loopback", "has_default_route", "wireless_guess"):
            assert isinstance(d[k], bool)
    lo = [d for d in ifaces if d["is_loopback"]]
    assert lo and lo[0]["ip"] == "127.0.0.1" and lo[0]["mac"] is None


@on_windows
def test_list_interfaces_extra_fields() -> None:
    for d in _win.list_interfaces_windows(include_extra=True):
        assert {"if_type", "ipv4_metric", "mtu", "link_local", "adapter_id"} <= set(d)
        if d["is_loopback"]:
            assert d["if_type"] == _win.IF_TYPE_SOFTWARE_LOOPBACK


@on_windows
def test_interface_ips_match_getaddrinfo() -> None:
    """Every IP the OS resolves for this host name must appear in our list (sanity cross-check)."""
    ours = {d["ip"] for d in _win.list_interfaces_windows()}
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
    except OSError:
        pytest.skip("host name does not resolve")
    for info in infos:
        assert info[4][0] in ours


# --- exclusive bind --------------------------------------------------------


def _udp() -> socket.socket:
    return socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


@on_windows
def test_exclusive_bind_blocks_second_bind() -> None:
    a = _udp()
    try:
        _win.exclusive_bind(a, ("127.0.0.1", 0))
        assert a.getsockopt(socket.SOL_SOCKET, _win.SO_EXCLUSIVEADDRUSE) == 1
        assert a.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
        port = a.getsockname()[1]
        for reuse in (False, True):
            b = _udp()
            try:
                if reuse:
                    b.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with pytest.raises(OSError) as ei:
                    b.bind(("127.0.0.1", port))
                assert _win.is_addr_in_use_error(ei.value)
            finally:
                b.close()
        # Note: a 0.0.0.0 bind on the same port by another program still succeeds when we hold a
        # specific address (see docs/dev/windows-validation.md), so callers must also check port_owners().
    finally:
        a.close()


@on_windows
def test_exclusive_bind_fails_when_port_taken() -> None:
    a = _udp()
    try:
        a.bind(("127.0.0.1", 0))  # another program, plain bind
        b = _udp()
        try:
            with pytest.raises(OSError) as ei:
                _win.exclusive_bind(b, ("127.0.0.1", a.getsockname()[1]))
            assert _win.is_addr_in_use_error(ei.value)
        finally:
            b.close()
    finally:
        a.close()


@on_windows
def test_exclusive_bind_refuses_reuseaddr_socket() -> None:
    s = _udp()
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        with pytest.raises(ValueError):
            _win.exclusive_bind(s, ("127.0.0.1", 0))
    finally:
        s.close()


# --- port owner ------------------------------------------------------------


@on_windows
def test_port_owner_finds_this_process() -> None:
    s = _udp()
    try:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        o = _win.port_owner(port)
        assert o is not None
        assert o["pid"] == os.getpid()
        assert o["local_ip"] == "127.0.0.1" and o["family"] == "ipv4"
        assert (o["name"] or "").lower().startswith("python")
        assert o["path"] and os.path.isfile(o["path"])
    finally:
        s.close()


@on_windows
def test_port_owner_none_when_free() -> None:
    s = _udp()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    assert _win.port_owner(port) is None
    assert _win.port_owners(port) == []


@on_windows
def test_port_owner_other_process() -> None:
    code = (
        "import socket,sys,time;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.bind(('127.0.0.1',0));print(s.getsockname()[1],flush=True);sys.stdin.read()"
    )
    p = subprocess.Popen([sys.executable, "-c", code], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        port = int(p.stdout.readline())
        o = _win.port_owner(port)
        assert o is not None and o["pid"] != os.getpid()
        # In a venv, python.exe is a launcher: the socket belongs to its child (the base interpreter).
        assert (o["name"] or "").lower().startswith("python")
    finally:
        p.stdin.close()
        p.wait(10)


# --- firewall: pure verdict logic (canned policy data) ----------------------

PROG = r"C:\Program Files\bacnet-health\bacnet-health.exe"


def _raw(enabled: bool = True, rules: list | None = None, *, default_allow: bool = False,
         block_all: bool = False, active: int = 4, lpms: int = 0) -> dict:
    return {
        "ok": True,
        "current_profile_types": active,
        "local_policy_modify_state": lpms,
        "profiles": [
            {"type": t, "active": bool(active & t), "enabled": enabled, "default_inbound_allow": default_allow,
             "block_all_inbound": block_all, "notifications_disabled": False}
            for t in (1, 2, 4)
        ],
        "rules": rules or [],
    }


def _rule(action: int = 1, ports: str = "*", profiles: int = 0x7FFFFFFF, remote: str = "*", **kw) -> dict:
    r = {"name": "test", "action": action, "application": PROG, "protocol": 17, "local_ports": ports,
         "local_addresses": "*", "remote_addresses": remote, "interface_types": "All", "profiles": profiles,
         "service": None, "grouping": None}
    r.update(kw)
    return r


@pytest.fixture
def fw(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(_win, "_require_windows", lambda name: None)
    return lambda raw: _win.firewall_inbound_status(PROG, 47808, _raw=raw)


def test_fw_off_is_allowed(fw) -> None:
    r = fw(_raw(enabled=False))
    assert r["verdict"] == "allowed" and r["firewall_enabled"] is False
    assert r["active_profiles"] == ["Public"]


def test_fw_on_no_rule_default_block(fw) -> None:
    r = fw(_raw())
    assert r["verdict"] == "blocked" and r["firewall_enabled"] is True


def test_fw_on_default_allow(fw) -> None:
    assert fw(_raw(default_allow=True))["verdict"] == "allowed"


def test_fw_allow_rule(fw) -> None:
    r = fw(_raw(rules=[_rule(ports="47808")]))
    assert r["verdict"] == "allowed" and len(r["allow_rules"]) == 1


def test_fw_allow_rule_port_range_and_list(fw) -> None:
    assert fw(_raw(rules=[_rule(ports="47800-47823")]))["verdict"] == "allowed"
    assert fw(_raw(rules=[_rule(ports="161,47808")]))["verdict"] == "allowed"
    assert fw(_raw(rules=[_rule(ports="47809")]))["verdict"] == "blocked"


def test_fw_block_rule_wins(fw) -> None:
    r = fw(_raw(rules=[_rule(), _rule(action=0)]))
    assert r["verdict"] == "blocked" and r["block_rules"]


def test_fw_rule_for_other_profile_ignored(fw) -> None:
    # Allow rule only for Private (2) while Public (4) is the active profile.
    assert fw(_raw(rules=[_rule(profiles=2)]))["verdict"] == "blocked"


def test_fw_conditional_rule_is_unknown(fw) -> None:
    r = fw(_raw(rules=[_rule(remote="LocalSubnet")]))
    assert r["verdict"] == "unknown" and r["allow_rules"][0]["conditional"]


def test_fw_shields_up(fw) -> None:
    assert fw(_raw(rules=[_rule()], block_all=True))["verdict"] == "blocked"


def test_fw_multiple_active_profiles_strictest(fw) -> None:
    r = fw(_raw(rules=[_rule(profiles=2)], active=2 | 4))
    assert r["verdict"] == "blocked"
    assert set(r["active_profiles"]) == {"Private", "Public"}


def test_fw_query_failure_is_unknown(fw) -> None:
    r = fw({"ok": False, "error": "COM error"})
    assert r["verdict"] == "unknown" and r["firewall_enabled"] is None


def test_fw_group_policy_noted(fw) -> None:
    r = fw(_raw(enabled=False, lpms=1))
    assert any("Group Policy" in u for u in r["unknown"])


def test_port_matches_keywords_undecidable() -> None:
    assert _win._port_matches("RPC", 47808) is None
    assert _win._port_matches(None, 47808) is True
    assert _win._port_matches("", 47808) is True
    assert _win._port_matches("1-100", 47808) is False


# --- firewall: live, read-only ----------------------------------------------


@on_windows
def test_firewall_live_query_is_read_only_and_well_formed() -> None:
    exe = getattr(sys, "_base_executable", sys.executable)
    r = _win.firewall_inbound_status(exe, 47808)
    assert r["verdict"] in ("allowed", "blocked", "unknown")
    assert r["firewall_enabled"] in (True, False, None)
    assert r["reasons"], r
    if r["firewall_enabled"] is not None:
        assert r["active_profiles"]


# --- host-internal virtual switches (auto-pick, design F5) ------------------


@pytest.mark.parametrize(("name", "desc", "mac", "virtual"), [
    ("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "00:15:5d:04:41:f4", True),
    ("vEthernet (WSL (Hyper-V firewall))", "Hyper-V Virtual Ethernet Adapter #3", "00:15:5d:aa:bb:cc", True),
    ("vEthernet (Internal LAB)", "Hyper-V Virtual Ethernet Adapter #4", "00:15:5D:01:02:03", True),
    ("VMware Network Adapter VMnet8", "VMware Virtual Ethernet Adapter for VMnet8", "00:50:56:c0:00:08", True),
    ("Ethernet 3", "VirtualBox Host-Only Ethernet Adapter", "0a:00:27:00:00:0c", True),
    # A Hyper-V *external* switch host vNIC carries the physical NIC's MAC: that is the real LAN.
    ("vEthernet (External)", "Hyper-V Virtual Ethernet Adapter #2", "c8:7f:54:0b:29:14", False),
    ("Ethernet", "Intel(R) Ethernet Controller I226-V", "c8:7f:54:0b:29:14", False),
    ("Meta", "Meta Tunnel", None, False),  # tunnels are handled by IfType, not here
])
def test_host_virtual_kind(name: str, desc: str, mac: str | None, virtual: bool) -> None:
    kind = _win.host_virtual_kind(name, desc, mac)
    assert (kind is not None) == virtual
    if virtual:
        assert "inside this computer" in kind


def test_auto_pick_skips_default_switch_tunnels_on_multi_adapter_pc() -> None:
    """The Lierre-PC layout (validation doc): the External vSwitch is the LAN, even though it has a gateway."""
    from bacnet_health.active.iface import _iface_from_dict, auto_pick

    def row(name, desc, cidr, mac, if_type=6, gw=False, up=True):
        net = ipaddress.ip_interface(cidr)
        return {"name": name, "description": desc, "ip": str(net.ip), "prefix": net.network.prefixlen,
                "netmask": str(net.netmask), "broadcast": str(net.network.broadcast_address), "is_up": up,
                "is_loopback": False, "has_default_route": gw, "wireless_guess": if_type == 71, "mac": mac,
                "if_type": if_type, "host_virtual": _win.host_virtual_kind(name, desc, mac)}

    rows = [
        row("Meta", "Meta Tunnel", "198.18.0.1/30", None, if_type=53, gw=True),
        row("Tailscale", "Tailscale Tunnel", "100.100.1.2/32", None, if_type=53),
        row("vEthernet (External)", "Hyper-V Virtual Ethernet Adapter #2", "192.168.2.100/23",
            "c8:7f:54:0b:29:14", gw=True),
        row("vEthernet (Default Switch)", "Hyper-V Virtual Ethernet Adapter", "172.19.64.1/20", "00:15:5d:04:41:f4"),
        row("Wi-Fi", "Wi-Fi 6E", "169.254.252.105/16", "8c:b8:7e:ce:22:55", if_type=71, up=False),
    ]
    best, ranked, reasons = auto_pick([_iface_from_dict(r) for r in rows])
    assert best is not None and best.name == "vEthernet (External)"
    assert ranked.index(best) < [i.name for i in ranked].index("vEthernet (Default Switch)")
    assert any("Default Switch" in r and "not a building network" in r for r in reasons)


@on_windows
def test_live_interfaces_carry_host_virtual() -> None:
    for d in _win.list_interfaces_windows(include_extra=True):
        assert "host_virtual" in d
        assert d["host_virtual"] is None or isinstance(d["host_virtual"], str)


# --- runner pre-flight uses the firewall verdict -----------------------------


@on_windows
@pytest.mark.parametrize(("verdict", "status"), [("allowed", "ok"), ("blocked", "error"), ("unknown", "unknown")])
def test_preflight_maps_firewall_verdict(monkeypatch, verdict: str, status: str) -> None:
    from bacnet_health import runner

    seen = {}

    def fake(program_path, port, **_):
        seen["program"] = program_path
        return {"verdict": verdict, "reasons": [f"canned {verdict}"]}

    monkeypatch.setattr(_win, "firewall_inbound_status", fake)
    checks = runner.preflight(runner.RunnerOptions(bind="127.0.0.1/8", port=47808, clock_synced=True))
    fw = next(c for c in checks if c["name"] == "Windows Firewall")
    assert fw["status"] == status
    assert fw["message"] == f"canned {verdict}"
    # Not frozen: the socket owner is the base interpreter, not the venv launcher.
    assert seen["program"] == getattr(sys, "_base_executable", sys.executable)
