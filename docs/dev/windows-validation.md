# Windows validation (empirical findings)

Resolves or narrows the Windows [TBV] items of `docs/design/v0.1-design.md`: §3.1 broadcast delivery to an IP-bound
socket, F5 (wrong network), F8 (port conflicts), F9 (firewall). Every result below was measured on a real Windows PC.
No BACnet traffic was sent. Test payloads were `b"bh-test …"` to UDP 49999 only.

## Test machine

| Item | Value |
|---|---|
| OS | Windows 11 Pro 25H2, build **26200.9457**, x64. Not LTSC. The registry `ProductName` still says "Windows 10 Pro", a known Windows 11 quirk, so detect the version by build number. |
| Locale | zh-TW UI, ANSI code page **cp932**. Adapter friendly names are localised, e.g. `乙太網路`, `區域連線* 9`. |
| Python | **3.12.10** (python.org, per-user). 3.11 is not installed. The project needs ≥ 3.10. |
| Packages | pytest 9.2.0, PySide6 6.12.0, PyInstaller 6.22.3 |
| Wireshark / dumpcap / tshark / Npcap | **Not installed.** The tshark-dependent tests skip. |
| Windows Defender Firewall | **Off on all three profiles** (Domain, Private, Public). The service (mpssvc, BFE) is running. No third-party firewall is registered in SecurityCenter2. |
| Defender AV | Enabled, but real-time protection is **off** |
| Shell | Medium integrity, not elevated. Everything below ran without admin. |

Adapters (IPv4). This PC is a useful multi-adapter worst case:

| Adapter | Address | Notes |
|---|---|---|
| `vEthernet (External)` | 192.168.2.100/23 (bcast 192.168.3.255) | Hyper-V external switch on the physical Intel I226-V NIC. The NIC itself (`乙太網路`) has no IPv4. This is the real LAN. |
| `Meta` (proxy TUN) | 198.18.0.1/30 | Holds the **default route** (metric 0) |
| `Tailscale` | 100.x.y.z/32 | **Installs a subnet route 192.168.2.0/23 with metric 0+5**, overlapping the LAN |
| `vEthernet (Default Switch)` | 172.19.64.1/20 | Hyper-V NAT switch, interface metric 5000 |
| Wi-Fi, Wi-Fi Direct ×2, Bluetooth PAN | 169.254.x.x/16 | Disconnected (OperStatus down), APIPA |

**Second host:** the WSL2 distro (Ubuntu 24.04) runs in *bridged* mode on the External vSwitch with its own
address, 192.168.2.101/23. Packets between it and Windows are real Ethernet frames between two IP stacks, not
loopback shortcuts. So inbound broadcasts from "another host" could be tested without touching other LAN devices.

## (a) Does an IP-bound socket receive broadcasts? (§3.1 TBV) → **Yes**

Receiver on UDP 49999 (with `SO_EXCLUSIVEADDRUSE`). Each sender sent 3 datagrams:

| Sender → destination | Receiver bound to 192.168.2.100 | Receiver bound to 0.0.0.0 |
|---|---|---|
| WSL host → 192.168.3.255 (directed) | ✅ 3/3 | ✅ 3/3 |
| WSL host → 255.255.255.255 (limited) | ✅ 3/3 | ✅ 3/3 |
| WSL host → 192.168.2.100 (unicast) | ✅ 3/3 | ✅ 3/3 |
| local, bound 192.168.2.100 → directed | ✅ (own copy, src 192.168.2.100) | ✅ |
| local, bound 192.168.2.100 → limited | ✅ (own copy) | ✅ |
| local, bound 0.0.0.0 → directed | ✅ | ✅ |
| local, bound 0.0.0.0 → limited | ❌ | ✅ 6 copies, **source 198.18.0.1** (went via the Meta TUN, see d) |
| control: receiver bound to 127.0.0.1 | – | nothing received (correct) |

- **Unlike macOS/Linux, a Windows UDP socket bound to a unicast interface address does receive directed subnet
  broadcasts and limited broadcasts that arrive on that interface.** This is the design's planned Windows behaviour:
  bind the interface IP. §3.1 TBV resolved.
- Loopback caveat: the sender's own broadcasts are delivered back to local sockets (rows "local …"). The scanner will
  see its own Who-Is, so the transport must drop frames whose source is one of our own addresses. These copies
  also prove nothing about the firewall (F9).
- Broadcasts are delivered to **every** matching socket. When we hold 192.168.2.100:P exclusively and another
  program holds 0.0.0.0:P, both receive each broadcast. Unicast to 192.168.2.100 goes **only** to the more specific
  socket (ours). (See b for why that combination is possible at all.)

## (b) `SO_EXCLUSIVEADDRUSE` conflicts (F8)

Cross-process matrix on UDP 49999. The "holder" is a separate process. IP = 192.168.2.100.
`10048` = `WSAEADDRINUSE`, `10013` = `WSAEACCES`.

| Holder (other program) | Requester | 0.0.0.0 | IP |
|---|---|---|---|
| **exclusive** on 0.0.0.0 | plain | 10048 | 10013 |
| | SO_REUSEADDR | 10013 | 10013 |
| | exclusive | 10048 | 10013 |
| **exclusive** on IP | plain | **OK** | 10048 |
| | SO_REUSEADDR | **OK** | 10013 |
| | exclusive | 10048 | 10048 |
| plain on 0.0.0.0 | plain | 10048 | **OK** |
| | SO_REUSEADDR | 10013 | **OK** |
| | exclusive | 10048 | **OK** |
| plain on IP | plain | **OK** | 10048 |
| | SO_REUSEADDR | **OK** | 10013 |
| | exclusive | 10048 | 10048 |
| SO_REUSEADDR on 0.0.0.0 | plain | 10048 | OK |
| | SO_REUSEADDR | **OK (port shared!)** | OK |
| | exclusive | 10048 | OK |
| SO_REUSEADDR on IP | plain | OK | 10048 |
| | SO_REUSEADDR | OK | **OK (port shared!)** |
| | exclusive | 10048 | 10048 |

Findings:

1. **Our side:** an exclusive bind to the *same* address fails with 10048, or 10013 when the other side used
   `SO_REUSEADDR`. `_win.is_addr_in_use_error()` accepts both.
2. **Important gap.** Windows treats `0.0.0.0:P` and `IP:P` as different endpoints unless the **wildcard** holder
   is exclusive:
   - If a BMS tool already holds `0.0.0.0:47808` with a plain bind (the common case), **our exclusive bind to
     `192.168.2.100:47808` succeeds**. Both programs then receive broadcasts, and the BMS tool's unicast replies may
     land at either socket.
   - If we hold `IP:47808` exclusively, another program can still bind `0.0.0.0:47808` afterwards.

   **So a successful bind does not prove the port is free on Windows.** Before binding, the transport must call
   `_win.port_owners(port)` and refuse if *any* endpoint (0.0.0.0, our IP or another IP) exists on that port, naming
   the process (D9). This needs no admin: `GetExtendedUdpTable` + `QueryFullProcessImageNameW`.
   Alternatively, bind `0.0.0.0` exclusively as well, which blocks everything. Then egress is no longer pinned (see
   d). → recommend: port_owners() check + IP bind.
3. **When another program holds the port:** we get 10048/10013 (or a silent success, as in 2). `port_owner()`
   returns the owner: pid, image name, full path and bound address. Example for a busy port:
   `{'pid': 18680, 'name': 'steamwebhelper.exe', 'path': 'C:\\Program Files (x86)\\Steam\\…\\steamwebhelper.exe',
   'local_ip': '0.0.0.0', 'family': 'ipv4', 'others': 21}`.
4. **venv detail:** in a venv, `python.exe` is a launcher that starts the *base* interpreter as a child process. The
   socket (and so any firewall rule or prompt) belongs to the child,
   `…\Python312\python.exe` (`sys._base_executable`), with a different pid from `Popen.pid`. PyInstaller `--onedir`
   runs Python in-process, so there the owner is `bacnet-health.exe` itself.

## (c) Windows Defender Firewall (F9) — **prompt experiment not yet run**

**Blocked:** the firewall is off on every profile on this PC. Watching the prompt (and the effect of *Cancel*) needs
it turned on, which is an admin change. That has been requested from the coordinator/owner. Until then, the
following comes from documented behaviour and the code paths, and is **[TBV on this PC with the firewall on]**:

- The prompt ("Windows Defender Firewall has blocked some features of this app") appears the first time a program
  without a rule *listens*: a UDP bind followed by a receive. It is expected for both a 0.0.0.0 bind and an
  interface-IP bind. **TBV.**
- *Allow* creates inbound allow rules for that program, for the profiles ticked in the dialog. *Cancel* (or closing
  the dialog) creates **inbound block rules** for the program on the current profile. Block rules beat allow rules,
  so the next run is silently blocked and no prompt appears. This is exactly F9.
- Stateful UDP: after we send to `A:P`, replies from `A:P` are allowed even without a rule. Replies to a
  **broadcast** Who-Is match no flow (the destination was 192.168.x.255), so I-Am replies are dropped when inbound is
  blocked. Unicast ReadProperty replies would still work. Expect "0 devices found" on discovery, while reads to
  known IPs succeed.
- Loopback is exempt from the firewall, and the scanner always sees its own broadcasts (see a). **A self-sent
  packet can never prove that inbound works.**

### Proposed no-admin pre-flight (F9)

Two parts. Both are implemented or easy to add:

1. **Static rule check before the scan** — `_win.firewall_inbound_status(program_path, port)`. It reads
   `HNetCfg.FwPolicy2` through PowerShell, needs no admin, makes no changes, and takes about 0.25 s here. It checks:
   firewall enabled per **active** profile; "block all incoming" (shields up); default inbound action; and enabled
   inbound UDP rules that match the program (or any program) and port, including port lists and ranges. Block
   rules win over allow rules. Rules limited by address, interface or service give `unknown`. The verdict is
   `allowed` | `blocked` | `unknown`, with plain-English reasons and a list of what could not be seen (third-party
   firewalls, Group Policy stores, network ACLs). `program_path` must be the process that owns the socket: the exe
   for the frozen app, `sys._base_executable` in a venv.
   On this PC: `verdict=allowed, firewall_enabled=False, active_profiles=[Private, Public]`.
2. **Runtime proof during the scan:** inbound is *verified* once at least one datagram arrives on the bound socket
   whose source is **not one of our own interface addresses**: any I-Am, BVLC frame or other broadcast from the
   subnet. The report then says "inbound UDP 47808 verified". If the scan ends with 0 devices and no foreign frame
   was seen, the report must say "0 devices — inbound reception **not verified**" plus the static verdict, and
   never just "no devices".

GUI wording: *blocked* → "Windows Firewall is blocking replies to this program. Ask IT to allow UDP 47808 for
bacnet-health, or run it once as administrator and click Allow." *unknown* → "Could not confirm the firewall allows
replies; results will show whether any reply was received."

Once the firewall can be turned on, the experiment will check: (1) does the prompt appear for an IP bind vs a 0.0.0.0
bind; (2) after *Cancel*, do the WSL host's broadcast and unicast still arrive (expected: no); (3) does
`firewall_inbound_status` report `blocked` and name the new block rules; (4) after *Allow*, `allowed`.

## (d) Source address and egress interface on a multi-adapter PC

No packet capture was available (no Wireshark/Npcap, and `pktmon` needs admin). Three no-admin signals were
combined: the WSL host listening on the wire, `Get-NetAdapterStatistics` counter deltas around 50-packet bursts,
and `connect()` + `getsockname()` (the source address the stack picks).

| Socket bound to | Destination | Source chosen | Arrived on the LAN (WSL host saw) | Broadcast counter delta |
|---|---|---|---|---|
| 0.0.0.0 | 192.168.3.255 (directed) | 192.168.2.100 | ✅ 50, from 192.168.2.100 | External +50 |
| 0.0.0.0 | 255.255.255.255 (limited) | **198.18.0.1 (Meta TUN)** | ❌ **none** | none on any LAN adapter |
| 0.0.0.0 | 192.168.2.101 (unicast, LAN host) | **100.x (Tailscale)** | ⚠️ 50, but **from 192.168.3.20** (a Tailscale subnet router on the LAN NATed them) | – |
| 192.168.2.100 | 192.168.3.255 | 192.168.2.100 | ✅ 50 | External +50 |
| 192.168.2.100 | 255.255.255.255 | 192.168.2.100 | ✅ 50 | External +50 |
| 192.168.2.100 | 192.168.2.101 | 192.168.2.100 | ✅ 50, from 192.168.2.100 | – |

Findings:

1. **With a 0.0.0.0 bind, Windows picks the route first and the source second.** The limited broadcast followed the
   default route into a proxy TUN and never reached the LAN. This confirms the F5 rule of never using
   255.255.255.255. Note that `Find-NetRoute -RemoteIPAddress 255.255.255.255` predicted the Default Switch, and
   that was wrong. Do not use it for this.
2. **Unicast to a LAN device leaked into a VPN.** Tailscale's overlapping 192.168.2.0/23 route (metric 5) beat the
   on-link route (metric 25+256). Our ReadProperty would have gone through the tunnel and reached the device NATed
   from a third host, with replies going back that way. This is a new, realistic F5-class failure: engineers'
   laptops often run VPN clients.
3. **Binding the interface IP pins both source and egress interface** (Windows strong-host send model; WeakHostSend
   is Disabled on all interfaces here). All three destinations went out `vEthernet (External)` with the right
   source.
4. Directed broadcasts are routed by their /32 broadcast route to the owning interface, so they were correct with
   either bind.

**Recommendation for `active/transport.py` on Windows:** bind the selected interface IP (exclusive) after a
`port_owners()` check. Send only directed broadcasts. Recognise and drop our own looped-back frames. In the
interface confirmation step (D18), warn when another adapter has a route that overlaps the selected subnet
(`Find-NetRoute`/`GetBestRoute2` for a sample target IP returns a different interface). Until then, the IP bind
alone keeps the traffic on the right adapter. Auto-pick (F5) should also deprioritise `IfType` 53
(proprietary virtual / TUN, used by both Tailscale and the proxy here) and 169.254/16 addresses
(`include_extra=True` provides `if_type`, `link_local`, `ipv4_metric`).

## `_win.py` API summary (for `active/iface.py` and `active/transport.py`)

- `list_interfaces_windows(include_extra=False) -> list[dict]`: one dict per IPv4 unicast address. It includes
  every `Iface` field from `contracts.md` plus `description`, `if_index` and `mac` (`aa:bb:…` or `None`). Down
  adapters are included with `is_up=False`. Names are proper Unicode (localised). Console output in a cp932/cp950
  code page needs UTF-8 handling in the CLI.
- `exclusive_bind(sock, addr)`: sets `SO_EXCLUSIVEADDRUSE` and binds. Raises `ValueError` if `SO_REUSEADDR` was set.
  `is_addr_in_use_error(exc)` recognises 10048/10013.
- `port_owners(port) -> list[dict]` / `port_owner(port) -> dict | None`: pid, name, path, local_ip, family (IPv4 and
  IPv6 tables).
- `firewall_inbound_status(program_path, port) -> dict`: see (c).
- All functions raise `NotImplementedError` off Windows. The module imports everywhere.

## Test results on this PC

`tests/test_win_platform.py`: 24 passed, 1 skipped (the non-Windows guard test).
Full suite (`.venv\Scripts\pytest`, commit 29c0185 + this branch): **393 passed, 12 skipped** (tshark/editcap not
installed), 0 failed.
