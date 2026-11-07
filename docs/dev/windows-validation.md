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

---

# Phase 2: real build and validation (2026-11-08)

Same PC as phase 1 (see "Test machine"). Branch `windows-phase2` from `origin/main` 39241cf. Nothing was sent on the
LAN: only `interfaces`, the pre-flight checks and one 30 s passive `listen` touched the real adapter. Every
simulator/network test uses 127.0.0.1.

## Environment

| Item | Value |
|---|---|
| OS | Windows 11 Pro 25H2, build 26200, x64, zh-TW UI, ANSI code page 932. **Apps use dark mode** (`AppsUseLightTheme=0`) |
| Display | 3440×1440 at 100 % (96 dpi). 150 % was tested with `QT_SCALE_FACTOR=1.5` |
| Python / packages | Python 3.12.10, PySide6 / shiboken6 / Qt 6.12.0, PyInstaller 6.22.3, pytest 9.2.0 (venv recreated from main: `pip install -e ".[dev,gui]" pyinstaller`) |
| Firewall / AV | Windows Defender Firewall off on all profiles. Defender real-time protection off |
| Windows Time | Service `w32time` **Stopped, Manual (trigger) start**. It last synchronised at 03:00 the same day (System log, Time-Service events 35/37) |

## Tests

| Run | Result |
|---|---|
| `pytest` (full, `QT_QPA_PLATFORM=offscreen`) | **525 passed, 13 skipped** (tshark/editcap not installed: 12; non-Windows guard: 1) |
| `pytest -m network` | 32 passed |
| `pytest -m gui` | 22 passed |
| `tests/test_win_platform.py` | 37 passed, 1 skipped |

Before this branch's changes, main gave 512 passed, 13 skipped. The 13 new tests are the host-virtual classifier,
the multi-adapter auto-pick case and the pre-flight firewall mapping.

## Fixes made in this phase

1. **Auto-pick chose the Hyper-V Default Switch** (`active/iface.py`, `active/_win.py`). The real LAN
   (`vEthernet (External)`) carries a gateway (−15 points), while the Default Switch looked "wired, private, no
   default route" (+45) and won. `_win.host_virtual_kind()` now recognises virtual switches that only exist inside
   the PC: name `Default Switch`, `vEthernet (WSL…`, `vEthernet (nat)`; VMware VMnet and VirtualBox host-only
   descriptions; and any `Hyper-V Virtual Ethernet Adapter` with the Hyper-V synthetic OUI `00:15:5d`. An
   external-switch host vNIC carries the physical NIC's MAC (here `c8:7f:54:…`), so it is not matched.
   `list_interfaces_windows(include_extra=True)` returns this as `host_virtual`. `Iface.host_virtual` (new optional
   field) costs −40 in `_score` and is labelled "virtual (this PC only)". These interfaces stay selectable.
2. **The firewall pre-flight was always "unknown"** (`runner.py`, Windows branch only).
   `firewall_inbound_status()` returns `verdict`, but the runner read `status`. So a **blocking firewall could never
   show as an error** (F9). The runner now reads `verdict`. It also passes the socket owner as the program: the
   exe when frozen, `sys._base_executable` in a venv (phase 1 (b)4), instead of the venv launcher.
3. **Packaging only:** a stdio runtime hook (redirected CLI output) and the GUI dark-mode hook (see below).

## Build

`packaging\windows\build.ps1 -Python .venv\Scripts\python.exe` (PyInstaller step about 25 s):

| Artifact | Value |
|---|---|
| `dist\bacnet-health\` | **57.3 MB, 89 files**. Qt DLLs: `Qt6Core`, `Qt6Gui`, `Qt6Widgets` only. Plugins: `platforms\qwindows`, `platforms\qoffscreen`, `imageformats\qico`, `styles\qmodernwindowsstyle` |
| `dist\bacnet-health-0.1.0a1-win-x64.zip` | **24.4 MB** (25,610,466 bytes), 90 entries, `/` separators, `README-FIRST.txt` at the root |
| SHA-256 (`.zip.sha256`) | `48b5496ff97b7936f6752983b68a2813152dc98ada74132a7249d1e2e4c6f16c` |
| `bacnet-health.exe` | PE subsystem 2 (GUI). Version resource 0.1.0a1, "bacnet-health". Icon + `IDI_ICON1`. `NotSigned` |
| `bacnet-health-cli.exe` | PE subsystem 3 (console). Version resource 0.1.0a1. Icon. `NotSigned` |

The spike measured 77.5 MB / 30.8 MB zip for the trimmed widgets build. The real app is smaller because it also
drops Network/Svg/OpenSSL and the unused image-format and platform plugins.

The zip was extracted with `Expand-Archive`. The CLI ran from the extracted folder, and `.sha256` matched.
`MpCmdRun -Scan -ScanType 3` on the folder found no threats. Real-time protection is off here, so on-access
scanning was not exercised.

## Smoke tests of the built exes

**CLI**

- `bacnet-health-cli.exe --version` → `bacnet-health 0.1.0a1`, exit 0, 0.06 s warm (first run 0.16 s).
- `demo --dir <tmp>` → exit 0. It wrote `demo-capture.pcap` (137,146 B), `demo-result.json` (53,081 B, all top-level
  keys present) and `demo-report.html` (66,477 B). 18 devices; findings 0 critical / 4 high / 1 medium / 1 low /
  3 info.
- `interfaces` (after fix 1):

  ```
  * vEthernet (External) 192.168.2.100 /23  bcast 192.168.3.255  up  default-route
    vEthernet (Default Switch) 172.19.64.1 /20  bcast 172.19.79.255  up
    Meta        198.18.0.1 /30   up  default-route
    Tailscale   100.x.y.z /32    up
    藍牙網路連線 / Wi-Fi / 區域連線* 9, 10   169.254.x.x  down
    - Not considered (VPN/tunnel, point-to-point or link-local 169.254.x.x): Meta, Tailscale.
    - Picked vEthernet (External) (Hyper-V Virtual Ethernet Adapter #2): 192.168.2.100/23, wired: private
      address, wired, carries the default route (likely the office or Internet connection).
    - Broadcasts will go to 192.168.3.255 only (never 255.255.255.255).
    - Not picked: vEthernet (Default Switch) …: virtual (this PC only) (private address, Hyper-V Default Switch
      (NAT inside this computer): not a building network, no default route).
    - Warning: the picked interface may be the office network. Confirm before scanning.
  ```

  Ranking scores (`_score`): External +20, Default Switch −10, Meta −35 (tunnel, default route), Tailscale −50
  (tunnel, /32), Bluetooth PAN −105, Wi-Fi / Wi-Fi Direct −145 (down, link-local). Meta and Tailscale are also
  excluded by `_usable()`. Before the fix, the Default
  Switch was picked (+45 vs +20).
- With output redirected to a file (`cmd /c … > file`), the frozen CLI writes the ANSI code page (cp932). The
  localised names are intact in the file. A frozen app ignores `PYTHONIOENCODING`. `rthook_stdio.py` sets
  `errors="backslashreplace"` on redirected streams, so a name outside the code page cannot raise
  `UnicodeEncodeError`.

**Runner pre-flight** (`runner.preflight(RunnerOptions(interface="vEthernet (External)"))`, dev venv, 0.27 s):

```
[warning] Network interface: vEthernet (External) 192.168.2.100/23, broadcast 192.168.3.255. This interface
          carries the computer's default route; make sure it is the building network.
[ok     ] UDP port 47808: Free.
[ok     ] Routing: Broadcasts to 192.168.3.255 leave through vEthernet (External).
[ok     ] Windows Firewall: Windows Defender Firewall is off for the active profile(s): Private, Public.
[warning] Computer clock: Windows Time service is not synchronised. Device clock checks will be skipped.
```

Before fix 2, the firewall row said `[unknown]` with the same message. Egress (`GetBestInterface`):
192.168.3.255 → External, 172.19.79.255 → Default Switch, 255.255.255.255 → External, **192.168.2.101 (a LAN
host) → Tailscale**, 8.8.8.8 → Meta. The pre-flight only checks the broadcast address, so the Tailscale overlap
from phase 1 (d)2 is still not reported (see open issues). The IP bind pins the egress anyway (phase 1 (d)3).

**Passive listen:** `bacnet-health-cli.exe listen --interface "vEthernet (External)" --duration 30s --yes -o
<tmp>\listen.json`

- During the run, `Get-NetUDPEndpoint -LocalPort 47808` showed exactly one endpoint: **192.168.2.100:47808**, owned
  by `bacnet-health-cli` (pid of the exe itself). It is the interface IP, not 0.0.0.0.
- Result: 0 frames, 0 devices, 0 findings (this LAN has no BACnet). `run.vantage = self`. `limitations` correctly
  says "No BACnet datagram was received at all … inbound UDP … may be blocked (firewall); this was not verified."
- Nothing was sent: the listen path never transmits. Output cosmetics are listed under open issues.

**GUI** (`packaging\windows\smoke-gui.ps1`, UI Automation):

| | 100 % | 150 % (`QT_SCALE_FACTOR=1.5`) |
|---|---|---|
| PE subsystem / console | 2 / no child process, no conhost | same |
| Launch → main window | 1.43 s (first launch after build) | 0.58 s |
| Home → Analyse → "Try a sample capture" → Done ("Findings" tree present) | 0.23 s | 0.30 s |
| Close | exit 0 | exit 0 |
| Screenshots | `packaging/windows/screenshots/gui-{home,analyse,done}-100.png` | `…-150.png` |

At 150 % nothing is clipped. Only Qt content scales; the OS title bar stays at 100 % because the display itself is at
100 %.

**Startup time** (launch until the main window has a handle and title):

| Case | Time |
|---|---|
| Fresh copy of the folder in `…\USB Drive (E)\Site Tools ü 測試\`, first launch | 1.41 s |
| Same copy, second launch | 0.55 s |
| `dist\` folder, 5 warm launches | 0.32, 0.56, 0.28, 0.53, 0.55 (median 0.53 s) |

A true cold start (after reboot, empty file cache) could not be produced without admin rights. The "first launch"
figures are the closest available.

**Windows dark mode (found and worked around):** with apps in dark mode, Qt 6.12 dark-palettes every widget part the
light stylesheet does not colour. The menu bar became a black strip (File/Settings/Help invisible), the findings
table header turned black, and the finding-details panel showed dark text on near-black (unreadable). The packaging
runtime hook `rthook_gui_windows.py` sets `QT_QPA_PLATFORM=windows:darkmode=0` unless already set. The screenshots
above are with the hook. The root cause belongs to the GUI theme (see open issues).

**Window icon:** the GUI sets no window icon, so the title bar and taskbar showed Qt's generic icon. The GUI exe now
carries an `IDI_ICON1` group-icon resource, which Qt's Windows plugin uses by default. The screenshots show it.

## Open issues (phase 2)

| # | Issue | Owner / suggestion |
|---|---|---|
| 1 | **Clock check is English-only and fooled by a trigger-start service.** `w32tm /query /status` output is localised (zh-TW here, and lossy in cp932), so `"Source"` never matches on non-English Windows. When `w32time` is stopped (normal for a trigger-start service between syncs), the check says "not synchronised" even though the clock synced hours ago | runner. Locale-independent signals that need no admin: Time-Service events 35/37 in the System log (last sync time), `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type` (`NTP`/`NT5DS`/`NoSync`) |
| 2 | GUI theme follows Windows dark mode in unstyled parts; worked around in packaging only | gui/theme: force a light palette or `QStyleHints.setColorScheme(Qt.ColorScheme.Light)` (Qt ≥ 6.8). Probably affects macOS dark mode too |
| 3 | GUI sets no window icon (fixed for the Windows exe via `IDI_ICON1`) | gui/app: `app.setWindowIcon(...)` for pip/macOS |
| 4 | `bacnet-health-cli.exe gui` prints "The GUI needs PySide6: pip install …", which is wrong in the bundle | cli: when `sys.frozen`, say "start bacnet-health.exe" |
| 5 | `listen` output: prints "Will broadcast on 192.168.3.255 …" for a passive listen; `--duration 30s` is shown as "Listen: 0 minutes" / "Listen for 0 min first"; progress lines on stderr are raw dicts (`{'type': 'listen', 'elapsed': …}`) because `_norm_progress` has no mapping for `listen` events | runner / cli |
| 6 | Pre-flight "Routing" checks only the broadcast address. A VPN route overlapping the LAN (Tailscale, phase 1 (d)2) is not reported. The IP bind keeps traffic on the adapter, but the user is not told | runner: also check `egress_interface()` for a unicast address in the subnet and warn when it differs |
| 7 | The repo has no `LICENSE` file (pyproject says MIT). The zip therefore ships no MIT text | owner |
| 8 | Firewall prompt experiment (c) still pending: needs the firewall turned on (admin) | owner |
| 9 | SmartScreen / Mark-of-the-Web not exercised: the zip was built locally, not downloaded. Defender real-time protection is off on this PC | human check on a second PC (download from a release/test URL) |
| 10 | `README-FIRST.txt` and `THIRD_PARTY_NOTICES.md` LGPL wording not yet reviewed | owner (design §10 [TBV]) |
