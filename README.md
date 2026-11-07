# bacnet-health

Read-only, rate-limited BACnet/IP network health check for building-management networks, with reports a consultant can
hand to a client.

> **Pre-release (0.1.0a1).** It has not yet been validated on physical controllers. Thresholds are provisional until
> they are calibrated with field captures. Please test it in a lab before using it on a live site.

## What it does

- **Listen** to a BMS network and measure broadcast load, Who-Is/I-Am storms and BBMD forwarding. It sends nothing.
- **Analyse** a pcap or pcapng capture taken on a normal switch port or a SPAN/mirror port.
- **Scan** the local subnet. It discovers devices with ranged Who-Is, reads a fixed set of Device-object properties,
  and audits the BBMD tables (Read-BDT and Read-FDT).
- **Report** findings. Each finding has a severity, a confidence (observed or inferred), the vantage point it needs, a
  plain-English explanation, a recommendation, evidence and a spec reference. Output is a terminal summary, JSON, and
  one offline HTML file. The HTML can be white-labelled, redacted for sharing, and diffed against an earlier visit.

## Safety

- **Read-only by construction.** The only messages it sends are Who-Is, ReadProperty, ReadPropertyMultiple,
  Read-BDT and Read-FDT. Foreign-device registration is opt-in. Encoders for write services do not exist in the code,
  and every outgoing frame is checked against an allow-list before it is sent.
- **Rate-limited.** Who-Is requests go out in adaptive instance ranges at least 1 s apart. Confirmed requests are
  capped at 5 per second, with one request in flight per device. You see a traffic budget before anything is sent, and
  Stop takes effect within 100 ms.
- **Stays on the network you chose.**
  - It never sends to 255.255.255.255.
  - Traffic is pinned to the chosen interface. A destination that would leave through a VPN or tunnel is refused.
  - It will not run if UDP 47808 is already in use.
- **Cross-subnet actions need typed confirmation.** These are reading devices behind routers, following BBMD peers,
  and foreign-device registration. You must type the target address, and the confirmation is recorded in the report.

See [docs/design/v0.1-design.md](docs/design/v0.1-design.md) for the design, including the safety analysis (FMEA) and
the finding catalogue.

## Install

| Who | How |
|---|---|
| Onsite engineers (Windows) | Unzip `bacnet-health-0.1.0a1-win-x64.zip` and double-click `bacnet-health.exe`. |
| macOS | Unzip, then right-click `bacnet-health.app` → Open (the app is not signed yet). |
| Python users | `pipx install "bacnet-health[gui]"`, or just `bacnet-health` for the CLI only (no dependencies) |
| Single file | `python bacnet-health.pyz …` (Python 3.10+, CLI only) |

## Using it

**GUI** (`bacnet-health gui`, or the app). The home screen has three buttons: Run health check, Analyse a capture
file, and Open & compare reports. Advanced options are in Settings. A consultant can prepare a `.bhprofile` with the
site details, branding and locked options, and give it to the onsite engineer.

**CLI**

```sh
bacnet-health demo                                  # synthetic capture + report; sends nothing
bacnet-health analyze site.pcapng --html report.html
bacnet-health interfaces                            # which interface would be used, and why
bacnet-health listen --interface en5 --duration 10m
bacnet-health scan --interface en5 --dry-run        # show the budget and first packets only
bacnet-health audit --interface en5 --html report.html
bacnet-health report visit2.json --diff visit1.json --branding branding.json -o report.html
bacnet-health report visit2.json --redact -o shareable.html
```

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e ".[dev,gui]"
QT_QPA_PLATFORM=offscreen .venv/bin/pytest          # wire, capture, analysis, active (localhost simulator), GUI
python scripts/build_pyz.py                         # dist/bacnet-health.pyz
bash packaging/macos/build.sh                       # unsigned .app (needs pyinstaller)
pwsh packaging/windows/build.ps1                    # Windows onedir + zip (on Windows)
```

The tests compare our decoding with tshark when it is installed. The network tests use the localhost simulator
(`bacnet_health.testing.sim`) only.

## Licence

MIT. The GUI bundles PySide6/Qt under the LGPL-3.0; see `THIRD_PARTY_NOTICES.md`.
