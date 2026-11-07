# bacnet-health — project brief

Owner: Lierre Wong (GitHub `lns-hk`), independent IT / OT consultant in Hong Kong. The owner audits building-management
(BMS) networks: BACnet/IP controllers (e.g. JCI Metasys, Carrier) on shared, often undocumented OT networks.

**Goal:** an open-source BACnet/IP network health-check tool that field engineers can trust on live building networks,
and that produces a report a consultant can hand to a client. It will be published on github.com/lns-hk and listed on
https://lns.hk/toybox/ as a portfolio piece.

**Working mode — important:** this project is developed in conversation with the owner. Before writing code, discuss
scope, priorities and design choices with the user and agree on a plan. Propose, don't assume. Build in small steps the
user can review. Do not create the GitHub repo or push until the user says so.

## Starting ideas (to discuss, not a fixed spec)
- Read-only by design: only Who-Is / ReadProperty(-Multiple); never write services. Rate-limited active traffic.
- Active scan: Who-Is discovery, I-Am details, device properties (vendor, model, firmware, object name).
- Passive analysis of pcap/pcapng: broadcast rate, Who-Is/I-Am storms, top talkers, error/reject/abort, BBMD traffic.
- Findings with severity + plain-English explanation + recommendation (duplicate device instances, duplicate IP:port,
  storms, multiple BBMDs, non-standard ports…).
- Outputs: terminal summary, JSON, self-contained HTML report.
- Python 3.10+, ideally stdlib-only at runtime; tests with a local device simulator and synthetic pcaps. MIT licence.

## Rules
- Never mention any employer, client, building or customer. Use documentation/private address ranges in samples.
- Git commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
