# bacnet-health

Read-only, rate-limited BACnet/IP network health check for building-management networks, with reports a consultant can
hand to a client.

> **Pre-release (0.1.0a1).** Not yet validated on physical controllers. Thresholds are provisional until calibrated with
> field captures.

- **Safe by design.** The tool only sends Who-Is, ReadProperty(-Multiple), and BVLC Read-BDT/Read-FDT. Write services
  are not implemented. Traffic is rate-limited, and you see a traffic budget before anything is sent.
- **Active + passive.** It can scan a subnet, listen to broadcasts, or analyse a pcap/pcapng capture.
- **Findings, not packet dumps.** Each finding has a severity, a confidence level, the capture position it needs, a
  plain-English explanation, a recommendation, and evidence.
- **Reports.** Output is a terminal summary, JSON, and a single offline HTML file that you can white-label.

Design: [docs/design/v0.1-design.md](docs/design/v0.1-design.md). Licence: MIT.
