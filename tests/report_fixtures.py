"""Rich fake Results for the report tests, and the generator for docs/samples/sample-report.html.

Only documentation address ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and generic names are used.

Regenerate the sample report with::

    .venv/bin/python tests/report_fixtures.py
"""

from __future__ import annotations

import os
import sys
import tempfile

from bacnet_health.model import (
    Bbmd,
    BdtEntry,
    Budget,
    Confidence,
    Device,
    Evidence,
    FdtEntry,
    Finding,
    InputFile,
    Result,
    RunInfo,
    Severity,
    Vantage,
)

T0 = 1793836800.0  # 2026-11-05 00:00:00 UTC
HOSTILE_NAME = '<script>alert("x")</script>&<b>'

SAMPLE_LOGO_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">'
    '<rect width="48" height="48" rx="8" fill="#1f4e79"/>'
    '<path d="M12 30 L20 18 L28 26 L36 14" stroke="#fff" stroke-width="4" fill="none" stroke-linecap="round"/>'
    "</svg>"
)


def _thr(name: str, value, meaning: str, provisional: bool = True) -> dict:
    return {name: {"value": value, "provisional": provisional, "meaning": meaning}}


def _dev(instance, ip, *, name, vendor="Example Controls", vendor_id=999, model="EC-100", fw="2.4.1", app="1.0",
         loc="Plant room", status="operational", port=47808, snet=None, sadr=None, db=12, scan=True, passive=True):
    props = {
        "object-name": name,
        "vendor-name": vendor,
        "model-name": model,
        "firmware-revision": fw,
        "application-software-version": app,
        "location": loc,
        "system-status": status,
        "database-revision": db,
        "protocol-revision": 14,
    }
    if snet is not None:  # remote devices are not read by default
        props = {}
    return Device(
        instance=instance, ip=ip, port=port, snet=snet, sadr=sadr, vendor_id=vendor_id, max_apdu=1476,
        segmentation="both", properties=props, responded_to_scan=scan, seen_passively=passive,
        first_seen=T0 + 5, last_seen=T0 + 590, iam_count=2,
    )


def make_devices(hostile: bool = False) -> list[Device]:
    devs = [
        _dev(1001, "192.0.2.10", name="AHU-01 Supervisory Controller", model="EC-500", fw="5.2.0", loc="Level 1 plant room"),
        _dev(1002, "192.0.2.11", name="AHU-02 Supervisory Controller", model="EC-500", fw="5.2.0", loc="Level 2 plant room"),
        _dev(1003, "192.0.2.12", name="Chiller Plant Controller", model="EC-700", fw="4.9.3", loc="Basement chiller hall"),
        _dev(1004, "192.0.2.13", name="Boiler Interface", vendor="Sample Automation", vendor_id=888, model="SA-IO 16",
             fw="1.8", app="3.1", loc="Basement boiler room"),
        _dev(1005, "192.0.2.14", name="Lighting Gateway", vendor="Sample Automation", vendor_id=888, model="SA-GW",
             fw="2.0.7", loc="Level 3 riser", status="non-operational"),
        _dev(1006, "192.0.2.15", name="Energy Meter Gateway", model="EC-EM", fw="1.2.0", loc="Main switch room",
             port=47809),
        _dev(1007, "192.0.2.16", name="Router RTR-01", model="EC-RTR", fw="3.3.1", loc="Level 1 comms room"),
        _dev(2001, "192.0.2.16", name="", snet=5, sadr="0a", scan=False),
        _dev(2002, "192.0.2.16", name="", snet=5, sadr="0b", scan=False),
        _dev(2003, "192.0.2.16", name="", snet=5, sadr="0c", scan=False),
        _dev(1010, "198.51.100.20", name="Tower B AHU Controller", model="EC-500", fw="5.1.4", loc="Tower B plant room",
             passive=False),
        _dev(1010, "198.51.100.21", name="Tower B FCU Controller", model="EC-200", fw="2.4.1", loc="Tower B level 4",
             passive=False),
    ]
    if hostile:
        devs.append(_dev(1099, "192.0.2.99", name=HOSTILE_NAME, loc="<img src=x onerror=alert(1)>",
                         vendor='Evil "Quotes" & Co', model="<i>m</i>"))
    return devs


def make_bbmds() -> list[Bbmd]:
    one = "255.255.255.255"
    return [
        Bbmd("192.0.2.1", 47808, "bbmd", "probe",
             bdt=[BdtEntry("192.0.2.1", 47808, one), BdtEntry("198.51.100.1", 47808, one),
                  BdtEntry("203.0.113.1", 47808, "255.255.255.0")],
             fdt=[FdtEntry("192.0.2.200", 47808, 300, 211), FdtEntry("203.0.113.50", 47808, 86400, 80211)],
             fdt_status="ack"),
        Bbmd("192.0.2.2", 47808, "bbmd", "probe",
             bdt=[BdtEntry("192.0.2.2", 47808, one), BdtEntry("198.51.100.1", 47808, one)], fdt=[], fdt_status="ack"),
        Bbmd("198.51.100.1", 47808, "bbmd", "bdt-peer",
             bdt=[BdtEntry("198.51.100.1", 47808, one), BdtEntry("192.0.2.1", 47808, one)], fdt=None,
             fdt_status="timeout"),
        Bbmd("192.0.2.10", 47808, "not-bbmd", "probe"),
        Bbmd("192.0.2.11", 47808, "not-bbmd", "probe"),
        Bbmd("192.0.2.14", 47808, "timeout", "probe"),
    ]


def make_findings(hostile: bool = False) -> list[Finding]:
    O, I = Confidence.OBSERVED, Confidence.INFERRED
    fs = [
        Finding(
            id="BBMD-006", group="BBMD", severity=Severity.CRITICAL, confidence=O, vantage_required=Vantage.SELF,
            title="Foreign device registered from a public address",
            subject="203.0.113.50:47808 via BBMD 192.0.2.1:47808",
            explanation="The BBMD at 192.0.2.1 has a foreign-device registration from an address outside the private "
            "ranges. Any host that can register as a foreign device receives every BACnet broadcast on the site and "
            "can send commands to controllers.",
            recommendation="Confirm who owns 203.0.113.50. If it is not an approved remote workstation, block UDP "
            "47808 from outside the site at the firewall and review the BBMD's foreign-device policy.",
            spec_refs=["ASHRAE 135 Annex J (BBMD foreign device table)"],
            evidence=[Evidence("table", "FDT entry 203.0.113.50:47808 ttl=86400 remaining=80211", T0 + 412,
                               "Read-FDT 192.0.2.1")],
            falsifier="The address belongs to an approved remote engineering workstation reached over a VPN that "
            "presents a public source address.",
        ),
        Finding(
            id="BBMD-001", group="BBMD", severity=Severity.HIGH, confidence=O, vantage_required=Vantage.SELF,
            title="Multiple BBMDs on one subnet", subject="192.0.2.0/24",
            explanation="Two devices on the same subnet answered as BBMDs and list overlapping peers. Each "
            "broadcast can be forwarded twice, which doubles broadcast load on remote subnets and can cause "
            "duplicate I-Am responses.",
            recommendation="Keep a single BBMD per subnet. Remove the BBMD function from 192.0.2.2 or remove the "
            "shared peers from one of the two tables.",
            spec_refs=["ASHRAE 135 Annex J.4 [TBV]"],
            evidence=[Evidence("table", "192.0.2.1 BDT lists 198.51.100.1", T0 + 400, "Read-BDT 192.0.2.1"),
                      Evidence("table", "192.0.2.2 BDT lists 198.51.100.1", T0 + 401, "Read-BDT 192.0.2.2")],
            falsifier="One of the two BBMDs has its forwarding disabled in its configuration although its BDT is "
            "populated.",
        ),
        Finding(
            id="DEV-001", group="DEV", severity=Severity.HIGH, confidence=O, vantage_required=Vantage.SELF,
            title="Duplicate device instance", subject="device 1010",
            explanation="Two different devices answer as device instance 1010. Workstations and controllers that "
            "look up a device by instance may talk to the wrong one, so values and commands can go to the wrong "
            "equipment.",
            recommendation="Give each device a unique instance number. Change the instance on one of the two "
            "controllers and update any references to it.",
            spec_refs=["ASHRAE 135 Cl. 12.11 Device object-identifier [TBV]"],
            evidence=[Evidence("exchange", "I-Am device 1010 from 198.51.100.20:47808", T0 + 120, "who-is 1-1024"),
                      Evidence("exchange", "I-Am device 1010 from 198.51.100.21:47808", T0 + 120.2, "who-is 1-1024")],
            falsifier="Both addresses belong to the same physical device (for example a dual-homed router); "
            "object-name, vendor and model would then match.",
        ),
        Finding(
            id="BCAST-001", group="BCAST", severity=Severity.MEDIUM, confidence=O, vantage_required=Vantage.SELF,
            title="High BACnet broadcast rate", subject="192.0.2.0/24",
            explanation="BACnet broadcasts averaged 31 packets per second over the busiest 60-second window. "
            "Every device on the subnet must process each broadcast, so a sustained high rate slows small "
            "controllers.",
            recommendation="Find the top broadcast sources (see the appendix) and reduce periodic Who-Is or I-Am "
            "announcements in their configuration.",
            evidence=[Evidence("metric", "peak 60 s window mean 31.2 pkt/s starting at +240 s", T0 + 240)],
            thresholds_used={**_thr("bcast_rate_medium_pps", 20, "sustained BACnet broadcasts per second (Medium)"),
                             **_thr("bcast_window_s", 60, "window for broadcast-rate evaluation, seconds")},
            falsifier="The burst was caused by a commissioning activity during the capture rather than normal "
            "operation.",
        ),
        Finding(
            id="DEV-005", group="DEV", severity=Severity.MEDIUM, confidence=O, vantage_required=Vantage.SELF,
            title="Device not operational", subject="device 1005",
            explanation="The Lighting Gateway reports its system status as non-operational. It may not be "
            "running its control program.",
            recommendation="Check the gateway's local diagnostics and event log, and restart its application "
            "through the vendor's normal maintenance procedure if required.",
            spec_refs=["ASHRAE 135 Cl. 12.11 System_Status"],
            evidence=[Evidence("exchange", "system-status = non-operational", T0 + 300, "RPM 192.0.2.14 invoke 17")],
        ),
        Finding(
            id="BBMD-002", group="BBMD", severity=Severity.MEDIUM, confidence=I, vantage_required=Vantage.SELF,
            title="Asymmetric BDT", subject="192.0.2.2:47808 -> 198.51.100.1:47808",
            explanation="The BBMD at 192.0.2.2 lists 198.51.100.1 as a peer, but 198.51.100.1 does not list "
            "192.0.2.2. Broadcasts flow in one direction only.",
            recommendation="Make the BDTs on both BBMDs list each other, or remove the one-sided entry.",
            spec_refs=["ASHRAE 135 Annex J"],
            evidence=[Evidence("table", "198.51.100.1 BDT: 198.51.100.1, 192.0.2.1", T0 + 405, "Read-BDT 198.51.100.1")],
            falsifier="198.51.100.1 is intentionally receive-only for this subnet.",
        ),
        Finding(
            id="DEV-003", group="DEV", severity=Severity.LOW, confidence=O, vantage_required=Vantage.SELF,
            title="Non-standard UDP port", subject="192.0.2.15:47809",
            explanation="The Energy Meter Gateway uses UDP port 47809 instead of the standard 47808. Devices on "
            "47808 will not hear its broadcasts.",
            recommendation="Move the device to port 47808 unless the separate port is a deliberate design choice.",
            spec_refs=["ASHRAE 135 Annex J (0xBAC0 default port)"],
            thresholds_used=_thr("standard_port", 47808, "BACnet/IP default UDP port", provisional=False),
        ),
        Finding(
            id="BBMD-007", group="BBMD", severity=Severity.LOW, confidence=O, vantage_required=Vantage.SELF,
            title="Unusual FDT TTL", subject="203.0.113.50:47808",
            explanation="A foreign device registered with a time-to-live of 86 400 s (24 hours). Stale "
            "registrations stay in the table long after the device has gone.",
            recommendation="Configure foreign devices to register with a TTL of a few minutes and re-register.",
            thresholds_used=_thr("fdt_ttl_max_s", 3600, "FDT time-to-live above which BBMD-007 applies"),
        ),
        Finding(
            id="BCAST-005", group="BCAST", severity=Severity.INFO, confidence=O, vantage_required=Vantage.SELF,
            title="Top broadcast sources", subject="192.0.2.0/24",
            explanation="The ten addresses that sent the most BACnet broadcasts are listed in the appendix.",
            recommendation="No action required; use the list when investigating broadcast load.",
        ),
        Finding(
            id="DEV-008", group="DEV", severity=Severity.INFO, confidence=O, vantage_required=Vantage.SELF,
            title="Inventory", subject="12 devices",
            explanation="The device inventory is listed in the inventory section.",
            recommendation="Keep the inventory with the site records.",
        ),
    ]
    if hostile:
        fs.append(Finding(
            id="DEV-004", group="DEV", severity=Severity.MEDIUM, confidence=O, vantage_required=Vantage.SELF,
            title=HOSTILE_NAME, subject=HOSTILE_NAME, explanation=HOSTILE_NAME, recommendation=HOSTILE_NAME,
            evidence=[Evidence("note", HOSTILE_NAME, None, HOSTILE_NAME)], falsifier=HOSTILE_NAME,
        ))
    return fs


def make_metrics() -> dict:
    ts = []
    for i in range(0, 600, 5):
        base = 8 + (i % 60) / 12
        if 240 <= i < 300:
            base += 24
        ts.append([float(i), round(base, 2)])
    return {
        "duration_s": 600,
        "frames_total": 48211,
        "bacnet_messages": 21934,
        "broadcast_total": 9120,
        "broadcast_peak_pps": 33.4,
        "broadcast_mean_pps": 15.2,
        "decode_errors": {"bvlc": 0, "npdu": 2, "apdu": 1},
        "broadcast_timeseries": ts,
        "top_broadcast_sources": [
            {"source": "192.0.2.16:47808", "count": 3120},
            {"source": "192.0.2.10:47808", "count": 1840},
            {"source": "192.0.2.12:47808", "count": 1210},
            {"source": "192.0.2.50:47808", "count": 980},
            {"source": "192.0.2.14:47808", "count": 440},
        ],
        "service_counts": {"i-am": 4120, "who-is": 3880, "read-property": 6100, "rp-ack": 6050, "cov-notification": 1710,
                           "error": 41, "reject": 3, "abort": 1},
        "checks_performed": ["BCAST-001", "BCAST-002", "BCAST-003", "DEV-001", "BBMD-001"],
    }


def make_rich_result(hostile: bool = False) -> Result:
    run = RunInfo(
        kind="audit",
        started="2026-11-05T00:00:00.000Z",
        finished="2026-11-05T00:14:32.000Z",
        command="bacnet-health audit --interface en5 --listen 10m --follow-bdt -o out/",
        interface="en5 (Ethernet)",
        local_ip="192.0.2.250",
        netmask="255.255.255.0",
        broadcast="192.0.2.255",
        port=47808,
        vantage=Vantage.ACCESS,
        vantage_source="inferred",
        ntp_synced=True,
        site="Sample Site",
        client="Sample Client",
        prepared_by="A. Engineer",
        org="Sample Consulting",
        authorised_by="Facility Manager, Sample Client",
        scope_note="BMS VLAN 192.0.2.0/24 only; 09:00-12:00 maintenance window",
        confirmations=[{"action": "follow-bdt", "target": "198.51.100.1", "user": "A. Engineer",
                        "at": "2026-11-05T00:11:02.000Z"}],
    )
    return Result(
        run=run,
        tool={"name": "bacnet-health", "version": "0.1.0a1", "python": "3.11.16", "os": "Darwin 25.0",
              "git_commit": "0123abc"},
        budget=Budget(whois_planned=18, reads_planned=40, bvlc_probes_planned=10, peak_pps_planned=5.0,
                      est_duration_s=95.0, frames_sent=71, whois_sent=17, reads_sent=44, bvlc_probes_sent=10,
                      peak_pps_actual=4.6, notes=["Local BBMD known from listen: Who-Is chunk cap reduced 4x."]),
        inputs=[InputFile("captures/sample-site-listen.pcapng", "9f2c" * 16, 5242880, 48211)],
        devices=make_devices(hostile),
        bbmds=make_bbmds(),
        topology={"broadcast_copies": {"192.0.2.0/24": 1, "198.51.100.0/24": 2, "203.0.113.0/24": 1}},
        metrics=make_metrics(),
        findings=make_findings(hostile),
        checks_not_performed=[
            {"id": "COMM-001", "title": "High Reject/Abort/Error rate",
             "reason": "Needs SPAN vantage: device-to-device requests are not visible from an access port."},
            {"id": "COMM-002", "title": "Unanswered confirmed requests", "reason": "Needs SPAN vantage."},
            {"id": "SEC-002", "title": "Unexpected writer",
             "reason": "Needs SPAN vantage: writes between devices cannot be seen from an access port."},
            {"id": "SEC-003", "title": "Write activity summary", "reason": "Needs SPAN vantage."},
        ],
        limitations=["The capture covered 10 minutes during a weekday morning."],
    )


def make_previous_result() -> Result:
    """An earlier visit: one device different firmware, one device gone, one finding since resolved."""
    r = make_rich_result()
    r.run.started = "2026-05-12T01:00:00.000Z"
    r.run.finished = "2026-05-12T01:12:00.000Z"
    r.devices = [d for d in r.devices if d.instance not in (1006,)]
    for d in r.devices:
        if d.instance == 1003:
            d.properties["firmware-revision"] = "4.8.0"
            d.properties["database-revision"] = 9
    r.devices.append(_dev(1020, "192.0.2.30", name="Old Supply Fan Controller", model="EC-100", fw="1.0"))
    r.findings = [f for f in r.findings if f.id not in ("BBMD-006", "DEV-003", "BBMD-007")]
    for f in r.findings:
        if f.id == "BCAST-001":
            f.severity = Severity.HIGH
    r.findings.append(Finding(
        id="DEV-006", group="DEV", severity=Severity.LOW, confidence=Confidence.OBSERVED,
        vantage_required=Vantage.SELF, title="Clock skew", subject="device 1002",
        explanation="Device clock was 9 minutes fast.", recommendation="Synchronise the device clock."))
    r.findings.append(Finding(
        id="SEC-002", group="SEC", severity=Severity.HIGH, confidence=Confidence.OBSERVED,
        vantage_required=Vantage.SPAN, title="Unexpected writer", subject="192.0.2.77",
        explanation="Writes from an unknown workstation.", recommendation="Identify the workstation."))
    return r


def write_sample(path: str) -> None:
    from bacnet_health.report.branding import Branding
    from bacnet_health.report.diff import diff_results
    from bacnet_health.report.html import render_html

    with tempfile.TemporaryDirectory() as tmp:
        logo = os.path.join(tmp, "logo.svg")
        with open(logo, "w", encoding="utf-8") as fh:
            fh.write(SAMPLE_LOGO_SVG)
        branding = Branding(org="Sample Consulting", prepared_by="A. Engineer", site="Sample Site",
                            client="Sample Client", logo_path=logo, accent="#1f4e79")
        new = make_rich_result()
        out = render_html(new, branding, diff=diff_results(make_previous_result(), new))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)


if __name__ == "__main__":
    here = os.path.dirname(os.path.abspath(__file__))
    target = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "..", "docs", "samples", "sample-report.html")
    write_sample(os.path.abspath(target))
    print(os.path.abspath(target))
