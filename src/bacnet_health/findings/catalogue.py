"""Static finding catalogue (design §4). Text is plain English for facility managers and engineers.

Explanations/recommendations may contain ``{placeholders}`` filled by ``make_finding(**fmt)``.
Spec references are at clause level; exact sub-clauses are to be verified against ASHRAE 135-2020 [TBV].
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from bacnet_health.model import Confidence, Evidence, Finding, Severity, Vantage

S, C, V = Severity, Confidence, Vantage


@dataclass(frozen=True)
class FindingSpec:
    id: str
    group: str
    title: str
    severity: Severity
    confidence: Confidence
    vantage: Vantage
    explanation: str
    recommendation: str
    spec_refs: tuple[str, ...] = ()
    falsifier: str = ""
    passive: bool = True  # can be evaluated from passive data
    active: bool = False  # can be evaluated from an active scan


_SPECS: list[FindingSpec] = [
    # ---------------- Device identity ----------------
    FindingSpec(
        "DEV-001", "DEV", "Duplicate device instance", S.HIGH, C.OBSERVED, V.SELF,
        "Device instance {instance} is claimed by more than one device ({addresses}). BACnet requires every device "
        "instance to be unique across the whole internetwork. Workstations and controllers may read from or command "
        "the wrong device, and the two devices can appear to 'flap' between addresses.",
        "Identify both devices on site and renumber one of them to an unused instance. Record instance allocations in "
        "the site's BACnet numbering register so new devices are not commissioned with a clash.",
        ("ASHRAE 135 Clause 12 (Device object, Object_Identifier uniqueness) [TBV]",),
        "The addresses belong to the same physical device (for example a dual-homed router or NAT); in that case the "
        "device name, vendor and model would match on both addresses.",
        passive=True, active=True,
    ),
    FindingSpec(
        "DEV-002", "DEV", "One address answers for several devices", S.MEDIUM, C.OBSERVED, V.SELF,
        "Address {address} answers for {count} different device instances ({instances}) without identifying itself as "
        "a BACnet router. This usually means two devices share an IP address, or a gateway is not routing properly.",
        "Check the address on site. If it is a gateway, confirm it presents routed networks correctly; otherwise give "
        "each device its own IP address.",
        ("ASHRAE 135 Annex J (B/IP addressing) [TBV]",),
        "The address is a gateway that legitimately hosts several virtual devices (check the vendor documentation).",
        passive=True, active=True,
    ),
    FindingSpec(
        "DEV-003", "DEV", "BACnet/IP on a non-standard UDP port", S.LOW, C.OBSERVED, V.SELF,
        "BACnet/IP traffic was seen on UDP port {port} ({addresses}). The standard port is 47808. Non-standard ports are "
        "allowed but are easy to miss in firewall rules, documentation and troubleshooting.",
        "Confirm the port is intentional and documented. If several ports are used on one subnet, make sure the "
        "BBMD/router configuration covers each one.",
        ("ASHRAE 135 Annex J (UDP port X'BAC0') [TBV]",),
        "The site deliberately uses separate ports to segment systems and documents this.",
        passive=True, active=True,
    ),
    FindingSpec(
        "DEV-004", "DEV", "Device did not answer", S.MEDIUM, C.OBSERVED, V.SELF,
        "{subject} was known (from {source}) but did not answer during the check. The device may be offline, "
        "overloaded, behind a failing router, or filtered by a firewall.",
        "Check power, cabling and the device's status on the BMS workstation. If it sits behind a router, check the "
        "router and the field bus.",
        ("ASHRAE 135 Clause 16 (Who-Is / I-Am) [TBV]",),
        "The device answered later (late replies are listed in the evidence) or was intentionally out of service.",
        passive=True, active=True,
    ),
    FindingSpec(
        "DEV-005", "DEV", "Device reports it is not operational", S.MEDIUM, C.OBSERVED, V.SELF,
        "Device {instance} reports System_Status '{status}'. Only 'operational' means the device is running normally.",
        "Check the device on the BMS workstation or with the vendor tool. 'download-required' or 'non-operational' "
        "normally needs a controls engineer.",
        ("ASHRAE 135 Clause 12 (Device object, System_Status) [TBV]",),
        "The device is being commissioned or updated on purpose.",
        passive=False, active=True,
    ),
    FindingSpec(
        "DEV-006", "DEV", "Device clock is wrong", S.LOW, C.OBSERVED, V.SELF,
        "Device {instance}'s clock differs from the audit laptop by about {skew}. Schedules, trends and alarms use the "
        "device clock, so they run at the wrong time.",
        "Set up time synchronisation from the BMS head-end (TimeSynchronization or UTCTimeSynchronization) and check "
        "the device's UTC offset and daylight-saving settings.",
        ("ASHRAE 135 Clause 12 (Local_Time, Local_Date, UTC_Offset) [TBV]",),
        "The audit laptop's clock was not synchronised (the report records the laptop's time-sync state).",
        passive=False, active=True,
    ),
    FindingSpec(
        "DEV-007", "DEV", "Old BACnet protocol revision", S.INFO, C.OBSERVED, V.SELF,
        "Device {instance} implements BACnet protocol revision {revision}. Older revisions lack newer features and "
        "security improvements.",
        "No action needed now. Consider it when planning upgrades.",
        ("ASHRAE 135 Clause 12 (Protocol_Revision) [TBV]",),
        "",
        passive=False, active=True,
    ),
    FindingSpec(
        "DEV-008", "DEV", "Device inventory", S.INFO, C.OBSERVED, V.SELF,
        "{count} BACnet devices were found ({local} on this subnet, {remote} behind routers). See the inventory "
        "section for vendor, model and firmware.",
        "Compare the inventory with the site's asset register.",
        (),
        "",
        passive=True, active=True,
    ),
    # ---------------- Broadcast health ----------------
    FindingSpec(
        "BCAST-001", "BCAST", "High BACnet broadcast rate", S.MEDIUM, C.OBSERVED, V.SELF,
        "BACnet broadcast traffic peaked at {peak:.1f} packets per second over a {window}-second window (average "
        "{avg:.1f}/s). Every device on the subnet has to process every broadcast, so a high rate slows controllers "
        "and can starve slow field buses behind routers.",
        "Find the top broadcast sources (see evidence) and reduce unnecessary discovery, for example by replacing "
        "periodic global Who-Is with targeted reads or static device bindings.",
        ("ASHRAE 135 Annex J (broadcast distribution) [TBV]",),
        "The peak coincides with a known one-off event (system start-up, commissioning).",
    ),
    FindingSpec(
        "BCAST-002", "BCAST", "Who-Is storm", S.HIGH, C.OBSERVED, V.SELF,
        "{count} Who-Is requests were seen in {window} seconds (peak {peak:.1f}/s). Each Who-Is can make every device "
        "answer with an I-Am, so a burst like this multiplies traffic across the network.",
        "Identify the sending workstation or controller ({sources}) and reduce its discovery frequency, or use "
        "ranged Who-Is.",
        ("ASHRAE 135 Clause 16 (Who-Is) [TBV]",),
        "",
    ),
    FindingSpec(
        "BCAST-003", "BCAST", "I-Am flood", S.MEDIUM, C.OBSERVED, V.SELF,
        "{detail}. Large numbers of I-Am messages add broadcast load and often point to a device or workstation "
        "repeatedly re-discovering the network.",
        "Find what triggers the I-Am traffic (usually Who-Is from a workstation) or devices that announce themselves "
        "too often, and reduce it.",
        ("ASHRAE 135 Clause 16 (I-Am) [TBV]",),
        "",
    ),
    FindingSpec(
        "BCAST-004", "BCAST", "Most Who-Is requests are global", S.LOW, C.OBSERVED, V.SELF,
        "{pct:.0f}% of Who-Is requests ({global_count} of {total}) asked every device on the network to answer. Ranged "
        "Who-Is requests produce far less traffic.",
        "Configure the sources ({sources}) to use device-instance ranges or static bindings.",
        ("ASHRAE 135 Clause 16 (Who-Is ranges) [TBV]",),
        "",
    ),
    FindingSpec(
        "BCAST-005", "BCAST", "Top broadcast sources", S.INFO, C.OBSERVED, V.SELF,
        "The busiest BACnet broadcast sources were: {sources}.",
        "Use this list as the starting point for any broadcast-reduction work.",
        (),
        "",
    ),
    FindingSpec(
        "BCAST-006", "BCAST", "Broadcasts are delivered more than once", S.HIGH, C.OBSERVED, V.SELF,
        "{count} broadcasts arrived twice or more within {window_ms} ms (for example from {example}). This is the "
        "classic sign of two BBMDs forwarding the same broadcast into one subnet, or of a forwarding loop.",
        "Check BBMD configuration: there must be only one BBMD per subnet in each broadcast distribution table. See "
        "the BBMD section of this report.",
        ("ASHRAE 135 Annex J (BBMD operation) [TBV]",),
        "The duplicates are legitimate retransmissions by the sender (they would then share the same origin and not "
        "arrive via different BBMDs).",
    ),
    # ---------------- Communication errors ----------------
    FindingSpec(
        "COMM-001", "COMM", "High rate of rejected or aborted requests", S.MEDIUM, C.OBSERVED, V.SPAN,
        "{subject}: {bad} of {total} confirmed requests ({pct:.0f}%) ended in Reject or Abort. Common causes are "
        "requests the device does not support, messages too large for the device, or overload.",
        "Check which services are rejected (evidence) and adjust the requesting workstation's configuration, for "
        "example to avoid ReadPropertyMultiple or segmented messages with this device.",
        ("ASHRAE 135 Clause 18 (error, reject and abort reasons) [TBV]",),
        "The rejects come from a one-off diagnostic tool session.",
    ),
    FindingSpec(
        "COMM-002", "COMM", "Requests are going unanswered", S.MEDIUM, C.OBSERVED, V.SPAN,
        "{subject}: {unanswered} of {total} confirmed requests ({pct:.0f}%) received no answer within {timeout:.0f} s.",
        "Check the device and the path to it (router, field bus load). Unanswered requests make workstations retry "
        "and add load.",
        ("ASHRAE 135 Clause 5 (transaction state machines) [TBV]",),
        "The capture started or ended in the middle of these transactions (requests near the capture edges are "
        "excluded).",
    ),
    FindingSpec(
        "COMM-003", "COMM", "Requests are being retransmitted", S.LOW, C.OBSERVED, V.SPAN,
        "{count} confirmed requests were sent again with the same invoke ID (top: {examples}). Retries mean the first "
        "attempt timed out.",
        "Look at the devices involved for slow responses; consider increasing APDU timeout on the client.",
        ("ASHRAE 135 Clause 5 (APDU retries) [TBV]",),
        "",
    ),
    FindingSpec(
        "COMM-004", "COMM", "Segmentation problems", S.MEDIUM, C.OBSERVED, V.SPAN,
        "{count} transactions were aborted for segmentation reasons ({reasons}). The requested data did not fit in one "
        "message and the device could not split it.",
        "Configure the client to request less data per message for these devices, or check max-APDU settings.",
        ("ASHRAE 135 Clause 5.4 (segmentation) [TBV]",),
        "",
    ),
    FindingSpec(
        "COMM-005", "COMM", "Router rejected messages", S.MEDIUM, C.OBSERVED, V.SELF,
        "{count} Reject-Message-To-Network messages were seen ({reasons}). A router could not deliver traffic to the "
        "requested network.",
        "Check router configuration and the network numbers referenced (evidence).",
        ("ASHRAE 135 Clause 6 (network layer) [TBV]",),
        "",
    ),
    FindingSpec(
        "COMM-006", "COMM", "Duplicate network number", S.HIGH, C.OBSERVED, V.SELF,
        "Network {network} is announced by more than one router ({routers}). BACnet network numbers must be unique; "
        "otherwise traffic for that network can be delivered to the wrong place.",
        "Renumber one of the networks and update the router configuration.",
        ("ASHRAE 135 Clause 6 (network numbers) [TBV]",),
        "The routers are redundant paths to the same network by design (rare; check the documentation).",
    ),
    FindingSpec(
        "COMM-007", "COMM", "Possible routing loop", S.HIGH, C.INFERRED, V.SELF,
        "{count} messages arrived with a hop count of 1 or less. Messages normally start with a hop count of 255; "
        "reaching nearly zero suggests they are circulating between routers.",
        "Check router and BBMD configuration for loops.",
        ("ASHRAE 135 Clause 6 (hop count) [TBV]",),
        "A sender deliberately sets a low hop count (unusual).",
    ),
    # ---------------- Security / write activity ----------------
    FindingSpec(
        "SEC-001", "SEC", "Device control commands observed", S.CRITICAL, C.OBSERVED, V.SELF,
        "{count} device control command(s) ({services}) were seen from {sources}. DeviceCommunicationControl can stop a "
        "controller from communicating and ReinitializeDevice restarts it.",
        "Confirm with the site whether the sender is an authorised engineering workstation. If not, treat it as a "
        "security incident: isolate the source and review access to the BMS network. Add authorised workstations to "
        "the profile's known-workstation list.",
        ("ASHRAE 135 Clause 16 (DeviceCommunicationControl, ReinitializeDevice) [TBV]",
         "ISA/IEC 62443-3-3 SR 2.1 (authorisation enforcement) [TBV]"),
        "The source is a known, authorised workstation performing planned maintenance.",
    ),
    FindingSpec(
        "SEC-002", "SEC", "Writes from an unexpected source", S.HIGH, C.OBSERVED, V.SPAN,
        "{source} sent {count} write operations ({services}) to {targets} device(s) and is not on the list of known "
        "workstations.",
        "Confirm whether the source is authorised. Unknown writers on a BMS network are a security and safety risk.",
        ("ASHRAE 135 Clause 15 (object access services) [TBV]", "ISA/IEC 62443-3-3 SR 2.1 [TBV]"),
        "The source is an authorised workstation that was not yet listed in the profile.",
    ),
    FindingSpec(
        "SEC-003", "SEC", "Write activity summary", S.INFO, C.OBSERVED, V.SPAN,
        "{count} write operations from {writers} source(s) were seen. See evidence for who wrote to which devices.",
        "Review the list with the site and record the authorised workstations.",
        (),
        "",
    ),
    FindingSpec(
        "SEC-004", "SEC", "BACnet traffic with public IP addresses", S.HIGH, C.OBSERVED, V.SELF,
        "BACnet traffic involved addresses outside private ranges ({addresses}). BACnet has no built-in "
        "authentication; devices reachable from public networks can be read and commanded by anyone.",
        "Remove direct Internet exposure. Use a VPN or a secured gateway for remote access.",
        ("CISA ICS guidance on exposed BACnet devices [TBV]",),
        "The addresses are private addresses the site uses outside RFC 1918 (for example re-used public space); check "
        "the IP plan.",
        passive=True, active=True,
    ),
    # ---------------- BBMD ----------------
    FindingSpec(
        "BBMD-001", "BBMD", "More than one BBMD on a subnet", S.HIGH, C.OBSERVED, V.SELF,
        "Subnet {subnet} has {count} BBMDs ({bbmds}). Each subnet should have exactly one BBMD in the broadcast "
        "distribution tables; otherwise broadcasts are forwarded twice, which can multiply traffic or create loops.",
        "Keep one BBMD per subnet and disable BBMD function on the others, then update every peer's BDT.",
        ("ASHRAE 135 Annex J (one BBMD per B/IP subnet) [TBV]",),
        "The second BBMD is not listed in any peer's BDT and is not forwarding (check BCAST-006 evidence).",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-002", "BBMD", "Broadcast distribution tables do not match", S.MEDIUM, C.OBSERVED, V.SELF,
        "{a} lists {b} as a peer, but {b}'s table does not list {a}. Broadcasts will reach {b}'s subnet from {a} but "
        "not the other way round.",
        "Make the broadcast distribution tables identical on all peer BBMDs.",
        ("ASHRAE 135 Annex J (BDT) [TBV]",),
        "",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-003", "BBMD", "BBMD missing from its own table", S.MEDIUM, C.OBSERVED, V.SELF,
        "BBMD {bbmd} does not list itself in its own broadcast distribution table. Peers copying this table will be "
        "inconsistent.",
        "Add the BBMD's own address to its BDT, as the standard expects.",
        ("ASHRAE 135 Annex J (BDT) [TBV]",),
        "The device is behind NAT and lists its public address instead (see NAT note in evidence).",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-004", "BBMD", "Mixed broadcast distribution masks", S.MEDIUM, C.OBSERVED, V.SELF,
        "BBMD {bbmd} mixes one-hop (all-ones) and two-hop (directed broadcast) masks: {detail}. Inconsistent masks "
        "make broadcast delivery depend on router support for directed broadcasts.",
        "Use one distribution method consistently; all-ones masks (one-hop) are the most robust.",
        ("ASHRAE 135 Annex J (broadcast distribution mask) [TBV]",),
        "",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-005", "BBMD", "Broadcast delivery is uneven", S.HIGH, C.INFERRED, V.SELF,
        "Based on the BBMD tables, a broadcast from {origin} would reach {detail}. Healthy configurations deliver "
        "exactly one copy to every subnet.",
        "Review the BBMD tables so each subnet appears once on every BBMD.",
        ("ASHRAE 135 Annex J (BBMD forwarding) [TBV]",),
        "Passive captures do not show the predicted duplicates or gaps.",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-006", "BBMD", "Foreign device registered from a public address", S.CRITICAL, C.OBSERVED, V.SELF,
        "BBMD {bbmd} has a foreign-device registration from {address}, outside private address ranges. Anyone who can "
        "register as a foreign device can see and send broadcasts on the BMS network.",
        "Confirm the registration is authorised. Block BBMD registration from the Internet at the firewall and "
        "require a VPN for remote engineering access.",
        ("ASHRAE 135 Annex J (foreign devices) [TBV]", "ISA/IEC 62443-3-3 SR 5.1 (network segmentation) [TBV]"),
        "The address belongs to the site's own remote-access gateway (still review the exposure).",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-007", "BBMD", "Unusual foreign-device time-to-live", S.LOW, C.OBSERVED, V.SELF,
        "BBMD {bbmd} has foreign-device entries with time-to-live {detail}. Very long registrations keep stale entries "
        "for a long time.",
        "Use shorter registration TTLs on foreign devices.",
        ("ASHRAE 135 Annex J (FDT time-to-live) [TBV]",),
        "",
        passive=False, active=True,
    ),
    FindingSpec(
        "BBMD-008", "BBMD", "BBMD inventory", S.INFO, C.OBSERVED, V.SELF,
        "{count} BBMD(s) were found: {bbmds}.",
        "Compare with the site's network documentation.",
        (),
        "",
        passive=True, active=True,
    ),
]

CATALOGUE: dict[str, FindingSpec] = {s.id: s for s in _SPECS}


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


def _fmt(template: str, fmt: dict[str, Any]) -> str:
    try:
        return template.format_map(_SafeDict(fmt))
    except (ValueError, KeyError, IndexError):
        return template


def make_finding(
    fid: str,
    subject: str = "",
    *,
    severity: Severity | None = None,
    confidence: Confidence | None = None,
    evidence: Iterable[Evidence] = (),
    thresholds: dict[str, Any] | None = None,
    **fmt: Any,
) -> Finding:
    spec = CATALOGUE[fid]
    fmt.setdefault("subject", subject)
    return Finding(
        id=spec.id,
        group=spec.group,
        severity=severity or spec.severity,
        confidence=confidence or spec.confidence,
        vantage_required=spec.vantage,
        title=spec.title,
        explanation=_fmt(spec.explanation, fmt),
        recommendation=_fmt(spec.recommendation, fmt),
        subject=subject,
        spec_refs=list(spec.spec_refs),
        evidence=list(evidence),
        thresholds_used=thresholds or {},
        falsifier=spec.falsifier,
    )


def not_performed(fid: str, reason: str) -> dict[str, str]:
    return {"id": fid, "title": CATALOGUE[fid].title, "reason": reason}
