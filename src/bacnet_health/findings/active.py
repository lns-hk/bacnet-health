"""Findings from an active scan (design §4.1 DEV, §4.4 SEC-004, §4.5 BBMD).

``evaluate_active`` reads only the Result (devices, bbmds, topology, metrics) and the per-device ``scan_stats``; it
sends nothing. Checks that could not be evaluated are listed by :func:`active_not_performed` so an absent finding is
never mistaken for a healthy network.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Any, Iterable

from bacnet_health.analysis.passive import is_private_or_special
from bacnet_health.findings.catalogue import make_finding, not_performed
from bacnet_health.findings.thresholds import th, used
from bacnet_health.model import Bbmd, Confidence, Device, Evidence, Finding, Result, Severity
from bacnet_health.topology import ALL_ONES, bdt_lists, subnet_of

__all__ = ["ACTIVE_IDS", "evaluate_active", "active_not_performed", "performed_active"]

ACTIVE_IDS = [
    "DEV-001", "DEV-002", "DEV-003", "DEV-004", "DEV-005", "DEV-006", "DEV-007", "DEV-008",
    "SEC-004",
    "BBMD-001", "BBMD-002", "BBMD-003", "BBMD-004", "BBMD-005", "BBMD-006", "BBMD-007", "BBMD-008",
]
_PROP_IDS = ("DEV-005", "DEV-006", "DEV-007")
_BBMD_IDS = tuple(i for i in ACTIVE_IDS if i.startswith("BBMD"))


def _ev(detail: str, ts: float | None = None, ref: str | None = None, kind: str = "exchange") -> Evidence:
    return Evidence(kind, detail, ts, ref)


def _addr(ip: str | None, port: int | None) -> str:
    return f"{ip}:{port}"


def _public_checker(extra: Iterable[str]) -> Any:
    nets = [ipaddress.ip_network(n, strict=False) for n in extra]

    def is_public(ip: str | None) -> bool:
        if not ip:
            return False
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in nets) or not is_private_or_special(ip)

    return is_public


def _steps(result: Result) -> set[str]:
    m = result.metrics if isinstance(result.metrics, dict) else {}
    return set(m.get("scan_steps", []))


def _human_duration(s: float) -> str:
    s = abs(s)
    if s < 120:
        return f"{s:.0f} seconds"
    if s < 7200:
        return f"{s / 60:.0f} minutes"
    if s < 172800:
        return f"{s / 3600:.1f} hours"
    return f"{s / 86400:.1f} days"


def _identity(d: Device) -> tuple[Any, ...] | None:
    name = d.properties.get("object-name")
    model = d.properties.get("model-name")
    if not name:
        return None
    return (name, d.vendor_id, model)


# ---------------------------------------------------------------------------------------------------------------------


def evaluate_active(
    result: Result,
    scan_stats: dict[str, dict[str, Any]] | None = None,
    host_ntp_synced: bool | None = None,
    *,
    treat_as_public: Iterable[str] = (),
) -> list[Finding]:
    """Evaluate DEV-001..008, SEC-004 and BBMD-001..008 from scan data.

    ``treat_as_public``: extra CIDR ranges to treat as public (lab scenarios that use documentation ranges).
    """
    if scan_stats is None:
        scan_stats = (result.metrics or {}).get("scan_stats", {}) if isinstance(result.metrics, dict) else {}
    is_public = _public_checker(treat_as_public)
    steps = _steps(result)
    out: list[Finding] = []
    out += _dev_identity(result.devices)
    out += _dev_unanswered(result, scan_stats)
    if "device-reads" in steps or any(d.properties for d in result.devices):
        out += _dev_properties(result.devices, scan_stats, host_ntp_synced)
    out += _dev_inventory(result.devices)
    out += _sec_public(result, is_public)
    if "bbmd-audit" in steps or result.bbmds:
        out += _bbmd(result, is_public, "bbmd-audit" in steps)
    out.sort(key=lambda f: (f.severity.rank, f.id, f.subject))
    return out


def active_not_performed(result: Result, host_ntp_synced: bool | None) -> list[dict[str, str]]:
    steps = _steps(result)
    out: list[dict[str, str]] = []
    if "device-reads" not in steps:
        out += [not_performed(i, "device properties were not read in this scan") for i in _PROP_IDS]
    elif host_ntp_synced is not True:
        state = "not synchronised" if host_ntp_synced is False else "of unknown synchronisation state"
        out.append(not_performed("DEV-006", f"the audit laptop's clock was {state}, so device clock skew cannot "
                                            "be judged"))
    if "bbmd-audit" not in steps:
        out += [not_performed(i, "the BBMD audit was not performed") for i in _BBMD_IDS]
    else:
        known = {(b.ip, b.port) for b in result.bbmds if b.status == "bbmd" and b.bdt is not None}
        unread = sorted({_addr(e.ip, e.port) for b in result.bbmds if b.status == "bbmd" for e in b.bdt or []
                         if (e.ip, e.port) not in known})
        if unread:
            out.append(not_performed(
                "BBMD-002", f"the tables of BDT peers {', '.join(unread[:5])}{' ...' if len(unread) > 5 else ''} were "
                            "not read (follow-bdt off or no answer), so symmetry with them was not checked"))
    return out


def performed_active(skipped: list[dict[str, str]]) -> list[str]:
    """Active check IDs that were evaluated (complete or partial), given the not-performed list."""
    full_skip = {x["id"] for x in skipped if x["id"] != "BBMD-002" or "not performed" in x["reason"]}
    return [i for i in ACTIVE_IDS if i not in full_skip]


# ---------------------------------------------------------------------------------------------------------------------
# DEV
# ---------------------------------------------------------------------------------------------------------------------


def _dev_identity(devices: list[Device]) -> list[Finding]:
    out: list[Finding] = []
    by_inst: dict[int, list[Device]] = defaultdict(list)
    for d in devices:
        by_inst[d.instance].append(d)
    for inst, ds in sorted(by_inst.items()):
        addrs = sorted({d.address_key for d in ds})
        if len(addrs) < 2:
            continue
        ids = {_identity(d) for d in ds}
        same = len(ids) == 1 and None not in ids
        ev = [_ev(f"I-Am for instance {inst} from {d.address_key} (vendor {d.vendor_id}, "
                  f"object-name {d.properties.get('object-name', 'not read')!r})", d.first_seen) for d in ds]
        if same:
            ev.append(_ev("Object-name, vendor and model match on every address: probably the same device seen "
                          "twice (dual-homed or NAT), so the severity is Info.", kind="note"))
        out.append(make_finding("DEV-001", f"device {inst}", severity=Severity.INFO if same else None, evidence=ev,
                                instance=inst, addresses=", ".join(addrs)))

    by_addr: dict[str, set[int]] = defaultdict(set)
    routers: set[str] = set()
    for d in devices:
        if d.remote:
            routers.add(_addr(d.ip, d.port))
        else:
            by_addr[_addr(d.ip, d.port)].add(d.instance)
    for a, insts in sorted(by_addr.items()):
        if len(insts) < 2:
            continue
        router = a in routers
        ev = [_ev(f"{a} sent I-Am for instances {', '.join(map(str, sorted(insts)))}")]
        if router:
            ev.append(_ev(f"{a} also routes to other BACnet networks (routed I-Am with SNET), so it is a gateway; "
                          "severity Info.", kind="note"))
        out.append(make_finding("DEV-002", a, severity=Severity.INFO if router else None, evidence=ev, address=a,
                                count=len(insts), instances=", ".join(map(str, sorted(insts)))))

    std = th("standard_port")
    local = [d for d in devices if not d.remote and d.port is not None]
    ports: dict[int, list[Device]] = defaultdict(list)
    for d in local:
        ports[d.port].append(d)  # type: ignore[index]
    for port, ds in sorted(ports.items()):
        if port == std:
            continue
        consistent = len(ports) == 1
        addrs = sorted({_addr(d.ip, d.port) for d in ds})
        ev = [_ev(f"device {d.instance} answered from {_addr(d.ip, d.port)}") for d in ds[:20]]
        if consistent:
            ev.append(_ev(f"Every device found uses port {port}: the site uses it consistently; severity Info.",
                          kind="note"))
        out.append(make_finding("DEV-003", f"UDP port {port}", severity=Severity.INFO if consistent else None,
                                evidence=ev, thresholds=used("standard_port"), port=port,
                                addresses=", ".join(addrs[:10]) + (" ..." if len(addrs) > 10 else "")))
    return out


def _dev_unanswered(result: Result, stats: dict[str, dict[str, Any]]) -> list[Finding]:
    out: list[Finding] = []
    found = {_addr(d.ip, d.port) for d in result.devices if d.responded_to_scan and not d.remote}
    for key, st in sorted(stats.items()):
        if not isinstance(st, dict) or not st.get("unresponsive"):
            continue
        subject = f"Device {st.get('instance')} at {st.get('address')}"
        ev = [_ev(f"{st.get('requests', 0)} read request(s) sent, {st.get('timeouts', 0)} timed out"
                  + (f"; {st['note']}" if st.get("note") else ""))]
        out.append(make_finding("DEV-004", subject, evidence=ev, source="its I-Am reply"))
    targets = (result.metrics or {}).get("targets", {}) if isinstance(result.metrics, dict) else {}
    for label, t in sorted(targets.items()):
        if t.get("method") is None and label not in found:  # falsifier: it answered later (late I-Am)
            ev = [_ev(f"ReadProperty object-identifier of device 4194303 to {label}: {t.get('wildcard_read')}"),
                  _ev(f"Unicast Who-Is 0-4194302 to {label}: no I-Am")]
            out.append(make_finding("DEV-004", f"Target {label}", evidence=ev, source="the target list"))
    if "discovery" in _steps(result):
        for d in result.devices:
            if d.seen_passively and not d.responded_to_scan:
                ev = [_ev(f"I-Am seen passively from {d.address_key} (last at {d.last_seen}) but no answer to the "
                          "ranged Who-Is", d.last_seen, kind="frame")]
                out.append(make_finding("DEV-004", f"Device {d.instance} at {d.address_key}", evidence=ev,
                                        source="passive traffic"))
    return out


def _dev_properties(devices: list[Device], stats: dict[str, dict[str, Any]],
                    ntp: bool | None) -> list[Finding]:
    out: list[Finding] = []
    for d in devices:
        key = f"{d.instance}@{d.address_key}"
        st = stats.get(key, {})
        status = d.properties.get("system-status")
        if status is not None and str(status) != "operational":
            sev = Severity.HIGH if str(status) == "non-operational" else None
            out.append(make_finding("DEV-005", f"device {d.instance}", severity=sev, instance=d.instance,
                                    status=status, evidence=[_ev(f"ReadProperty system-status from {d.address_key} "
                                                                 f"= {status}")]))
        clk = st.get("clock", {}) if isinstance(st, dict) else {}
        skew = clk.get("skew_s")
        if ntp is True and isinstance(skew, (int, float)) and abs(skew) > th("clock_skew_low_s"):
            sev = Severity.MEDIUM if abs(skew) > th("clock_skew_medium_s") else Severity.LOW
            direction = "ahead of" if skew > 0 else "behind"
            out.append(make_finding(
                "DEV-006", f"device {d.instance}", severity=sev, instance=d.instance,
                skew=f"{_human_duration(skew)} ({direction} the laptop)",
                thresholds=used("clock_skew_low_s", "clock_skew_medium_s"),
                evidence=[_ev(f"device local date/time {clk.get('device_local')} vs laptop {clk.get('host_local')} "
                              f"(skew {skew:+.0f} s; laptop clock NTP-synchronised)", clk.get("host_ts"))]))
        rev = d.properties.get("protocol-revision")
        if isinstance(rev, int) and rev < th("min_protocol_revision"):
            out.append(make_finding("DEV-007", f"device {d.instance}", instance=d.instance, revision=rev,
                                    thresholds=used("min_protocol_revision"),
                                    evidence=[_ev(f"protocol-revision = {rev} from {d.address_key}")]))
    return out


def _dev_inventory(devices: list[Device]) -> list[Finding]:
    remote = sum(1 for d in devices if d.remote)
    ev = []
    for d in sorted(devices, key=lambda x: x.instance)[:50]:
        p = d.properties
        ev.append(_ev(f"{d.instance} at {d.address_key}: vendor {p.get('vendor-name', d.vendor_id)}, model "
                      f"{p.get('model-name', '-')}, firmware {p.get('firmware-revision', '-')}", kind="table"))
    return [make_finding("DEV-008", "devices", evidence=ev, count=len(devices), local=len(devices) - remote,
                         remote=remote)]


# ---------------------------------------------------------------------------------------------------------------------
# SEC-004
# ---------------------------------------------------------------------------------------------------------------------


def _sec_public(result: Result, is_public: Any) -> list[Finding]:
    seen: dict[str, str] = {}
    for d in result.devices:
        if is_public(d.ip):
            seen.setdefault(d.ip, f"device {d.instance} answered from {d.address_key}")
    for b in result.bbmds:
        if is_public(b.ip):
            seen.setdefault(b.ip, f"BBMD probe target {b.ip}:{b.port}")
        for e in b.bdt or []:
            if is_public(e.ip):
                seen.setdefault(e.ip, f"BDT of {b.ip}:{b.port} lists {e.ip}:{e.port}")
        for f in b.fdt or []:
            if is_public(f.ip):
                seen.setdefault(f.ip, f"FDT of {b.ip}:{b.port} has foreign device {f.ip}:{f.port}")
    if not seen:
        return []
    return [make_finding("SEC-004", "public addresses", addresses=", ".join(sorted(seen)),
                         evidence=[_ev(v, kind="table") for _, v in sorted(seen.items())])]


# ---------------------------------------------------------------------------------------------------------------------
# BBMD
# ---------------------------------------------------------------------------------------------------------------------


def _peers(b: Bbmd) -> set[tuple[str, int]]:
    return {(e.ip, e.port) for e in b.bdt or []} - {(b.ip, b.port)}


def _bbmd(result: Result, is_public: Any, audited: bool) -> list[Finding]:
    out: list[Finding] = []
    topo = result.topology if isinstance(result.topology, dict) else {}
    local = topo.get("local_subnet")
    bbmds = [b for b in result.bbmds if b.status == "bbmd"]
    known = {(b.ip, b.port): b for b in bbmds if b.bdt is not None}
    dup_bcast = any(f.id == "BCAST-006" for f in result.findings)

    # BBMD-001: >= 2 BBMDs (found on this subnet, not via follow-bdt) in one subnet with overlapping peers
    groups: dict[str, list[Bbmd]] = defaultdict(list)
    for b in bbmds:
        if b.source != "bdt-peer":
            groups[subnet_of(b.ip, None, local)].append(b)
    for subnet, bs in sorted(groups.items()):
        if len(bs) < 2:
            continue
        overlapping = set()
        for i, a in enumerate(bs):
            for c in bs[i + 1:]:
                if (bdt_lists(a.bdt, c.ip, c.port) or bdt_lists(c.bdt, a.ip, a.port)
                        or (_peers(a) & _peers(c))):
                    overlapping |= {_addr(a.ip, a.port), _addr(c.ip, c.port)}
        if len(overlapping) < 2:
            continue
        ev = [_ev(f"Read-BDT-Ack from {_addr(b.ip, b.port)}: {len(b.bdt or [])} entries "
                  f"({', '.join(_addr(e.ip, e.port) for e in b.bdt or [])})", kind="table") for b in bs]
        if dup_bcast:
            ev.append(_ev("Duplicate forwarded broadcasts were also observed (BCAST-006).", kind="note"))
        out.append(make_finding("BBMD-001", subnet, severity=Severity.CRITICAL if dup_bcast else None, evidence=ev,
                                subnet=subnet, count=len(overlapping), bbmds=", ".join(sorted(overlapping))))

    for a in sorted(known.values(), key=lambda x: (x.ip, x.port)):
        aa = _addr(a.ip, a.port)
        # BBMD-002: asymmetric tables (both tables known)
        for e in a.bdt or []:
            if (e.ip, e.port) == (a.ip, a.port):
                continue
            b = known.get((e.ip, e.port))
            if b is not None and not bdt_lists(b.bdt, a.ip, a.port):
                ba = _addr(b.ip, b.port)
                out.append(make_finding(
                    "BBMD-002", f"{aa} -> {ba}", a=aa, b=ba,
                    evidence=[_ev(f"BDT of {aa} lists {ba} (mask {e.mask})", kind="table"),
                              _ev(f"BDT of {ba}: {', '.join(_addr(x.ip, x.port) for x in b.bdt or []) or 'empty'}",
                                  kind="table")]))
        # BBMD-003: own entry missing
        if a.bdt and not bdt_lists(a.bdt, a.ip, a.port):
            ev = [_ev(f"BDT of {aa}: {', '.join(_addr(x.ip, x.port) for x in a.bdt)}", kind="table")]
            nat = [x for x in a.bdt if x.port == a.port and is_public(x.ip)]
            if nat:
                ev.append(_ev(f"Entry {_addr(nat[0].ip, nat[0].port)} may be this BBMD's public (NAT) address; "
                              "if so this is expected.", kind="note"))
            out.append(make_finding("BBMD-003", aa, bbmd=aa, evidence=ev))
        # BBMD-004: mixed masks
        masks = {(e.ip, e.port): e.mask for e in a.bdt or [] if (e.ip, e.port) != (a.ip, a.port)}
        one = sorted(_addr(*k) for k, m in masks.items() if m == ALL_ONES)
        two = sorted(f"{_addr(*k)} ({m})" for k, m in masks.items() if m != ALL_ONES)
        if one and two:
            out.append(make_finding("BBMD-004", aa, bbmd=aa,
                                    detail=f"one-hop to {', '.join(one)}; two-hop to {', '.join(two)}",
                                    evidence=[_ev(f"BDT of {aa}: " + "; ".join(
                                        f"{_addr(e.ip, e.port)} mask {e.mask}" for e in a.bdt or []), kind="table")]))

    # BBMD-005: simulated distribution (§3.5)
    for origin, copies in sorted((topo.get("broadcast_matrix") or {}).items()):
        bad = {s: n for s, n in copies.items() if n != 1}
        if not bad:
            continue
        parts = [f"{s} {n} times" if n > 1 else f"{s} not at all" for s, n in sorted(bad.items())]
        sev = Severity.HIGH if any(n > 1 for n in bad.values()) else Severity.MEDIUM
        out.append(make_finding("BBMD-005", origin, severity=sev, origin=origin, detail="; ".join(parts),
                                evidence=[_ev(f"simulated copies of one broadcast from {origin}: "
                                              + ", ".join(f"{s}={n}" for s, n in sorted(copies.items())),
                                              kind="table")]))

    for b in bbmds:
        ba = _addr(b.ip, b.port)
        for f in b.fdt or []:
            if is_public(f.ip):  # BBMD-006
                out.append(make_finding("BBMD-006", f"{ba} FDT {f.ip}:{f.port}", bbmd=ba, address=f"{f.ip}:{f.port}",
                                        evidence=[_ev(f"Read-FDT-Ack from {ba}: {f.ip}:{f.port} TTL {f.ttl} s, "
                                                      f"{f.remaining} s remaining", kind="table")]))
        long = [f for f in b.fdt or [] if f.ttl > th("fdt_ttl_max_s")]
        if long:  # BBMD-007
            out.append(make_finding("BBMD-007", ba, bbmd=ba, thresholds=used("fdt_ttl_max_s"),
                                    detail="above " + str(th("fdt_ttl_max_s")) + " s ("
                                    + ", ".join(f"{f.ip}:{f.port} {f.ttl} s" for f in long) + ")",
                                    evidence=[_ev(f"FDT entry {f.ip}:{f.port} TTL {f.ttl} s", kind="table")
                                              for f in long]))

    if audited:  # BBMD-008
        names = ", ".join(f"{_addr(b.ip, b.port)} ({b.source})" for b in bbmds) or "none"
        ev = [_ev(f"{_addr(b.ip, b.port)}: {b.status} (found by {b.source})"
                  + (f", FDT {b.fdt_status}" if b.fdt_status else ""), kind="table") for b in result.bbmds]
        out.append(make_finding("BBMD-008", "BBMDs", count=len(bbmds), bbmds=names, evidence=ev,
                                confidence=Confidence.OBSERVED))
    return out
