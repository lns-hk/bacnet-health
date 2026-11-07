"""``analyze``: passive analysis of a pcap/pcapng file into a :class:`Result`."""

from __future__ import annotations

import os
from typing import Callable, Iterable

from bacnet_health.analysis.passive import PassiveAnalyzer, PassiveState, infer_vantage
from bacnet_health.capture.link import UdpExtractor
from bacnet_health.capture.pcap import iter_packets, sha256_file
from bacnet_health.findings.passive import build_metrics, evaluate_passive, performed_checks
from bacnet_health.model import Bbmd, InputFile, Result, RunInfo, Vantage, utcnow_iso
from bacnet_health.wire.message import decode_message, looks_like_bacnet

ProgressCb = Callable[[dict], None]


def bbmds_from_state(s: PassiveState) -> list[Bbmd]:
    out = []
    for (ip, port), why in sorted(s.bbmd_candidates.items()):
        bdt = s.bdt_seen.get((ip, port))
        fdt = s.fdt_seen.get((ip, port))
        out.append(Bbmd(ip=ip, port=port, status="bbmd" if bdt is not None else "candidate", source="passive",
                        bdt=bdt, fdt=fdt, fdt_status="ack" if fdt is not None else None))
    return out


def build_passive_result(
    state: PassiveState,
    run: RunInfo,
    vantage: Vantage,
    known_writers: Iterable[str] = (),
) -> Result:
    findings, skipped = evaluate_passive(state, vantage, known_writers)
    metrics = build_metrics(state)
    metrics["checks_performed"] = performed_checks(skipped)
    res = Result(run=run, devices=sorted(state.devices.values(), key=lambda d: (d.instance, d.address_key)),
                 bbmds=bbmds_from_state(state), metrics=metrics, findings=findings, checks_not_performed=skipped)
    res.limitations.append(
        "Passive analysis only sees what reached the capture point. "
        + {"self": "Listening on the tool's own UDP port shows broadcasts and traffic addressed to the tool only.",
           "access": "A normal switch port shows broadcasts and the capturing host's own traffic only.",
           "span": "A SPAN/mirror port shows the traffic the switch mirrors; check that all relevant ports were "
                   "mirrored."}[vantage.value]
    )
    return res


def analyze_file(
    path: str,
    vantage_override: Vantage | None = None,
    known_writers: Iterable[str] = (),
    progress: ProgressCb | None = None,
) -> Result:
    run = RunInfo(kind="analyze", command=f"analyze {os.path.basename(path)}")
    analyzer = PassiveAnalyzer()
    extractor = UdpExtractor()
    reader = iter_packets(path)
    n = 0
    for pkt in reader:
        n += 1
        for udp in extractor.feed(pkt):
            if looks_like_bacnet(udp.payload):
                analyzer.feed(udp, decode_message(udp.payload))
        if progress and n % 50000 == 0:
            progress({"type": "frames", "frames": n})
    extractor.finish()
    state = analyzer.finish()
    inferred, why = infer_vantage(state)
    vantage = vantage_override or Vantage(inferred)
    run.vantage = vantage
    run.vantage_source = "user" if vantage_override else "inferred"
    res = build_passive_result(state, run, vantage, known_writers)
    res.inputs.append(InputFile(path=path, sha256=sha256_file(path), size=os.path.getsize(path), frames=n))
    res.metrics["vantage_reason"] = why if not vantage_override else f"set by user (inferred: {inferred}, {why})"
    res.metrics["frames_total"] = n
    res.metrics["link_stats"] = dict(extractor.stats)
    for w in getattr(reader, "warnings", []):
        res.limitations.append(f"Capture file: {w}")
    run.finished = utcnow_iso()
    return res
