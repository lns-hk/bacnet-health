"""Evaluate passive findings (design §4) from a :class:`PassiveState`.

Findings whose required vantage is higher than the capture's vantage are not raised; they are listed in
``checks_not_performed`` so an absent finding is never mistaken for a healthy network (design §1.3).
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable

from bacnet_health.analysis.passive import PassiveState
from bacnet_health.findings.catalogue import CATALOGUE, make_finding, not_performed
from bacnet_health.findings.thresholds import th, used
from bacnet_health.model import Confidence, Evidence, Finding, Severity, Vantage

PASSIVE_IDS = [s.id for s in CATALOGUE.values() if s.passive]


def _window_peak(per_sec: Counter, window: int) -> tuple[float, float]:
    """(peak average over any `window`-second window, overall average) in events/second."""
    if not per_sec:
        return 0.0, 0.0
    lo, hi = min(per_sec), max(per_sec)
    span = hi - lo + 1
    total = sum(per_sec.values())
    w = max(1, min(window, span))
    run = sum(per_sec.get(t, 0) for t in range(lo, lo + w))
    peak = run
    for t in range(lo + w, hi + 1):
        run += per_sec.get(t, 0) - per_sec.get(t - w, 0)
        peak = max(peak, run)
    return peak / w, total / span


def _ev(detail: str, ts: float | None = None, frame: int | None = None) -> Evidence:
    return Evidence(kind="frame" if frame else "metric", detail=detail, ts=ts, ref=f"frame {frame}" if frame else None)


def _top(counter: Counter, n: int = 5) -> str:
    return ", ".join(f"{k} ({v})" for k, v in counter.most_common(n)) or "none"


def build_metrics(state: PassiveState) -> dict[str, Any]:
    s = state
    peak, avg = _window_peak(s.bcast_per_sec, int(th("bcast_window_s")))
    series: list[list[float]] = []
    if s.bcast_per_sec:
        lo, hi = min(s.bcast_per_sec), max(s.bcast_per_sec)
        step = max(1, (hi - lo + 1) // 600)
        for t in range(lo, hi + 1, step):
            n = sum(s.bcast_per_sec.get(t + i, 0) for i in range(step))
            series.append([t - lo, n / step])
    answered = sum(1 for t in s.txns if t.response)
    return {
        "duration_s": round(s.duration, 3),
        "frames_total": s.frames,
        "bacnet_messages": s.bacnet_frames,
        "own_frames_excluded": s.own_frames,
        "broadcast_total": sum(s.bcast_per_sec.values()),
        "broadcast_peak_pps": round(peak, 2),
        "broadcast_mean_pps": round(avg, 2),
        "broadcast_threshold_pps": th("bcast_rate_medium_pps"),
        "broadcast_timeseries": series,
        "top_broadcast_sources": [{"source": k, "count": v} for k, v in s.bcast_sources.most_common(10)],
        "service_counts": dict(s.kinds.most_common()),
        "whois_total": s.whois_total,
        "whois_global": s.whois_global,
        "whois_sources": dict(s.whois_sources.most_common(20)),
        "iam_total": sum(s.iam_per_sec.values()),
        "confirmed_requests": len(s.txns),
        "confirmed_answered": answered,
        "unmatched_responses": s.unmatched_responses,
        "decode_errors": dict(s.decode_errors),
        "duplicate_broadcasts": len(s.dup_broadcasts),
        "writes_seen": len(s.writes),
        "device_control_seen": len(s.controls),
    }


def evaluate_passive(
    state: PassiveState, vantage: Vantage, known_writers: Iterable[str] = ()
) -> tuple[list[Finding], list[dict[str, str]]]:
    s = state
    known = set(known_writers)
    out: list[Finding] = []
    skipped: list[dict[str, str]] = []

    def allowed(fid: str) -> bool:
        need = CATALOGUE[fid].vantage
        if vantage.satisfies(need):
            return True
        skipped.append(not_performed(
            fid, f"Needs a capture from a SPAN/mirror port (vantage '{need.value}'); this capture's vantage is "
                 f"'{vantage.value}'. Device-to-device traffic is not visible from here."))
        return False

    # ---------------- DEV ----------------
    by_instance: dict[int, list] = defaultdict(list)
    by_addr: dict[str, list] = defaultdict(list)
    for d in s.devices.values():
        by_instance[d.instance].append(d)
        if not d.remote:
            by_addr[d.address_key].append(d)
    if allowed("DEV-001"):
        for inst, devs in sorted(by_instance.items()):
            addrs = sorted({d.address_key for d in devs})
            if len(addrs) > 1:
                out.append(make_finding(
                    "DEV-001", f"device {inst}", instance=inst, addresses=", ".join(addrs),
                    evidence=[_ev(f"I-Am for instance {inst} from {d.address_key} (vendor {d.vendor_id}, "
                                  f"{d.iam_count} I-Am)", d.first_seen) for d in devs],
                ))
    if allowed("DEV-002"):
        for addr, devs in sorted(by_addr.items()):
            insts = sorted({d.instance for d in devs})
            if len(insts) > 1:
                out.append(make_finding(
                    "DEV-002", addr, address=addr, count=len(insts), instances=", ".join(map(str, insts)),
                    evidence=[_ev(f"I-Am for instance {d.instance} from {addr}", d.first_seen) for d in devs],
                ))
    if allowed("DEV-003"):
        for port, addrs in sorted(s.device_ports.items()):
            if port != th("standard_port"):
                out.append(make_finding(
                    "DEV-003", f"UDP {port}", port=port, addresses=", ".join(sorted(addrs)[:10]),
                    thresholds=used("standard_port"),
                    evidence=[_ev(f"device address {a}") for a in sorted(addrs)[:20]],
                ))
    if allowed("DEV-008") and s.devices:
        local = sum(1 for d in s.devices.values() if not d.remote)
        out.append(make_finding("DEV-008", "inventory", count=len(s.devices), local=local,
                                remote=len(s.devices) - local))

    # ---------------- BCAST ----------------
    win = int(th("bcast_window_s"))
    peak, avg = _window_peak(s.bcast_per_sec, win)
    if allowed("BCAST-001") and peak > th("bcast_rate_medium_pps"):
        sev = Severity.HIGH if peak > th("bcast_rate_high_pps") else Severity.MEDIUM
        out.append(make_finding(
            "BCAST-001", "subnet broadcast rate", severity=sev, peak=peak, avg=avg, window=win,
            thresholds=used("bcast_rate_medium_pps", "bcast_rate_high_pps", "bcast_window_s"),
            evidence=[_ev(f"top source {k}: {v} broadcasts") for k, v in s.bcast_sources.most_common(5)],
        ))
    w10 = int(th("whois_storm_window_s"))
    wpeak, _ = _window_peak(s.whois_per_sec, w10)
    if allowed("BCAST-002"):
        storm = wpeak > th("whois_storm_pps")
        busy = [ip for ip, n in s.whois_global_sources.items()
                if s.duration >= 60 and n / max(s.duration, 1) * 10 > th("global_whois_per_source_per_10s")]
        if storm or busy:
            out.append(make_finding(
                "BCAST-002", "Who-Is traffic", count=s.whois_total, window=w10, peak=wpeak,
                sources=_top(s.whois_sources),
                thresholds=used("whois_storm_pps", "whois_storm_window_s", "global_whois_per_source_per_10s"),
                evidence=[_ev(f"{ip}: {n} Who-Is ({s.whois_global_sources.get(ip, 0)} global)")
                          for ip, n in s.whois_sources.most_common(5)],
            ))
    if allowed("BCAST-003"):
        ipeak, _ = _window_peak(s.iam_per_sec, w10)
        chatty = {}
        if s.duration >= 300:
            for inst, times in s.iam_unsolicited.items():
                rate = len(times) / (s.duration / 60)
                if rate > th("iam_reannounce_per_min"):
                    chatty[inst] = rate
        if ipeak > th("iam_storm_pps") or chatty:
            parts = []
            if ipeak > th("iam_storm_pps"):
                parts.append(f"I-Am traffic peaked at {ipeak:.1f} messages per second")
            if chatty:
                parts.append(f"{len(chatty)} device(s) announced themselves more than "
                             f"{th('iam_reannounce_per_min')} time(s) per minute without being asked")
            out.append(make_finding(
                "BCAST-003", "I-Am traffic", detail="; ".join(parts).capitalize(),
                thresholds=used("iam_storm_pps", "iam_reannounce_per_min"),
                evidence=[_ev(f"device {i}: {r:.1f} I-Am per minute") for i, r in
                          sorted(chatty.items(), key=lambda x: -x[1])[:10]],
            ))
    if allowed("BCAST-004") and s.whois_total and s.duration > 0:
        per_hour = s.whois_total / (s.duration / 3600)
        ratio = s.whois_global / s.whois_total
        if ratio > th("global_whois_ratio") and per_hour >= th("global_whois_min_per_hour"):
            out.append(make_finding(
                "BCAST-004", "Who-Is traffic", pct=ratio * 100, global_count=s.whois_global, total=s.whois_total,
                sources=_top(s.whois_global_sources), thresholds=used("global_whois_ratio", "global_whois_min_per_hour"),
            ))
    if allowed("BCAST-005") and s.bcast_sources:
        out.append(make_finding("BCAST-005", "broadcast sources", sources=_top(s.bcast_sources, 10)))
    if allowed("BCAST-006") and s.dup_broadcasts:
        n = len(s.dup_broadcasts)
        rate = n / max(s.duration, 1.0)
        ex = s.dup_broadcasts[0]
        out.append(make_finding(
            "BCAST-006", "broadcast forwarding",
            severity=Severity.CRITICAL if rate > th("dup_forward_critical_per_s") else Severity.HIGH,
            count=n, window_ms=int(th("dup_forward_window_s") * 1000),
            example=f"{ex['origin']} via {' and '.join(ex['via'])}",
            thresholds=used("dup_forward_window_s", "dup_forward_critical_per_s"),
            evidence=[_ev(f"{d['kind']} from {d['origin']} delivered via {', '.join(d['via'])} "
                          f"(first copy frame {d['first_frame']})", d["ts"], d["frame"]) for d in s.dup_broadcasts[:10]],
        ))

    # ---------------- COMM ----------------
    end = s.last_ts or 0.0
    timeout = th("unanswered_timeout_s")
    per_server: dict[str, dict[str, Any]] = defaultdict(lambda: {"total": 0, "bad": 0, "unanswered": 0,
                                                                  "reasons": Counter(), "ev": []})
    seg_aborts: Counter = Counter()
    retrans = []
    for t in s.txns:
        key = f"{t.server[0]}:{t.server[1]}"
        st = per_server[key]
        if t.response is None and end - t.ts < timeout:
            continue  # too close to the end of the capture to judge
        st["total"] += 1
        if t.response in ("reject", "abort"):
            st["bad"] += 1
            st["reasons"][f"{t.response}: {t.reason}"] += 1
            if len(st["ev"]) < 5:
                st["ev"].append(_ev(f"{t.service} from {t.client[0]} -> {t.response} ({t.reason})", t.ts, t.frame_no))
            if t.response == "abort" and t.reason in ("segmentation-not-supported", "buffer-overflow"):
                seg_aborts[t.reason] += 1
        elif t.response is None:
            st["unanswered"] += 1
        if t.retransmits:
            retrans.append(t)
    if allowed("COMM-001"):
        for srv, st in sorted(per_server.items()):
            if st["total"] >= th("error_min_requests") and st["bad"] / st["total"] > th("error_ratio"):
                out.append(make_finding(
                    "COMM-001", srv, bad=st["bad"], total=st["total"], pct=100 * st["bad"] / st["total"],
                    thresholds=used("error_ratio", "error_min_requests"),
                    evidence=st["ev"] + [_ev(f"{r}: {n}") for r, n in st["reasons"].most_common(5)],
                ))
    if allowed("COMM-002"):
        for srv, st in sorted(per_server.items()):
            if st["total"] >= th("unanswered_min_requests"):
                ratio = st["unanswered"] / st["total"]
                if ratio > th("unanswered_ratio_medium"):
                    out.append(make_finding(
                        "COMM-002", srv,
                        severity=Severity.HIGH if ratio > th("unanswered_ratio_high") else Severity.MEDIUM,
                        unanswered=st["unanswered"], total=st["total"], pct=100 * ratio, timeout=timeout,
                        thresholds=used("unanswered_ratio_medium", "unanswered_ratio_high", "unanswered_timeout_s",
                                        "unanswered_min_requests"),
                    ))
    if allowed("COMM-003") and retrans:
        top = Counter(f"{t.client[0]} -> {t.server[0]}" for t in retrans)
        out.append(make_finding(
            "COMM-003", "retransmissions", count=sum(t.retransmits for t in retrans), examples=_top(top, 3),
            evidence=[_ev(f"{t.service} {t.client[0]} -> {t.server[0]} invoke {t.invoke_id} sent "
                          f"{t.retransmits + 1} times", t.ts, t.frame_no) for t in retrans[:10]],
        ))
    if allowed("COMM-004") and seg_aborts:
        out.append(make_finding("COMM-004", "segmentation", count=sum(seg_aborts.values()),
                                reasons=", ".join(f"{k} ({v})" for k, v in seg_aborts.items())))
    if allowed("COMM-005") and s.reject_to_network:
        reasons = Counter(str(r.get("reason")) for r in s.reject_to_network)
        out.append(make_finding(
            "COMM-005", "routers", count=len(s.reject_to_network), reasons=_top(reasons),
            evidence=[_ev(f"from {r['src']}: reason {r.get('reason')} for network {r.get('network')}", r["ts"],
                          r["frame"]) for r in s.reject_to_network[:10]],
        ))
    if allowed("COMM-006"):
        for net, routers in sorted(s.router_networks.items()):
            if len(routers) > 1:
                out.append(make_finding("COMM-006", f"network {net}", network=net, routers=", ".join(sorted(routers)),
                                        evidence=[_ev(f"I-Am-Router-To-Network {net} from {r}") for r in sorted(routers)]))
    if allowed("COMM-007") and s.low_hop:
        out.append(make_finding("COMM-007", "routing", count=len(s.low_hop),
                                evidence=[_ev(f"from {h['src']} hop count {h['hop']}", h["ts"], h["frame"])
                                          for h in s.low_hop[:10]]))

    # ---------------- SEC ----------------
    if allowed("SEC-001") and s.controls:
        unknown = [c for c in s.controls if c["src"] not in known]
        sev = Severity.CRITICAL if unknown else Severity.MEDIUM
        out.append(make_finding(
            "SEC-001", "device control", severity=sev, count=len(s.controls),
            services=", ".join(sorted({c["service"] or c["kind"] for c in s.controls})),
            sources=", ".join(sorted({c["src"] for c in s.controls})),
            evidence=[_ev(f"{c['service'] or c['kind']} {c['src']} -> {c['dst']} {c['detail'] or ''}".strip(), c["ts"],
                          c["frame"]) for c in s.controls[:20]],
        ))
    if s.writes:
        by_src: dict[str, list] = defaultdict(list)
        for w in s.writes:
            by_src[w["src"]].append(w)
        if allowed("SEC-002"):
            for src, ws in sorted(by_src.items()):
                if src in known:
                    continue
                out.append(make_finding(
                    "SEC-002", src, source=src, count=len(ws),
                    services=", ".join(sorted({w["service"] or w["kind"] for w in ws})),
                    targets=len({w["dst"] for w in ws}),
                    evidence=[_ev(f"{w['service'] or w['kind']} -> {w['dst']} {w['detail'] or ''}".strip(), w["ts"],
                                  w["frame"]) for w in ws[:10]],
                ))
        if allowed("SEC-003"):
            out.append(make_finding(
                "SEC-003", "write activity", count=len(s.writes), writers=len(by_src),
                evidence=[_ev(f"{src}: {len(ws)} writes to {len({w['dst'] for w in ws})} device(s)"
                              f"{' (known workstation)' if src in known else ''}") for src, ws in sorted(by_src.items())],
            ))
    else:
        for fid in ("SEC-002", "SEC-003"):
            allowed(fid)
    if allowed("SEC-004") and s.public_addrs:
        out.append(make_finding(
            "SEC-004", "public addresses", addresses=_top(s.public_addrs, 10),
            evidence=[_ev(f"{ip}: {n} BACnet messages") for ip, n in s.public_addrs.most_common(10)],
        ))

    # ---------------- BBMD (passive view) ----------------
    if allowed("BBMD-008") and s.bbmd_candidates:
        out.append(make_finding(
            "BBMD-008", "BBMDs", count=len(s.bbmd_candidates),
            bbmds=", ".join(f"{ip}:{port}" for ip, port in sorted(s.bbmd_candidates)),
            confidence=Confidence.INFERRED if not s.bdt_seen else Confidence.OBSERVED,
            evidence=[_ev(f"{ip}:{port} {why}") for (ip, port), why in sorted(s.bbmd_candidates.items())],
        ))

    out.sort(key=lambda f: (f.severity.rank, f.id, f.subject))
    return out, skipped


def performed_checks(skipped: list[dict[str, str]]) -> list[str]:
    """Passive check IDs that were evaluated, given the skipped list returned by evaluate_passive."""
    skip = {x["id"] for x in skipped}
    return [fid for fid in PASSIVE_IDS if fid not in skip]
