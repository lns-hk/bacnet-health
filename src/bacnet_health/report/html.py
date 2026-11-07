"""Self-contained, print-ready HTML report.

The output is one HTML file with inline CSS, inline SVG charts, the logo as a base64 data URI and an optional tiny
script for table sorting. It makes no network requests and is fully readable with JavaScript disabled. Every value
taken from a Result is HTML-escaped: device strings (object-name, location, ...) are untrusted input.

Section ids (stable, used for links and tests): ``cover``, ``summary``, ``changes`` (only with a diff), ``scope``,
``findings``, ``not-performed``, ``inventory``, ``topology``, ``methodology``, ``appendix``.

Metric keys consumed from ``Result.metrics`` (all optional; missing or malformed values are skipped):

``broadcast_timeseries``
    list of ``[t_offset_s, pkts_per_s]`` pairs (dicts ``{"t": .., "pps": ..}`` are also accepted). BACnet broadcast
    rate over the capture, drawn as a line chart.
``broadcast_threshold_pps``
    number; the threshold line drawn on the broadcast chart. Defaults to the ``bcast_rate_medium_pps`` threshold.
``top_broadcast_sources``
    list of ``{"source": str, "count": int}`` (pairs or a ``{source: count}`` dict are also accepted).
``service_counts``
    ``{service_name: count}``; BACnet messages by service/kind.
``duration_s``, ``frames_total``, ``bacnet_messages``, ``broadcast_total``, ``broadcast_peak_pps``,
``broadcast_mean_pps``, ``decode_errors``
    scalar key figures shown in the appendix (``decode_errors`` may also be a ``{layer: count}`` dict).
``checks_performed``
    list of check ids (used by ``merge_results``; listed in the appendix raw metrics only).

Topology keys consumed from ``Result.topology`` (optional): ``broadcast_copies`` = ``{subnet: copies}``, the
simulated number of copies of a broadcast originating in each subnet (design §3.5).
"""

from __future__ import annotations

import html
import json
import math
import re
from datetime import datetime, timezone
from typing import Any, Iterable

from bacnet_health import __version__
from bacnet_health.model import Bbmd, Confidence, Device, Finding, Result, Severity, Vantage
from bacnet_health.report.branding import Branding

# --------------------------------------------------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------------------------------------------------

DASH = "—"

SEV_LABEL = {
    Severity.CRITICAL: "Critical",
    Severity.HIGH: "High",
    Severity.MEDIUM: "Medium",
    Severity.LOW: "Low",
    Severity.INFO: "Info",
}

SEV_MEANING = {
    Severity.CRITICAL: "Observed, with a direct security exposure or a control disruption happening during the capture.",
    Severity.HIGH: "Likely to affect control or security now.",
    Severity.MEDIUM: "Degrades reliability or maintainability.",
    Severity.LOW: "Hygiene: worth fixing during normal maintenance.",
    Severity.INFO: "Inventory facts and context; no action required.",
}

VANTAGE_TEXT = {
    Vantage.SELF: "Self (the tool's own UDP socket). Sees broadcasts on the local subnet and traffic addressed to the "
    "tool. Device-to-device unicast traffic is not visible.",
    Vantage.ACCESS: "Access port (capture on a normal switch port). Sees broadcasts on the local subnet. "
    "Device-to-device unicast traffic is not visible.",
    Vantage.SPAN: "SPAN / mirror port or inline tap. Sees all traffic the mirror delivers, including "
    "device-to-device unicast.",
}

VANTAGE_SOURCE_TEXT = {
    "inferred": "inferred by the tool from the capture content",
    "user": "set by the operator",
    "listen": "listen mode (the tool's own socket)",
}

KEY_FIGURES = (
    ("duration_s", "Observation duration", "s"),
    ("frames_total", "Frames read", ""),
    ("bacnet_messages", "BACnet messages", ""),
    ("broadcast_total", "BACnet broadcasts", ""),
    ("broadcast_peak_pps", "Peak broadcast rate", "pkt/s"),
    ("broadcast_mean_pps", "Mean broadcast rate", "pkt/s"),
    ("decode_errors", "Frames that failed to decode", ""),
)

MAX_EVIDENCE_ROWS = 50
MAX_TOPOLOGY_NODES = 16
MAX_FD_PER_BBMD = 6


def esc(v: Any) -> str:
    return html.escape("" if v is None else str(v), quote=True)


def val(v: Any) -> str:
    """Escaped value, or an em dash for empty."""
    if v is None or v == "" or v == [] or v == {}:
        return DASH
    if isinstance(v, (list, tuple)):
        return esc(", ".join(str(x) for x in v))
    if isinstance(v, dict):
        return esc(json.dumps(v, ensure_ascii=False, sort_keys=True))
    if isinstance(v, bool):
        return "Yes" if v else "No"
    if isinstance(v, (int, float)):
        return esc(num(v))
    return esc(v)


def num(v: Any) -> str:
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int):
        return f"{v:,}"
    if isinstance(v, float):
        if not math.isfinite(v):
            return str(v)
        if v == int(v) and abs(v) < 1e12:
            return f"{int(v):,}"
        return f"{v:,.2f}".rstrip("0").rstrip(".")
    return str(v)


def is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v)


def plural(n: int, word: str, pl: str | None = None) -> str:
    return f"{n} {word if n == 1 else (pl or word + 's')}"


def parse_iso(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def fmt_iso(s: str | None, with_time: bool = True) -> str:
    d = parse_iso(s)
    if d is None:
        return esc(s) if s else DASH
    d = d.astimezone(timezone.utc)
    if not with_time:
        return f"{d.day} {d:%B %Y}"
    return f"{d.day} {d:%B %Y}, {d:%H:%M:%S} UTC"


def fmt_epoch(ts: float | None) -> str:
    if not is_num(ts):
        return DASH
    try:
        d = datetime.fromtimestamp(float(ts), tz=timezone.utc)  # type: ignore[arg-type]
    except (OverflowError, OSError, ValueError):
        return esc(ts)
    return d.strftime("%Y-%m-%d %H:%M:%S.") + f"{d.microsecond // 1000:03d}Z"


def duration_text(a: str | None, b: str | None) -> str:
    da, db = parse_iso(a), parse_iso(b)
    if da is None or db is None:
        return DASH
    secs = int((db - da).total_seconds())
    if secs < 0:
        return DASH
    h, rem = divmod(secs, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} h {m:02d} min"
    if m:
        return f"{m} min {s:02d} s"
    return f"{s} s"


def first_sentence(text: str) -> str:
    text = " ".join(str(text or "").split())
    m = re.search(r"(?<=[.!?])\s", text)
    return text[: m.start()] if m else text


def dprop(d: Device, name: str) -> Any:
    if name in d.properties:
        return d.properties[name]
    return d.properties.get(name.replace("-", "_"))


def sev_badge(s: Severity) -> str:
    return f'<span class="badge sev sev-{s.value}">{SEV_LABEL[s]}</span>'


def table(headers: Iterable[str], rows: Iterable[Iterable[str]], cls: str = "", sortable: bool = False) -> str:
    """Rows are lists of already-escaped HTML cell contents. A cell may be a (html, sort_value) tuple."""
    classes = " ".join(c for c in (cls, "sortable" if sortable else "") if c)
    out = [f'<table class="{classes}">' if classes else "<table>", "<thead><tr>"]
    out += [f'<th scope="col">{h}</th>' for h in headers]
    out.append("</tr></thead><tbody>")
    for row in rows:
        out.append("<tr>")
        for cell in row:
            if isinstance(cell, tuple):
                out.append(f'<td data-v="{esc(cell[1])}">{cell[0]}</td>')
            else:
                out.append(f"<td>{cell}</td>")
        out.append("</tr>")
    out.append("</tbody></table>")
    return "".join(out)


def kv_table(pairs: Iterable[tuple[str, str]]) -> str:
    rows = "".join(f'<tr><th scope="row">{esc(k)}</th><td>{v}</td></tr>' for k, v in pairs)
    return f'<table class="kv"><tbody>{rows}</tbody></table>'


# --------------------------------------------------------------------------------------------------------------------
# metric extraction (defensive)
# --------------------------------------------------------------------------------------------------------------------


def metric_timeseries(m: dict[str, Any]) -> list[tuple[float, float]]:
    raw = m.get("broadcast_timeseries")
    pts: list[tuple[float, float]] = []
    if not isinstance(raw, (list, tuple)):
        return pts
    for item in raw:
        t = v = None
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            t, v = item[0], item[1]
        elif isinstance(item, dict):
            t = item.get("t", item.get("ts"))
            v = item.get("pps", item.get("value"))
        if is_num(t) and is_num(v):
            pts.append((float(t), float(v)))
    pts.sort()
    return pts


def metric_top_sources(m: dict[str, Any]) -> list[tuple[str, float]]:
    raw = m.get("top_broadcast_sources")
    items: list[tuple[str, float]] = []
    if isinstance(raw, dict):
        raw = [{"source": k, "count": v} for k, v in raw.items()]
    if not isinstance(raw, (list, tuple)):
        return items
    for it in raw:
        if isinstance(it, dict):
            s, c = it.get("source"), it.get("count")
        elif isinstance(it, (list, tuple)) and len(it) >= 2:
            s, c = it[0], it[1]
        else:
            continue
        if s is not None and is_num(c):
            items.append((str(s), float(c)))
    items.sort(key=lambda x: -x[1])
    return items[:10]


def metric_service_counts(m: dict[str, Any]) -> list[tuple[str, float]]:
    raw = m.get("service_counts")
    if not isinstance(raw, dict):
        return []
    items = [(str(k), float(v)) for k, v in raw.items() if is_num(v)]
    items.sort(key=lambda x: (-x[1], x[0]))
    return items


def bcast_threshold(m: dict[str, Any]) -> float | None:
    t = m.get("broadcast_threshold_pps")
    if is_num(t):
        return float(t)
    try:
        from bacnet_health.findings.thresholds import THRESHOLDS

        v = THRESHOLDS["bcast_rate_medium_pps"][0]
        return float(v) if is_num(v) else None
    except Exception:  # noqa: BLE001 - optional dependency on another subsystem
        return None


# --------------------------------------------------------------------------------------------------------------------
# SVG charts
# --------------------------------------------------------------------------------------------------------------------


def nice_step(span: float, target: int = 4) -> float:
    if span <= 0:
        return 1.0
    raw = span / target
    mag = 10 ** math.floor(math.log10(raw))
    for f in (1, 2, 2.5, 5, 10):
        if f * mag >= raw:
            return f * mag
    return 10 * mag


def svg_severity_bar(counts: dict[str, int]) -> str:
    row_h, label_w, bar_w, w = 26, 78, 380, 520
    h = row_h * len(Severity) + 8
    mx = max(max(counts.values(), default=0), 1)
    parts = [
        f'<svg class="chart" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
        f'aria-label="Findings by severity">'
    ]
    for i, s in enumerate(Severity):
        y = 4 + i * row_h
        n = counts.get(s.value, 0)
        bw = 0 if n == 0 else max(3.0, bar_w * n / mx)
        parts.append(f'<text x="0" y="{y + 17}" class="ch-label">{SEV_LABEL[s]}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{bar_w}" height="16" class="ch-track" rx="2"/>')
        if bw:
            parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{bw:.1f}" height="16" class="fill-{s.value}" rx="2"/>')
        parts.append(f'<text x="{label_w + bar_w + 10}" y="{y + 17}" class="ch-value">{n}</text>')
    parts.append("</svg>")
    return "".join(parts)


def downsample(pts: list[tuple[float, float]], max_points: int = 600) -> list[tuple[float, float]]:
    """Reduce to at most max_points by taking the maximum of each bucket (keeps peaks visible)."""
    if len(pts) <= max_points:
        return pts
    size = math.ceil(len(pts) / max_points)
    out = []
    for i in range(0, len(pts), size):
        chunk = pts[i : i + size]
        peak = max(chunk, key=lambda p: p[1])
        out.append((chunk[0][0], peak[1]))
    return out


def svg_timeseries(pts: list[tuple[float, float]], threshold: float | None) -> str:
    w, h, ml, mr, mt, mb = 680, 250, 52, 16, 14, 40
    pw, ph = w - ml - mr, h - mt - mb
    pts = downsample(pts)
    t0, t1 = pts[0][0], pts[-1][0]
    if t1 <= t0:
        t1 = t0 + 1
    vmax = max(p[1] for p in pts)
    top = max(vmax, threshold or 0) * 1.12 or 1.0
    step = nice_step(top)
    top = math.ceil(top / step) * step

    def x(t: float) -> float:
        return ml + (t - t0) / (t1 - t0) * pw

    def y(v: float) -> float:
        return mt + ph - (v / top) * ph

    use_min = (t1 - t0) > 180
    parts = [
        f'<svg class="chart" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" '
        f'aria-label="BACnet broadcast rate over time">'
    ]
    v = 0.0
    while v <= top + 1e-9:
        yy = y(v)
        parts.append(f'<line x1="{ml}" x2="{ml + pw}" y1="{yy:.1f}" y2="{yy:.1f}" class="ch-grid"/>')
        parts.append(f'<text x="{ml - 6}" y="{yy + 4:.1f}" class="ch-tick" text-anchor="end">{esc(num(v))}</text>')
        v += step
    tstep = nice_step((t1 - t0) / (60 if use_min else 1), 6) * (60 if use_min else 1)
    t = math.ceil(t0 / tstep) * tstep
    while t <= t1 + 1e-9:
        xx = x(t)
        label = num(t / 60) + " min" if use_min else num(t) + " s"
        parts.append(f'<line x1="{xx:.1f}" x2="{xx:.1f}" y1="{mt + ph}" y2="{mt + ph + 4}" class="ch-axis"/>')
        parts.append(f'<text x="{xx:.1f}" y="{mt + ph + 17}" class="ch-tick" text-anchor="middle">{esc(label)}</text>')
        t += tstep
    parts.append(f'<line x1="{ml}" x2="{ml + pw}" y1="{mt + ph}" y2="{mt + ph}" class="ch-axis"/>')
    parts.append(f'<line x1="{ml}" x2="{ml}" y1="{mt}" y2="{mt + ph}" class="ch-axis"/>')
    if threshold is not None and threshold <= top:
        ty = y(threshold)
        parts.append(f'<line x1="{ml}" x2="{ml + pw}" y1="{ty:.1f}" y2="{ty:.1f}" class="ch-threshold"/>')
        parts.append(
            f'<text x="{ml + pw - 4}" y="{ty - 5:.1f}" class="ch-thlabel" text-anchor="end">'
            f"Threshold {esc(num(threshold))} pkt/s (provisional)</text>"
        )
    poly = " ".join(f"{x(a):.1f},{y(b):.1f}" for a, b in pts)
    if len(pts) == 1:
        parts.append(f'<circle cx="{x(pts[0][0]):.1f}" cy="{y(pts[0][1]):.1f}" r="3" class="ch-dot"/>')
    else:
        parts.append(f'<polyline points="{poly}" class="ch-line"/>')
    parts.append(
        f'<text x="{ml + pw / 2:.0f}" y="{h - 4}" class="ch-axislabel" text-anchor="middle">'
        f"Time from start of observation</text>"
    )
    parts.append(
        f'<text x="12" y="{mt + ph / 2:.0f}" class="ch-axislabel" text-anchor="middle" '
        f'transform="rotate(-90 12 {mt + ph / 2:.0f})">pkt/s</text>'
    )
    parts.append("</svg>")
    return "".join(parts)


def svg_hbars(items: list[tuple[str, float]], aria: str) -> str:
    row_h, label_w, bar_w = 24, 190, 360
    w = label_w + bar_w + 70
    h = row_h * len(items) + 6
    mx = max((c for _, c in items), default=1) or 1
    parts = [f'<svg class="chart" viewBox="0 0 {w} {h}" width="{w}" height="{h}" role="img" aria-label="{esc(aria)}">']
    for i, (label, c) in enumerate(items):
        y = 3 + i * row_h
        short = label if len(label) <= 30 else label[:29] + "…"
        parts.append(f'<text x="0" y="{y + 16}" class="ch-label mono">{esc(short)}</text>')
        parts.append(f'<rect x="{label_w}" y="{y + 4}" width="{bar_w}" height="15" class="ch-track" rx="2"/>')
        parts.append(
            f'<rect x="{label_w}" y="{y + 4}" width="{max(2.0, bar_w * c / mx):.1f}" height="15" class="ch-bar" rx="2"/>'
        )
        parts.append(f'<text x="{label_w + bar_w + 8}" y="{y + 16}" class="ch-value">{esc(num(c))}</text>')
    parts.append("</svg>")
    return "".join(parts)


def _trim(cx: float, cy: float, tx: float, ty: float, hw: float, hh: float) -> tuple[float, float]:
    """Point where the segment from (cx,cy) towards (tx,ty) leaves a rectangle of half-size hw x hh."""
    dx, dy = tx - cx, ty - cy
    if dx == 0 and dy == 0:
        return cx, cy
    t = min(hw / abs(dx) if dx else math.inf, hh / abs(dy) if dy else math.inf)
    return cx + dx * t, cy + dy * t


def svg_topology(bbmds: list[Bbmd]) -> str | None:
    """BBMDs (and BDT peers that were not read) as boxes, BDT entries as arrows, FDT entries as small boxes.

    Returns None when there is nothing to draw or too many nodes for a readable diagram (the tables still show all).
    """
    real = [b for b in bbmds if b.status == "bbmd" or b.bdt]
    if not real:
        return None
    nodes: dict[str, dict[str, Any]] = {}
    for b in real:
        nodes[f"{b.ip}:{b.port}"] = {"kind": "bbmd", "b": b}
    edges: dict[tuple[str, str], str] = {}
    for b in real:
        a = f"{b.ip}:{b.port}"
        for e in b.bdt or []:
            peer = f"{e.ip}:{e.port}"
            if peer == a:
                continue
            edges[(a, peer)] = e.mask
            if peer not in nodes:
                nodes[peer] = {"kind": "peer", "b": None}
    if len(nodes) > MAX_TOPOLOGY_NODES:
        return None

    keys = list(nodes)
    n = len(keys)
    nw, nh, fw, fh = 156, 42, 128, 24
    pos: dict[str, tuple[float, float]] = {}
    angle: dict[str, float] = {}
    if n == 1:
        pos[keys[0]] = (0.0, 0.0)
        angle[keys[0]] = -math.pi / 2
        radius = 0.0
    else:
        radius = max(150.0, n * 175 / (2 * math.pi))
        for i, k in enumerate(keys):
            a = -math.pi / 2 + 2 * math.pi * i / n
            angle[k] = a
            pos[k] = (radius * math.cos(a), radius * 0.72 * math.sin(a))

    fds: list[tuple[str, float, float, str, bool]] = []  # (owner, x, y, label, is_more)
    for k in keys:
        b = nodes[k]["b"]
        if b is None or not b.fdt:
            continue
        entries = b.fdt[:MAX_FD_PER_BBMD]
        labels = [f"{e.ip}:{e.port}" for e in entries]
        more = len(b.fdt) - len(entries)
        if more > 0:
            labels.append(f"+{more} more")
        cnt = len(labels)
        cx, cy = pos[k]
        a = angle[k] if n > 1 else math.pi / 2
        ca, sa = math.cos(a), math.sin(a)
        if abs(sa) >= 0.6:
            # node at the top or bottom: rows of up to three boxes, growing away from the centre
            per_row = 3
            sign = 1.0 if sa > 0 else -1.0
            for j, label in enumerate(labels):
                row, col = divmod(j, per_row)
                in_row = min(per_row, cnt - row * per_row)
                fx = cx + (col - (in_row - 1) / 2) * (fw + 12)
                fy = cy + sign * (nh / 2 + 34 + fh / 2 + row * (fh + 10))
                fds.append((k, fx, fy, label, label.startswith("+")))
        else:
            # node at a side: a vertical column beside it, away from the centre
            sign = 1.0 if ca > 0 else -1.0
            for j, label in enumerate(labels):
                fx = cx + sign * (nw / 2 + 40 + fw / 2)
                fy = cy + (j - (cnt - 1) / 2) * (fh + 8)
                fds.append((k, fx, fy, label, label.startswith("+")))

    xs = [p[0] for p in pos.values()] + [f[1] for f in fds]
    ys = [p[1] for p in pos.values()] + [f[2] for f in fds]
    pad_x, pad_y = nw / 2 + 12, nh / 2 + 12
    minx, maxx = min(xs) - pad_x, max(xs) + pad_x
    miny, maxy = min(ys) - pad_y, max(ys) + pad_y
    vw, vh = maxx - minx, maxy - miny

    parts = [
        f'<svg class="chart topo" viewBox="{minx:.0f} {miny:.0f} {vw:.0f} {vh:.0f}" width="{min(vw, 720):.0f}" '
        f'role="img" aria-label="BBMD topology diagram">',
        '<defs><marker id="tp-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" '
        'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" class="tp-arrowhead"/></marker></defs>',
    ]
    done: set[tuple[str, str]] = set()
    for (a, b2), mask in edges.items():
        if (a, b2) in done:
            continue
        back = (b2, a) in edges
        done.add((a, b2))
        done.add((b2, a))
        peer_read = nodes[b2]["kind"] == "bbmd"
        asym = peer_read and not back
        one_hop = mask == "255.255.255.255"
        cls = "tp-edge" + ("" if one_hop else " tp-twohop") + (" tp-asym" if asym else "")
        (ax, ay), (bx, by) = pos[a], pos[b2]
        x1, y1 = _trim(ax, ay, bx, by, nw / 2 + 2, nh / 2 + 2)
        x2, y2 = _trim(bx, by, ax, ay, nw / 2 + 2, nh / 2 + 2)
        start = ' marker-start="url(#tp-arrow)"' if back else ""
        parts.append(
            f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" class="{cls}"{start} '
            f'marker-end="url(#tp-arrow)"/>'
        )
    for owner, fx, fy, _label, _more in fds:
        ox, oy = pos[owner]
        x1, y1 = _trim(ox, oy, fx, fy, nw / 2, nh / 2)
        x2, y2 = _trim(fx, fy, ox, oy, fw / 2, fh / 2)
        parts.append(f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" class="tp-fdline"/>')
    for k in keys:
        cx, cy = pos[k]
        node = nodes[k]
        b = node["b"]
        if b is not None:
            sub = f"BBMD · BDT {len(b.bdt or [])} · FDT {len(b.fdt or [])}"
            cls = "tp-node"
        else:
            sub = "BDT peer (not read)"
            cls = "tp-node tp-peer"
        parts.append(
            f'<rect x="{cx - nw / 2:.1f}" y="{cy - nh / 2:.1f}" width="{nw}" height="{nh}" rx="5" class="{cls}"/>'
        )
        parts.append(f'<text x="{cx:.1f}" y="{cy - 3:.1f}" text-anchor="middle" class="tp-label mono">{esc(k)}</text>')
        parts.append(f'<text x="{cx:.1f}" y="{cy + 12:.1f}" text-anchor="middle" class="tp-sub">{esc(sub)}</text>')
    for _owner, fx, fy, label, more in fds:
        cls = "tp-fd tp-more" if more else "tp-fd"
        parts.append(
            f'<rect x="{fx - fw / 2:.1f}" y="{fy - fh / 2:.1f}" width="{fw}" height="{fh}" rx="12" class="{cls}"/>'
        )
        parts.append(f'<text x="{fx:.1f}" y="{fy + 4:.1f}" text-anchor="middle" class="tp-fdlabel mono">{esc(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


# --------------------------------------------------------------------------------------------------------------------
# sections
# --------------------------------------------------------------------------------------------------------------------


class _Ctx:
    def __init__(self, result: Result, branding: Branding, diff: dict[str, Any] | None):
        self.r = result
        self.b = branding
        self.diff = diff
        self.site = branding.site or result.run.site
        self.client = branding.client or result.run.client
        self.prepared_by = branding.prepared_by or result.run.prepared_by
        self.org = branding.org or result.run.org
        self.counts = result.severity_counts()
        self.findings = result.sorted_findings()
        self.metrics = result.metrics if isinstance(result.metrics, dict) else {}
        self.numbers: dict[str, int] = {}


def section_ids(diff: dict[str, Any] | None) -> list[tuple[str, str]]:
    s = [("summary", "Executive summary")]
    if diff is not None:
        s.append(("changes", "Changes since previous visit"))
    s += [
        ("scope", "Scope and rules of engagement"),
        ("findings", "Findings"),
        ("not-performed", "Checks not performed"),
        ("inventory", "Device inventory"),
        ("topology", "BBMDs and topology"),
        ("methodology", "Methodology and limitations"),
        ("appendix", "Appendix: reproducibility and raw metrics"),
    ]
    return s


def h2(c: _Ctx, sid: str, title: str) -> str:
    return f'<h2><span class="secno">{c.numbers[sid]}</span>{esc(title)}</h2>'


def render_cover(c: _Ctx, sections: list[tuple[str, str]]) -> str:
    run = c.r.run
    logo = c.b.logo_data_uri()
    logo_html = f'<img class="logo" src="{logo}" alt="{esc(c.org or "Logo")}">' if logo else ""
    org_html = f'<div class="cover-org">{esc(c.org)}</div>' if c.org else ""
    rows = [
        ("Site", val(c.site)),
        ("Client", val(c.client)),
        ("Prepared by", val(c.prepared_by)),
        ("Organisation", val(c.org)),
        ("Date of observation", fmt_iso(run.started, with_time=False)),
        ("Run type", esc(run.kind)),
        ("Tool", f"bacnet-health {esc(__version__)}"),
    ]
    toc = "".join(
        f'<li><a href="#{sid}"><span class="secno">{c.numbers[sid]}</span>{esc(t)}</a></li>' for sid, t in sections
    )
    pre = ""
    if is_prerelease(__version__):
        pre = f'<p class="cover-note">{esc(prerelease_statement(__version__))}</p>'
    incomplete = ""
    if run.incomplete:
        incomplete = '<p class="cover-note warn">This run was stopped before completion. Results are partial.</p>'
    return f"""
<section id="cover" class="cover">
  <div class="cover-band"></div>
  <div class="cover-head">{logo_html}{org_html}</div>
  <div class="cover-title">
    <div class="eyebrow">BACnet/IP network health check</div>
    <h1>{esc(c.site) if c.site else "Network health report"}</h1>
    <div class="cover-sub">{"Prepared for " + esc(c.client) if c.client else "Building-management network assessment"}</div>
  </div>
  {kv_table(rows)}
  {incomplete}{pre}
  <nav class="toc" aria-label="Contents"><div class="toc-title">Contents</div><ol>{toc}</ol></nav>
</section>"""


def condition_statement(c: _Ctx) -> str:
    k = c.counts
    nd = len(c.r.devices)
    nb = sum(1 for b in c.r.bbmds if b.status == "bbmd")
    if k["critical"]:
        s = (
            f"The assessment found {plural(k['critical'], 'critical issue')} that "
            f"{'needs' if k['critical'] == 1 else 'need'} immediate attention: an observed problem with a direct "
            "security exposure or a control disruption during the observation."
        )
        if k["high"]:
            s += f" A further {plural(k['high'], 'high-severity issue')} should be addressed promptly."
    elif k["high"]:
        s = (
            f"No critical issues were found, but {plural(k['high'], 'high-severity issue')} "
            f"{'is' if k['high'] == 1 else 'are'} likely to affect control or security now and should be addressed "
            "promptly."
        )
    elif k["medium"]:
        s = (
            f"No critical or high-severity issues were found. {plural(k['medium'], 'medium-severity issue')} "
            f"{'degrades' if k['medium'] == 1 else 'degrade'} reliability or maintainability and should be planned "
            "into normal maintenance."
        )
    elif k["low"]:
        s = (
            "No issues above low severity were found. The "
            f"{plural(k['low'], 'low-severity item')} listed are good-practice improvements."
        )
    else:
        s = "No issues above informational level were found within the checks that were performed."
    if k["medium"] and (k["critical"] or k["high"]):
        s += f" {plural(k['medium'], 'medium-severity issue')} can be planned into normal maintenance."
    s += f" The observation covered {plural(nd, 'device')} and {plural(nb, 'BBMD')}."
    n = len(c.r.checks_not_performed)
    if n:
        s += (
            f" {plural(n, 'check')} could not be performed from this observation point (see section "
            f"{c.numbers['not-performed']}), so the absence of a finding in those areas does not show that the "
            "network is healthy there."
        )
    if c.r.run.incomplete:
        s += " The run was stopped before completion, so the results are partial."
    return s


def render_summary(c: _Ctx) -> str:
    tiles = "".join(
        f'<div class="tile tile-{s.value}"><div class="tile-n">{c.counts[s.value]}</div>'
        f'<div class="tile-l">{SEV_LABEL[s]}</div></div>'
        for s in Severity
    )
    top = [f for f in c.findings if f.severity != Severity.INFO][:5] or c.findings[:5]
    if top:
        items = []
        for f in top:
            subj = f' <span class="muted">({esc(f.subject)})</span>' if f.subject else ""
            items.append(
                f'<li>{sev_badge(f.severity)} <a href="#f-{esc(anchor(f))}"><strong>{esc(f.title)}</strong></a>{subj}'
                f'<div class="top-expl">{esc(first_sentence(f.explanation))}</div>'
                f'<div class="top-rec"><span class="label">What to do:</span> {esc(first_sentence(f.recommendation))}</div></li>'
            )
        top_html = f'<h3>Most important findings</h3><ol class="top5">{"".join(items)}</ol>'
    else:
        top_html = "<h3>Most important findings</h3><p>No findings were raised.</p>"
    return f"""
<section id="summary" class="major">
  {h2(c, "summary", "Executive summary")}
  <p class="condition">{esc(condition_statement(c))}</p>
  <div class="tiles" role="list" aria-label="Findings by severity">{tiles}</div>
  <figure class="figure">{svg_severity_bar(c.counts)}<figcaption>Findings by severity. Severity is a category, not a score: see section {c.numbers['methodology']} for definitions.</figcaption></figure>
  {top_html}
</section>"""


def render_changes(c: _Ctx) -> str:
    d = c.diff or {}
    old = d.get("old", {}) or {}
    dev = d.get("devices", {}) or {}
    fnd = d.get("findings", {}) or {}
    sm = d.get("summary", {}) or {}

    def sev_of(x: Any) -> str:
        try:
            return sev_badge(Severity(x))
        except ValueError:
            return val(x)

    def frows(items: list[dict[str, Any]], with_old: bool = False) -> list[list[str]]:
        rows = []
        for f in items:
            row = [sev_of(f.get("severity")), f'<span class="mono">{val(f.get("id"))}</span>', val(f.get("title")),
                   val(f.get("subject"))]
            if with_old:
                os_, ns = f.get("old_severity"), f.get("severity")
                row.append("Unchanged" if os_ == ns else f"{sev_of(os_)} → {sev_of(ns)}")
            rows.append(row)
        return rows

    def drows(items: list[dict[str, Any]]) -> list[list[str]]:
        return [[esc(x.get("instance")), val(x.get("object_name")), f'<span class="mono">{val(x.get("address"))}</span>',
                 val(x.get("vendor_id"))] for x in items]

    parts = [f'<section id="changes" class="major">{h2(c, "changes", "Changes since previous visit")}']
    parts.append(
        f"<p>Compared with the previous observation on {fmt_iso(old.get('started'), with_time=False)}"
        f"{(' (' + esc(old.get('kind')) + ')') if old.get('kind') else ''}: "
        f"{plural(int(sm.get('findings_new', 0)), 'new finding')}, "
        f"{plural(int(sm.get('findings_resolved', 0)), 'resolved finding')}, "
        f"{plural(int(sm.get('findings_persisting', 0)), 'persisting finding')}; "
        f"{plural(int(sm.get('devices_added', 0)), 'device')} added, "
        f"{int(sm.get('devices_removed', 0))} removed and {int(sm.get('devices_changed', 0))} changed.</p>"
    )
    fh = ["Severity", "ID", "Title", "Subject"]
    for key, title, note in (
        ("new", "New findings", ""),
        ("resolved", "Resolved findings", "Raised on the previous visit and not raised now, with the check performed."),
        ("not_rechecked", "Not re-checked",
         "Raised on the previous visit, but the check could not be performed this time, so it is not known whether "
         "the issue is resolved."),
    ):
        items = fnd.get(key) or []
        if items:
            parts.append(f"<h3>{esc(title)} ({len(items)})</h3>")
            if note:
                parts.append(f'<p class="muted">{esc(note)}</p>')
            parts.append(table(fh, frows(items)))
    pers = fnd.get("persisting") or []
    if pers:
        parts.append(f"<h3>Persisting findings ({len(pers)})</h3>")
        parts.append(table(fh + ["Severity change"], frows(pers, with_old=True)))
    dh = ["Instance", "Object name", "Address", "Vendor ID"]
    for key, title in (("added", "Devices added"), ("removed", "Devices removed")):
        items = dev.get(key) or []
        if items:
            parts.append(f"<h3>{title} ({len(items)})</h3>")
            parts.append(table(dh, drows(items)))
    ch = dev.get("changed") or []
    if ch:
        parts.append(f"<h3>Devices changed ({len(ch)})</h3>")
        rows = []
        for x in ch:
            for chg in x.get("changes") or []:
                rows.append([esc(x.get("instance")), val(x.get("object_name")), esc(chg.get("field")),
                             val(chg.get("old")), val(chg.get("new"))])
        parts.append(table(["Instance", "Object name", "Property", "Previous", "Now"], rows))
    if not any(fnd.get(k) for k in ("new", "resolved", "persisting", "not_rechecked")) and not any(
        dev.get(k) for k in ("added", "removed", "changed")
    ):
        parts.append("<p>No differences were found.</p>")
    parts.append("</section>")
    return "".join(parts)


def render_scope(c: _Ctx) -> str:
    run = c.r.run
    roe = [
        ("Site", val(c.site)),
        ("Client", val(c.client)),
        ("Authorised by", val(run.authorised_by)),
        ("Scope", val(run.scope_note)),
        ("Prepared by", val(c.prepared_by)),
    ]
    vant = DASH
    if run.vantage is not None:
        src = VANTAGE_SOURCE_TEXT.get(run.vantage_source or "", run.vantage_source or "")
        vant = f'<strong>{esc(run.vantage.value)}</strong>{(" — " + esc(src)) if src else ""}' \
               f'<div class="muted">{esc(VANTAGE_TEXT[run.vantage])}</div>'
    ntp = DASH if run.ntp_synced is None else ("Yes" if run.ntp_synced else "No (clock-skew checks are not reliable)")
    addr = DASH
    if run.local_ip:
        addr = esc(run.local_ip) + (f" / {esc(run.netmask)}" if run.netmask else "")
    info = [
        ("Run type", esc(run.kind)),
        ("Started", fmt_iso(run.started)),
        ("Finished", fmt_iso(run.finished)),
        ("Duration", duration_text(run.started, run.finished)),
        ("Interface", val(run.interface)),
        ("Local address", addr),
        ("Broadcast address", val(run.broadcast)),
        ("UDP port", val(run.port)),
        ("Vantage", vant),
        ("Host clock NTP-synchronised", ntp),
        ("Completed", "No — stopped early, results are partial" if run.incomplete else "Yes"),
    ]
    parts = [f'<section id="scope" class="major">{h2(c, "scope", "Scope and rules of engagement")}',
             "<h3>Authorisation</h3>", kv_table(roe), "<h3>Run</h3>", kv_table(info)]
    parts.append("<h3>Confirmations given</h3>")
    if run.confirmations:
        rows = [[val(x.get("action")), f'<span class="mono">{val(x.get("target"))}</span>', val(x.get("user")),
                 fmt_iso(x.get("at")) if x.get("at") else DASH] for x in run.confirmations]
        parts.append(table(["Action", "Target", "Confirmed by", "When"], rows))
        if any("fdr" in str(x.get("action", "")).lower() or "foreign" in str(x.get("action", "")).lower()
               for x in run.confirmations):
            parts.append(
                '<p class="note">Foreign Device Registration is not strictly read-only: the BBMD creates a table '
                "entry for the tool's address with a short time-to-live. The tool lets the entry expire and does not "
                "delete it.</p>"
            )
    else:
        parts.append("<p>No cross-subnet or elevated actions were confirmed during this run.</p>")
    parts.append("<h3>Traffic sent by the tool</h3>")
    b = c.r.budget
    if b is None:
        parts.append("<p>No active traffic was sent in this run: it was passive observation only.</p>")
    else:
        rows = [
            ["Who-Is requests", val(b.whois_planned), val(b.whois_sent)],
            ["Property reads (ReadProperty / ReadPropertyMultiple)", val(b.reads_planned), val(b.reads_sent)],
            ["BBMD table reads (Read-BDT / Read-FDT)", val(b.bvlc_probes_planned), val(b.bvlc_probes_sent)],
            ["Peak packets per second", val(b.peak_pps_planned), val(b.peak_pps_actual)],
            ["Total frames sent", DASH, val(b.frames_sent)],
            ["Estimated duration (s)", val(b.est_duration_s), DASH],
        ]
        parts.append(table(["Item", "Planned", "Actual"], rows, cls="num-cols"))
        if b.notes:
            parts.append("<ul>" + "".join(f"<li>{esc(n)}</li>" for n in b.notes) + "</ul>")
    parts.append(
        '<p class="muted">The tool only transmits Who-Is, ReadProperty, ReadPropertyMultiple, Read-BDT and '
        "Read-FDT (plus Register-Foreign-Device and Distribute-Broadcast-To-Network only after a typed confirmation). "
        "It never sends write, device-control, reinitialise, time-synchronisation or network-layer messages.</p>"
    )
    parts.append("</section>")
    return "".join(parts)


def anchor(f: Finding) -> str:
    return re.sub(r"[^A-Za-z0-9_-]+", "-", f"{f.id}-{f.subject}").strip("-")


def render_finding(f: Finding) -> str:
    conf = "Observed" if f.confidence == Confidence.OBSERVED else "Inferred"
    conf_title = ("Seen directly in the traffic or responses." if f.confidence == Confidence.OBSERVED
                  else "Deduced from other evidence; not seen directly. Capped at High severity.")
    parts = [
        f'<article class="finding sevb-{f.severity.value}" id="f-{esc(anchor(f))}">',
        '<header class="f-head">',
        f'<div class="f-title"><span class="f-id mono">{esc(f.id)}</span> {esc(f.title)}</div>',
        '<div class="badges">',
        sev_badge(f.severity),
        f'<span class="badge conf" title="{esc(conf_title)}">Confidence: {conf}</span>',
        f'<span class="badge vant">Min. vantage: {esc(f.vantage_required.value)}</span>',
        "</div>",
    ]
    if f.subject:
        parts.append(f'<div class="f-subject"><span class="label">Subject:</span> <span class="mono">{esc(f.subject)}</span></div>')
    parts.append("</header>")
    parts.append(f'<p class="f-expl">{esc(f.explanation)}</p>')
    parts.append(f'<div class="f-rec"><span class="label">Recommendation</span><p>{esc(f.recommendation)}</p></div>')
    if f.evidence:
        rows = [[esc(e.kind), esc(e.detail), fmt_epoch(e.ts), f'<span class="mono">{val(e.ref)}</span>']
                for e in f.evidence[:MAX_EVIDENCE_ROWS]]
        parts.append('<div class="f-block"><div class="label">Evidence</div>')
        parts.append(table(["Kind", "Detail", "Time (UTC)", "Reference"], rows, cls="evidence"))
        extra = len(f.evidence) - MAX_EVIDENCE_ROWS
        if extra > 0:
            parts.append(f'<p class="muted">{plural(extra, "further evidence item")} in the JSON result.</p>')
        parts.append("</div>")
    if f.thresholds_used:
        rows = []
        for name, t in f.thresholds_used.items():
            if isinstance(t, dict):
                v, prov, meaning = t.get("value"), t.get("provisional", True), t.get("meaning", "")
            else:
                v, prov, meaning = t, True, ""
            tag = ('<span class="tag prov">Provisional</span>' if prov
                   else '<span class="tag fixed">Standard</span>')
            rows.append([f'<span class="mono">{esc(name)}</span>', val(v), val(meaning), tag])
        parts.append('<div class="f-block"><div class="label">Thresholds used</div>')
        parts.append(table(["Threshold", "Value", "Meaning", "Status"], rows, cls="thresholds"))
        parts.append("</div>")
    if f.spec_refs:
        parts.append('<div class="f-block"><span class="label">Specification references:</span> '
                     + "; ".join(esc(s) for s in f.spec_refs) + "</div>")
    if f.falsifier:
        parts.append(f'<div class="f-block f-fals"><span class="label">What would disprove this:</span> '
                     f"{esc(f.falsifier)}</div>")
    parts.append("</article>")
    return "".join(parts)


def render_findings(c: _Ctx) -> str:
    parts = [f'<section id="findings" class="major">{h2(c, "findings", "Findings")}']
    if not c.findings:
        parts.append("<p>No findings were raised by the checks that were performed.</p>")
    else:
        parts.append(
            "<p>Findings are grouped by severity. Each one states what was found, why it matters, what to do, the "
            "evidence, and what would disprove it.</p>"
        )
        for s in Severity:
            fs = [f for f in c.findings if f.severity == s]
            if not fs:
                continue
            parts.append(f'<h3 class="sev-heading">{sev_badge(s)} {SEV_LABEL[s]} '
                         f'<span class="muted">({len(fs)})</span></h3>')
            parts.extend(render_finding(f) for f in fs)
    parts.append("</section>")
    return "".join(parts)


def render_not_performed(c: _Ctx) -> str:
    parts = [f'<section id="not-performed" class="major">{h2(c, "not-performed", "Checks not performed")}']
    items = c.r.checks_not_performed
    if not items:
        parts.append("<p>All checks in the catalogue were performed for this run.</p>")
    else:
        parts.append(
            "<p>The checks below could not be performed, usually because the observation point (vantage) cannot see "
            "the traffic they need. <strong>The absence of a finding for these checks does not mean the network is "
            "healthy in that respect.</strong></p>"
        )
        rows = [[f'<span class="mono">{val(x.get("id"))}</span>', val(x.get("title")), val(x.get("reason"))]
                for x in items]
        parts.append(table(["Check", "Title", "Reason"], rows))
    parts.append("</section>")
    return "".join(parts)


def device_status(d: Device) -> str:
    st = dprop(d, "system-status")
    if st is not None and str(st) != "":
        s = str(st)
        if s.lower() in ("operational",):
            return esc(s)
        return f'<span class="warn-text">{esc(s)}</span>'
    if d.responded_to_scan:
        return "Responding"
    return DASH


def render_inventory(c: _Ctx) -> str:
    devs = sorted(c.r.devices, key=lambda d: (d.remote, d.instance, d.address_key))
    nr = sum(1 for d in devs if d.remote)
    resp = sum(1 for d in devs if d.responded_to_scan)
    pas = sum(1 for d in devs if d.seen_passively)
    parts = [f'<section id="inventory" class="major">{h2(c, "inventory", "Device inventory")}']
    if not devs:
        parts.append("<p>No BACnet devices were discovered.</p></section>")
        return "".join(parts)
    parts.append(
        f"<p>{plural(len(devs), 'device')} recorded: {resp} answered the scan, {pas} were seen in passive traffic, "
        f"{nr} {'is' if nr == 1 else 'are'} remote (behind a BACnet router; addressed through the router and "
        "not read unless explicitly enabled).</p>"
    )
    rows = []
    for d in devs:
        addr = f'<span class="mono">{esc(d.ip)}:{esc(d.port)}</span>' if d.ip else DASH
        if d.remote:
            addr += (f'<div class="small"><span class="tag remote">Remote</span> net {esc(d.snet)}'
                     f'{(" · MAC " + esc(d.sadr)) if d.sadr else ""}</div>')
        vendor = dprop(d, "vendor-name")
        vendor_html = val(vendor) if vendor not in (None, "") else (
            f"Vendor ID {esc(d.vendor_id)}" if d.vendor_id is not None else DASH)
        model = dprop(d, "model-name")
        if model not in (None, ""):
            vendor_html += f'<div class="small">{esc(model)}</div>'
        if vendor not in (None, "") and d.vendor_id is not None:
            vendor_html += f'<div class="small muted">ID {esc(d.vendor_id)}</div>'
        fw = dprop(d, "firmware-revision")
        app = dprop(d, "application-software-version")
        fw_html = val(fw)
        if app not in (None, ""):
            fw_html += f'<div class="small muted">App {esc(app)}</div>'
        seen = ", ".join(x for x, ok in (("scan", d.responded_to_scan), ("passive", d.seen_passively)) if ok) or DASH
        rows.append([
            (esc(d.instance), d.instance),
            val(dprop(d, "object-name")),
            (addr, d.address_key),
            vendor_html,
            fw_html,
            val(dprop(d, "location")),
            device_status(d),
            esc(seen),
        ])
    parts.append(table(["Instance", "Object name", "Address", "Vendor / model", "Firmware", "Location", "Status",
                        "Seen by"], rows, cls="inventory", sortable=True))
    parts.append('<p class="muted small no-print">Click a column heading to sort (requires JavaScript).</p>')
    parts.append("</section>")
    return "".join(parts)


def render_topology(c: _Ctx) -> str:
    bbmds = c.r.bbmds
    parts = [f'<section id="topology" class="major">{h2(c, "topology", "BBMDs and topology")}']
    if not bbmds:
        parts.append(
            "<p>No BACnet Broadcast Management Devices (BBMDs) were found or probed. Without a BBMD, BACnet "
            "broadcasts stay on the local subnet.</p></section>"
        )
        return "".join(parts)
    nb = sum(1 for b in bbmds if b.status == "bbmd")
    parts.append(
        f"<p>A BBMD forwards BACnet broadcasts between IP subnets using its Broadcast Distribution Table (BDT), and "
        f"accepts registrations from foreign devices in its Foreign Device Table (FDT). {plural(len(bbmds), 'address')} "
        f"{'was' if len(bbmds) == 1 else 'were'} checked; {plural(nb, 'is a BBMD', 'are BBMDs')}.</p>"
    )
    svg = svg_topology(bbmds)
    if svg:
        parts.append(
            f'<figure class="figure">{svg}<figcaption><span class="lg lg-one"></span> one-hop BDT entry '
            '(mask 255.255.255.255) &nbsp; <span class="lg lg-two"></span> two-hop entry (directed broadcast mask) '
            '&nbsp; <span class="lg lg-asym"></span> asymmetric (peer read, does not list back) &nbsp; '
            '<span class="lg lg-fd"></span> registered foreign device. Arrows point from the BBMD whose table '
            "lists the peer.</figcaption></figure>"
        )
    elif any(b.status == "bbmd" or b.bdt for b in bbmds):
        parts.append('<p class="muted">The topology is too large to draw clearly; see the tables below.</p>')
    rows = []
    for b in bbmds:
        fdt = DASH if b.fdt is None else str(len(b.fdt))
        if b.fdt_status and b.fdt_status != "ack":
            fdt = f"{fdt} ({esc(b.fdt_status)})" if b.fdt is not None else esc(b.fdt_status)
        rows.append([f'<span class="mono">{esc(b.ip)}:{esc(b.port)}</span>', esc(b.status), esc(b.source),
                     DASH if b.bdt is None else str(len(b.bdt)), fdt])
    parts.append("<h3>Addresses checked</h3>")
    parts.append(table(["Address", "Status", "Found by", "BDT entries", "FDT entries"], rows, sortable=True))
    bdt_rows = []
    for b in bbmds:
        for e in b.bdt or []:
            hop = "one-hop" if e.mask == "255.255.255.255" else "two-hop"
            bdt_rows.append([f'<span class="mono">{esc(b.ip)}:{esc(b.port)}</span>',
                             f'<span class="mono">{esc(e.ip)}:{esc(e.port)}</span>',
                             f'<span class="mono">{esc(e.mask)}</span>', hop])
    if bdt_rows:
        parts.append("<h3>Broadcast Distribution Tables</h3>")
        parts.append(table(["BBMD", "Peer", "Mask", "Distribution"], bdt_rows))
    fdt_rows = []
    for b in bbmds:
        for e in b.fdt or []:
            fdt_rows.append([f'<span class="mono">{esc(b.ip)}:{esc(b.port)}</span>',
                             f'<span class="mono">{esc(e.ip)}:{esc(e.port)}</span>', val(e.ttl), val(e.remaining)])
    if fdt_rows:
        parts.append("<h3>Foreign Device Tables</h3>")
        parts.append(table(["BBMD", "Foreign device", "TTL (s)", "Remaining (s)"], fdt_rows, cls="num-cols"))
    copies = (c.r.topology or {}).get("broadcast_copies") if isinstance(c.r.topology, dict) else None
    if isinstance(copies, dict) and copies:
        rows = []
        for subnet, n in copies.items():
            note = "Expected" if n == 1 else ("Not reached" if n == 0 else "Duplicate distribution")
            rows.append([f'<span class="mono">{esc(subnet)}</span>', val(n), esc(note)])
        parts.append("<h3>Simulated broadcast distribution</h3>")
        parts.append('<p class="muted">Copies of one broadcast each subnet would receive, predicted from the BDTs. '
                     "A healthy network delivers exactly one copy to every reachable subnet.</p>")
        parts.append(table(["Subnet", "Copies", "Assessment"], rows))
    parts.append("</section>")
    return "".join(parts)


def is_prerelease(version: str) -> bool:
    return "a" in version or "b" in version


def prerelease_statement(version: str) -> str:
    short = ".".join(re.split(r"[^0-9.]", version, maxsplit=1)[0].split(".")[:2]) or version
    return f"bacnet-health {short} is a pre-release and has not yet been validated on physical controllers."


PROVISIONAL_PARAGRAPH = (
    "Thresholds marked provisional have not yet been calibrated with field data. They are conservative starting "
    "values chosen from the BACnet standard and engineering judgement, and they will be revised as field captures "
    "become available. A finding that depends on a provisional threshold is a prompt to investigate, not a measured "
    "fault. The raw metrics are kept in the JSON result so that findings can be re-evaluated later."
)


def render_methodology(c: _Ctx) -> str:
    sev_rows = [[sev_badge(s), esc(SEV_MEANING[s])] for s in Severity]
    parts = [f'<section id="methodology" class="major">{h2(c, "methodology", "Methodology and limitations")}']
    parts.append("<h3>How the assessment works</h3>")
    parts.append(
        "<p>bacnet-health combines two kinds of observation. <strong>Passive</strong> observation listens to BACnet/IP "
        "traffic (live, or from a packet capture file) and measures broadcast rates, storms, errors and BBMD "
        "forwarding without sending anything. <strong>Active</strong> observation sends a small, rate-limited set of "
        "read-only requests: ranged Who-Is to discover devices, ReadProperty(-Multiple) to read the Device object, "
        "and Read-BDT / Read-FDT to audit BBMDs. The tool never writes to a device or changes its configuration. "
        "When both are done, listening comes first so that the tool's own traffic does not distort the baseline, "
        "and the tool's own frames are excluded from all passive metrics.</p>"
    )
    parts.append("<h3>Severity, confidence and vantage</h3>")
    parts.append(table(["Severity", "Meaning"], sev_rows))
    parts.append(
        "<p><strong>Confidence</strong> is <em>Observed</em> when the problem was seen directly in traffic or "
        "responses, and <em>Inferred</em> when it was deduced from other evidence (for example from BBMD tables). "
        "Inferred findings are never rated Critical. <strong>Vantage</strong> is where the traffic was observed "
        "from: <em>self</em> (the tool's own socket), <em>access</em> (an ordinary switch port) or <em>span</em> "
        "(a mirror port). Each check needs a minimum vantage; checks that could not be performed are listed in "
        f"section {c.numbers['not-performed']}. There is deliberately no overall numeric score.</p>"
    )
    parts.append("<h3>Thresholds</h3>")
    parts.append(f'<p class="note">{esc(PROVISIONAL_PARAGRAPH)}</p>')
    parts.append("<h3>Limitations</h3>")
    lims = [
        "A passive observation only covers the time it ran. Intermittent problems outside that window are not seen.",
        "From a self or access vantage, device-to-device unicast traffic (including writes) is not visible.",
        "Devices behind BACnet routers are recorded from their I-Am, but are not read unless explicitly enabled.",
        "BACnet/IPv6 (Annex U), BACnet Secure Connect and MS/TP links that do not reach the IP network are out of "
        "scope for this version.",
    ]
    lims += [str(x) for x in c.r.limitations]
    parts.append("<ul>" + "".join(f"<li>{esc(x)}</li>" for x in lims) + "</ul>")
    if is_prerelease(__version__):
        parts.append(f'<p class="note warn">{esc(prerelease_statement(__version__))}</p>')
    parts.append("</section>")
    return "".join(parts)


def compact(obj: Any, max_list: int = 60, depth: int = 0) -> Any:
    """Shorten long lists for display; the full data stays in the JSON result."""
    if depth > 8:
        return "…"
    if isinstance(obj, dict):
        return {str(k): compact(v, max_list, depth + 1) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        items = [compact(v, max_list, depth + 1) for v in obj[:max_list]]
        if len(obj) > max_list:
            items.append(f"… {len(obj) - max_list} more items in the JSON result")
        return items
    return obj


def _is_flat(v: Any) -> bool:
    if isinstance(v, (list, tuple)):
        return all(not isinstance(x, (list, tuple, dict)) or (isinstance(x, (list, tuple)) and _is_flat(x)) for x in v)
    return not isinstance(v, dict)


def pretty_json(obj: Any, indent: int = 0) -> str:
    """Indented JSON, but lists of scalars (or of short scalar lists) are kept on one line and wrapped."""
    pad, pad2 = "  " * indent, "  " * (indent + 1)
    if isinstance(obj, dict):
        if not obj:
            return "{}"
        items = [f"{pad2}{json.dumps(str(k), ensure_ascii=False)}: {pretty_json(v, indent + 1)}"
                 for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))]
        return "{\n" + ",\n".join(items) + "\n" + pad + "}"
    if isinstance(obj, (list, tuple)):
        if not obj:
            return "[]"
        if _is_flat(obj):
            parts = [json.dumps(x, ensure_ascii=False, default=str) for x in obj]
            lines, cur = [], ""
            for p_ in parts:
                if cur and len(cur) + len(p_) + 2 > 96:
                    lines.append(cur + ",")
                    cur = p_
                else:
                    cur = f"{cur}, {p_}" if cur else p_
            lines.append(cur)
            if len(lines) == 1:
                return "[" + lines[0] + "]"
            return "[\n" + "\n".join(pad2 + ln for ln in lines) + "\n" + pad + "]"
        return "[\n" + ",\n".join(pad2 + pretty_json(x, indent + 1) for x in obj) + "\n" + pad + "]"
    return json.dumps(obj, ensure_ascii=False, default=str)


def render_appendix(c: _Ctx) -> str:
    r = c.r
    tool = r.tool or {}
    parts = [f'<section id="appendix" class="major">{h2(c, "appendix", "Appendix: reproducibility and raw metrics")}']
    parts.append("<h3>Reproducibility</h3>")
    rows = [
        ("Tool", f"{esc(tool.get('name', 'bacnet-health'))} {esc(tool.get('version', ''))}"),
        ("Python", val(tool.get("python"))),
        ("Operating system", val(tool.get("os"))),
    ]
    if tool.get("git_commit") or tool.get("commit"):
        rows.append(("Git commit", f'<span class="mono">{esc(tool.get("git_commit") or tool.get("commit"))}</span>'))
    rows += [
        ("Result schema", val(r.schema_version)),
        ("Report rendered by", f"bacnet-health {esc(__version__)}"),
        ("Command", f'<code class="cmd">{esc(r.run.command)}</code>' if r.run.command else DASH),
    ]
    parts.append(kv_table(rows))
    parts.append("<h4>Inputs</h4>")
    if r.inputs:
        irows = [[f'<span class="mono">{esc(i.path)}</span>', val(i.size), val(i.frames),
                  f'<span class="mono hash">{esc(i.sha256)}</span>'] for i in r.inputs]
        parts.append(table(["File", "Size (bytes)", "Frames", "SHA-256"], irows, cls="inputs"))
    else:
        parts.append("<p>No input files: this result came from a live run.</p>")

    m = c.metrics
    parts.append("<h3>Traffic metrics</h3>")
    figs = []
    for key, label, unit in KEY_FIGURES:
        v = m.get(key)
        if isinstance(v, dict):
            tot = sum(x for x in v.values() if is_num(x))
            figs.append((label, f"{esc(num(tot))}" + (f' <span class="muted small">({esc(", ".join(f"{k}: {num(x)}" for k, x in v.items() if is_num(x)))})</span>' if v else "")))
        elif is_num(v):
            figs.append((label, esc(num(v)) + (f" {unit}" if unit else "")))
    if figs:
        parts.append(kv_table(figs))
    any_chart = False
    pts = metric_timeseries(m)
    if pts:
        any_chart = True
        parts.append(
            f'<figure class="figure">{svg_timeseries(pts, bcast_threshold(m))}<figcaption>BACnet broadcast rate '
            "over the observation (packets per second). The dashed line is the provisional threshold for a high "
            "broadcast rate.</figcaption></figure>"
        )
    tops = metric_top_sources(m)
    if tops:
        any_chart = True
        parts.append(f'<figure class="figure">{svg_hbars(tops, "Top broadcast sources")}'
                     "<figcaption>Top broadcast sources (packets).</figcaption></figure>")
    svc = metric_service_counts(m)
    if svc:
        any_chart = True
        mx = max(v for _, v in svc) or 1
        rows = [[f'<span class="mono">{esc(k)}</span>', (esc(num(v)), v),
                 f'<span class="minibar"><span style="width:{max(1.0, 100 * v / mx):.1f}%"></span></span>']
                for k, v in svc]
        parts.append("<h4>Messages by service</h4>")
        parts.append(table(["Service / message", "Count", ""], rows, cls="services", sortable=True))
    if not any_chart and not figs:
        parts.append("<p>No traffic metrics were recorded in this result.</p>")
    parts.append("<h3>Raw metrics</h3>")
    if m:
        raw = pretty_json(compact(m))
        parts.append(f'<pre class="raw">{esc(raw)}</pre>')
    else:
        parts.append("<p>None.</p>")
    if r.topology:
        raw = pretty_json(compact(r.topology))
        parts.append("<h4>Topology data</h4>")
        parts.append(f'<pre class="raw">{esc(raw)}</pre>')
    parts.append("</section>")
    return "".join(parts)


# --------------------------------------------------------------------------------------------------------------------
# page
# --------------------------------------------------------------------------------------------------------------------

CSS = """
:root{--accent:__ACCENT__;--ink:#1f2328;--muted:#57606a;--line:#d0d7de;--soft:#f6f8fa;
--c-critical:#7f1d1d;--c-high:#c2410c;--c-medium:#f0a400;--c-low:#1d4ed8;--c-info:#6b7280;
--t-critical:#fbeaea;--t-high:#fdeee6;--t-medium:#fff6dc;--t-low:#e8effd;--t-info:#f1f2f4}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:#eef0f3;color:var(--ink);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,
"Helvetica Neue",Arial,"Noto Sans",sans-serif}
.page{max-width:900px;margin:24px auto;background:#fff;padding:40px 56px;box-shadow:0 1px 4px rgba(0,0,0,.08)}
h1,h2,h3,h4{line-height:1.25;color:var(--ink)}
h2{font-size:1.55em;margin:0 0 .8em;padding-bottom:.35em;border-bottom:2px solid var(--accent)}
h3{font-size:1.12em;margin:1.6em 0 .6em}
h4{font-size:1em;margin:1.3em 0 .5em}
.secno{color:var(--accent);margin-right:.55em;font-variant-numeric:tabular-nums}
a{color:var(--accent)}
section.major{margin-top:56px}
p{margin:.6em 0}
.muted{color:var(--muted)}
.small{font-size:.85em}
.mono,code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:.9em}
.label{font-weight:600;color:var(--ink)}
.note{background:var(--soft);border-left:4px solid var(--accent);padding:.7em 1em;margin:1em 0}
.note.warn,.cover-note.warn{border-left-color:var(--c-medium)}
.warn-text{color:#8a5a00;font-weight:600}
table{width:100%;border-collapse:collapse;margin:.6em 0 1em;font-size:.88em}
th,td{text-align:left;vertical-align:top;padding:6px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}
thead th{background:var(--soft);border-bottom:2px solid var(--line);font-weight:600;white-space:nowrap}
tbody tr:nth-child(even) td{background:#fbfcfd}
table.kv th{width:30%;background:transparent;color:var(--muted);font-weight:500;white-space:normal}
table.kv td,table.kv th{border-bottom:1px solid #eaeef2}
table.num-cols td:not(:first-child){font-variant-numeric:tabular-nums}
td .hash{word-break:break-all}
.badge{display:inline-block;font-size:.74em;font-weight:600;letter-spacing:.02em;padding:2px 8px;border-radius:3px;
border:1px solid var(--line);background:#fff;color:var(--ink);white-space:nowrap;vertical-align:middle}
.sev{border:0;text-transform:uppercase;letter-spacing:.05em}
.sev-critical{background:var(--c-critical);color:#fff}
.sev-high{background:var(--c-high);color:#fff}
.sev-medium{background:var(--c-medium);color:#1f1300}
.sev-low{background:var(--c-low);color:#fff}
.sev-info{background:var(--c-info);color:#fff}
.tag{display:inline-block;font-size:.75em;font-weight:600;padding:1px 6px;border-radius:3px;white-space:nowrap}
.tag.prov{background:#fff3cd;color:#6b4e00;border:1px solid #e6c766}
.tag.fixed{background:#e6f4ea;color:#1e5c2f;border:1px solid #a8d5b4}
.tag.remote{background:#ede9fe;color:#4c2a85;border:1px solid #c9b8f0}
.cover{position:relative;padding-top:24px}
.cover-band{height:10px;background:var(--accent);margin:-40px -56px 32px}
.cover-head{display:flex;align-items:center;gap:18px;min-height:56px}
.logo{max-height:64px;max-width:240px}
.cover-org{font-weight:600;font-size:1.1em;color:var(--muted)}
.cover-title{margin:56px 0 36px}
.eyebrow{text-transform:uppercase;letter-spacing:.12em;font-size:.8em;font-weight:600;color:var(--accent)}
.cover h1{font-size:2.4em;margin:.2em 0 .15em}
.cover-sub{font-size:1.15em;color:var(--muted)}
.cover-note{font-size:.88em;background:var(--soft);border-left:4px solid var(--accent);padding:.6em 1em}
.toc{margin-top:36px}
.toc-title{font-weight:600;text-transform:uppercase;letter-spacing:.08em;font-size:.8em;color:var(--muted)}
.toc ol{list-style:none;padding:0;margin:.5em 0;columns:2;column-gap:32px}
.toc li{padding:3px 0;break-inside:avoid}
.toc a{text-decoration:none;color:var(--ink)}
.condition{font-size:1.06em;background:var(--soft);padding:14px 18px;border-radius:4px}
.tiles{display:flex;gap:10px;margin:18px 0}
.tile{flex:1;border:1px solid var(--line);border-top:5px solid;border-radius:4px;padding:10px 12px;text-align:center}
.tile-n{font-size:1.9em;font-weight:700;font-variant-numeric:tabular-nums;line-height:1.1}
.tile-l{font-size:.8em;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);font-weight:600}
.tile-critical{border-top-color:var(--c-critical);background:var(--t-critical)}
.tile-high{border-top-color:var(--c-high);background:var(--t-high)}
.tile-medium{border-top-color:var(--c-medium);background:var(--t-medium)}
.tile-low{border-top-color:var(--c-low);background:var(--t-low)}
.tile-info{border-top-color:var(--c-info);background:var(--t-info)}
.top5{padding-left:1.4em}
.top5 li{margin:.2em 0 1em}
.top5 a{color:var(--ink);text-decoration:none}
.top-expl{margin-top:.25em}
.top-rec{color:var(--muted)}
.figure{margin:1em 0 1.4em}
.figure figcaption{font-size:.82em;color:var(--muted);margin-top:.4em}
svg.chart{max-width:100%;height:auto;display:block}
.ch-label,.ch-value,.ch-tick,.ch-axislabel,.ch-thlabel{font:12px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;fill:var(--ink)}
.ch-label.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:11px}
.ch-value{font-weight:600}
.ch-tick,.ch-axislabel{fill:var(--muted);font-size:11px}
.ch-track{fill:#eef1f4}
.ch-bar{fill:var(--accent)}
.ch-grid{stroke:#e6e9ed;stroke-width:1}
.ch-axis{stroke:#8c959f;stroke-width:1}
.ch-line{fill:none;stroke:var(--accent);stroke-width:1.6;stroke-linejoin:round}
.ch-dot{fill:var(--accent)}
.ch-threshold{stroke:var(--c-high);stroke-width:1.2;stroke-dasharray:5 4}
.ch-thlabel{fill:var(--c-high);font-size:11px}
.fill-critical{fill:var(--c-critical)}.fill-high{fill:var(--c-high)}.fill-medium{fill:var(--c-medium)}
.fill-low{fill:var(--c-low)}.fill-info{fill:var(--c-info)}
.sev-heading{display:flex;align-items:center;gap:8px;margin-top:2em}
.finding{border:1px solid var(--line);border-left:6px solid var(--c-info);border-radius:4px;padding:14px 18px;margin:12px 0 18px}
.sevb-critical{border-left-color:var(--c-critical)}.sevb-high{border-left-color:var(--c-high)}
.sevb-medium{border-left-color:var(--c-medium)}.sevb-low{border-left-color:var(--c-low)}
.f-head{break-inside:avoid;break-after:avoid}
.f-title{font-size:1.08em;font-weight:600}
.f-id{color:var(--muted);font-weight:600;margin-right:.3em}
.badges{margin:.45em 0 .2em;display:flex;flex-wrap:wrap;gap:6px}
.f-subject{font-size:.92em;color:var(--muted)}
.f-rec{background:var(--soft);border-radius:4px;padding:8px 12px;margin:.8em 0}
.f-rec p{margin:.2em 0 0}
.f-block{margin:.8em 0 0;font-size:.95em}
.f-block>.label{display:block;margin-bottom:.1em}
.f-fals{color:var(--muted)}
table.evidence,table.thresholds{font-size:.84em;margin:.3em 0 .4em}
.minibar{display:inline-block;width:160px;height:9px;background:#eef1f4;border-radius:2px;vertical-align:middle}
.minibar span{display:block;height:100%;background:var(--accent);border-radius:2px}
.lg{display:inline-block;width:22px;height:0;border-top:2px solid var(--accent);vertical-align:middle;margin-right:4px}
.lg-two{border-top-style:dashed}
.lg-asym{border-top:2px dashed var(--c-medium)}
.lg-fd{border-top:2px dotted #8c959f}
.tp-node{fill:#fff;stroke:var(--accent);stroke-width:1.6}
.tp-peer{stroke-dasharray:4 3;fill:var(--soft);stroke:#8c959f}
.tp-label{font:600 11.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;fill:var(--ink)}
.tp-sub{font:10.5px -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;fill:var(--muted)}
.tp-edge{stroke:var(--accent);stroke-width:1.6;fill:none}
.tp-twohop{stroke-dasharray:6 4}
.tp-asym{stroke:var(--c-medium)}
.tp-arrowhead{fill:var(--accent)}
.tp-fdline{stroke:#8c959f;stroke-width:1.2;stroke-dasharray:2 3}
.tp-fd{fill:var(--soft);stroke:#8c959f;stroke-width:1}
.tp-more{stroke-dasharray:3 2}
.tp-fdlabel{font:10.5px ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;fill:var(--ink)}
pre.raw{background:var(--soft);border:1px solid var(--line);border-radius:4px;padding:10px 12px;font-size:.78em;
white-space:pre-wrap;overflow-wrap:anywhere;max-height:none}
code.cmd{white-space:pre-wrap;overflow-wrap:anywhere}
.report-footer{margin-top:56px;padding-top:12px;border-top:1px solid var(--line);font-size:.8em;color:var(--muted);
display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap}
th.js-sort{cursor:pointer;user-select:none}
th.js-sort::after{content:" \\2195";color:#aab2bb;font-weight:400}
th.js-sort[aria-sort="ascending"]::after{content:" \\2191";color:var(--accent)}
th.js-sort[aria-sort="descending"]::after{content:" \\2193";color:var(--accent)}
@media (max-width:720px){.page{padding:24px 18px}.cover-band{margin:-24px -18px 24px}.tiles{flex-wrap:wrap}
.tile{flex:1 1 30%}.toc ol{columns:1}}
@page{margin:16mm 14mm 18mm;@bottom-left{content:"Generated by bacnet-health v__VERSION__";font-size:8pt;color:#57606a}
@bottom-right{content:counter(page);font-size:8pt;color:#57606a}}
@media print{
body{background:#fff;font-size:9.6pt;line-height:1.45}
.page{max-width:none;margin:0;padding:0;box-shadow:none}
.cover{min-height:238mm;break-after:page}
.cover-band{margin:0 0 24px}
section.major{margin-top:0;break-before:page}
#cover+section.major{break-before:auto}
h2,h3,h4,.sev-heading{break-after:avoid}
table{font-size:8.4pt}
thead{display:table-header-group}
tr,img,svg,.tile,.top5 li,figure{break-inside:avoid}
a{color:inherit;text-decoration:none}
.no-print{display:none}
.finding{break-inside:auto}
.f-rec,.f-fals{break-inside:avoid}
.f-block>.label,.f-block>div.label{break-after:avoid;break-inside:avoid}
h4+table,.label+table{break-before:avoid}
pre.raw{font-size:7.4pt}
table.inventory{font-size:7.8pt}
table.inventory th,table.inventory td{padding:4px 5px}
*{-webkit-print-color-adjust:exact;print-color-adjust:exact}
th.js-sort::after{content:""}
.report-footer{break-before:avoid;break-inside:avoid;margin-top:24px}
}
"""

JS = """
(function(){
  function key(td){var v=td.getAttribute('data-v');return v!==null?v:td.textContent.trim();}
  document.querySelectorAll('table.sortable').forEach(function(tbl){
    var ths=tbl.querySelectorAll('thead th');
    ths.forEach(function(th,i){
      th.classList.add('js-sort');th.setAttribute('tabindex','0');th.setAttribute('role','button');
      function go(){
        var asc=th.getAttribute('aria-sort')!=='ascending';
        ths.forEach(function(o){o.removeAttribute('aria-sort');});
        th.setAttribute('aria-sort',asc?'ascending':'descending');
        var body=tbl.tBodies[0];var rows=Array.prototype.slice.call(body.rows);
        var num=rows.every(function(r){var k=key(r.cells[i]);return k===''||!isNaN(parseFloat(k))&&isFinite(k);});
        rows.sort(function(a,b){var x=key(a.cells[i]),y=key(b.cells[i]);
          var c=num?(parseFloat(x)||0)-(parseFloat(y)||0):x.localeCompare(y,undefined,{numeric:true});
          return asc?c:-c;});
        rows.forEach(function(r){body.appendChild(r);});
      }
      th.addEventListener('click',go);
      th.addEventListener('keydown',function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();go();}});
    });
  });
})();
"""


def render_html(result: Result, branding: Branding | None = None, diff: dict[str, Any] | None = None) -> str:
    branding = branding or Branding()
    c = _Ctx(result, branding, diff)
    sections = section_ids(diff)
    c.numbers = {sid: i + 1 for i, (sid, _t) in enumerate(sections)}
    safe_version = re.sub(r"[^0-9A-Za-z.+-]", "", __version__)
    css = CSS.replace("__ACCENT__", branding.safe_accent()).replace("__VERSION__", safe_version)
    title_bits = ["BACnet/IP network health check"]
    if c.site:
        title_bits.append(c.site)
    body = [
        render_cover(c, sections),
        render_summary(c),
        render_changes(c) if diff is not None else "",
        render_scope(c),
        render_findings(c),
        render_not_performed(c),
        render_inventory(c),
        render_topology(c),
        render_methodology(c),
        render_appendix(c),
    ]
    rendered = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    footer = (
        f'<footer class="report-footer"><span>Generated by bacnet-health v{esc(__version__)}</span>'
        f"<span>{esc(c.org) + ' · ' if c.org else ''}Rendered {esc(rendered)}</span></footer>"
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n'
        '<meta name="generator" content="bacnet-health ' + esc(__version__) + '">\n'
        "<title>" + esc(" — ".join(title_bits)) + "</title>\n"
        "<style>" + css + "</style>\n</head>\n<body>\n<main class=\"page\">"
        + "".join(body)
        + footer
        + "</main>\n<script>" + JS + "</script>\n</body>\n</html>\n"
    )
