"""Compact plain-text summary for the terminal."""

from __future__ import annotations

from bacnet_health import __version__
from bacnet_health.model import Result, Severity

_ANSI = {
    Severity.CRITICAL: "\033[1;37;41m",  # bold white on red
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[34m",
    Severity.INFO: "\033[2m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_MAX_LINE = 110


def _clean(s: object) -> str:
    """Strip control characters (device strings are untrusted and could carry terminal escapes)."""
    return "".join(ch if ch.isprintable() else "?" for ch in str(s))


def render_terminal(result: Result, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    run = result.run
    lines: list[str] = []
    title = f"bacnet-health {__version__} - {run.kind} summary"
    lines.append(paint(title, _BOLD))
    lines.append("=" * len(title))
    meta = []
    if run.site:
        meta.append(f"Site: {_clean(run.site)}")
    meta.append(f"Started: {_clean(run.started)}")
    if run.vantage is not None:
        src = f" ({_clean(run.vantage_source)})" if run.vantage_source else ""
        meta.append(f"Vantage: {run.vantage.value}{src}")
    lines.append("   ".join(meta))
    remote = sum(1 for d in result.devices if d.remote)
    dev = f"Devices: {len(result.devices)}" + (f" ({remote} remote)" if remote else "")
    lines.append(f"{dev}   BBMDs: {sum(1 for b in result.bbmds if b.status == 'bbmd')}")
    if run.incomplete:
        lines.append(paint("Run incomplete: results are partial.", _ANSI[Severity.HIGH]))
    lines.append("")

    counts = result.severity_counts()
    parts = [paint(f"{counts[s.value]} {s.value}", _ANSI[s]) if counts[s.value] else f"0 {s.value}" for s in Severity]
    lines.append("Findings: " + ", ".join(parts))
    for f in result.sorted_findings():
        label = f"{f.severity.value.upper():<8}"
        text = f"{f.id:<10}{_clean(f.title)}"
        if f.subject:
            text += f" - {_clean(f.subject)}"
        if len(text) > _MAX_LINE:
            text = text[: _MAX_LINE - 3] + "..."
        lines.append(f"  {paint(label, _ANSI[f.severity])}  {text}")
    if not result.findings:
        lines.append("  (none)")
    lines.append("")
    n = len(result.checks_not_performed)
    lines.append(f"Checks not performed: {n}" + (" (see the report for reasons)" if n else ""))
    return "\n".join(lines) + "\n"
