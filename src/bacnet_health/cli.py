"""Command-line interface. Onsite engineers use the GUI; the CLI is for consultants and scripting (design D21).

Every sub-command writes a JSON result first; ``report`` turns results into HTML.
"""

from __future__ import annotations

import argparse
import os
import re
import secrets
import sys
from datetime import datetime, timezone
from typing import Sequence

from bacnet_health import __version__
from bacnet_health.model import Result, Vantage

DURATION_RE = re.compile(r"^(\d+(?:\.\d+)?)\s*([smh]?)$")


def parse_duration(text: str) -> float:
    m = DURATION_RE.match(text.strip().lower())
    if not m:
        raise argparse.ArgumentTypeError(f"invalid duration '{text}' (examples: 90s, 10m, 1h)")
    value, unit = float(m.group(1)), m.group(2) or "s"
    return value * {"s": 1, "m": 60, "h": 3600}[unit]


def default_name(kind: str, ext: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"bacnet-health-{kind}-{stamp}.{ext}"


def _write_outputs(res: Result, args: argparse.Namespace) -> None:
    from bacnet_health.report.terminal import render_terminal

    out = args.output or default_name(res.run.kind, "json")
    res.save(out)
    if not getattr(args, "quiet", False):
        print(render_terminal(res, color=sys.stdout.isatty() and not os.environ.get("NO_COLOR")))
    print(f"JSON written to {out}")
    if getattr(args, "html", None):
        _render_html_file([res], args.html, branding_path=getattr(args, "branding", None))


def _render_html_file(results: list[Result], path: str, *, branding_path: str | None = None,
                      diff_path: str | None = None, redact: bool = False) -> None:
    from bacnet_health.report.branding import Branding
    from bacnet_health.report.diff import diff_results
    from bacnet_health.report.html import render_html
    from bacnet_health.report.merge import merge_results

    res = results[0] if len(results) == 1 else merge_results(results)
    diff = diff_results(Result.load(diff_path), res) if diff_path else None
    if redact:
        from bacnet_health.report.redact import redact_result

        res = redact_result(res, secrets.token_bytes(32))
        diff = None  # a diff against unredacted data would leak; re-run with both inputs redacted if needed
    branding = Branding.load(branding_path) if branding_path else Branding()
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_html(res, branding, diff))
    print(f"HTML report written to {path}")


# --------------------------------------------------------------------------------------------- sub-commands
def cmd_analyze(args: argparse.Namespace) -> int:
    from bacnet_health.analysis.analyze import analyze_file

    vantage = None if args.vantage == "auto" else Vantage(args.vantage)
    res = analyze_file(args.capture, vantage_override=vantage, known_writers=args.known_writer,
                       progress=lambda p: print(f"  ... {p['frames']} frames", file=sys.stderr))
    _write_outputs(res, args)
    if args.redact_pcap:
        from bacnet_health.report.redact import redact_pcap

        stats = redact_pcap(args.capture, args.redact_pcap, secrets.token_bytes(32))
        print(f"Redacted capture written to {args.redact_pcap} ({stats})")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    results = [Result.load(p) for p in args.inputs]
    _render_html_file(results, args.output or default_name("report", "html"), branding_path=args.branding,
                      diff_path=args.diff, redact=args.redact)
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    from bacnet_health.testing.synth import demo_capture

    os.makedirs(args.dir, exist_ok=True)
    pcap = demo_capture(os.path.join(args.dir, "demo-capture.pcap"))
    print(f"Synthetic demo capture written to {pcap}")
    ns = argparse.Namespace(capture=pcap, vantage="auto", known_writer=[], redact_pcap=None,
                            output=os.path.join(args.dir, "demo-result.json"),
                            html=os.path.join(args.dir, "demo-report.html"), branding=None, quiet=False)
    return cmd_analyze(ns)


def cmd_interfaces(args: argparse.Namespace) -> int:
    from bacnet_health.active.iface import auto_pick, list_interfaces

    ifaces = list_interfaces()
    best, ranked, reasons = auto_pick(ifaces)
    for i in ranked:
        mark = "*" if best is not None and i.name == best.name and i.ip == best.ip else " "
        print(f"{mark} {i.name:<16} {i.ip:<15} /{i.prefix:<3} bcast {i.broadcast or '-':<15} "
              f"{'up' if i.is_up else 'down':<4} {'default-route' if i.has_default_route else ''}"
              f"{' wireless?' if i.wireless_guess else ''}")
    for r in reasons:
        print(f"  - {r}")
    return 0


def _confirm(prompt: str) -> bool:
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _typed_confirm(action: str, target: str, flag_value: str | None) -> bool:
    """Cross-subnet actions need the target typed back (or the long explicit flag)."""
    if flag_value is not None:
        return flag_value == target
    if not sys.stdin.isatty():
        print(f"Refusing {action}: needs interactive confirmation or --i-understand-this-crosses-subnets={target}",
              file=sys.stderr)
        return False
    print(f"\n{action} sends traffic beyond the local subnet (target {target}).")
    try:
        typed = input(f"Type the target IP address ({target}) to confirm: ").strip()
    except EOFError:
        return False
    return typed == target


def _active_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--interface", help="network interface name (default: auto-pick, you confirm)")
    p.add_argument("--bind", help="bind address with prefix, e.g. 192.0.2.10/24 (instead of --interface)")
    p.add_argument("--port", type=int, default=47808, choices=range(47808, 47824), metavar="47808-47823")
    p.add_argument("--profile", help="scan profile (.bhprofile)")
    p.add_argument("--yes", action="store_true", help="skip the ordinary confirmation (requires --interface/--bind)")
    p.add_argument("-o", "--output", help="JSON output path")
    p.add_argument("--html", help="also write an HTML report")
    p.add_argument("--branding", help="branding JSON for the HTML report")


def _runner_options(args: argparse.Namespace):
    from bacnet_health.runner import RunnerOptions

    return RunnerOptions.from_args(args)


def _run_active(kind: str, args: argparse.Namespace) -> int:
    from bacnet_health import runner

    if args.yes and not (args.interface or args.bind):
        print("--yes needs an explicit --interface or --bind (auto-pick must be confirmed by a person).",
              file=sys.stderr)
        return 2
    opts = _runner_options(args)
    try:
        session = runner.prepare(kind, opts)
    except runner.RunnerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(session.describe())
    if getattr(args, "dry_run", False):
        print(session.dry_run_text())
        return 0
    for action, target, flag in session.cross_subnet_actions(args):
        if not _typed_confirm(action, target, getattr(args, "i_understand_this_crosses_subnets", None)):
            print(f"{action} not confirmed; aborting.", file=sys.stderr)
            return 3
        session.confirm(action, target, user=os.environ.get("USER") or os.environ.get("USERNAME") or "unknown")
    if not args.yes and not _confirm("Proceed? [y/N] "):
        print("Cancelled; nothing was sent.")
        return 1
    try:
        res = session.run(progress=lambda p: print(runner.progress_line(p), file=sys.stderr))
    except KeyboardInterrupt:
        session.cancel()
        res = session.result()
        print("Stopped by user; partial results kept.", file=sys.stderr)
    finally:
        session.close()
    _write_outputs(res, args)
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    return _run_active("scan", args)


def cmd_listen(args: argparse.Namespace) -> int:
    return _run_active("listen", args)


def cmd_audit(args: argparse.Namespace) -> int:
    return _run_active("audit", args)


def cmd_gui(args: argparse.Namespace) -> int:
    try:
        from bacnet_health.gui.app import main as gui_main
    except ImportError as exc:
        if getattr(sys, "frozen", False):
            print("This is the command-line program. Open bacnet-health.exe (or the app) for the GUI.",
                  file=sys.stderr)
        else:
            print(f"The GUI needs PySide6: pip install 'bacnet-health[gui]' ({exc})", file=sys.stderr)
        return 2
    return gui_main([args.profile] if args.profile else [])


# --------------------------------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bacnet-health", description="Read-only BACnet/IP network health check.")
    p.add_argument("--version", action="version", version=f"bacnet-health {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    a = sub.add_parser("analyze", help="analyse a pcap/pcapng capture (passive, sends nothing)")
    a.add_argument("capture")
    a.add_argument("--vantage", choices=["auto", "self", "access", "span"], default="auto",
                   help="where the capture was taken (default: inferred)")
    a.add_argument("--known-writer", action="append", default=[], metavar="IP",
                   help="authorised engineering workstation (repeatable)")
    a.add_argument("--redact-pcap", metavar="OUT", help="also write a redacted copy of the capture")
    a.add_argument("-o", "--output")
    a.add_argument("--html")
    a.add_argument("--branding")
    a.add_argument("-q", "--quiet", action="store_true")
    a.set_defaults(func=cmd_analyze)

    r = sub.add_parser("report", help="render JSON results to one HTML report")
    r.add_argument("inputs", nargs="+")
    r.add_argument("--diff", metavar="PREVIOUS.json", help="compare with an earlier visit")
    r.add_argument("--redact", action="store_true", help="pseudonymise addresses and names for sharing")
    r.add_argument("--branding")
    r.add_argument("-o", "--output")
    r.set_defaults(func=cmd_report)

    s = sub.add_parser("scan", help="active read-only scan of the local subnet")
    _active_common(s)
    s.add_argument("--target", action="append", default=[], metavar="IP", help="unicast target (repeatable)")
    s.add_argument("--whois-gap", type=float, help="seconds between Who-Is (default 1.0)")
    s.add_argument("--rate", type=float, help="max confirmed requests per second (default 5)")
    s.add_argument("--no-read", action="store_true", help="discover only, do not read properties")
    s.add_argument("--no-bbmd", action="store_true", help="skip the BBMD audit")
    s.add_argument("--read-remote", action="store_true", help="read devices behind routers (cross-subnet)")
    s.add_argument("--follow-bdt", action="store_true", help="read BDTs of peer BBMDs (cross-subnet)")
    s.add_argument("--fdr", metavar="BBMD_IP", help="register as a foreign device with this BBMD (cross-subnet)")
    s.add_argument("--i-understand-this-crosses-subnets", metavar="IP", help=argparse.SUPPRESS)
    s.add_argument("--dry-run", action="store_true", help="show the budget and packets, send nothing")
    s.set_defaults(func=cmd_scan)

    li = sub.add_parser("listen", help="listen to BACnet broadcasts (sends nothing)")
    _active_common(li)
    li.add_argument("--duration", type=parse_duration, default=600.0, help="e.g. 90s, 10m (default 10m)")
    li.set_defaults(func=cmd_listen)

    au = sub.add_parser("audit", help="listen, then scan, then report")
    _active_common(au)
    au.add_argument("--listen", dest="duration", type=parse_duration, default=600.0)
    au.add_argument("--target", action="append", default=[], metavar="IP")
    au.add_argument("--read-remote", action="store_true")
    au.add_argument("--follow-bdt", action="store_true")
    au.add_argument("--fdr", metavar="BBMD_IP")
    au.add_argument("--i-understand-this-crosses-subnets", metavar="IP", help=argparse.SUPPRESS)
    au.add_argument("--dry-run", action="store_true")
    au.set_defaults(func=cmd_audit)

    i = sub.add_parser("interfaces", help="list network interfaces and the auto-pick choice")
    i.set_defaults(func=cmd_interfaces)

    d = sub.add_parser("demo", help="generate a synthetic demo capture and report (sends nothing)")
    d.add_argument("--dir", default="bacnet-health-demo")
    d.set_defaults(func=cmd_demo)

    g = sub.add_parser("gui", help="open the graphical interface")
    g.add_argument("profile", nargs="?")
    g.set_defaults(func=cmd_gui)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args) or 0)


if __name__ == "__main__":
    raise SystemExit(main())
