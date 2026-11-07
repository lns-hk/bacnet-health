"""The layer the CLI and the GUI share for active work: listen, scan, audit (see docs/dev/runner-api.md).

Neither front end contains BACnet logic; both call :func:`prepare` and drive the returned :class:`Session`.
"""

from __future__ import annotations

import ipaddress
import os
import platform
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass, field, fields
from typing import Any, Callable

from bacnet_health.model import Budget, Result, utcnow_iso

ProgressCb = Callable[[dict], None]

CROSS_SUBNET_RISK = {
    "read_remote": (
        "Read devices behind routers",
        "Requests will travel through BACnet routers onto slower field networks (for example MS/TP). bacnet-health "
        "sends at most one request at a time per network, but a congested field bus can still slow down control. "
        "Only enable this if the site has agreed.",
    ),
    "follow_bdt": (
        "Read BBMD peers on other subnets",
        "One Read-BDT request will be sent to every peer BBMD listed in this subnet's tables. These are other "
        "subnets, possibly other buildings. Only enable this if your authorisation covers them.",
    ),
    "fdr": (
        "Register as a foreign device",
        "The BBMD will accept bacnet-health as a foreign device for 60 seconds and forward its Who-Is requests to "
        "every subnet in its table, possibly to other buildings. This creates a short-lived entry in the BBMD's "
        "foreign-device table. Only enable this if your authorisation covers the whole BACnet internetwork.",
    ),
}


class RunnerError(Exception):
    """Plain-English, user-facing error."""


@dataclass
class RunnerOptions:
    kind: str = "audit"
    interface: str | None = None
    bind: str | None = None
    port: int = 47808
    targets: list[str] = field(default_factory=list)
    whois_gap_s: float = 1.0
    max_req_per_s: float = 5.0
    apdu_timeout_s: float = 3.0
    apdu_retries: int = 1
    read_properties: bool = True
    bbmd_audit: bool = True
    read_remote: bool = False
    follow_bdt: bool = False
    fdr_bbmd: str | None = None
    listen_s: float = 600.0
    known_writers: list[str] = field(default_factory=list)
    clock_synced: bool | None = None  # None = check automatically where possible
    site: str = ""
    client: str = ""
    prepared_by: str = ""
    org: str = ""
    authorised_by: str = ""
    scope_note: str = ""

    @classmethod
    def from_args(cls, args: Any) -> "RunnerOptions":
        o = cls(kind=args.command)
        if getattr(args, "profile", None):
            from bacnet_health.profile import Profile

            o = cls.from_profile(Profile.load(args.profile), args.command)
        for name in ("interface", "bind", "port", "read_remote", "follow_bdt"):
            v = getattr(args, name, None)
            if v not in (None, False):
                setattr(o, name, v)
        if getattr(args, "target", None):
            o.targets = list(args.target)
        if getattr(args, "fdr", None):
            o.fdr_bbmd = args.fdr
        if getattr(args, "duration", None):
            o.listen_s = float(args.duration)
        if getattr(args, "whois_gap", None):
            o.whois_gap_s = args.whois_gap
        if getattr(args, "rate", None):
            o.max_req_per_s = args.rate
        if getattr(args, "no_read", False):
            o.read_properties = False
        if getattr(args, "no_bbmd", False):
            o.bbmd_audit = False
        return o

    @classmethod
    def from_profile(cls, profile: Any, kind: str = "audit") -> "RunnerOptions":
        names = {f.name for f in fields(cls)}
        kw = {n: getattr(profile, n) for n in names if hasattr(profile, n)}
        kw["kind"] = kind
        kw["listen_s"] = float(getattr(profile, "listen_minutes", 10.0)) * 60
        kw["targets"] = list(getattr(profile, "targets", []))
        kw["known_writers"] = list(getattr(profile, "known_writers", []))
        return cls(**kw)


# --------------------------------------------------------------------------------------------- interfaces
def interface_choices():
    from bacnet_health.active.iface import auto_pick, list_interfaces

    return auto_pick(list_interfaces())


def _resolve_iface(opts: RunnerOptions):
    from bacnet_health.active.iface import iface_from_cidr, list_interfaces

    if opts.bind:
        try:
            return iface_from_cidr(opts.bind)
        except ValueError as exc:
            raise RunnerError(f"'{opts.bind}' is not a valid address with prefix (example: 192.0.2.10/24).") from exc
    ifaces = list_interfaces()
    if opts.interface:
        for i in ifaces:
            if i.name == opts.interface or i.ip == opts.interface:
                return i
        raise RunnerError(f"No IPv4 interface called '{opts.interface}' was found. Run 'bacnet-health interfaces' "
                          f"to see the list.")
    from bacnet_health.active.iface import auto_pick

    best, _, reasons = auto_pick(ifaces)
    if best is None:
        raise RunnerError("No suitable network interface is up. " + " ".join(reasons))
    return best


# --------------------------------------------------------------------------------------------- pre-flight
def clock_sync_state() -> tuple[bool | None, str]:
    """Best-effort, no admin: is this computer's clock synchronised automatically?"""
    try:
        if sys.platform == "win32":
            out = subprocess.run(["w32tm", "/query", "/status"], capture_output=True, text=True, timeout=5).stdout
            if "Source" in out and "Local CMOS Clock" not in out and "Free-running" not in out:
                return True, "Windows Time service is synchronising with a time source."
            return (False, "Windows Time service is not synchronised.") if out else (None, "Unknown.")
        if sys.platform.startswith("linux") and shutil.which("timedatectl"):
            out = subprocess.run(["timedatectl", "show", "-p", "NTPSynchronized", "--value"], capture_output=True,
                                 text=True, timeout=5).stdout.strip()
            return (out == "yes"), f"timedatectl NTPSynchronized={out or 'unknown'}"
        if sys.platform == "darwin":
            out = subprocess.run(["/usr/bin/pgrep", "-x", "timed"], capture_output=True, text=True, timeout=5)
            if out.returncode == 0:
                return None, "macOS time daemon is running, but sync state cannot be confirmed without admin rights."
    except (OSError, subprocess.SubprocessError):
        pass
    return None, "Clock synchronisation state is unknown."


def preflight(opts: RunnerOptions) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    try:
        iface = _resolve_iface(opts)
        st = "warning" if (iface.has_default_route or iface.wireless_guess or not iface.is_up) else "ok"
        msg = f"{iface.name} {iface.ip}/{iface.prefix}, broadcast {iface.broadcast}"
        if iface.has_default_route:
            msg += ". This interface carries the computer's default route; make sure it is the building network"
        if iface.wireless_guess:
            msg += ". This looks like Wi-Fi; BMS networks are normally wired"
        checks.append({"name": "Network interface", "status": st, "message": msg + "."})
    except RunnerError as exc:
        checks.append({"name": "Network interface", "status": "error", "message": str(exc)})
        iface = None
    from bacnet_health.active.transport import port_owners

    try:
        owners = port_owners(opts.port)
    except Exception:  # noqa: BLE001 - best effort
        owners = []
    if owners:
        checks.append({"name": f"UDP port {opts.port}", "status": "error",
                       "message": f"Port {opts.port} is in use by {', '.join(map(str, owners))}. Close that program "
                                  f"(BMS workstation, another scanner) or choose another port."})
    else:
        checks.append({"name": f"UDP port {opts.port}", "status": "ok", "message": "Free."})
    if iface is not None:
        try:
            from bacnet_health.active.iface import check_egress

            check_egress(iface, iface.broadcast)
            checks.append({"name": "Routing", "status": "ok",
                           "message": f"Broadcasts to {iface.broadcast} leave through {iface.name}."})
        except Exception as exc:  # noqa: BLE001 - EgressMismatch or OS errors
            checks.append({"name": "Routing", "status": "error", "message": str(exc)})
    if sys.platform == "win32":
        try:
            from bacnet_health.active._win import firewall_inbound_status

            fw = firewall_inbound_status(sys.executable, opts.port)
            status = {"allowed": "ok", "blocked": "error", "unknown": "unknown"}.get(fw.get("status"), "unknown")
            checks.append({"name": "Windows Firewall", "status": status,
                           "message": fw.get("summary") or "; ".join(fw.get("reasons", [])) or fw.get("status", "")})
        except Exception as exc:  # noqa: BLE001
            checks.append({"name": "Windows Firewall", "status": "unknown", "message": f"Could not check: {exc}"})
    synced, why = (opts.clock_synced, "Confirmed by the user.") if opts.clock_synced is not None else clock_sync_state()
    checks.append({"name": "Computer clock", "status": "ok" if synced else ("warning" if synced is False else "unknown"),
                   "message": why + ("" if synced else " Device clock checks will be skipped.")})
    return checks


# --------------------------------------------------------------------------------------------- session
def _norm_progress(ev: dict) -> dict:
    """Map scanner/listener events onto the documented runner events (extra keys are kept)."""
    t = ev.get("type")
    phase_names = {"discovery": "discover", "targets": "discover", "reads": "read", "bbmd-audit": "bbmd",
                   "listen": "listen", "done": "done"}
    if t == "phase":
        return {**ev, "phase": phase_names.get(ev.get("phase"), ev.get("phase")),
                "message": ev.get("message") or str(ev.get("phase", "")).replace("-", " ").capitalize()}
    if t == "whois":
        planned = ev.get("planned") or 0
        frac = (ev.get("sent", 0) / planned) if planned else 0.0
        return {**ev, "type": "progress", "fraction": min(1.0, frac),
                "message": f"Discovery: Who-Is {ev.get('low')}-{ev.get('high')}"}
    if t == "done":
        return {**ev, "type": "phase", "phase": "done", "message": "Finished"}
    if t in ("progress", "device", "log", "budget-exceeded"):
        return ev
    return {**ev, "type": "log", "level": "info", "message": ev.get("message") or str(ev)}


def progress_line(p: dict) -> str:
    t = p.get("type")
    if t == "device":
        return f"  device {p.get('instance')} at {p.get('address')}"
    if t == "progress":
        return f"  {p.get('message', '')} ({p.get('fraction', 0) * 100:.0f}%)"
    if t == "phase":
        return f"== {p.get('message') or p.get('phase')}"
    if t == "budget-exceeded":
        return f"!! {p.get('message')}"
    return f"  {p.get('message', '')}"


class Session:
    def __init__(self, kind: str, opts: RunnerOptions, iface: Any, test_hooks: dict | None = None) -> None:
        from bacnet_health.active.scan import ScanOptions, Scanner
        from bacnet_health.active.transport import BacnetTransport, PortInUse

        if kind not in ("scan", "listen", "audit"):
            raise RunnerError(f"Unknown run type '{kind}'.")
        self.kind, self.opts, self.iface = kind, opts, iface
        self.cancel_event = threading.Event()
        self._result: Result | None = None
        self._partial: list[Result] = []
        self._confirmed: dict[str, dict] = {}
        synced, _ = (opts.clock_synced, "") if opts.clock_synced is not None else clock_sync_state()
        self.scan_opts = ScanOptions(
            port=opts.port, interface=iface.name, local_ip=iface.ip, netmask=iface.netmask,
            broadcast=iface.broadcast, subnet=iface.network, targets=list(opts.targets),
            whois_gap_s=opts.whois_gap_s, max_req_per_s=opts.max_req_per_s, apdu_timeout_s=opts.apdu_timeout_s,
            apdu_retries=opts.apdu_retries, read_properties=opts.read_properties, bbmd_audit=opts.bbmd_audit,
            read_remote=opts.read_remote, follow_bdt=opts.follow_bdt, fdr_bbmd=opts.fdr_bbmd,
            host_ntp_synced=synced,
        )
        hooks = test_hooks or {}
        for k, v in hooks.get("scan_options", {}).items():
            setattr(self.scan_opts, k, v)
        try:
            bind_ip = iface.ip if sys.platform == "win32" else "0.0.0.0"
            tkw = {"iface": iface, "rate": opts.max_req_per_s, "cancel": self.cancel_event}
            if "transport" in hooks:  # tests only: localhost simulator fan-out, never a real network
                bind_ip = hooks["transport"].pop("bind_ip", "127.0.0.1")
                tkw = {**hooks["transport"], "rate": hooks["transport"].get("rate", 300), "cancel": self.cancel_event}
            self.transport = BacnetTransport(bind_ip, opts.port, **tkw)
            self.scan_opts.port = self.transport.port
        except PortInUse as exc:
            raise RunnerError(str(exc)) from exc
        except OSError as exc:
            raise RunnerError(f"Could not open UDP port {opts.port} on {iface.name}: {exc}") from exc
        except Exception as exc:  # noqa: BLE001 - EgressMismatch etc. carry plain-English text
            raise RunnerError(str(exc)) from exc
        self.scanner = Scanner(self.transport, self.scan_opts, cancel=self.cancel_event) if kind != "listen" else None
        self.budget: Budget = self.scanner.plan() if self.scanner else Budget()
        if kind != "scan":
            self.budget.notes.append(f"Listen for {opts.listen_s / 60:.0f} min first (sends nothing).")

    # ---- description ---------------------------------------------------------------------------------------
    def describe(self) -> str:
        i, b = self.iface, self.budget
        lines = [f"Will broadcast on {i.broadcast} via {i.name} ({i.ip}/{i.prefix}), UDP port {self.opts.port}."]
        if self.kind in ("listen", "audit"):
            lines.append(f"Listen: {self.opts.listen_s / 60:.0f} minutes, nothing is sent.")
        if self.kind in ("scan", "audit"):
            lines += [
                f"Scan: up to {b.whois_planned} ranged Who-Is requests, at least {self.opts.whois_gap_s:g} s apart.",
                f"Property reads: about {b.reads_planned} requests (estimate until devices are found), at most "
                f"{self.opts.max_req_per_s:g} per second, one at a time per device.",
                f"BBMD checks: about {b.bvlc_probes_planned} Read-BDT/Read-FDT requests.",
                f"Estimated duration of the scan: {b.est_duration_s / 60:.1f} minutes; peak "
                f"{b.peak_pps_planned:.1f} packets per second.",
                "Only Who-Is, ReadProperty, ReadPropertyMultiple, Read-BDT and Read-FDT are sent. Nothing is written.",
            ]
        lines += [f"Note: {n}" for n in b.notes]
        return "\n".join(lines)

    def dry_run_text(self) -> str:
        from bacnet_health.active.scan import WhoisChunker
        from bacnet_health.wire.apdu import encode_who_is
        from bacnet_health.wire.bvlc import encode_original_broadcast, encode_read_bdt
        from bacnet_health.wire.npdu import encode_npdu

        if self.kind == "listen":
            return "Listen mode sends no packets."
        o = self.scan_opts
        plan = WhoisChunker.sparse_plan(o.whois_low, o.whois_high, o.whois_initial_chunk, o.whois_min_chunk,
                                        o.whois_max_chunk)
        out = [f"Who-Is plan (if the network is sparse): {len(plan)} requests"]
        for lo, hi in plan[:5]:
            frame = encode_original_broadcast(encode_npdu(encode_who_is(lo, hi)))
            out.append(f"  -> {self.iface.broadcast}:{self.opts.port}  Who-Is {lo}-{hi}  {frame.hex(' ')}")
        if len(plan) > 5:
            out.append(f"  ... {len(plan) - 5} more ranges, up to {plan[-1][1]}")
        out.append(f"Then, per device found: ReadProperty / ReadPropertyMultiple of the Device object only.")
        out.append(f"BBMD check, per device found: Read-BDT  {encode_read_bdt().hex(' ')}")
        return "\n".join(out)

    # ---- confirmations -------------------------------------------------------------------------------------
    def required_confirmations(self) -> list[tuple[str, str, str]]:
        out = []
        if self.kind == "listen":
            return out
        if self.opts.read_remote:
            out.append(("read_remote", "routers", CROSS_SUBNET_RISK["read_remote"][1]))
        if self.opts.follow_bdt:
            out.append(("follow_bdt", "peers", CROSS_SUBNET_RISK["follow_bdt"][1]))
        if self.opts.fdr_bbmd:
            out.append(("fdr", self.opts.fdr_bbmd.split(":")[0], CROSS_SUBNET_RISK["fdr"][1]))
        return [(a, t if t not in ("routers", "peers") else self.iface.ip, r) for a, t, r in out]

    def cross_subnet_actions(self, args: Any = None) -> list[tuple[str, str, str | None]]:
        return [(CROSS_SUBNET_RISK[a][0], t, None) for a, t, _ in self.required_confirmations()]

    def confirm(self, action_id: str, target: str, user: str) -> None:
        aid = next((a for a, (title, _) in CROSS_SUBNET_RISK.items() if action_id in (a, title)), action_id)
        rec = {"action": aid, "target": target, "user": user, "at": utcnow_iso()}
        self._confirmed[aid] = rec
        self.scan_opts.confirmations.append(rec)
        if aid == "fdr":
            self.scan_opts.fdr_confirmed_ip = target

    def _check_confirmed(self) -> None:
        missing = [a for a, _, _ in self.required_confirmations() if a not in self._confirmed]
        if missing:
            raise RunnerError("Not confirmed: " + ", ".join(CROSS_SUBNET_RISK[m][0] for m in missing)
                              + ". Type the target address to confirm before starting.")

    # ---- execution -----------------------------------------------------------------------------------------
    def run(self, progress: ProgressCb | None = None) -> Result:
        from bacnet_health.active.listen import listen

        self._check_confirmed()
        cb = (lambda ev: progress(_norm_progress(ev))) if progress else None
        results: list[Result] = []
        try:
            if self.kind in ("listen", "audit"):
                if cb:
                    cb({"type": "phase", "phase": "listen", "message": "Listening (nothing is sent)"})
                lr = listen(self.transport, self.opts.listen_s, cb, self.cancel_event,
                            known_writers=self.opts.known_writers)
                results.append(lr)
                self._partial = list(results)
                if self.scanner is not None:
                    cands = [f"{b.ip}:{b.port}" for b in lr.bbmds]
                    self.scan_opts.passive_bbmd_candidates = cands
                    self.scan_opts.local_bbmd_known = bool(cands)
            if self.scanner is not None and not self.cancel_event.is_set():
                if cb:
                    self.scanner.progress = cb
                try:
                    results.append(self.scanner.run())
                except Exception as exc:  # noqa: BLE001 - surface plain-English refusal messages
                    if type(exc).__name__ in ("EgressMismatch", "ScanRefused"):
                        raise RunnerError(str(exc)) from exc
                    raise
                self._partial = list(results)
        finally:
            self._result = self._finish(results)
        if cb:
            cb({"type": "phase", "phase": "done", "message": "Finished"})
        return self._result

    def _finish(self, results: list[Result]) -> Result:
        from bacnet_health.report.merge import merge_results

        if not results:
            from bacnet_health.model import RunInfo

            res = Result(run=RunInfo(kind=self.kind, incomplete=True))
        else:
            res = merge_results(results) if len(results) > 1 else results[0]
        r = res.run
        r.kind = self.kind
        r.interface, r.local_ip, r.netmask = self.iface.name, self.iface.ip, self.iface.netmask
        r.broadcast, r.port = self.iface.broadcast, self.opts.port
        for k in ("site", "client", "prepared_by", "org", "authorised_by", "scope_note"):
            if getattr(self.opts, k):
                setattr(r, k, getattr(self.opts, k))
        known = {(c.get("action"), c.get("at")) for c in r.confirmations}
        r.confirmations += [c for c in self._confirmed.values() if (c["action"], c["at"]) not in known]
        if self.cancel_event.is_set():
            r.incomplete = True
            res.limitations.append("The run was stopped before it finished; results are partial.")
        r.command = f"{self.kind} via {self.iface.name}"
        r.finished = r.finished or utcnow_iso()
        res.tool["host"] = platform.system()
        return res

    def cancel(self) -> None:
        self.cancel_event.set()

    def result(self) -> Result:
        return self._result if self._result is not None else self._finish(self._partial)

    def close(self) -> None:
        try:
            self.transport.close()
        except Exception:  # noqa: BLE001
            pass


def prepare(kind: str, opts: RunnerOptions, *, test_hooks: dict | None = None) -> Session:
    for t in opts.targets + ([opts.fdr_bbmd] if opts.fdr_bbmd else []):
        try:
            ipaddress.ip_address(t.split(":")[0])
        except ValueError as exc:
            raise RunnerError(f"'{t}' is not a valid IPv4 address.") from exc
    iface = _resolve_iface(opts)
    opts.kind = kind
    return Session(kind, opts, iface, test_hooks)


__all__ = ["RunnerError", "RunnerOptions", "Session", "interface_choices", "preflight", "prepare", "progress_line",
           "clock_sync_state", "CROSS_SUBNET_RISK"]
_ = os  # keep import for future platform paths
