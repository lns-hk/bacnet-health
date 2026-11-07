"""A fake ``bacnet_health.runner`` for GUI tests and the screenshot script.

Implements the documented interface (docs/dev/runner-api.md) without opening any socket: interface_choices,
preflight, prepare -> Session (describe, dry_run_text, required_confirmations, confirm, run, cancel, result, close),
RunnerOptions, RunnerError, progress_line. ``Session.run`` emits the documented progress events and returns a Result
built from the synthetic demo capture.
"""

from __future__ import annotations

import os
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from bacnet_health.active.iface import Iface
from bacnet_health.analysis.analyze import analyze_file
from bacnet_health.model import Budget, Result, utcnow_iso
from bacnet_health.testing.synth import demo_capture


class RunnerError(Exception):
    pass


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
    site: str = ""
    client: str = ""
    prepared_by: str = ""
    org: str = ""
    authorised_by: str = ""
    scope_note: str = ""

    @classmethod
    def from_profile(cls, profile: Any, kind: str = "audit") -> "RunnerOptions":
        names = set(cls.__dataclass_fields__)
        kw = {k: getattr(profile, k) for k in names if hasattr(profile, k)}
        kw["listen_s"] = float(profile.listen_minutes) * 60.0
        kw["kind"] = kind
        kw["targets"] = list(profile.targets)
        kw["known_writers"] = list(profile.known_writers)
        return cls(**kw)


WIRED = Iface(name="en7", ip="192.0.2.50", netmask="255.255.255.0", prefix=24, broadcast="192.0.2.255",
              description="USB 10/100/1000 LAN")
WIFI = Iface(name="en0", ip="198.51.100.23", netmask="255.255.255.0", prefix=24, broadcast="198.51.100.255",
             has_default_route=True, wireless_guess=True, description="Wi-Fi")

_demo_lock = threading.Lock()
_demo_path: str | None = None


def demo_path() -> str:
    global _demo_path
    with _demo_lock:
        if _demo_path is None or not os.path.exists(_demo_path):
            d = tempfile.mkdtemp(prefix="bh-gui-fake-")
            _demo_path = demo_capture(os.path.join(d, "demo.pcap"))
        return _demo_path


class FakeSession:
    def __init__(self, runner: "FakeRunner", kind: str, opts: RunnerOptions):
        self.runner = runner
        self.kind = kind
        self.opts = opts
        self.iface = next((i for i in runner.ifaces if i.name == opts.interface), runner.ifaces[0])
        self.budget = Budget(whois_planned=12, reads_planned=60, bvlc_probes_planned=10, peak_pps_planned=5.0,
                             est_duration_s=opts.listen_s + 90)
        self.confirmations: list[dict] = []
        self._cancel = threading.Event()
        self._partial: Result | None = None
        self.closed = False
        self.ran = False

    def describe(self) -> str:
        b = self.budget
        lines = [f"Will broadcast on {self.iface.broadcast} via {self.iface.name} "
                 f"({self.iface.ip}/{self.iface.prefix}), UDP port {self.opts.port}.",
                 f"First listens for {int(self.opts.listen_s // 60)} minutes without sending anything."]
        if self.kind != "listen":
            lines += [f"Then sends at most {b.whois_planned} Who-Is (at least {self.opts.whois_gap_s:g} s apart) and "
                      f"about {b.reads_planned} read requests (at most {self.opts.max_req_per_s:g} per second).",
                      f"BBMD checks: up to {b.bvlc_probes_planned} table reads.",
                      f"Peak rate {b.peak_pps_planned:g} packets per second. Estimated duration "
                      f"{int(b.est_duration_s // 60)} min {int(b.est_duration_s % 60)} s."]
        return "\n".join(lines)

    def dry_run_text(self) -> str:
        return ("# Who-Is 0-4194303 (first chunk)\n81 0b 00 0c 01 20 ff ff 00 ff 10 08\n"
                "# Read-BDT\n81 02 00 04\n")

    def required_confirmations(self) -> list[tuple[str, str, str]]:
        out = []
        if self.opts.read_remote:
            out.append(("read_remote", "192.0.2.40", "Reads devices behind router 192.0.2.40 on network 5."))
        if self.opts.follow_bdt:
            out.append(("follow_bdt", "198.51.100.2", "Reads the BDT of peer BBMD 198.51.100.2."))
        if self.opts.fdr_bbmd:
            out.append(("fdr", self.opts.fdr_bbmd, "Registers as a foreign device; the BBMD keeps an entry for "
                                                   "60 s."))
        return out

    def cross_subnet_actions(self, args):  # CLI helper, unused by the GUI
        return []

    def confirm(self, action_id: str, target: str, user: str) -> None:
        self.confirmations.append({"action": action_id, "target": target, "user": user, "at": utcnow_iso()})

    def _build(self, incomplete: bool) -> Result:
        res = analyze_file(demo_path(), known_writers=self.opts.known_writers)
        res.run.kind = self.kind
        for k in ("site", "client", "prepared_by", "org", "authorised_by", "scope_note"):
            setattr(res.run, k, getattr(self.opts, k))
        res.run.interface = self.iface.name
        res.run.local_ip = self.iface.ip
        res.run.broadcast = self.iface.broadcast
        res.run.port = self.opts.port
        res.run.confirmations = list(self.confirmations)
        res.run.incomplete = incomplete
        res.budget = self.budget
        return res

    def run(self, progress: Callable[[dict], None] | None = None) -> Result:
        self.ran = True
        cb = progress or (lambda p: None)
        delay = self.runner.step_delay
        phases = ["listen", "report"] if self.kind == "listen" else ["listen", "discover", "read", "bbmd", "report"]
        names = {"listen": "Listening", "discover": "Discovering devices", "read": "Reading device properties",
                 "bbmd": "Auditing BBMDs", "report": "Building the report"}
        n_dev = 0
        for ph in phases:
            if self._cancel.is_set():
                break
            cb({"type": "phase", "phase": ph, "message": names[ph]})
            for k in range(self.runner.steps):
                if self._cancel.wait(delay):
                    break
                cb({"type": "progress", "fraction": (k + 1) / self.runner.steps, "message": f"{names[ph]}…"})
                while ph == "discover" and n_dev < self.runner.n_devices * (k + 1) / self.runner.steps:
                    cb({"type": "device", "instance": 1000 + n_dev, "address": f"192.0.2.{20 + n_dev}:47808"})
                    n_dev += 1
            if ph == "read" and self.runner.budget_warning:
                cb({"type": "budget-exceeded", "message": "Traffic is 25% above the preview."})
            cb({"type": "log", "level": "info", "message": f"{names[ph]} finished"})
        cancelled = self._cancel.is_set()
        self._partial = self._build(incomplete=cancelled)
        if not cancelled:
            cb({"type": "phase", "phase": "done", "message": "Finished"})
        return self._partial

    def cancel(self) -> None:
        self._cancel.set()

    def result(self) -> Result:
        return self._partial or self._build(incomplete=True)

    def close(self) -> None:
        self.closed = True


class FakeRunner:
    """Module-like fake. Pass an instance wherever the GUI expects the ``runner`` module."""

    RunnerError = RunnerError
    RunnerOptions = RunnerOptions

    def __init__(self, ifaces: list[Iface] | None = None, preflight_items: list[dict] | None = None,
                 step_delay: float = 0.002, steps: int = 4, n_devices: int = 9, prepare_error: str | None = None,
                 budget_warning: bool = False):
        self.ifaces = ifaces if ifaces is not None else [WIRED, WIFI]
        self.preflight_items = preflight_items
        self.step_delay = step_delay
        self.steps = steps
        self.n_devices = n_devices
        self.prepare_error = prepare_error
        self.budget_warning = budget_warning
        self.sessions: list[FakeSession] = []
        self.prepared_opts: list[RunnerOptions] = []

    def interface_choices(self):
        if not self.ifaces:
            return None, [], ["No usable interface is up. Connect the laptop to the BMS network and try again."]
        best = self.ifaces[0]
        reasons = [f"Picked {best.label()}: wired, private address, no default route.",
                   f"Broadcasts will go to {best.broadcast} only (never 255.255.255.255).",
                   "Not picked: en0 (Wi-Fi), it carries the default route."]
        return best, list(self.ifaces), reasons

    def preflight(self, opts: RunnerOptions) -> list[dict]:
        if self.preflight_items is not None:
            return self.preflight_items
        return [
            {"name": "UDP port free", "status": "ok", "message": f"Port {opts.port} is free on {opts.interface}."},
            {"name": "Firewall", "status": "ok", "message": "Inbound UDP is allowed for this program."},
            {"name": "Clock", "status": "warning",
             "message": "The clock could not be checked against a time server (no internet). Times in the "
                        "report use the laptop clock."},
            {"name": "Interface up", "status": "ok", "message": f"{opts.interface} is up with a cable connected."},
        ]

    def prepare(self, kind: str, opts: RunnerOptions) -> FakeSession:
        if self.prepare_error:
            raise RunnerError(self.prepare_error)
        self.prepared_opts.append(opts)
        s = FakeSession(self, kind, opts)
        self.sessions.append(s)
        return s

    @staticmethod
    def progress_line(p: dict) -> str:
        return str(p.get("message", p))
