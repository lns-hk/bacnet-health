"""Non-visual helpers: runner loading, profile -> options/branding, capture-tool detection, file names."""

from __future__ import annotations

import getpass
import os
import re
import shutil
import sys
from datetime import datetime
from typing import Any

from bacnet_health.profile import Profile
from bacnet_health.report.branding import Branding

WIRESHARK_URL = "https://www.wireshark.org/download.html"

# Options that send traffic beyond the local subnet (design D19): always need a typed confirmation.
CROSS_SUBNET = ("read_remote", "follow_bdt", "fdr_bbmd")


def load_runner() -> tuple[Any | None, str]:
    """The real runner module, or (None, reason) if this build does not have it."""
    try:
        from bacnet_health import runner  # noqa: PLC0415
    except Exception as exc:  # noqa: BLE001
        return None, f"The network check engine could not be loaded ({type(exc).__name__}: {exc})."
    return runner, ""


def os_user() -> str:
    try:
        return getpass.getuser()
    except Exception:  # noqa: BLE001
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def branding_from(p: Profile) -> Branding:
    return Branding(org=p.org, prepared_by=p.prepared_by, site=p.site, client=p.client,
                    logo_path=p.logo_path or None, accent=p.accent or "#1f4e79")


def kind_for(p: Profile) -> str:
    return "audit" if p.do_scan else "listen"


def build_options(runner: Any, p: Profile, interface: str | None):
    """RunnerOptions from the profile, with the confirmed interface."""
    kind = kind_for(p)
    opts = runner.RunnerOptions.from_profile(p, kind)
    overrides = {
        "kind": kind,
        "interface": interface,
        "listen_s": float(p.listen_minutes) * 60.0,
        "site": p.site, "client": p.client, "prepared_by": p.prepared_by, "org": p.org,
        "authorised_by": p.authorised_by, "scope_note": p.scope_note,
    }
    for k, v in overrides.items():
        if hasattr(opts, k):
            setattr(opts, k, v)
    return opts


def find_capture_tool() -> tuple[str, str] | None:
    """(kind, path) of dumpcap or tcpdump, or None. Looks on PATH and at the usual Wireshark install paths."""
    candidates: list[tuple[str, str]] = []
    for name in ("dumpcap", "tcpdump"):
        found = shutil.which(name)
        if found:
            candidates.append((name, found))
    if sys.platform == "win32":
        for base in (os.environ.get("ProgramFiles", r"C:\Program Files"),
                     os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")):
            candidates.append(("dumpcap", os.path.join(base, "Wireshark", "dumpcap.exe")))
    elif sys.platform == "darwin":
        candidates.append(("dumpcap", "/Applications/Wireshark.app/Contents/MacOS/dumpcap"))
        candidates.append(("tcpdump", "/usr/sbin/tcpdump"))
    else:
        candidates.append(("tcpdump", "/usr/sbin/tcpdump"))
    for kind, path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return kind, path
    return None


def capture_command(kind: str, path: str, interface: str, seconds: int, out: str) -> list[str]:
    """Command line for a time-limited capture of UDP traffic to ``out`` (pcapng for dumpcap, pcap for tcpdump)."""
    seconds = max(1, int(seconds))
    if kind == "dumpcap":
        return [path, "-i", interface, "-f", "udp", "-a", f"duration:{seconds}", "-q", "-w", out]
    return [path, "-i", interface, "-n", "-s", "0", "-G", str(seconds), "-W", "1", "-w", out, "udp"]


def slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "-", text or "").strip("-").lower()
    return s[:40]


def default_filename(p: Profile, what: str, ext: str) -> str:
    stamp = datetime.now().strftime("%Y-%m-%d_%H%M")
    site = slug(p.site)
    return f"bacnet-health_{site + '_' if site else ''}{what}_{stamp}.{ext}"


def documents_dir() -> str:
    d = os.path.join(os.path.expanduser("~"), "Documents")
    return d if os.path.isdir(d) else os.path.expanduser("~")


def redact_available() -> bool:
    try:
        from bacnet_health.report.redact import redact_result  # noqa: F401,PLC0415
    except Exception:  # noqa: BLE001
        return False
    return True


def parse_ip_list(text: str) -> list[str]:
    return [t for t in re.split(r"[\s,;]+", text.strip()) if t]


IPV4_RE = re.compile(r"^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$")


def is_ipv4(s: str) -> bool:
    return bool(IPV4_RE.match(s.strip()))
