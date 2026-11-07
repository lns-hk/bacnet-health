"""Scan profiles (.bhprofile): every option the CLI/GUI exposes, plus branding and rules-of-engagement defaults.

A consultant prepares a profile; an onsite engineer double-clicks it and the GUI opens the health-check wizard.
``locked`` lists option names the GUI must not let the user change.

Cross-subnet actions (read_remote, follow_bdt, fdr_bbmd) are never "pre-confirmed" by a profile: the GUI/CLI still
asks the user to type the target IP at run time (design D19).
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from typing import Any

PROFILE_VERSION = 1


@dataclass
class Profile:
    # site / rules of engagement
    site: str = ""
    client: str = ""
    prepared_by: str = ""
    org: str = ""
    authorised_by: str = ""
    scope_note: str = ""
    # branding
    logo_path: str | None = None
    accent: str = "#1f4e79"
    # network
    interface: str | None = None  # None = auto-pick (user confirms)
    port: int = 47808
    targets: list[str] = field(default_factory=list)  # unicast targets
    # active scan
    listen_minutes: float = 10.0
    do_scan: bool = True
    whois_gap_s: float = 1.0
    max_req_per_s: float = 5.0
    apdu_timeout_s: float = 3.0
    apdu_retries: int = 1
    read_properties: bool = True
    bbmd_audit: bool = True
    read_remote: bool = False
    follow_bdt: bool = False
    fdr_bbmd: str | None = None
    # analysis
    known_writers: list[str] = field(default_factory=list)  # IPs of authorised engineering workstations
    redact: bool = False
    # GUI
    locked: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps({"bhprofile": PROFILE_VERSION, **asdict(self)}, indent=2)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Profile":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in known})

    @classmethod
    def load(cls, path: str) -> "Profile":
        with open(path, encoding="utf-8") as fh:
            d = json.load(fh)
        if not isinstance(d, dict) or "bhprofile" not in d:
            raise ValueError(f"{path} is not a bacnet-health profile")
        return cls.from_dict(d)

    def is_locked(self, name: str) -> bool:
        return name in self.locked
