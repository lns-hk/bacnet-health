"""Shared data model. Every subsystem (scan, listen, analyze, report, GUI) produces or consumes these types.

All types serialise to plain JSON via ``to_dict`` and back via ``Result.from_dict``. Keep field names stable: they are
the public JSON schema (see ``SCHEMA_VERSION``).
"""

from __future__ import annotations

import dataclasses
import enum
import json
import platform
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from bacnet_health import SCHEMA_VERSION, __version__


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _SEV_RANK[self]


_SEV_RANK = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


class Confidence(str, enum.Enum):
    OBSERVED = "observed"
    INFERRED = "inferred"


class Vantage(str, enum.Enum):
    """Where traffic was observed from. Ordered: SELF < ACCESS < SPAN."""

    SELF = "self"
    ACCESS = "access"
    SPAN = "span"

    @property
    def level(self) -> int:
        return {Vantage.SELF: 0, Vantage.ACCESS: 1, Vantage.SPAN: 2}[self]

    def satisfies(self, required: "Vantage") -> bool:
        return self.level >= required.level


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass
class Evidence:
    kind: str  # "frame" | "exchange" | "table" | "metric" | "note"
    detail: str
    ts: float | None = None  # epoch seconds
    ref: str | None = None  # e.g. "frame 1234" or "pcap#1234"


@dataclass
class Finding:
    id: str  # e.g. "DEV-001"
    group: str  # DEV | BCAST | COMM | SEC | BBMD
    severity: Severity
    confidence: Confidence
    vantage_required: Vantage
    title: str
    explanation: str
    recommendation: str
    subject: str = ""  # what the finding is about, e.g. "device 1001" or "192.0.2.10:47808"
    spec_refs: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    thresholds_used: dict[str, Any] = field(default_factory=dict)  # name -> {"value": x, "provisional": bool}
    falsifier: str = ""

    def __post_init__(self) -> None:
        # Design rule D14: inferred findings are capped at High.
        if self.confidence == Confidence.INFERRED and self.severity == Severity.CRITICAL:
            self.severity = Severity.HIGH


@dataclass
class Device:
    instance: int
    ip: str | None = None  # BACnet/IP address the I-Am came from (the router's address for remote devices)
    port: int | None = None
    snet: int | None = None  # source network if routed (remote device)
    sadr: str | None = None  # hex MAC on the remote network
    vendor_id: int | None = None
    max_apdu: int | None = None
    segmentation: str | None = None  # both | transmit | receive | none
    properties: dict[str, Any] = field(default_factory=dict)  # property name -> decoded value
    property_errors: dict[str, str] = field(default_factory=dict)  # property name -> "unknown-property" etc.
    responded_to_scan: bool = False
    seen_passively: bool = False
    first_seen: float | None = None
    last_seen: float | None = None
    iam_count: int = 0

    @property
    def remote(self) -> bool:
        return self.snet is not None

    @property
    def address_key(self) -> str:
        base = f"{self.ip}:{self.port}"
        return f"{base}/net{self.snet}/{self.sadr}" if self.remote else base


@dataclass
class BdtEntry:
    ip: str
    port: int
    mask: str  # dotted, e.g. "255.255.255.255"


@dataclass
class FdtEntry:
    ip: str
    port: int
    ttl: int
    remaining: int


@dataclass
class Bbmd:
    ip: str
    port: int
    status: str  # "bbmd" | "not-bbmd" | "timeout" | "candidate"
    source: str  # how it was found: "probe" | "passive" | "user" | "bdt-peer"
    bdt: list[BdtEntry] | None = None
    fdt: list[FdtEntry] | None = None
    fdt_status: str | None = None  # "ack" | "nak" | "timeout" | None (not read)


@dataclass
class Budget:
    whois_planned: int = 0
    reads_planned: int = 0
    bvlc_probes_planned: int = 0
    peak_pps_planned: float = 0.0
    est_duration_s: float = 0.0
    frames_sent: int = 0
    whois_sent: int = 0
    reads_sent: int = 0
    bvlc_probes_sent: int = 0
    peak_pps_actual: float = 0.0
    notes: list[str] = field(default_factory=list)


@dataclass
class RunInfo:
    kind: str  # scan | listen | analyze | audit | report
    started: str = field(default_factory=utcnow_iso)
    finished: str | None = None
    command: str = ""
    interface: str | None = None
    local_ip: str | None = None
    netmask: str | None = None
    broadcast: str | None = None
    port: int | None = None
    vantage: Vantage | None = None
    vantage_source: str | None = None  # "inferred" | "user" | "listen"
    ntp_synced: bool | None = None
    site: str = ""
    client: str = ""
    prepared_by: str = ""
    org: str = ""
    authorised_by: str = ""
    scope_note: str = ""
    confirmations: list[dict[str, Any]] = field(default_factory=list)  # {"action","target","user","at"}
    incomplete: bool = False


@dataclass
class InputFile:
    path: str
    sha256: str
    size: int
    frames: int = 0


@dataclass
class Result:
    run: RunInfo
    schema_version: str = SCHEMA_VERSION
    tool: dict[str, Any] = field(
        default_factory=lambda: {
            "name": "bacnet-health",
            "version": __version__,
            "python": sys.version.split()[0],
            "os": f"{platform.system()} {platform.release()}",
        }
    )
    budget: Budget | None = None
    inputs: list[InputFile] = field(default_factory=list)
    devices: list[Device] = field(default_factory=list)
    bbmds: list[Bbmd] = field(default_factory=list)
    topology: dict[str, Any] = field(default_factory=dict)
    metrics: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    checks_not_performed: list[dict[str, str]] = field(default_factory=list)  # {"id","title","reason"}
    limitations: list[str] = field(default_factory=list)

    # ---- serialisation -------------------------------------------------
    def to_dict(self) -> dict[str, Any]:
        return _to_jsonable(self)

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False, sort_keys=False)

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(self.to_json())

    @classmethod
    def load(cls, path: str) -> "Result":
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Result":
        run = RunInfo(**{**d["run"], "vantage": _enum_or_none(Vantage, d["run"].get("vantage"))})
        return cls(
            run=run,
            schema_version=d.get("schema_version", SCHEMA_VERSION),
            tool=d.get("tool", {}),
            budget=Budget(**d["budget"]) if d.get("budget") else None,
            inputs=[InputFile(**x) for x in d.get("inputs", [])],
            devices=[Device(**x) for x in d.get("devices", [])],
            bbmds=[_bbmd_from(x) for x in d.get("bbmds", [])],
            topology=d.get("topology", {}),
            metrics=d.get("metrics", {}),
            findings=[_finding_from(x) for x in d.get("findings", [])],
            checks_not_performed=d.get("checks_not_performed", []),
            limitations=d.get("limitations", []),
        )

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (f.severity.rank, f.id, f.subject))

    def severity_counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts


def _enum_or_none(enum_cls, v):
    return None if v is None else enum_cls(v)


def _bbmd_from(x: dict[str, Any]) -> Bbmd:
    x = dict(x)
    if x.get("bdt") is not None:
        x["bdt"] = [BdtEntry(**e) for e in x["bdt"]]
    if x.get("fdt") is not None:
        x["fdt"] = [FdtEntry(**e) for e in x["fdt"]]
    return Bbmd(**x)


def _finding_from(x: dict[str, Any]) -> Finding:
    x = dict(x)
    x["severity"] = Severity(x["severity"])
    x["confidence"] = Confidence(x["confidence"])
    x["vantage_required"] = Vantage(x["vantage_required"])
    x["evidence"] = [Evidence(**e) for e in x.get("evidence", [])]
    return Finding(**x)


def _to_jsonable(obj: Any) -> Any:
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: _to_jsonable(getattr(obj, f.name)) for f in dataclasses.fields(obj)}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, bytes):
        return obj.hex()
    return obj
