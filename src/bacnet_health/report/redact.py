"""Redaction for sharing: consistent pseudonyms in a Result, and a rewritten pcap (design section 5.1, D20).

Two entry points::

    redact_result(result, key) -> Result          # deep copy; the input is not modified
    redact_pcap(in_path, out_path, key) -> dict   # statistics; see below

Use one :class:`Redactor` for both when a report and its capture are shared together: the pseudonyms then agree
(the same device has the same address and the same name in the report and in the pcap). ``new_key()`` returns a fresh
random key; the CLI keeps it in memory only.

Pseudonyms (HMAC-SHA256 keyed, deterministic for a given key; collisions are resolved by probing so the mapping is
one-to-one within a :class:`Redactor`):

* IPv4, private (RFC 1918, RFC 6598, link-local, and the documentation / benchmarking ranges themselves) ->
  192.0.2.0/24 or 198.51.100.0/24. The /24 prefix and the host octet are mapped separately, so addresses that share a
  /24 still share one after redaction; host 0 and 255 (network / directed broadcast) are kept. A third and further
  private /24 overflow into 198.18.0.0/15 (RFC 2544, also non-routable).
* IPv4, public -> 203.0.113.0/24, one address at a time (public addresses are rarely related; at most 254).
* Unchanged: 0.0.0.0, 255.255.255.255, loopback, multicast and 240/4 (which covers every common netmask).
* Names and other identifying strings -> ``name-<4 hex>``; input file paths -> ``capture-<4 hex>.<ext>``.
* Ethernet MACs -> locally administered unicast MACs (group addresses are kept). BACnet MAC addresses (SADR/DADR) ->
  same length; 1-octet MS/TP addresses are permuted within 0-127 and 128-254 (255 is kept); a 6-octet address with a
  0xBAC0-0xBACF port is treated as a BACnet/IP address (IP mapped, port kept).

Kept as-is: device instance numbers, vendor, model, firmware and application-software versions, counts, timings,
UDP ports, finding ids and severities.

The pcap rewriter only emits a frame it has rewritten completely. Anything it cannot fully parse is dropped and
counted, because a partially redacted frame is a leak.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import shlex
import socket
from typing import Any, Callable

from bacnet_health.capture.link import UdpExtractor, build_udp_frame
from bacnet_health.capture.pcap import PcapWriter, iter_packets
from bacnet_health.model import Result
from bacnet_health.wire.constants import (
    BVLC_TYPE_BIP,
    BvlcFunction as BF,
    ConfirmedService as CS,
    NetworkMessage as NM,
    PduType,
    PropertyId as PID,
    UnconfirmedService as US,
)
from bacnet_health.wire.errors import DecodeError
from bacnet_health.wire.message import decode_message
from bacnet_health.wire.npdu import CTRL_NETWORK_MESSAGE, decode_npdu
from bacnet_health.wire.tags import decode_primitive, decode_tag, encode_tag, find_closing

__all__ = [
    "LIMITATION_ADDRESSES",
    "LIMITATION_REDACTED",
    "PUBLIC_MARK",
    "RedactionError",
    "Redactor",
    "new_key",
    "redact_pcap",
    "redact_result",
]

LIMITATION_REDACTED = "This report has been redacted for sharing; addresses and names are pseudonyms."
LIMITATION_ADDRESSES = (
    "Redacted: addresses were replaced with pseudonyms in documentation ranges (192.0.2.0/24 and 198.51.100.0/24 for "
    "private addresses, 203.0.113.0/24 for public addresses). Addresses that shared a /24 still share one. Findings "
    "about public addresses (SEC-004, BBMD-006) were evaluated on the original addresses; where a finding's subject "
    "or evidence refers to a public address it is marked \"public address (redacted)\"."
)
LIMITATION_SHARED = (
    "Redacted: there were more distinct addresses than the documentation ranges can hold, so some different "
    "addresses share a pseudonym."
)
LIMITATION_OVERFLOW = (
    "Redacted: more than two private /24 subnets were present, so further subnets were mapped into 198.18.0.0/15 "
    "(a non-routable benchmarking range)."
)
PUBLIC_MARK = "public address (redacted)"


class RedactionError(ValueError):
    """The name pseudonym space is exhausted (more than 65 536 distinct names)."""


def new_key() -> bytes:
    """A fresh random redaction key (32 octets). Keep it in memory only."""
    return secrets.token_bytes(32)


# ---------------------------------------------------------------------------------------------------------------------
# Address classification and text patterns
# ---------------------------------------------------------------------------------------------------------------------

_N = ipaddress.IPv4Network
_PRIVATE_NETS = tuple(
    _N(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "169.254.0.0/16",
        "192.0.0.0/24", "192.0.2.0/24", "198.51.100.0/24", "198.18.0.0/15",
    )
)
_KEEP_NETS = tuple(_N(n) for n in ("0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"))
_PRIVATE_TARGETS = ((192, 0, 2), (198, 51, 100))
_OVERFLOW_TARGETS = tuple((198, 18 + i // 256, i % 256) for i in range(512))
_PUBLIC_TARGET = (203, 0, 113)

_IP_RE = re.compile(r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})(:\d{1,5})?(?!\.?\d)")
_MAC_RE = re.compile(r"(?<![0-9A-Fa-f:-])([0-9A-Fa-f]{2})([:-])((?:[0-9A-Fa-f]{2}\2){4}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
_NETADDR_RE = re.compile(r"(/net\d+/)([0-9A-Fa-f]+)\b")
_IP_LIST_RE = re.compile(r"^[\d.,/:\-]+$")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){2,}")  # octet strings are rendered as lowercase hex in Result
_ENUM_RE = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*")  # decoded enumeration names: "operational", "both"

# Device properties whose string values identify the site or its equipment.
NAME_PROPERTIES = frozenset({
    "object-name", "location", "description", "profile-name", "profile-location", "deployed-profile-location",
    "serial-number", "node-subtype", "tags", "user-name", "host-name", "domain-name",
})
# Kept verbatim (design section 5.1).
KEPT_PROPERTIES = frozenset({"vendor-name", "model-name", "firmware-revision", "application-software-version"})
_RUN_NAME_FIELDS = ("site", "client", "prepared_by", "org", "authorised_by", "scope_note")
_CAPTURE_EXTS = {".pcap", ".pcapng", ".cap", ".gz", ".zst", ".xz"}


def _ip_tuple(s: str) -> tuple[int, int, int, int] | None:
    parts = s.split(".")
    if len(parts) != 4 or not all(p.isdigit() and len(p) <= 3 for p in parts):
        return None
    vals = tuple(int(p) for p in parts)
    return vals if all(v <= 255 for v in vals) else None  # type: ignore[return-value]


def _ip_class(ip: tuple[int, int, int, int]) -> str:
    """'keep' | 'private' | 'public'."""
    addr = ipaddress.IPv4Address(bytes(ip))
    if any(addr in n for n in _KEEP_NETS):
        return "keep"
    if any(addr in n for n in _PRIVATE_NETS):
        return "private"
    return "public"


def _has_letter(s: str) -> bool:
    return any(c.isalpha() for c in s)


def _is_free_text(v: Any) -> bool:
    """A string device property that is neither an enumeration name, an address, nor hex octets."""
    return (
        isinstance(v, str)
        and _has_letter(v)
        and not _ENUM_RE.fullmatch(v)
        and not _HEX_RE.fullmatch(v)
        and not _IP_RE.fullmatch(v)
    )


# ---------------------------------------------------------------------------------------------------------------------
# Redactor: the pseudonym tables
# ---------------------------------------------------------------------------------------------------------------------


class Redactor:
    """Keyed, consistent pseudonym tables shared by :meth:`result` and :meth:`pcap`."""

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)) or not key:
            raise ValueError("redaction key must be non-empty bytes")
        self._key = bytes(key)
        self._prefix: dict[tuple[int, int, int], tuple[int, int, int]] = {}
        self._prefix_used: set[tuple[int, int, int]] = set()
        self._host_perm: dict[tuple[int, int, int], list[int]] = {}
        self._public: dict[tuple[int, int, int, int], int] = {}
        self._public_used: set[int] = set()
        self._names: dict[str, str] = {}
        self._names_used: set[str] = set()
        self._paths: dict[str, str] = {}
        self._macs: dict[bytes, bytes] = {}
        self._macs_used: set[bytes] = set()
        self._hw: dict[bytes, bytes] = {}
        self._mstp: dict[int, list[int]] = {}
        self.overflow_used = False
        self.shared_used = False
        self.public_seen = False
        self.seen_ips: set[bytes] = set()  # every original address pseudonymised so far (4 octets)

    # -- primitives ----------------------------------------------------------------------------------------------
    def _h(self, *parts: Any) -> bytes:
        msg = b"\x1f".join(p if isinstance(p, bytes) else str(p).encode("utf-8", "surrogatepass") for p in parts)
        return hmac.new(self._key, msg, hashlib.sha256).digest()

    def _int(self, *parts: Any) -> int:
        return int.from_bytes(self._h(*parts)[:8], "big")

    # -- IPv4 ----------------------------------------------------------------------------------------------------
    def is_public(self, ip: str) -> bool:
        t = _ip_tuple(ip)
        return t is not None and _ip_class(t) == "public"

    def ip(self, ip: str) -> str:
        """Pseudonym for a dotted IPv4 address; anything that is not one is returned unchanged."""
        t = _ip_tuple(ip)
        if t is None:
            return ip
        return ".".join(map(str, self._ip_t(t)))

    def ip_bytes(self, b: bytes) -> bytes:
        return bytes(self._ip_t(tuple(b)))  # type: ignore[arg-type]

    def _ip_t(self, t: tuple[int, int, int, int]) -> tuple[int, int, int, int]:
        cls = _ip_class(t)
        if cls == "keep":
            return t
        self.seen_ips.add(bytes(t))
        if cls == "public":
            self.public_seen = True
            return (*_PUBLIC_TARGET, self._public_host(t))
        prefix = self._private_prefix(t[:3])  # type: ignore[arg-type]
        host = t[3]
        if host not in (0, 255):
            host = self._perm(t[:3])[host - 1]  # type: ignore[arg-type]
        return (*prefix, host)

    def _private_prefix(self, p: tuple[int, int, int]) -> tuple[int, int, int]:
        got = self._prefix.get(p)
        if got is not None:
            return got
        h = self._int("prefix", *p)
        order = list(_PRIVATE_TARGETS) if h & 1 == 0 else list(reversed(_PRIVATE_TARGETS))
        start = (h >> 1) % len(_OVERFLOW_TARGETS)
        order += [_OVERFLOW_TARGETS[(start + i) % len(_OVERFLOW_TARGETS)] for i in range(len(_OVERFLOW_TARGETS))]
        cand = next((c for c in order if c not in self._prefix_used), None)
        if cand is None:  # more than 514 private /24s: share a pseudonym /24 rather than fail
            cand = _OVERFLOW_TARGETS[start]
            self.shared_used = True
        if cand not in _PRIVATE_TARGETS:
            self.overflow_used = True
        self._prefix[p] = cand
        self._prefix_used.add(cand)
        return cand

    def _perm(self, p: tuple[int, int, int]) -> list[int]:
        perm = self._host_perm.get(p)
        if perm is None:
            perm = sorted(range(1, 255), key=lambda h: self._h("host", *p, h))
            self._host_perm[p] = perm
        return perm

    def _public_host(self, t: tuple[int, int, int, int]) -> int:
        got = self._public.get(t)
        if got is not None:
            return got
        if t[3] in (0, 255):  # network / broadcast keep their role
            self._public[t] = t[3]
            return t[3]
        start = self._int("public", *t) % 254
        for i in range(254):
            cand = 1 + (start + i) % 254
            if cand in self._public_used or (*_PUBLIC_TARGET, cand) == t:
                continue
            break
        else:  # more than 253 public addresses: share a pseudonym rather than fail
            cand = 1 + start
            if (*_PUBLIC_TARGET, cand) == t:
                cand = 1 + (start + 1) % 254
            self.shared_used = True
        self._public[t] = cand
        self._public_used.add(cand)
        return cand

    # -- names, paths --------------------------------------------------------------------------------------------
    def name(self, s: str) -> str:
        """``name-<4 hex>`` for a non-empty string; the empty string stays empty."""
        if not s:
            return s
        got = self._names.get(s)
        if got is None:
            for i in range(1 << 16):
                cand = "name-" + self._h("name", i, s)[:2].hex()
                if cand not in self._names_used:
                    break
            else:  # pragma: no cover - 65536 distinct names
                raise RedactionError("too many distinct names to pseudonymise")
            self._names[s] = got = cand
            self._names_used.add(cand)
        return got

    def path(self, p: str) -> str:
        """``capture-<4 hex>.<ext>`` (capture files), ``file-<4 hex>.<ext>`` or ``dir-<4 hex>``."""
        got = self._paths.get(p)
        if got is None:
            base = re.split(r"[\\/]", p.rstrip("\\/"))[-1]
            m = re.search(r"(\.[A-Za-z0-9]{1,10})$", base)
            ext = m.group(1) if m and m.start() > 0 else ""
            kind = "capture" if ext.lower() in _CAPTURE_EXTS else "file" if ext else "dir"
            got = f"{kind}-{self._h('path', base)[:2].hex()}{ext}"  # by basename: relative and absolute agree
            self._paths[p] = got
        return got

    # -- link and BACnet MAC addresses ---------------------------------------------------------------------------
    def mac_bytes(self, b: bytes) -> bytes:
        """6-octet Ethernet MAC -> locally administered unicast pseudonym; group addresses are kept."""
        b = bytes(b)
        if len(b) != 6 or b[0] & 0x01:
            return b
        got = self._macs.get(b)
        if got is None:
            for i in range(1 << 16):
                h = self._h("mac", i, b)
                cand = bytes([(h[0] & 0xFC) | 0x02]) + h[1:6]
                if cand not in self._macs_used and cand != b:
                    break
            self._macs[b] = got = cand
            self._macs_used.add(cand)
        return got

    def mac(self, s: str) -> str:
        sep = "-" if "-" in s else ":"
        raw = bytes.fromhex(s.replace(":", "").replace("-", ""))
        out = self.mac_bytes(raw).hex(sep)
        return out.upper() if s.isupper() else out

    def hw_addr(self, b: bytes) -> bytes:
        """BACnet MAC (SADR/DADR) pseudonym of the same length. The empty address (broadcast) stays empty."""
        b = bytes(b)
        if not b:
            return b
        got = self._hw.get(b)
        if got is not None:
            return got
        if len(b) == 1:
            v = b[0]
            if v == 255:
                got = b
            else:
                lo, hi = (0, 127) if v <= 127 else (128, 254)
                perm = self._mstp.get(lo)
                if perm is None:
                    perm = self._mstp[lo] = sorted(range(lo, hi + 1), key=lambda x: self._h("mstp", x))
                got = bytes([perm[v - lo]])
        elif len(b) == 6 and 0xBAC0 <= int.from_bytes(b[4:6], "big") <= 0xBACF:
            got = self.ip_bytes(b[:4]) + b[4:6]
        elif len(b) == 6:
            got = self.mac_bytes(b)
        else:
            got = self._h("hw", b)[: len(b)]
            while len(got) < len(b):
                got += self._h("hw", len(got), b)
            got = got[: len(b)]
        self._hw[b] = got
        return got

    def octets(self, b: bytes) -> bytes:
        """Octet-string value of unknown meaning: 4 octets are treated as an IPv4 address, others as a MAC."""
        b = bytes(b)
        if len(b) == 4:
            return self.ip_bytes(b)
        return self.hw_addr(b)

    def hw_hex(self, s: str) -> str:
        try:
            raw = bytes.fromhex(s)
        except ValueError:
            return self.name(s)
        return self.hw_addr(raw).hex()

    # -- Result --------------------------------------------------------------------------------------------------
    def result(self, result: Result) -> Result:
        """Redacted deep copy of *result* (see the module docstring)."""
        return _ResultRedaction(self, result).run()

    # -- pcap ----------------------------------------------------------------------------------------------------
    def pcap(self, in_path: str, out_path: str) -> dict[str, Any]:
        return _redact_pcap(self, in_path, out_path)


def redact_result(result: Result, key: bytes) -> Result:
    """Return a redacted deep copy of *result*. The input is not modified."""
    return Redactor(key).result(result)


def redact_pcap(in_path: str, out_path: str, key: bytes) -> dict[str, Any]:
    """Write a redacted classic pcap (Ethernet) of the BACnet/IP traffic in *in_path*; return statistics.

    Statistics keys:

    * ``frames_in``: input frames; ``written``: frames written.
    * ``dropped_non_bacnet``: frames that were not BACnet/IP (non-IPv4, non-UDP, other UDP protocols).
    * ``dropped_undecodable``: BACnet/IP (or damaged) frames that could not be decoded and rewritten completely.
    * ``dropped_fragments``: datagrams lost because their IPv4 fragments never completed.
    * ``fragment_frames``: input frames that were IPv4 fragments. A reassembled datagram is written once, as one
      unfragmented frame, at the frame that completed it; the other fragments are counted in ``fragments_merged``.
    * ``drop_reasons``: reason -> count, for the dropped frames.

    ``frames_in == written + dropped_non_bacnet + dropped_undecodable + fragments_merged``.
    """
    return Redactor(key).pcap(in_path, out_path)


# ---------------------------------------------------------------------------------------------------------------------
# Result redaction
# ---------------------------------------------------------------------------------------------------------------------


class _ResultRedaction:
    def __init__(self, r: Redactor, result: Result) -> None:
        self.r = r
        self.d = copy.deepcopy(result.to_dict())
        self.names: set[str] = set()  # originals replaced as names wherever they occur in text
        self.path_originals: dict[str, str] = {}
        self.hw_originals: set[str] = set()
        self.done: set[str] = set()  # pseudonyms written into structured fields: never re-processed
        self.protected_ips: set[str] = set()  # IP-like text inside kept fields (e.g. a firmware "1.2.3.4")
        self.address_ips: set[str] = set()
        self._name_re: re.Pattern[str] | None = None
        self._name_lookup: dict[str, str] = {}
        self._name_lookup_ci: dict[str, str] = {}

    # -- table building ------------------------------------------------------------------------------------------
    def _add_name(self, s: Any) -> None:
        if isinstance(s, str) and s.strip():
            self.r.name(s)
            if (len(s) >= 2 and _has_letter(s)) or len(s) >= 4:
                self.names.add(s)

    def _collect(self) -> None:
        d = self.d
        run = d["run"]
        for f in _RUN_NAME_FIELDS:
            self._add_name(run.get(f))
        for c in run.get("confirmations") or []:
            if isinstance(c, dict):
                self._add_name(c.get("user"))
        for ip_field in ("local_ip", "broadcast"):
            if run.get(ip_field):
                self.address_ips.add(run[ip_field])
        for inp in d.get("inputs", []):
            p = inp.get("path") or ""
            if not p:
                continue
            self.path_originals[p] = self.r.path(p)
            parts = [x for x in re.split(r"[\\/]", p) if x]
            if parts:
                base = parts[-1]
                self.path_originals[base] = self.r.path(p)
                stem = re.sub(r"\.[A-Za-z0-9]{1,10}$", "", base)
                if len(stem) >= 3:
                    self._add_name(stem)
            for comp in parts[:-1]:
                if len(comp) >= 3 and comp not in (".", ".."):
                    self._add_name(comp)
        for dev in d.get("devices", []):
            if dev.get("ip"):
                self.address_ips.add(dev["ip"])
            if dev.get("sadr"):
                if len(dev["sadr"]) >= 4:
                    self.hw_originals.add(dev["sadr"])
            for k, v in (dev.get("properties") or {}).items():
                if k in KEPT_PROPERTIES:
                    for m in _IP_RE.finditer(str(v)):
                        self.protected_ips.add(m.group(1))
                elif k in NAME_PROPERTIES:
                    for s in v if isinstance(v, list) else [v]:
                        self._add_name(s)
                elif _is_free_text(v):
                    self._add_name(v)
        for b in d.get("bbmds", []):
            self.address_ips.add(b.get("ip") or "")
            for e in (b.get("bdt") or []) + (b.get("fdt") or []):
                self.address_ips.add(e.get("ip") or "")
        self.protected_ips -= self.address_ips
        for tool_v in (d.get("tool") or {}).values():
            for m in _IP_RE.finditer(str(tool_v)):
                if m.group(1) not in self.address_ips:
                    self.protected_ips.add(m.group(1))

        lookup: dict[str, str] = {}
        for p, ps in self.path_originals.items():
            lookup[p] = ps
        for n in self.names:
            lookup.setdefault(n, self.r.name(n))
        for h in self.hw_originals:
            lookup.setdefault(h, self.r.hw_hex(h))
        self._name_lookup = lookup
        self._name_lookup_ci = {k.casefold(): v for k, v in sorted(lookup.items(), key=lambda kv: -len(kv[0]))}
        if lookup:
            alts = []
            for o in sorted(lookup, key=len, reverse=True):
                pat = re.escape(o)
                if re.match(r"\w", o):
                    pat = r"(?<!\w)" + pat
                if o[0].isdigit():
                    pat = r"(?<!\d\.)" + pat  # never start inside a dotted number such as an address
                if re.search(r"\w$", o):
                    pat = pat + r"(?!\w)"
                if o[-1].isdigit():
                    pat = pat + r"(?!\.\d)"
                alts.append(pat)
            self._name_re = re.compile("|".join(alts), re.IGNORECASE)

    # -- text replacement ----------------------------------------------------------------------------------------
    def text(self, s: str, mark_public: bool = False) -> str:
        if s in self.done:
            return s
        if self._name_re is not None:
            s = self._name_re.sub(self._name_sub, s)

        def ip_sub(m: re.Match[str]) -> str:
            ip, port = m.group(1), m.group(2) or ""
            if _ip_tuple(ip) is None or ip in self.protected_ips:
                return m.group(0)
            out = self.r.ip(ip) + port
            if mark_public and self.r.is_public(ip):
                out += f" [{PUBLIC_MARK}]"
            return out

        s = _IP_RE.sub(ip_sub, s)
        s = _MAC_RE.sub(lambda m: self.r.mac(m.group(0)), s)
        s = _NETADDR_RE.sub(lambda m: m.group(1) + self.r.hw_hex(m.group(2)), s)
        return s

    def _name_sub(self, m: re.Match[str]) -> str:
        o = m.group(0)
        return self._name_lookup.get(o) or self._name_lookup_ci.get(o.casefold()) or self.r.name(o)

    def command(self, cmd: str) -> str:
        if not cmd:
            return cmd
        try:
            toks = shlex.split(cmd)
        except ValueError:
            toks = cmd.split()
        out = []
        for i, t in enumerate(toks):
            if t.startswith("-") and "=" in t:
                opt, val = t.split("=", 1)
                out.append(opt + "=" + self._cmd_value(val))
            elif t.startswith("-"):
                out.append(t)
            elif i == 0 and re.search(r"[\\/]", t):
                out.append(re.split(r"[\\/]", t)[-1])  # program name, without its directory
            else:
                out.append(self._cmd_value(t))
        return shlex.join(out)

    def _cmd_value(self, v: str) -> str:
        if v in self.path_originals:
            return self.path_originals[v]
        if _IP_LIST_RE.match(v):
            return self.text(v)
        if re.search(r"[\\/]", v) or re.search(r"[^.]\.[A-Za-z][A-Za-z0-9]{0,9}$", v):
            return self.r.path(v)
        return self.text(v)

    # -- walking -------------------------------------------------------------------------------------------------
    def _skip(self, path: tuple[Any, ...]) -> bool:
        if not path:
            return False
        top = path[0]
        if top in ("tool", "schema_version"):
            return True
        if top == "run" and len(path) >= 2 and path[1] in (
            "kind", "started", "finished", "vantage", "vantage_source", "netmask", "port", "command",
        ):
            return True
        if top == "run" and len(path) >= 4 and path[1] == "confirmations" and path[3] == "at":
            return True
        if top == "findings" and len(path) >= 3 and path[2] in (
            "id", "group", "severity", "confidence", "vantage_required", "spec_refs", "thresholds_used",
        ):
            return True
        if top == "findings" and len(path) >= 5 and path[2] == "evidence" and path[4] in ("kind", "ts"):
            return True
        if top == "devices" and len(path) >= 4 and path[2] == "properties" and path[3] in KEPT_PROPERTIES:
            return True
        if top == "bbmds" and len(path) >= 5 and path[4] == "mask":
            return True
        if top == "inputs" and len(path) >= 3 and path[2] == "sha256":
            return True
        if top == "checks_not_performed" and len(path) >= 3 and path[2] == "id":
            return True
        return False

    def _mark(self, path: tuple[Any, ...]) -> bool:
        return bool(
            path
            and path[0] == "findings"
            and (
                (len(path) == 3 and path[2] == "subject")
                or (len(path) == 5 and path[2] == "evidence" and path[4] in ("detail", "ref"))
            )
        )

    def walk(self, obj: Any, path: tuple[Any, ...] = ()) -> Any:
        if self._skip(path):
            return obj
        if isinstance(obj, str):
            return self.text(obj, self._mark(path))
        if isinstance(obj, dict):
            out = {}
            free_keys = bool(path) and path[0] in ("topology", "metrics")  # data keys, not schema field names
            for k, v in obj.items():
                nk = self.text(k) if free_keys and isinstance(k, str) else k
                out[nk] = self.walk(v, path + (k,))
            return out
        if isinstance(obj, list):
            return [self.walk(v, path + (i,)) for i, v in enumerate(obj)]
        return obj

    # -- structured fields ---------------------------------------------------------------------------------------
    def _set_name(self, container: dict[str, Any], key: str) -> None:
        v = container.get(key)
        if isinstance(v, str) and v:
            container[key] = self.r.name(v)
            self.done.add(container[key])
        elif isinstance(v, list):
            container[key] = [self.r.name(x) if isinstance(x, str) and x else x for x in v]
            self.done.update(x for x in container[key] if isinstance(x, str))

    def _structured(self) -> None:
        d = self.d
        run = d["run"]
        for f in _RUN_NAME_FIELDS:
            self._set_name(run, f)
        for c in run.get("confirmations") or []:
            if isinstance(c, dict):
                self._set_name(c, "user")
        run["command"] = self.command(run.get("command") or "")
        for inp in d.get("inputs", []):
            if inp.get("path"):
                inp["path"] = self.r.path(inp["path"])
                self.done.add(inp["path"])
        for dev in d.get("devices", []):
            if dev.get("sadr"):
                dev["sadr"] = self.r.hw_hex(dev["sadr"])
                self.done.add(dev["sadr"])
            props = dev.get("properties") or {}
            for k in list(props):
                v = props[k]
                if k in KEPT_PROPERTIES:
                    continue
                if k in NAME_PROPERTIES:
                    self._set_name(props, k)
                elif isinstance(v, str) and _HEX_RE.fullmatch(v):
                    props[k] = self.r.octets(bytes.fromhex(v)).hex()  # an octet string (address?) in hex
                    self.done.add(props[k])
                elif _is_free_text(v):
                    self._set_name(props, k)  # free text from the device: treat as a name

    def run(self) -> Result:
        self._collect()
        self._structured()
        walked = self.walk(self.d)
        lim = walked.setdefault("limitations", [])
        lines = [LIMITATION_REDACTED, LIMITATION_ADDRESSES]
        if self.r.overflow_used:
            lines.append(LIMITATION_OVERFLOW)
        if self.r.shared_used:
            lines.append(LIMITATION_SHARED)
        for line in lines:
            if line not in lim:
                lim.append(line)
        return Result.from_dict(walked)


# ---------------------------------------------------------------------------------------------------------------------
# BACnet payload rewriting
# ---------------------------------------------------------------------------------------------------------------------


class _Drop(Exception):
    """The frame cannot be rewritten completely; drop it. ``args[0]`` is the reason (a short stable string)."""


_VALUE = "value"  # abstract-syntax region: application tags only, constructed via opening/closing context tags
_PRIM_LEN = {"u": (1, 8), "e": (1, 8), "o": (4, 4), "b": (1, 1), "r": (4, 4), "d": (8, 8), "t": (4, 4)}


class _S:
    """Schema for a service payload or a constructed element: context tag -> kind; ``app`` allows application tags.

    Kinds: a primitive type letter from ``_PRIM_LEN`` (content copied after a length check), ``"str"`` (context
    character string, replaced), ``_VALUE`` (abstract-syntax property value) or a nested :class:`_S`. A tag the
    schema does not list cannot be classified, so the frame is dropped. ``prop_tag`` names the context tag that carries
    the property identifier, so that the values of kept properties (vendor, model, firmware) keep their strings.
    """

    def __init__(self, ctx: dict[int, Any] | None = None, app: bool = False, prop_tag: int | None = None) -> None:
        self.ctx = ctx or {}
        self.app = app
        self.prop_tag = prop_tag


_APP_ONLY = _S(app=True)
_PROP_VALUE = _S({0: "e", 1: "u", 2: _VALUE, 3: "u"}, prop_tag=0)
_COV = _S({0: "u", 1: "o", 2: "o", 3: "u", 4: _PROP_VALUE})

_UNCONFIRMED: dict[int, _S] = {
    US.I_AM: _APP_ONLY,
    US.I_HAVE: _APP_ONLY,
    US.WHO_IS: _S({0: "u", 1: "u"}),
    US.WHO_HAS: _S({0: "u", 1: "u", 2: "o", 3: "str"}),
    US.TIME_SYNCHRONIZATION: _APP_ONLY,
    US.UTC_TIME_SYNCHRONIZATION: _APP_ONLY,
    US.UNCONFIRMED_COV_NOTIFICATION: _COV,
}
_CONFIRMED: dict[int, _S] = {
    CS.READ_PROPERTY: _S({0: "o", 1: "e", 2: "u"}),
    CS.READ_PROPERTY_MULTIPLE: _S({0: "o", 1: _S({0: "e", 1: "u"})}),
    CS.WRITE_PROPERTY: _S({0: "o", 1: "e", 2: "u", 3: _VALUE, 4: "u"}, prop_tag=1),
    CS.WRITE_PROPERTY_MULTIPLE: _S({0: "o", 1: _PROP_VALUE}),
    CS.SUBSCRIBE_COV: _S({0: "u", 1: "o", 2: "b", 3: "u"}),
    CS.CONFIRMED_COV_NOTIFICATION: _COV,
    CS.DEVICE_COMMUNICATION_CONTROL: _S({0: "u", 1: "e", 2: "str"}),
    CS.REINITIALIZE_DEVICE: _S({0: "e", 1: "str"}),
}
_ACKS: dict[int, _S] = {
    CS.READ_PROPERTY: _S({0: "o", 1: "e", 2: "u", 3: _VALUE}, prop_tag=1),
    CS.READ_PROPERTY_MULTIPLE: _S({0: "o", 1: _S({2: "e", 3: "u", 4: _VALUE, 5: _APP_ONLY}, prop_tag=2)}),
}
# Network-layer messages whose payload carries only network numbers / codes (validated by decode_network_message).
_SAFE_NETWORK_MESSAGES = {
    NM.WHO_IS_ROUTER_TO_NETWORK, NM.I_AM_ROUTER_TO_NETWORK, NM.I_COULD_BE_ROUTER_TO_NETWORK,
    NM.REJECT_MESSAGE_TO_NETWORK, NM.ROUTER_BUSY_TO_NETWORK, NM.ROUTER_AVAILABLE_TO_NETWORK,
    NM.WHAT_IS_NETWORK_NUMBER, NM.NETWORK_NUMBER_IS,
}
# vendor-name, model-name, firmware-revision, application-software-version: kept (design section 5.1).
_KEPT_PROPERTY_IDS = {PID.VENDOR_NAME, PID.MODEL_NAME, PID.FIRMWARE_REVISION, PID.APPLICATION_SOFTWARE_VERSION}
_MAX_DEPTH = 16
_MAX_BITSTRING = 33  # octets incl. the unused-bits octet; the longest standard bit-string is far shorter
# Primitive content is copied verbatim, so a damaged or unusual frame could carry text in, say, a bit-string or an
# 8-octet unsigned. Content with a run of 4+ text-like octets (3+ of them letters) is not copied: the frame is dropped.
_TEXTLIKE = re.compile(rb"[A-Za-z0-9 _.,:;/()\-]{4,}")


def _is_netmask(b: bytes) -> bool:
    v = int.from_bytes(b, "big")
    return (v | (v - 1)) & 0xFFFFFFFF == 0xFFFFFFFF if v else True


def _suspicious(content: bytes) -> bool:
    return any(sum(c.isalpha() for c in m.group(0).decode("ascii")) >= 3 for m in _TEXTLIKE.finditer(content))
_CHARSETS = {0: "utf-8", 3: "utf-32-be", 4: "utf-16-be", 5: "latin-1"}


class _Rewriter:
    def __init__(self, r: Redactor) -> None:
        self.r = r

    # -- BVLC ----------------------------------------------------------------------------------------------------
    def payload(self, data: bytes) -> bytes:
        if len(data) < 4 or data[0] != BVLC_TYPE_BIP:
            raise _Drop("not-bvlc")
        if int.from_bytes(data[2:4], "big") != len(data):
            raise _Drop("bvlc-length-mismatch")
        msg = decode_message(data)
        if msg.decode_error or msg.bvlc is None:
            raise _Drop(f"undecodable-{msg.error_layer or 'bvlc'}")
        fn = data[1]
        body = data[4:]
        if fn in (BF.ORIGINAL_UNICAST_NPDU, BF.ORIGINAL_BROADCAST_NPDU, BF.DISTRIBUTE_BROADCAST_TO_NETWORK):
            new = self.npdu(body)
        elif fn == BF.FORWARDED_NPDU:
            new = self.r.ip_bytes(body[:4]) + body[4:6] + self.npdu(body[6:])
        elif fn in (BF.READ_BDT_ACK, BF.WRITE_BDT):
            entries = [body[i:i + 10] for i in range(0, len(body), 10)]
            for e in entries:
                if not _is_netmask(e[6:10]):
                    raise _Drop("bad-bdt-mask")
            new = b"".join(self.r.ip_bytes(e[:4]) + self._copy(e[4:6]) + e[6:10] for e in entries)
        elif fn == BF.READ_FDT_ACK:
            new = b"".join(self.r.ip_bytes(body[i:i + 4]) + self._copy(body[i + 4:i + 10])
                           for i in range(0, len(body), 10))
        elif fn == BF.DELETE_FDT_ENTRY:
            new = self.r.ip_bytes(body[:4]) + body[4:6]
        elif fn in (BF.RESULT, BF.REGISTER_FOREIGN_DEVICE, BF.READ_BDT, BF.READ_FDT):
            new = body  # result code / TTL / empty
        else:
            raise _Drop("bvlc-function-unsupported")
        out = bytes([BVLC_TYPE_BIP, fn]) + (4 + len(new)).to_bytes(2, "big") + new
        check = decode_message(out)
        if check.decode_error or check.kind != msg.kind:
            raise _Drop("rewrite-check-failed")  # pragma: no cover - defensive
        return out

    # -- NPDU ----------------------------------------------------------------------------------------------------
    def npdu(self, data: bytes) -> bytes:
        try:
            n = decode_npdu(data)
        except DecodeError as exc:  # pragma: no cover - decode_message already succeeded
            raise _Drop("undecodable-npdu") from exc
        hdr = bytearray(data[:2])
        if n.dnet is not None:
            dadr = self.r.hw_addr(n.dadr or b"")
            hdr += n.dnet.to_bytes(2, "big") + bytes([len(dadr)]) + dadr
        if n.snet is not None:
            sadr = self.r.hw_addr(n.sadr or b"")
            hdr += n.snet.to_bytes(2, "big") + bytes([len(sadr)]) + sadr
        if n.dnet is not None:
            hdr.append(n.hop_count or 0)
        if n.control & CTRL_NETWORK_MESSAGE:
            if n.network_message not in _SAFE_NETWORK_MESSAGES:
                raise _Drop("network-message-unsupported")
            payload = n.network_payload or b""
            if n.network_message == NM.WHAT_IS_NETWORK_NUMBER and payload:
                raise _Drop("network-message-trailing-data")
            hdr.append(n.network_message)  # type: ignore[arg-type]
            return bytes(hdr) + self._copy(payload)
        assert n.apdu is not None
        return bytes(hdr) + self.apdu(n.apdu)

    # -- APDU ----------------------------------------------------------------------------------------------------
    def apdu(self, data: bytes) -> bytes:
        ptype = data[0] >> 4
        if ptype in (PduType.CONFIRMED_REQUEST, PduType.COMPLEX_ACK) and data[0] & 0x08:
            raise _Drop("segmented")
        if ptype == PduType.CONFIRMED_REQUEST:
            hlen, schemas, service = 4, _CONFIRMED, data[3]
        elif ptype == PduType.UNCONFIRMED_REQUEST:
            hlen, schemas, service = 2, _UNCONFIRMED, data[1]
        elif ptype == PduType.COMPLEX_ACK:
            hlen, schemas, service = 3, _ACKS, data[2]
        elif ptype == PduType.ERROR:
            hlen, schemas, service = 3, None, data[2]
        elif ptype in (PduType.SIMPLE_ACK, PduType.REJECT, PduType.ABORT):
            if len(data) != 3:
                raise _Drop("trailing-data")
            return data
        elif ptype == PduType.SEGMENT_ACK:
            if len(data) != 4:
                raise _Drop("trailing-data")
            return data
        else:  # pragma: no cover - decode_message already rejected reserved types
            raise _Drop("undecodable-apdu")
        schema = _APP_ONLY if schemas is None else schemas.get(service)
        if schema is None:
            raise _Drop("service-unsupported")
        return data[:hlen] + self.region(data, hlen, len(data), schema, 0)

    def region(self, data: bytes, start: int, end: int, schema: Any, depth: int, keep: bool = False) -> bytes:
        """Rewrite the tags in ``data[start:end]`` under *schema*; ``keep`` = inside the value of a kept property."""
        if depth > _MAX_DEPTH:
            raise _Drop("nested-too-deeply")
        out = bytearray()
        pos = start
        prop: int | None = None
        try:
            while pos < end:
                tag = decode_tag(data, pos, end)
                if tag.closing:
                    raise _Drop("unexpected-closing-tag")
                if tag.opening:
                    inner_end = find_closing(data, tag.end, tag.number, end)
                    close_end = decode_tag(data, inner_end, end).end
                    sub = _VALUE if schema is _VALUE else schema.ctx.get(tag.number)
                    if not (sub is _VALUE or isinstance(sub, _S)):
                        raise _Drop("unknown-constructed-tag")
                    sub_keep = keep if schema is _VALUE else (sub is _VALUE and prop in _KEPT_PROPERTY_IDS)
                    out += data[pos:tag.end] + self.region(data, tag.end, inner_end, sub, depth + 1, sub_keep)
                    out += data[inner_end:close_end]
                    pos = close_end
                elif tag.context:
                    if schema is _VALUE:
                        raise _Drop("context-tag-in-value")
                    out += self._context(data, pos, tag, schema.ctx.get(tag.number))
                    if tag.number == schema.prop_tag:
                        prop = int.from_bytes(data[tag.start:tag.end], "big")
                    pos = tag.end
                else:
                    if not (schema is _VALUE or schema.app):
                        raise _Drop("unexpected-application-tag")
                    out += self._application(data, pos, tag, keep)
                    pos = tag.end
        except DecodeError as exc:
            raise _Drop("undecodable-tags") from exc
        return bytes(out)

    def _context(self, data: bytes, pos: int, tag: Any, kind: Any) -> bytes:
        content = data[tag.start:tag.end]
        if kind in _PRIM_LEN:
            lo, hi = _PRIM_LEN[kind]
            if not lo <= len(content) <= hi:
                raise _Drop("bad-primitive-length")
            self._copy(content)
            return data[pos:tag.end]
        if kind == "str":
            return self._charstring(content, tag.number, True)
        raise _Drop("unknown-context-tag")

    def _application(self, data: bytes, pos: int, tag: Any, keep: bool = False) -> bytes:
        content = data[tag.start:tag.end]
        if tag.number == 7:
            if keep:
                decode_primitive(7, content)  # must at least carry a charset octet
                return data[pos:tag.end]
            return self._charstring(content, 7, False)
        if tag.number == 6:
            new = self._octets(content)
            return encode_tag(6, False, len(new)) + new
        if tag.number > 12:
            raise _Drop("reserved-application-tag")
        decode_primitive(tag.number, content, tag.lvt)  # validates lengths; DecodeError -> drop
        if tag.number == 8 and len(content) > _MAX_BITSTRING:
            raise _Drop("bit-string-too-long")
        self._copy(content)
        return data[pos:tag.end]

    def _copy(self, content: bytes) -> bytes:
        """Gate for octets copied verbatim: no text-like run and no original address may pass through."""
        if _suspicious(content):
            raise _Drop("text-in-primitive")
        seen = self.r.seen_ips
        if any(content[i:i + 4] in seen for i in range(len(content) - 3)):
            raise _Drop("address-in-primitive")
        return content

    def _charstring(self, content: bytes, number: int, context: bool) -> bytes:
        if not content:
            raise _Drop("bad-character-string")
        raw = content[1:]
        if raw:
            codec = _CHARSETS.get(content[0])
            text = raw.decode(codec, errors="replace") if codec else "charset%d:%s" % (content[0], raw.hex())
            new = b"\x00" + self.r.name(text).encode("utf-8")
        else:
            new = b"\x00"
        return encode_tag(number, context, len(new)) + new

    def _octets(self, b: bytes) -> bytes:
        return self.r.octets(b)


# ---------------------------------------------------------------------------------------------------------------------
# pcap redaction
# ---------------------------------------------------------------------------------------------------------------------

_NON_BACNET_STATS = ("non_ip", "ipv6", "non_udp", "unsupported_linktype")
_DAMAGED_STATS = ("malformed", "truncated")


def _redact_pcap(r: Redactor, in_path: str, out_path: str) -> dict[str, Any]:
    stats: dict[str, Any] = dict.fromkeys(
        ("frames_in", "written", "dropped_non_bacnet", "dropped_undecodable", "dropped_fragments",
         "fragment_frames", "fragments_merged"), 0)
    reasons: dict[str, int] = {}

    def drop(cat: str, reason: str) -> None:
        stats[cat] += 1
        reasons[reason] = reasons.get(reason, 0) + 1

    rw = _Rewriter(r)
    ex = UdpExtractor()
    try:
        _copy_frames(r, rw, ex, in_path, out_path, stats, drop)
    except BaseException:
        try:
            os.remove(out_path)  # never leave a half-written file behind
        except OSError:
            pass
        raise
    ex.finish()
    stats["dropped_fragments"] = (
        ex.stats["fragments_expired"] + ex.stats["fragments_dropped"] + ex.stats["fragments_incomplete"]
    )
    stats["drop_reasons"] = dict(sorted(reasons.items()))
    return stats


def _copy_frames(r: Redactor, rw: _Rewriter, ex: UdpExtractor, in_path: str, out_path: str, stats: dict[str, Any],
                 drop: Callable[[str, str], None]) -> None:
    with PcapWriter(out_path, linktype=1) as w:
        for pkt in iter_packets(in_path):
            stats["frames_in"] += 1
            before = dict(ex.stats)
            dgrams = ex.feed(pkt)
            delta = {k: ex.stats[k] - before[k] for k in ex.stats}
            if delta["fragments"]:
                stats["fragment_frames"] += 1
            if not dgrams:
                if any(delta[k] for k in _DAMAGED_STATS):
                    drop("dropped_undecodable", "damaged-frame")
                elif any(delta[k] for k in _NON_BACNET_STATS):
                    drop("dropped_non_bacnet", "not-ipv4-udp")
                elif delta["fragments"]:
                    stats["fragments_merged"] += 1
                else:  # pragma: no cover - every UdpExtractor path increments a counter
                    drop("dropped_undecodable", "unknown")
                continue
            for dg in dgrams:  # at most one per frame
                frame = _rewrite_datagram(r, rw, dg, drop)
                if frame is not None:
                    w.write(pkt.ts, frame)
                    stats["written"] += 1


def _rewrite_datagram(r: Redactor, rw: _Rewriter, dg: Any, drop: Callable[[str, str], None]) -> bytes | None:
    p = dg.payload
    if len(p) < 4 or p[0] != BVLC_TYPE_BIP:
        drop("dropped_non_bacnet", "not-bacnet-udp")
        return None
    src_ip, dst_ip = r.ip(dg.src_ip), r.ip(dg.dst_ip)  # before the payload, so copied octets are checked against them
    try:
        payload = rw.payload(p)
    except _Drop as exc:
        drop("dropped_undecodable", str(exc.args[0]))
        return None
    except RedactionError:
        raise
    except Exception:  # pragma: no cover - defensive: a rewriter bug must drop the frame, never emit it
        drop("dropped_undecodable", "internal-error")
        return None
    src_mac = r.mac(dg.eth_src) if dg.eth_src else _ip_mac(r, dg.src_ip)
    if dg.eth_dst:
        dst_mac = r.mac(dg.eth_dst)
    elif dst_ip == "255.255.255.255" or dst_ip.endswith(".255"):
        dst_mac = "ff:ff:ff:ff:ff:ff"
    else:
        dst_mac = _ip_mac(r, dg.dst_ip)
    try:
        return build_udp_frame(src_ip, dg.src_port, dst_ip, dg.dst_port, payload, src_mac=src_mac, dst_mac=dst_mac)
    except (ValueError, OSError):  # pragma: no cover - payload is no larger than the input
        drop("dropped_undecodable", "rebuild-failed")
        return None


def _ip_mac(r: Redactor, ip: str) -> str:
    """A consistent pseudo-MAC for link types that carry no Ethernet header."""
    return r.mac_bytes(b"\x02\x00" + socket.inet_aton(ip)).hex(":")

