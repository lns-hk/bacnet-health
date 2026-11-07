"""Differential decoding against Wireshark's BACnet dissectors (design §9.2)."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire import npdu as N
from bacnet_health.wire.constants import PduType
from bacnet_health.wire.message import decode_message

from helpers.frames import write_pcap
from helpers.samples import sample_frames

TSHARK = shutil.which("tshark") or "/Applications/Wireshark.app/Contents/MacOS/tshark"

pytestmark = [
    pytest.mark.tshark,
    pytest.mark.skipif(not os.path.exists(TSHARK), reason="tshark not installed"),
]

FIELDS = [
    "bvlc.function", "bvlc.result", "bvlc.bdt_ip", "bvlc.fdt_ip", "bvlc.fwd_ip",
    "bacnet.control", "bacnet.dnet", "bacnet.snet", "bacnet.hopc", "bacnet.mesgtyp", "bacnet.vendor",
    "bacapp.type", "bacapp.confirmed_service", "bacapp.unconfirmed_service", "bacapp.invoke_id",
    "bacapp.instance_number", "bacapp.objectType", "bacapp.property_identifier", "bacapp.vendor_identifier",
    "bacapp.error_class", "bacapp.error_code", "bacapp.reject_reason", "bacapp.abort_reason",
]


def _ints(s: str) -> list[int]:
    return [int(x, 0) for x in s.split(",") if x]


def _tshark_rows(path: str) -> list[dict[str, list[int] | list[str]]]:
    cmd = [TSHARK, "-r", path, "-T", "fields", "-E", "separator=|", "-E", "occurrence=a"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60, check=True).stdout
    rows = []
    for line in out.splitlines():
        cols = line.split("|")
        rows.append({f: (c.split(",") if c and f.endswith("_ip") else _ints(c) if c else [])
                     for f, c in zip(FIELDS, cols)})
    return rows


def _expected(frame: bytes) -> dict[str, list]:
    m = decode_message(frame)
    assert m.decode_error is None, m.decode_error
    e: dict[str, list] = {"bvlc.function": [m.bvlc.function]}
    if m.bvlc.result_code is not None:
        e["bvlc.result"] = [m.bvlc.result_code]
    if m.bvlc.bdt is not None:
        e["bvlc.bdt_ip"] = [x.ip for x in m.bvlc.bdt]
    if m.bvlc.fdt is not None:
        e["bvlc.fdt_ip"] = [x.ip for x in m.bvlc.fdt]
    if m.bvlc.function == 0x04:
        e["bvlc.fwd_ip"] = [m.bvlc.origin[0]]
    n = m.npdu
    if n is None:
        return e
    e["bacnet.control"] = [n.control]
    if n.snet is not None:
        e["bacnet.snet"] = [n.snet]
    if n.dnet is not None:
        e["bacnet.dnet"], e["bacnet.hopc"] = [n.dnet], [n.hop_count]
    if n.network_message is not None:
        e["bacnet.mesgtyp"] = [n.network_message]
        if n.vendor_id is not None:
            e["bacnet.vendor"] = [n.vendor_id]
        return e
    ap = m.apdu
    e["bacapp.type"] = [ap.pdu_type]
    if ap.invoke_id is not None:
        e["bacapp.invoke_id"] = [ap.invoke_id]
    if ap.pdu_type == PduType.UNCONFIRMED_REQUEST:
        e["bacapp.unconfirmed_service"] = [ap.service]
    elif ap.pdu_type in (PduType.CONFIRMED_REQUEST, PduType.COMPLEX_ACK, PduType.ERROR):
        e["bacapp.confirmed_service"] = [ap.service]
    if ap.pdu_type == PduType.REJECT:
        e["bacapp.reject_reason"] = [ap.reason]
    if ap.pdu_type == PduType.ABORT:
        e["bacapp.abort_reason"] = [ap.reason]
    d = m.decoded
    if isinstance(d, A.IAm):
        e["bacapp.instance_number"], e["bacapp.objectType"] = [d.device_instance], [d.object_type]
        e["bacapp.vendor_identifier"] = [d.vendor_id]
    elif isinstance(d, (A.RpRequest, A.RpAck)):
        e["bacapp.instance_number[0]"], e["bacapp.objectType[0]"] = [d.instance], [d.object_type]
        e["bacapp.property_identifier"] = [d.property_id]
    elif isinstance(d, list) and d and isinstance(d[0], A.ReadAccessSpec):
        e["bacapp.property_identifier"] = [p for s in d for p, _ in s.properties]
        e["bacapp.instance_number[0]"] = [d[0].instance]
    elif isinstance(d, list) and d and isinstance(d[0], A.RpmResult):
        e["bacapp.property_identifier"] = [r.property_id for r in d]
        e["bacapp.error_class"] = [r.error[0] for r in d if r.error]
        e["bacapp.error_code"] = [r.error[1] for r in d if r.error]
    elif ap.pdu_type == PduType.ERROR:
        e["bacapp.error_class"], e["bacapp.error_code"] = [d[0]], [d[1]]
    return e


def test_differential_against_tshark(tmp_path):
    frames = sample_frames() + [B.encode_original_broadcast(N.encode_npdu(A.encode_i_am(4194302, 1024, 1, 999)))]
    path = str(tmp_path / "wire.pcap")
    write_pcap(path, frames)
    rows = _tshark_rows(path)
    assert len(rows) == len(frames)
    mismatches = []
    for i, (frame, row) in enumerate(zip(frames, rows), start=1):
        for key, want in _expected(frame).items():
            field, first_only = (key[:-3], True) if key.endswith("[0]") else (key, False)
            got = row.get(field, [])
            if first_only:
                got = got[:1]
            if got != want:
                mismatches.append(f"frame {i} {field}: ours={want} tshark={got} ({frame.hex()})")
    assert not mismatches, "\n".join(mismatches)
