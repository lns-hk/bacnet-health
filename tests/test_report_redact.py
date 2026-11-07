"""Redaction: consistent pseudonyms in a Result and in a rewritten pcap; nothing original may survive."""

from __future__ import annotations

import ipaddress
import json
import shutil
import socket
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from bacnet_health.capture.link import UdpExtractor, build_udp_frame, ip_checksum
from bacnet_health.capture.pcap import PcapWriter, iter_packets
from bacnet_health.model import BdtEntry, FdtEntry, Result
from bacnet_health.report.redact import (
    LIMITATION_ADDRESSES,
    LIMITATION_REDACTED,
    PUBLIC_MARK,
    Redactor,
    redact_pcap,
    redact_result,
)
from bacnet_health.wire import apdu as A
from bacnet_health.wire import bvlc as B
from bacnet_health.wire.constants import ConfirmedService as CS, NetworkMessage as NM
from bacnet_health.wire.message import decode_message
from bacnet_health.wire.npdu import encode_network_list, encode_network_message, encode_npdu
from bacnet_health.wire.tags import Enumerated, Raw, encode_application, encode_context

sys.path.insert(0, str(Path(__file__).parent))
from report_fixtures import HOSTILE_NAME, make_rich_result  # noqa: E402

KEY = b"k" * 32
KEY2 = b"j" * 32
DOC_PRIVATE = (ipaddress.ip_network("192.0.2.0/24"), ipaddress.ip_network("198.51.100.0/24"))
DOC_PUBLIC = ipaddress.ip_network("203.0.113.0/24")
PRIVATE_OUT = DOC_PRIVATE + (ipaddress.ip_network("198.18.0.0/15"),)  # third and further private /24s overflow
TS0 = 1_793_836_800.0


def _in(ip: str, *nets) -> bool:
    return any(ipaddress.ip_address(ip) in n for n in nets)


# ---------------------------------------------------------------------------------------------------------------------
# Pseudonym primitives
# ---------------------------------------------------------------------------------------------------------------------


def test_ip_classes_and_consistency():
    for ip in ("10.1.2.3", "172.16.9.4", "192.168.0.7", "100.64.1.1", "169.254.3.3"):
        r = Redactor(KEY)  # a fresh table each time: a third distinct /24 would overflow (tested below)
        out = r.ip(ip)
        assert _in(out, *DOC_PRIVATE), (ip, out)
        assert out != ip
        assert r.ip(ip) == out  # same input, same pseudonym
        assert Redactor(KEY).ip(ip) == out  # same key, fresh redactor, same pseudonym
    pub = r.ip("203.0.113.50")
    assert _in(pub, DOC_PUBLIC) and pub != "203.0.113.50"
    assert r.is_public("203.0.113.50") and not r.is_public("10.1.2.3")
    for keep in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "224.0.0.251", "255.255.255.0", "255.255.240.0"):
        assert r.ip(keep) == keep
    assert r.ip("not.an.ip.addr") == "not.an.ip.addr"


def test_ip_key_dependence():
    ips = [f"10.9.{i}.{j}" for i in range(2) for j in range(1, 40)]
    a = [Redactor(KEY).ip(x) for x in ips]
    b = [Redactor(KEY2).ip(x) for x in ips]
    assert a != b


def test_subnet_relationships_preserved():
    r = Redactor(KEY)
    a, b, c = r.ip("10.1.1.5"), r.ip("10.1.1.6"), r.ip("10.1.2.5")
    assert a.rsplit(".", 1)[0] == b.rsplit(".", 1)[0]  # same /24 -> same /24
    assert a.rsplit(".", 1)[0] != c.rsplit(".", 1)[0]  # different /24 -> different /24
    assert r.ip("10.1.1.255") == a.rsplit(".", 1)[0] + ".255"  # directed broadcast stays the broadcast
    assert r.ip("10.1.1.0") == a.rsplit(".", 1)[0] + ".0"
    hosts = {r.ip(f"10.1.1.{h}") for h in range(256)}
    assert len(hosts) == 256  # one-to-one within the /24


def test_private_overflow_and_public_capacity():
    r = Redactor(KEY)
    outs = {r.ip(f"10.0.{i}.1") for i in range(6)}
    assert len(outs) == 6
    assert r.overflow_used
    assert all(_in(o, *DOC_PRIVATE, ipaddress.ip_network("198.18.0.0/15")) for o in outs)
    pubs = {r.ip(f"203.0.113.{h}") for h in range(1, 101)}
    assert len(pubs) == 100 and all(_in(x, DOC_PUBLIC) for x in pubs)


def test_public_exhaustion_shares_rather_than_fails():
    r = Redactor(KEY)
    outs = [r.ip(f"198.{i // 250 + 1}.{i % 250}.7") for i in range(300)]
    assert all(_in(o, DOC_PUBLIC) for o in outs)
    assert len(set(outs[:253])) == 253  # one-to-one while the range lasts
    assert r.shared_used


def test_names_and_paths():
    r = Redactor(KEY)
    n = r.name("Chiller Plant Controller")
    assert n.startswith("name-") and len(n) == 9
    assert r.name("Chiller Plant Controller") == n
    assert Redactor(KEY2).name("Chiller Plant Controller") != n
    assert r.name("") == ""
    many = {r.name(f"point {i}") for i in range(3000)}
    assert len(many) == 3000  # collisions in the 16-bit space are probed away
    p = r.path("/home/user/jobs/site-x/capture 01.pcapng")
    assert p.startswith("capture-") and p.endswith(".pcapng") and "site-x" not in p


def test_mac_and_bacnet_addresses():
    r = Redactor(KEY)
    m = r.mac("00:1a:2b:3c:4d:5e")
    assert m != "00:1a:2b:3c:4d:5e" and len(m) == 17
    first = int(m[:2], 16)
    assert first & 0x02 and not first & 0x01  # locally administered unicast
    assert r.mac("ff:ff:ff:ff:ff:ff") == "ff:ff:ff:ff:ff:ff"
    assert r.mac("00-1A-2B-3C-4D-5E") == m.replace(":", "-").upper()
    # MS/TP: a permutation within master (0-127) and slave (128-254) ranges; 255 kept.
    masters = {r.hw_addr(bytes([v])) for v in range(128)}
    assert masters == {bytes([v]) for v in range(128)}
    assert r.hw_addr(b"\xff") == b"\xff"
    assert all(r.hw_addr(bytes([v]))[0] >= 128 for v in range(128, 255))
    # 6-octet BACnet/IP address: IP mapped, port kept.
    bip = socket.inet_aton("10.1.1.5") + (47808).to_bytes(2, "big")
    out = r.hw_addr(bip)
    assert socket.inet_ntoa(out[:4]) == r.ip("10.1.1.5") and out[4:] == bip[4:]
    assert len(r.hw_addr(b"\x01\x02\x03")) == 3
    assert r.hw_addr(b"") == b""


# ---------------------------------------------------------------------------------------------------------------------
# Result redaction
# ---------------------------------------------------------------------------------------------------------------------

_TRANSLATE = {"192.0.2.": "10.20.30.", "198.51.100.": "172.16.5."}


def _private_result(hostile: bool = False) -> Result:
    """The rich report fixture moved onto RFC 1918 addresses (203.0.113.x stays as the 'public' address)."""
    text = make_rich_result(hostile).to_json()
    for a, b in _TRANSLATE.items():
        text = text.replace(a, b)
    res = Result.from_dict(json.loads(text))
    dev = res.devices[0]
    dev.properties["description"] = "Serves the east wing offices"
    dev.properties["mac-address"] = "0a141e0abac0"  # an octet string rendered as hex: 10.20.30.10:47808
    res.devices[1].properties["profile-name"] = "east-wing-ahu"
    res.findings[0].evidence[0].detail += " seen on 00:1a:2b:3c:4d:5e"
    res.topology["routers"] = {"10.20.30.16": {"networks": [5], "name": "Router RTR-01"}}
    res.metrics["per_source"] = {"10.20.30.10:47808": 12, "192.168.7.20:47808": 3}
    res.run.command = ("bacnet-health analyze '/Users/someone/Jobs/Sample Site/captures/sample-site-listen.pcapng' "
                       "--site 'Sample Site' --target 10.20.30.0/24 -o '/Users/someone/Jobs/Sample Site/out'")
    return res


def _originals(res: Result) -> tuple[list[str], list[str]]:
    names = [res.run.site, res.run.client, res.run.prepared_by, res.run.org, res.run.authorised_by,
             res.run.scope_note, "sample-site-listen", "captures/sample-site-listen.pcapng", "Serves the east wing",
             "east-wing-ahu", "Router RTR-01", "someone", "/Users", "Jobs", "00:1a:2b:3c:4d:5e", "0a141e0abac0"]
    for d in res.devices:
        for k in ("object-name", "location"):
            if d.properties.get(k):
                names.append(d.properties[k])
    return [n for n in names if n], sorted(_all_ips(res))


def _all_ips(res: Result) -> set[str]:
    import re

    found = set(re.findall(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])", res.to_json()))
    return {ip for ip in found if ip.startswith(("10.", "172.16.", "192.168."))}


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k)
            yield from _strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _strings(v)


def test_redact_result_no_originals_survive():
    res = _private_result(hostile=True)
    names, ips = _originals(res)
    names.append(HOSTILE_NAME)
    assert len(ips) >= 15
    out = redact_result(res, KEY)
    strings = list(_strings(out.to_dict()))
    text = out.to_json()
    for s in names + ips:
        assert not any(s.lower() in x.lower() for x in strings), s
    for ip in ips:
        assert ip not in text
    assert "203.0.113.50" not in text


def test_redact_result_input_untouched_and_counts_kept():
    res = _private_result()
    before = res.to_json()
    out = redact_result(res, KEY)
    assert res.to_json() == before
    assert len(out.devices) == len(res.devices)
    assert len(out.findings) == len(res.findings) and len(out.bbmds) == len(res.bbmds)
    assert out.severity_counts() == res.severity_counts()
    assert [f.id for f in out.findings] == [f.id for f in res.findings]
    assert [d.instance for d in out.devices] == [d.instance for d in res.devices]
    for a, b in zip(res.devices, out.devices):
        for k in ("vendor-name", "model-name", "firmware-revision", "application-software-version",
                  "system-status", "database-revision"):
            assert a.properties.get(k) == b.properties.get(k)
        assert (a.vendor_id, a.port, a.snet, a.iam_count, a.first_seen) == (b.vendor_id, b.port, b.snet,
                                                                            b.iam_count, b.first_seen)
    assert out.metrics["frames_total"] == res.metrics["frames_total"]
    assert out.metrics["broadcast_timeseries"] == res.metrics["broadcast_timeseries"]
    assert out.inputs[0].sha256 == res.inputs[0].sha256 and out.inputs[0].frames == res.inputs[0].frames
    assert out.tool == res.tool
    assert out.run.netmask == "255.255.255.0"
    assert [e.mask for e in out.bbmds[0].bdt] == [e.mask for e in res.bbmds[0].bdt]
    # The redacted Result round-trips through JSON.
    assert Result.from_dict(json.loads(out.to_json())).to_json() == out.to_json()


def test_redact_result_structure_and_consistency():
    res = _private_result()
    out = redact_result(res, KEY)
    r = Redactor(KEY)  # same key: same pseudonyms for the same values
    assert out.run.site == r.name("Sample Site") and out.run.site.startswith("name-")
    assert out.devices[0].properties["object-name"] == r.name("AHU-01 Supervisory Controller")
    assert out.inputs[0].path.startswith("capture-") and out.inputs[0].path.endswith(".pcapng")
    assert out.run.local_ip == r.ip("10.20.30.250")
    assert out.run.broadcast == out.run.local_ip.rsplit(".", 1)[0] + ".255"
    # Subnet relationships: devices in one /24 stay in one /24; the other site stays separate.
    prefixes = {d.ip.rsplit(".", 1)[0] for d in out.devices if d.ip and d.instance < 1010}
    assert len(prefixes) == 1
    assert out.devices[-1].ip.rsplit(".", 1)[0] not in prefixes
    assert all(_in(d.ip, *DOC_PRIVATE) for d in out.devices)
    # Free text uses the same pseudonyms as the structured fields.
    dev1010 = r.ip("172.16.5.20")
    dup = next(f for f in out.findings if f.id == "DEV-001")
    assert dev1010 in dup.evidence[0].detail
    lighting = next(f for f in out.findings if f.id == "DEV-005")
    assert r.name("Lighting Gateway") in lighting.explanation
    assert r.ip("10.20.30.14") in lighting.evidence[0].ref
    # Topology / metrics keys.
    assert r.ip("10.20.30.0") + "/24" in out.topology["broadcast_copies"]
    assert r.ip("10.20.30.16") in out.topology["routers"]
    assert out.topology["routers"][r.ip("10.20.30.16")]["name"] == r.name("Router RTR-01")
    assert r.ip("192.168.7.20") + ":47808" in out.metrics["per_source"]
    # Routed devices: SADR pseudonymised, same length, consistent.
    routed = [d for d in out.devices if d.snet is not None]
    assert [d.sadr for d in routed] == [r.hw_addr(bytes.fromhex(x)).hex() for x in ("0a", "0b", "0c")]
    # Octet-string property in hex -> treated as a BACnet/IP address.
    assert out.devices[0].properties["mac-address"] == r.octets(bytes.fromhex("0a141e0abac0")).hex()
    # Command: paths pseudonymised, options kept, IPs mapped.
    cmd = out.run.command
    assert cmd.startswith(f"bacnet-health analyze {out.inputs[0].path} ") and "--site" in cmd and "--target" in cmd
    assert r.ip("10.20.30.0") + "/24" in cmd
    # Confirmations: user and target.
    assert out.run.confirmations[0]["user"] == r.name("A. Engineer")
    assert out.run.confirmations[0]["target"] == r.ip("172.16.5.1")
    # Limitations.
    assert LIMITATION_REDACTED in out.limitations and LIMITATION_ADDRESSES in out.limitations
    assert res.limitations[0] in out.limitations


def test_redact_result_public_marker():
    out = redact_result(_private_result(), KEY)
    pub = Redactor(KEY).ip("203.0.113.50")
    f = next(f for f in out.findings if f.id == "BBMD-006")
    assert f"{pub}:47808 [{PUBLIC_MARK}]" in f.subject
    assert PUBLIC_MARK in f.evidence[0].detail
    assert PUBLIC_MARK not in next(f for f in out.findings if f.id == "DEV-001").subject
    fdt_ips = [e.ip for e in out.bbmds[0].fdt]
    assert pub in fdt_ips and _in(pub, DOC_PUBLIC)


def test_redact_result_key_dependence_and_determinism():
    res = _private_result()
    a, b, c = redact_result(res, KEY), redact_result(res, KEY), redact_result(res, KEY2)
    assert a.to_json() == b.to_json()
    assert a.to_json() != c.to_json()
    assert a.run.site != c.run.site and a.devices[0].ip != c.devices[0].ip or a.devices[1].ip != c.devices[1].ip


def test_redact_result_protects_kept_versions():
    res = _private_result()
    res.devices[2].properties["firmware-revision"] = "10.4.0.12"
    res.findings[4].explanation += " Firmware 10.4.0.12 is current."
    out = redact_result(res, KEY)
    assert out.devices[2].properties["firmware-revision"] == "10.4.0.12"
    assert "Firmware 10.4.0.12 is current." in out.findings[4].explanation


def test_redact_result_rejects_bad_key():
    with pytest.raises(ValueError):
        redact_result(_private_result(), b"")


# ---------------------------------------------------------------------------------------------------------------------
# pcap redaction
# ---------------------------------------------------------------------------------------------------------------------

DEV_IP, DEV2_IP, ROUTER_IP, BBMD_IP, PEER_IP, FD_IP, WS_IP = (
    "10.20.30.10", "10.20.30.11", "10.20.30.16", "10.20.30.1", "172.16.5.1", "192.168.7.20", "10.20.30.250")
BCAST = "10.20.30.255"
PUBLIC_FD = "203.0.113.50"
MACS = {DEV_IP: "00:1a:2b:3c:4d:01", DEV2_IP: "00:1a:2b:3c:4d:02", ROUTER_IP: "00:1a:2b:3c:4d:03",
        BBMD_IP: "00:1a:2b:3c:4d:04", WS_IP: "00:1a:2b:3c:4d:05"}
SECRETS = ["AHU-01 Supervisory Controller", "Level 1 plant room", "Serves the east wing offices", "Chiller Hall",
           "Secret Tower", "hunter2-password", "Who Has This", "Boiler Interface", "Fragmented Description"]
ORIGINAL_IPS = [DEV_IP, DEV2_IP, ROUTER_IP, BBMD_IP, PEER_IP, FD_IP, WS_IP, BCAST]
P = 47808
OBJECT_NAME, LOCATION, DESCRIPTION, IP_ADDRESS = 77, 58, 28, 400


def _uni(apdu: bytes, **npdu_kw) -> bytes:
    return B.encode_original_unicast(encode_npdu(apdu, **npdu_kw))


def _bc(apdu: bytes, **npdu_kw) -> bytes:
    return B.encode_original_broadcast(encode_npdu(apdu, **npdu_kw))


def _frame(src, dst, payload, sport=P, dport=P):
    return build_udp_frame(src, sport, dst, dport, payload, src_mac=MACS.get(src, "00:1a:2b:3c:4d:09"),
                           dst_mac="ff:ff:ff:ff:ff:ff" if dst.endswith(".255") else MACS.get(dst, "00:1a:2b:3c:4d:0a"))


def _fragments(src: str, dst: str, payload: bytes, size: int, ident: int) -> list[bytes]:
    full = _frame(src, dst, payload)
    eth, udp = full[:14], full[34:]
    out = []
    for off in range(0, len(udp), size):
        chunk = udp[off:off + size]
        more = off + size < len(udp)
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(chunk), ident, (0x2000 if more else 0) | off // 8,
                          64, 17, 0, socket.inet_aton(src), socket.inet_aton(dst))
        hdr = hdr[:10] + struct.pack(">H", ip_checksum(hdr)) + hdr[12:]
        out.append(eth + hdr + chunk)
    return out


def _build_capture(path: Path) -> dict[str, int]:
    """Write the synthetic capture; return the expected counts."""
    keep: list[bytes] = []
    drop_bacnet: list[bytes] = []
    drop_other: list[bytes] = []

    # --- frames that must be rewritten and kept -------------------------------------------------------------------
    keep.append(_frame(WS_IP, BCAST, _bc(A.encode_who_is())))
    keep.append(_frame(DEV_IP, BCAST, _bc(A.encode_i_am(1001, vendor_id=999))))
    keep.append(_frame(WS_IP, DEV_IP, _uni(A.encode_read_property(1, "device", 1001, OBJECT_NAME),
                                           expecting_reply=True)))
    keep.append(_frame(DEV_IP, WS_IP, _uni(A.encode_read_property_ack(1, "device", 1001, OBJECT_NAME,
                                                                      "AHU-01 Supervisory Controller"))))
    keep.append(_frame(DEV2_IP, WS_IP, _uni(A.encode_rpm_ack(2, [
        A.RpmResult(object_type=8, instance=1004, property_id=OBJECT_NAME, value="Boiler Interface"),
        A.RpmResult(object_type=8, instance=1004, property_id=LOCATION, value="Level 1 plant room"),
        A.RpmResult(object_type=8, instance=1004, property_id=DESCRIPTION, value="Serves the east wing offices"),
        A.RpmResult(object_type=8, instance=1004, property_id=44, value="5.2.0"),
        A.RpmResult(object_type=8, instance=1004, property_id=112, value=Enumerated(0)),
        A.RpmResult(object_type=8, instance=1004, property_id=99, error=(2, 32)),
    ]))))
    keep.append(_frame(BBMD_IP, BCAST, B.encode_forwarded_npdu(PEER_IP, P, encode_npdu(A.encode_i_am(1010)))))
    keep.append(_frame(BBMD_IP, WS_IP, B.encode_read_bdt_ack([BdtEntry(BBMD_IP, P, "255.255.255.255"),
                                                             BdtEntry(PEER_IP, P, "255.255.255.255")])))
    keep.append(_frame(BBMD_IP, WS_IP, B.encode_read_fdt_ack([FdtEntry(FD_IP, P, 300, 211),
                                                             FdtEntry(PUBLIC_FD, P, 65535, 8021)])))
    keep.append(_frame(ROUTER_IP, BCAST, _bc(A.encode_i_am(2001), snet=5, sadr=b"\x0a")))
    keep.append(_frame(WS_IP, ROUTER_IP, _uni(A.encode_read_property(3, "device", 2001, OBJECT_NAME), dnet=5,
                                              dadr=b"\x0a", expecting_reply=True)))
    keep.append(_frame(ROUTER_IP, WS_IP, _uni(A.encode_read_property_ack(3, "device", 2001, OBJECT_NAME,
                                                                         "Chiller Hall"),
                                              snet=5, sadr=socket.inet_aton(FD_IP) + P.to_bytes(2, "big"))))
    keep.append(_frame(ROUTER_IP, BCAST, B.encode_original_broadcast(
        encode_network_message(NM.I_AM_ROUTER_TO_NETWORK, encode_network_list([5, 6])))))
    keep.append(_frame(WS_IP, BCAST, _bc(bytes([0x10, 0x07]) + encode_context(3, "Who Has This"))))
    keep.append(_frame(DEV_IP, BCAST, _bc(bytes([0x10, 0x01]) + encode_application({"type": "device", "instance": 1001})
                                          + encode_application({"type": "analog-input", "instance": 1})
                                          + encode_application("Secret Tower"))))
    keep.append(_frame(WS_IP, DEV_IP, _uni(bytes([0x00, 0x05, 9, CS.DEVICE_COMMUNICATION_CONTROL])
                                           + encode_context(0, 5) + encode_context(1, Enumerated(1))
                                           + encode_context(2, "hunter2-password"), expecting_reply=True)))
    keep.append(_frame(DEV_IP, WS_IP, _uni(A.encode_read_property_ack(4, "network-port", 1, IP_ADDRESS,
                                                                      socket.inet_aton(DEV_IP)))))
    keep.append(_frame(DEV_IP, WS_IP, _uni(A.encode_error(5, CS.READ_PROPERTY, 2, 32))))
    keep.append(_frame(DEV_IP, WS_IP, _uni(A.encode_reject(6, 9))))
    keep.append(_frame(BBMD_IP, WS_IP, B.encode_result(0)))
    keep.append(_frame(FD_IP, BBMD_IP, B.encode_register_foreign_device(300)))
    keep.append(_frame(WS_IP, BBMD_IP, bytes([0x81, 0x08, 0x00, 0x0A]) + socket.inet_aton(FD_IP) + P.to_bytes(2, "big")))
    n_keep = len(keep) + 1  # + the fragmented datagram below

    # --- BACnet frames that cannot be rewritten completely: dropped -----------------------------------------------
    drop_bacnet.append(_frame(DEV_IP, WS_IP, _uni(A.encode_read_property_ack(
        7, "device", 1001, 999, Raw(encode_context(0, "Secret Tower"))))))  # context string inside a value
    drop_bacnet.append(_frame(DEV_IP, WS_IP, _uni(A.encode_complex_ack(
        8, CS.READ_PROPERTY, b"\x0c" + encode_application("Secret Tower"), segmented=True, more_follows=True))))
    drop_bacnet.append(_frame(DEV_IP, BCAST, _bc(bytes([0x10, 0x04]) + encode_context(0, 999)
                                                 + encode_context(1, 1) + b"\x2e" + encode_application("Secret Tower")
                                                 + b"\x2f")))  # unconfirmed private transfer
    drop_bacnet.append(_frame(DEV_IP, WS_IP, B.encode_original_unicast(encode_npdu(
        A.encode_read_property_ack(9, "device", 1001, OBJECT_NAME, "Secret Tower"))) + b"Secret Tower"))  # length
    drop_bacnet.append(_frame(DEV_IP, WS_IP, bytes([0x81, 0x0C, 0x00, 0x10]) + b"Secret Tower"))  # Secure-BVLL
    drop_bacnet.append(_frame(ROUTER_IP, BCAST, B.encode_original_broadcast(
        encode_network_message(NM.ESTABLISH_CONNECTION_TO_NETWORK, b"\x00\x05\x00" + b"Secret Tower"))))
    drop_bacnet.append(_frame(DEV_IP, WS_IP, _uni(A.encode_read_property_ack(  # text hidden in a bit-string
        13, "device", 1001, 999, Raw(b"\x85\x0d\x00" + b"Secret Tower")))))
    drop_bacnet.append(_frame(DEV_IP, WS_IP, _uni(bytes([0x00, 0x05, 10, CS.ATOMIC_WRITE_FILE])
                                                  + encode_context(0, 1) + encode_application(b"Secret Tower"))))

    # --- not BACnet/IP --------------------------------------------------------------------------------------------
    drop_other.append(_frame(WS_IP, DEV_IP, b"Secret Tower over plain UDP", sport=5353, dport=5353))
    arp = bytes.fromhex("ffffffffffff001a2b3c4d05" "0806") + b"\x00" * 28 + b"Secret Tower"
    drop_other.append(arp)

    big = "Fragmented Description " * 40
    frags = _fragments(DEV_IP, WS_IP, _uni(A.encode_read_property_ack(11, "device", 1001, DESCRIPTION, big)), 256, 77)
    lost = _fragments(DEV_IP, WS_IP, _uni(A.encode_read_property_ack(12, "device", 1001, DESCRIPTION, big)), 256, 78)

    frames = keep + drop_bacnet + drop_other + frags + lost[:1]
    with PcapWriter(path) as w:
        for i, f in enumerate(frames):
            w.write(TS0 + i * 0.01, f)
    return {"frames_in": len(frames), "written": n_keep, "dropped_undecodable": len(drop_bacnet),
            "dropped_non_bacnet": len(drop_other), "fragment_frames": len(frags) + 1,
            "fragments_merged": len(frags), "dropped_fragments": 1}


@pytest.fixture()
def capture(tmp_path):
    src = tmp_path / "site-capture.pcap"
    expected = _build_capture(src)
    return src, expected


def _datagrams(path: Path):
    ex = UdpExtractor()
    out = []
    for pkt in iter_packets(path):
        assert pkt.linktype == 1
        out.extend(ex.feed(pkt))
    return out


def test_redact_pcap_counts(capture, tmp_path):
    src, expected = capture
    out = tmp_path / "redacted.pcap"
    stats = redact_pcap(str(src), str(out), KEY)
    for k, v in expected.items():
        assert stats[k] == v, (k, stats)
    assert stats["frames_in"] == (stats["written"] + stats["dropped_non_bacnet"] + stats["dropped_undecodable"]
                                  + stats["fragments_merged"])
    reasons = stats["drop_reasons"]
    for r in ("context-tag-in-value", "segmented", "text-in-primitive", "service-unsupported", "bvlc-length-mismatch",
              "bvlc-function-unsupported", "network-message-unsupported", "not-bacnet-udp", "not-ipv4-udp"):
        assert reasons.get(r), (r, reasons)


def test_redact_pcap_no_originals(capture, tmp_path):
    src, _ = capture
    out = tmp_path / "redacted.pcap"
    redact_pcap(str(src), str(out), KEY)
    raw = out.read_bytes()
    for s in SECRETS:
        assert s.encode() not in raw, s
        assert s.encode("utf-16-be") not in raw
    for ip in ORIGINAL_IPS + [PUBLIC_FD]:
        assert socket.inet_aton(ip) not in raw, ip
        assert ip.encode() not in raw
    for mac in MACS.values():
        assert bytes.fromhex(mac.replace(":", "")) not in raw, mac
    # The input file is untouched.
    assert b"AHU-01 Supervisory Controller" in src.read_bytes()


def test_redact_pcap_rewrites_consistently(capture, tmp_path):
    src, _ = capture
    out = tmp_path / "redacted.pcap"
    r = Redactor(KEY)
    r.pcap(str(src), str(out))
    dgs = _datagrams(out)
    msgs = [(dg, decode_message(dg.payload)) for dg in dgs]
    for dg, m in msgs:
        assert m.decode_error is None, (m.kind, m.decode_error)
        assert int.from_bytes(dg.payload[2:4], "big") == len(dg.payload)
        assert _in(dg.src_ip, *PRIVATE_OUT)
        assert dg.dst_ip.endswith(".255") or _in(dg.dst_ip, *PRIVATE_OUT)
    kinds = [m.kind for _, m in msgs]
    assert kinds.count("rp-ack") == 4 and "rpm-ack" in kinds and "i-am" in kinds
    acks = [m.decoded for _, m in msgs if m.kind == "rp-ack"]
    assert acks[0].value == r.name("AHU-01 Supervisory Controller")
    assert acks[1].value == r.name("Chiller Hall")
    assert acks[2].value == socket.inet_aton(r.ip(DEV_IP))  # octet-string IP mapped like the IP header
    assert acks[3].value == r.name("Fragmented Description " * 40)  # reassembled and rewritten
    rpm = next(m.decoded for _, m in msgs if m.kind == "rpm-ack")
    assert [x.value for x in rpm[:4]] == [r.name("Boiler Interface"), r.name("Level 1 plant room"),
                                          r.name("Serves the east wing offices"), "5.2.0"]  # firmware kept
    assert rpm[4].value == 0 and rpm[5].error == (2, 32)
    # Who-Is / I-Am: broadcast destination stays the (mapped) subnet broadcast; device instance kept.
    iam = next((dg, m) for dg, m in msgs if m.kind == "i-am" and m.npdu.snet is None and m.bvlc.origin is None)
    assert iam[0].dst_ip == r.ip(BCAST) and iam[0].dst_ip.endswith(".255")
    assert iam[0].src_ip == r.ip(DEV_IP) and iam[1].decoded.device_instance == 1001
    assert iam[0].eth_dst == "ff:ff:ff:ff:ff:ff" and iam[0].eth_src == r.mac(MACS[DEV_IP])
    # Forwarded-NPDU origin.
    fwd = next(m for _, m in msgs if m.bvlc.origin is not None and m.kind == "i-am")
    assert fwd.bvlc.origin == (r.ip(PEER_IP), P)
    # BDT / FDT.
    bdt = next(m for _, m in msgs if m.kind == "bvlc:read-bdt-ack").bvlc.bdt
    assert [(e.ip, e.port, e.mask) for e in bdt] == [(r.ip(BBMD_IP), P, "255.255.255.255"),
                                                      (r.ip(PEER_IP), P, "255.255.255.255")]
    fdt = next(m for _, m in msgs if m.kind == "bvlc:read-fdt-ack").bvlc.fdt
    assert [(e.ip, e.ttl, e.remaining) for e in fdt] == [(r.ip(FD_IP), 300, 211), (r.ip(PUBLIC_FD), 65535, 8021)]
    assert _in(fdt[1].ip, DOC_PUBLIC)
    # Routed traffic: SNET/SADR and DNET/DADR pseudonymised consistently, same length.
    routed = next(m for _, m in msgs if m.kind == "i-am" and m.npdu.snet == 5)
    assert routed.npdu.sadr == r.hw_addr(b"\x0a") and routed.decoded.device_instance == 2001
    req = next(m for _, m in msgs if m.npdu and m.npdu.dnet == 5)
    assert req.npdu.dadr == routed.npdu.sadr and req.npdu.hop_count == 255
    sadr6 = next(m for _, m in msgs if m.npdu and m.npdu.sadr and len(m.npdu.sadr) == 6).npdu.sadr
    assert socket.inet_ntoa(sadr6[:4]) == r.ip(FD_IP) and sadr6[4:] == P.to_bytes(2, "big")
    # Who-Has / I-Have / DCC strings.
    who_has = next(m for _, m in msgs if m.kind == "who-has").decoded
    assert who_has.object_name == r.name("Who Has This")
    i_have = next(m for _, m in msgs if m.kind == "i-have").decoded
    assert i_have.object_name == r.name("Secret Tower") and i_have.device_instance == 1001
    assert any(m.kind == "dcc" for _, m in msgs)
    assert any(m.kind == "net:i-am-router-to-network" and m.decoded == {"networks": [5, 6]} for _, m in msgs)


def test_redact_pcap_report_consistency(tmp_path):
    """One Redactor for the report and the pcap: the same device has the same address and name in both."""
    path = tmp_path / "c.pcap"
    with PcapWriter(path) as w:
        w.write(TS0, _frame("10.20.30.10", "10.20.30.250", _uni(A.encode_read_property_ack(
            1, "device", 1001, OBJECT_NAME, "AHU-01 Supervisory Controller"))))
    r = Redactor(KEY)
    rep = r.result(_private_result())
    r.pcap(str(path), str(tmp_path / "o.pcap"))
    (dg,) = _datagrams(tmp_path / "o.pcap")
    m = decode_message(dg.payload)
    dev = next(d for d in rep.devices if d.instance == 1001)
    assert dg.src_ip == dev.ip
    assert m.decoded.value == dev.properties["object-name"]


def test_redact_pcap_raw_ip_linktype(tmp_path):
    """Captures without an Ethernet header still produce valid Ethernet output with consistent pseudo-MACs."""
    path = tmp_path / "raw.pcap"
    with PcapWriter(path, linktype=101) as w:
        w.write(TS0, _frame(DEV_IP, WS_IP, _uni(A.encode_i_am(1001)))[14:])
        w.write(TS0 + 1, _frame(DEV_IP, BCAST, _bc(A.encode_i_am(1001)))[14:])
    out = tmp_path / "o.pcap"
    stats = redact_pcap(str(path), str(out), KEY)
    assert stats["written"] == 2
    a, b = _datagrams(out)
    assert a.eth_src == b.eth_src and b.eth_dst == "ff:ff:ff:ff:ff:ff"


def test_redact_pcap_mutations_never_leak_or_crash(capture, tmp_path):
    """Corrupted frames are either dropped or written fully decodable; no original string survives."""
    import random

    src, _ = capture
    rng = random.Random(1234)
    frames = [p.data for p in iter_packets(src)]
    mutated = tmp_path / "mutated.pcap"
    with PcapWriter(mutated) as w:
        for i in range(1500):
            f = bytearray(rng.choice(frames))
            for _ in range(rng.randint(1, 4)):
                pos = rng.randrange(42, len(f)) if len(f) > 42 else rng.randrange(len(f))
                f[pos] = rng.randrange(256)
            if rng.random() < 0.2:
                f = f[: rng.randrange(14, len(f))]
            w.write(TS0 + i, bytes(f))
    out = tmp_path / "o.pcap"
    stats = redact_pcap(str(mutated), str(out), KEY)
    assert stats["frames_in"] == 1500
    kept_props = {121, 70, 44, 12}  # vendor/model/firmware/application-software-version strings are kept by design
    fragments = [s[i:i + 5].encode() for s in SECRETS for i in range(len(s) - 4)]
    checked = 0
    for dg in _datagrams(out):
        m = decode_message(dg.payload)
        assert m.decode_error is None
        if m.kind == "rp-ack" and m.decoded.property_id in kept_props:
            continue
        if m.kind == "rpm-ack" and any(x.property_id in kept_props for x in m.decoded):
            continue
        checked += 1
        for frag in fragments:  # not even a fragment of an original string
            assert frag not in dg.payload, (frag, dg.payload)
    assert checked > 100


def test_redact_pcap_key_dependence(capture, tmp_path):
    src, _ = capture
    redact_pcap(str(src), str(tmp_path / "a.pcap"), KEY)
    redact_pcap(str(src), str(tmp_path / "b.pcap"), KEY)
    redact_pcap(str(src), str(tmp_path / "c.pcap"), KEY2)
    a, b, c = ((tmp_path / f"{x}.pcap").read_bytes() for x in "abc")
    assert a == b and a != c


# ---------------------------------------------------------------------------------------------------------------------
# tshark: the redacted pcap is valid and decodes cleanly
# ---------------------------------------------------------------------------------------------------------------------

_TSHARK_APP = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
TSHARK = str(_TSHARK_APP) if _TSHARK_APP.exists() else shutil.which("tshark")


@pytest.mark.tshark
@pytest.mark.skipif(TSHARK is None, reason="tshark not installed")
def test_redacted_pcap_tshark(capture, tmp_path):
    src, _ = capture
    out = tmp_path / "redacted.pcap"
    stats = redact_pcap(str(src), str(out), KEY)
    verbose = subprocess.run([TSHARK, "-n", "-r", str(out), "-V", "-o", "udp.check_checksum:TRUE",
                              "-o", "ip.check_checksum:TRUE"], capture_output=True, text=True, check=True).stdout
    assert "Malformed" not in verbose
    assert "Expert Info (Error" not in verbose
    assert "Bad checksum" not in verbose and "[incorrect" not in verbose.lower()
    frames = subprocess.run([TSHARK, "-n", "-r", str(out), "-Y", "bvlc", "-T", "fields", "-e", "frame.number"],
                            capture_output=True, text=True, check=True).stdout.split()
    assert len(frames) == stats["written"]
    bad = subprocess.run([TSHARK, "-n", "-r", str(out), "-Y", "_ws.malformed || _ws.expert.severity >= error",
                          "-T", "fields", "-e", "frame.number"], capture_output=True, text=True, check=True).stdout
    assert bad.strip() == ""
    for s in SECRETS:
        assert s not in verbose, s
    for ip in ORIGINAL_IPS + [PUBLIC_FD]:
        assert ip not in verbose, ip
    for mac in MACS.values():
        assert mac not in verbose, mac
    assert "name-" in verbose  # the pseudonymised strings are decoded as BACnet character strings
