from __future__ import annotations

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from report_fixtures import make_previous_result, make_rich_result  # noqa: E402

from bacnet_health.model import (  # noqa: E402
    Bbmd,
    BdtEntry,
    Budget,
    Confidence,
    Device,
    Finding,
    InputFile,
    Result,
    RunInfo,
    Severity,
    Vantage,
)
from bacnet_health.report.diff import diff_results  # noqa: E402
from bacnet_health.report.merge import merge_results  # noqa: E402


def _f(fid, subject, sev, conf=Confidence.OBSERVED):
    return Finding(id=fid, group=fid.split("-")[0], severity=sev, confidence=conf, vantage_required=Vantage.SELF,
                   title=fid, explanation="e", recommendation="r", subject=subject)


def _listen() -> Result:
    r = Result(run=RunInfo(kind="listen", started="2026-11-05T00:00:00.000Z", finished="2026-11-05T00:10:00.000Z",
                           vantage=Vantage.SELF, vantage_source="listen", interface="en5", site="Sample Site"))
    r.devices = [Device(1001, "192.0.2.10", 47808, vendor_id=999, seen_passively=True, first_seen=10.0,
                        last_seen=500.0, iam_count=3)]
    r.bbmds = [Bbmd("192.0.2.1", 47808, "candidate", "passive")]
    r.findings = [_f("BCAST-001", "192.0.2.0/24", Severity.MEDIUM), _f("DEV-001", "device 7", Severity.MEDIUM)]
    r.metrics = {"broadcast_total": 100, "duration_s": 600, "checks_performed": ["BCAST-001", "COMM-005"]}
    r.checks_not_performed = [{"id": "SEC-002", "title": "Unexpected writer", "reason": "span"},
                              {"id": "DEV-004", "title": "Device did not answer", "reason": "no scan"}]
    r.inputs = [InputFile("a.pcapng", "aa" * 32, 10, 1)]
    r.limitations = ["L1"]
    return r


def _scan() -> Result:
    r = Result(run=RunInfo(kind="scan", started="2026-11-05T00:10:05.000Z", finished="2026-11-05T00:12:00.000Z",
                           vantage=Vantage.SELF, vantage_source="listen", local_ip="192.0.2.250",
                           confirmations=[{"action": "follow-bdt", "target": "198.51.100.1", "user": "u", "at": "t"}]))
    r.devices = [
        Device(1001, "192.0.2.10", 47808, vendor_id=999, responded_to_scan=True, first_seen=5.0, last_seen=700.0,
               iam_count=1, properties={"object-name": "AHU-01"}, property_errors={"location": "unknown-property"}),
        Device(1002, "192.0.2.11", 47808, vendor_id=999, responded_to_scan=True),
    ]
    r.bbmds = [Bbmd("192.0.2.1", 47808, "bbmd", "probe", bdt=[BdtEntry("192.0.2.1", 47808, "255.255.255.255")])]
    r.findings = [_f("DEV-001", "device 7", Severity.HIGH), _f("DEV-005", "device 1002", Severity.LOW)]
    r.metrics = {"broadcast_total": 250, "checks_performed": ["DEV-004"]}
    r.checks_not_performed = [{"id": "SEC-002", "title": "Unexpected writer", "reason": "span"}]
    r.budget = Budget(whois_planned=10, whois_sent=9, frames_sent=20, peak_pps_actual=3.0)
    r.inputs = [InputFile("a.pcapng", "aa" * 32, 10, 1)]
    r.limitations = ["L1", "L2"]
    return r


def test_merge_basic():
    m = merge_results([_scan(), _listen()])  # order of inputs must not matter for "earliest"
    assert m.run.kind == "audit"
    assert m.run.started == "2026-11-05T00:00:00.000Z"
    assert m.run.finished == "2026-11-05T00:12:00.000Z"
    assert m.run.interface == "en5" and m.run.local_ip == "192.0.2.250"
    assert len(m.run.confirmations) == 1
    # devices unioned and merged
    assert [d.instance for d in m.devices] == [1001, 1002]
    d = m.devices[0]
    assert d.responded_to_scan and d.seen_passively
    assert d.properties["object-name"] == "AHU-01"
    assert d.first_seen == 5.0 and d.last_seen == 700.0 and d.iam_count == 4
    # bbmd status upgraded, bdt kept
    assert len(m.bbmds) == 1 and m.bbmds[0].status == "bbmd" and m.bbmds[0].bdt
    # findings deduped keeping highest severity
    keyed = {(f.id, f.subject): f for f in m.findings}
    assert len(m.findings) == 3
    assert keyed[("DEV-001", "device 7")].severity == Severity.HIGH
    # metrics namespaced on clash
    assert m.metrics["broadcast_total"] == 100 and m.metrics["scan.broadcast_total"] == 250
    assert m.metrics["duration_s"] == 600
    assert set(m.metrics["checks_performed"]) == {"BCAST-001", "COMM-005", "DEV-004"}
    # checks not performed: DEV-004 performed by scan -> dropped; SEC-002 deduped
    assert [c["id"] for c in m.checks_not_performed] == ["SEC-002"]
    assert len(m.inputs) == 1
    assert m.budget is not None and m.budget.whois_sent == 9
    assert m.limitations == ["L1", "L2"]


def test_merge_property_error_dropped_when_read_elsewhere():
    a, b = _scan(), _listen()
    b.devices[0].properties["location"] = "Plant room"
    m = merge_results([a, b])
    d = m.devices[0]
    assert d.properties["location"] == "Plant room" and "location" not in d.property_errors


def test_merge_does_not_mutate_inputs():
    a, b = _scan(), _listen()
    a0, b0 = a.to_dict(), b.to_dict()
    merge_results([a, b])
    assert a.to_dict() == a0 and b.to_dict() == b0


def test_merge_single_and_empty():
    r = _scan()
    m = merge_results([r])
    assert m is not r and m.to_dict() == r.to_dict()
    with pytest.raises(ValueError):
        merge_results([])


def test_merge_distinct_devices_same_instance_kept():
    a, b = _scan(), _listen()
    b.devices.append(Device(1002, "192.0.2.99", 47808, vendor_id=999))
    m = merge_results([a, b])
    assert sum(1 for d in m.devices if d.instance == 1002) == 2


def test_merge_roundtrips_json():
    m = merge_results([_scan(), _listen()])
    assert Result.from_dict(m.to_dict()).to_dict() == m.to_dict()


def test_diff_semantics():
    old, new = make_previous_result(), make_rich_result()
    d = diff_results(old, new)
    added = {x["instance"] for x in d["devices"]["added"]}
    removed = {x["instance"] for x in d["devices"]["removed"]}
    assert added == {1006} and removed == {1020}
    changed = {x["instance"]: {c["field"]: (c["old"], c["new"]) for c in x["changes"]} for x in d["devices"]["changed"]}
    assert changed == {1003: {"firmware-revision": ("4.8.0", "4.9.3"), "database-revision": ("9", "12")}}
    f = d["findings"]
    assert {x["id"] for x in f["new"]} == {"BBMD-006", "DEV-003", "BBMD-007"}
    assert [x["id"] for x in f["resolved"]] == ["DEV-006"]
    assert [x["id"] for x in f["not_rechecked"]] == ["SEC-002"]  # new run could not perform SEC-002
    pers = {x["id"]: x for x in f["persisting"]}
    assert pers["BCAST-001"]["old_severity"] == "high" and pers["BCAST-001"]["severity"] == "medium"
    assert d["summary"]["findings_new"] == 3 and d["summary"]["devices_changed"] == 1
    assert d["new"]["started"] == new.run.started


def test_diff_duplicate_instances_and_address_change():
    old, new = make_rich_result(), make_rich_result()
    # both visits have two devices with instance 1010 (same vendor); no spurious changes
    d = diff_results(old, new)
    assert d["devices"]["changed"] == [] and d["devices"]["added"] == [] and d["devices"]["removed"] == []
    new2 = copy.deepcopy(new)
    for dev in new2.devices:
        if dev.instance == 1001:
            dev.ip = "192.0.2.110"
            dev.properties["object-name"] = "AHU-01 Renamed"
    d = diff_results(old, new2)
    fields = {c["field"] for x in d["devices"]["changed"] for c in x["changes"]}
    assert fields == {"address", "object-name"}


def test_diff_vendor_change_is_add_remove():
    old, new = make_rich_result(), make_rich_result()
    for dev in new.devices:
        if dev.instance == 1001:
            dev.vendor_id = 1
    d = diff_results(old, new)
    assert [x["instance"] for x in d["devices"]["added"]] == [1001]
    assert [x["instance"] for x in d["devices"]["removed"]] == [1001]


def test_diff_missing_property_not_a_change():
    old, new = make_rich_result(), make_rich_result()
    for dev in new.devices:
        if dev.instance == 1001:
            del dev.properties["firmware-revision"]
    assert diff_results(old, new)["devices"]["changed"] == []
