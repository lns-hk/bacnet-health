"""Merge several Results (e.g. ``listen`` + ``scan``, or ``analyze`` + ``scan``) into one ``audit`` Result.

Rules:

- ``run``: a copy of the earliest run (by ``started``) with ``kind="audit"``; ``finished`` is the latest finish;
  ``vantage``/``vantage_source`` come from the input with the highest vantage; empty identity fields (site, client,
  interface, ...) are filled from later inputs; confirmations are concatenated; ``incomplete`` if any input is.
- ``devices``: union keyed by ``(instance, address_key)``. Scalars keep the first non-None value, properties are
  unioned (first value wins), a property error is dropped when another input read the property, flags are OR-ed,
  ``first_seen``/``last_seen`` are min/max and ``iam_count`` is summed.
- ``bbmds``: union keyed by ``ip:port``. The most informative status wins (bbmd > not-bbmd > candidate > timeout);
  BDT/FDT tables keep the first non-None.
- ``findings``: concatenated and de-duplicated by ``(id, subject)``, keeping the highest severity (ties: first seen).
- ``inputs``: concatenated, de-duplicated by ``(path, sha256)``. ``budget``: counters summed, peaks maxed.
- ``metrics`` and ``topology``: union; on a key clash with a different value the later value is stored under
  ``"<kind>.<key>"`` (``<kind>`` is the input's run kind; a numeric suffix is added if needed).
  ``metrics["checks_performed"]`` lists are unioned instead.
- ``checks_not_performed``: de-duplicated by id, dropping any id that some input lists in
  ``metrics["checks_performed"]``.
- ``limitations``: union, order preserved.

A single input is returned as an unchanged deep copy.
"""

from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from bacnet_health.model import Bbmd, Budget, Device, Finding, Result

_BBMD_STATUS_RANK = {"bbmd": 0, "not-bbmd": 1, "candidate": 2, "timeout": 3}


def _started_key(r: Result) -> tuple[int, Any]:
    s = r.run.started or ""
    try:
        return (0, datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp())
    except (ValueError, TypeError):
        return (1, s)


def merge_results(results: list[Result]) -> Result:
    if not results:
        raise ValueError("merge_results needs at least one Result")
    if len(results) == 1:
        return copy.deepcopy(results[0])

    ordered = sorted(results, key=_started_key)
    first = ordered[0]
    run = copy.deepcopy(first.run)
    run.kind = "audit"
    run.confirmations = []
    best_vantage = None
    for r in ordered:
        run.confirmations.extend(copy.deepcopy(r.run.confirmations))
        run.incomplete = run.incomplete or r.run.incomplete
        if r.run.finished and (run.finished is None or r.run.finished > run.finished):
            run.finished = r.run.finished
        if r.run.vantage is not None and (best_vantage is None or r.run.vantage.level > best_vantage.level):
            best_vantage = r.run.vantage
            run.vantage = r.run.vantage
            run.vantage_source = r.run.vantage_source
        for name in ("site", "client", "prepared_by", "org", "authorised_by", "scope_note", "interface", "local_ip",
                     "netmask", "broadcast", "port", "ntp_synced"):
            if getattr(run, name) in (None, "") and getattr(r.run, name) not in (None, ""):
                setattr(run, name, getattr(r.run, name))
    commands = [r.run.command for r in ordered if r.run.command]
    if len(set(commands)) > 1:
        run.command = " ; ".join(dict.fromkeys(commands))

    merged = Result(run=run, schema_version=first.schema_version, tool=copy.deepcopy(first.tool))
    merged.budget = _merge_budgets([r.budget for r in ordered if r.budget is not None])

    seen_inputs: set[tuple[str, str]] = set()
    for r in ordered:
        for inp in r.inputs:
            k = (inp.path, inp.sha256)
            if k not in seen_inputs:
                seen_inputs.add(k)
                merged.inputs.append(copy.deepcopy(inp))

    merged.devices = _merge_devices(ordered)
    merged.bbmds = _merge_bbmds(ordered)
    merged.findings = _merge_findings(ordered)

    performed: set[str] = set()
    for r in ordered:
        cp = r.metrics.get("checks_performed", []) if isinstance(r.metrics, dict) else []
        if isinstance(cp, (list, tuple, set)):
            performed.update(str(x) for x in cp)

    merged.metrics = _merge_dicts(ordered, "metrics")
    if performed:
        merged.metrics["checks_performed"] = sorted(performed)
    merged.topology = _merge_dicts(ordered, "topology")

    seen_cnp: set[str] = set()
    for r in ordered:
        for c in r.checks_not_performed:
            cid = str(c.get("id", ""))
            if cid in performed or cid in seen_cnp:
                continue
            seen_cnp.add(cid)
            merged.checks_not_performed.append(dict(c))

    for r in ordered:
        for lim in r.limitations:
            if lim not in merged.limitations:
                merged.limitations.append(lim)
    return merged


def _merge_budgets(budgets: list[Budget]) -> Budget | None:
    if not budgets:
        return None
    if len(budgets) == 1:
        return copy.deepcopy(budgets[0])
    out = Budget()
    for b in budgets:
        for name in ("whois_planned", "reads_planned", "bvlc_probes_planned", "est_duration_s", "frames_sent",
                     "whois_sent", "reads_sent", "bvlc_probes_sent"):
            setattr(out, name, getattr(out, name) + (getattr(b, name) or 0))
        out.peak_pps_planned = max(out.peak_pps_planned, b.peak_pps_planned or 0.0)
        out.peak_pps_actual = max(out.peak_pps_actual, b.peak_pps_actual or 0.0)
        out.notes.extend(n for n in b.notes if n not in out.notes)
    return out


def _merge_devices(results: list[Result]) -> list[Device]:
    by_key: dict[tuple[int, str], Device] = {}
    for r in results:
        for d in r.devices:
            key = (d.instance, d.address_key)
            cur = by_key.get(key)
            if cur is None:
                by_key[key] = copy.deepcopy(d)
                continue
            for name in ("ip", "port", "snet", "sadr", "vendor_id", "max_apdu", "segmentation"):
                if getattr(cur, name) is None and getattr(d, name) is not None:
                    setattr(cur, name, getattr(d, name))
            for pname, pval in d.properties.items():
                cur.properties.setdefault(pname, copy.deepcopy(pval))
            for pname, perr in d.property_errors.items():
                cur.property_errors.setdefault(pname, perr)
            for pname in list(cur.property_errors):
                if pname in cur.properties:
                    del cur.property_errors[pname]
            cur.responded_to_scan = cur.responded_to_scan or d.responded_to_scan
            cur.seen_passively = cur.seen_passively or d.seen_passively
            cur.first_seen = _opt(min, cur.first_seen, d.first_seen)
            cur.last_seen = _opt(max, cur.last_seen, d.last_seen)
            cur.iam_count += d.iam_count
    return sorted(by_key.values(), key=lambda d: (d.instance, d.address_key))


def _opt(fn, a, b):
    if a is None:
        return b
    if b is None:
        return a
    return fn(a, b)


def _merge_bbmds(results: list[Result]) -> list[Bbmd]:
    by_key: dict[str, Bbmd] = {}
    for r in results:
        for b in r.bbmds:
            key = f"{b.ip}:{b.port}"
            cur = by_key.get(key)
            if cur is None:
                by_key[key] = copy.deepcopy(b)
                continue
            if _BBMD_STATUS_RANK.get(b.status, 9) < _BBMD_STATUS_RANK.get(cur.status, 9):
                cur.status = b.status
                cur.source = b.source
            if cur.bdt is None and b.bdt is not None:
                cur.bdt = copy.deepcopy(b.bdt)
            if cur.fdt is None and b.fdt is not None:
                cur.fdt = copy.deepcopy(b.fdt)
            if cur.fdt_status is None and b.fdt_status is not None:
                cur.fdt_status = b.fdt_status
    return list(by_key.values())


def _merge_findings(results: list[Result]) -> list[Finding]:
    by_key: dict[tuple[str, str], Finding] = {}
    for r in results:
        for f in r.findings:
            key = (f.id, f.subject)
            cur = by_key.get(key)
            if cur is None or f.severity.rank < cur.severity.rank:
                by_key[key] = copy.deepcopy(f)
    return list(by_key.values())


def _merge_dicts(results: list[Result], attr: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for r in results:
        src = getattr(r, attr) or {}
        if not isinstance(src, dict):
            continue
        for k, v in src.items():
            if attr == "metrics" and k == "checks_performed":
                continue
            if k not in out:
                out[k] = copy.deepcopy(v)
            elif out[k] != v:
                base = f"{r.run.kind}.{k}"
                name, i = base, 2
                while name in out and out[name] != v:
                    name = f"{base}.{i}"
                    i += 1
                out[name] = copy.deepcopy(v)
    return out
