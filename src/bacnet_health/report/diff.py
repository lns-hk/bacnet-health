"""Compare two Results from different visits to the same site.

Device identity is ``(instance, vendor_id)`` (design §5). If several devices share one identity (for example a
duplicate device instance), they are paired by ``address_key`` first and then in order.

Return value (plain JSON-able dict)::

    {
      "old": {"started", "kind", "site", "tool_version"},
      "new": {...},
      "devices": {
        "added":   [DeviceRef, ...],
        "removed": [DeviceRef, ...],
        "changed": [DeviceRef + {"changes": [{"field", "old", "new"}, ...]}, ...],
        "unchanged": int,
      },
      "findings": {
        "new":          [FindingRef, ...],
        "resolved":     [FindingRef, ...],
        "persisting":   [FindingRef + {"old_severity"}, ...],
        "not_rechecked":[FindingRef, ...],   # gone, but the new run lists the check as not performed
      },
      "summary": {"devices_added", "devices_removed", "devices_changed",
                  "findings_new", "findings_resolved", "findings_persisting", "findings_not_rechecked"},
    }

``DeviceRef`` = ``{"instance", "vendor_id", "address", "object_name"}``;
``FindingRef`` = ``{"id", "subject", "title", "severity"}``.

Compared device fields: the properties in ``COMPARED_PROPERTIES`` and ``address`` (ip:port, including the routed
network/MAC for remote devices). A property is only compared when both visits have a value for it, so a property
that was simply not read on one visit (e.g. a remote device without ``read-remote``) is not reported as a change.
"""

from __future__ import annotations

from typing import Any

from bacnet_health.model import Device, Finding, Result

COMPARED_PROPERTIES = (
    "firmware-revision",
    "application-software-version",
    "database-revision",
    "object-name",
    "model-name",
)


def prop(d: Device, name: str) -> Any:
    """Property lookup tolerant of ``object-name`` / ``object_name`` spelling."""
    if name in d.properties:
        return d.properties[name]
    alt = name.replace("-", "_")
    return d.properties.get(alt)


def _device_ref(d: Device) -> dict[str, Any]:
    name = prop(d, "object-name")
    return {
        "instance": d.instance,
        "vendor_id": d.vendor_id,
        "address": d.address_key,
        "object_name": None if name is None else str(name),
    }


def _finding_ref(f: Finding) -> dict[str, Any]:
    return {"id": f.id, "subject": f.subject, "title": f.title, "severity": f.severity.value}


def _run_ref(r: Result) -> dict[str, Any]:
    return {
        "started": r.run.started,
        "kind": r.run.kind,
        "site": r.run.site,
        "tool_version": (r.tool or {}).get("version"),
    }


def _norm(v: Any) -> str:
    return str(v).strip()


def _pair(old: list[Device], new: list[Device]) -> tuple[list[tuple[Device, Device]], list[Device], list[Device]]:
    old_left, new_left = list(old), list(new)
    pairs: list[tuple[Device, Device]] = []
    for o in list(old_left):
        match = next((n for n in new_left if n.address_key == o.address_key), None)
        if match is not None:
            pairs.append((o, match))
            old_left.remove(o)
            new_left.remove(match)
    while old_left and new_left:
        pairs.append((old_left.pop(0), new_left.pop(0)))
    return pairs, old_left, new_left


def diff_results(old: Result, new: Result) -> dict[str, Any]:
    def group(devs: list[Device]) -> dict[tuple[int, int | None], list[Device]]:
        g: dict[tuple[int, int | None], list[Device]] = {}
        for d in devs:
            g.setdefault((d.instance, d.vendor_id), []).append(d)
        return g

    og, ng = group(old.devices), group(new.devices)
    added: list[dict[str, Any]] = []
    removed: list[dict[str, Any]] = []
    changed: list[dict[str, Any]] = []
    unchanged = 0
    for key in sorted(set(og) | set(ng), key=lambda k: (k[0], -1 if k[1] is None else k[1])):
        pairs, gone, fresh = _pair(og.get(key, []), ng.get(key, []))
        removed.extend(_device_ref(d) for d in gone)
        added.extend(_device_ref(d) for d in fresh)
        for o, n in pairs:
            changes = []
            for p in COMPARED_PROPERTIES:
                ov, nv = prop(o, p), prop(n, p)
                if ov is not None and nv is not None and _norm(ov) != _norm(nv):
                    changes.append({"field": p, "old": _norm(ov), "new": _norm(nv)})
            if o.address_key != n.address_key:
                changes.append({"field": "address", "old": o.address_key, "new": n.address_key})
            if changes:
                ref = _device_ref(n)
                ref["changes"] = changes
                changed.append(ref)
            else:
                unchanged += 1

    of = {(f.id, f.subject): f for f in old.findings}
    nf = {(f.id, f.subject): f for f in new.findings}
    not_checked = {str(c.get("id", "")) for c in new.checks_not_performed}

    def sort_key(f: Finding) -> tuple[int, str, str]:
        return (f.severity.rank, f.id, f.subject)

    new_list = [_finding_ref(f) for f in sorted((nf[k] for k in nf if k not in of), key=sort_key)]
    persisting = []
    for f in sorted((nf[k] for k in nf if k in of), key=sort_key):
        ref = _finding_ref(f)
        ref["old_severity"] = of[(f.id, f.subject)].severity.value
        persisting.append(ref)
    resolved, not_rechecked = [], []
    for f in sorted((of[k] for k in of if k not in nf), key=sort_key):
        (not_rechecked if f.id in not_checked else resolved).append(_finding_ref(f))

    return {
        "old": _run_ref(old),
        "new": _run_ref(new),
        "devices": {"added": added, "removed": removed, "changed": changed, "unchanged": unchanged},
        "findings": {
            "new": new_list,
            "resolved": resolved,
            "persisting": persisting,
            "not_rechecked": not_rechecked,
        },
        "summary": {
            "devices_added": len(added),
            "devices_removed": len(removed),
            "devices_changed": len(changed),
            "findings_new": len(new_list),
            "findings_resolved": len(resolved),
            "findings_persisting": len(persisting),
            "findings_not_rechecked": len(not_rechecked),
        },
    }
