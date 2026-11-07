"""BBMD topology graph and broadcast-distribution simulation (design §3.5).

For every origin subnet that has at least one BBMD with a known BDT, the simulation follows one Original-Broadcast:

* the original broadcast is one copy in the origin subnet;
* every BBMD in the origin subnet forwards it to each BDT entry other than itself:
  - all-ones mask (one-hop): a Forwarded-NPDU unicast to the peer BBMD, which re-broadcasts it on its own subnet
    (one copy there);
  - any other mask (two-hop): the Forwarded-NPDU goes to the peer subnet's directed broadcast address (one copy there);
* a BBMD never re-forwards a Forwarded-NPDU to its own BDT peers (Annex J [TBV]), so there is no second hop.

The healthy result is exactly one copy per reachable subnet. More than one means duplicate distribution; zero means
a subnet that other BBMDs can reach is not reached from this origin.

Subnets of BBMDs outside the local subnet are known only through two-hop masks; otherwise they are labelled
``"subnet of <ip>"``.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from bacnet_health.model import Bbmd, BdtEntry

ALL_ONES = "255.255.255.255"

__all__ = ["build_topology", "subnet_of"]


def _addr(ip: str, port: int) -> str:
    return f"{ip}:{port}"


def subnet_of(ip: str, mask: str | None, local_subnet: str | None) -> str:
    """Subnet label for ``ip``: the local subnet if it contains ``ip``, the network from a directed (two-hop) mask,
    else ``"subnet of <ip>"``."""
    if local_subnet:
        try:
            if ipaddress.ip_address(ip) in ipaddress.ip_network(local_subnet, strict=False):
                return str(ipaddress.ip_network(local_subnet, strict=False))
        except ValueError:
            pass
    if mask and mask != ALL_ONES:
        try:
            return str(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
        except ValueError:
            pass
    return f"subnet of {ip}"


def build_topology(bbmds: list[Bbmd], local_subnet: str | None) -> dict[str, Any]:
    """Return ``{"nodes", "edges", "broadcast_copies", "broadcast_matrix", "notes"}``.

    ``broadcast_copies`` is ``{subnet: copies}`` for a broadcast originating in the local subnet (empty if the local
    subnet has no BBMD with a known BDT); ``broadcast_matrix`` is ``{origin_subnet: {target_subnet: copies}}``.
    """
    local = str(ipaddress.ip_network(local_subnet, strict=False)) if local_subnet else None
    known = {(b.ip, b.port): b for b in bbmds if b.status == "bbmd"}

    # Best subnet knowledge per BBMD address: a two-hop mask anywhere in any BDT identifies the subnet.
    masks: dict[tuple[str, int], str] = {}
    for b in known.values():
        for e in b.bdt or []:
            if e.mask != ALL_ONES:
                masks.setdefault((e.ip, e.port), e.mask)

    def sub(ip: str, port: int) -> str:
        return subnet_of(ip, masks.get((ip, port)), local)

    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []

    def node(nid: str, **attrs: Any) -> None:
        nodes.setdefault(nid, {"id": nid, **attrs})

    if local:
        node(local, type="subnet", local=True)
    for b in bbmds:
        a = _addr(b.ip, b.port)
        s = sub(b.ip, b.port)
        node(s, type="subnet", local=s == local)
        node(a, type="bbmd", status=b.status, source=b.source, subnet=s)
        edges.append({"from": a, "to": s, "type": "member"})
        for e in b.bdt or []:
            pa = _addr(e.ip, e.port)
            if pa == a:
                continue
            ps = sub(e.ip, e.port)
            node(ps, type="subnet", local=ps == local)
            node(pa, type="bbmd", status=known[(e.ip, e.port)].status if (e.ip, e.port) in known else "unread",
                 source="bdt-entry", subnet=ps)
            edges.append({"from": a, "to": pa, "type": "bdt", "mask": e.mask,
                          "distribution": "one-hop" if e.mask == ALL_ONES else "two-hop"})
        for f in b.fdt or []:
            fa = _addr(f.ip, f.port)
            node(fa, type="foreign-device")
            edges.append({"from": fa, "to": a, "type": "fdt", "ttl": f.ttl, "remaining": f.remaining})

    # all subnets that appear anywhere (targets for the simulation)
    all_subnets = sorted({n["id"] for n in nodes.values() if n["type"] == "subnet"})
    by_subnet: dict[str, list[Bbmd]] = {}
    for b in known.values():
        by_subnet.setdefault(sub(b.ip, b.port), []).append(b)

    matrix: dict[str, dict[str, int]] = {}
    notes: list[str] = []
    for origin in all_subnets:
        forwarders = [b for b in by_subnet.get(origin, []) if b.bdt is not None]
        if not forwarders:
            continue
        copies = dict.fromkeys(all_subnets, 0)
        copies[origin] = 1
        for b in forwarders:
            for e in b.bdt or []:
                if (e.ip, e.port) == (b.ip, b.port):
                    continue
                target = sub(e.ip, e.port) if e.mask == ALL_ONES else subnet_of(e.ip, e.mask, local)
                copies[target] = copies.get(target, 0) + 1
        matrix[origin] = copies
    unread = sorted(n["id"] for n in nodes.values() if n["type"] == "bbmd" and n.get("status") == "unread")
    if unread:
        notes.append("BDT peers not read (their own forwarding is not simulated): " + ", ".join(unread))
    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "broadcast_copies": dict(matrix.get(local, {})) if local else {},
        "broadcast_matrix": matrix,
        "local_subnet": local,
        "notes": notes,
    }


def bdt_lists(bdt: list[BdtEntry] | None, ip: str, port: int) -> bool:
    """True if ``bdt`` contains an entry for ``ip:port``."""
    return any(e.ip == ip and e.port == port for e in bdt or [])
