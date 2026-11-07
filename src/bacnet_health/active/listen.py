"""``listen``: passive observation through the tool's own UDP socket (vantage ``self``, design §1.3).

Nothing is transmitted. Every received datagram is decoded and fed to
:class:`~bacnet_health.analysis.passive.PassiveAnalyzer`; at the end the passive findings are evaluated for vantage
``self``. The destination address of each datagram comes from ``IP_RECVDSTADDR``/``IP_PKTINFO`` when the transport
was opened with ``want_dst=True`` and the OS supports it; otherwise broadcast BVLC functions are attributed to the
subnet broadcast address and everything else to the tool's own address.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Iterable

from bacnet_health.active.transport import BacnetTransport
from bacnet_health.analysis.passive import PassiveAnalyzer
from bacnet_health.capture.link import UdpDatagram
from bacnet_health.model import Bbmd, Result, RunInfo, Vantage, utcnow_iso
from bacnet_health.wire.constants import BvlcFunction as BF
from bacnet_health.wire.message import decode_message

__all__ = ["listen"]

_BROADCAST_FUNCTIONS = {BF.ORIGINAL_BROADCAST_NPDU, BF.FORWARDED_NPDU}


def listen(
    transport: BacnetTransport,
    duration_s: float,
    progress: Callable[[dict[str, Any]], None] | None = None,
    cancel: threading.Event | None = None,
    *,
    known_writers: Iterable[str] = (),
) -> Result:
    """Listen for ``duration_s`` seconds (or until ``cancel`` is set) and return a Result of kind ``"listen"``."""
    progress = progress or (lambda ev: None)
    cancel = cancel or transport.cancel
    analyzer = PassiveAnalyzer(own_addrs=set(transport.own_addrs))
    iface = getattr(transport, "iface", None)
    run = RunInfo(kind="listen", interface=iface.name if iface else None, local_ip=transport.local_ip,
                  netmask=iface.netmask if iface else None, broadcast=transport.broadcast, port=transport.port,
                  vantage=Vantage.SELF, vantage_source="listen")
    bcast_dst = transport.broadcast or "255.255.255.255"
    own_dst = transport.local_ip or transport.bind_ip
    frame_no = dst_known = 0
    start = time.monotonic()
    next_progress = start + 1.0
    while not cancel.is_set():
        now = time.monotonic()
        if now - start >= duration_s:
            break
        rec = transport.recv_datagram(min(0.1, duration_s - (now - start)))
        if now >= next_progress:
            next_progress = now + 1.0
            progress({"type": "listen", "elapsed": round(now - start, 1), "duration": duration_s,
                      "frames": frame_no, "devices": len(analyzer.s.devices)})
        if rec is None:
            continue
        frame_no += 1
        msg = decode_message(rec.data)
        if rec.dst_ip is not None:
            dst, dst_known = rec.dst_ip, dst_known + 1
        elif msg.bvlc is not None and msg.bvlc.function in _BROADCAST_FUNCTIONS:
            dst = bcast_dst
        else:
            dst = own_dst
        udp = UdpDatagram(frame_no=frame_no, ts=rec.ts, src_ip=rec.src[0], src_port=rec.src[1], dst_ip=dst,
                          dst_port=transport.port, payload=rec.data)
        analyzer.feed(udp, msg)
    state = analyzer.finish()
    run.finished = utcnow_iso()
    run.incomplete = cancel.is_set() and time.monotonic() - start < duration_s

    r = Result(run=run)
    r.devices = sorted(state.devices.values(), key=lambda d: (d.instance, d.address_key))
    for (ip, port), why in sorted(state.bbmd_candidates.items()):
        bdt, fdt = state.bdt_seen.get((ip, port)), state.fdt_seen.get((ip, port))
        r.bbmds.append(Bbmd(ip=ip, port=port, status="bbmd" if bdt is not None else "candidate", source="passive",
                            bdt=bdt, fdt=fdt, fdt_status="ack" if fdt is not None else None))
    elapsed = round(time.monotonic() - start, 3)
    r.metrics = {
        "listen": {"duration_s": elapsed, "requested_s": duration_s, "datagrams": frame_no,
                   "destination_known": dst_known, "transport": dict(transport.stats)},
        "inbound_verified": bool(transport.inbound_verified),
    }
    r.limitations = [
        "Listened through the tool's own socket (vantage 'self'): only broadcasts and traffic addressed to this "
        "computer were visible; device-to-device unicast was not.",
    ]
    if not r.metrics["inbound_verified"]:
        r.limitations.append("No BACnet datagram was received at all. The network may be silent, or inbound UDP to "
                             "this computer may be blocked (firewall); this was not verified.")
    if run.incomplete:
        r.limitations.append(f"Listening was stopped early after {elapsed:.0f} s.")
    try:
        from bacnet_health.findings import passive as fp
    except ImportError:
        r.limitations.append("Passive findings were not evaluated (findings module unavailable).")
        return r
    r.metrics.update(fp.build_metrics(state))
    findings, skipped = fp.evaluate_passive(state, Vantage.SELF, known_writers)
    r.findings, r.checks_not_performed = list(findings), list(skipped)
    if hasattr(fp, "performed_checks"):
        r.metrics["checks_performed"] = fp.performed_checks(skipped)
    return r
