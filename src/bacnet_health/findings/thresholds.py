"""Finding thresholds. Every value is PROVISIONAL until calibrated against field captures (design D12)."""

from __future__ import annotations

from typing import Any

# name -> (value, provisional, unit/description)
THRESHOLDS: dict[str, tuple[Any, bool, str]] = {
    "bcast_rate_medium_pps": (20, True, "sustained BACnet broadcasts per second over a 60 s window (Medium)"),
    "bcast_rate_high_pps": (100, True, "sustained BACnet broadcasts per second over a 60 s window (High)"),
    "bcast_window_s": (60, True, "window for broadcast-rate evaluation, seconds"),
    "whois_storm_pps": (10, True, "Who-Is per second over a 10 s window"),
    "whois_storm_window_s": (10, True, "window for Who-Is storm, seconds"),
    "global_whois_per_source_per_10s": (1, True, "sustained global Who-Is per source per 10 s"),
    "iam_storm_pps": (50, True, "I-Am per second over a 10 s window"),
    "iam_reannounce_per_min": (1, True, "I-Am from one device per minute, sustained (unsolicited)"),
    "global_whois_ratio": (0.5, True, "share of unranged Who-Is above which BCAST-004 applies"),
    "global_whois_min_per_hour": (20, True, "minimum Who-Is per hour for BCAST-004"),
    "dup_forward_window_s": (0.05, True, "window for identical NPDUs to count as duplicate forwarding"),
    "dup_forward_critical_per_s": (1.0, True, "duplicate forwarded broadcasts per second for Critical"),
    "error_ratio": (0.05, True, "(Reject+Abort)/confirmed requests per device"),
    "error_min_requests": (50, True, "minimum confirmed requests before error ratio is evaluated"),
    "unanswered_ratio_medium": (0.10, True, "unanswered confirmed requests (Medium)"),
    "unanswered_ratio_high": (0.30, True, "unanswered confirmed requests (High)"),
    "unanswered_timeout_s": (10.0, True, "time after which a confirmed request counts as unanswered"),
    "unanswered_min_requests": (20, True, "minimum confirmed requests before unanswered ratio is evaluated"),
    "clock_skew_low_s": (120, True, "device clock offset (Low)"),
    "clock_skew_medium_s": (3600, True, "device clock offset (Medium)"),
    "min_protocol_revision": (14, True, "protocol-revision below which DEV-007 is reported"),
    "fdt_ttl_max_s": (3600, True, "FDT time-to-live above which BBMD-007 applies"),
    "standard_port": (47808, False, "BACnet/IP default UDP port (0xBAC0), Annex J"),
}


def th(name: str) -> Any:
    return THRESHOLDS[name][0]


def used(*names: str) -> dict[str, dict[str, Any]]:
    """Build Finding.thresholds_used for the given threshold names."""
    return {n: {"value": THRESHOLDS[n][0], "provisional": THRESHOLDS[n][1], "meaning": THRESHOLDS[n][2]} for n in names}
