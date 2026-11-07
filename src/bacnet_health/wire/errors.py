"""Exception types shared by the wire codec."""

from __future__ import annotations


class DecodeError(ValueError):
    """Raised by every decoder on truncated, malformed or out-of-range input."""
