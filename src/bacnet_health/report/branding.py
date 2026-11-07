"""White-label branding for the HTML report.

A branding file is JSON, for example::

    {
      "org": "Sample Consulting",
      "prepared_by": "A. Engineer",
      "site": "Sample Site",
      "client": "Sample Client",
      "logo_path": "logo.png",
      "accent": "#1f4e79"
    }

``logo`` is accepted as an alias of ``logo_path`` and ``accent_colour``/``accent_color`` as aliases of ``accent``.
A relative ``logo_path`` is resolved against the directory of the branding file. Unknown keys are ignored.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any

DEFAULT_ACCENT = "#1f4e79"

_HEX_COLOUR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6})$")

_LOGO_MIME = {
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
}

MAX_LOGO_BYTES = 2 * 1024 * 1024


@dataclass
class Branding:
    org: str = ""
    prepared_by: str = ""
    site: str = ""
    client: str = ""
    logo_path: str | None = None
    accent: str = DEFAULT_ACCENT

    @classmethod
    def load(cls, path: str) -> "Branding":
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError(f"branding file {path!r} must contain a JSON object")
        return cls.from_dict(data, base_dir=os.path.dirname(os.path.abspath(path)))

    @classmethod
    def from_dict(cls, data: dict[str, Any], base_dir: str | None = None) -> "Branding":
        logo = data.get("logo_path", data.get("logo"))
        if logo and base_dir and not os.path.isabs(str(logo)):
            logo = os.path.join(base_dir, str(logo))
        accent = data.get("accent", data.get("accent_colour", data.get("accent_color", DEFAULT_ACCENT)))
        return cls(
            org=str(data.get("org", "") or ""),
            prepared_by=str(data.get("prepared_by", "") or ""),
            site=str(data.get("site", "") or ""),
            client=str(data.get("client", "") or ""),
            logo_path=str(logo) if logo else None,
            accent=str(accent or DEFAULT_ACCENT),
        )

    def safe_accent(self) -> str:
        """The accent colour if it is a plain #rgb/#rrggbb value, else the default (prevents CSS injection)."""
        a = (self.accent or "").strip()
        return a if _HEX_COLOUR.match(a) else DEFAULT_ACCENT

    def logo_data_uri(self) -> str | None:
        """The logo as a base64 data URI, or None if there is no usable logo file."""
        if not self.logo_path:
            return None
        ext = os.path.splitext(self.logo_path)[1].lower()
        mime = _LOGO_MIME.get(ext)
        if mime is None:
            return None
        try:
            if os.path.getsize(self.logo_path) > MAX_LOGO_BYTES:
                return None
            with open(self.logo_path, "rb") as fh:
                raw = fh.read()
        except OSError:
            return None
        if not raw:
            return None
        return f"data:{mime};base64,{base64.b64encode(raw).decode('ascii')}"
