"""Generate packaging/windows/bacnet-health.ico (no third-party art).

A rounded square in the GUI accent colour with a white "pulse" line over three network nodes. Drawn with QPainter at
each size and packed into one .ico (PNG-compressed entries, supported since Windows Vista).

    python packaging/windows/make_icon.py [OUT.ico]
"""

from __future__ import annotations

import os
import struct
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QPointF, QRectF, Qt  # noqa: E402
from PySide6.QtGui import QColor, QGuiApplication, QImage, QPainter, QPainterPath, QPen  # noqa: E402

ACCENT = QColor("#1f4e79")  # same as bacnet_health.gui.theme.ACCENT
NODE = QColor("#9cc3e6")
SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)


def render(size: int) -> bytes:
    img = QImage(size, size, QImage.Format_ARGB32)
    img.fill(Qt.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.Antialiasing)
    s = size / 64.0  # design grid: 64 x 64
    inset = 1.0 * s if size >= 32 else 0.0
    p.setPen(Qt.NoPen)
    p.setBrush(ACCENT)
    p.drawRoundedRect(QRectF(inset, inset, size - 2 * inset, size - 2 * inset), 12 * s, 12 * s)
    if size >= 24:  # nodes are noise at 16/20 px
        p.setBrush(NODE)
        for x, y in ((14, 48), (32, 48), (50, 48)):
            p.drawEllipse(QPointF(x * s, y * s), 3.6 * s, 3.6 * s)
        p.setPen(QPen(NODE, max(1.0, 2.0 * s)))
        p.drawLine(QPointF(14 * s, 48 * s), QPointF(50 * s, 48 * s))
    path = QPainterPath(QPointF(8 * s, 30 * s))
    for x, y in ((20, 30), (25, 18), (32, 42), (38, 24), (42, 30), (56, 30)):
        path.lineTo(x * s, y * s)
    pen = QPen(Qt.white, max(1.6, 5.0 * s))
    pen.setJoinStyle(Qt.RoundJoin)
    pen.setCapStyle(Qt.RoundCap)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    p.drawPath(path)
    p.end()
    ba = QByteArray()
    buf = QBuffer(ba)
    buf.open(QIODevice.WriteOnly)
    img.save(buf, "PNG")
    return bytes(ba)


def write_ico(path: str) -> None:
    images = [(n, render(n)) for n in SIZES]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for n, png in images:
        dim = 0 if n >= 256 else n
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset + len(blobs))
        blobs += png
    with open(path, "wb") as fh:
        fh.write(header + entries + blobs)


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                             "bacnet-health.ico")
    _app = QGuiApplication.instance() or QGuiApplication([])
    write_ico(out)
    preview = os.environ.get("BH_ICON_PREVIEW")
    if preview:
        QImage.fromData(render(256)).save(preview)
    print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
