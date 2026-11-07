"""Colours, the application style sheet and small painted icons (no image assets, no emoji)."""

from __future__ import annotations

from PySide6.QtCore import QPointF, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPainterPath, QPen, QPixmap, QPolygonF

ACCENT = "#1f4e79"
ACCENT_HOVER = "#173b5c"
ACCENT_SOFT = "#e7eef6"
BG = "#f4f5f7"
CARD = "#ffffff"
BORDER = "#d9dee4"
TEXT = "#1d2329"
MUTED = "#5b6570"
DANGER = "#b42318"
DANGER_HOVER = "#912018"
WARN_BG = "#fff6e5"
WARN_BORDER = "#e9b44c"
WARN_TEXT = "#6b4200"
ERR_BG = "#fdeceb"
ERR_BORDER = "#e8a29b"
OK = "#1e7a46"

# severity -> (text colour, background, label)
SEVERITY = {
    "critical": ("#ffffff", "#7a1616", "Critical"),
    "high": ("#ffffff", "#c0392b", "High"),
    "medium": ("#4a3000", "#f2c14e", "Medium"),
    "low": ("#ffffff", "#2f6fa8", "Low"),
    "info": ("#ffffff", "#66707b", "Info"),
}

STATUS = {
    "ok": (OK, "OK"),
    "warning": ("#b7791f", "Warning"),
    "error": (DANGER, "Problem"),
    "unknown": ("#7b8591", "Not checked"),
}


def stylesheet() -> str:
    return f"""
QMainWindow, QWidget#Page, QStackedWidget, QScrollArea, QWidget#ScrollBody {{ background: {BG}; }}
QWidget {{ color: {TEXT}; }}
QDialog {{ background: {BG}; }}
QFrame#Inset {{ background: #f7f9fb; border: 1px solid #e3e7ec; border-radius: 8px; }}
QLabel#AppTitle {{ font-size: 15pt; font-weight: 600; color: #ffffff; }}
QWidget#Header {{ background: {ACCENT}; }}
QLabel#HeaderVersion {{ color: #d5e1ee; }}
QLabel#Badge {{ color: {ACCENT}; background: #ffffff; border-radius: 9px; padding: 2px 9px;
                font-size: 8.5pt; font-weight: 600; }}
QLabel#PageTitle {{ font-size: 19pt; font-weight: 600; }}
QLabel#PageIntro, QLabel#Muted {{ color: {MUTED}; }}
QLabel#SectionTitle {{ font-size: 12pt; font-weight: 600; }}
QLabel#StepCrumb {{ color: {MUTED}; }}
QLabel#Sentence {{ font-size: 12pt; font-weight: 600; color: {ACCENT}; }}
QLabel#BigNumber {{ font-size: 26pt; font-weight: 600; color: {ACCENT}; }}
QFrame#Card {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 10px; }}
QFrame#Warn {{ background: {WARN_BG}; border: 1px solid {WARN_BORDER}; border-radius: 8px; }}
QFrame#Warn QLabel {{ color: {WARN_TEXT}; }}
QFrame#Error {{ background: {ERR_BG}; border: 1px solid {ERR_BORDER}; border-radius: 8px; }}
QFrame#Error QLabel {{ color: #7a1a12; }}
QFrame#Info {{ background: {ACCENT_SOFT}; border: 1px solid #bfd0e3; border-radius: 8px; }}
QFrame#DropZone {{ background: {CARD}; border: 2px dashed #a9b4c0; border-radius: 12px; }}
QFrame#DropZone[hover="true"] {{ border-color: {ACCENT}; background: {ACCENT_SOFT}; }}
QPushButton {{ background: {CARD}; border: 1px solid #b9c2cc; border-radius: 6px; padding: 7px 16px;
               min-height: 20px; }}
QPushButton:hover {{ background: #eef1f4; }}
QPushButton:focus {{ border: 2px solid {ACCENT}; padding: 6px 15px; }}
QPushButton:disabled {{ color: #9aa3ad; background: #f1f3f5; border-color: #dde1e6; }}
QPushButton#Primary {{ background: {ACCENT}; color: #ffffff; border: 1px solid {ACCENT}; font-weight: 600; }}
QPushButton#Primary:hover {{ background: {ACCENT_HOVER}; }}
QPushButton#Primary:focus {{ border: 2px solid #0b2033; }}
QPushButton#Primary:disabled {{ background: #9fb3c8; border-color: #9fb3c8; color: #f4f7fa; }}
QPushButton#Danger {{ background: {DANGER}; color: #ffffff; border: 1px solid {DANGER}; font-size: 14pt;
                      font-weight: 700; padding: 12px 40px; border-radius: 8px; }}
QPushButton#Danger:hover {{ background: {DANGER_HOVER}; }}
QPushButton#Danger:focus {{ border: 3px solid #3d0a06; }}
QPushButton#Danger:disabled {{ background: #d99a94; border-color: #d99a94; }}
QPushButton#HomeButton {{ background: {CARD}; border: 1px solid {BORDER}; border-radius: 12px; padding: 0px;
                          text-align: left; }}
QPushButton#HomeButton:hover {{ border: 1px solid {ACCENT}; background: #fbfcfe; }}
QPushButton#HomeButton:focus {{ border: 2px solid {ACCENT}; }}
QPushButton#Link {{ background: transparent; border: none; color: {ACCENT}; text-decoration: underline;
                    padding: 2px 0px; text-align: left; }}
QPushButton#Link:focus {{ border: 1px dotted {ACCENT}; }}
QLineEdit, QPlainTextEdit, QSpinBox, QDoubleSpinBox, QComboBox {{ background: #ffffff; border: 1px solid #b9c2cc;
    border-radius: 5px; padding: 5px 7px; selection-background-color: {ACCENT}; }}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border: 2px solid {ACCENT}; padding: 4px 6px; }}
QLineEdit:read-only, QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled,
QPlainTextEdit:read-only {{ background: #eef0f3; color: #4b5560; }}
QPlainTextEdit#Mono {{ font-family: "Consolas", "Menlo", "DejaVu Sans Mono", monospace; font-size: 9pt; }}
QListWidget, QTreeWidget, QTableWidget {{ background: #ffffff; border: 1px solid {BORDER}; border-radius: 6px; }}
QListWidget::item, QTreeWidget::item {{ padding: 5px 4px; }}
QListWidget::item:selected, QTreeWidget::item:selected {{ background: {ACCENT_SOFT}; color: {TEXT}; }}
QProgressBar {{ border: 1px solid {BORDER}; border-radius: 6px; background: #e9ecef; height: 14px;
                text-align: center; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 5px; }}
QCheckBox {{ spacing: 8px; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 6px; background: {CARD}; top: -1px; }}
QTabBar::tab {{ padding: 7px 14px; border: 1px solid transparent; }}
QTabBar::tab:selected {{ background: {CARD}; border: 1px solid {BORDER}; border-bottom-color: {CARD};
                         border-top-left-radius: 6px; border-top-right-radius: 6px; font-weight: 600; }}
QGroupBox {{ font-weight: 600; border: 1px solid {BORDER}; border-radius: 8px; margin-top: 12px;
             padding: 14px 10px 10px 10px; background: {CARD}; }}
QGroupBox::title {{ subcontrol-origin: margin; left: 10px; padding: 0 4px; }}
QToolTip {{ background: #ffffff; color: {TEXT}; border: 1px solid {BORDER}; padding: 4px; }}
"""


def _pixmap(size: int) -> tuple[QPixmap, QPainter]:
    pm = QPixmap(size * 2, size * 2)
    pm.setDevicePixelRatio(2.0)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    return pm, p


def status_icon(status: str, size: int = 18) -> QIcon:
    """A small painted status marker; shape differs per status so it is not colour-only."""
    colour = QColor(STATUS.get(status, STATUS["unknown"])[0])
    pm, p = _pixmap(size)
    s = float(size)
    pen = QPen(QColor("#ffffff"), s * 0.13, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    if status == "warning":
        p.setPen(Qt.NoPen)
        p.setBrush(colour)
        p.drawPolygon(QPolygonF([QPointF(s / 2, s * 0.06), QPointF(s * 0.96, s * 0.92), QPointF(s * 0.04, s * 0.92)]))
        p.setPen(pen)
        p.drawLine(QPointF(s / 2, s * 0.38), QPointF(s / 2, s * 0.62))
        p.drawPoint(QPointF(s / 2, s * 0.78))
    else:
        p.setPen(Qt.NoPen)
        p.setBrush(colour)
        p.drawEllipse(QRectF(s * 0.04, s * 0.04, s * 0.92, s * 0.92))
        p.setPen(pen)
        if status == "ok":
            path = QPainterPath(QPointF(s * 0.28, s * 0.52))
            path.lineTo(s * 0.44, s * 0.68)
            path.lineTo(s * 0.73, s * 0.34)
            p.setBrush(Qt.NoBrush)
            p.drawPath(path)
        elif status == "error":
            p.drawLine(QPointF(s * 0.33, s * 0.33), QPointF(s * 0.67, s * 0.67))
            p.drawLine(QPointF(s * 0.67, s * 0.33), QPointF(s * 0.33, s * 0.67))
        else:
            f = QFont()
            f.setPixelSize(int(s * 0.7))
            f.setBold(True)
            p.setFont(f)
            p.drawText(QRectF(0, 0, s, s), Qt.AlignCenter, "?")
    p.end()
    return QIcon(pm)


def lock_icon(size: int = 16) -> QIcon:
    pm, p = _pixmap(size)
    s = float(size)
    c = QColor(MUTED)
    p.setPen(QPen(c, s * 0.12))
    p.setBrush(Qt.NoBrush)
    p.drawArc(QRectF(s * 0.28, s * 0.08, s * 0.44, s * 0.5), 0, 180 * 16)
    p.drawLine(QPointF(s * 0.28, s * 0.33), QPointF(s * 0.28, s * 0.46))
    p.drawLine(QPointF(s * 0.72, s * 0.33), QPointF(s * 0.72, s * 0.46))
    p.setPen(Qt.NoPen)
    p.setBrush(c)
    p.drawRoundedRect(QRectF(s * 0.16, s * 0.44, s * 0.68, s * 0.5), s * 0.08, s * 0.08)
    p.end()
    return QIcon(pm)


def home_icon(kind: str, size: int = 44) -> QPixmap:
    """Simple line pictograms for the three home buttons."""
    pm, p = _pixmap(size)
    s = float(size)
    p.setBrush(QColor(ACCENT_SOFT))
    p.setPen(Qt.NoPen)
    p.drawRoundedRect(QRectF(0, 0, s, s), s * 0.22, s * 0.22)
    pen = QPen(QColor(ACCENT), s * 0.07, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.NoBrush)
    if kind == "check":
        # pulse line
        path = QPainterPath(QPointF(s * 0.18, s * 0.52))
        for x, y in ((0.36, 0.52), (0.44, 0.3), (0.56, 0.72), (0.64, 0.52), (0.82, 0.52)):
            path.lineTo(s * x, s * y)
        p.drawPath(path)
    elif kind == "file":
        p.drawRoundedRect(QRectF(s * 0.3, s * 0.2, s * 0.4, s * 0.6), s * 0.05, s * 0.05)
        for y in (0.38, 0.5, 0.62):
            p.drawLine(QPointF(s * 0.38, s * y), QPointF(s * 0.62, s * y))
    else:
        p.drawRoundedRect(QRectF(s * 0.2, s * 0.26, s * 0.28, s * 0.48), s * 0.04, s * 0.04)
        p.drawRoundedRect(QRectF(s * 0.52, s * 0.26, s * 0.28, s * 0.48), s * 0.04, s * 0.04)
    p.end()
    return pm
