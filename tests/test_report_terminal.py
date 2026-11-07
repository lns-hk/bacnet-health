from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from report_fixtures import make_rich_result  # noqa: E402

from bacnet_health import __version__  # noqa: E402
from bacnet_health.model import Result, RunInfo  # noqa: E402
from bacnet_health.report.terminal import render_terminal  # noqa: E402


def test_terminal_plain():
    out = render_terminal(make_rich_result())
    assert "\033[" not in out
    assert f"bacnet-health {__version__}" in out
    assert "Findings: 1 critical, 2 high, 3 medium, 2 low, 2 info" in out
    assert "Checks not performed: 4" in out
    lines = [ln for ln in out.splitlines() if ln.startswith("  ") and ln.strip()]
    sevs = [ln.split()[0] for ln in lines]
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    assert sevs == sorted(sevs, key=order.index)
    assert lines[0].split()[1] == "BBMD-006"
    assert "Devices: 12 (3 remote)" in out


def test_terminal_colour():
    out = render_terminal(make_rich_result(), color=True)
    assert "\033[1;37;41mCRITICAL" in out and "\033[0m" in out


def test_terminal_strips_control_chars():
    r = make_rich_result()
    r.findings[0].title = "evil\033[2Jtitle"
    out = render_terminal(r)
    assert "\033" not in out


def test_terminal_empty():
    out = render_terminal(Result(run=RunInfo(kind="scan")))
    assert "(none)" in out and "Checks not performed: 0" in out
