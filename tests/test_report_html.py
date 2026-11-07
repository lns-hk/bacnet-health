from __future__ import annotations

import base64
import os
import re
import sys
from html.parser import HTMLParser

import pytest

sys.path.insert(0, os.path.dirname(__file__))

from report_fixtures import HOSTILE_NAME, SAMPLE_LOGO_SVG, make_previous_result, make_rich_result  # noqa: E402

from bacnet_health import __version__  # noqa: E402
from bacnet_health.model import Bbmd, BdtEntry, FdtEntry, Result, RunInfo  # noqa: E402
from bacnet_health.report.branding import DEFAULT_ACCENT, Branding  # noqa: E402
from bacnet_health.report.diff import diff_results  # noqa: E402
from bacnet_health.report.html import render_html, svg_topology  # noqa: E402

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr",
        "path", "rect", "line", "circle", "polyline"}
SECTIONS = ["cover", "summary", "scope", "findings", "not-performed", "inventory", "topology", "methodology",
            "appendix"]


class Walker(HTMLParser):
    """Checks tag balance and collects ids, resource attributes and script/text content."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.ids: list[str] = []
        self.resources: list[str] = []
        self.errors: list[str] = []
        self.scripts = 0
        self.text: list[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.append(a["id"])
        for k in ("src", "href", "xlink:href", "action", "data"):
            if a.get(k):
                self.resources.append(a[k])
        if a.get("style") and "url(" in a["style"]:
            self.resources.append(a["style"])
        if tag == "script":
            self.scripts += 1
        if tag not in VOID:
            self.stack.append(tag)

    def handle_startendtag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.append(a["id"])
        for k in ("src", "href"):
            if a.get(k):
                self.resources.append(a[k])

    def handle_endtag(self, tag):
        if tag in VOID:
            return
        if not self.stack or self.stack[-1] != tag:
            self.errors.append(f"unexpected </{tag}>, open: {self.stack[-3:]}")
            if tag in self.stack:
                while self.stack and self.stack.pop() != tag:
                    pass
            return
        self.stack.pop()

    def handle_data(self, data):
        self.text.append(data)


def walk(doc: str) -> Walker:
    w = Walker()
    w.feed(doc)
    w.close()
    return w


@pytest.fixture
def logo(tmp_path):
    p = tmp_path / "logo.svg"
    p.write_text(SAMPLE_LOGO_SVG, encoding="utf-8")
    return str(p)


@pytest.fixture
def branding(logo):
    return Branding(org="Sample Consulting", prepared_by="A. Engineer", site="Sample Site", client="Sample Client",
                    logo_path=logo, accent="#335577")


def test_well_formed_and_sections(branding):
    doc = render_html(make_rich_result(), branding)
    w = walk(doc)
    assert not w.errors, w.errors
    assert w.stack == [], w.stack
    for sid in SECTIONS:
        assert sid in w.ids, sid
    assert "changes" not in w.ids
    assert len(w.ids) == len(set(w.ids)), "duplicate ids"
    assert doc.startswith("<!DOCTYPE html>")
    # section order
    positions = [doc.index(f'id="{s}"') for s in SECTIONS]
    assert positions == sorted(positions)


def test_no_external_resources(branding):
    doc = render_html(make_rich_result(), branding, diff=diff_results(make_previous_result(), make_rich_result()))
    w = walk(doc)
    for r in w.resources:
        assert r.startswith("#") or r.startswith("data:"), r
    assert "http://" not in doc and "https://" not in doc
    assert "@import" not in doc
    assert "<link" not in doc
    assert w.scripts == 1 and "<script src" not in doc


def test_internal_links_resolve(branding):
    doc = render_html(make_rich_result(), branding)
    w = walk(doc)
    for r in w.resources:
        if r.startswith("#"):
            assert r[1:] in w.ids, r


def test_escaping_hostile_strings():
    doc = render_html(make_rich_result(hostile=True), Branding(site='<script>x</script>', org='"><b>org'))
    assert "<script>alert" not in doc
    assert "<img src=x" not in doc
    assert "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;&amp;&lt;b&gt;" in doc
    assert "&lt;script&gt;x&lt;/script&gt;" in doc
    w = walk(doc)
    assert not w.errors and w.stack == []
    assert w.scripts == 1  # only the sorting script
    assert HOSTILE_NAME in "".join(w.text)  # rendered as visible text


def test_logo_embedded_and_accent(branding):
    doc = render_html(make_rich_result(), branding)
    expected = base64.b64encode(SAMPLE_LOGO_SVG.encode()).decode()
    assert f'src="data:image/svg+xml;base64,{expected}"' in doc
    assert "--accent:#335577" in doc


def test_accent_injection_rejected():
    doc = render_html(make_rich_result(), Branding(accent="red;}</style><script>alert(1)</script>"))
    assert f"--accent:{DEFAULT_ACCENT}" in doc
    assert "alert(1)" not in doc


def test_missing_logo_is_ignored(tmp_path):
    doc = render_html(make_rich_result(), Branding(logo_path=str(tmp_path / "nope.png")))
    assert "data:image" not in doc


def test_branding_load(tmp_path, logo):
    f = tmp_path / "brand.json"
    f.write_text('{"org": "Org", "prepared_by": "P", "site": "S", "client": "C", "logo": "logo.svg", '
                 '"accent_colour": "#abcdef", "extra": 1}', encoding="utf-8")
    (tmp_path / "logo.svg").write_text(SAMPLE_LOGO_SVG, encoding="utf-8")
    b = Branding.load(str(f))
    assert (b.org, b.prepared_by, b.site, b.client, b.accent) == ("Org", "P", "S", "C", "#abcdef")
    assert b.logo_path == str(tmp_path / "logo.svg")
    assert b.logo_data_uri().startswith("data:image/svg+xml;base64,")


def test_footer_version_and_prerelease(branding):
    doc = render_html(make_rich_result(), branding)
    assert f"Generated by bacnet-health v{__version__}" in doc
    if "a" in __version__ or "b" in __version__:
        assert "bacnet-health 0.1 is a pre-release and has not yet been validated on physical controllers." in doc
    assert "not yet been calibrated with field data" in doc


def test_finding_content(branding):
    doc = render_html(make_rich_result(), branding)
    assert "What would disprove this" in doc
    assert "Provisional" in doc and "Standard" in doc
    assert "BBMD-006" in doc and "Foreign device registered from a public address" in doc
    for label in ("Critical", "High", "Medium", "Low", "Info"):
        assert f'sev-{label.lower()}">{label}</span>' in doc
    # executive summary condition statement, no numeric score
    assert "1 critical issue that needs immediate attention" in doc
    assert "score" not in doc.lower().replace("not a score", "").replace("numeric score", "")
    # checks not performed listed
    assert "COMM-001" in doc and "Needs SPAN vantage" in doc


def test_inventory_and_topology(branding):
    doc = render_html(make_rich_result(), branding)
    assert 'class="inventory sortable"' in doc
    assert doc.count('<span class="tag remote">Remote</span>') == 3
    assert "non-operational" in doc
    assert 'aria-label="BBMD topology diagram"' in doc
    assert "BDT peer (not read)" in doc  # 203.0.113.1 is listed but not read
    assert "Duplicate distribution" in doc


def test_charts_from_metrics(branding):
    doc = render_html(make_rich_result(), branding)
    assert 'aria-label="BACnet broadcast rate over time"' in doc
    assert "(provisional)" in doc
    assert 'aria-label="Top broadcast sources"' in doc
    assert "cov-notification" in doc


def test_defensive_metrics():
    r = make_rich_result()
    r.metrics = {"broadcast_timeseries": [["x", 1], None, {"t": 1, "pps": "a"}, [1]],
                 "top_broadcast_sources": "junk", "service_counts": [1, 2], "duration_s": float("nan")}
    r.topology = {"broadcast_copies": "junk"}
    doc = render_html(r)
    assert "BACnet broadcast rate over time" not in doc
    w = walk(doc)
    assert not w.errors


def test_minimal_result_renders():
    r = Result(run=RunInfo(kind="analyze"))
    doc = render_html(r)
    w = walk(doc)
    assert not w.errors and w.stack == []
    for sid in SECTIONS:
        assert sid in w.ids
    assert "No findings were raised" in doc
    assert "No active traffic was sent" in doc
    assert "No BACnet devices were discovered" in doc


def test_diff_section(branding):
    new = make_rich_result()
    doc = render_html(new, branding, diff=diff_results(make_previous_result(), new))
    w = walk(doc)
    assert "changes" in w.ids
    assert doc.index('id="summary"') < doc.index('id="changes"') < doc.index('id="scope"')
    assert "Changes since previous visit" in doc
    assert "Not re-checked" in doc
    assert "firmware-revision" in doc and "4.8.0" in doc and "4.9.3" in doc


def test_topology_single_bbmd_and_many_fds():
    b = Bbmd("192.0.2.1", 47808, "bbmd", "probe", bdt=[BdtEntry("192.0.2.1", 47808, "255.255.255.255")],
             fdt=[FdtEntry(f"192.0.2.{i}", 47808, 60, 30) for i in range(100, 112)])
    svg = svg_topology([b])
    assert svg and "+6 more" in svg
    assert svg_topology([Bbmd("192.0.2.9", 47808, "not-bbmd", "probe")]) is None
    many = [Bbmd(f"192.0.2.{i}", 47808, "bbmd", "probe", bdt=[]) for i in range(1, 30)]
    assert svg_topology(many) is None


def test_print_css(branding):
    doc = render_html(make_rich_result(), branding)
    assert "@page" in doc and "@media print" in doc and "break-before:page" in doc
    assert re.search(r"thead\{display:table-header-group\}", doc)
