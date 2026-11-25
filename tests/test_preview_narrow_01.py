"""PREVIEW-NARROW-01: the preview form ("Check your Cisco release") must fit a
320-360 px screen.

The grid column was `1fr`, which is `minmax(auto, 1fr)`: its minimum is the
min-content width of the platform <select>, set by the longest option
("Cisco Catalyst SD-WAN Controller (vSmart)", 324 px). At 320 and 360 px the form
was 361 px wide and the page scrolled sideways (only with PREVIEW_ENABLED=1).

Static check of the stylesheet, as in test_home_ovf_01.py. Measured in headless
Chrome with every <details> open: scrollWidth 362 -> 320 at 320 px, 361 -> 360 at
360 px, 390 unchanged at 390 px, form geometry at 1280 px identical.
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _css():
    with open(os.path.join(ROOT, "web", "style-home.css"), encoding="utf-8") as f:
        return f.read()


def _decls(css, selector):
    """Every declaration block written for exactly `selector`, in file order."""
    out = []
    for m in re.finditer(r"(^|[\n}])\s*" + re.escape(selector) + r"\s*\{([^}]*)\}", css):
        out.append(m.group(2))
    return out


def test_form_columns_have_a_zero_minimum():
    cols = [d for d in _decls(_css(), ".preview-form") if "grid-template-columns" in d]
    assert len(cols) == 2, cols          # desktop rule + the <=600 px rule
    for d in cols:
        value = re.search(r"grid-template-columns:\s*([^;]+);", d).group(1).strip()
        assert value in ("auto minmax(0, 1fr)", "minmax(0, 1fr)"), value


def test_select_and_input_may_shrink():
    css = _css()
    m = re.search(r"\.preview-form select,\s*\.preview-form input\s*\{([^}]*)\}", css)
    assert m, "no shrink rule for the preview form fields"
    assert "min-width: 0" in m.group(1)
    assert "max-width: 100%" in m.group(1)
