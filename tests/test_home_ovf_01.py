"""HOME-OVF-01: the Cisco advisories rows on Home must not push the page sideways
on a phone.

Every chip in a row (score, CVE, KEV badge, date, severity) is flex-shrink:0, so a
row with a KEV badge measured ~520 px on a 390 px screen and the whole page scrolled
horizontally. Below 768 px the row now wraps; above it nothing changes.

Static check of the stylesheet, as in test_unconfirmed_section_collapsed.py. The
layout itself was measured in headless Chrome (scrollWidth 519 -> 390 at 390 px,
widget geometry at 1280 px identical before and after).
"""
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _css():
    with open(os.path.join(ROOT, "web", "style-home.css"), encoding="utf-8") as f:
        return f.read()


def _block(text, start):
    """Body of the `{...}` block that opens at `start` (handles one nesting level)."""
    i = text.index("{", start) + 1
    depth = 1
    j = i
    while depth:
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
        j += 1
    return text[i:j - 1]


def _rule(text, selector):
    m = re.search(r"(^|\n)\s*" + re.escape(selector) + r"\s*\{", text)
    assert m, selector
    return _block(text, m.start())


def _mobile_block(css):
    """The @media (max-width: 768px) block that styles the advisories header."""
    for m in re.finditer(r"@media \(max-width: 768px\)\s*\{", css):
        body = _block(css, m.start())
        if ".cisco-advisories-header" in body:
            return body
    raise AssertionError("no mobile block for the advisories widget")


def test_rows_wrap_on_narrow_screens():
    mobile = _mobile_block(_css())
    item = _rule(mobile, ".cisco-advisories-item")
    assert "flex-wrap: wrap" in item
    assert "min-width: 0" in item
    # date + severity stay together, pushed to the right edge
    assert "margin-left: auto" in _rule(mobile, ".cisco-advisories-date")


def test_kev_badge_stays_visible_on_mobile():
    """The fix moves the KEV badge to its own line; it must not hide it."""
    mobile = _mobile_block(_css())
    hidden = [sel for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", mobile)
              if "display: none" in body]
    assert hidden, "the mobile block still hides the description and the extra chips"
    assert not any(".cisco-advisories-kev" in sel for sel in hidden)
    assert "order: 1" in _rule(mobile, ".cisco-advisories-kev")


def test_desktop_row_is_unchanged():
    css = _css()
    desktop = css[:css.index("@media (max-width: 768px)", css.index(".cisco-advisories-card {"))]
    item = _rule(desktop, ".cisco-advisories-item")
    assert "flex-wrap" not in item
    assert "white-space: nowrap" in _rule(desktop, ".cisco-advisories-desc")
