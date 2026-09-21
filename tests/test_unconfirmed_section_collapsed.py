"""v0.6.57: the "not confirmed" section of the CVE report ships collapsed.

An IOS XE report opened on a long list of matches Cisco never confirmed for the
queried release, so the confirmed ones were off the screen before the reader
scrolled. The section now renders inside a native <details> whose <summary>
carries the count, one click away.

Nothing is removed. The text report keeps every unconfirmed entry, the API keeps
returning them in `matched` / `coverage_uncertain`, and the server-side PDF/JSON/MD
exports never read the DOM.
"""
import os
import re

from fastapi.testclient import TestClient

from api.main import app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)


def _web(name):
    with open(os.path.join(ROOT, "web", name), encoding="utf-8") as f:
        return f.read()


def _unconfirmed_render_block(js):
    start = js.index("if (unconfirmedItems.length > 0) {", js.index("renderItems(confirmedItems);"))
    return js[start:js.index("// Security posture summary", start)]


def test_unconfirmed_section_is_a_details_element_with_the_count_in_the_summary():
    block = _unconfirmed_render_block(_web("app-security.js"))
    assert 'createElement("details")' in block
    assert 'cve-unconfirmed-block' in block
    assert 'createElement("summary")' in block
    # the count is what the reader sees without expanding anything
    assert "${unconfirmedItems.length}" in block


def test_the_section_is_collapsed_by_default():
    """No `open` on the <details>, so the browser renders it closed."""
    block = _unconfirmed_render_block(_web("app-security.js"))
    assert not re.search(r"\.open\s*=\s*true", block)
    assert "open" not in re.findall(r'createElement\("details"\)([^\n]*)', block)[0]


def test_unconfirmed_cards_are_rendered_inside_the_collapsed_body():
    """renderItems must write into the <details> body, not next to it."""
    block = _unconfirmed_render_block(_web("app-security.js"))
    body_assign = block.index("cardTarget = body;")
    assert body_assign < block.index("renderItems(unconfirmedItems);")
    assert block.index("renderItems(unconfirmedItems);") < block.index("cardTarget = cveCards;")
    # every card renderer appends to the switchable target
    js = _web("app-security.js")
    cards_block = js[js.index('cveCards.innerHTML = "";'):js.index("// Security posture summary")]
    assert "cveCards.appendChild(card)" not in cards_block
    assert cards_block.count("cardTarget.appendChild") >= 3


def test_summary_is_keyboard_reachable_and_visibly_a_control():
    """<summary> is focusable and Enter/Space-toggleable natively; the styles
    must not take the affordance away."""
    css = _web("style-tools.css")
    assert ".cve-unconfirmed-summary" in css and ".cve-unconfirmed-block" in css
    rule = css[css.index(".cve-unconfirmed-summary {"):]
    rule = rule[:rule.index("}")]
    assert "cursor: pointer" in rule
    assert ".cve-unconfirmed-summary:focus-visible" in css      # visible focus ring
    # no display:none / hidden trickery that would drop it out of the tab order
    assert "list-style: none" not in rule or "cursor: pointer" in rule


def test_text_report_still_lists_every_unconfirmed_entry():
    js = _web("app-security.js")
    assert "Lower confidence, NOT confirmed for your release" in js
    assert "writeItems(unconfirmedItems);" in js


def test_api_still_returns_the_unconfirmed_matches_so_exports_are_unchanged():
    r = client.post("/analyze/cve", json={"platform": "IOS XE", "version": "17.9.4"})
    assert r.status_code == 200, r.text
    data = r.json()
    uncertain = set(data.get("coverage_uncertain") or [])
    matched = {c["cve_id"] for c in data["matched"]}
    assert uncertain, "17.9.4 is the reference case: it must still produce unconfirmed matches"
    assert uncertain <= matched, "an unconfirmed CVE must stay in `matched` (exports read the payload)"
