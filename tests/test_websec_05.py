"""
WEBSEC-01b, conditions W1 and W2 from the @ciso review 11.11
(raporty/zespol/2026-11-11_ciso-autonomia-4-galezie_review.md).

W1: two sinks of the same class as WEBSEC-01 were left: the CVE Analyzer error
    card (app-security.js) put `err.message` into innerHTML, and showToast
    (app-core.js) rendered title/message via innerHTML while app-profiles.js
    passes `err.message` to it. Both are text now; esc() moved to app-core.js,
    which loads before every app-*.js that uses it.
W2: mitigation steps come from cve_mitigations/*.json and hold placeholders
    like <STRING> / <V3GROUP>; the HTML parser swallowed them. Steps are built as
    DOM with textContent, and reference / Cisco source links accept only https:.
"""
import json
import os
import re
import shutil

import pytest

from tests.test_websec_03 import ROOT, _js_function, _node, _web

XSS = "<img src=x onerror=alert(1)>"
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

# Minimal DOM: any innerHTML write with a tag throws, so a markup path fails loudly.
FAKE_DOM = r"""
let markupWrites = 0;
class FakeNode {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this._text = ""; this.className = "";
    this.style = {}; this.value = ""; this.href = ""; this.id = ""; this.listeners = 0; }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...c) { this.children = c; this._text = ""; }
  remove() {}
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  set innerHTML(v) { if (/</.test(String(v))) { markupWrites++; throw new Error("markup: " + v); } this.children = []; this._text = ""; }
  addEventListener() { this.listeners++; }
}
const nodes = {};
const document = {
  createElement: t => new FakeNode(t),
  getElementById: id => (nodes[id] = nodes[id] || new FakeNode("div")),
  body: new FakeNode("body"),
};
function dump(n) { return { tag: n.tagName, cls: n.className, text: n._text, value: n.value, href: n.href,
  kids: n.children.map(dump) }; }
"""


def _record(cve):
    with open(os.path.join(ROOT, "cve_mitigations", cve + ".json"), encoding="utf-8") as f:
        return json.load(f)


class TestW1ErrorSinks:
    def test_esc_lives_in_core_and_core_loads_first(self):
        assert re.search(r"^function esc\(", _web("app-core.js"), re.M)
        for name in ("app-feeds.js", "app-network.js", "app-security.js", "app-profiles.js", "app-kev.js"):
            assert not re.search(r"^function esc\(", _web(name), re.M), name
        html = open(os.path.join(ROOT, "web", "index.html"), encoding="utf-8").read()
        order = re.findall(r'<script src="(app-[a-z]+)\.js', html)
        core = order.index("app-core")
        for name in order:
            if name != "app-gate" and re.search(r"\besc\(", _web(name + ".js")):
                assert order.index(name) >= core, name
        assert not re.search(r"\besc\(", _web("app-gate.js"))

    def test_cve_analyzer_error_card_escapes(self):
        js = _web("app-security.js")
        assert "Error during CVE analysis: ${esc(err.message)}" in js

    def test_show_toast_has_no_markup_path(self):
        assert "innerHTML" not in _js_function(_web("app-core.js"), "showToast")

    @needs_node
    def test_show_toast_renders_error_text_as_text(self):
        script = (FAKE_DOM + _js_function(_web("app-core.js"), "showToast") + "\n"
                  + "globalThis.setTimeout = () => 0;\n"
                  + "showToast(%s, 'Error: ' + %s, true);\n" % (json.dumps("Export " + XSS), json.dumps(XSS))
                  + "showToast('only title');\n"
                  + "process.stdout.write(JSON.stringify({ body: dump(document.body), markupWrites }));")
        out = json.loads(_node(script))
        assert out["markupWrites"] == 0
        first, second = out["body"]["kids"]
        assert first["cls"] == "toast"
        assert [(k["cls"], k["text"]) for k in first["kids"]] == [("toast-title", "Export " + XSS), ("", "Error: " + XSS)]
        assert [k["text"] for k in second["kids"]] == ["only title", ""]  # no literal "undefined"


def _mitigation_script(call):
    net = _web("app-network.js")
    core = _web("app-core.js")
    return (FAKE_DOM
            + _js_function(core, "safeHttpsUrl") + "\n"
            + "\n".join(_js_function(net, f) for f in ("setText", "renderWorkarounds", "renderReferences",
                                                       "renderCiscoWorkaround")) + "\n"
            + re.search(r"const CISCO_STATUS_TEXT = \{.*?\};", net, re.S).group(0) + "\n"
            + call + "\n"
            + "process.stdout.write(JSON.stringify({ nodes: Object.fromEntries(Object.entries(nodes).map(([k, v]) => [k, dump(v)])), markupWrites }));")


class TestW2Mitigations:
    @needs_node
    def test_cve_2017_6736_placeholders_show_literally(self):
        rec = _record("CVE-2017-6736")
        assert any("<STRING>" in (s.get("platform_notes") or "") for s in rec["workaround_steps"])
        out = json.loads(_node(_mitigation_script("renderWorkarounds(%s);" % json.dumps(rec["workaround_steps"]))))
        assert out["markupWrites"] == 0
        steps = out["nodes"]["mitigation-workarounds"]["kids"]
        assert len(steps) == len(rec["workaround_steps"])
        for node, step in zip(steps, rec["workaround_steps"]):
            h4 = node["kids"][0]
            assert (h4["tag"], h4["text"]) == ("H4", "Step %s: %s" % (step["order"], step["description"]))
            if step.get("platform_notes"):
                notes = node["kids"][1]
                assert notes["cls"] == "step-notes"
                assert notes["kids"][0]["text"] == step["platform_notes"]
            textarea = node["kids"][-1]["kids"][1]
            assert textarea["cls"] == "output-text step-commands"
            assert textarea["value"] == "\n".join(step["commands"])
        notes3 = steps[2]["kids"][1]["kids"][0]["text"]
        assert "<STRING>" in notes3
        assert "<STRING>" in steps[1]["kids"][-1]["kids"][1]["value"]

    @needs_node
    def test_markup_in_step_fields_is_text(self):
        step = {"order": XSS, "description": XSS, "platform_notes": XSS, "commands": ["</textarea>" + XSS]}
        out = json.loads(_node(_mitigation_script("renderWorkarounds([%s]);" % json.dumps(step))))
        assert out["markupWrites"] == 0
        node = out["nodes"]["mitigation-workarounds"]["kids"][0]
        assert node["kids"][0]["text"] == "Step %s: %s" % (XSS, XSS)
        assert node["kids"][1]["kids"][0]["text"] == XSS
        assert node["kids"][-1]["kids"][1]["value"] == "</textarea>" + XSS

    @needs_node
    def test_references_link_only_https(self):
        m = {"cisco_psirt": "https://sec.cloudapps.cisco.com/x", "cisa_alert": "javascript:alert(1)",
             "field_notice": "http://example.com/fn"}
        out = json.loads(_node(_mitigation_script("renderReferences(%s);" % json.dumps(m))))
        assert out["markupWrites"] == 0
        items = out["nodes"]["mitigation-references"]["kids"]
        assert items[0]["kids"][0]["tag"] == "A"
        assert items[0]["kids"][0]["href"] == "https://sec.cloudapps.cisco.com/x"
        assert items[0]["kids"][0]["text"] == "Cisco PSIRT Advisory"
        assert (items[1]["kids"], items[1]["text"]) == ([], "CISA Alert")
        assert (items[2]["kids"], items[2]["text"]) == ([], "Field Notice")

    @needs_node
    def test_no_references_message(self):
        out = json.loads(_node(_mitigation_script("renderReferences({});")))
        assert out["markupWrites"] == 0
        assert out["nodes"]["mitigation-references"]["kids"][0]["text"] == "No external references available"

    @needs_node
    def test_cisco_source_link_only_https(self):
        bad = {"cisco_workaround": {"text": "t", "status": "none", "source": "javascript:alert(1)"},
               "cisco_psirt": "https://sec.cloudapps.cisco.com/a"}
        worse = {"cisco_workaround": {"text": "t", "status": "none", "source": "data:text/html,x"},
                 "cisco_psirt": "javascript:alert(2)"}
        out1 = json.loads(_node(_mitigation_script("renderCiscoWorkaround(%s);" % json.dumps(bad))))
        out2 = json.loads(_node(_mitigation_script("renderCiscoWorkaround(%s);" % json.dumps(worse))))
        assert out1["nodes"]["mitigation-cisco-source"]["href"] == "https://sec.cloudapps.cisco.com/a"
        assert out2["nodes"]["mitigation-cisco-source"]["href"] == "#"

    def test_every_record_link_is_https(self):
        """Real data stays linked: every reference URL in the repo passes the allowlist."""
        for name in os.listdir(os.path.join(ROOT, "cve_mitigations")):
            if not name.endswith(".json"):
                continue
            rec = _record(name[:-5])
            for key in ("cisco_psirt", "cisa_alert", "field_notice"):
                if rec.get(key):
                    assert rec[key].startswith("https://"), (name, key)
            src = (rec.get("cisco_workaround") or {}).get("source")
            if src:
                assert src.startswith("https://"), (name, "cisco_workaround.source")
