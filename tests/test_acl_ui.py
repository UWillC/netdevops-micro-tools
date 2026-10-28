"""
ACL What-If tab (ACL-01.4): wiring, @ciso N1 and the module count.

N1 (@ciso, 28.10): the API echoes the paste (ACL names, quoted lines, tokens
inside the lint sentences), the app has no CSP, so web/app-acl.js must build
every node with createElement + textContent / createTextNode. Two checks:
1. static: no markup API anywhere in web/app-acl.js;
2. behaviour: the renderers run in Node (vm sandbox, fake DOM whose markup
   setters throw) on a real API answer with `<img src=x onerror=alert(1)>` in
   the ACL name and in a token, and on an answer where EVERY string is that
   payload. The payload must come out as text, never as an element.
Skipped when node is not installed; the static checks always run.
"""
import json
import os
import re
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

import api.main as api_main
from api.main import app

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)
XSS = "<img src=x onerror=alert(1)>"
XSS_TOKEN = "<img/src=x/onerror=alert(1)>"   # same payload without spaces (IOS names hold none)
MARKUP_APIS = ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
               "createContextualFragment", "DOMParser", "srcdoc")


def _web(name):
    with open(os.path.join(ROOT, "web", name), encoding="utf-8") as f:
        return f.read()


def _tab(html):
    return html.split('id="tab-acl-whatif"', 1)[1].split("</section>", 1)[0]


class TestWiring:
    def test_assets_are_whitelisted_and_served(self):
        assert "app-acl" in api_main.JS_FILES
        assert "style-acl" in api_main.CSS_FILES
        js = client.get("/app-acl.js")
        assert js.status_code == 200 and "aclRenderAll" in js.text
        assert js.headers["content-type"].startswith("application/javascript")
        css = client.get("/style-acl.css")
        assert css.status_code == 200 and ".acl-table" in css.text

    def test_index_wires_tab_card_and_assets(self):
        html = _web("index.html")
        assert html.count('data-tab="acl-whatif"') == 2   # sidebar button + home card
        assert 'id="tab-acl-whatif"' in html
        assert 'src="app-acl.js?v=' in html and 'href="style-acl.css?v=' in html
        # Loaded after app-core.js (it needs API_BASE_URL).
        assert html.index('src="app-core.js') < html.index('src="app-acl.js')
        tab = _tab(html)
        for el in ("acl-form", "acl-config", "acl-trace-on", "acl-trace-src", "acl-status",
                   "acl-lint-content", "acl-packets-content", "acl-trace-content", "acl-output"):
            assert 'id="%s"' % el in tab, el

    def test_feature_flag(self):
        assert "acl_whatif" in client.get("/meta/version").json()["feature_flags"]

    def test_quick_access_knows_the_tab(self):
        core = _web("app-core.js")
        assert '"acl-whatif": "ACL What-If"' in core
        assert '"acl-whatif": "' in core.split("const toolIcons", 1)[1].split("};", 1)[0]

    def test_no_em_dash(self):
        for text in (_tab(_web("index.html")), _web("app-acl.js"), _web("style-acl.css")):
            assert "—" not in text


class TestNoMarkupApis:
    """@ciso N1, static half: grep for markup APIs in the new module = 0."""

    def test_module_has_no_markup_api(self):
        js = _web("app-acl.js")
        hits = [api for api in MARKUP_APIS if api in js]
        assert hits == [], hits

    def test_module_sets_text_only(self):
        js = _web("app-acl.js")
        assert "textContent" in js and "createTextNode" in js
        # No template literal builds a tag (the KEV/Drift style `<tr>${...}`).
        assert not re.search(r"`[^`]*<[a-zA-Z/][^`]*`", js)


# ----------------------------------------------------------------- Node harness

HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const src = fs.readFileSync(process.argv[2], "utf8");
const input = JSON.parse(fs.readFileSync(0, "utf8"));

const created = [];
let markupWrites = 0;
class FakeNode {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.nodeType = 1; this.children = []; this._text = ""; this.className = ""; this.style = {}; this.hidden = false; this.value = ""; }
  appendChild(c) { this.children.push(c); c.parentNode = this; return c; }
  removeChild(c) { this.children = this.children.filter(x => x !== c); return c; }
  get firstChild() { return this.children[0] || null; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  set innerHTML(v) { markupWrites++; throw new Error("innerHTML used"); }
  set outerHTML(v) { markupWrites++; throw new Error("outerHTML used"); }
  insertAdjacentHTML() { markupWrites++; throw new Error("insertAdjacentHTML used"); }
  addEventListener() {}
}
class FakeText { constructor(t) { this.nodeType = 3; this.textContent = String(t); this.children = []; } }

const document = {
  createElement: tag => { const n = new FakeNode(tag); created.push(n.tagName); return n; },
  createTextNode: t => new FakeText(t),
  getElementById: () => null,
  querySelector: () => null,
  querySelectorAll: () => [],
  addEventListener: () => {},
};
const ctx = { document, console, JSON, String, Number, Array, Object, Math, isNaN, parseInt, Promise,
              API_BASE_URL: "", fetch: async () => { throw new Error("no network in test"); } };
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(src, ctx);

function walk(n, out) {
  out.tags.push(n.tagName || "#text");
  if (n.nodeType === 3) out.text.push(n.textContent); else if (n._text) out.text.push(n._text);
  (n.children || []).forEach(c => walk(c, out));
  return out;
}

const result = {};
for (const [name, data] of Object.entries(input.responses)) {
  const ui = { summary: new FakeNode("div"), lint: new FakeNode("div"), packets: new FakeNode("div"),
               trace: new FakeNode("div"), output: { value: "" } };
  vm.runInContext("aclRenderAll", ctx)(data, input.paste, ui);
  const out = { tags: [], text: [] };
  ["summary", "lint", "packets", "trace"].forEach(k => walk(ui[k], out));
  result[name] = { tags: Array.from(new Set(out.tags)).sort(), text: out.text, output: ui.output.value };
}
const errMsg = vm.runInContext("aclErrorMessage", ctx);
result.errors = {
  e413: errMsg(413, { detail: "Too many ACL rules: at most 500 per request (the paste has 501)." }, null),
  e422s: errMsg(422, { detail: "ACL to trace was not found in the paste." }, null),
  e422l: errMsg(422, { detail: [{ type: "string_too_long", loc: ["body", "trace", "src"], msg: "String should have at most 15 characters" }] }, null),
  e429: errMsg(429, { detail: "Too many requests. Try again later." }, 42),
  e503: errMsg(503, { detail: "ACL analysis is busy right now. Try again in a few seconds." }, 5),
  e500: errMsg(500, null, null),
};
result.created = Array.from(new Set(created)).sort();
result.markupWrites = markupWrites;
process.stdout.write(JSON.stringify(result));
"""

ALLOWED_TAGS = {"DIV", "SPAN", "P", "H4", "TABLE", "THEAD", "TBODY", "TR", "TH", "TD", "#text"}

PASTE = ("ip access-list extended %s\n"
         " 10 permit tcp any any eq %s\n"
         " 20 permit tcp any host 192.0.2.10 eq 22\n"
         " 30 permit tcp any host 192.0.2.10 eq 22\n"
         "ip access-list extended %s\n"
         " 10 permit tcp any any eq %s\n" % (XSS_TOKEN, XSS_TOKEN, XSS, XSS))


def _poison(value):
    """Every string leaf of the answer replaced by the payload."""
    if isinstance(value, str):
        return XSS
    if isinstance(value, list):
        return [_poison(v) for v in value]
    if isinstance(value, dict):
        return {k: _poison(v) for k, v in value.items()}
    return value


@pytest.fixture(scope="module")
def node_run(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    real = client.post("/tools/acl/analyze", json={
        "config_text": PASTE,
        "trace": {"acl": XSS_TOKEN, "src": "10.0.0.1", "dst": "192.0.2.10", "protocol": "tcp",
                  "src_port": 1000, "dst_port": 22}})
    assert real.status_code == 200, real.text
    data = real.json()
    assert data["acls"][0]["acl"] == XSS_TOKEN
    payload = {"paste": PASTE, "responses": {"real": data, "poisoned": _poison(data)}}
    script = tmp_path_factory.mktemp("acl_ui") / "harness.js"
    script.write_text(HARNESS, encoding="utf-8")
    proc = subprocess.run([node, str(script), os.path.join(ROOT, "web", "app-acl.js")],
                          input=json.dumps(payload), capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return data, json.loads(proc.stdout)


class TestRenderersInNode:
    def test_no_markup_write_and_only_safe_tags(self, node_run):
        _, out = node_run
        assert out["markupWrites"] == 0
        assert set(out["created"]) <= ALLOWED_TAGS, out["created"]
        for name in ("real", "poisoned"):
            assert set(out[name]["tags"]) <= ALLOWED_TAGS, (name, out[name]["tags"])
            assert "IMG" not in out[name]["tags"]

    def test_payload_shows_as_text(self, node_run):
        data, out = node_run
        text = "\n".join(out["real"]["text"])
        assert XSS_TOKEN in text                      # ACL name and token, verbatim
        assert ("ACL " + XSS_TOKEN) in text           # group title / trace head
        assert XSS in text                            # spaced form from not_evaluated
        assert XSS in "\n".join(out["poisoned"]["text"])
        assert XSS_TOKEN in out["real"]["output"]     # text report (textarea value)

    def test_real_answer_is_rendered_fully(self, node_run):
        data, out = node_run
        text = "\n".join(out["real"]["text"])
        assert "P01" in text and "L03" in text        # token error + duplicate rule
        assert "NOT EVALUATED" in text
        assert "PERMIT" in text and "DENY" in text
        # Trace path rows show the rule text from the paste by line number.
        assert "20 permit tcp any host 192.0.2.10 eq 22" in text

    def test_error_messages(self, node_run):
        _, out = node_run
        e = out["errors"]
        assert e["e413"].startswith("Paste too large.") and "at most 500" in e["e413"]
        assert e["e422s"] == "ACL to trace was not found in the paste."
        assert "trace.src" in e["e422l"] and "at most 15" in e["e422l"]
        assert "Rate limit" in e["e429"] and "42 s" in e["e429"]
        assert "busy" in e["e503"] and "5 s" in e["e503"]
        assert "HTTP 500" in e["e500"]


class TestModuleCount:
    """Public "22 live modules" = 21 tool cards + the Threat Feed widget (@ceo 28.10)."""

    def test_home_has_21_tool_cards_and_the_feed(self):
        html = _web("index.html")
        assert html.count('class="home-tool-card') == 21
        assert 'id="cisco-advisories-card"' in html   # Threat Feed widget = module 22

    def test_sidebar_matches_the_cards(self):
        html = _web("index.html")
        nav = html.split('<nav class="tab-nav">', 1)[1].split("</nav>", 1)[0]
        assert nav.count('class="tab-button"') == 21
        badges = [int(b) for b in re.findall(r'nav-group-badge">(\d+)<', nav)]
        assert sum(badges) == 21
        for group in re.findall(r'id="group-([a-z]+)">(.*?)</div>', nav, re.S):
            name, body = group
            badge = re.search(r'data-group="%s">.*?nav-group-badge">(\d+)<' % name, nav, re.S)
            assert int(badge.group(1)) == body.count('class="tab-button"'), name

    def test_public_number_is_22_everywhere(self):
        html = _web("index.html")
        counts = re.findall(r"(\d+) live modules", html)
        assert counts and set(counts) == {"22"}
