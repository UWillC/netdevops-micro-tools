"""
WEBSEC-01, slots from the @ciso final review 02.11 (2026-11-02_ciso-final-review.md).

1. Error text in innerHTML (@cto finding, web/app-network.js:577,670,691,1007,1030
   in v0.7.13). `err.message` often holds `err.detail` from the server, and the
   app has no CSP, so it must reach the page as text. The same class was also in
   app-feeds.js (threat feed) and app-profiles.js (two widgets): those go through
   esc(). The time cards (renderTzResult / renderDtgResult) print server fields
   and go through esc() too. UI stays the same: same tag, same class, same words.
2. W30: a client that leaves during the upload got a bare `return` from the gate,
   so the outer BaseHTTPMiddleware logged "No response returned" with a traceback.
   Now the gate answers 400 and the slot is never taken.
3. W31: `b"".join(chunks)` ran between `acquire` and `try`; an exception there left
   the slot taken until restart. The body is now joined before `acquire`.
"""
import asyncio
import glob
import json
import os
import re
import shutil

import pytest

from api import body_limit as bl
from api import heavy_gate as hg
from api.main import app
from tests.test_websec_03 import ROOT, _http_scope, _Inner, _js_function, _node, _run, _web

XSS = "<img src=x onerror=alert(1)>"
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")

# Minimal DOM: setting innerHTML to anything with a tag throws, so the test fails
# loudly if a markup path comes back.
FAKE_DOM = r"""
let markupWrites = 0;
class FakeNode {
  constructor(tag) { this.tagName = tag.toUpperCase(); this.children = []; this._text = ""; this.className = ""; this.style = {}; this.value = ""; }
  appendChild(c) { this.children.push(c); return c; }
  replaceChildren(...c) { this.children = c; this._text = ""; }
  set textContent(v) { this.children = []; this._text = String(v); }
  get textContent() { return this._text + this.children.map(c => c.textContent).join(""); }
  set innerHTML(v) { if (/</.test(String(v))) { markupWrites++; throw new Error("markup: " + v); } this.children = []; this._text = ""; }
  addEventListener() {}
}
const document = { createElement: t => new FakeNode(t), getElementById: () => new FakeNode("div") };
const API_BASE_URL = "";
function dump(n) { return { tag: n.tagName, cls: n.className, text: n._text, kids: n.children.map(dump) }; }
"""


def _error_paths_script(fetch_js):
    net = _web("app-network.js")
    funcs = ["showErrorIn", "renderTzResult", "renderDtgResult", "convertTimestamp",
             "fetchCurrentTime", "convertDtg", "fetchCurrentDtg", "fetchMitigationList"]
    return (
        FAKE_DOM
        + _js_function(_web("app-core.js"), "esc") + "\n"
        + "\n".join(_js_function(net, f) for f in funcs) + "\n"
        + "const TARGET_TIMEZONES = [];\n"
        + "const tzResults = new FakeNode('div'), tzResultsGrid = new FakeNode('div'), tzNowResults = new FakeNode('div'),"
        + " tzNowGrid = new FakeNode('div'), tzGeneratedAt = new FakeNode('p'), dtgResults = new FakeNode('div'),"
        + " dtgResultsGrid = new FakeNode('div'), dtgParsedUtc = new FakeNode('p'), mitigationCveList = new FakeNode('div'),"
        + " mitigationAvailable = new FakeNode('div'), mitigationResult = new FakeNode('div'), mitigationNotFound = new FakeNode('div');\n"
        + "function setDtgPickerToNow() {}\n"
        + "globalThis.fetch = " + fetch_js + ";\n"
        + "(async () => {\n"
        + "  const out = {};\n"
        + "  await convertTimestamp('x', 'UTC'); out.tzConvert = dump(tzResultsGrid);\n"
        + "  await fetchCurrentTime(); out.tzNow = dump(tzNowGrid);\n"
        + "  await convertDtg('x'); out.dtgConvert = dump(dtgResultsGrid);\n"
        + "  dtgResultsGrid.replaceChildren();\n"
        + "  await fetchCurrentDtg(); out.dtgNow = dump(dtgResultsGrid);\n"
        + "  await fetchMitigationList(); out.cveList = dump(mitigationCveList);\n"
        + "  out.markupWrites = markupWrites;\n"
        + "  process.stdout.write(JSON.stringify(out));\n"
        + "})();\n"
    )


class TestErrorTextIsText:
    @needs_node
    def test_server_detail_with_markup_comes_out_as_text(self):
        # The server answers 4xx with the payload in `detail` (convert paths) and
        # the "now" / list paths fail on fetch with the payload as the message.
        fetch = ("async (url) => { if (/convert/.test(url)) return { ok: false, json: async () => ({ detail: %s }) };"
                 " throw new Error(%s); }" % (json.dumps(XSS), json.dumps(XSS)))
        out = json.loads(_node(_error_paths_script(fetch)))
        assert out["markupWrites"] == 0
        for key in ("tzConvert", "tzNow", "dtgConvert", "dtgNow"):
            grid = out[key]
            assert len(grid["kids"]) == 1, key
            p = grid["kids"][0]
            assert (p["tag"], p["cls"], p["text"]) == ("P", "error", "Error: " + XSS), key
        p = out["cveList"]["kids"][0]
        assert (p["tag"], p["cls"], p["text"]) == ("P", "", "Error loading CVE list: " + XSS)

    def test_no_error_text_goes_into_markup(self):
        # Every web/*.js, not a hand-kept list (WEBSEC-01b, @ciso review 11.11 W1).
        names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "web", "*.js")))
        assert "app-security.js" in names and "app-core.js" in names
        for name in names:
            js = _web(name)
            assert not re.search(r"innerHTML\s*\+?=\s*`[^`]*\$\{err\.message\}", js), name
        net = _web("app-network.js")
        assert net.count("showErrorIn(") == 6  # definition + 5 call sites
        assert "${esc(err.message)}" in _web("app-feeds.js")
        assert _web("app-profiles.js").count("${esc(err.message)}") == 2

    @needs_node
    def test_time_cards_escape_server_fields(self):
        script = (
            _js_function(_web("app-core.js"), "esc") + "\n"
            + "const document = { createElement: () => ({}) };\n"
            + _js_function(_web("app-network.js"), "renderTzResult") + "\n"
            + _js_function(_web("app-network.js"), "renderDtgResult") + "\n"
            + "const r = { label: %s, datetime_formatted: %s, offset: '+00:00', military_letter: 'Z',"
              " military_name: 'Zulu', dtg_full: '111200Z NOV 26' };\n" % (json.dumps(XSS), json.dumps(XSS))
            + "process.stdout.write(renderTzResult(r).innerHTML + renderDtgResult(r).innerHTML);"
        )
        html = _node(script)
        assert "<img" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html
        assert "Zulu" in html and "111200Z NOV 26" in html and "+00:00" in html


@pytest.fixture
def free_slot():
    assert not hg._slot.locked()
    yield
    assert not hg._slot.locked()


class TestW30ClientLeftDuringUpload:
    PASTE = sorted(bl.PASTE_PATHS)[0]

    def test_gate_answers_400_and_never_takes_the_slot(self, free_slot):
        inner = _Inner()
        sent = _run(inner, _http_scope(self.PASTE),
                    [{"type": "http.request", "body": b"x", "more_body": True}])
        assert inner.calls == 0
        assert sent[0]["status"] == 400
        assert json.loads(sent[1]["body"])["detail"] == hg.CLIENT_LEFT_MESSAGE

    def test_whole_app_raises_nothing(self, free_slot):
        """Through every middleware: before W30 this raised "No response returned"."""
        scope = {"type": "http", "method": "POST", "path": self.PASTE, "raw_path": self.PASTE.encode(),
                 "query_string": b"", "root_path": "", "scheme": "http", "http_version": "1.1",
                 "headers": [(b"host", b"testserver"), (b"content-type", b"application/json"),
                             (b"content-length", b"100")],
                 "client": ("192.0.2.1", 1234), "server": ("testserver", 80)}
        queue = [{"type": "http.request", "body": b'{"config_a": "', "more_body": True}]
        sent = []

        async def receive():
            if queue:
                return queue.pop(0)
            return {"type": "http.disconnect"}

        async def send(message):
            sent.append(message)

        asyncio.run(app(scope, receive, send))  # must not raise
        starts = [m for m in sent if m["type"] == "http.response.start"]
        assert starts and starts[0]["status"] == 400


class TestW31JoinBeforeAcquire:
    PASTE = sorted(bl.PASTE_PATHS)[0]

    def test_exception_while_joining_leaves_the_slot_free(self, free_slot):
        # A body that is not bytes makes b"".join raise: the stand-in for a
        # MemoryError at that line. The fixture checks the slot after the call.
        inner = _Inner()
        with pytest.raises(TypeError):
            _run(inner, _http_scope(self.PASTE), [{"type": "http.request", "body": object()}])
        assert inner.calls == 0

    def test_join_happens_before_acquire_in_the_source(self):
        src = open(hg.__file__, encoding="utf-8").read()
        assert src.index('b"".join(chunks)') < src.index("_slot.acquire(")
