"""
Public beta frontend (BETA-A, 2026-10-05), @ciso conditions W1 + M2/M3/M8.

The fetch wrapper in web/app-gate.js is run for real in Node (vm sandbox with a
stub window/document/localStorage/fetch): X-Beta-Token goes only to
same-origin tool paths, never to the feedback widget (AWS), Google or any other
origin. Skipped when node is not installed; the static checks always run.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from api import beta

WEB = Path(__file__).resolve().parent.parent / "web"
PRIVACY = "https://netdevops.thebackroom.ai/legal/privacy.html"

HARNESS = r"""
const fs = require("fs");
const vm = require("vm");
const src = fs.readFileSync(process.argv[2], "utf8");

function makeSandbox(href, store) {
  const calls = [];
  const loc = new URL(href);
  const storage = {
    getItem: k => (k in store ? store[k] : null),
    setItem: (k, v) => { store[k] = String(v); },
  };
  const fakeFetch = async (input, init) => {
    const isReq = input && typeof input === "object" && "url" in input;
    const url = isReq ? input.url : String(input);
    const h = new Headers((init && init.headers) || (isReq ? input.headers : undefined));
    calls.push({ url, token: h.get("X-Beta-Token"), ctype: h.get("Content-Type") });
    let body = { success: true, token: null };
    if (url.endsWith("/api/subscribe")) body = { success: true, message: "Subscribed", token: "v1.111.sub" };
    if (url.endsWith("/api/beta/token")) body = { token: "v1.222.backfill" };
    return { ok: true, json: async () => body };
  };
  const document = {
    readyState: "complete",
    querySelector: () => null,
    querySelectorAll: () => [],
    getElementById: () => null,
    addEventListener: () => {},
  };
  const ctx = { document, localStorage: storage, Headers, URL, Request, console,
                setTimeout, Promise, JSON, Date, Object, String, Array,
                location: loc, fetch: fakeFetch };
  ctx.window = ctx;  // as in a browser: window === globalThis, bare fetch === window.fetch
  vm.createContext(ctx);
  vm.runInContext(src, ctx);
  return { ctx, calls, store };
}

(async () => {
  const out = {};
  const prod = "https://netdevops-tools.thebackroom.ai/";
  const targets = [
    ["/tools/config/parse", { method: "POST", headers: { "Content-Type": "application/json" } }],
    ["/generate/snmpv3", { method: "POST" }],
    ["/api/kev/watch?days=7", undefined],
    ["https://netdevops-tools.thebackroom.ai/mitigate/list", undefined],
    ["/analyze/cve", { method: "POST" }],
    ["https://3w7nw22j1d.execute-api.us-east-1.amazonaws.com/webhook/feedback", { method: "POST" }],
    ["https://www.googletagmanager.com/gtag/js?id=G-X", undefined],
    ["https://www.thebackroom.ai/widget.js", undefined],
    ["/api/subscribe", { method: "POST" }],
    ["/api/beta/token", { method: "POST" }],
    ["/analyze/advisories?platform=ios-xe", undefined],
    ["/profiles/list", undefined],
    ["https://evil.example/tools/subnet/info", { method: "POST" }],
    ["//evil.example/generate/snmpv3", { method: "POST" }],
    ["http://127.0.0.1:8000/tools/subnet/info", { method: "POST" }],
    ["/meta/version", undefined],
  ];

  let s = makeSandbox(prod, { netdevops_unlocked: "true", netdevops_beta_token: "v1.123.sig",
                              netdevops_email: "a@b.co" });
  s.calls.length = 0;
  for (const [u, init] of targets) await s.ctx.window.fetch(u, init);
  await s.ctx.window.fetch(new Request("https://netdevops-tools.thebackroom.ai/tools/whoami/json"));
  out.prod = s.calls;

  s = makeSandbox(prod, {});
  for (const [u, init] of targets) await s.ctx.window.fetch(u, init);
  out.noToken = s.calls;

  s = makeSandbox("http://127.0.0.1:5500/web/index.html", { netdevops_beta_token: "v1.123.sig" });
  await s.ctx.window.fetch("http://127.0.0.1:8000/tools/subnet/info", { method: "POST" });
  await s.ctx.window.fetch("http://example.com:8000/tools/subnet/info", { method: "POST" });
  out.dev = s.calls;

  // submitEmail stores the token from /api/subscribe
  s = makeSandbox(prod, {});
  await vm.runInContext("submitEmail('a@b.co')", s.ctx);
  out.afterSubmit = s.store.netdevops_beta_token || null;

  // backfill: unlocked, email, no token -> one read-only call per day
  s = makeSandbox(prod, { netdevops_unlocked: "true", netdevops_email: "a@b.co" });
  await new Promise(r => setTimeout(r, 0));
  const first = s.calls.filter(c => c.url.endsWith("/api/beta/token")).length;
  delete s.store.netdevops_beta_token;
  await vm.runInContext("backfillBetaToken()", s.ctx);
  out.backfill = { first, token: s.ctx.localStorage.getItem("netdevops_beta_token"),
                   calls: s.calls.filter(c => c.url.endsWith("/api/beta/token")).length };

  // not unlocked: no backfill call
  s = makeSandbox(prod, { netdevops_email: "a@b.co" });
  await new Promise(r => setTimeout(r, 0));
  out.lockedBackfillCalls = s.calls.length;

  console.log(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""


@pytest.fixture(scope="module")
def harness(tmp_path_factory):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not installed")
    script = tmp_path_factory.mktemp("beta") / "harness.js"
    script.write_text(HARNESS)
    res = subprocess.run([node, str(script), str(WEB / "app-gate.js")],
                         capture_output=True, text=True, timeout=60)
    assert res.returncode == 0, res.stderr
    return json.loads(res.stdout.strip().splitlines()[-1])


def _tokens(calls):
    return {c["url"]: c["token"] for c in calls}


def test_token_only_on_same_origin_tool_paths(harness):
    t = _tokens(harness["prod"])
    sent = {u for u, tok in t.items() if tok}
    assert sent == {
        "/tools/config/parse", "/generate/snmpv3", "/api/kev/watch?days=7",
        "https://netdevops-tools.thebackroom.ai/mitigate/list", "/analyze/cve",
        "https://netdevops-tools.thebackroom.ai/tools/whoami/json",
    }
    assert all(tok == "v1.123.sig" for tok in t.values() if tok)


def test_existing_headers_kept(harness):
    (c,) = [c for c in harness["prod"] if c["url"] == "/tools/config/parse"]
    assert c["ctype"] == "application/json"


def test_never_to_widget_google_or_other_origins(harness):
    t = _tokens(harness["prod"])
    for u in ("https://3w7nw22j1d.execute-api.us-east-1.amazonaws.com/webhook/feedback",
              "https://www.googletagmanager.com/gtag/js?id=G-X",
              "https://www.thebackroom.ai/widget.js",
              "https://evil.example/tools/subnet/info", "//evil.example/generate/snmpv3",
              "http://127.0.0.1:8000/tools/subnet/info",   # dev API origin is dev-only
              "/api/subscribe", "/api/beta/token", "/meta/version",
              "/analyze/advisories?platform=ios-xe", "/profiles/list"):
        assert t[u] is None, u


def test_no_token_no_header(harness):
    assert all(c["token"] is None for c in harness["noToken"])


def test_local_dev_api_origin(harness):
    assert [c["token"] for c in harness["dev"]] == ["v1.123.sig", None]


def test_subscribe_stores_token_and_backfill_once_a_day(harness):
    assert harness["afterSubmit"] == "v1.111.sub"
    assert harness["backfill"]["first"] == 1
    assert harness["backfill"]["calls"] == 1  # same day: no second call
    assert harness["lockedBackfillCalls"] == 0


def test_prefix_lists_match_backend():
    js = (WEB / "app-gate.js").read_text()
    prefixes = json.loads(re.search(r"BETA_TOOL_PREFIXES = (\[.*?\]);", js).group(1))
    passive = json.loads(re.search(r"BETA_PASSIVE_PATHS = (\[.*?\]);", js).group(1))
    assert tuple(prefixes) == beta.TOOL_PREFIXES
    assert set(passive) == set(beta.PASSIVE_PATHS)


# ---------------------------------------------------------------- static

def test_ga4_removed_from_app():
    for f in WEB.glob("*.html"):
        html = f.read_text()
        assert "googletagmanager" not in html and "gtag(" not in html, f.name
    for f in WEB.glob("*.js"):
        assert "gtag(" not in f.read_text(), f.name


def test_privacy_link_in_gate_modal_and_app_footer():
    js = (WEB / "app-gate.js").read_text()
    assert f'PRIVACY_URL = "{PRIVACY}"' in js
    modal = js.split('class="gate-modal"', 1)[1].split("`;", 1)[0]
    assert "${PRIVACY_URL}" in modal and "Privacy policy" in modal
    html = (WEB / "index.html").read_text()
    footer = html.split('<footer class="footer">', 1)[1].split("</footer>", 1)[0]
    assert PRIVACY in footer


def test_gate_copy_announces_beta_emails_and_unsubscribe():
    js = (WEB / "app-gate.js").read_text()
    note = re.search(r'class="gate-modal-note">(.*?)</p>', js, re.S).group(1)
    assert "email you about the beta" in note
    assert "unsubscribe" in note
    assert "confirm your email" in note  # status only after a confirmed mailbox (W6)


def test_gate_copy_publication_gate():
    js = (WEB / "app-gate.js").read_text()
    assert "—" not in js
    assert not re.search(r"\b(NATO|NCIA|military|wojsko|ramstein|psyops)\b", js, re.I)
    assert "10 testers" not in js and "10 active" not in js  # threshold stays internal
