"""Cisco CLI Cheat Sheet: Reference page served byte for byte with a strict CSP (v0.7.10).

Content rules that a test can hold:
* the shipped file works offline: no external scripts, styles, fonts or network calls;
* generic content only: no environment data (domains, public IPs, organisation names);
* the download is the same file, not a variant of it.
Plus the integration decisions of 29.10: two routes, no email gate, not under /static/,
Reference outside the "22 live modules" count.
"""

import base64
import hashlib
import ipaddress
import os
import re
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

from api import cheatsheet
from api.main import app

client = TestClient(app)

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.path.join(REPO, "cheatsheet", "Cisco_CLI_Cheat_Sheet.html")
RUNNER = os.path.join(REPO, "tools", "cheatsheet", "run.mjs")


def _bytes():
    with open(FILE, "rb") as fh:
        return fh.read()


def _text():
    return _bytes().decode("utf-8")


def _web(name):
    with open(os.path.join(REPO, "web", name), encoding="utf-8") as fh:
        return fh.read()


def _csp_directives(header):
    return {d.split()[0]: d.split()[1:] for d in (p.strip() for p in header.split(";")) if d}


class TestRoutes:
    def test_page_is_the_file_byte_for_byte(self):
        r = client.get("/cli-cheat-sheet")
        assert r.status_code == 200
        assert r.headers["content-type"] == "text/html; charset=utf-8"
        assert r.content == _bytes()
        assert "content-disposition" not in r.headers

    def test_download_is_the_same_file_as_attachment(self):
        r = client.get("/cli-cheat-sheet/download")
        assert r.status_code == 200
        assert r.headers["content-disposition"] == 'attachment; filename="Cisco_CLI_Cheat_Sheet.html"'
        assert r.content == _bytes()

    def test_sha256_matches_the_file(self):
        r = client.get("/cli-cheat-sheet/sha256")
        assert r.status_code == 200
        assert r.headers["content-type"].startswith("text/plain")
        assert r.text == hashlib.sha256(_bytes()).hexdigest() + "  Cisco_CLI_Cheat_Sheet.html\n"

    @pytest.mark.parametrize("path", ["/cli-cheat-sheet", "/cli-cheat-sheet/download"])
    def test_head_is_allowed(self, path):
        r = client.head(path)
        assert r.status_code == 200
        assert r.headers["content-security-policy"]

    def test_free_without_signup(self):
        gate = _web("app-gate.js")
        assert '"cli-cheat-sheet"' in gate.split("FREE_TOOLS", 1)[1].split("]", 1)[0]


class TestHeaders:
    @pytest.mark.parametrize("path", ["/cli-cheat-sheet", "/cli-cheat-sheet/download"])
    def test_strict_csp(self, path):
        h = client.get(path).headers
        d = _csp_directives(h["content-security-policy"])
        assert d["default-src"] == ["'none'"]
        assert d["connect-src"] == ["'none'"]
        assert d["frame-ancestors"] == ["'none'"]
        assert d["object-src"] == ["'none'"]
        assert d["base-uri"] == ["'none'"]
        assert d["form-action"] == ["'none'"]
        assert all(s.startswith("'sha256-") for s in d["script-src"]), d["script-src"]
        assert h["x-content-type-options"] == "nosniff"
        assert h["referrer-policy"] == "no-referrer"

    @pytest.mark.parametrize("path", ["/cli-cheat-sheet", "/cli-cheat-sheet/download", "/cli-cheat-sheet/sha256"])
    def test_cache_control_no_transform(self, path):
        assert client.get(path).headers["cache-control"] == "no-cache, no-transform"

    def test_script_hash_matches_the_file(self):
        """Computed here independently: the text between the one <script> tag and its </script>."""
        html = _text()
        start = html.index("<script>") + len("<script>")
        body = html[start:html.index("</script>", start)]
        expected = "'sha256-" + base64.b64encode(hashlib.sha256(body.encode("utf-8")).digest()).decode() + "'"
        d = _csp_directives(client.get("/cli-cheat-sheet").headers["content-security-policy"])
        assert d["script-src"] == [expected]

    def test_only_these_routes_get_the_cheat_sheet_csp(self):
        """Site-wide headers are slot WEBSEC-01(a); this change must not alter them."""
        assert "content-security-policy" not in client.get("/").headers
        assert "content-security-policy" not in client.get("/health").headers


class TestNotElsewhere:
    def test_not_in_web_dir(self):
        assert not any(n.lower().endswith(".html") and "cheat" in n.lower() for n in os.listdir(os.path.join(REPO, "web")))

    @pytest.mark.parametrize("path", [
        "/static/Cisco_CLI_Cheat_Sheet.html",
        "/static/cheatsheet/Cisco_CLI_Cheat_Sheet.html",
        "/static/../cheatsheet/Cisco_CLI_Cheat_Sheet.html",
        "/static/%2e%2e/cheatsheet/Cisco_CLI_Cheat_Sheet.html",
    ])
    def test_static_mount_does_not_serve_it(self, path):
        r = client.get(path)
        assert r.status_code == 404 or r.content != _bytes()


class TestOfflineFile:
    def test_one_inline_script_no_external_resources(self):
        html = _text()
        tags = re.findall(r"<script\b[^>]*>", html, re.I)
        # "<script>.py" also occurs as text inside the data; every hit is a bare tag, never with src
        assert tags and all(t == "<script>" for t in tags)
        assert len(cheatsheet._script_hashes(html)) == 1
        assert not re.search(r"<link\b", html, re.I)
        assert not re.search(r"""\b(?:src|href)\s*=\s*["']?(?:https?:)?//""", html, re.I)
        assert not re.search(r"@import|url\(\s*['\"]?https?:", html, re.I)

    def test_no_network_calls(self):
        html = _text()
        for needle in ("fetch(", "XMLHttpRequest", "WebSocket", "sendBeacon", "EventSource", "import(", "importScripts"):
            assert needle not in html, needle


class TestNoEnvironmentData:
    DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

    def test_no_public_ipv4(self):
        """Private / documentation / multicast addresses, masks and wildcards are fine;
        dotted runs longer than four numbers are OIDs (1.3.6.1.4.1.9.9...)."""
        bad = []
        for m in re.finditer(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])", _text()):
            try:
                ip = ipaddress.ip_address(m.group(1))
            except ValueError:
                continue
            first = int(m.group(1).split(".")[0])
            if ip.is_private or ip.is_multicast or ip.is_unspecified or first in (0, 255) \
                    or any(ip in n for n in self.DOC_NETS):
                continue
            bad.append(m.group(1))
        assert not bad, sorted(set(bad))

    def test_no_internal_domains(self):
        hits = re.findall(r"\b[a-z0-9-]+\.(?:int|mil|corp|lan|internal|gov)\b", _text(), re.I)
        assert not hits, sorted(set(hits))

    def test_jump_host_linux_section_is_generic(self):
        """29.10: the jump-host Linux section names the RHEL family, not one distribution release."""
        html = _text()
        assert '["Linux (RHEL family)", [' in html
        assert '"RHEL / Rocky / Oracle Linux","Variant / detail"' in html


class TestReferenceOutsideTheModuleCount:
    """User decision 29.10: Reference, not module 23. TestModuleCount (test_acl_ui.py) keeps 21/22."""

    def test_sidebar_entry_is_outside_the_nav_groups(self):
        html = _web("index.html")
        nav = html.split('<nav class="tab-nav">', 1)[1].split("</nav>", 1)[0]
        assert 'data-tab="cli-cheat-sheet"' not in nav
        assert html.count('data-tab="cli-cheat-sheet"') == 1
        assert 'class="sidebar-reference"' in html

    def test_home_has_a_reference_card_not_a_tool_card(self):
        html = _web("index.html")
        card = html.split('class="home-reference-card"', 1)[1].split('<div class="home-footer">', 1)[0]
        assert 'href="/cli-cheat-sheet"' in card and 'href="/cli-cheat-sheet/download"' in card
        assert "home-tool-card" not in card

    def test_tab_has_open_download_and_hash(self):
        html = _web("index.html")
        tab = html.split('id="tab-cli-cheat-sheet"', 1)[1].split("</section>", 1)[0]
        assert 'href="/cli-cheat-sheet"' in tab
        assert 'href="/cli-cheat-sheet/download"' in tab
        assert 'id="cheatsheet-sha256"' in tab and 'href="/cli-cheat-sheet/sha256"' in tab

    def test_public_texts_no_em_dash(self):
        html = _web("index.html")
        new = html.split('class="sidebar-reference"', 1)[1].split("</div>", 1)[0] \
            + html.split('class="home-category home-reference"', 1)[1].split('<div class="home-footer">', 1)[0] \
            + html.split('id="tab-cli-cheat-sheet"', 1)[1].split("</section>", 1)[0]
        assert "—" not in new


def _browser_available():
    if not shutil.which("node"):
        return False
    try:
        subprocess.run(["node", "-e", "1"], check=True, capture_output=True, timeout=20)
    except Exception:
        return False
    if os.environ.get("CHROME"):
        return os.path.exists(os.environ["CHROME"])
    return any(os.path.exists(p) for p in (
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "/usr/bin/google-chrome", "/usr/bin/google-chrome-stable", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    ))


def test_page_ux_tests_and_audit_in_a_real_browser():
    """The page's own 58 UX tests (all PASS) and data audit (only the 5 known false positives).
    CI sets CHEATSHEET_BROWSER_REQUIRED=1, so a missing browser fails there instead of skipping."""
    if not _browser_available():
        if os.environ.get("CHEATSHEET_BROWSER_REQUIRED") == "1":
            pytest.fail("node + Chrome/Chromium needed for the cheat sheet browser tests")
        pytest.skip("node + Chrome/Chromium not available")
    r = subprocess.run(["node", RUNNER, "check"], capture_output=True, text=True, timeout=300)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "uxtest: 58 PASS" in r.stdout
    assert "audit: 5 findings" in r.stdout
