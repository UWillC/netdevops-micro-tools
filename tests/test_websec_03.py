"""
WEBSEC-01 (g), @ciso re-review: W18 subnet bomb, W19 one heavy request at a time,
W20 timezone batch, W21 summary escaping, W22 path taken from the ASGI scope.

The old subnet code stays here as the oracle for results from /16 to /32.
The Node checks run the real frontend functions on strings; they do not use a DOM.
"""
import asyncio
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tracemalloc
import urllib.error
import urllib.request

import pytest
from fastapi.testclient import TestClient

from api import body_limit as bl
from api import heavy_gate as hg
from api import rate_limit as rl
from api.main import app
from api.routers import subnet as sn
from api.routers import timezone as tz

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
client = TestClient(app)

DRIFT = "/tools/config-drift/compare"
BATCH = "/tools/timezone/batch"


# ----------------------------
# W18 Subnet Calculator
# ----------------------------

def _old_hosts(network):
    hosts = list(network.hosts())
    if hosts:
        return str(hosts[0]), str(hosts[-1])
    return str(network.network_address), str(network.network_address)


def _old_split(network, new_prefix):
    subnets = list(network.subnets(new_prefix=new_prefix))
    return len(subnets), len(subnets) > 64, [str(s) for s in subnets[:64]]


class TestSubnetSameResult:
    @pytest.mark.parametrize("prefix", range(16, 33))
    @pytest.mark.parametrize("address", ["10.1.2.3", "192.168.200.77", "172.16.0.1", "224.0.0.5"])
    def test_host_range_matches_the_old_code(self, address, prefix):
        network = ipaddress.ip_network(f"{address}/{prefix}", strict=False)
        info = sn.get_subnet_info(network)
        assert (info["first_host"], info["last_host"]) == _old_hosts(network)

    @pytest.mark.parametrize("cidr,new_prefix", [
        ("192.168.1.0/24", 26), ("192.168.1.0/24", 32), ("10.0.0.0/16", 24), ("10.0.0.0/16", 22),
        ("10.0.0.0/30", 31), ("10.0.0.0/30", 32), ("10.0.0.0/31", 32), ("172.16.0.0/20", 26),
    ])
    def test_split_matches_the_old_code(self, cidr, new_prefix):
        data = client.post("/tools/subnet/split", json={"ip_cidr": cidr, "new_prefix": new_prefix}).json()
        total, truncated, listed = _old_split(ipaddress.ip_network(cidr), new_prefix)
        assert data["total_subnets"] == total
        assert data["truncated"] is truncated
        assert [s["cidr"] for s in data["subnets"]] == listed

    def test_host_range_of_the_edge_prefixes(self):
        for cidr, first, last in [("10.0.0.5/32", "10.0.0.5", "10.0.0.5"),
                                  ("10.0.0.4/31", "10.0.0.4", "10.0.0.5"),
                                  ("10.0.0.4/30", "10.0.0.5", "10.0.0.6"),
                                  ("10.0.0.0/8", "10.0.0.1", "10.255.255.254"),
                                  ("0.0.0.0/0", "0.0.0.1", "255.255.255.254")]:
            info = client.post("/tools/subnet/info", json={"ip_cidr": cidr}).json()["subnet_info"]
            assert (info["first_host"], info["last_host"]) == (first, last), cidr

    def test_supernet_still_aggregates(self):
        data = client.post("/tools/subnet/supernet",
                           json={"networks": ["192.168.0.0/24", "192.168.1.0/24"]}).json()
        assert [n["cidr"] for n in data["result_networks"]] == ["192.168.0.0/23"]


class TestSubnetBomb:
    @pytest.mark.parametrize("call", [
        lambda: sn.subnet_info(sn.SubnetInfoRequest(ip_cidr="0.0.0.0/0")),
        lambda: sn.subnet_info(sn.SubnetInfoRequest(ip_cidr="10.0.0.0/8")),
        lambda: sn.subnet_split(sn.SubnetSplitRequest(ip_cidr="0.0.0.0/0", new_prefix=32)),
        lambda: sn.subnet_split(sn.SubnetSplitRequest(ip_cidr="10.0.0.0/8", new_prefix=32)),
        lambda: sn.subnet_supernet(sn.SupernetRequest(networks=["10.0.0.0/9", "10.128.0.0/9"])),
    ], ids=["info-0", "info-8", "split-0-32", "split-8-32", "supernet-8"])
    def test_under_50_ms_and_10_mb(self, call):
        start = time.perf_counter()
        call()
        assert time.perf_counter() - start < 0.05
        tracemalloc.start()
        call()
        peak = tracemalloc.get_traced_memory()[1]
        tracemalloc.stop()
        assert peak < 10 * 1024 * 1024

    def test_split_counts_without_building(self):
        data = client.post("/tools/subnet/split", json={"ip_cidr": "0.0.0.0/0", "new_prefix": 32}).json()
        assert data["total_subnets"] == 2 ** 32
        assert data["truncated"] is True
        assert len(data["subnets"]) == 64

    @pytest.mark.parametrize("path,body", [
        ("/tools/subnet/info", {"ip_cidr": "::/0"}),
        ("/tools/subnet/info", {"ip_cidr": "2001:db8::/64"}),
        ("/tools/subnet/info", {"ip_cidr": "2001:db8::1/128"}),
        ("/tools/subnet/split", {"ip_cidr": "::/0", "new_prefix": 32}),
        ("/tools/subnet/split", {"ip_cidr": "2001:db8::/64", "new_prefix": 120}),
        ("/tools/subnet/supernet", {"networks": ["::/0", "2001:db8::/64"]}),
        ("/tools/subnet/supernet", {"networks": ["10.0.0.0/24", "2001:db8::/64"]}),
    ])
    def test_ipv6_is_400_at_once(self, path, body):
        start = time.perf_counter()
        r = client.post(path, json=body)
        assert time.perf_counter() - start < 0.2
        assert r.status_code == 400
        assert r.json()["detail"] == sn.IPV6_MESSAGE


# ----------------------------
# W19 one heavy request at a time
# ----------------------------

def _http_scope(path, method="POST"):
    return {"type": "http", "method": method, "path": path, "headers": []}


class _Inner:
    """ASGI app that records what it read and when the slot was held."""

    def __init__(self, fail=False, respond=True):
        self.body = None
        self.calls = 0
        self.fail = fail
        self.respond = respond
        self.held_inside = None

    async def __call__(self, scope, receive, send):
        self.calls += 1
        self.held_inside = hg._slot.locked()
        message = await receive()
        self.body = message.get("body")
        if self.fail:
            raise RuntimeError("boom")
        if self.respond:
            await send({"type": "http.response.start", "status": 200, "headers": []})
            self.held_after_start = hg._slot.locked()
            await send({"type": "http.response.body", "body": b"ok"})


def _run(inner, scope, chunks):
    sent = []
    queue = list(chunks)

    async def receive():
        if queue:
            return queue.pop(0)
        return {"type": "http.disconnect"}

    async def send(message):
        sent.append(message)

    asyncio.run(hg.HeavyGateMiddleware(inner)(scope, receive, send))
    return sent


@pytest.fixture
def free_slot():
    assert not hg._slot.locked()
    yield
    assert not hg._slot.locked()


class TestGateUnit:
    PASTE = sorted(bl.PASTE_PATHS)[0]

    def test_gated_paths_are_exactly_the_paste_tools(self):
        assert {"/tools/config-drift/compare", "/tools/port-auditor/analyze"} <= bl.PASTE_PATHS
        assert "/tools/subnet/info" not in bl.PASTE_PATHS

    def test_body_arrives_whole_and_slot_is_held(self, free_slot):
        inner = _Inner()
        sent = _run(inner, _http_scope(self.PASTE), [
            {"type": "http.request", "body": b"ab", "more_body": True},
            {"type": "http.request", "body": b"cd", "more_body": False},
        ])
        assert inner.body == b"abcd"
        assert inner.held_inside is True
        assert inner.held_after_start is False  # a slow reader cannot hold it
        assert sent[0]["status"] == 200

    def test_busy_gets_503_with_retry_after_and_the_tool_does_not_run(self, free_slot):
        inner = _Inner()
        hg._slot.acquire()
        try:
            sent = _run(inner, _http_scope(self.PASTE), [{"type": "http.request", "body": b"x"}])
        finally:
            hg._slot.release()
        assert inner.calls == 0
        assert sent[0]["status"] == 503
        assert (b"retry-after", b"5") in sent[0]["headers"]
        assert json.loads(sent[1]["body"])["detail"] == hg.BUSY_MESSAGE

    def test_slot_is_freed_after_an_exception(self, free_slot):
        with pytest.raises(RuntimeError):
            _run(_Inner(fail=True), _http_scope(self.PASTE), [{"type": "http.request", "body": b"x"}])

    def test_slot_is_freed_when_no_response_is_sent(self, free_slot):
        _run(_Inner(respond=False), _http_scope(self.PASTE), [{"type": "http.request", "body": b"x"}])

    def test_client_leaving_during_upload_never_takes_the_slot(self, free_slot):
        inner = _Inner()
        _run(inner, _http_scope(self.PASTE), [{"type": "http.request", "body": b"x", "more_body": True}])
        assert inner.calls == 0

    def test_slow_upload_does_not_hold_the_slot(self, free_slot):
        async def scenario():
            gate = asyncio.Event()
            seen = []

            async def receive():
                await gate.wait()
                return {"type": "http.request", "body": b"x"}

            async def send(message):
                pass

            task = asyncio.create_task(hg.HeavyGateMiddleware(_Inner())(_http_scope(self.PASTE), receive, send))
            await asyncio.sleep(0.01)
            seen.append(hg._slot.locked())
            gate.set()
            await task
            return seen

        assert asyncio.run(scenario()) == [False]

    @pytest.mark.parametrize("scope", [
        _http_scope("/tools/subnet/info"),
        _http_scope(PASTE, method="GET"),
        {"type": "lifespan"},
    ], ids=["other-path", "get", "lifespan"])
    def test_everything_else_passes_while_busy(self, scope):
        inner = _Inner()
        hg._slot.acquire()
        try:
            _run(inner, scope, [{"type": "http.request", "body": b"x"}])
        finally:
            hg._slot.release()
        assert inner.calls == 1


class TestGateThroughTheApp:
    def test_busy_paste_tool_is_503_other_tools_answer(self, free_slot):
        hg._slot.acquire()
        try:
            for path in sorted(bl.PASTE_PATHS):
                r = client.post(path, json={})
                assert r.status_code == 503, path
                assert r.headers["retry-after"] == "5"
                assert r.json() == {"detail": hg.BUSY_MESSAGE}
            assert client.post("/tools/subnet/info", json={"ip_cidr": "10.0.0.0/24"}).status_code == 200
            assert client.get("/health").status_code == 200
        finally:
            hg._slot.release()

    def test_oversized_body_is_still_413_while_busy(self, free_slot):
        hg._slot.acquire()
        try:
            r = client.post(DRIFT, content=(b"x" * (bl.PASTE_MAX + 1) for _ in range(1)),
                            headers={"Content-Type": "application/json"})
            assert r.status_code == 413
        finally:
            hg._slot.release()

    def test_slot_is_free_after_a_normal_request(self, free_slot):
        assert client.post(DRIFT, json={"config_a": "abc", "config_b": "abd"}).status_code == 200
        assert not hg._slot.locked()


class TestGateOnARealServer:
    """DONE W19: five parallel Drift requests at the body limit, peak RSS under 450 MB."""

    LIMIT_MB = 450

    def test_five_parallel_at_the_body_limit(self):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        env = {"PATH": os.environ.get("PATH", ""), "CVE_WARMUP_SYNC": "0"}
        server = subprocess.Popen(
            [sys.executable, "-W", "ignore", "-m", "uvicorn", "api.main:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "error"],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        base = f"http://127.0.0.1:{port}"
        body = json.dumps({"config_a": "x\n" + " a\n" * 237_000, "config_b": "abc"}).encode()
        assert bl.PASTE_MAX - 50_000 < len(body) <= bl.PASTE_MAX
        results = [None] * 5
        other = {}

        def post(path, data):
            request = urllib.request.Request(base + path, data, {"Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(request, timeout=120) as answer:
                    answer.read()
                    return answer.status, None
            except urllib.error.HTTPError as error:
                error.read()
                return error.code, error.headers.get("Retry-After")

        def heavy(index):
            results[index] = post(DRIFT, body)

        try:
            for _ in range(150):
                try:
                    urllib.request.urlopen(base + "/health", timeout=1).read()
                    break
                except OSError:
                    time.sleep(0.1)
            threads = [threading.Thread(target=heavy, args=(i,)) for i in range(5)]
            for thread in threads:
                thread.start()
            time.sleep(0.5)  # the first one is working now
            start = time.perf_counter()
            other["subnet"] = post("/tools/subnet/info", b'{"ip_cidr": "10.0.0.0/24"}')[0]
            other["health"] = urllib.request.urlopen(base + "/health", timeout=30).status
            other["took"] = time.perf_counter() - start
            for thread in threads:
                thread.join()
            after = post(DRIFT, b'{"config_a": "abc", "config_b": "abd"}')[0]
        finally:
            server.terminate()
            _, _, usage = os.wait4(server.pid, 0)
            server.returncode = 0

        peak_mb = usage.ru_maxrss / (1024 * 1024 if sys.platform == "darwin" else 1024)
        codes = sorted(code for code, _ in results)
        assert codes.count(200) >= 1
        assert set(codes) <= {200, 503}
        assert codes.count(503) >= 1
        assert all(retry == "5" for code, retry in results if code == 503)
        assert other["subnet"] == other["health"] == 200
        assert after == 200
        assert peak_mb < self.LIMIT_MB, peak_mb


# ----------------------------
# W20 timezone batch
# ----------------------------

class TestTimezoneBatch:
    def test_over_the_cap_is_400_without_echo(self):
        r = client.post(BATCH, json={"timestamps": ["Q" * 20] * 1001})
        assert r.status_code == 400
        assert "QQQ" not in r.text
        assert len(r.content) < 200

    def test_at_the_cap_is_fast(self):
        start = time.perf_counter()
        r = client.post(BATCH, json={"timestamps": ["a"] * 1000})
        assert time.perf_counter() - start < 0.2
        assert r.status_code == 200
        assert len(r.json()) == 1000

    def test_results_as_before(self):
        r = client.post(BATCH, json={"timestamps": ["2026-11-02 12:00:00", "nope"],
                                     "from_timezone": "UTC", "to_timezone": "America/New_York"})
        first, second = r.json()
        assert first["success"] is True
        assert first["converted"] == "2026-11-02 07:00:00 EST"
        assert second["success"] is False

    def test_not_a_coroutine(self):
        assert not asyncio.iscoroutinefunction(tz.batch_convert)

    def test_other_requests_answer_during_a_batch(self, monkeypatch):
        started, finish = threading.Event(), threading.Event()
        real = tz.parse_timestamp

        def slow(*args):
            started.set()
            assert finish.wait(5)
            return real(*args)

        monkeypatch.setattr(tz, "parse_timestamp", slow)
        with TestClient(app) as local:
            answers = {}
            thread = threading.Thread(
                target=lambda: answers.update(batch=local.post(BATCH, json={"timestamps": ["a"]}).status_code))
            thread.start()
            try:
                assert started.wait(5)
                answers["health"] = local.get("/health").status_code
            finally:
                finish.set()
                thread.join()
        assert answers == {"batch": 200, "health": 200}

    def test_has_its_own_limit(self, monkeypatch):
        monkeypatch.setattr(rl, "ENABLED", True)
        monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter())
        statuses = [client.post(BATCH, json={"timestamps": []}).status_code for _ in range(11)]
        assert statuses == [200] * 10 + [429]


# ----------------------------
# W22 path from the scope
# ----------------------------

class TestHostHeader:
    @pytest.mark.parametrize("host", ["x/y", "a?", "a#"])
    def test_host_header_does_not_escape_the_path_limit(self, monkeypatch, host):
        monkeypatch.setattr(rl, "ENABLED", True)
        monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter())
        for _ in range(10):
            assert client.post(DRIFT, json={}).status_code == 422
        assert client.post(DRIFT, json={}, headers={"Host": host}).status_code == 429


# ----------------------------
# Frontend: W19 sentence, W21 escaping
# ----------------------------

def _web(name):
    with open(os.path.join(ROOT, "web", name), encoding="utf-8") as f:
        return f.read()


def _js_function(source, name):
    """The text of a top-level function, by brace counting from its signature."""
    start = re.search(r"(?:async )?function %s\(" % name, source).start()
    depth, i, opened = 0, start, False
    while True:
        ch = source[i]
        if ch == "{":
            depth += 1
            opened = True
        elif ch == "}":
            depth -= 1
            if opened and depth == 0:
                return source[start:i + 1]
        i += 1


def _node(script):
    done = subprocess.run(["node", "-e", script], capture_output=True, text=True, timeout=30)
    assert done.returncode == 0, done.stderr
    return done.stdout


needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
XSS_TITLE = "router <img src=x onerror=alert(1)>"


class TestDriftSummaryEscaping:
    @needs_node
    def test_real_answer_comes_out_as_text(self):
        data = client.post(DRIFT, json={"config_a": XSS_TITLE + "\n network 10.0.0.0\n",
                                        "config_b": "hostname R\n"}).json()
        assert any("<img" in s for s in data["summary"])  # the API does send it back
        script = (_js_function(_web("app-feeds.js"), "esc") + "\n"
                  + _js_function(_web("app-network.js"), "formatDriftSummary") + "\n"
                  + "process.stdout.write(formatDriftSummary(" + json.dumps(data) + "));")
        html = _node(script)
        assert "<img" not in html
        assert "&lt;img src=x onerror=alert(1)&gt;" in html

    def test_critical_colouring_still_reads_the_raw_text(self):
        source = _js_function(_web("app-network.js"), "formatDriftSummary")
        assert 's.includes("CRITICAL")' in source
        assert "${esc(s)}" in source
        assert "${s}" not in source


class TestBusySentence:
    PASTE_OUTPUTS = ["cdOutput", "cisOutput", "ceOutput", "configParserOutput"]

    @needs_node
    def test_503_gives_the_server_sentence_without_error(self):
        script = (
            "const API_BASE_URL='';\n" + _js_function(_web("app-core.js"), "postJSON") + "\n"
            + _js_function(_web("app-core.js"), "errorText") + "\n"
            + "globalThis.fetch = async () => ({status: 503, ok: false, "
            + "json: async () => ({detail: " + json.dumps(hg.BUSY_MESSAGE) + "})});\n"
            + "postJSON('/x', {}).catch(e => process.stdout.write(errorText(e)));"
        )
        assert _node(script) == hg.BUSY_MESSAGE

    @needs_node
    def test_503_from_the_platform_without_json_is_still_a_sentence(self):
        script = (
            "const API_BASE_URL='';\n" + _js_function(_web("app-core.js"), "postJSON") + "\n"
            + _js_function(_web("app-core.js"), "errorText") + "\n"
            + "globalThis.fetch = async () => ({status: 503, ok: false, json: async () => { throw new Error('html'); }});\n"
            + "postJSON('/x', {}).catch(e => process.stdout.write(errorText(e)));"
        )
        out = _node(script)
        assert out.startswith("The service is busy")
        assert "Error" not in out

    @needs_node
    def test_other_failures_still_read_as_errors(self):
        script = (
            "const API_BASE_URL='';\n" + _js_function(_web("app-core.js"), "postJSON") + "\n"
            + _js_function(_web("app-core.js"), "errorText") + "\n"
            + "globalThis.fetch = async () => ({status: 500, ok: false, statusText: 'x', text: async () => 'boom'});\n"
            + "postJSON('/x', {}).catch(e => process.stdout.write(errorText(e)));"
        )
        assert _node(script) == "Error: Request failed (500): boom"

    def test_every_paste_tool_uses_it(self):
        network = _web("app-network.js")
        for output in self.PASTE_OUTPUTS:
            assert re.search(r"%s\.value = errorText\(err\)" % output, network), output
        assert "paOutput.value = errorText(err)" in _web("app-feeds.js")
