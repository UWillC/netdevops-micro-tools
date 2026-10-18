"""
Per-IP POST rate limit (api/rate_limit.py, fix 2026-09-30).

Pins: the key is the address Cloudflare saw (second-to-last X-Forwarded-For
entry), so a forged first entry cannot mint new buckets; GET is never limited;
/api/subscribe has its own stricter limit; windows reset; 429 carries a
generic message, Retry-After and the CORS header.
"""
import pytest
from fastapi.testclient import TestClient

from api import rate_limit as rl
from api.main import app


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(rl, "ENABLED", True)
    monkeypatch.setattr(rl, "limiter", rl.SlidingWindowLimiter(clock=c))
    return c


@pytest.fixture
def client():
    return TestClient(app)


def _xff(forged, real="70.0.0.1", edge="172.71.0.1"):
    return {"X-Forwarded-For": f"{forged},{real}, {edge}", "Origin": "https://netdevops.thebackroom.ai"}


def _post(client, headers):
    return client.post("/tools/subnet/info", json={"cidr": "10.0.0.0/24"}, headers=headers)


def test_forged_first_entry_does_not_bypass(client, clock):
    for i in range(60):
        assert _post(client, _xff(f"1.1.1.{i}")).status_code != 429
    r = _post(client, _xff("9.9.9.9"))
    assert r.status_code == 429
    assert r.json() == {"detail": rl.LIMIT_MESSAGE}
    assert r.headers["retry-after"] == "60"
    assert "access-control-allow-origin" in r.headers


def test_other_client_unaffected(client, clock):
    for _ in range(60):
        _post(client, _xff("x", real="70.0.0.1"))
    assert _post(client, _xff("x", real="70.0.0.1")).status_code == 429
    assert _post(client, _xff("x", real="70.0.0.2")).status_code != 429


def test_window_resets(client, clock):
    for _ in range(60):
        _post(client, _xff("x"))
    assert _post(client, _xff("x")).status_code == 429
    clock.t += 61
    assert _post(client, _xff("x")).status_code != 429


def test_hourly_cap(client, clock):
    for _ in range(10):
        for _ in range(60):
            assert _post(client, _xff("x")).status_code != 429
        clock.t += 61
    assert _post(client, _xff("x")).status_code == 429


def test_get_never_limited(client, clock):
    for _ in range(100):
        assert client.get("/health", headers=_xff("x")).status_code == 200


def test_subscribe_stricter(client, clock, monkeypatch):
    from api.routers import subscribe
    monkeypatch.setattr(subscribe, "MAILERLITE_API_KEY", "")  # dev mode, no network
    for _ in range(5):
        r = client.post("/api/subscribe", json={"email": "a@example.com"}, headers=_xff("x"))
        assert r.status_code == 200
    r = client.post("/api/subscribe", json={"email": "b@example.com"}, headers=_xff("x"))
    assert r.status_code == 429 and r.headers["retry-after"] == "900"
    # generators from the same IP still work
    assert _post(client, _xff("x")).status_code != 429


def test_client_ip_parsing():
    class R:
        def __init__(self, xff, host="10.9.9.9"):
            self.headers = {"x-forwarded-for": xff} if xff is not None else {}
            self.client = type("C", (), {"host": host})()
    assert rl.client_ip(R("1.2.3.4,70.160.137.150, 172.71.223.186")) == "70.160.137.150"
    assert rl.client_ip(R("70.160.137.150, 172.71.223.186")) == "70.160.137.150"
    assert rl.client_ip(R("70.160.137.150")) == "70.160.137.150"
    assert rl.client_ip(R(None)) == "10.9.9.9"


def test_limiter_bug_fails_open(client, clock, monkeypatch):
    def boom(_):
        raise RuntimeError("counter broken")
    monkeypatch.setattr(rl.limiter, "check_and_record", boom)
    assert _post(client, _xff("x")).status_code != 429


# --- Retention sweep (2026-10-18): privacy policy "in memory for up to about an hour" ---

def test_retention_covers_longest_window():
    assert rl.RETENTION_SECONDS == 60 * 60
    assert rl.SWEEP_INTERVAL == 5 * 60


def test_sweep_drops_inactive_ip_without_it_returning():
    c = Clock()
    lim = rl.SlidingWindowLimiter(clock=c)
    keys = [("ip:70.0.0.1", rl.DEFAULT_LIMITS), ("ip:70.0.0.1|/api/subscribe", rl.PATH_LIMITS["/api/subscribe"])]
    assert lim.check_and_record(keys) is None
    assert lim.key_count() == 2
    # Still inside the hour: a due sweep keeps the address.
    c.t += 30 * 60
    assert lim.sweep_if_due() is True
    assert lim.key_count() == 2
    # Past the hour: the next due sweep removes it, although the IP never came back.
    c.t += 31 * 60
    assert lim.sweep_if_due() is True
    assert lim.key_count() == 0


def test_sweep_not_due_before_interval():
    c = Clock()
    lim = rl.SlidingWindowLimiter(clock=c)
    c.t += rl.SWEEP_INTERVAL - 1
    assert lim.sweep_if_due() is False
    c.t += 1
    assert lim.sweep_if_due() is True


def test_inline_sweep_on_post_when_due():
    """A POST from another client clears an inactive address once a sweep is due."""
    c = Clock()
    lim = rl.SlidingWindowLimiter(clock=c)
    lim.check_and_record([("ip:70.0.0.1", rl.DEFAULT_LIMITS)])
    c.t += 60 * 60 + rl.SWEEP_INTERVAL
    lim.check_and_record([("ip:70.0.0.2", rl.DEFAULT_LIMITS)])
    assert lim.key_count() == 1


def test_sweep_keeps_active_limits_intact(client, clock):
    for _ in range(60):
        _post(client, _xff("x"))
    clock.t += 30  # inside the minute window
    rl.limiter.sweep_if_due()
    assert _post(client, _xff("x")).status_code == 429


def test_sweeper_loop_calls_sweep_and_survives_errors(monkeypatch):
    calls = []

    class Boom:
        def sweep_if_due(self):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("bug")
            return True

    monkeypatch.setattr(rl, "limiter", Boom())

    class Stop(Exception):
        pass

    def fake_sleep(seconds):
        assert seconds == rl.SWEEP_INTERVAL
        if len(calls) >= 2:
            raise Stop

    with pytest.raises(Stop):
        rl._sweeper_loop(sleep=fake_sleep)
    assert len(calls) == 2


def test_start_sweeper_once(monkeypatch):
    started = []

    class FakeThread:
        def __init__(self, target, name, daemon):
            assert daemon is True
            started.append(name)

        def start(self):
            pass

    monkeypatch.setattr(rl, "_sweeper_started", False)
    monkeypatch.setattr(rl.threading, "Thread", FakeThread)
    assert rl.start_sweeper() is True
    assert rl.start_sweeper() is False
    assert started == ["rate-limit-sweeper"]
