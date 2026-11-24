"""
Suite-wide safety net (KEV-X, 2026-09-18).

Code under test can now reach the network to refresh the CISA KEV catalog. No
test should ever do that: it makes the suite slow, flaky, and dependent on a
third-party site. This fixture switches the fetch off for every test and points
the on-disk cache at a temp directory, so a developer's real cache/kev/ can
neither leak into assertions nor be overwritten by them.

Tests that need KEV data install their own index via the `kev_index` fixture.

Background: earlier the same day a feed test wandered into a live PSIRT branch
and auto-imported ~1000 advisories into cve_data/. Same class of mistake,
closed here by default instead of per test.
"""

import datetime
import ipaddress
import socket
import threading

import pytest

from services import kev_catalog

# The day the ISE / KEV fixtures were written. The feed gives a KEV listing a
# ranking boost only for KEV_PRIORITY_WINDOW_DAYS after `date_added`; without a
# frozen clock every "KEV row is first" assertion in this suite would start
# failing on 2026-10-17 for no reason related to the code.
FROZEN_TODAY = datetime.date(2026, 9, 18)


@pytest.fixture(autouse=True)
def _kev_offline(monkeypatch, tmp_path):
    monkeypatch.setenv("KEV_CATALOG_OFFLINE", "1")
    monkeypatch.setenv("CISCO_CHECKER_OFFLINE", "1")   # UPG-02
    from services import cisco_software_checker
    cisco_software_checker.reset_for_tests()
    monkeypatch.setattr(kev_catalog, "KEV_CACHE_DIR", str(tmp_path / "kev"))
    monkeypatch.setattr(kev_catalog, "KEV_CACHE_PATH", str(tmp_path / "kev" / "catalog.json"))
    kev_catalog.reset_for_tests()
    yield
    kev_catalog.reset_for_tests()


@pytest.fixture(autouse=True)
def _frozen_clock(monkeypatch):
    from api.routers import cve as cve_router
    monkeypatch.setattr(cve_router, "_today", lambda: FROZEN_TODAY)


@pytest.fixture(autouse=True)
def _no_background_refresh(monkeypatch):
    """CACHE-01: the feed refreshes stale platform caches on a background thread.

    In a test that thread would call the real PSIRT API and, for IOS XE, run the
    auto-import into cve_data/. Suppress it suite-wide; tests that care about
    the refresh install their own `_spawn`. State is reset so one test's
    backoff or in-flight marker cannot leak into the next.
    """
    from api.routers import cve as cve_router
    monkeypatch.setattr(cve_router, "_spawn", lambda target, *args: None)
    cve_router._platform_refresh_failed_at.clear()
    cve_router._platform_refresh_running.clear()
    yield
    cve_router._platform_refresh_failed_at.clear()
    cve_router._platform_refresh_running.clear()


@pytest.fixture
def kev_index(monkeypatch):
    """Install a fake KEV index: kev_index({"CVE-…": {"due_date": …}})."""
    def _install(records, version="2026.09.16"):
        index = {}
        for cve_id, rec in records.items():
            full = {"cve_id": cve_id, "date_added": None, "due_date": None,
                    "catalog_version": version, "directive": None, "ransomware": None}
            full.update(rec)
            index[cve_id] = full
        monkeypatch.setattr(kev_catalog, "load_kev_index", lambda force_refresh=False: index)
        return index
    return _install


@pytest.fixture(autouse=True)
def _cisco_workaround_offline(monkeypatch):
    """C1 (2026-09-25): imports fetch Cisco's Workarounds text from the CSAF document.

    No test may reach sec.cloudapps.cisco.com; tests that exercise the fetch keep a
    reference to the real function (imported at collection time) and mock urlopen.
    """
    from services import cisco_workaround
    monkeypatch.setattr(cisco_workaround, "fetch", lambda *a, **k: None)
    monkeypatch.setattr(cisco_workaround, "fetch_checked", lambda *a, **k: (None, False))


@pytest.fixture(autouse=True)
def _rate_limit_off(monkeypatch):
    """The suite fires thousands of POSTs from one TestClient address; the
    per-IP limiter (api/rate_limit.py) would start returning 429 mid-run.
    tests/test_rate_limit.py turns it back on for its own tests."""
    from api import rate_limit
    monkeypatch.setattr(rate_limit, "ENABLED", False)


# ---------------------------------------------------------------------------
# TEST-NET-01 (2026-11-24): no test leaves the machine.
#
# Before this, only four test files replaced cve_router._fetch_latest_advisories.
# Every other test that rendered the feed called the real Cisco PSIRT API
# (id.cisco.com, apix.cisco.com) with the developer's own PSIRT credentials and
# wrote cache/cisco/latest.json. CI has no credentials, so it never showed there.
#
# Three layers:
#   1. the PSIRT credentials can not be found (file path redirected, env cleared),
#   2. the known fetchers are replaced by offline stand-ins,
#   3. Python sockets and name lookups are refused for anything that is not
#      loopback, for the whole session (installed at import, so collection is
#      covered too). Tests with a real local server on 127.0.0.1 / ::1 still work.
#
# A refused attempt raises NetworkBlockedError (an OSError, so code under test
# takes its normal "network down" path) AND is recorded; the test that made it
# fails in teardown with the host it tried, so a leak can not hide behind a
# broad `except Exception`.
#
# An attempt that no test can own (collection, between tests, teardown of a
# module/session fixture after the per-test check) fails the session in
# pytest_sessionfinish, so CI can not go green over a leak.
#
# Not covered (@ciso review 2026-11-24, R3):
#   - child processes (node, a second python, uvicorn in test_websec_03) do not
#     inherit these patches; the node harnesses in this suite stub fetch themselves,
#   - uvloop / libuv: its event loop opens sockets and resolves names in C, past
#     the socket module (installed, not imported by the code under test),
#   - a raw `_socket.socket` (the C class, not the socket.socket subclass),
#   - C extensions with their own network stack (grpc is installed, unused).
# ---------------------------------------------------------------------------

class NetworkBlockedError(OSError):
    """Raised by the suite-wide guard for a non-loopback connect or lookup."""


_LOOPBACK_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}
_network_attempts = []            # [(nodeid, what, target)]
_current_test = {"nodeid": "<collection>"}
_attempts_lock = threading.Lock()


def _is_local_host(host) -> bool:
    if host is None:
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "replace")
    host = str(host).strip().strip("[]").split("%", 1)[0].lower()
    if host in ("", "0.0.0.0", "::") or host in _LOOPBACK_NAMES:
        return True     # "" / unspecified: bind-style lookups, they stay on this host
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False    # any other name would need a DNS query


def _refuse(what: str, target) -> None:
    with _attempts_lock:
        _network_attempts.append((_current_test["nodeid"], what, repr(target)))
    raise NetworkBlockedError(f"TEST-NET-01: network blocked in tests ({what} {target!r})")


def _check_address(sock, address, what) -> None:
    if sock.family == getattr(socket, "AF_UNIX", None):
        return
    if isinstance(address, tuple) and address and not _is_local_host(address[0]):
        _refuse(what, address)


_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_sendto = socket.socket.sendto
_real_sendmsg = socket.socket.sendmsg
_real_getaddrinfo = socket.getaddrinfo
_real_gethostbyname = socket.gethostbyname
_real_gethostbyname_ex = socket.gethostbyname_ex
_real_gethostbyaddr = socket.gethostbyaddr
_real_getnameinfo = socket.getnameinfo


def _guarded_connect(self, address):
    _check_address(self, address, "connect")
    return _real_connect(self, address)


def _guarded_connect_ex(self, address):
    _check_address(self, address, "connect_ex")
    return _real_connect_ex(self, address)


def _guarded_sendto(self, data, *args):
    _check_address(self, args[-1] if args else None, "sendto")
    return _real_sendto(self, data, *args)


def _guarded_sendmsg(self, buffers, *args):
    # sendmsg(buffers[, ancdata[, flags[, address]]]): W1, @ciso 2026-11-24.
    _check_address(self, args[2] if len(args) >= 3 else None, "sendmsg")
    return _real_sendmsg(self, buffers, *args)


def _name_guard(what, real):
    def guarded(host, *args, **kwargs):
        if not _is_local_host(host):
            _refuse(what, host)
        return real(host, *args, **kwargs)
    guarded.__name__ = f"_guarded_{what}"
    return guarded


def _guarded_getnameinfo(sockaddr, flags):
    if isinstance(sockaddr, tuple) and sockaddr and not _is_local_host(sockaddr[0]):
        _refuse("getnameinfo", sockaddr)
    return _real_getnameinfo(sockaddr, flags)


socket.socket.connect = _guarded_connect
socket.socket.connect_ex = _guarded_connect_ex
socket.socket.sendto = _guarded_sendto
socket.socket.sendmsg = _guarded_sendmsg
socket.getaddrinfo = _name_guard("getaddrinfo", _real_getaddrinfo)
socket.gethostbyname = _name_guard("gethostbyname", _real_gethostbyname)
socket.gethostbyname_ex = _name_guard("gethostbyname_ex", _real_gethostbyname_ex)
socket.gethostbyaddr = _name_guard("gethostbyaddr", _real_gethostbyaddr)
socket.getnameinfo = _guarded_getnameinfo


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_protocol(item, nextitem):
    _current_test["nodeid"] = item.nodeid
    yield
    _current_test["nodeid"] = "<between tests>"


@pytest.fixture
def network_attempts():
    """The guard's record, for tests that provoke a refusal on purpose.

    Such a test removes its own entries; anything left fails the test."""
    return _network_attempts


@pytest.fixture(autouse=True)
def _no_network(request):
    start = len(_network_attempts)
    yield
    with _attempts_lock:
        mine = [a for a in _network_attempts[start:] if a[0] == request.node.nodeid]
    if mine:
        targets = ", ".join(f"{what} {target}" for _, what, target in mine)
        pytest.fail(f"TEST-NET-01: test tried to reach the network: {targets}", pytrace=False)


def pytest_terminal_summary(terminalreporter):
    if not _network_attempts:
        return
    terminalreporter.section("TEST-NET-01: blocked network attempts")
    for nodeid, what, target in _network_attempts:
        terminalreporter.write_line(f"{nodeid}: {what} {target}")


def pytest_sessionfinish(session, exitstatus):
    """W2, @ciso 2026-11-24: a leftover attempt fails the run.

    Tests that provoke a refusal on purpose remove their own entries, so
    anything still here is a leak, including ones no per-test check could see."""
    if _network_attempts and session.exitstatus == pytest.ExitCode.OK:
        session.exitstatus = pytest.ExitCode.TESTS_FAILED


@pytest.fixture(autouse=True)
def _psirt_offline(monkeypatch, tmp_path):
    """No test may read the developer's Cisco PSIRT credentials or call PSIRT.

    The provider finds no credentials (file path redirected to a file that does
    not exist, env pair removed), so every PSIRT path takes its documented "no
    credentials" branch. The feed's latest-advisories fetch is replaced by an
    empty list; tests that need data install their own fake, which wins because
    it is set later. cisco_software_checker's cached provider is dropped so no
    instance created before this fixture can carry credentials in.
    """
    from api.routers import cve as cve_router
    from services import cisco_software_checker, cve_sources
    monkeypatch.setattr(cve_sources, "CISCO_CREDENTIALS_PATH",
                        str(tmp_path / "no-psirt-credentials.json"))
    monkeypatch.delenv("CISCO_CLIENT_ID", raising=False)
    monkeypatch.delenv("CISCO_CLIENT_SECRET", raising=False)
    # R2, @ciso 2026-11-24: the developer's shell must not switch providers on
    # or hand a real MailerLite key to the suite (subscribe reads it at import).
    for var in ("CVE_CISCO_PSIRT", "CVE_NVD_ENRICH", "CVE_TENABLE_PROVIDER",
                "MAILERLITE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    from api.routers import subscribe
    monkeypatch.setattr(subscribe, "MAILERLITE_API_KEY", "")
    monkeypatch.setattr(cisco_software_checker, "_provider", None)
    monkeypatch.setattr(cve_router, "_fetch_latest_advisories", lambda: [])


@pytest.fixture(autouse=True)
def _whoami_offline(monkeypatch):
    """/whoami does a PTR lookup of the caller; under TestClient that is a DNS
    query for "testclient" sent to the developer's resolver (found by the guard,
    test_beta_activity). Answer as the endpoint does on a miss."""
    from api.routers import whoami
    monkeypatch.setattr(whoami, "reverse_dns", lambda ip: "unavailable")

