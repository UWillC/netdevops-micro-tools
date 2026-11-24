"""
TEST-NET-01 (2026-11-24): the suite never leaves the machine.

tests/conftest.py refuses every non-loopback connect and name lookup for the
whole session, hides the developer's Cisco PSIRT credentials and stubs the feed's
latest-advisories fetch. These tests prove each layer holds; they use TEST-NET
addresses (RFC 5737) and reserved .invalid names, so even a broken guard sends
nothing anywhere useful.
"""
import os
import socket
import threading
import urllib.request

import pytest

from tests.conftest import NetworkBlockedError

EXTERNAL = ("192.0.2.1", 443)          # TEST-NET-1, RFC 5737


def _drop_own(network_attempts, nodeid):
    network_attempts[:] = [a for a in network_attempts if a[0] != nodeid]


def test_connect_to_external_address_is_refused(request, network_attempts):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        with pytest.raises(NetworkBlockedError):
            s.connect(EXTERNAL)
        with pytest.raises(NetworkBlockedError):
            s.connect_ex(EXTERNAL)
    with pytest.raises(NetworkBlockedError):
        socket.create_connection(EXTERNAL, timeout=1)
    recorded = [a for a in network_attempts if a[0] == request.node.nodeid]
    assert len(recorded) == 3 and all("192.0.2.1" in a[2] for a in recorded)
    _drop_own(network_attempts, request.node.nodeid)


def test_name_lookup_and_http_clients_are_refused(request, network_attempts):
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("apix.cisco.com", 443)
    with pytest.raises(NetworkBlockedError):
        socket.gethostbyaddr("192.0.2.1")
    # urllib wraps the OSError in URLError: code under test sees "network down".
    with pytest.raises(OSError):
        urllib.request.urlopen("https://id.cisco.com/", timeout=1)
    httpx = pytest.importorskip("httpx")
    with pytest.raises(httpx.ConnectError):
        httpx.get("https://services.nvd.nist.gov/", timeout=1)
    assert [a for a in network_attempts if a[0] == request.node.nodeid]
    _drop_own(network_attempts, request.node.nodeid)


def test_refusal_from_a_background_thread_is_recorded(request, network_attempts):
    errors = []

    def worker():
        try:
            socket.create_connection(EXTERNAL, timeout=1)
        except NetworkBlockedError as exc:
            errors.append(exc)

    t = threading.Thread(target=worker)
    t.start()
    t.join(5)
    assert len(errors) == 1
    assert any(a[0] == request.node.nodeid for a in network_attempts)
    _drop_own(network_attempts, request.node.nodeid)


def test_loopback_still_works():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        with socket.create_connection(("127.0.0.1", port), timeout=2):
            conn, _ = server.accept()
            conn.close()
    assert socket.getaddrinfo("localhost", 80)


def test_psirt_credentials_are_not_readable():
    from services import cve_sources
    real = os.path.join(os.path.expanduser("~"), ".config", "cisco-psirt", "credentials.json")
    assert cve_sources.CISCO_CREDENTIALS_PATH != real
    assert not os.path.exists(cve_sources.CISCO_CREDENTIALS_PATH)
    assert os.environ.get("CISCO_CLIENT_ID") is None
    assert os.environ.get("CISCO_CLIENT_SECRET") is None
    assert cve_sources.CiscoAdvisoryProvider()._load_credentials() is None


def test_latest_advisories_fetch_is_stubbed():
    from api.routers import cve as cve_router
    assert cve_router._fetch_latest_advisories() == []
