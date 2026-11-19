"""WEBSEC-01 re-review 02.11: build_time in /meta/version was the request time."""
import re
import time

from fastapi.testclient import TestClient

import api.main as main
from api.main import app
from version import APP_VERSION

client = TestClient(app)


def test_build_time_is_stable_between_calls():
    first = client.get("/meta/version").json()
    time.sleep(1.1)
    second = client.get("/meta/version").json()
    assert first["build_time"] == second["build_time"]
    assert first["version"] == APP_VERSION
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", first["build_time"])


def test_build_time_read_from_file(tmp_path, monkeypatch):
    root = tmp_path
    (root / "api").mkdir()
    (root / "BUILD_TIME").write_text("2026-11-19T10:00:00Z\n", encoding="utf-8")
    monkeypatch.setattr(main.os.path, "abspath", lambda _p: str(root / "api" / "main.py"))
    assert main._read_build_time() == "2026-11-19T10:00:00Z"


def test_build_time_falls_back_without_file(tmp_path, monkeypatch):
    (tmp_path / "api").mkdir()
    monkeypatch.setattr(main.os.path, "abspath", lambda _p: str(tmp_path / "api" / "main.py"))
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", main._read_build_time())


def test_dockerfile_writes_build_time_after_copy():
    text = open("Dockerfile", encoding="utf-8").read()
    assert text.index("COPY . .") < text.index("> /app/BUILD_TIME")
