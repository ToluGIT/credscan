"""Tests for the GUI FastAPI backend.

Skipped entirely if the gui extra (fastapi) is not installed, so the core test
suite does not require it.
"""
import json
import time

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from credscan.gui.server import create_app  # noqa: E402

DEMO = "demo/aws"


@pytest.fixture
def client():
    return TestClient(create_app())


def _run_scan_to_completion(client, path=DEMO, **opts):
    r = client.post("/api/scan", json={"path": path, "min_confidence": 0.5, **opts})
    assert r.status_code == 200
    jid = r.json()["id"]
    # Drain the SSE stream (blocks until the scan signals done).
    with client.stream("GET", f"/api/scan/{jid}/stream") as s:
        lines = [ln for ln in s.iter_lines() if ln]
    time.sleep(0.2)
    return jid, lines


class TestHealth:
    def test_health(self, client):
        assert client.get("/api/health").json()["status"] == "ok"


class TestScanLifecycle:
    def test_scan_returns_id(self, client):
        r = client.post("/api/scan", json={"path": DEMO})
        assert r.status_code == 200
        assert "id" in r.json()

    def test_unknown_path_rejected(self, client):
        r = client.post("/api/scan", json={"path": "/does/not/exist/xyz"})
        assert r.status_code == 400

    def test_stream_then_findings(self, client):
        jid, lines = _run_scan_to_completion(client)
        assert lines, "stream produced no output"
        data = client.get(f"/api/scan/{jid}/findings").json()
        assert data["status"] == "done"
        assert len(data["findings"]) > 0
        assert set(data["summary"]) == {"critical", "high", "medium", "low"}

    def test_unknown_job_404(self, client):
        assert client.get("/api/scan/deadbeef/findings").status_code == 404


class TestFindingShape:
    def test_finding_fields(self, client):
        jid, _ = _run_scan_to_completion(client)
        f = client.get(f"/api/scan/{jid}/findings").json()["findings"][0]
        for key in ("severity", "type", "file", "line", "masked",
                    "confidence", "remediation"):
            assert key in f

    def test_no_raw_secret_over_the_wire(self, client):
        # The masked form leaves the server; the raw secret never does.
        jid, lines = _run_scan_to_completion(client)
        body = json.dumps(client.get(f"/api/scan/{jid}/findings").json())
        assert "wJalrX" not in body
        assert "AKIAY2K7MNQ4RST6UVWX" not in body
        # And the SSE stream must not carry raw secrets either.
        assert all("AKIAY2K7MNQ4RST6UVWX" not in ln for ln in lines)


class TestScopeCap:
    def test_oversized_scan_errors_not_hangs(self, client, monkeypatch):
        # Lower the cap so a normal directory trips it, and confirm the scan
        # ends with an error verdict rather than hanging the server.
        import credscan.gui.server as srv
        monkeypatch.setattr(srv, "_MAX_GUI_FILES", 1)
        jid, lines = _run_scan_to_completion(client, path="src")
        data = client.get(f"/api/scan/{jid}/findings").json()
        assert data["status"] == "error"
        assert any("scope too large" in ln for ln in lines)


class TestFrontendServed:
    def test_index_served(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "CREDSCAN" in r.text
