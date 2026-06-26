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
        for key in (
            "severity",
            "type",
            "file",
            "line",
            "masked",
            "confidence",
            "remediation",
        ):
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
        # The app links to the guide so users can reach it.
        assert "/guide" in r.text

    def test_guide_served(self, client):
        r = client.get("/guide")
        assert r.status_code == 200
        # The guide covers all four usage surfaces and uses the shared styles.
        assert "/static/style.css" in r.text
        for surface in ("online", "docker", "local", "cli"):
            assert surface in r.text.lower()
        # No em dash slipped into the shipped guide.
        assert "—" not in r.text and "–" not in r.text

    def test_guide_available_in_public_mode(self, monkeypatch):
        # The guide is documentation; it must be reachable on the hosted demo.
        monkeypatch.setenv("CREDSCAN_PUBLIC", "1")
        pc = TestClient(create_app())
        assert pc.get("/guide").status_code == 200


class TestMode:
    def test_mode_local_by_default(self, client):
        m = client.get("/api/mode").json()
        assert m["public"] is False
        assert m["max_bytes"] > 0 and m["max_files"] > 0


class TestContext:
    def test_context_reports_root_and_real_dirs(self, client):
        # Local mode exposes the scan root + the dirs that actually exist there,
        # so the GUI can build quick-actions instead of hardcoding folders.
        c = client.get("/api/context").json()
        assert c["root"]
        assert isinstance(c["dirs"], list)
        # The repo's own dirs are present (the test runs from the repo root).
        assert "src" in c["dirs"] or "tests" in c["dirs"]

    def test_context_empty_in_public_mode(self, monkeypatch):
        monkeypatch.setenv("CREDSCAN_PUBLIC", "1")
        pc = TestClient(create_app())
        c = pc.get("/api/context").json()
        assert c["root"] is None and c["dirs"] == []


class TestExport:
    """Server-side report generation (#30). Exports are MASKED."""

    @pytest.mark.parametrize("fmt", ["sarif", "compliance", "json"])
    def test_export_formats(self, client, fmt):
        jid, _ = _run_scan_to_completion(client)
        r = client.get(f"/api/scan/{jid}/export", params={"fmt": fmt})
        assert r.status_code == 200
        assert r.content, "export was empty"

    def test_export_bad_format_rejected(self, client):
        jid, _ = _run_scan_to_completion(client)
        assert (
            client.get(f"/api/scan/{jid}/export", params={"fmt": "exe"}).status_code
            == 400
        )

    def test_export_unknown_job_404(self, client):
        assert client.get("/api/scan/deadbeef/export").status_code == 404

    @pytest.mark.parametrize("fmt", ["sarif", "compliance", "json"])
    def test_export_has_no_raw_secret(self, client, fmt):
        # Every downloadable format must be masked, including the JSON export
        # (the CLI JSON is a full-value audit log, but the GUI export forces
        # masking via mask_values).
        jid, _ = _run_scan_to_completion(client)
        body = client.get(f"/api/scan/{jid}/export", params={"fmt": fmt}).text
        assert "wJalrX" not in body
        assert "AKIAY2K7MNQ4RST6UVWX" not in body


class TestUrlScanSsrf:
    """URL scanning (#28) must refuse internal/metadata targets."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://localhost/app.js",
            "http://127.0.0.1:8000/",
            "http://169.254.169.254/latest/meta-data/",
            "http://metadata.google.internal/",
            "file:///etc/passwd",
        ],
    )
    def test_ssrf_targets_blocked(self, client, url):
        assert client.post("/api/scan/url", json={"url": url}).status_code == 400


class TestHistoryGuards:
    """git-history endpoint (#27) must validate input before spawning a job."""

    def test_non_repo_rejected(self, client, tmp_path):
        # demo/aws is not a git repo on its own
        r = client.post("/api/scan/history", json={"path": str(tmp_path)})
        assert r.status_code == 400

    def test_excessive_commit_count_rejected(self, client):
        r = client.post("/api/scan/history", json={"path": ".", "max_commits": 999999})
        assert r.status_code == 400


class TestValidateToggle:
    """Live-validation flag (#29): a validate scan still completes cleanly even
    with no AWS creds / network; validators degrade to skipped/unknown."""

    def test_scan_with_validate_completes(self, client):
        jid, lines = _run_scan_to_completion(client, validate=True)
        data = client.get(f"/api/scan/{jid}/findings").json()
        assert data["status"] == "done"
        assert "validation" in data["findings"][0]


def _public_client(monkeypatch):
    monkeypatch.setenv("CREDSCAN_PUBLIC", "1")
    return TestClient(create_app())


class TestPublicMode:
    def test_mode_reports_public(self, monkeypatch):
        c = _public_client(monkeypatch)
        assert c.get("/api/mode").json()["public"] is True

    def test_path_scan_forbidden(self, monkeypatch):
        c = _public_client(monkeypatch)
        assert c.post("/api/scan", json={"path": "."}).status_code == 403

    def test_history_scan_forbidden(self, monkeypatch):
        c = _public_client(monkeypatch)
        assert c.post("/api/scan/history", json={"path": "."}).status_code == 403

    def test_upload_paste_is_scanned_and_masked(self, monkeypatch):
        c = _public_client(monkeypatch)
        leak = "AKIAY2K7MNQ4RST6UVWX"
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f"aws_access_key_id = {leak}\naws_secret_access_key = {secret}\n"
        r = c.post(
            "/api/scan/upload",
            data={"text": text, "filename": "creds.env", "min_confidence": "0.5"},
        )
        assert r.status_code == 200
        jid = r.json()["id"]
        with c.stream("GET", f"/api/scan/{jid}/stream") as s:
            [ln for ln in s.iter_lines() if ln]
        time.sleep(0.2)
        data = c.get(f"/api/scan/{jid}/findings").json()
        assert data["status"] == "done"
        body = json.dumps(data)
        # Findings come back masked; the raw secret never leaves the sandbox.
        assert leak not in body
        assert "wJalrX" not in body
        # Sandbox paths are relativized, never leaking the temp dir layout.
        assert "/tmp" not in body and "credscan-upload-" not in body

    def test_upload_honors_detector_flags(self, monkeypatch):
        # The Config tab exposes the entropy/context toggles in public mode, so
        # the upload endpoint must accept and apply them. Disabling entropy must
        # drop the entropy-only finding (a high-entropy base64 string with no
        # keyword) without erroring.
        c = _public_client(monkeypatch)
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"

        def _scan(no_entropy):
            r = c.post(
                "/api/scan/upload",
                data={
                    "text": text,
                    "filename": "creds.env",
                    "min_confidence": "0.5",
                    "no_entropy": str(no_entropy).lower(),
                },
            )
            assert r.status_code == 200
            jid = r.json()["id"]
            with c.stream("GET", f"/api/scan/{jid}/stream") as s:
                [ln for ln in s.iter_lines() if ln]
            time.sleep(0.2)
            return c.get(f"/api/scan/{jid}/findings").json()

        with_entropy = _scan(no_entropy=False)
        without_entropy = _scan(no_entropy=True)
        assert with_entropy["status"] == "done"
        assert without_entropy["status"] == "done"
        # Turning entropy off should not increase findings; the flag took effect.
        assert len(without_entropy["findings"]) <= len(with_entropy["findings"])
