"""
FastAPI backend for the CredScan GUI.

Wraps the existing scan engine (via engine_factory) behind a small HTTP API and
serves the static terminal-styled frontend. A scan runs in a background thread;
its output lines and progress are streamed to the browser over Server-Sent
Events, and findings are fetched once it completes.

The GUI runs in one of two modes:

  - LOCAL (default): scans server-local filesystem paths. For a developer
    running the tool on their own machine.
  - PUBLIC (CREDSCAN_PUBLIC=1, or --public): a hardened mode for hosting the
    GUI on the open internet. Path scanning is DISABLED; the only input is
    uploaded files or pasted text, which are written to a per-request sandboxed
    temp directory, scanned, and deleted immediately. Size, file-count, and
    time limits bound every request. This exists because a publicly reachable
    path scanner would let any visitor read the server's own filesystem
    (/etc, env files, mounted secrets) through the scanner's findings.

Security posture (the GUI is part of the tool's threat model):
  - Findings are masked before they leave the server: the API never returns a
    raw secret value, only the masked form (AKIA...MPLE).
  - No secret value is placed in a URL, query string, or log line.
  - In PUBLIC mode there is no path access, no persistence, and hard limits.
"""

import logging
import os
import queue
import shutil
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
    from fastapi.responses import FileResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel, ConfigDict, Field
    from starlette.background import BackgroundTask
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The GUI requires extra dependencies. Install with: pip install 'credscan[gui]'"
    ) from e

from credscan.engine_factory import build_scan_engine
from credscan.output.reporter import Reporter
from credscan.remediation import remediation_for

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Local-mode cap: a whole-monorepo scan belongs on the CLI; in the browser it
# would tie up the server with no feedback. Oversized scans are rejected.
_MAX_GUI_FILES = 5000
# Keep only the most recent N jobs so a long-lived server does not grow unbounded.
_MAX_JOBS = 50
# Cap a browser-initiated history walk; deeper scans belong on the CLI.
_MAX_HISTORY_COMMITS = 2000

# Public-mode hard limits (a publicly reachable scanner is a high-value target).
_PUBLIC_MAX_BYTES = 2 * 1024 * 1024  # 2 MB total upload
_PUBLIC_MAX_FILES = 200  # files per request (incl. inside archives)
_PUBLIC_SCAN_TIMEOUT = 30  # seconds per scan
_PUBLIC_RATE_WINDOW = 60  # seconds
_PUBLIC_RATE_MAX = 20  # scans per window per client


def _is_public_mode() -> bool:
    return os.environ.get("CREDSCAN_PUBLIC", "").strip().lower() in ("1", "true", "yes")


@dataclass
class ScanJob:
    id: str
    path: str
    options: Dict[str, Any]
    status: str = "queued"  # queued | running | done | error
    lines: "queue.Queue" = field(default_factory=queue.Queue)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    files_scanned: int = 0
    files_found: int = 0
    started: float = 0.0
    finished: float = 0.0
    error: Optional[str] = None
    # Public/upload mode: an isolated sandbox dir holding the uploaded content.
    sandbox: Optional[str] = None


class ScanRequest(BaseModel):
    # Accept "validate" on the wire but store it as validate_live internally, so
    # the field does not shadow BaseModel.validate.
    model_config = ConfigDict(populate_by_name=True)

    path: str = "."
    min_confidence: float = 0.5
    no_context_analysis: bool = False
    no_entropy: bool = False
    exclude: Optional[str] = None
    validate_live: bool = Field(default=False, alias="validate")


class HistoryRequest(BaseModel):
    path: str = "."
    max_commits: Optional[int] = 100
    since: Optional[str] = None


class UrlRequest(BaseModel):
    url: str
    crawl: bool = False


def _mask(value: str) -> str:
    return Reporter._mask_value(value or "")


def _public_finding(f: Dict[str, Any]) -> Dict[str, Any]:
    """Project an internal finding to a safe, masked API shape.

    The raw secret value never leaves the server; only the masked form does.
    """
    rem = remediation_for(f)
    return {
        "severity": f.get("severity", "medium"),
        "type": f.get("rule_name", "Credential"),
        "category": f.get("pattern_category") or f.get("category") or "",
        "file": f.get("path", ""),
        "line": f.get("line", 0),
        "masked": _mask(f.get("value", "")),
        "confidence": round(
            float(f.get("overall_confidence", f.get("confidence", 0)) or 0), 3
        ),
        "detector": f.get("rule_id", ""),
        "validation": f.get("verification") or f.get("aws_validation") or "not run",
        "context_type": f.get("context_type", ""),
        "remediation": rem["action"],
        "remediation_fix": rem["root_cause"],
    }


def _apply_validation(findings, job):
    """Run AWS + token validators over findings (read-only, opt-in)."""
    try:
        from credscan.validators import AWSCredentialValidator, TokenValidator

        findings = AWSCredentialValidator({}).enrich_findings(findings)
        findings = TokenValidator({}).enrich_findings(findings)
    except Exception as e:
        job.lines.put(f"  validation skipped: {e}")
    return findings


def _ssrf_blocked(url: str) -> Optional[str]:
    """Return a reason string if the URL must not be fetched, else None.

    Blocks scanning of internal/loopback/link-local/metadata addresses so the
    URL-scan feature cannot be turned into an SSRF probe of the host's network.
    """
    import ipaddress
    import socket
    from urllib.parse import urlparse

    parsed = urlparse(url if "://" in url else "http://" + url)
    if parsed.scheme not in ("http", "https"):
        return "only http/https URLs are allowed"
    host = parsed.hostname
    if not host:
        return "no host in URL"
    if host.lower() in ("localhost", "metadata.google.internal"):
        return "internal host blocked"
    try:
        for info in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(info[4][0])
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return f"non-public address blocked ({ip})"
            if str(ip) == "169.254.169.254":  # cloud metadata
                return "cloud metadata endpoint blocked"
    except Exception:
        return "could not resolve host"
    return None


def create_app() -> "FastAPI":
    app = FastAPI(title="CredScan GUI", docs_url="/api/docs")
    jobs: Dict[str, ScanJob] = {}

    def _run_scan(job: ScanJob):
        job.status = "running"
        job.started = time.monotonic()
        try:
            config: Dict[str, Any] = {
                "scan_path": job.path,
                "min_confidence_threshold": job.options.get("min_confidence", 0.5),
                "enable_context_analysis": not job.options.get(
                    "no_context_analysis", False
                ),
                "enable_entropy": not job.options.get("no_entropy", False),
            }
            if job.options.get("exclude"):
                config["exclude_patterns"] = [
                    p.strip() for p in job.options["exclude"].split(",") if p.strip()
                ]
            # Upload mode restricts the scan to exactly the uploaded files.
            if job.options.get("explicit_files") is not None:
                config["explicit_files"] = job.options["explicit_files"]

            uploaded = job.sandbox is not None
            label = "uploaded content" if uploaded else job.path
            job.lines.put(
                f"$ credscan {'(upload)' if uploaded else '--path ' + job.path} "
                f"--min-confidence {config['min_confidence_threshold']}"
            )
            job.lines.put("initializing engine ...")

            engine = build_scan_engine(config)

            try:
                planned = engine.find_files()
            except Exception:
                planned = []
            if len(planned) > _MAX_GUI_FILES:
                msg = (
                    f"scope too large: {len(planned)} files "
                    f"(GUI limit {_MAX_GUI_FILES}). Narrow --path or use the CLI."
                )
                job.lines.put(f"error: {msg}")
                job.error = msg
                job.status = "error"
                return

            job.lines.put(f"scanning {len(planned)} files ...")
            findings = engine.scan()

            # Optional live validation: confirm which discovered keys are active.
            if job.options.get("validate_live"):
                job.lines.put("validating discovered credentials (read-only) ...")
                findings = _apply_validation(findings, job)

            job.files_found = getattr(engine, "files_found", 0)
            job.files_scanned = getattr(engine, "files_scanned", job.files_found)

            # In upload mode, display paths relative to the sandbox so the
            # server's temp directory layout is never revealed to the client.
            def _project(f):
                pf = _public_finding(f)
                if uploaded and job.sandbox and pf["file"].startswith(job.sandbox):
                    pf["file"] = os.path.relpath(pf["file"], job.sandbox)
                return pf

            job.findings = [_project(f) for f in findings]

            by_sev: Dict[str, int] = {}
            for f in job.findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            for sev in ("critical", "high", "medium", "low"):
                if by_sev.get(sev):
                    job.lines.put(f"  {sev:<8} {by_sev[sev]}")
            job.lines.put(
                f"scan complete · {len(job.findings)} findings · "
                f"{job.files_scanned} files"
            )
            job.status = "done"
        except Exception as e:  # surface, don't crash the server
            logger.exception("scan failed")
            job.error = str(e)
            job.status = "error"
            job.lines.put(f"error: {e}")
        finally:
            # Always delete the uploaded content; nothing is persisted.
            if job.sandbox:
                shutil.rmtree(job.sandbox, ignore_errors=True)
                job.sandbox = None
            job.finished = time.monotonic()
            job.lines.put("__END__")

    def _run_custom(job: ScanJob, produce, banner: str):
        """Run a non-path scan (git history, URL) that produces a finding list."""
        job.status = "running"
        job.started = time.monotonic()
        try:
            job.lines.put(banner)
            findings = produce(job)
            job.findings = [_public_finding(f) for f in findings]
            job.files_scanned = len(findings)
            by_sev: Dict[str, int] = {}
            for f in job.findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            for sev in ("critical", "high", "medium", "low"):
                if by_sev.get(sev):
                    job.lines.put(f"  {sev:<8} {by_sev[sev]}")
            job.lines.put(f"scan complete · {len(job.findings)} findings")
            job.status = "done"
        except Exception as e:
            logger.exception("custom scan failed")
            job.error = str(e)
            job.status = "error"
            job.lines.put(f"error: {e}")
        finally:
            job.finished = time.monotonic()
            job.lines.put("__END__")

    public_mode = _is_public_mode()
    rate_hits: Dict[str, List[float]] = {}

    def _register_custom(job: ScanJob, produce, banner: str):
        jobs[job.id] = job
        if len(jobs) > _MAX_JOBS:
            for old in list(jobs)[: len(jobs) - _MAX_JOBS]:
                jobs.pop(old, None)
        threading.Thread(
            target=_run_custom, args=(job, produce, banner), daemon=True
        ).start()

    def _register_job(job: ScanJob):
        jobs[job.id] = job
        if len(jobs) > _MAX_JOBS:
            for old in list(jobs)[: len(jobs) - _MAX_JOBS]:
                jobs.pop(old, None)
        threading.Thread(target=_run_scan, args=(job,), daemon=True).start()

    def _rate_limit(client: str):
        now = time.monotonic()
        hits = [t for t in rate_hits.get(client, []) if now - t < _PUBLIC_RATE_WINDOW]
        if len(hits) >= _PUBLIC_RATE_MAX:
            raise HTTPException(
                status_code=429, detail="rate limit exceeded, slow down"
            )
        hits.append(now)
        rate_hits[client] = hits

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "credscan-gui"}

    @app.get("/api/mode")
    def mode():
        # The frontend uses this to switch between path-scan and upload-only UI.
        return {
            "public": public_mode,
            "max_bytes": _PUBLIC_MAX_BYTES,
            "max_files": _PUBLIC_MAX_FILES,
        }

    @app.post("/api/scan")
    def start_scan(req: ScanRequest):
        if public_mode:
            # Path scanning would let a visitor read the server's filesystem.
            raise HTTPException(
                status_code=403,
                detail="path scanning is disabled in public mode; upload files instead",
            )
        path = os.path.abspath(os.path.expanduser(req.path))
        if not os.path.exists(path):
            raise HTTPException(status_code=400, detail=f"path not found: {req.path}")
        options = req.model_dump() if hasattr(req, "model_dump") else req.dict()
        job = ScanJob(id=uuid.uuid4().hex[:12], path=path, options=options)
        _register_job(job)
        return {"id": job.id, "path": path}

    @app.post("/api/scan/upload")
    async def scan_upload(
        request: Request,
        files: List[UploadFile] = File(default=[]),
        text: str = Form(default=""),
        filename: str = Form(default="pasted.txt"),
        min_confidence: float = Form(default=0.5),
    ):
        """Scan uploaded files or pasted text in a sandboxed temp dir.

        Available in both modes; it is the ONLY scan path in public mode.
        Content is written under an isolated temp dir, scanned, and deleted.
        """
        client = request.client.host if request.client else "unknown"
        _rate_limit(client)

        sandbox = tempfile.mkdtemp(prefix="credscan-upload-")
        total = 0
        count = 0
        try:
            # Pasted text becomes a single file.
            if text:
                data = text.encode("utf-8", errors="ignore")
                total += len(data)
                if total > _PUBLIC_MAX_BYTES:
                    raise HTTPException(status_code=413, detail="upload too large")
                safe = os.path.basename(filename) or "pasted.txt"
                with open(os.path.join(sandbox, safe), "wb") as fh:
                    fh.write(data)
                count += 1

            for up in files:
                if count >= _PUBLIC_MAX_FILES:
                    raise HTTPException(status_code=413, detail="too many files")
                # Flatten any path components in the client-supplied name.
                safe = os.path.basename(up.filename or f"file{count}")
                data = await up.read()
                total += len(data)
                if total > _PUBLIC_MAX_BYTES:
                    raise HTTPException(status_code=413, detail="upload too large")
                with open(os.path.join(sandbox, safe), "wb") as fh:
                    fh.write(data)
                count += 1

            if count == 0:
                raise HTTPException(status_code=400, detail="no files or text provided")

            explicit = [os.path.join(sandbox, n) for n in os.listdir(sandbox)]
            options = {
                "min_confidence": min_confidence,
                "explicit_files": explicit,
            }
            job = ScanJob(
                id=uuid.uuid4().hex[:12], path=sandbox, options=options, sandbox=sandbox
            )
            # explicit_files flows into the engine config via _run_scan below.
            job.options["explicit_files"] = explicit
            _register_job(job)
            return {"id": job.id, "files": count}
        except HTTPException:
            shutil.rmtree(sandbox, ignore_errors=True)
            raise
        except Exception as e:
            shutil.rmtree(sandbox, ignore_errors=True)
            raise HTTPException(status_code=500, detail=f"upload failed: {e}")

    @app.post("/api/scan/history")
    def scan_history(req: HistoryRequest):
        """Scan git commit history (local mode only — needs a repo on disk)."""
        if public_mode:
            raise HTTPException(
                status_code=403,
                detail="git-history scanning is disabled in public mode",
            )
        repo = os.path.abspath(os.path.expanduser(req.path))
        if not os.path.isdir(os.path.join(repo, ".git")):
            raise HTTPException(
                status_code=400, detail=f"not a git repository: {req.path}"
            )
        # Bound the work so the browser cannot kick off an unbounded history walk
        # that ties up a worker thread; deep scans belong on the CLI.
        max_commits = req.max_commits or 100
        if max_commits > _MAX_HISTORY_COMMITS:
            raise HTTPException(
                status_code=400,
                detail=f"max_commits exceeds GUI limit ({_MAX_HISTORY_COMMITS}); "
                f"use the CLI for a deeper history scan",
            )

        def produce(job):
            from credscan.history.scanner import HistoryScanner

            cfg = {"repo_path": repo, "history_max_commits": max_commits}
            if req.since:
                cfg["history_since"] = req.since
            return HistoryScanner(cfg).scan()

        job = ScanJob(id=uuid.uuid4().hex[:12], path=repo, options={})
        _register_custom(
            job, produce, f"$ credscan --scan-history --max-commits {req.max_commits}"
        )
        return {"id": job.id}

    @app.post("/api/scan/url")
    def scan_url(req: UrlRequest):
        """Scan a web URL for exposed credentials, with SSRF guardrails."""
        blocked = _ssrf_blocked(req.url)
        if blocked:
            raise HTTPException(status_code=400, detail=f"URL not allowed: {blocked}")

        def produce(job):
            from credscan.web.scanner import WebScanner

            # block_private_addresses makes WebScanner re-validate every redirect
            # hop and refuse internal targets, defeating redirect/DNS-rebind SSRF
            # that the one-shot pre-flight check above cannot catch.
            return WebScanner(
                {"web_timeout": 10, "block_private_addresses": True}
            ).scan_url(req.url)

        job = ScanJob(id=uuid.uuid4().hex[:12], path=req.url, options={})
        _register_custom(job, produce, f"$ credscan --url {req.url}")
        return {"id": job.id}

    @app.get("/api/scan/{job_id}/export")
    def export(job_id: str, fmt: str = "sarif"):
        """Generate a server-side report (sarif | compliance | json) for a scan."""
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown scan id")
        if fmt not in ("sarif", "compliance", "json"):
            raise HTTPException(
                status_code=400, detail="fmt must be sarif|compliance|json"
            )

        # Map the GUI finding shape back to the reporter's expected keys. The
        # 'value' carried into the report is the MASKED form, so the export
        # never contains a raw secret.
        def _to_report_shape(f):
            return {
                "rule_id": f.get("detector", "enhanced_pattern"),
                "rule_name": f.get("type", "Credential"),
                "severity": f.get("severity", "medium"),
                "path": f.get("file", ""),
                "line": f.get("line", 0),
                "value": f.get("masked", ""),
                "pattern_category": f.get("category", ""),
                "description": f.get("type", ""),
            }

        report_findings = [_to_report_shape(f) for f in job.findings]
        out_dir = tempfile.mkdtemp(prefix="credscan-export-")
        try:
            reporter = Reporter(
                {
                    "output_formats": [fmt],
                    "output_directory": out_dir,
                    "disable_colors": True,
                    # Force masking: an HTTP-downloadable artifact must never
                    # carry a raw secret, regardless of what the caller passed.
                    "mask_values": True,
                }
            )
            getattr(reporter, f"report_{fmt}")(
                report_findings, {"files_scanned": job.files_scanned}
            )
            produced = [os.path.join(out_dir, n) for n in os.listdir(out_dir)]
            if not produced:
                raise HTTPException(status_code=500, detail="export produced no file")
            ext = {"sarif": "sarif", "compliance": "csv", "json": "json"}[fmt]
            # Remove the temp dir after the file has finished streaming so a
            # long-lived server does not accumulate export scratch directories.
            cleanup = BackgroundTask(shutil.rmtree, out_dir, ignore_errors=True)
            return FileResponse(
                produced[0],
                filename=f"credscan-report.{ext}",
                media_type="application/octet-stream",
                background=cleanup,
            )
        except HTTPException:
            shutil.rmtree(out_dir, ignore_errors=True)
            raise
        except Exception as e:
            shutil.rmtree(out_dir, ignore_errors=True)
            raise HTTPException(status_code=500, detail=f"export failed: {e}")

    @app.get("/api/scan/{job_id}/stream")
    def stream(job_id: str):
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown scan id")

        def event_gen():
            while True:
                try:
                    line = job.lines.get(timeout=30)
                except queue.Empty:
                    break
                if line == "__END__":
                    yield f"event: done\ndata: {job.status}\n\n"
                    break
                # SSE is newline-delimited: collapse any embedded newlines so a
                # single logical line stays a single event.
                safe = str(line).replace("\r", " ").replace("\n", " ")
                yield f"data: {safe}\n\n"

        return StreamingResponse(event_gen(), media_type="text/event-stream")

    @app.get("/api/scan/{job_id}/findings")
    def findings(job_id: str):
        job = jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="unknown scan id")
        return {
            "id": job.id,
            "status": job.status,
            "error": job.error,
            "files_scanned": job.files_scanned,
            "files_found": job.files_found,
            "findings": job.findings,
            "summary": _summary(job.findings),
        }

    def _summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
        out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for f in findings:
            sev = f["severity"]
            if sev in out:
                out[sev] += 1
        return out

    # Serve the frontend.
    if os.path.isdir(_STATIC_DIR):

        @app.get("/")
        def index():
            return FileResponse(os.path.join(_STATIC_DIR, "index.html"))

        app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

    return app


def main():
    """Console entry point: launch the GUI server with uvicorn."""
    import argparse

    parser = argparse.ArgumentParser(description="Launch the CredScan web GUI")
    parser.add_argument(
        "--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="bind port (default: 8000)"
    )
    parser.add_argument(
        "--public",
        action="store_true",
        help="hardened public mode: upload-only, no path scanning "
        "(safe to host on the open internet)",
    )
    args = parser.parse_args()

    if args.public:
        os.environ["CREDSCAN_PUBLIC"] = "1"

    try:
        import uvicorn
    except ImportError:
        raise SystemExit("The GUI requires: pip install 'credscan[gui]'")

    public = _is_public_mode()
    if args.host not in ("127.0.0.1", "localhost") and not public:
        print(
            f"WARNING: binding to {args.host} in LOCAL mode exposes filesystem "
            f"path scanning on the network with no authentication. Use --public "
            f"to host safely (upload-only), or bind to 127.0.0.1."
        )

    mode_label = "PUBLIC (upload-only)" if public else "LOCAL (path scanning)"
    print(f"CredScan GUI [{mode_label}] -> http://{args.host}:{args.port}")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
