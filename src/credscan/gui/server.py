"""
FastAPI backend for the CredScan GUI.

Wraps the existing scan engine (via engine_factory) behind a small HTTP API and
serves the static terminal-styled frontend. A scan runs in a background thread;
its output lines and progress are streamed to the browser over Server-Sent
Events, and findings are fetched once it completes.

Security posture (the GUI is part of the tool's threat model):
  - Findings are masked before they leave the server: the API never returns a
    raw secret value, only the masked form (AKIA...MPLE).
  - No secret value is placed in a URL, query string, or log line.
  - Scans run against server-local paths only; this is a local developer tool,
    not a multi-tenant service.
"""
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import FileResponse, StreamingResponse
    from fastapi.staticfiles import StaticFiles
    from pydantic import BaseModel
except ImportError as e:  # pragma: no cover - exercised only without the extra
    raise ImportError(
        "The GUI requires extra dependencies. Install with: pip install 'credscan[gui]'"
    ) from e

from credscan.engine_factory import build_scan_engine
from credscan.output.reporter import Reporter
from credscan.remediation import remediation_for

_STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Cap how many files a single GUI scan will process. A whole-monorepo scan
# belongs on the CLI; in the browser it would tie up the server with no
# feedback. Oversized scans are rejected with a clear message rather than hung.
_MAX_GUI_FILES = 5000
# Keep only the most recent N jobs so a long-lived server does not grow
# unbounded.
_MAX_JOBS = 50


@dataclass
class ScanJob:
    id: str
    path: str
    options: Dict[str, Any]
    status: str = "queued"           # queued | running | done | error
    lines: "queue.Queue" = field(default_factory=queue.Queue)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    files_scanned: int = 0
    files_found: int = 0
    started: float = 0.0
    finished: float = 0.0
    error: Optional[str] = None


class ScanRequest(BaseModel):
    path: str = "."
    min_confidence: float = 0.5
    no_context_analysis: bool = False
    no_entropy: bool = False
    exclude: Optional[str] = None


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
                "enable_context_analysis": not job.options.get("no_context_analysis", False),
                "enable_entropy": not job.options.get("no_entropy", False),
            }
            if job.options.get("exclude"):
                config["exclude_patterns"] = [
                    p.strip() for p in job.options["exclude"].split(",") if p.strip()
                ]

            job.lines.put(f"$ credscan --path {job.path} --min-confidence "
                          f"{config['min_confidence_threshold']}")
            job.lines.put("initializing engine ...")

            engine = build_scan_engine(config)

            # Enforce the scope cap before scanning so a huge tree cannot hang
            # the server. find_files() is a cheap directory walk.
            try:
                planned = engine.find_files()
            except Exception:
                planned = []
            if len(planned) > _MAX_GUI_FILES:
                msg = (f"scope too large: {len(planned)} files "
                       f"(GUI limit {_MAX_GUI_FILES}). Narrow --path or use the CLI.")
                job.lines.put(f"error: {msg}")
                job.error = msg
                job.status = "error"
                return

            job.lines.put(f"scanning {len(planned)} files ...")
            findings = engine.scan()

            job.files_found = getattr(engine, "files_found", 0)
            job.files_scanned = getattr(engine, "files_scanned", job.files_found)
            job.findings = [_public_finding(f) for f in findings]

            by_sev: Dict[str, int] = {}
            for f in job.findings:
                by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
            for sev in ("critical", "high", "medium", "low"):
                if by_sev.get(sev):
                    job.lines.put(f"  {sev:<8} {by_sev[sev]}")
            job.lines.put(f"scan complete · {len(job.findings)} findings · "
                          f"{job.files_scanned} files")
            job.status = "done"
        except Exception as e:  # surface, don't crash the server
            logger.exception("scan failed")
            job.error = str(e)
            job.status = "error"
            job.lines.put(f"error: {e}")
        finally:
            job.finished = time.monotonic()
            job.lines.put("__END__")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "credscan-gui"}

    @app.post("/api/scan")
    def start_scan(req: ScanRequest):
        path = os.path.abspath(os.path.expanduser(req.path))
        if not os.path.exists(path):
            raise HTTPException(status_code=400, detail=f"path not found: {req.path}")
        options = req.model_dump() if hasattr(req, "model_dump") else req.dict()
        job = ScanJob(id=uuid.uuid4().hex[:12], path=path, options=options)
        jobs[job.id] = job
        # Evict oldest jobs so a long-lived server does not grow unbounded.
        if len(jobs) > _MAX_JOBS:
            for old in list(jobs)[: len(jobs) - _MAX_JOBS]:
                jobs.pop(old, None)
        threading.Thread(target=_run_scan, args=(job,), daemon=True).start()
        return {"id": job.id, "path": path}

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
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="bind port (default: 8000)")
    args = parser.parse_args()

    try:
        import uvicorn
    except ImportError:
        raise SystemExit("The GUI requires: pip install 'credscan[gui]'")

    if args.host not in ("127.0.0.1", "localhost"):
        print(f"WARNING: binding to {args.host} exposes the scanner on the "
              f"network with no authentication. Findings (masked) and scan "
              f"control would be reachable by others. Use 127.0.0.1 unless you "
              f"are certain.")

    print(f"CredScan GUI -> http://{args.host}:{args.port}")
    uvicorn.run(create_app(), host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
