#!/usr/bin/env python3
"""
CredScan throughput benchmark.

Generates a fixed-size synthetic corpus (mostly clean code with a few planted
secrets, mirroring a typical repo) and times a full scan, reporting files/sec and
MB/sec. The corpus is generated deterministically so the number is comparable
across runs on the same hardware.

Usage:
    python benchmarks/throughput.py                # default 500 files
    python benchmarks/throughput.py --files 2000   # larger corpus
    python benchmarks/throughput.py --json

Honest framing: CredScan is pure Python and will not match Go scanners
(gitleaks, TruffleHog) on raw throughput. The number here is to (a) track
regressions and (b) confirm scans stay in a range nobody disables.
"""
import argparse
import json
import os
import platform
import sys
import tempfile
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "src"))

# A representative-ish source file: mostly benign code, occasional secret.
_CLEAN_TEMPLATE = '''\
import os
import logging

logger = logging.getLogger(__name__)

class Service{n}:
    """A service component."""
    def __init__(self, config):
        self.config = config
        self.endpoint = config.get("endpoint", "https://api.example.com/v{n}")
        self.timeout = {n} % 30 + 5

    def connect(self):
        token = os.environ["SERVICE_TOKEN_{n}"]
        return {{"endpoint": self.endpoint, "token": token}}

    def process(self, items):
        return [self._handle(i) for i in items if i is not None]

    def _handle(self, item):
        # routine processing, no secrets here
        return {{"id": item, "ok": True}}
'''

_SECRET_SNIPPET = 'AWS_SECRET_ACCESS_KEY = "wJ4pR2nK8mZ5qX7vL9hE3yF6cB1tA0sD/Ng2PqRb"\n'


def generate_corpus(directory: str, n_files: int) -> int:
    """Write n_files .py files; ~1 in 25 carries a planted secret. Returns bytes."""
    total = 0
    for i in range(n_files):
        body = _CLEAN_TEMPLATE.format(n=i)
        if i % 25 == 0:
            body += _SECRET_SNIPPET
        path = os.path.join(directory, f"module_{i:05d}.py")
        with open(path, "w") as f:
            f.write(body)
        total += len(body.encode("utf-8"))
    return total


def run(n_files: int, as_json: bool):
    from credscan.core.engine import ScanEngine
    from credscan.enhanced.config_integration import EnhancedConfig

    with tempfile.TemporaryDirectory() as tmp:
        total_bytes = generate_corpus(tmp, n_files)

        config = EnhancedConfig({"scan_path": tmp, "enable_context_analysis": True})
        engine = config.create_enhanced_engine()
        from credscan.parsers.code_parser import CodeParser
        engine.register_parser(CodeParser({}))

        # Wrap in the context-aware engine, the default production path.
        from credscan.enhanced.context_aware_engine import ContextAwareEngine
        engine = ContextAwareEngine(engine, {"scan_path": tmp})

        start = time.monotonic()
        findings = engine.scan()
        elapsed = time.monotonic() - start

    files_per_sec = n_files / elapsed if elapsed else 0.0
    mb = total_bytes / (1024 * 1024)
    mb_per_sec = mb / elapsed if elapsed else 0.0

    result = {
        "files": n_files,
        "megabytes": round(mb, 2),
        "seconds": round(elapsed, 3),
        "files_per_sec": round(files_per_sec, 1),
        "mb_per_sec": round(mb_per_sec, 2),
        "findings": len(findings),
        "python": platform.python_version(),
        "platform": f"{platform.system()} {platform.machine()}",
    }

    if as_json:
        print(json.dumps(result, indent=2))
    else:
        print()
        print("CredScan Throughput")
        print("=" * 48)
        print(f"  Corpus:     {result['files']} files, {result['megabytes']} MB")
        print(f"  Wall clock: {result['seconds']} s")
        print(f"  Throughput: {result['files_per_sec']} files/s, {result['mb_per_sec']} MB/s")
        print(f"  Findings:   {result['findings']}")
        print(f"  Env:        Python {result['python']} on {result['platform']}")
        print("=" * 48)
        print("Note: pure-Python; not comparable to Go scanners on raw speed.")
        print()
    return result


def main():
    ap = argparse.ArgumentParser(description="CredScan throughput benchmark")
    ap.add_argument("--files", type=int, default=500, help="number of files to generate")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()
    run(args.files, args.json)


if __name__ == "__main__":
    main()
