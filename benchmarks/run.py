#!/usr/bin/env python3
"""
CredScan benchmark harness.

Runs CredScan against a labeled corpus and reports precision, recall, and F1
at line granularity. A finding counts as a true positive (TP) if its
(relative path, line) is listed in the ground-truth labels. A finding whose
location is not in the ground truth is a false positive (FP) -- this includes
any finding in a clean file. A labeled secret with no corresponding finding is
a false negative (FN).

Usage:
    python benchmarks/run.py
    python benchmarks/run.py --json        # machine-readable summary on stdout
    python benchmarks/run.py --fail-under-f1 0.80   # exit 1 if F1 below threshold

Exit codes: 0 = ran (and met threshold if given); 1 = F1 below threshold.
"""
import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
CORPUS_DIR = BENCH_DIR / "corpus"
REPO_ROOT = BENCH_DIR.parent
SRC_DIR = REPO_ROOT / "src"
LABELS_FILE = CORPUS_DIR / "labels.json"


def load_labels():
    with open(LABELS_FILE) as f:
        data = json.load(f)
    truth = {(e["file"], int(e["line"])) for e in data["true_secrets"]}
    clean = set(data["clean_files"])
    return truth, clean, data


def run_scan(output_dir: str) -> str:
    """Run CredScan over the corpus, return the path to the JSON report."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR)
    cmd = [
        sys.executable, "-m", "credscan.cli",
        "--path", str(CORPUS_DIR),
        "--output", "json",
        "--output-dir", output_dir,
        "--no-color",
    ]
    # Exit code 1 just means findings were present; that is expected here.
    subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=300)
    reports = sorted(Path(output_dir).glob("*.json"))
    if not reports:
        raise RuntimeError("CredScan produced no JSON report")
    return str(reports[-1])


def relposix(path: str) -> str:
    """Normalize a finding path to a corpus-relative POSIX path."""
    try:
        return Path(path).resolve().relative_to(CORPUS_DIR).as_posix()
    except ValueError:
        # Fall back to matching the trailing components if not under CORPUS_DIR
        return Path(path).as_posix()


def score(report_path: str, truth: set, clean: set):
    with open(report_path) as f:
        report = json.load(f)

    # Collapse findings to unique (relative_path, line) locations -- multiple
    # detectors firing on one line is one detection event for scoring.
    detected = set()
    for finding in report.get("findings", []):
        rel = relposix(finding.get("path", ""))
        line = finding.get("line")
        if line is None:
            continue
        detected.add((rel, int(line)))

    tp = sorted(detected & truth)
    fp = sorted(detected - truth)
    fn = sorted(truth - detected)

    precision = len(tp) / (len(tp) + len(fp)) if (tp or fp) else 1.0
    recall = len(tp) / (len(tp) + len(fn)) if (tp or fn) else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0

    return {
        "tp": tp, "fp": fp, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "detected_count": len(detected),
    }


def main():
    ap = argparse.ArgumentParser(description="CredScan benchmark harness")
    ap.add_argument("--json", action="store_true", help="emit machine-readable summary")
    ap.add_argument("--fail-under-f1", type=float, default=None,
                    help="exit 1 if F1 is below this threshold")
    args = ap.parse_args()

    truth, clean, raw = load_labels()
    n_leaky_files = len({t[0] for t in truth})
    n_clean_files = len(clean)

    with tempfile.TemporaryDirectory() as tmp:
        report_path = run_scan(tmp)
        result = score(report_path, truth, clean)

    if args.json:
        print(json.dumps({
            "precision": round(result["precision"], 4),
            "recall": round(result["recall"], 4),
            "f1": round(result["f1"], 4),
            "tp": len(result["tp"]),
            "fp": len(result["fp"]),
            "fn": len(result["fn"]),
            "corpus": {
                "true_secrets": len(truth),
                "leaky_files": n_leaky_files,
                "clean_files": n_clean_files,
            },
        }, indent=2))
    else:
        print()
        print("CredScan Benchmark")
        print("=" * 52)
        print(f"Corpus: {len(truth)} labeled secrets across {n_leaky_files} leaky "
              f"files + {n_clean_files} clean files")
        print("-" * 52)
        print(f"  True positives  (TP): {len(result['tp'])}")
        print(f"  False positives (FP): {len(result['fp'])}")
        print(f"  False negatives (FN): {len(result['fn'])}")
        print("-" * 52)
        print(f"  Precision: {result['precision']:.3f}")
        print(f"  Recall:    {result['recall']:.3f}")
        print(f"  F1 score:  {result['f1']:.3f}")
        print("=" * 52)
        if result["fp"]:
            print("\nFalse positives (flagged but not a labeled secret):")
            for path, line in result["fp"]:
                print(f"  {path}:{line}")
        if result["fn"]:
            print("\nFalse negatives (labeled secret that was missed):")
            for path, line in result["fn"]:
                print(f"  {path}:{line}")
        print()

    if args.fail_under_f1 is not None and result["f1"] < args.fail_under_f1:
        print(f"F1 {result['f1']:.3f} is below threshold {args.fail_under_f1}", file=sys.stderr)
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
