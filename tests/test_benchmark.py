"""Regression guard: the benchmark corpus must keep meeting a quality floor.

This runs the same harness as benchmarks/run.py and asserts precision/recall
do not regress below a threshold. It is the gate that stops detection quality
from silently degrading.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
RUN = REPO_ROOT / "benchmarks" / "run.py"


@pytest.mark.skipif(not RUN.exists(), reason="benchmark harness not present")
def test_benchmark_meets_quality_floor():
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    proc = subprocess.run(
        [sys.executable, str(RUN), "--json"],
        capture_output=True,
        text=True,
        env=env,
        timeout=300,
    )
    assert proc.returncode == 0, f"benchmark run failed:\n{proc.stderr}"
    result = json.loads(proc.stdout)

    # Quality floor. The corpus is small and curated, so the bar is high; the
    # point of the gate is to catch regressions, not to certify the score is
    # representative of arbitrary repositories.
    assert result["precision"] >= 0.90, f"precision regressed: {result}"
    assert result["recall"] >= 0.90, f"recall regressed: {result}"
    assert result["f1"] >= 0.90, f"F1 regressed: {result}"
