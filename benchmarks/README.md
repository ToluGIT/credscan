# Benchmarks

A labeled corpus and harness for measuring CredScan's detection quality. The
point is to make accuracy claims verifiable rather than asserted.

## Run it

```bash
PYTHONPATH=src python benchmarks/run.py
# machine-readable:
PYTHONPATH=src python benchmarks/run.py --json
# CI gate:
PYTHONPATH=src python benchmarks/run.py --fail-under-f1 0.90
```

## How scoring works

Matching is at **line granularity**. A finding is a true positive if its
`(relative path, line)` appears in `corpus/labels.json`. A finding whose
location is not labeled is a false positive (this includes any finding inside a
`clean/` file). A labeled secret with no corresponding finding is a false
negative. Multiple detectors firing on one line collapse to a single detection
event so the score is not inflated by overlap.

## Corpus composition

- `corpus/leaky/` holds files with planted, synthetic secrets across categories
  (AWS keys, provider tokens, a Terraform provider block, a GitHub Actions
  workflow, a `.env` file, and a PEM private key).
- `corpus/clean/` holds files with deliberate decoys that a naive scanner would
  false-positive on: environment-variable references, placeholders
  (`REPLACE_WITH_*`, `changeme`), hashes (MD5/SHA-256), a UUID, base64-encoded
  config, and a public key. These files should produce zero findings.
- `corpus/labels.json` is the ground truth.

## What this benchmark is, and is not

This is a **regression suite, not an independent benchmark.** Its job is to stop
detector quality from silently degrading between changes, not to prove CredScan
beats other tools on a neutral dataset.

The corpus and several detector fixes were authored together: the corpus was
built first, run against the engine, and the failing cases it exposed drove
fixes (a private-key pattern that was never loaded; false positives on
environment references, placeholders, and hashes). The current perfect score
records that those specific fixes landed, nothing more. Because the corpus and
the detectors evolved together, the score is **not** evidence of generalization,
and you should read it as "the documented detectors and false-positive guards
behave as intended on representative inputs," not as a production precision
figure.

A defensible production number would require a much larger, independently labeled
dataset (for example, a public secrets benchmark scanned by multiple tools). That
is future work and is called out as such; until then no such claim is made.

- The corpus is **small and curated** (see the printed counts).
- All secret values are **synthetic** and fabricated for testing. None are live.
- The harness is wired into the test suite (`tests/test_benchmark.py`) and CI as
  a regression gate, so detector changes that degrade quality fail the build.

## Extending it

Add a file under `leaky/` or `clean/`, then add its true secrets (or list it as
clean) in `labels.json`. Re-run the harness. Growing the corpus with harder
cases is more valuable than chasing a perfect score on an easy one.
