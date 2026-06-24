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

## Honest caveats

- The corpus is **small and curated** (see the printed counts). A high score
  here demonstrates that the documented detectors and false-positive guards work
  on representative inputs. It is **not** a claim about precision/recall on
  arbitrary production repositories, which would require a much larger,
  independently labeled dataset.
- All secret values are **synthetic** and fabricated for testing. None are live.
- The harness is wired into the test suite (`tests/test_benchmark.py`) as a
  regression gate, so detector changes that degrade quality fail CI.

## Extending it

Add a file under `leaky/` or `clean/`, then add its true secrets (or list it as
clean) in `labels.json`. Re-run the harness. Growing the corpus with harder
cases is more valuable than chasing a perfect score on an easy one.
