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

## Throughput

Detection quality is the priority, but a scan also has to be fast enough that
nobody disables it. `throughput.py` generates a fixed synthetic corpus and times
a full scan:

```bash
PYTHONPATH=src python benchmarks/throughput.py --files 500
PYTHONPATH=src python benchmarks/throughput.py --files 2000 --json
```

Measured on the development machine (Apple Silicon, Python 3.12), CredScan scans
roughly **400 files/second** through the full pipeline (pattern matching +
entropy + context + confidence) on this corpus. CredScan is pure Python and does
not try to match Go scanners (gitleaks, TruffleHog) on raw speed; it competes on
signal quality and source coverage. The number here exists to catch regressions
and to set honest expectations.

Caveat on the number: the synthetic corpus is small source files (~30 lines
each). Throughput is per-file dominated, so a repository with large or minified
files (bundled JS, generated JSON) will scan slower per megabyte. Treat 400
files/s as an order-of-magnitude figure for typical source, not a guarantee for
any file mix.

Each file is read from disk once per scan via a small bounded LRU cache
(`credscan/file_cache.py`); on this corpus that collapses the parser, pattern,
and entropy reads into one. Measured effect is about a 4% wall-clock improvement
(406 vs 389 files/s, median of 3 runs) -- modest, because the dominant cost is
regex and entropy CPU work, not IO. The larger benefits are bounded memory and
no repeated reads.

### Performance targets

- **Incremental / pre-commit scan** (`--staged`): should feel instant. Because
  it scans only the files changed in the commit (typically a handful), it
  completes in well under a second on a normal change set.
- **Full mid-size repo scan**: should stay in a range a developer tolerates on
  demand or in CI (order of seconds to low tens of seconds for a few thousand
  files). If a full scan is ever too slow for a hook, use `--staged`.

```bash
# Pre-commit: scan only what changed (fast path)
credscan --staged
# CI: scan everything changed versus the base branch
credscan --diff origin/main
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
