# Quality Bar

The gates every change must clear, the tool's own threat model, and how to measure the claims you make.

## Definition of Done

A change is NOT done until:

1. **Tests exist and pass.** Every new detector has ≥1 true-positive and ≥1 true-negative fixture. Every bug fix has a regression test. `pytest` is green.
2. **No coverage regression.** Coverage is measured (`pytest --cov=credscan`) and reported as a number; new code is covered.
3. **The claim is proven.** If the change adds/affects detection, the `benchmarks/` corpus was re-run and precision/recall/F1 did not regress (or improved, with the delta stated).
4. **Self-security holds.** Output still masks values; HTML still escapes; no raw secret hits logs at default verbosity. See threat model below.
5. **Docs match reality.** Any user-facing flag/behavior change is reflected in `--help`, README, and TESTING.md. No doc claim without a command that proves it.
6. **It's honest.** No new superlative without a number. No comparison cell without evidence.

## Tool threat model (the scanner must not be the leak)

CredScan handles the most sensitive data in a repo. Its own security is a feature, not an afterthought.

| Threat | Control | Where |
|--------|---------|-------|
| Secret value re-exposed in reports | Mask to `AKIA…MPLE` in all human-readable output; full value only in JSON audit output the user explicitly requests | `output/reporter.py` |
| XSS via malicious "secret" in HTML report | `html.escape()` all scanned content before templating; never `to_html(escape=False)` on raw values | `output/reporter.py` |
| Secret leaked to logs | Never log raw values at INFO; redact in debug too where feasible | engine + analyzers |
| Verification exfiltrates secrets | Active verification is opt-in, read-only (identity endpoints only), never auto-runs, rate-limited, never sends the secret anywhere except its own provider | `validators/` |
| Baseline file leaks secrets | Baseline stores hashes/fingerprints, not raw values, where possible | `baseline/manager.py` |
| Malicious archive (zip bomb) DoS | Size + depth + file-count limits on extraction | `parsers/binary_parser.py` |
| ReDoS via crafted input | Audit patterns for catastrophic backtracking; bound input line length | `enhanced/pattern_library.py` |
| Web scanner SSRF / redirect abuse / DoS | Bound redirect depth and crawl depth; respect timeouts; do not follow arbitrary redirects to internal hosts | `web/scanner.py`, `web/crawler.py` |

Document this table in the README/SECURITY.md. It is one of the most senior-signaling things in the whole project.

### Integration security (distinct from the tool's own threat model)

When CredScan runs inside someone else's pipeline, *that surface* has its own risks — do not conflate with the tool threat model above:

- **GitHub Action / CI** — findings (even masked) must not leak to build logs that are world-readable on public repos; the Action should not echo raw values; mind `GITHUB_TOKEN` scope.
- **Docker image** — runs as a non-root user; minimal base; no secrets baked into layers (dogfood the Dockerfile scanner on itself).
- **Pre-commit hook** — fail closed on error in block mode; a hook that silently passes on a crash is worse than no hook.

## Performance gates

- **Throughput must be measured**, not asserted. Time a scan of a known corpus (e.g. a checked-out mid-size OSS repo) and report files/sec or MB/sec. Re-run before claiming "fast".
- Single full filesystem traversal per scan (the double-`find_files()` class of bug is forbidden — verify).
- Parallelism via the existing `ThreadPoolExecutor` model; web scanning parallelized too.
- Memory: stream/iterate; never load an entire large repo into a dict at once.
- Honest framing: CredScan is Python — it will not beat gitleaks/TruffleHog (Go) on raw speed. Compete on signal quality and coverage, and report your actual numbers without spin.

## Measurement methodology (how to earn a number)

**Precision / Recall / F1:**
1. Build a labeled corpus under `benchmarks/corpus/` — synthetic leaky files + clean files, each with a ground-truth label file listing the true secrets (file, line, type).
2. A `benchmarks/run.py` runs CredScan, compares findings to ground truth, prints TP/FP/FN, precision, recall, F1.
3. Wire it into CI so the number is always current and regressions block merge.
4. Report the corpus size and composition alongside the number — "F1 0.9 on 12 files" is honest; "F1 0.9" alone is not.

**Verified-secret rate:** of findings for providers CredScan can verify, what % were confirmed live. Report separately — it's the strongest single number.

**Throughput:** `time credscan -p <fixed-corpus>`; report files scanned and wall-clock, with hardware noted.

## Skill-compliance self-audit

Before marking any roadmap item done — and whenever you're about to state a capability — run this honesty check against the *actual* source, not memory:

- CWE tagging in findings/SARIF? → `grep -ri "CWE" src/` — if empty, it's NOT done; don't claim it.
- SARIF `partialFingerprints`? → `grep -ri "partialFingerprint\|fingerprint" src/` — verify before claiming dedup-across-runs.
- Measured F1? → does `benchmarks/run.py` exist and run? If not, there is no F1 to cite.
- Multi-provider verification? → check `validators/` for which providers exist; claim only those.
- `SECURITY.md`? → does the file exist with the threat-model table?

The rule: **the tool's real state is the source of truth.** If a doc, report, or statement to the user would describe something this audit shows is absent, fix the statement (or build the feature) — never paper over the gap.

## Release gates (production-grade)

- Semantic versioning; a `CHANGELOG.md` (Keep a Changelog format).
- CI matrix across supported Python versions, green.
- A self-scan job (dogfooding) that runs CredScan on its own repo.
- Packaged for real use: PyPI (`pip install credscan`) and a Docker image.
- `SECURITY.md` (the threat model above + responsible disclosure contact), `LICENSE`, `CONTRIBUTING.md`.
- At least 2–3 ADRs (`docs/adr/`) for the non-obvious decisions: why confidence scoring over ML, why a custom engine vs wrapping gitleaks, GUI stack choice.
