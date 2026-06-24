# Security

CredScan handles the most sensitive data in a repository: its credentials. The
tool's own security is treated as a feature, not an afterthought. A secrets
scanner that prints secrets in clear text, is XSS-able in its own report, or
fires unsolicited network calls would fail its own threat model.

## Tool threat model

How CredScan avoids becoming the leak it is built to find.

| Threat | Control | Where |
|--------|---------|-------|
| Secret value re-exposed in reports | Values are masked to `AKIA...MPLE` in all human-readable output (console, HTML, CSV, Excel). | `output/reporter.py` (`_mask_value`) |
| XSS via a malicious "secret" in the HTML report | All scanned content is passed through `html.escape()` before templating; the report cannot execute content from a scanned file. | `output/reporter.py` (`report_html`) |
| Raw secret leaked into SARIF | SARIF `partialFingerprints` are derived from a masked value, not the raw secret, so the SARIF file carries no credential. | `output/reporter.py` (`_partial_fingerprint`) |
| Verification exfiltrates secrets | Active AWS validation is opt-in (`--validate-aws`), read-only (`sts:GetCallerIdentity` only), rate-limited, and never sends the secret anywhere except AWS's own identity endpoint. | `validators/aws_validator.py` |
| Malicious archive (zip bomb) denial of service | Extraction is bounded by size, depth, file-count, and time limits. | `parsers/binary_parser.py` |
| Web scanning abuse (runaway crawl / slow host) | Requests are bounded by a timeout and crawl depth limit. | `web/scanner.py`, `web/crawler.py` |
| Test/example credentials inflating results | Findings classified as test/placeholder/reference values are filtered from output by default (override with `--show-test-credentials`). | `enhanced/result_deduplicator.py` |

## Integration security

When CredScan runs inside someone else's pipeline, that surface has its own
considerations:

- **CI / GitHub Actions:** findings are masked in human-readable output; use
  `--output sarif` and upload to the Security tab rather than echoing findings
  into build logs, especially on public repositories.
- **Exit codes:** CredScan exits `1` when credentials are found and `2` on
  argument errors, so a pipeline gate fails closed rather than passing silently.
- **Pre-commit hook:** in `block` mode the hook stops the commit when
  credentials are detected.

## Reporting a vulnerability

If you find a security issue in CredScan itself (for example, a way to make it
leak a scanned secret, or a crash on crafted input), please open a private
report via GitHub Security Advisories on the repository rather than a public
issue. Include the input that triggers it and the observed behavior.

## A note on findings

CredScan is a detection aid, not a guarantee. It will not catch every possible
credential exposure and is not a substitute for managed secret storage (AWS
Secrets Manager, HashiCorp Vault, GCP Secret Manager, SOPS, sealed-secrets).
Any credential it surfaces should be rotated immediately. Detection confirms
exposure, not just risk, and for anything found in git history, deleting the
file does not remediate it: the secret must be rotated and the history rewritten.
