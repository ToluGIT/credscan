# CredScan

[![CI](https://github.com/ToluGIT/credscan/actions/workflows/ci.yml/badge.svg)](https://github.com/ToluGIT/credscan/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A cloud-security credential scanner that goes beyond simple regex matching. CredScan layers pattern matching, Shannon entropy analysis, and context-aware scoring to detect hardcoded secrets across source code, Infrastructure as Code, CI/CD pipelines, Dockerfiles, git commit history, and web endpoints. Includes optional live AWS key validation.

---

## Install

```bash
git clone https://github.com/ToluGIT/credscan.git
cd credscan
pip install -e .
```

Requires Python 3.9+. Optional extras: `pip install -e ".[aws]"` for live AWS
key validation, `".[reports]"` for Excel/PDF output.

---

## How detection works

Most credential scanners apply a regex pattern and report a match. CredScan runs every finding through four layers before reporting it:

1. **Pattern matching**: 15+ categories of regex rules covering cloud providers, payment processors, messaging services, database URIs, cryptographic material, and generic secret patterns
2. **Shannon entropy analysis**: high-randomness strings are flagged even without a keyword match; thresholds are tuned per token type (base64 keys have different entropy profiles than hex secrets or JWTs)
3. **Context analysis**: the surrounding lines are examined to assess whether the credential is in production config, test code, documentation, or an example file; confidence is adjusted accordingly
4. **Confidence scoring**: a weighted score combining pattern strength, entropy, context, and technology signals produces a final confidence value; low-confidence findings are filtered before output

The aim is high signal with minimal noise, so findings reported at default settings are worth investigating.

---

## Measured quality

Accuracy claims are backed by a reproducible benchmark, not asserted. Against
the bundled labeled corpus (16 planted secrets across 6 files, plus 4 clean
files of decoys: env references, placeholders, hashes, UUIDs, base64 config):

| Metric | Score |
|--------|-------|
| Precision | 1.00 |
| Recall | 1.00 |
| F1 | 1.00 |

```bash
PYTHONPATH=src python benchmarks/run.py
```

This is a **regression suite, not an independent benchmark.** The corpus and
several detector fixes were authored together, so the perfect score records that
those fixes behave as intended on representative inputs; it is not evidence of
generalization, and it is not a production precision figure. Its purpose is to
fail CI (`--fail-under-f1 0.90`) if a change degrades detection. A neutral
cross-tool comparison on a larger labeled dataset is future work. See
[benchmarks/README.md](benchmarks/README.md) for the full design notes.

Test coverage is currently 27% (`pytest --cov`); the detection pipeline,
parsers, and SARIF output are well covered, while the git-history, web, and
binary subsystems are not yet unit-tested. See [SECURITY.md](SECURITY.md) for
the tool's own threat model.

---

## Architecture

![CredScan Architecture](credscan-architecture.png)

---

## What it scans

**Source types**

| Source | How |
|--------|-----|
| Files and directories | Recursive scan; parsers selected per file type |
| Git commit history | Every commit diff is scanned; secrets deleted from code still exist in history |
| Git staged files | Pre-commit hook mode blocks or warns before a commit lands |
| Web endpoints | HTTP fetch with optional crawling |

**File types with dedicated parsers**

| Parser | Handles |
|--------|---------|
| IaCParser | Terraform `.tf`/`.tfvars`, CloudFormation YAML/JSON |
| CICDParser | GitHub Actions workflows, GitLab CI, CircleCI, Jenkinsfiles |
| DockerParser | Dockerfiles (`ENV`/`ARG` instructions), Docker image tarballs |
| CodeParser | Python, JavaScript/TypeScript, Java, Go, Ruby, C/C++, C#, PHP, Kotlin, Swift |
| JSONParser / YAMLParser | Config files, API specs, package files |
| BinaryParser | ZIP, TAR, JAR, WAR, APK, IPA archives |
| WebScanner | HTML pages, JavaScript bundles, API responses |

---

## What it detects

**Credentials and tokens**

- AWS Access Key IDs (`AKIA...`) and Secret Access Keys
- GCP service account keys and API keys (`AIzaSy...`)
- Azure connection strings and access keys
- Stripe secret/publishable keys, PayPal Braintree, Square
- GitHub, GitLab, and Bitbucket personal access tokens
- Slack API tokens and webhook URLs
- Twilio, SendGrid, Mailgun, Postmark API keys
- OpenAI, Anthropic, and Hugging Face API keys
- Database connection strings: PostgreSQL, MySQL, MongoDB, Redis
- Generic password assignments, JWT signing secrets, OAuth client secrets

**Cryptographic material**

CredScan detects private keys and certificates committed directly to repositories. All are flagged at critical severity:

- RSA, DSA, EC, and OPENSSH private keys (`-----BEGIN RSA PRIVATE KEY-----`)
- PGP private key blocks (`-----BEGIN PGP PRIVATE KEY BLOCK-----`)
- PKCS#12 and PFX certificate bundles (references to `.p12`, `.pfx`, `.pem`, `.key` files)
- X.509 certificates (`-----BEGIN CERTIFICATE-----`)

**Infrastructure as Code**

- Hardcoded provider credentials in Terraform (`access_key`, `secret_key` in `provider "aws"` blocks)
- Passwords in variable defaults and resource properties
- CloudFormation parameters without `NoEcho: true`
- Secrets hardcoded in CI/CD `env:` blocks instead of referenced from a secrets store

---

## Git history scanning

A credential that was committed and later deleted still exists in git history. Every clone of the repository has it. CredScan walks every commit diff in the specified range, applying the full detection pipeline to each change set.

```bash
# Scan the entire history of the current branch
credscan --scan-history

# Scan the last 200 commits on main
credscan --scan-history --branch main --max-commits 200

# Scan a specific time window
credscan --scan-history --since "6 months ago" --until "1 week ago"

# Scan history and export findings as SARIF
credscan --scan-history -o sarif -d ./reports
```

Each finding includes the commit hash, author, timestamp, and the file and line where the secret appeared, giving you exactly what you need to assess exposure and determine when rotation is required.

---

## Quick start

```bash
# Scan the current directory
credscan

# Scan a specific path, group output by severity
credscan -p ./src --group-by-severity

# Scan Terraform and CloudFormation files
credscan -p ./infra -o json,sarif -d ./reports

# Scan a web endpoint
credscan --url https://example.com/static/app.js

# Validate any AWS keys found (calls sts:GetCallerIdentity, read-only)
credscan -p . --validate-aws

# Tune confidence threshold to reduce false positives
credscan -p . --min-confidence 0.6 --entropy-threshold 4.5
```

Exit codes: `0` = clean · `1` = credentials found · `2` = argument error

---

## Output formats

Reports are generated with `--output` and saved to `--output-dir`:

| Format | Use case |
|--------|----------|
| `console` | Default; colored, with confidence scores and context |
| `json` | Audit log; full finding detail |
| `sarif` | GitHub Code Scanning, VS Code, and other SARIF-compatible tools |
| `html` | Shareable report; values are masked and HTML-escaped |
| `excel` / `csv` | Spreadsheet-based triage |
| `pdf` | Printable report |

Secret values are masked in all human-readable output (`AKIA...MPLE`) and full values are only present in the JSON audit log. The HTML report is generated with proper escaping so content from scanned files cannot execute as code in the browser.

---

## Baseline management

Once you have identified which findings are false positives, save them to a baseline file. Subsequent scans automatically suppress those findings.

```bash
# Run a scan and save all findings as the baseline
credscan -p . --create-baseline .credscan-baseline.json

# Future scans exclude anything in the baseline
credscan -p . --baseline-file .credscan-baseline.json

# Show what is being suppressed
credscan -p . --baseline-file .credscan-baseline.json --show-excluded

# Mark a specific finding as a false positive
credscan -p . --baseline-file .credscan-baseline.json --mark-fp <finding-id>
```

---

## Pre-commit hook

Install CredScan as a git pre-commit hook to prevent secrets from being committed in the first place:

```bash
credscan --install-hook
```

Configure blocking behaviour in `.credscan-hook.conf`:

```bash
HOOK_CONFIG="block"          # block the commit if credentials are found
# HOOK_CONFIG="warning-only" # warn but allow the commit through
BASELINE_FILE=".credscan-baseline.json"
```

---

## CI/CD integration

CredScan exits with code `1` if any credentials are found, making it straightforward to fail a pipeline:

```yaml
# GitHub Actions example
- name: Scan for credentials
  run: |
    pip install credscan
    credscan -p . --no-color -o sarif -d ./reports --min-confidence 0.5
  
- name: Upload SARIF to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ./reports/
```

---

## Configuration file

For repeatable scans across environments, put settings in `config.yaml`:

```yaml
scan_path: "."
exclude_patterns:
  - "node_modules/"
  - ".git/"
  - "dist/"
  - "*.log"
min_confidence_threshold: 0.4
entropy_threshold: 4.0
output_formats: ["console", "sarif"]
output_directory: "./reports"
baseline_file: ".credscan-baseline.json"
```

```bash
credscan --config config.yaml
```

---

## Security note

CredScan is a detection aid. It will not catch every possible credential exposure and is not a substitute for proper secret management (AWS Secrets Manager, HashiCorp Vault, GCP Secret Manager, etc.). Any credential it finds should be rotated immediately. Detection confirms exposure, not just risk.
