# CredScan — Manual Testing Guide

Step-by-step tests using real sample files. Every expected result in this guide was captured from an actual run. Run each command, compare your output to the expected section — if it matches, the feature works.

---

## Setup

```bash
# From the repo root
cd /path/to/credscan

# Make sure the package is importable
export PYTHONPATH=src

# Verify it loads
python3 -m credscan.cli --help
```

If you see the help text, you're ready. If you get `ModuleNotFoundError`, check your `PYTHONPATH`.

> **Note on output**: credscan prints log lines to stderr and findings to stdout. Commands below suppress logs with `2>/dev/null` so you only see findings. Remove it if you want to see debug detail.

---

## Test 1 — AWS Credentials (Python + YAML)

**What it tests**: AWS Access Key ID format, AWS Secret Key via entropy, Google API Key, Stripe keys.

**Sample files**: `tests/manual/samples/aws/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/aws \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1` (findings present)**

```bash
echo $?   # should print: 1
```

**Expected findings** (look for these in the output):

| File | Line | What should be found | Severity |
|------|------|----------------------|----------|
| `credentials.py` | 5 | `AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"` | HIGH |
| `credentials.py` | 6 | `AWS_SECRET_ACCESS_KEY` (entropy: base64, confidence 1.000) | HIGH |
| `credentials.py` | 11 | `STS_SESSION_TOKEN` | HIGH |
| `credentials.py` | 14 | `MWS_KEY = "amzn.mws..."` | HIGH |
| `config.yaml` | 2–3 | `access_key_id` + `secret_access_key` | HIGH |
| `config.yaml` | 6 | `google_api_key: "AIzaSy..."` | HIGH |
| `config.yaml` | 9 | `stripe.secret_key: "sk_live_..."` | HIGH |

**Pass criteria**: Output shows `≥ 15 findings`, `High severity: ≥ 10`, summary line says `26 potential credential(s) found`.

**Fail signal**: Exit code `0`, or AWS key `AKIAIOSFODNN7EXAMPLE` not appearing in any finding.

---

## Test 2 — Database Connection Strings

**What it tests**: Password assignment patterns, connection URI entropy detection, JSON credential fields.

**Sample files**: `tests/manual/samples/database/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/database \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1`**

**Expected findings**:

| File | What should be found | Severity |
|------|----------------------|----------|
| `connections.py:4` | `POSTGRES_URL` containing password (entropy detection) | LOW/MEDIUM |
| `connections.py:19` | `DB_PASSWORD = "HardcodedInCode_NotEnv_123!"` | HIGH |
| `connections.py:20` | `database_password = "AnotherLeakedPassword456$"` | HIGH |
| `config.json:5` | `"password": "Pr0duct10n_DB_S3cret!"` | LOW/MEDIUM |
| `config.json:12` | `"github_token": "ghp_123..."` | MEDIUM |
| `config.json:15` | `"openai_api_key": "sk-abc..."` | MEDIUM |
| `config.json:16` | `"anthropic_api_key": "sk-ant-api03-..."` | MEDIUM |

**Pass criteria**: `≥ 15 findings`, both HIGH password assignments present, GitHub/OpenAI tokens detected.

> **Known behaviour**: Connection string URIs (`postgresql://user:pass@host`) are caught by **entropy analysis** at LOW/MEDIUM severity rather than a named pattern. This is expected — the full URI is high-entropy. The password inside it is what matters; a `--min-confidence 0.5` flag will keep them visible.

---

## Test 3 — Infrastructure as Code (Terraform + CloudFormation)

**What it tests**: IaCParser for `.tf` and CloudFormation YAML, hardcoded provider credentials, variable defaults.

**Sample files**: `tests/manual/samples/iac/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/iac \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1`**

**Expected findings**:

| File | Line | What should be found | Severity |
|------|------|----------------------|----------|
| `main.tf` | 10 | `access_key = "AKIAIOSFODNN7EXAMPLE"` | HIGH |
| `main.tf` | 11 | `secret_key = "wJalrX..."` (entropy 1.000) | HIGH |
| `main.tf` | 21 | `password = "TerraformHardcoded_P@ss!"` | HIGH |
| `main.tf` | 28 | `default = "ghp_abcdef..."` (GitHub token in variable default) | MEDIUM |
| `cloudformation.yaml` | 18 | `MasterUserPassword: "CloudForm@tionHardcoded_Pass!"` | HIGH |
| `cloudformation.yaml` | 27 | `Value: "hardcoded-api-key-value..."` | LOW |

**Pass criteria**: `≥ 10 findings`, Terraform `access_key` and CloudFormation `MasterUserPassword` both present.

**Verify IaC parser specifically**:

```bash
# The IaC parser should claim .tf files before the generic CodeParser
python3 -c "
from credscan.parsers.iac_parser import IaCParser
p = IaCParser({})
print('can_parse .tf:', p.can_parse('main.tf'))
print('can_parse cloudformation.yaml:', p.can_parse('cloudformation.yaml'))
print('rejects plain.yaml:', not p.can_parse('config.yaml'))
"
```

Expected: all three print `True`.

---

## Test 4 — CI/CD Pipeline Files (GitHub Actions + GitLab CI)

**What it tests**: CICDParser for workflow YAML, hardcoded env vars, echo leaks, Bearer tokens in curl.

**Sample files**: `tests/manual/samples/cicd/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/cicd \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1`**

**Expected findings**:

| File | Line | What should be found | Severity |
|------|------|----------------------|----------|
| `github_actions_leaky.yml` | 20 | `AWS_ACCESS_KEY_ID: "AKIA..."` | HIGH |
| `github_actions_leaky.yml` | 21 | `AWS_SECRET_ACCESS_KEY` (entropy 1.000) | HIGH |
| `github_actions_leaky.yml` | 22 | `DATABASE_PASSWORD: "ProdDeploy..."` | HIGH |
| `github_actions_leaky.yml` | 23 | `STRIPE_SECRET_KEY: "sk_live_..."` | HIGH |
| `github_actions_leaky.yml` | 31 | `SLACK_TOKEN: "xoxb-..."` | HIGH |
| `github_actions_leaky.yml` | 35 | `Authorization: Bearer ...` in curl | MEDIUM |
| `gitlab_ci_leaky.yml` | 7 | `AWS_ACCESS_KEY_ID: "AKIA..."` | HIGH |
| `gitlab_ci_leaky.yml` | 9 | `DEPLOY_TOKEN: "glpat-..."` | HIGH |
| `gitlab_ci_leaky.yml` | 10 | `DATABASE_PASSWORD: "GitLabCI..."` | HIGH |

**Pass criteria**: `≥ 18 findings`, both files produce findings, Stripe key and GitLab `DEPLOY_TOKEN` both present.

**Verify CI/CD platform detection**:

```bash
python3 -c "
from credscan.parsers.cicd_parser import CICDParser
p = CICDParser({})
print('GitHub Actions:', p.can_parse('.github/workflows/deploy.yml'))
print('GitLab CI:',      p.can_parse('.gitlab-ci.yml'))
print('CircleCI:',       p.can_parse('.circleci/config.yml'))
print('Jenkinsfile:',    p.can_parse('Jenkinsfile'))
print('Rejects plain:',  not p.can_parse('config.yaml'))
"
```

Expected: all five print `True`.

---

## Test 5 — Dockerfile Credentials

**What it tests**: DockerParser for `ENV`/`ARG` instructions with hardcoded secrets.

**Sample files**: `tests/manual/samples/docker/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/docker \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1`**

**Expected findings**:

| File | Line | What should be found | Severity |
|------|------|----------------------|----------|
| `Dockerfile` | 6 | `ENV DB_PASSWORD="Dockerfile_DB_Hardcoded_Pass!"` | HIGH |
| `Dockerfile` | 7 | `ENV AWS_SECRET_ACCESS_KEY="wJalrX..."` (entropy 1.000) | HIGH |
| `Dockerfile` | 8 | `ENV API_SECRET_TOKEN="docker_api_secret..."` | HIGH |
| `Dockerfile` | 9 | `ENV STRIPE_SECRET_KEY="sk_live_..."` | HIGH |

**Pass criteria**: `≥ 7 findings`, all four `ENV` lines flagged.

**Note**: Line 12 (`ENV VERSION=$BUILD_VERSION`) should **NOT** appear in findings — it's a safe build arg reference.

**Verify DockerParser**:

```bash
python3 -c "
from credscan.parsers.docker_parser import DockerParser
p = DockerParser({})
print('Dockerfile:',       p.can_parse('Dockerfile'))
print('Dockerfile.dev:',   p.can_parse('Dockerfile.dev'))
print('docker-image.tar:', p.can_parse('docker-image.tar'))
print('Rejects app.py:',   not p.can_parse('app.py'))
"
```

---

## Test 6 — Mixed .env File

**What it tests**: Environment file with multiple credential types in a single file.

**Sample files**: `tests/manual/samples/mixed/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/mixed \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1`**

**Expected findings** — all of these must appear:

| Line | Credential | Severity |
|------|-----------|---------|
| 6 | `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE` | HIGH |
| 7 | `AWS_SECRET_ACCESS_KEY` (entropy 1.000) | HIGH |
| 15 | `STRIPE_SECRET_KEY=sk_live_...` | HIGH |
| 16 | `STRIPE_WEBHOOK_SECRET=whsec_...` | HIGH |
| 17 | `SENDGRID_API_KEY=SG....` | HIGH |
| 20 | `JWT_SECRET=my_super_secret_jwt...` | HIGH |
| 24 | `GITHUB_CLIENT_SECRET=github_secret_...` | HIGH |
| 25 | `GOOGLE_CLIENT_SECRET=GOCSPX-...` | HIGH |

**Pass criteria**: `≥ 15 findings`, `High severity: ≥ 12`.

---

## Test 7 — Entropy-Only Detection

**What it tests**: Strings caught by Shannon entropy even without a named keyword pattern.

**Sample files**: `tests/manual/samples/entropy/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/entropy \
  --no-color \
  --output console \
  2>/dev/null
```

**Expected: exit code `1`**

**Expected findings**:

| Line | Credential | Detection method |
|------|-----------|-----------------|
| 5 | `secret_key = "wJalrX...KEY"` | Pattern + entropy (BASE64, confidence 1.000) |
| 8 | `jwt_token = "eyJhbGci..."` | Pattern + JWT entropy |
| 11 | `api_secret = "a3f8e2b1..."` | Pattern |
| 17 | `openai_key = "sk-proj-..."` | Pattern + entropy |
| 20 | `hf_token = "hf_abc..."` | Pattern + entropy |

**Pass criteria**: `≥ 12 findings`, JWT token on line 8 detected, OpenAI and HuggingFace tokens detected.

---

## Test 8 — Clean Code (False Positive Check)

**What it tests**: Code that uses environment variables safely — should produce minimal or no high-confidence findings.

**Sample files**: `tests/manual/samples/clean/`

```bash
python3 -m credscan.cli \
  --path tests/manual/samples/clean \
  --no-color \
  --min-confidence 0.7 \
  --output console \
  2>/dev/null
echo "Exit: $?"
```

**Expected: exit code `1` with low-confidence findings only**

> **Known behaviour**: `REPLACE_WITH_ENV_VAR` and `CHANGE_ME` are automatically identified as test/example credentials and filtered from output (you'll see "N test/example credentials filtered out"). `os.environ["SECRET_KEY"]` assignments are still flagged because the pattern engine sees the variable name `SECRET_KEY` — these are low-risk but unavoidable false positives at this threshold.

**Pass criteria with `--min-confidence 0.7`**: `≤ 4 findings`, no `critical` severity findings. The "2 test/example credentials filtered out" message should appear.

---

## Test 9 — Output Formats

**What it tests**: JSON, SARIF, and HTML report generation.

```bash
mkdir -p /tmp/credscan-test-output

# Generate all formats from the mixed sample
python3 -m credscan.cli \
  --path tests/manual/samples/mixed \
  --output json,sarif,html \
  --output-dir /tmp/credscan-test-output \
  --no-color \
  2>/dev/null

ls -la /tmp/credscan-test-output/
```

**Expected**: three files — `*.json`, `*.sarif`, `*.html`

**Verify JSON structure**:

```bash
python3 -c "
import json, glob
f = sorted(glob.glob('/tmp/credscan-test-output/*.json'))[-1]
d = json.load(open(f))
print('Keys:', list(d.keys()))
print('Findings count:', len(d['findings']))
print('First finding keys:', list(d['findings'][0].keys()))
"
```

Expected output:
```
Keys: ['scan_time', 'statistics', 'findings']
Findings count: 18
First finding keys: ['rule_id', 'rule_name', 'severity', ...]
```

**Verify secret masking in HTML**:

```bash
python3 -c "
import glob
f = sorted(glob.glob('/tmp/credscan-test-output/*.html'))[-1]
content = open(f).read()
# Full key should NOT appear verbatim
assert 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY' not in content, 'FAIL: secret not masked'
# Masked form should appear
assert '...' in content, 'FAIL: no masking found'
# XSS payload should not be executable
assert '<script>' not in content, 'FAIL: XSS vulnerability'
print('PASS: secrets masked, no XSS')
"
```

**Verify SARIF is valid**:

```bash
python3 -c "
import json, glob
f = sorted(glob.glob('/tmp/credscan-test-output/*.sarif'))[-1]
d = json.load(open(f))
assert d['version'] == '2.1.0'
assert len(d['runs'][0]['results']) > 0
print('PASS: valid SARIF with', len(d['runs'][0]['results']), 'results')
"
```

---

## Test 10 — Git History Scan

**What it tests**: Scanning commit history for credentials that were added and removed.

```bash
# Scan the last 10 commits of this repo itself
python3 -m credscan.cli \
  --scan-history \
  --max-commits 10 \
  --branch HEAD \
  --no-color \
  --output console \
  2>/dev/null
echo "Exit: $?"
```

**Expected**: exits `0` (no real credentials should be in the repo's own history) or `1` with findings from the test sample files if they were committed.

---

## Test 11 — Baseline Management

**What it tests**: Creating a baseline, scanning again with it applied, verifying findings are suppressed.

```bash
# Step 1: Scan and create a baseline
python3 -m credscan.cli \
  --path tests/manual/samples/aws \
  --create-baseline /tmp/test-baseline.json \
  --no-color \
  2>/dev/null

cat /tmp/test-baseline.json | python3 -c "import json,sys; d=json.load(sys.stdin); print('Baseline entries:', len(d.get('exclusions', [])))"
```

Expected: `Baseline entries: ≥ 1`

```bash
# Step 2: Scan again using the baseline — all findings should be excluded
python3 -m credscan.cli \
  --path tests/manual/samples/aws \
  --baseline-file /tmp/test-baseline.json \
  --no-color \
  2>/dev/null
echo "Exit with baseline: $?"
```

Expected: exit code `0` (all findings suppressed by baseline).

---

## Test 12 — CLI Flag Sanity

**What it tests**: The new clean `--no-X` flags work without errors.

```bash
# Each of these should run without argparse errors
python3 -m credscan.cli --path tests/manual/samples/aws --no-context-analysis  --no-color 2>/dev/null; echo "no-context-analysis: $?"
python3 -m credscan.cli --path tests/manual/samples/aws --no-confidence-scoring --no-color 2>/dev/null; echo "no-confidence-scoring: $?"
python3 -m credscan.cli --path tests/manual/samples/aws --no-enhanced-entropy   --no-color 2>/dev/null; echo "no-enhanced-entropy: $?"
python3 -m credscan.cli --path tests/manual/samples/aws --no-deduplication      --no-color 2>/dev/null; echo "no-deduplication: $?"
python3 -m credscan.cli --path tests/manual/samples/aws --no-binary-parsing     --no-color 2>/dev/null; echo "no-binary-parsing: $?"
python3 -m credscan.cli --path tests/manual/samples/aws --legacy-patterns       --no-color 2>/dev/null; echo "legacy-patterns: $?"
```

**Pass criteria**: All six return exit code `0` or `1` (not `2`). Exit code `2` means argparse error.

---

## Test 13 — Pre-commit Hook Mode

**What it tests**: The `--hook-scan` mode that scans git-staged files.

```bash
# Stage one of the sample files temporarily
cp tests/manual/samples/aws/credentials.py /tmp/test_hook_cred.py
git add /tmp/test_hook_cred.py 2>/dev/null || true

# Simulate hook scan on staged files
python3 -m credscan.cli \
  --hook-scan \
  --no-color \
  2>/dev/null
echo "Hook exit: $?"

# Clean up
git reset /tmp/test_hook_cred.py 2>/dev/null || true
```

**Expected**: exit code `1` if staged files contain credentials (hook blocks commit), or `0` if nothing staged.

---

## Test 14 — Full Pipeline (all parsers together)

**What it tests**: Everything at once — runs the complete leaky_repo fixture through the full detection pipeline.

```bash
python3 -m credscan.cli \
  --path tests/testdata/leaky_repo \
  --no-color \
  --group-by-severity \
  --output console \
  2>/dev/null
echo "Exit: $?"
```

**Expected: exit code `1`**

You should see findings grouped under `HIGH SEVERITY FINDINGS` that include:
- `config.py` — AWS key + Stripe key + OpenAI key
- `infra/main.tf` — Terraform access_key + password
- `.github/workflows/deploy.yml` — CI/CD hardcoded env vars
- `Dockerfile` — ENV secrets

**Pass criteria**: `≥ 10 findings` across at least 4 different files/parsers.

---

## Quick Full-Suite Run

Run all automated tests (44 tests) to verify nothing is broken:

```bash
PYTHONPATH=src /opt/homebrew/bin/pytest tests/ \
  --ignore=tests/test_integration.py \
  -v \
  2>&1 | tail -20
```

**Expected**: `44 passed` (or higher if new tests have been added).

---

## Summary Checklist

| Test | Command target | Expected exit | Key signal |
|------|---------------|--------------|------------|
| 1 — AWS creds | `samples/aws/` | `1` | `AKIAIOSFODNN7EXAMPLE` detected |
| 2 — Databases | `samples/database/` | `1` | `DB_PASSWORD` HIGH severity |
| 3 — IaC | `samples/iac/` | `1` | Terraform `access_key` + CF `MasterUserPassword` |
| 4 — CI/CD | `samples/cicd/` | `1` | GitHub Actions + GitLab CI both fire |
| 5 — Docker | `samples/docker/` | `1` | All 4 `ENV` lines flagged |
| 6 — .env | `samples/mixed/` | `1` | ≥ 15 findings across 8+ credential types |
| 7 — Entropy | `samples/entropy/` | `1` | JWT + OpenAI + HuggingFace detected |
| 8 — Clean code | `samples/clean/` + `--min-confidence 0.7` | `1` | ≤ 3 findings, no critical |
| 9 — Output formats | JSON + SARIF + HTML | n/a | 3 files created, secrets masked, no XSS |
| 10 — Git history | `--scan-history` | `0` or `1` | No crash |
| 11 — Baseline | create + rescan | `0` on rescan | All findings suppressed |
| 12 — CLI flags | `--no-X` flags | `0` or `1` (not `2`) | No argparse errors |
| 13 — Hook mode | `--hook-scan` | `0` or `1` | No crash |
| 14 — Full pipeline | `testdata/leaky_repo/` | `1` | ≥ 4 file types caught |
