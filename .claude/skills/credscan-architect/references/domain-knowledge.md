# Secret Detection — Domain Knowledge

The body of knowledge a CredScan contributor must operate from. This is what separates a credible secrets scanner from a regex dump.

## 1. Taxonomy of secrets (know what you're hunting)

Secrets fall into classes with very different detection economics:

| Class | Examples | Detectability | Verifiable? |
|-------|----------|---------------|-------------|
| **Structured / fingerprinted** | AWS `AKIA…`, GitHub `ghp_…`, Stripe `sk_live_…`, Slack `xox[bap]-…`, Google `AIza…` | High — provider-defined prefixes + length + charset, often a checksum | Often yes (provider verify endpoint) |
| **Cryptographic material** | RSA/EC/OPENSSH/PGP private keys, PKCS#12, certs | High — unambiguous PEM armor headers | Partially (can derive public key) |
| **Connection strings** | `postgres://user:pass@host`, `mongodb+srv://…` | Medium — URI grammar, secret is the password segment | Rarely (would require connecting) |
| **Generic high-entropy** | bcrypt hashes, random API keys, base64 blobs | Low — entropy + keyword proximity only | No |
| **Assignment-context** | `password = "..."`, `SECRET_KEY: ...` | Low–medium — depends on key name + value plausibility | No |

**Design implication:** structured secrets should be matched by *specific, anchored* patterns (high precision). Generic secrets are where false positives live — they need entropy + context + confidence scoring to be usable. CredScan's four-layer pipeline exists precisely to make the low-detectability classes safe to report.

## 2. Detection techniques (and their failure modes)

1. **Regex / pattern matching.** Best for structured secrets. Failure mode: over-broad patterns (e.g. `[A-Za-z0-9/+]{40}` matches any base64) cause false-positive floods. *Rule: anchor on provider prefix or require assignment context.*
2. **Shannon entropy.** Catches random strings with no keyword. Failure mode: high-entropy non-secrets (hashes, UUIDs, minified JS, base64 images). *Rule: per-type thresholds (base64 ≠ hex ≠ JWT), and entropy alone should rarely be high-confidence.*
3. **Context analysis.** Reads surrounding lines to decide if a match is in prod config vs test/docs/example. Failure mode: comment/test detection is heuristic; document it.
4. **Verification (active).** Call the provider's read-only identity endpoint (e.g. AWS `sts:GetCallerIdentity`) to prove a key is live. This is the single biggest precision multiplier the field has — a *verified* secret is ~100% precision. Failure modes: network dependency, rate limits, ethics (only ever read-only, never state-changing, opt-in, never auto-exfiltrate). TruffleHog's reputation is built on this; CredScan should match it for the providers it claims.
5. **Validity/decay awareness.** A secret in old git history may be rotated already. Report exposure with commit metadata so a human can assess rotation need — don't claim "active" without verifying.

## 3. The precision/recall trade-off (the core tension)

- **Precision** = of what we flagged, how much is truly a secret. Low precision → alert fatigue → tool gets uninstalled. This is the #1 reason secret scanners fail in practice.
- **Recall** = of the real secrets present, how many we caught. Low recall → false sense of safety.
- **F1** = harmonic mean; the single number to track over time.

You cannot claim a precision/recall number without a **labeled corpus**: a set of files/commits where every secret is marked. Build a small one in `benchmarks/` (synthetic + a few well-known public test vectors). Re-run it in CI so regressions surface. A scanner that can't report its own F1 is not production-grade.

**Verified-secret precision** is the killer metric: report precision *and* "of verified-capable findings, X% were confirmed live." That number is honest and devastatingly persuasive.

## 4. Standards & compliance (speak the language)

- **CWE-798: Use of Hard-coded Credentials** — the canonical weakness ID. Tag findings with it. CWE-259 (hard-coded password) and CWE-321 (hard-coded crypto key) are the sub-cases.
- **SARIF 2.1.0** (OASIS) — the interchange format for static analysis results. GitHub code scanning, VS Code SARIF Viewer, and Azure DevOps consume it. Getting SARIF *correct* (rules, `partialFingerprints` for dedup across runs, `region` with line/column, severity mapping) is a strong competence signal. Validate against the schema.
- **OWASP** — secrets map to A07:2021 (Identification & Auth Failures) and the ASVS V2/V6 verification requirements. Cite where relevant, don't overclaim.
- **Compliance hooks** — PCI-DSS 3.2/6.3, SOC 2 CC6.1, NIST 800-53 IA-5 all care about credential management. A one-line "maps to" note in docs shows you understand the buyer, not just the bytes.
- **Secret rotation** — detection is step 1; the finding should always point toward rotation. NIST SP 800-57 covers key lifecycle.

## 5. Remediation is part of detection

A finding without a next step is half a tool. Each finding type should carry:
- **What it is** and why it's dangerous (one line).
- **Immediate action**: rotate/revoke (with the provider's revoke path where known).
- **Root-cause fix**: move to a secrets manager (AWS Secrets Manager, Vault, GCP Secret Manager, SOPS, sealed-secrets for k8s).
- **Prevent recurrence**: pre-commit hook, CI gate.

This is cheap to add (a remediation map keyed by detector) and disproportionately impressive — it shows product thinking, not just pattern matching.

## 6. Git history is a force multiplier

A secret committed once lives forever in every clone, even after deletion. History scanning (already in CredScan) is table-stakes for credibility. The advanced move: report the **commit hash, author, and timestamp** so a responder can scope exposure ("this key was public for 14 months across 3 forks"). Pair with guidance that deleting the file does NOT remediate — the key must be rotated and history rewritten (BFG/`git filter-repo`).

## 7. Where the field is going (shows you're current)

- **Verification-first scanning** (prove it's live) is becoming the default expectation.
- **Pre-commit / shift-left** prevention over after-the-fact detection.
- **Machine-identity sprawl** — non-human credentials (CI tokens, service accounts, k8s SAs) now outnumber human ones; cloud-native sources (IaC, CI/CD, containers) are where the growth is. This is exactly CredScan's differentiation lane — lean into it.
- **Noise reduction via ML/validity** — the industry is fighting false positives; CredScan's confidence pipeline is the same fight fought with transparent, explainable scoring (a defensible design choice vs a black-box model).
