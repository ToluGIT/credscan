# Competitive Landscape — Honest Positioning

A reviewer who works in security knows these tools. Claiming superiority you can't back up is an instant credibility loss. The goal is *honest differentiation*: be clear-eyed about what the incumbents do better, and stake CredScan's claim on a real, defensible lane.

## The incumbents (respect them)

### gitleaks (Go)
- **Strengths:** extremely fast (Go, concurrent), huge install base, simple TOML rules, excellent git-history scanning, trusted in CI everywhere. The default reach-for tool.
- **Gaps CredScan can own:** it's regex-only (no active verification), limited semantic understanding of IaC/CI-CD structure, no confidence scoring — every match is equal weight.

### TruffleHog (Go)
- **Strengths:** the verification leader — 800+ detectors that *actively verify* secrets against provider APIs. This is its moat and it's a strong one. Fast, well-funded (Truffle Security).
- **Gaps CredScan can own:** verification breadth is huge but CredScan can match it *for the cloud providers it claims* while adding transparent confidence scoring and richer IaC/CI-CD/Docker context that Trufflehog treats more generically.
- **Honest note:** Do NOT claim to out-verify TruffleHog in breadth. Claim depth + explainability in CredScan's lane.

### detect-secrets (Python, Yelp)
- **Strengths:** the baseline-workflow pioneer; pre-commit native; plugin model; entropy + keyword heuristics; audit workflow for triaging the baseline. Closest peer architecturally (also Python).
- **Gaps CredScan can own:** no active verification, weaker cloud-native/IaC coverage, less emphasis on multi-factor confidence and per-finding remediation.

### GitGuardian (commercial SaaS)
- **Strengths:** enterprise platform, dashboards, 350+ detector types, historical scanning at org scale, incident workflow. Not an apples-to-apples comparison (it's a product, not a CLI).
- **Positioning:** CredScan is an open, self-hosted, transparent alternative for the single-repo / CI use case — not a GitGuardian replacement. Say so.

## CredScan's defensible lane

Do not try to beat everyone at everything. Win clearly here:

1. **Cloud-native source coverage as a first-class concern** — dedicated, structure-aware parsers for Terraform, CloudFormation, GitHub Actions/GitLab CI/Jenkins/CircleCI, and Dockerfiles/image tarballs. Most CLI scanners treat these as plain text; CredScan understands `provider "aws" {}` blocks, `env:` blocks, and `ENV` instructions. This maps to where credential sprawl is actually growing (machine identities).
2. **Transparent, explainable confidence scoring** — every finding shows *why* it scored what it did (pattern + entropy + context + technology weights). This is the antidote to black-box noise and is genuinely differentiated against regex-only tools.
3. **Verification + explainability together** — prove AWS keys are live (`sts:GetCallerIdentity`) AND explain the confidence. TruffleHog gives you verified/not; CredScan gives you verified + a reasoned score for the unverifiable majority.
4. **The scanner that doesn't leak** — masking, HTML-escaping its own reports, a documented self-threat-model. A surprising number of tools fail this.

## The comparison table rule

Any comparison table in README/docs MUST:
- Include a row where a competitor wins (speed → gitleaks; verification breadth → TruffleHog). Absence of this is a red flag to reviewers.
- Use ✓ / partial / ✗ with a footnote defining each, OR cite the specific capability — never bare checkmarks implying total dominance.
- Be reproducible: if you claim CredScan detects something a competitor misses, have the fixture file and both tools' output saved under `benchmarks/`.

A table where CredScan wins every row is marketing. A table that concedes real ground and still shows a clear lane is *credible* — and far more persuasive.

## Language discipline

- Never: "the best", "most comprehensive", "industry-leading", "revolutionary".
- Instead: "purpose-built for cloud-native sources", "verification + transparent scoring", "respects gitleaks for raw speed; differentiates on X".
- When unsure if a claim is defensible, downgrade it to what you measured.
