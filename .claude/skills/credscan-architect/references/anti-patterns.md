# Anti-Patterns — What Gets a Project Dismissed

These are the tells that make a reviewer think "AI-generated" or "junior" and stop reading. Treat this as a disqualifier checklist: if any appears, fix it before calling work done.

## Documentation tells

- **Emoji-bullet soup** — every bullet led by a decorative emoji; rocket ships and sparkles. Use prose and plain tables.
- **Superlatives without numbers** — "blazing fast", "highly accurate", "comprehensive", "enterprise-grade", "robust", "seamless", "powerful". Each is a flag. Replace with a measured value or delete.
- **Invented benchmarks** — a comparison table with checkmarks and no reproducible evidence. Worse than no table.
- **Dominance tables** — CredScan wins every row. Real tools concede ground. A table without a conceded row is marketing.
- **The em-dash-and-"real" register** — the generic AI cadence. Vary sentence structure; prefer concrete nouns.
- **Marketing verbs** — "revolutionize", "supercharge", "unleash", "cutting-edge", "next-generation". Banned.
- **Restating the obvious** — "This README explains the project." Cut.
- **A wall of 45 flags in `--help`** — group them, suppress power-user tunables, add examples + exit codes. (Already done; keep it that way.)

## Domain mistakes (the expert cringe)

- **Over-broad regexes** — `[A-Za-z0-9/+]{40}`, bare `[a-f0-9]{32}`, `password\s*=\s*.+`. These flood false positives and tell an expert you don't understand precision. Anchor on provider prefixes or require assignment context + plausibility.
- **Entropy as high-confidence on its own** — high entropy ≠ secret (hashes, UUIDs, minified JS). Entropy is a *contributing* factor, never a verdict.
- **Claiming "active"/"valid" without verifying** — a key in old history may be rotated. Only "verified" via a provider call earns "active".
- **One global entropy threshold** — base64, hex, and JWT have different entropy profiles. Per-type thresholds or it's naive.
- **Ignoring git history** — secrets persist post-deletion. A scanner that only sees the working tree is incomplete (CredScan has history scanning — keep it prominent).
- **Auto-verifying without consent / state-changing verification** — verification must be opt-in, read-only, rate-limited. A scanner that fires live API calls by default, or hits non-identity endpoints, is dangerous and disqualifying.
- **The scanner leaks** — printing raw secrets to console/logs, unescaped HTML reports, raw values in baseline files. The tool becomes the vulnerability.
- **Detector count theater** — "500+ patterns!" where 480 are near-duplicates. Quality and precision per detector matter, not the count.

## "Science project" / scope-confusion tells

- **Format/feature theater** — "supports 47 output formats", "real-time monitoring" bolted onto a batch scanner, "blockchain"/buzzword box-checking. Breadth as a substitute for depth.
- **"ML-powered" with no model** — claiming machine learning with no model artifact, no training data, no eval. CredScan's transparent confidence scoring is a *deliberate, defensible* alternative — say that, don't fake ML.
- **Wrong exit codes** — exits 0 when secrets are found. Breaks every CI gate; an instant "they never used this in anger" tell. (CredScan: 0 clean / 1 found / 2 error — keep it.)
- **High-friction setup** — a 12-step manual install for a tool meant to run on every commit. Friction kills adoption.

## Git-awareness tells (the expert checks these)

- **Parsing `.git/objects` by hand** instead of using `git` commands / a library — fragile and reinvents the wheel.
- **Whole-file rescans on every commit** instead of diffing — naive and slow; pre-commit must scan the delta.
- **No binary-blob handling in diffs** — `git diff` emits binary noise; flagging entropy in it floods FPs.
- **Missing submodules** — scanning a repo without considering submodules silently misses nested code.

## Engineering tells

- **No tests, or tests that are `print()` debugging** — assertions or it doesn't count.
- **Committed `__pycache__`/`.DS_Store`/reports** — signals carelessness. (`.gitignore` handles this; keep it clean.)
- **Secrets in the repo that aren't clearly fixtures** — demo credentials must be obviously synthetic and isolated; document that they're fake. (GitHub push protection will catch real-looking ones.)
- **A monolith `cli.py` doing everything** — keep the plugin parser/analyzer architecture clean; the GUI calls the engine, doesn't reimplement it.
- **Rewriting instead of reusing** — the GUI/API must wrap the existing engine, not fork detection logic.

## The redemption move

When you catch one of these, don't just remove it — replace it with the evidenced version. "Comprehensive AWS detection" → "detects 6 AWS credential formats; benchmark precision 0.94 on the bundled corpus." The fix is always: *make the claim smaller and true.*
