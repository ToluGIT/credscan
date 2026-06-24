# CredScan Roadmap — Best-of-Best, Phased

Ordered by **credibility ROI**: each phase makes the project more defensible to an expert and more striking to a recruiter. Do phases roughly in order — later phases assume earlier ones. Every item has a *why it matters* and an *acceptance test*. Nothing here deviates from "functional credential scanner."

Legend: **P0** = credibility floor (do first) … **P5** = distribution & polish.

## Phase gate: Codex review between every phase (mandatory)

A phase is not "done" until it has passed an independent Codex review. After completing the items in a phase and before starting the next one:

1. Run the phase's acceptance tests yourself; capture the evidence (benchmark numbers, test output, generated artifacts).
2. Hand the phase's diff and evidence to Codex (via the `codex:codex-rescue` subagent) with a skeptical-staff-engineer brief: confirm the acceptance criteria are truly met, find correctness bugs, find domain mistakes, and flag anything that reads as AI-generic or overclaimed.
3. Triage Codex's findings: fix the real ones; for anything dismissed, write one line on why. Re-run acceptance tests.
4. Only then mark the phase complete and move on. Record the review outcome (what was found, what was fixed) so the trail is auditable.

This gate is non-negotiable: it is how the project stays honest between phases instead of accumulating unverified claims. The cost of a review is far less than a reviewer finding the bug in your portfolio.

---

## P0 #0 — Portfolio-Ready Floor (the verifiable gate)

Before any new feature, an expert must be able to verify these in under 5 minutes **without reading code**. This is the testable contract between the skill and the tool's real state. If any item fails, it is the next thing to fix — nothing downstream is "portfolio-ready" until they pass.

1. `pip install -e . && credscan --path demo/` → real findings, **exit code 1**.
2. `python benchmarks/run.py` → prints `Precision / Recall / F1` on a committed corpus, with corpus size stated.
3. `SECURITY.md` exists → contains the tool threat-model table.
4. A generated `*.sarif` → validates against the SARIF 2.1.0 schema, carries CWE-798 tags and `partialFingerprints`.
5. README comparison table concedes ≥1 row to a competitor.

Track each as DONE/NOT-DONE honestly. The gap between this list and reality *is* the current work queue.

## P0 — Credibility floor (you cannot skip these)

These are the things whose *absence* gets a project dismissed in 30 seconds.

1. **Labeled benchmark corpus + `benchmarks/run.py`**
   - *Why:* turns every accuracy claim from marketing into evidence. The single highest-leverage addition. No serious security tool ships without a measured F1.
   - *Accept:* `python benchmarks/run.py` prints TP/FP/FN, precision, recall, F1 on a committed corpus; documented composition.

2. **Coverage number + CI gate**
   - *Why:* "tests exist" is table stakes; a visible coverage % and green matrix CI signals maintenance.
   - *Accept:* CI prints coverage; badge in README reflects it; build red on failure.

3. **`SECURITY.md` with the tool threat model**
   - *Why:* a secrets tool documenting how it avoids being the leak is a top-tier seniority signal; almost no hobby project does this.
   - *Accept:* the threat-model table from `quality-bar.md` is published; masking/escaping claims each have a test.

4. **Honest README top-fold + comparison table with conceded rows**
   - *Why:* recruiter-legible value in 30s; expert-credible on deep read.
   - *Accept:* headline metric is real (from #1); table concedes speed to gitleaks and verification breadth to TruffleHog; no superlatives.

---

## P1 — Signal quality (the core craft)

5. **Detector precision pass** — audit every pattern for over-breadth (the `[A-Za-z0-9/+]{40}` class), add anchors/assignment context, expand true/false-negative fixtures.
   - *Why:* precision is *the* reason scanners get uninstalled; this is the domain craft on display.
   - *Accept:* benchmark precision improves or holds with recall steady; each detector has TP+TN fixtures.

6. **Verification breadth for cloud providers** — extend the AWS validator pattern to GCP (tokeninfo), GitHub (`/user`), Slack (`auth.test`), Stripe (read-only `/v1/account`). All opt-in, read-only, rate-limited.
   - *Why:* verified-secret precision (~100%) is the field's most persuasive metric and TruffleHog's moat; matching it *in CredScan's lane* is a direct credibility claim.
   - *Accept:* `--verify` reports ACTIVE/INVALID/UNVERIFIED per provider; verified-rate metric printed; ethics constraints enforced and tested.

7. **Remediation map** — each finding type carries rotate/revoke + secrets-manager guidance.
   - *Why:* product thinking, not just detection; cheap to add, disproportionately impressive.
   - *Accept:* every detector maps to a remediation note shown in output and reports.

7b. **Exposure-window + rotation reasoning** — for history findings, compute and show how long a secret was exposed (first-seen commit timestamp → now or deletion) and state plainly that deletion ≠ remediation (rotate + rewrite history). For verified-live keys, link the provider's revoke path.
   - *Why:* a principal scopes blast radius, not just presence. "Public for 14 months across N commits" is what an incident responder needs.
   - *Accept:* history findings include first-seen commit, author, timestamp, and exposure duration; remediation text distinguishes rotate-vs-delete.

7c. **False-positive feedback signal** — track baseline growth and surface which detectors generate the most suppressed findings, so precision work targets the worst offenders.
   - *Why:* a rising FP rate is the leading indicator of a tool about to be uninstalled; measuring it is senior behavior.
   - *Accept:* a `--fp-report` (or benchmark output) ranks detectors by suppression count; baseline stores fingerprints, not raw values.

---

## P2 — Integration surface (where engineers actually use it)

8. **SARIF 2.1.0 correctness** — proper `rules`, `partialFingerprints` (stable dedup across runs), `region` line/col, CWE-798 tags, severity mapping. Validate against schema.
   - *Why:* loads into GitHub code scanning / VS Code; getting SARIF *right* is a competence signal most miss.
   - *Accept:* output validates against the SARIF schema; renders in GitHub's Security tab in a demo.

9. **Official GitHub Action** (`action.yml`) + documented usage.
   - *Why:* "drop this in your pipeline" is the adoption path; shows you think about the user's workflow.
   - *Accept:* a sample workflow in another repo runs CredScan and uploads SARIF.

10. **Docker image + pre-commit hook polish** — published image (runs as a non-root user); `.pre-commit-hooks.yaml` so others can `repo:` it.
    - *Why:* meets users where they are; pre-commit ecosystem reach. Non-root is the detail an expert checks.
    - *Accept:* `docker run … credscan` works as a non-root user; pre-commit consumers can reference the repo.

10b. **Compliance mapping output (concrete, not name-drops)** — map detector → control IDs (CWE-798, NIST 800-53 IA-5, PCI-DSS 6.3.x) and emit a compliance-oriented report (CSV/columns with control + finding + remediation).
    - *Why:* name-dropping standards without an output that uses them is a tell. A real control-mapped report shows you understand the enterprise buyer, not just the bytes.
    - *Accept:* a report variant lists each finding against its mapped control(s); the mapping table is documented.

---

## P3 — Performance & scale (measured)

11. **Throughput benchmark + tuning** — time against a fixed mid-size repo; remove any remaining redundant traversal/IO; report files/sec.
    - *Why:* "fast enough for every commit" must be a number, framed honestly against Go tools.
    - *Accept:* `benchmarks/` reports throughput with hardware noted; no double-traversal.

12. **Incremental / diff-only mode** — scan only changed lines in a commit/diff, not whole files; apply baseline per content-fingerprint so renamed files don't re-alert; handle binary blobs in diffs gracefully.
    - *Why:* makes per-commit scanning instant; whole-file rescanning on every commit is the naive approach an expert spots immediately.
    - *Accept:* `--staged`/diff mode scans only the delta; measured speedup shown; a renamed file with an unchanged known-FP secret does not re-alert.

12b. **Performance targets (not just measurement)** — define and defend acceptable latency: pre-commit/diff scan should feel instant (target order: low seconds); a full mid-size repo scan should be tolerable enough that nobody disables it.
    - *Why:* "if the scan takes too long, the developer turns it off" is the real threat model for adoption. A target, stated and measured, shows you understand that.
    - *Accept:* `benchmarks/` reports diff-mode and full-scan wall-clock against fixed corpora with targets stated and hardware noted.

---

## P4 — GUI (Part 2: the visible wow)

13. **Web GUI to drive scans and explore findings** — see `references/roadmap.md` GUI section below.
    - *Why:* a live, interactive demo is the recruiter buzzer; turns a CLI into something a non-engineer can grasp instantly.
    - *Accept:* a user can launch a scan (path/upload), watch progress, and explore findings with severity/confidence filtering, masked values, and the confidence-score breakdown visualized.

---

## P5 — Distribution & narrative

14. **PyPI release + CHANGELOG + ADRs** — semver, Keep-a-Changelog, 2–3 ADRs for non-obvious calls.
15. **Demo asset** — an asciinema/GIF (CLI) and a short screen capture (GUI) embedded in README.
16. **A short "how detection works" deep-dive doc** — the four-layer pipeline with a worked example (one secret, scored step by step). Teaches the reader you understand the problem.

---

## GUI design brief (P4 detail)

**Goal:** a self-hostable web UI that makes CredScan's *differentiators visible* — confidence scoring, verification status, cloud-native source coverage — not a generic table.

**Architecture (recommended):**
- **Backend:** thin FastAPI layer wrapping the existing engine (reuse, don't rewrite). Endpoints: start scan, stream progress (SSE/websocket), fetch findings (filter/sort), fetch one finding's confidence breakdown. CredScan stays the source of truth; the API is a façade.
- **Frontend:** a single-page app (React or Svelte). Keep it buildless-simple if possible for portfolio review (one `npm run build`, static output the FastAPI serves).
- **Why not Streamlit/Gradio:** fine for a 1-hour demo, but they read as "data-science notebook," not "security product." A real SPA + API signals product engineering. (If time-boxed hard, Streamlit is an acceptable MVP — state the trade-off.)

**The screens that matter:**
1. **Scan launcher** — pick a path / upload a file or zip / paste a snippet; toggle verification; start.
2. **Live results** — findings stream in; severity + confidence badges; masked values; filter by severity/type/confidence; group by file or by detector.
3. **Finding detail** — the confidence-score breakdown *visualized* (the four factors as a stacked bar), the masked value, file/line, remediation guidance, and verification status if applicable. This screen is the differentiator made tangible.
4. **Summary / posture** — counts by severity, by source type (IaC vs CI/CD vs code), verified-live count. A small dashboard, not a SIEM.

**Self-security in the GUI:** the same masking/escaping rules apply — the GUI must never render an unescaped value or expose a raw secret in a URL/log. The GUI is part of the threat model.

**Acceptance:** a non-CLI user scans the bundled `demo/`, sees findings appear live, filters to critical+verified, opens one, and understands *why* it scored as it did — all without reading the docs.
