# CredScan — Logo Design Brief

A brief to hand to a designer (or an AI image/vector tool) for a CredScan logo.
It captures what the product is, the visual system it must live inside, and
concrete direction so the result is coherent with the existing terminal UI.

---

## 1. What CredScan is (so the mark means something)

CredScan is an open-source **credential / secret scanner** for developers and
cloud-security engineers. It finds hardcoded secrets (API keys, tokens, private
keys, passwords) across source code, Infrastructure-as-Code, CI/CD pipelines,
Docker images, and git history — and can verify which keys are actually live.

One-line positioning: **"finds the secrets that incumbents miss, and proves
which ones are live."**

The audience is technical: engineers who live in terminals, read SARIF, and run
this in CI. The mark must read as a serious developer security tool, not a
consumer app or a generic "shield + checkmark" security cliché.

---

## 2. Brand personality

- **Precise, not flashy** — instrument, not mascot. Think `htop`, `ripgrep`,
  Vault, 1Password's developer side — utilitarian and exact.
- **Terminal-native** — monospace, sharp edges, command-line heritage.
- **Trustworthy** — it handles the most sensitive data in a repo. Calm and
  solid, never alarmist.
- **Cloud-native** — modern infrastructure, not legacy enterprise.

Three adjectives to hit: **precise, technical, trustworthy.**
Three to avoid: **cute, corporate-generic, alarmist.**

---

## 3. Visual system it must fit (non-negotiable constraints)

The existing GUI uses a strict terminal design system. The logo has to live
beside it without clashing.

- **Background**: near-black `#0A0A0A`. The logo must work on a dark
  background first (and remain legible on white for README/light contexts).
- **Primary accent**: terminal green `#00FF14`. This is the signature color.
- **Supporting neutrals**: off-white `#E0E0E0` (primary text), muted grey
  `#5C5C5C`.
- **Semantic colors** (use sparingly, only if meaningful): amber `#F59E0B`,
  red `#EF4444`.
- **Typeface**: JetBrains Mono (weights 400 / 700). Any wordmark should be
  monospace; JetBrains Mono is the house font.
- **Geometry**: **zero border-radius** — sharp corners everywhere. No rounded
  shapes, no soft edges. This is a hard rule in the design system.
- **No gradients, no drop shadows, no 3D, no bevels.** Flat only. Depth is
  communicated by border and background, never by shadow.
- **No emoji, no photographic elements.** All "art" is geometric or ASCII.

---

## 4. Concept directions (pick or blend)

Offer 2-3 routes; these are the strongest given the product and constraints.

### Direction A — The bracket prompt (recommended)
A monospace wordmark `credscan` preceded by a terminal prompt glyph. Options
for the glyph: a blinking-cursor block `▋`, a `$`, or `>`. The signature detail:
render it as a command, e.g. `$ credscan` or `> credscan_`, with the cursor in
green. The icon-only mark is the prompt glyph in a sharp-cornered square tile
(green on near-black).
- **Why:** it directly encodes the CLI identity and matches the GUI's prompt
  headers. Most authentic to what the tool is.

### Direction B — The redacted secret
A wordmark where part of a "secret" is masked, echoing how CredScan reports
values (`AKIA••••MPLE`). For example the icon is a short monospace string with
the middle glyphs replaced by solid blocks `▮▮`, in green. Conveys "we find and
mask secrets" in one glyph.
- **Why:** unique to a *secrets* tool specifically — not reusable by any
  generic security product. Strong differentiation.

### Direction C — The scan line
A monogram `C` or `cs` built from a scanning motif: a horizontal scan line
crossing a block of monospace characters, one character highlighted green (the
"found" secret). Subtle nod to detection.
- **Why:** evokes scanning without the literal magnifying glass.

**Avoid:** padlocks, shields, keyholes, magnifying glasses, fingerprints,
checkmark-in-circle. These are the security-logo clichés that read as generic.

---

## 5. Deliverables to request

- **Primary logo** (icon + wordmark, horizontal lockup) for the README header.
- **Icon-only mark** (square), for favicons, GitHub social preview, avatars.
  Must be legible at 16x16 and 32x32 (favicon sizes).
- **Monochrome variants**: all-green, all-white, all-black (for stamping on any
  background and for single-color contexts like a CI badge).
- **Light-background variant** (the green may need a darker outline or a
  near-black wordmark on white to keep contrast).
- Formats: **SVG** (primary, vector), plus exported PNG at 16/32/180/512 px.

---

## 6. Concrete specs

- **Color on dark**: green `#00FF14` mark on `#0A0A0A`. Keep the green for the
  accent element (cursor / highlighted char / `$`), and use `#E0E0E0` for the
  wordmark body so the green stays a deliberate highlight, not a flood.
- **Color on light**: wordmark in `#0A0A0A`; keep one green accent element.
- **Clear space**: at least the width of one monospace character around the
  lockup.
- **Minimum size**: icon legible at 16px; wordmark legible at ~80px wide.
- **Corners**: 0px radius on any container/tile.
- **Font**: JetBrains Mono, weight 700 for the wordmark.

---

## 7. One-paragraph prompt (for an AI vector/image tool)

> A minimalist logo for "CredScan", an open-source developer secret-scanning
> tool. Flat vector, terminal/CLI aesthetic. Monospace wordmark "credscan" in
> JetBrains Mono bold, near-white `#E0E0E0`, preceded by a terminal prompt:
> a solid green `#00FF14` cursor block or `$`. Sharp corners, zero border
> radius. Near-black `#0A0A0A` background. No gradients, no shadows, no 3D, no
> padlock/shield/magnifying-glass clichés. Also provide a square icon-only
> version: the green prompt glyph in a sharp-cornered tile, legible at 16px.
> Calm, precise, technical — an instrument, not a mascot.

---

## 8. What "done" looks like

- Reads as a developer security tool in under 2 seconds, with no security
  cliché.
- Sits beside the existing terminal GUI (same green, same monospace, sharp
  corners) without looking bolted on.
- The icon is recognizable at favicon size.
- Works in one color for badges and stamps.
