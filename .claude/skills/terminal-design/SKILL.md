---
name: terminal-design
description: Design and build websites and web apps using an authentic Terminal / CLI design system — monospace typography, near-black backgrounds, prompt-style headers (`user@host $ cmd`), `//` comment labels, bracket notation `[status]`, flat sharp-edged progress bars, ASCII separators, and purposeful micro-animations (cursor blink, type-in). Use this skill whenever the user asks to design, build, create, or style anything in a "terminal style", "CLI aesthetic", "hacker UI", "terminal website", "command-line interface", "dev tool look", or says things like "make it look like a terminal", "terminal design", "hacker aesthetic", "CLI-style app", "developer dashboard", or "terminal app/website/component". Always use this skill — do NOT attempt terminal design from memory alone.
---

# Terminal Design Skill

Build interfaces that look like a real developer tool or CLI — not a "hacker movie" cliché. The goal is something a real designer would craft: dense, purposeful, precise.

> **CredScan note:** `DESIGN.md` (next to this file) is the canonical design guide for the CredScan GUI. The GUI in `src/credscan/gui/static/` follows it and the original mockup (`Design/CredScan.html`): left-sidebar app shell, colored severity cards, dense grid, the palette and tokens below. When building or changing the GUI, match that mockup's layout — but never fabricate data to fill a mockup panel (no invented detector-coverage %, no fake scan-history). Build only panels backed by real data; replace the rest with honest equivalents.

---

## Step 0 — Ask the User (Before Writing Any Code)

Ask these two questions upfront. Keep it conversational. If the user says "default" or doesn't know, proceed immediately with the defaults below.

**Q1 — Accent color:**
> "What accent color? Default is **neon green** `#00FF14`. Other options: amber `#F59E0B`, cyan `#06B6D4`, purple `#A855F7`, red `#EF4444`, or give me a hex."

**Q2 — Flavor:**
> "Any vibe preference? Default is **clean dev tool**. Options: retro CRT (scanlines + phosphor glow), data terminal (pure data density, no decoration), minimal mono (near-silent, maximum whitespace for a terminal), hacker dark (high contrast, aggressive)."

Do not ask more than these two questions.

---

## Color Palette

```css
:root {
  /* Backgrounds */
  --bg:           #0A0A0A;   /* page background */
  --bg-surface:   #111111;   /* cards, panels */
  --bg-raised:    #1A1A1A;   /* hover states, elevated rows */

  /* Borders */
  --border:       #2A2A2A;   /* default dividers */
  --border-bright:#3D3D3D;   /* active / hover borders */

  /* Text */
  --text-primary: #E0E0E0;   /* main content */
  --text-muted:   #5C5C5C;   /* comments, labels, timestamps */
  --text-dim:     #333333;   /* very subtle / disabled */

  /* Accent — swap for user's choice */
  --accent:       #00FF14;
  --accent-dim:   rgba(0, 255, 20, 0.08);

  /* Semantic */
  --warn:         #F59E0B;   /* partial, in-progress */
  --error:        #EF4444;   /* errors, critical */
}
```

**Flavor overrides:**
- **Retro CRT** — add `--phosphor-glow: 0 0 8px var(--accent)`; text-shadow on accent elements
- **Data terminal** — reduce `--text-primary` to `#BBBBBB`; tighten all padding by 25%
- **Minimal mono** — use `--accent: #F5F5F5`; reduce accents to near-zero; lots of negative space
- **Hacker dark** — `--accent: #00FF14`; increase all accent uses; `--bg: #000000`

---

## Typography

```css
font-family: 'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
```
Load from Google Fonts: `family=JetBrains+Mono:wght@400;700`

**Scale:**
| Token        | Size | Line-height | Use                        |
|-------------|------|-------------|----------------------------|
| `--text-xs`  | 11px | 1.4         | timestamps, tiny meta      |
| `--text-sm`  | 13px | 1.5         | comments, secondary labels |
| `--text-base`| 15px | 1.6         | body, list items           |
| `--text-lg`  | 18px | 1.5         | section headers            |
| `--text-xl`  | 22px | 1.4         | page title                 |
| `--text-2xl` | 32px | 1.2         | hero stats, big numbers    |

**Weights:** 400 and 700 only. No medium.  
**Letter spacing:** `0.05em` on ALL-CAPS labels; `-0.01em` on body; `0em` default.

---

## Core UI Patterns

### 1. Prompt Header
```
user@hostname $ command-name
// subtitle or description here
```
- `user@hostname` → `var(--text-muted)`, font-size sm
- `$` → `var(--accent)`, bold
- `command-name` → `var(--text-primary)`, bold
- `// subtitle` → `var(--text-muted)`, font-size sm, on next line

### 2. Section Headers
```
● section-name                              [metadata]
// description of this section
```
- `●` or `>` in `var(--accent)`
- `section-name` bold `var(--text-primary)`
- `[metadata]` right-aligned `var(--text-muted)`
- `// description` below in `var(--text-muted)` font-size sm

### 3. Bracket Notation
Use for statuses, counts, filters, and checkboxes:
```
[ ] unchecked item          [✓] completed item
[active]  [30d]  [all]      [3/5]  [v2.1.0]
```
- Inactive: `var(--text-muted)`
- Active bracket: `var(--accent)` bold
- Completed checkmark: `var(--accent)`

### 4. Progress Bars
```css
.progress-track {
  height: 8px;
  background: var(--bg-raised);
  border: 1px solid var(--border);
  border-radius: 0; /* always zero */
}
.progress-fill {
  height: 100%;
  background: var(--accent);
  transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1);
}
/* warn state */
.progress-fill.warn { background: var(--warn); }
```

### 5. Data Rows
```
days tracked     62            [good]
avg completion   68%           ↑14%
current streak   0 days
```
- Use CSS grid: `grid-template-columns: 1fr auto auto` for perfect alignment
- Keys: `var(--text-muted)` — Values: `var(--text-primary)` bold
- Status/delta: color-coded inline

### 6. ASCII-Style Separators
```css
.divider      { border-top: 1px solid var(--border); margin: 16px 0; }
.divider-dash { border-top: 1px dashed var(--border-bright); }
/* For section breaks — dashes as text: */
/* ─────────────────────────────────── */
```

### 7. Panels / Cards
```css
.panel {
  background: var(--bg-surface);
  border: 1px solid var(--border);
  border-radius: 0;
  padding: 16px 20px;
}
.panel:hover { border-color: var(--border-bright); }
```

### 8. Buttons
```css
/* Primary */
.btn-primary {
  background: var(--accent); color: var(--bg);
  font-family: monospace; font-weight: 700; font-size: 11px;
  border: none; border-radius: 0;
  padding: 8px 16px; text-transform: uppercase; letter-spacing: 0.08em;
  cursor: pointer;
}
.btn-primary:hover { filter: brightness(1.15); }

/* Ghost */
.btn-ghost {
  background: transparent; color: var(--accent);
  border: 1px solid var(--accent); border-radius: 0;
  font-family: monospace; font-size: 11px;
  padding: 7px 15px; text-transform: uppercase; letter-spacing: 0.08em;
}
.btn-ghost:hover { background: var(--accent-dim); }
```

### 9. Inputs
```css
input, textarea, select {
  background: var(--bg); color: var(--text-primary);
  border: 1px solid var(--border); border-radius: 0;
  font-family: monospace; font-size: 14px;
  padding: 8px 12px; outline: none;
}
input:focus { border-color: var(--accent); box-shadow: 0 0 0 2px var(--accent-dim); }
input::placeholder { color: var(--text-dim); }
```

### 10. Contribution Grid (GitHub-style)
Small squares (`10px × 10px`, `2px gap`) colored by intensity:
```
--grid-0: #1A1A1A   --grid-1: #003D05
--grid-2: #006B09   --grid-3: #00A60D   --grid-4: var(--accent)
```

### 11. Tree Visualization
Use ASCII connectors with inline progress bars for hierarchies:
```
Root ──── at 2025-06-24 14:06:24 ──────────────── /
├── / paths    ████████████████████████████████
├── / boughs   ██████
│   ├── / rays ████████████████
│   └── / canes ................................
```
Solid fill `█` for dense data; dotted `·` or `░` for sparse.

---

## Icons

**Use Lucide icons exclusively** (SVG, stroke-based).
- Inline size: `16px` — Standalone: `20px` — Stroke width: `1.5`
- Color: `currentColor` — inherit from parent
- Never use emoji as UI elements

---

## Micro-Animations

Include all of these. They make it feel like a live system, not a static mockup.

```css
/* 1. Blinking cursor — use on active prompt or hero */
@keyframes blink { 0%,49%{opacity:1} 50%,100%{opacity:0} }
.cursor::after {
  content: '▋'; color: var(--accent);
  animation: blink 1s step-end infinite;
}

/* 2. Type-in effect — on page load for main prompt */
@keyframes typing { from{width:0} to{width:100%} }
.type-in {
  overflow: hidden; white-space: nowrap;
  animation: typing 0.5s steps(40) forwards;
}

/* 3. Scanlines overlay — retro CRT flavor only */
.scanlines::after {
  content:''; position:fixed; inset:0; pointer-events:none; z-index:9999;
  background: repeating-linear-gradient(
    0deg, transparent, transparent 2px,
    rgba(0,0,0,0.04) 2px, rgba(0,0,0,0.04) 4px
  );
}

/* 4. Fade-up on mount */
@keyframes fadeUp { from{opacity:0;transform:translateY(6px)} to{opacity:1;transform:none} }
.fade-up { animation: fadeUp 0.25s ease forwards; }

/* 5. Progress fill animation */
@keyframes fillBar { from{width:0} }
.progress-fill { animation: fillBar 0.8s cubic-bezier(0.4,0,0.2,1) forwards; }

/* 6. Phosphor glow — retro CRT flavor only */
.glow { text-shadow: 0 0 8px var(--accent), 0 0 20px var(--accent-dim); }
```

Stagger fade-up by index for lists: `animation-delay: calc(var(--i) * 0.04s)`

---

## Layout Rules

- **Max content width:** `880px` centered
- **Side gutters:** `24px` mobile, `48px` desktop  
- **Spacing unit:** 8px base — use multiples: 8, 16, 24, 32, 48
- **Single column** primary — use 2-column only for side-by-side stats panels
- **Dense by default** — terminals don't waste space

---

## Anti-Patterns — Never Do These

| ❌ Don't | ✅ Do Instead |
|---------|--------------|
| Any border-radius | `border-radius: 0` everywhere |
| Box shadows | Border color changes on hover |
| Background gradients | Flat `var(--bg)` or `var(--bg-surface)` |
| Emoji as icons | Lucide SVG icons |
| Sans-serif fonts | Monospace only |
| Airy generous padding | Dense — pack data meaningfully |
| Decorative color use | Color only carries meaning (green=good, amber=partial, red=error) |
| Rounded buttons | Square, uppercase, letter-spaced |
| Centered hero gradient section | Prompt-style header on left |
| More than 3 accent colors at once | 1 accent + warn + error max |

---

## What Makes This Feel Real (Not AI Slop)

1. **Prompt hierarchy** — every major section is a command output. `user@host $ cmd` is sacred.
2. **Column alignment** — monospace means equal char widths. Use CSS grid to lock columns.
3. **`//` comments everywhere** — every section has a subtitle in comment syntax.
4. **Bracket status notation** — `[3/5]`, `[active]`, `[v1.2]` sprinkled throughout.
5. **Timestamps and metadata** — show `10:34`, `62 days`, `↑14%` — makes it feel like a live system.
6. **Terse microcopy** — "no data" not "No data available yet". "err" not "An error occurred".
7. **Cursor somewhere** — blinking `▋` on the hero or active input. Non-negotiable.
8. **Meaningful color** — a green value means something is good. Don't use green decoratively.
9. **Data density** — if it looks like it could be a React marketing page, add more data.
10. **ASCII texture** — use `─`, `│`, `├`, `└`, `·`, `█`, `░` for dividers, trees, progress.

---

## Quick-Start CSS Reset

```css
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap');
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
:root {
  --bg:#0A0A0A; --bg-surface:#111111; --bg-raised:#1A1A1A;
  --border:#2A2A2A; --border-bright:#3D3D3D;
  --text-primary:#E0E0E0; --text-muted:#5C5C5C; --text-dim:#333333;
  --accent:#00FF14; --accent-dim:rgba(0,255,20,0.08);
  --warn:#F59E0B; --error:#EF4444;
}
body {
  background: var(--bg); color: var(--text-primary);
  font-family: 'JetBrains Mono', monospace; font-size: 15px; line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
```

---

## Build Checklist

Before delivering, verify:
- [ ] All `border-radius: 0`
- [ ] Monospace font everywhere
- [ ] Blinking cursor or type-in animation present
- [ ] `//` comment syntax used for section subtitles
- [ ] Bracket notation `[ ]` / `[✓]` / `[status]` used where appropriate
- [ ] Icons are Lucide SVGs, not emoji
- [ ] Only 1 accent color + semantic warn/error
- [ ] Progress bars have `border-radius: 0`
- [ ] Layout is dense — not airy
- [ ] At least `fadeUp` animation on list/section mount
