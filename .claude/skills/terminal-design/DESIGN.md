# Design Guidelines — Terminal / CLI UI

## Visual Style
- **Aesthetic**: Dark terminal / CLI — near-black backgrounds, monospace everything, data-dense layouts
- **Mood**: Precise, live, purposeful — feels like a running system, not a static page
- **Inspiration**: init.Habits app, GitHub contribution graph, `htop`, `btop`, classic Unix man pages, code diffs

---

## Color Palette

- **Background**: `#0A0A0A` — page background, deepest layer
- **Surface / Panel**: `#111111` — cards, sections, panels
- **Raised**: `#1A1A1A` — hover states, elevated rows, nested panels
- **Border (default)**: `#2A2A2A` — all dividers, panel outlines, input borders
- **Border (active)**: `#3D3D3D` — hover/focus borders, highlighted rows
- **Text Primary**: `#E0E0E0` — main content, values, headings
- **Text Muted**: `#5C5C5C` — comments (`// ...`), labels, timestamps, secondary meta
- **Text Dim**: `#333333` — disabled, placeholder, very subtle content
- **Accent (default)**: `#00FF14` — active states, checkmarks, progress fills, prompt `$`, CTAs
- **Accent Dim**: `rgba(0, 255, 20, 0.08)` — focus rings, tinted backgrounds
- **Warning**: `#F59E0B` — partial completion, in-progress, degraded states
- **Error**: `#EF4444` — failures, critical values, destructive actions
- **Grid Level 0**: `#1A1A1A` — empty contribution squares
- **Grid Level 1–3**: `#003D05` → `#006B09` → `#00A60D` — low to mid activity
- **Grid Level 4**: `#00FF14` — peak activity (same as accent)

**Accent swap options** (user-configurable):
| Name    | Hex       |
|---------|-----------|
| Green   | `#00FF14` |
| Amber   | `#F59E0B` |
| Cyan    | `#06B6D4` |
| Purple  | `#A855F7` |
| Red     | `#EF4444` |
| White   | `#F5F5F5` |

---

## Typography

- **Primary Font**: JetBrains Mono — or Fira Code, Cascadia Code, Courier New as fallback
- **Rule**: Monospace only — no sans-serif or serif anywhere, ever
- **Weights**: 400 (regular) and 700 (bold) only — no medium or light

| Token         | Size | Line Height | Usage                            |
|--------------|------|-------------|----------------------------------|
| `text-xs`    | 11px | 1.4         | Timestamps, tiny meta, grid labels |
| `text-sm`    | 13px | 1.5         | Comments (`// ...`), secondary labels |
| `text-base`  | 15px | 1.6         | Body text, list items, data rows  |
| `text-lg`    | 18px | 1.5         | Section headers                  |
| `text-xl`    | 22px | 1.4         | Page title / command name        |
| `text-2xl`   | 32px | 1.2         | Hero stats, big numbers          |

- **Letter spacing**: `0.05em` on ALL-CAPS labels; `-0.01em` on body; `0em` default
- **Load via**: `https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700`

---

## Spacing & Layout

- **Base unit**: 8px — all spacing in multiples: 8, 16, 24, 32, 48
- **Max content width**: 880px centered
- **Side gutters**: 24px mobile / 48px desktop
- **Overall feel**: Dense — terminals don't waste vertical space. If it looks airy, add more data.
- **Column structure**: Single-column primary. 2-column only for side-by-side stats panels.
- **Section separation**: 1px `--border` divider line, or 16px gap — not both

---

## Borders & Radius

- **Border radius**: `0px` — everywhere, no exceptions (not even 2px)
- **Default border**: `1px solid #2A2A2A`
- **Active/hover border**: `1px solid #3D3D3D`
- **Focus border**: `1px solid var(--accent)` + `box-shadow: 0 0 0 2px rgba(0,255,20,0.08)`
- **Dashed separator variant**: `1px dashed #3D3D3D` — used for tree connectors, subtle dividers

---

## Shadows & Elevation

- **No box shadows** — ever. Elevation is communicated through border color and background lightness only.
- Hover: change `border-color` from `#2A2A2A` → `#3D3D3D`
- Active panel: change `background` from `#111111` → `#1A1A1A`

---

## Buttons

- **Primary**: `background: #00FF14`, `color: #0A0A0A`, bold, 11px, uppercase, `letter-spacing: 0.08em`, `border-radius: 0`, `padding: 8px 16px`
- **Ghost**: `background: transparent`, `color: #00FF14`, `border: 1px solid #00FF14`, same type treatment
- **Hover (primary)**: `filter: brightness(1.15)`
- **Hover (ghost)**: `background: rgba(0,255,20,0.08)`
- **Disabled**: `color: #333333`, `border-color: #2A2A2A`, no pointer

---

## Icons

- **Library**: Lucide — stroke-based SVG icons only
- **Size**: 16px inline / 20px standalone
- **Stroke width**: 1.5px
- **Color**: `currentColor` — inherits from parent
- **No emoji** as icons or decorative elements — ever

---

## Components

### Prompt Header
```
user@hostname $ command-name
// subtitle or description
```
- `user@hostname` → muted, sm — `$` → accent, bold — `command-name` → primary, bold
- `// subtitle` → muted, sm, on the line below

### Section Header
```
● section-name                        [metadata]
// description of this section
```
- `●` or `>` in accent — `section-name` bold primary — `[metadata]` right-aligned muted

### Bracket Notation
```
[ ] unchecked    [✓] done    [active]    [30d]    [3/5]    [v2.1.0]
```
- Inactive: muted — Active: accent bold — Checked `✓`: accent

### Progress Bar
- Track: `height: 8px`, `background: #1A1A1A`, `border: 1px solid #2A2A2A`, `border-radius: 0`
- Fill: accent color (or `--warn` for partial) — no radius — animate width on mount
- Dotted/dithered variant: use `░` or `·` characters for low-density ASCII progress

### Data Row
```
label                value             [status]
// sub-label         secondary-value
```
- CSS grid: `grid-template-columns: 1fr auto auto` for column alignment
- Key: muted — Value: primary bold — Status/delta: color-coded

### Contribution Grid
- 10×10px squares, 2px gap, colored by intensity level (4 levels + empty)
- Label months and days of week in `text-xs` muted above/beside grid

### Tree Visualization
```
Root ──── 2025-06-24 14:06 ─────────────── /
├── / paths   ████████████████████████
├── / nodes   ░░░░░░░░░░░░░░░░..........
└── / rays    ██████████
```
- Use `─`, `│`, `├──`, `└──` for connectors — `█` solid, `░` dithered, `·` sparse

### Panel / Card
- `background: #111111`, `border: 1px solid #2A2A2A`, `border-radius: 0`, `padding: 16px 20px`
- Hover: `border-color: #3D3D3D`

### Input / Textarea
- `background: #0A0A0A`, `border: 1px solid #2A2A2A`, `border-radius: 0`, `font-family: monospace`
- Focus: `border-color: accent`, `box-shadow: 0 0 0 2px accent-dim`
- Placeholder: `#333333`

### Separator
- Solid: `border-top: 1px solid #2A2A2A`
- Dashed: `border-top: 1px dashed #3D3D3D`
- ASCII text: `───────────────────────────────`

---

## Micro-Animations

| Name | Trigger | Description |
|------|---------|-------------|
| `blink` | Always on cursor | `▋` after active prompt, 1s step-end infinite |
| `typing` | Page load | Prompt text types in — `steps(40)`, 0.5s |
| `fadeUp` | Mount | Elements fade in + translate up 6px, 0.25s — stagger lists with `--i` delay |
| `fillBar` | Mount | Progress fills from 0 to target width, 0.8s ease |
| `scanlines` | CRT flavor only | Fixed overlay, repeating 4px horizontal gradient at ~4% opacity |
| `glow` | CRT / hacker flavor | `text-shadow: 0 0 8px accent, 0 0 20px accent-dim` on accent text |

---

## Imagery & Illustration

- No photography, no illustrations, no decorative imagery
- Data visualizations only: contribution grids, progress bars, tree charts, sparklines
- All "art" is ASCII or SVG — characters and geometry only

---

## Replication Notes

Key things to nail this style:

- **Monospace rhythm is sacred** — every character is the same width. Use CSS grid to align columns precisely; never rely on flex to "eyeball" it.
- **`//` comment syntax everywhere** — every section, every subtitle. It's the voice of the UI.
- **Color carries meaning, never decoration** — green = active/good, amber = partial/warning, red = error. Don't use accent color for aesthetics.
- **Zero border radius — no exceptions** — even 2px feels wrong. Sharp edges only.
- **A blinking cursor must exist somewhere** — on the hero prompt or the active input. It signals "live system."
- **Terse microcopy** — "no data" not "No data available yet". "err" not "An error occurred".
- **Density over airiness** — if it feels like a SaaS marketing page, it's too spacious. Pack it.
- **Timestamps and metadata everywhere** — `10:34`, `62 days`, `↑14%`, `v2.1.0`. Makes it feel real.
- **1 accent color max** — plus `--warn` and `--error` for semantic use only.
- **No shadows, ever** — if you need elevation, change background darkness and border brightness.
