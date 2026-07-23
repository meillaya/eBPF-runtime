# PANOPTES — kernel-v1 Sentinel Console design system

Design contract for the kernel-v1 eBPF runtime-security dashboard. Every
color, font size, spacing value, and motion duration in `src/` traces to a
token defined here. Direction comes from the project brief: a dark
security-operations-center (SOC) surface, monospace for data/IDs, sans-serif
for UI text, severity-coded telemetry, dense tables over cards.

The console opens on a live telemetry board — identity strip, sensor LEDs,
counters, event stream — never on a marketing hero.

## 1. Identity

- **Product wordmark**: `KERNEL-V1` (display face) + `SENTINEL CONSOLE`
  (micro caption). SVG mark: hexagonal kernel ring with a scan sweep.
- **Posture**: instrument panel, not website. Dense, calm, precise. The
  surface is quiet until telemetry says otherwise; severity is the loudest
  thing on screen.

## 2. Color tokens

Layered deep blue-graphite (never pure black), multiple functional hues —
severity provides the warm ladder, phosphor-green and cyan carry
interactive/live meaning.

| Token | Value | Role |
|---|---|---|
| `--bg-void` | `#06090f` | page void behind panels |
| `--bg-canvas` | `#0a101b` | content canvas |
| `--bg-panel` | `#0f1725` | panel surface |
| `--bg-raised` | `#152033` | raised controls, hover rows |
| `--bg-inset` | `#0b1220` | wells, code blocks, table header |
| `--line-faint` | `#1b2740` | panel hairlines |
| `--line-strong` | `#2b3c5f` | active borders, focus-adjacent |
| `--text-primary` | `#e9eff8` | body text (≈15:1 on canvas) |
| `--text-secondary` | `#a3b3cb` | secondary text (≈7.5:1) |
| `--text-muted` | `#7b8dab` | labels, metadata (≈5:1, AA small) |
| `--accent-live` | `#3fe0a0` | live/healthy, primary action (≈11:1) |
| `--accent-live-ink` | `#04120c` | text on live accent |
| `--accent-info` | `#59c2ff` | links, focus ring, info (≈8:1) |
| `--sev-critical` | `#ff5468` | critical (text ≥4.6:1 on panel) |
| `--sev-high` | `#ff8f42` | high |
| `--sev-medium` | `#ffc94d` | medium |
| `--sev-low` | `#5aa7ff` | low |
| `--sev-info` | `#8fa0b8` | info/neutral |
| `--state-degraded` | `#ffc94d` | degraded/stale (amber) |
| `--state-offline` | `#ff5468` | offline/error (red) |
| `--overlay` | `rgba(6,9,15,0.74)` | modal scrim (void at 74%) |

Each severity also emits `--sev-<n>-bg` (12–14% alpha wash) and
`--sev-<n>-line` (35% alpha) for badges and row tinting. No other hex value
may appear in `src/`.

## 3. Typography

Three families, loaded from Google Fonts with full system fallback stacks
(the console must remain functional offline; fallbacks are visually close).

| Token | Family | Use |
|---|---|---|
| `--font-display` | Chakra Petch 500/600/700 | wordmark, view titles, nav, big counters |
| `--font-body` | IBM Plex Sans 400/500/600 | UI text, buttons, alerts |
| `--font-mono` | JetBrains Mono 400/500/700 | tables, IDs, timestamps, digests, code |

Scale (strong contrast between console chrome and dense data):

| Token | Size/line | Weight | Use |
|---|---|---|---|
| `--text-display` | 30px/36px | 700 display, uppercase, +0.01em | view titles |
| `--text-heading` | 13px/18px | 600 body, uppercase, +0.10em | panel headers |
| `--text-body` | 13.5px/20px | 400 | default UI text |
| `--text-caption` | 11px/16px | 500, uppercase, +0.08em | labels, table heads |
| `--text-data` | 12.5px/18px | 400 mono | table cells |
| `--text-data-lg` | 22px/28px | 500 mono | headline counters |
| `--text-micro` | 10px/14px | 500, uppercase, +0.12em | LEDs, chips, timestamps |

## 4. Space, radius, elevation

- 4px grid: `--space-1 … --space-12` = 4/8/12/16/20/24/32/40/56/72px.
- Radius: `--radius-sm` 2px (controls), `--radius-md` 4px (panels),
  `--radius-full` (LED dots only). Angular on purpose — no rounded-2xl.
- Elevation = hairline border + 1px inset top highlight
  (`inset 0 1px 0 rgba(233,239,248,0.04)`); glow (`0 0 0 1px <line>, 0 0
  18px <hue> 12%`) reserved for live/focus/error emphasis. No drop shadows.

## 5. Ambient surface

Canvas is layered, pure CSS, GPU-cheap: base color + 32px blueprint grid
(two repeating-linear-gradients at 2.5% white) + radial cyan tint top-left
and deep-blue well bottom-right + a slow 14s horizontal scan-sheen across
the topbar only. `prefers-reduced-motion` freezes the sheen and LED pulse.

## 6. Motion

| Token | Value | Use |
|---|---|---|
| `--dur-fast` | 120ms | hover, press |
| `--dur-base` | 180ms | color/border transitions |
| `--dur-slow` | 320ms | panel/row reveals |
| `--ease-out` | cubic-bezier(0.22, 0.9, 0.28, 1) | everything |

Every animation maps to meaning: LIVE LED pulse (stream health), row
insertion slide-fade with 40ms stagger (new telemetry arriving), counter
tick (value change), hover tint (affordance), focus ring (keyboard
position). Transform/opacity only. No decorative motion.

## 7. Primitives (src/ui/)

- **Button** — variants `primary` (live-green solid, dark ink), `secondary`
  (outline), `ghost`, `danger`; sizes `sm|md`; optional loading spinner;
  disabled dims to 45%; focus-visible 2px `--accent-info` ring, 2px offset.
- **Badge** — `severity` (critical/high/medium/low/info: tint wash bg,
  severity-line border, severity text, leading dot), `status` (live
  pulsing / degraded / offline / idle), plus `badge--live` (accent-live
  wash, for ESTABLISHED/SUCCESS/paired states) and `badge--muted`
  (inset bg + faint line, for terminal-neutral states like CLOSED).
  Mono micro text.
- **Card (Panel)** — bordered panel with a console-strip header: caption
  title left, meta/actions right; body padding `--space-4`.
- **Table** — dense 34px rows, mono data cells, sticky caption-styled
  header, hover row tint, `aria-sort`, roving-tabindex rows with
  Enter/Space activation, `aria-rowcount` when paginated.
- **Alert** — info/warning/critical banner, `role=alert` (critical) or
  `role=status`, icon + title + detail + optional action, dismissible.
- **Spinner** — SVG arc, `role=status` + `aria-label`, sizes 14/18/28.
- **EmptyState** — dashed-border well, SVG glyph, title, hint, action slot.
- **ErrorBoundary** — class boundary; fallback panel with retry button and
  a mono detail block (message + component stack), never raw dumps inline.
- **SocketStateBadge** — connection lifecycle phase (ATTEMPT / EINPROGRESS /
  ESTABLISHED / REFUSED / FAILED / TCP-state names). Tone ladder: attempts
  info-blue, established live-green, draining states (FIN_WAIT/TIME_WAIT/
  CLOSE_WAIT) amber, refusals/failures critical-red, CLOSED muted. Always
  dot + word.
- **LatencyHistogram** — log-decade bars (count-proportional, `--accent-info`
  fill, buckets at/above p99 tinted `--sev-high`) with count + wall-time sum
  as text per row; a log axis carries p50/p95/p99/p99.9 markers in
  live/medium/high/critical. Bars are `aria-hidden`; all numbers are text.
- **EventToolbar** — feed controls strip: Live/Historical segmented toggle
  (`aria-pressed`), window select (historical-only), cluster select
  (live-only; disabled states carry a `title` explaining why).
- **ProcessCell** — process attribution (tgid/pid strong mono + uid) with an
  always-rendered validity chip: `validity--ok` (live wash), `validity--bad`
  (amber, lists invalid fields), `validity--na` (muted) when the wire
  carried no valids.
- **ProcessTree** (`components/ProcessTree.tsx` + `ProcessNode.tsx`, styled
  by `ui-tree.css`) — ARIA `tree` of flat `treeitem` rows (CSS indent
  guides, no canvas/SVG). Identity cell is always `PID n` + `G<m>`
  generation badge (`badge--info`; `badge--high` + row tint
  `--sev-high-bg` when PID reuse is observed) — PID alone is never shown.
  State dots: running = `--accent-live` pulsing, exited = `--state-idle`,
  thread = `--accent-info` with a dotted guide. A dashed
  `--sev-medium-line` guide marks a missing parent edge ("ANCESTRY
  INCOMPLETE" chip — ancestry is never invented). Full exec path reveals
  as an inset tooltip strip on hover/focus (`--dur-base` opacity).
  Keyboard: ↑/↓ traverse, → expand/enter, ← collapse/parent, Enter/Space
  toggle, Home/End, Escape collapse-all; roving tabindex, `aria-level`,
  `aria-setsize/posinset`, `aria-expanded`. Chevron rotates 90° in
  `--dur-fast`; fresh rows use the `row-in` animation.
- **Segmented control** (`.seg`) — inset-well mode switch (Live /
  Historical); pressed segment tints `--accent-info-dim` with a 2px
  `--accent-info` underline bar.
- **Exec timeline** — dense 30px rows (wall or mono-short timestamp,
  basename with full-path title, `pid·G<m>` in `--accent-info`, OK/ERRNO
  badge); newest first, bounded scroll.
- **Agent inventory surfaces** — fleet summary counters (reuse
  `.counter-row`), node compatibility matrix (`.kv` + ACTIVE/INACTIVE
  capability badges), sensor-coverage list (reuse `.sensor-list`), and
  health LEDs whose word is always rendered (healthy/degraded/blocked/
  offline — never color alone).
- **SeverityBadge** (`components/SeverityBadge.tsx`) — the severity
  ladder extended with an INFO level for neutral telemetry and action
  chips (ALERT = info, DENY = critical). Same dot + word contract as
  Badge; an optional `label` override keeps the tone while renaming the
  word.
- **ConfirmDialog** (`components/ConfirmDialog.tsx`) — mutation gate.
  `--overlay` scrim (void at 74%, new token), `role=dialog` +
  `aria-modal`, focus trap with Cancel as the safe default focus,
  Escape/overlay dismiss, focus restore on close. Always renders the
  audit intent grid (actor / action / resource / recorded-at, mirroring
  control-plane `AuditRecord`) before the confirm button; danger tone
  gets the `--glow-error` shadow. Entry animation is transform/opacity
  over `--dur-slow`.
- **Toggle switch** (`.switch`, `role=switch`) — 34×18 track, knob
  slides 16px in `--dur-base`; checked = `--accent-live-dim` track +
  live knob, unchecked = inset track + muted knob; state word always
  rendered beside it (ACTIVE/DRAFT).
- **DropCounter** (`components/DropCounter.tsx`) — per-source loss
  card: mono counters (reserve fail / discard / commit / attempt), a
  pure-SVG loss-per-poll sparkline (`--accent-info`, escalating to
  `--sev-high`/`--sev-critical` when loss/saturation heats up, dashed
  `--line-strong` baseline), a ring-saturation meter (fill escalates
  live → medium → high → critical at 35/60/85%), and a sequence-gap
  strip (one 5×12 cell per poll, red where gaps arrived).
- **RolloutProgress + LifecycleStepper** — segmented progress bar
  (applied live-green / ready info / rejected critical / disconnected
  high, remainder = staged) with a per-agent dot grid: staged = raised
  outline, ready = `--accent-info`, applied = `--accent-live`, rejected
  = `--sev-critical`, disconnected = hollow `--sev-medium` ring.
  Rejected and disconnected dots are always rendered, never folded into
  the healthy mass; the legend gives every tone a word. The stepper is
  a four-step rail (STAGE → READY → COMMIT → APPLIED) — done steps fill
  live-green, the current step pulses (`led-pulse`), REJECTED marks the
  final step critical.
- **Explanation tree** (`.explain-tree`) — the rule engine's
  `Explanation{field, operator, value, matched, children}` rendered as
  an indented tree (`--line-faint` left guides): HIT marks in
  `--accent-live`, MISS muted, composite AND/OR/NOT nodes strong.
  Unparseable explanations fall back to pre-wrapped plain text — the
  tree is never invented.
- **YAML preview** (`.yaml-block`) — read-only rule body rendering
  (inset well, mono, scroll-capped at 340px). The console never offers
  an editable rule surface; openapi v1 has no rule-write endpoint.

## 8. First-class view states

Every data view renders exactly one of, in precedence order:

1. **error** — no data at all → ErrorPanel (message, status chip, Retry).
2. **loading** — no data yet → skeleton rows + spinner, `aria-busy`.
3. **empty** — data arrived, zero rows → EmptyState with next action.
4. **degraded** — data exists but stale/partial (query failed after a
   success, or stream dropped) → amber banner over the live-last data with
   reconnect countdown.
5. **live/ready** — normal render.

## 9. Accessibility constraints (non-negotiable)

- WCAG 2.1 AA contrast for every text token on its intended surface.
- Skip-to-content link; landmark roles (`banner`, `nav`, `main`);
  `aria-current="page"` on nav; connection indicator is `role=status`
  with text, not color alone (LED + word: LIVE / RECONNECTING / OFFLINE).
- Severity is never color-alone: badges always carry the severity word.
- Full keyboard operation: visible focus ring everywhere, roving tabindex
  in tables, Enter/Space activation, Escape to dismiss.
- `prefers-reduced-motion` disables pulse, stagger, and sheen.

## 10. Accepted debt

- ID-token signature verification (JWKS + WebCrypto) is delegated to the
  control plane; the browser shell validates `iss/aud/nonce/exp` claims only.
- Fonts are CDN-loaded with system fallbacks; vendoring woff2 is deferred
  to keep the repository binary-light.
- No virtualized table yet; pages are capped at the API's 1000-row limit.
- Process identity on the dashboard wire is `(pid, task_start_time)` per
  node; boot_id scoping arrives when the batch envelope (`boot_id_hex`,
  `agent_generation`) is surfaced on the REST/stream contract. The `G<m>`
  generation badge is the ordinal of that identity among all identities
  seen for the same PID inside the observation window.
- Remote-agent health is derived from heartbeat staleness
  (<90s healthy, <300s degraded, else offline) until a fleet-wide health
  API exists; only the local agent (matched by `agent_id` against
  `/health`) reports true sensor blocked/degraded state and event rate.
