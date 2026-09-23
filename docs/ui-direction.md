# UI direction — making it sleek

R&D notes on the current interface: what's already good, what's inconsistent,
and a concrete direction. "Sleek" here means *dense, consistent, and quiet* —
hierarchy from type and spacing, colour used for meaning, and a few
high-craft surfaces — not decoration.

## What's already good

- **A real token layer.** `index.css` defines the shadcn/Tailwind v4 theme in
  `oklab` greys, and `chrome.css` adds control tokens (`--selection`,
  `--control-h`, `--chrome-h`, `--radius-control`, `--space-1/2/3`) with
  matching class names in `lib/chrome.ts`. This is the right foundation.
- **Density.** 13px body, compact 6px scrollbars, `scrollbar-gutter: stable`,
  a monospace stack — it already reads as a tool, not a web page.
- **Restraint.** No gradients, no drop shadows on content, one card colour.

## What's inconsistent (measured)

| axis | finding |
| --- | --- |
| font size | `text-[11px]` ×58 vs `text-xs` (12px) ×50, plus 10px ×16, `text-sm` ×12, and one-offs at 9/10.5/8/13px — two near-equal primaries |
| colour | ~25 hardcoded palette colours (`text-sky-600 dark:text-sky-400`, `emerald`, `fuchsia`, `cyan`, `amber`, `violet`, `orange`…) with no token; no single place to retune |
| radius | `rounded` ×17, `rounded-md` ×13, `rounded-lg` ×4, `rounded-sm`/`none` — three radii in play |
| spacing | ad-hoc `px-1.5/2/3`, `py-px/0.5/1`, `leading-[17px]` alongside the `--space-*` tokens |
| panes | every pane hand-rolls its own header (`PaneHeader`, `Section`, ad-hoc bars) |
| accent | the palette is pure grey — `--primary` is a grey used for selection *and* addresses *and* links, so nothing signals "interactive" |

## Direction

### 1. A type scale, and numbers that line up
Define the scale once and stop reaching for arbitrary sizes:

```css
--text-2xs: 10px;  /* uppercase pane labels, badges */
--text-xs:  11px;  /* dense rows: disasm, stack, registers, lists */
--text-sm:  12px;  /* controls, tab labels, body copy */
--text-base:13px;  /* prose: agent chat, docs */
```

Use `text-xs`/`text-sm` via Tailwind; reserve a single `--text-mono` for the
disasm/hex. Add `.nums { font-variant-numeric: tabular-nums }` and apply it to
**every** column of numbers — addresses, sizes, offsets, registers, entropy,
counts — so digits align instead of jittering.

One `.label` utility for the uppercase micro-heading (10px, `tracking`,
muted) instead of repeating the same four classes in every pane.

### 2. Colour = meaning, tokenised
The asm palette is the interface's most-seen colour and it's hardcoded in ~25
places. Give it semantic tokens:

```css
--asm-addr --asm-bytes --asm-mnemonic --asm-register --asm-number
--asm-string --asm-symbol --asm-jump
```

Then retune **once**, and desaturate ~15–20%: Tailwind's 400s are loud for a
screen of hex. A refined RE palette is closer to slate-blue addresses, dim
green bytes, soft violet mnemonics, teal registers, amber numbers, warm
strings, grey symbols.

Also split the overloaded grey: `--selection` (quiet selected fill, already
exists), `--accent-hue` (focus ring / links / active tab — one desaturated
hue so the UI isn't monochrome), and keep `--primary` for emphasis text.

### 3. One `Pane` primitive
A single component — title (label · count · actions), body, optional scroll —
used by every docked surface (functions, disasm, strings, imports, recon
cards, debugger panes, chat). Today each reimplements it. This is the cheapest
large consistency win.

Pair it with shared **empty** (`<Empty>` with a muted glyph + hint) and
**loading** (skeleton rows, not a centred spinner) states.

### 4. A status bar
A 22px bottom strip — arch · bits · backend · functions · selected address ·
debug state. Cheap, high-signal, and it's the single most "IDE" thing we're
missing.

### 5. Resizable, collapsible panes
The shell is a fixed `260px 1fr 340px` grid. Drag handles + collapse + persisted
widths (localStorage) make it feel like a real workspace. Pairs with a
**command palette** (Ctrl+K): open binary, goto address/symbol, switch tab,
run/step/break, switch backend — we already have every store for it.

### 6. The hero surfaces

**Disassembly / CPU view** — fixed columns with faint guides so
address/bytes/text align; a soft full-width current-line bar with a left
accent (not a hard `bg-primary/25` block); clickable `0x…` and `[rip+X]`
operands; a breakpoint gutter with a right-click menu (enable/disable,
condition, log); kind-coloured `→ 0x…` jump links.

**Graph** — a left accent per block kind (entry/exit/loop); edge labels as
pills; dim non-neighbour edges on hover; mini-map on large graphs; a "centre
on PC" action while debugging; highlight the current block.

**Debugger** — toolbar on the chrome tokens (`ui-bar`/`ui-seg`/`ui-sep`);
registers grouped GP / segment / flags / FPU with **changed-since-last-stop
highlighted**; the missing **memory/hex pane**; stack values followable.

**Agent chat** — send button only when there's input; a streaming caret;
tool-call cards with a left border by tool kind; collapse long tool output
behind "expand"; provider config behind a gear.

### 7. Motion, restrained
120–150 ms `ease-out` for hovers, ~180 ms for panel reveal/collapse, a 1px
focus ring. `tw-animate-css` is already imported. Animate only: tab underline,
panel collapse, the PC highlight, toasts. No bounce.

### 8. Polish details
`::selection` styled to `--selection`; visible `focus-visible` rings
throughout; thumb only on scrollbar hover; toasts for copy/save/errors instead
of inline bars; a copy affordance with micro-feedback on addresses and hashes.

## Sequencing

**Tier 1 (a day, most of the payoff)** — type-scale + tabular-nums tokens;
tokenise the asm palette; the `Pane` primitive; the status bar; one shared row
height so columns align across panes.

**Tier 2** — resizable/collapsible panes; command palette; debugger toolbar on
chrome tokens; register change-highlight; empty/loading states.

**Tier 3** — memory pane; graph polish; theming (Graphite default + one accent
palette); a motion pass.

Tier 1 is mostly mechanical and touches few files: `index.css`, `chrome.css`,
`lib/chrome.ts`, and a new `components/Pane.tsx` plus the panes that adopt it.
