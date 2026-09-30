# UI smoothness audit — `recurse/tauri`

Status: audit complete. **Tiers 1–5 implemented and verified** (tsc clean, 381/381
frontend tests, 68/68 agent tests, prettier clean, lint at its pre-existing
baseline, `vite build` green).

Verification commands used:

```
cd tauri
npx tsc --noEmit            # clean
npx vitest run              # 24 files, 381 tests passed
npm run lint                # 1 error, 0 warnings -- all pre-existing
npx prettier --check ...    # clean
npm run build               # green
cargo test -p recurse-agent --lib   # 68 passed
```

The one remaining lint error (`CenterPanel.tsx` `setRawByteLimit` in an effect
keyed on `selectedAddr`) predates this work — confirmed by stashing the changes
and re-running lint on the clean tree, which reports the same single error. It is
a derive-state-from-prop pattern and is out of scope for these tiers.

Scope: all 60 source files under `tauri/src`, plus `package.json`, `vite.config.ts`,
`index.html`, and the Rust event pump that feeds the debug channel.

## The shape of the problem

```
$ rg "React\.memo" src            -> 0 hits
$ rg "useDeferredValue|startTransition" src -> 0 hits
$ rg "onScroll" src               -> 0 hits   (a genuine win, keep it)
$ rg "setInterval" src            -> 0 hits
$ rg "getComputedStyle|offsetWidth|clientWidth" src -> 0 hits
$ rg "react-virtual|useVirtualizer" src package.json -> no hits
$ rg "scroll-behavior" src        -> 0 hits
$ rg "prefers-reduced-motion" src -> 0 hits
```

There is not a single `React.memo` in the app, no virtualization, and no
transition or deferral primitive. The jank is entirely in the React layer.

## What is already right — preserve these

- **Zero `onScroll` / `onWheel` handlers.** No scroll-driven `setState` anywhere.
  Every scroll container uses native `overflow: auto`, which composites better
  than a JS-driven viewport. Do not "fix" this by adopting Radix `ScrollArea`.
- **No layout-property transitions exist.** Verified: `App.tsx:137-144`
  `grid-template-columns`, `stack-split.tsx:92` `flexBasis`, and
  `resizable-column.tsx:88`'s CSS variable are all written *untransitioned*. The
  sidebar resize relayouts but does not animate, which is correct.
- **Divider drags write to the DOM, not to state.** `resizable-column.tsx:86-91`
  and `stack-split.tsx:88-96` both `paint()` into a CSS variable / `flexBasis`
  rather than calling `setState` per `pointermove`, with explanatory comments
  saying why. `setPointerCapture` is used and released correctly in both, and
  both have window-level `pointerup` / `pointercancel` fallbacks.
- **Every store subscription passes a selector.** `rg "use[A-Z][A-Za-z]*Store\(\)"`
  returns zero hits. No whole-store subscriptions.
- **`scrollbar-gutter: stable`** (`index.css:157-159`) with 6px WebKit
  scrollbars, so the first overflow of a container does not shift content.
- **`body { overflow: hidden }` + `overscroll-behavior: none`** — no document
  scroll, no rubber-band fighting nested scrollers.
- **No `getComputedStyle`, `offsetWidth`, or `clientWidth` reads.** The layout
  reads that do exist are enumerated below.
- **ELK already runs in a real Worker** in `CallGraphPanel.tsx:72-75`.
- **Radix `Dialog` animates opacity only** (`ui/dialog.tsx:18,35`).
- **`React.StrictMode` is kept** and the code tolerates double-invoked effects.

---

## HIGH severity

### H1 — Unbounded debugger output writes, with a forced layout each

`store/debugStore.ts:444-447` (fed by `crates/recurse-debug/src/session.rs:100`
`push_output` -> `debug_events.rs:181` forwarder thread). The backend pushes one
IPC `Output` event per read-chunk from the debuggee's stdout. Each one calls
`setState` with a new `output` array, re-rendering the whole `DebugPanel` subtree
(`DebugCpu` + `BottomTabs` + `RegistersPane` + `StackBody`). Then
`DebugPanel.tsx:538-542` runs:

```tsx
outputRef.current.scrollTop = outputRef.current.scrollHeight;
```

— a forced synchronous layout **per chunk**. `lib/debugOutput.ts:71-77` also
re-scans the entire transcript to trim on every append. There is no interval to
blame; the channel is worse than an interval.

**Fix:** buffer pushes in a ref, flush via `requestAnimationFrame` (coalesce N
chunks into 1 render). In `debugOutput.ts`, keep a running `total` in a ref
instead of re-summing all chunks per append.

### H2 — Full transcript re-render per streamed token

`store/agentStore.ts:297-321`:

```ts
channel.onmessage = (ev) => {
  set((st) => { /* ... */
    const messages = updateLast(st.messages, (m) => applyEvent(m, ev));
  });
};
```

No batching, no rAF coalescing, no `startTransition`. `appendText`
(`agentStore.ts:158-169`) also does `last.text + text` per delta. `AgentChat`
subscribes to the resulting array (`:31`) and `.map`s it (`:184-222`) with no
memo, so on every token:

- every `ToolCallCard` re-runs `classifyToolCall` (a `JSON.parse`) and
  `getToolResultFacts` (another `JSON.parse`) — `ToolCallCard.tsx:247-252`;
- every `Markdown` block re-parses through micromark — `Markdown.tsx:96`;
- `AgentChat.tsx:63` forces a layout via `scrollHeight` **per token**.

**Fix:** coalesce deltas behind a rAF (append to a ref, commit at most once per
frame). `React.memo` the message components. `useMemo` the `view`/`facts` in
`ToolCallCard` on `[call.name, call.arguments, call.result]`.

### H3 — `localStorage.setItem` on every `pointermove`

`components/ui/stack-split.tsx:169-191`: `move()` calls `remember()`, and `move()`
is called from `onPointerMove` (`:225`). A 60Hz drag is 60 synchronous storage
writes per second.

**Fix:** split `move` into a paint path (DOM write, per move) and a remember
path (call once from `endDrag`).

### H4 — Un-virtualized, uncapped function list

`components/FunctionList.tsx:97-114, 146-244`. `ordered` sorts *all* funcs;
`filtered` re-filters with a `.toLowerCase()` allocation per item per keystroke;
then `filtered.map` renders every row. No cap, no windowing. A 50k-function
binary renders 50k rows.

**Fix:** add `@tanstack/react-virtual`. Short term: memo a lowercase search key
per function, and cap the rendered slice as `CenterPanel` already does for strings.

### H5 — Un-virtualized disassembly

`components/CenterPanel.tsx:914-947`: `asm?.ops?.map(op => <OpRow .../>)`. Every
instruction of the selected function, at once, no windowing.

**Fix:** virtualize over `asm.ops` with a fixed row height — `--row-h` already
exists in `chrome.css:42`.

### H6 — O(n^2) on function select

`components/CenterPanel.tsx:181-189`. Every `OpRow` instance runs its own
`useMemo` mapping the *entire* `insns` array into `frameOps`. M instructions
means M maps over M elements — M^2 object allocations before the first pixel.

**Fix:** hoist the mapping to a single `useMemo` in `CenterPanel` and pass the
array down as a prop.

### H7 — One store subscription per instruction row

`components/VarNameChip.tsx:38-39`, mounted once per row at
`CenterPanel.tsx:236-240`. Each chip subscribes to `s.variableNames`; renaming any
variable creates a new object (`analysisStore.ts:90-97`) and re-renders every
chip in the listing. Additionally `lib/debugVars.ts:238` (`frameSlot`) does
`new RegExp(...)` on every call, and `VarNameChip.tsx:42` runs `frameOf`
(4 regex tests x n instructions) per chip.

**Fix:** hoist `variableNames` and `frame` to a single parent read; pass a
resolved name map down. Move the two `frameSlot` regexes to module constants.

### H8 — Decompiler highlighter runs on every render

`components/CenterPanel.tsx:102-133, 1079-1083`. `highlight(decompiled,
annotations)` does `new Array<string>(code.length).fill("")` plus a per-character
fill loop over the entire decompiled source, on every `CenterPanel` render — which
is every App resize, every context selection change, every `publishSections`.

**Fix:** `useMemo(() => highlight(decompiled, decompiledAnnotations), [...])`.

### H9 — 4,096 controlled `<input>` elements

`components/HexPanel.tsx:65, 118-126, 191-243`. `api.readBytes(addr,
Math.min(len, 4096))` -> 256 rows x 16 inputs. Typing one hex nibble calls
`setEdits` with a new `Map`, re-reconciling all 4,096 inputs.

**Fix:** render the row as text and swap in a single `<input>` only for the byte
being edited. Also cap the default `len` (256 -> 4,096 is a 16x jump).

### H10 — Window resize re-renders the whole tree at 60Hz

`components/ui/resizable-column.tsx:121-137`. The `resize` listener calls
`apply()`, which calls `setWidth(fitted)`. `setWidth` lives inside `App`'s hook
scope (`App.tsx:41-42`), so every resize tick re-renders `App` and therefore
`MenuBar` (which calls `buildCommands()` fresh, `MenuBar.tsx:177-180`),
`Sidebar`, `CenterPanel`, and `AgentChat`.

**Fix:** `width` is only used for `aria-valuenow`. Write it to a ref and reflect
it into the divider's `aria-valuenow` imperatively, or debounce the `setWidth` to
pointer-up. Wrap `Sidebar`/`CenterPanel`/`AgentChat` in `React.memo`.

---

## 1. Re-render storms and unnecessary work

### 1.1 Store subscriptions

No whole-store subscriptions exist — every call site passes a selector. The
problem is **identity churn on large slices**:

| Location | Subscription | Why it churns |
|---|---|---|
| `AgentChat.tsx:31` | `s.messages` | New array on every token. See H2. |
| `DebugPanel.tsx:513` | `s.output` | New array on every stdout chunk. See H1. |
| `DebugCpu.tsx:60` | `s.disasm` | `mergeDisasm` (`lib/debugDisasm.ts:128-148`) returns a new `Map` (up to 20k entries) per decode. Bounded by step rate; acceptable. |
| `VarNameChip.tsx:38` | `s.variableNames` | One subscription per instruction row. See H7. |
| `FunctionList.tsx:43` | `s.funcs` | Identity changes on every background-index poll tick (`binaryStore.ts:50`). The `[...funcs].sort()` is memoized on `[funcs, entry]` so it re-sorts every 1.5s. MED. |
| `GraphPanel.tsx:309` | `s.funcs` | Feeds a `useEffect` dep. See 1.3. |
| `Sidebar.tsx:30-32` | `s.dataRegions.sections.length + ...` | Returns a number. Correct, no churn. |

### 1.2 `React.memo`

Zero uses. The panel tree `App` -> `ActivityBar`, `Sidebar` -> (`FunctionList`,
`DataRegionsPanel`), `CenterPanel`, `AgentChat` is entirely re-rendered by any
ancestor render.

Fresh object/array/function props created per render from parents:

- `CenterPanel.tsx:914-947` — `onSelect={(address) => ...}`, `target={callTarget(op, funcByAddr)}`, `func={selectedAddr}`. Adding `React.memo` alone will not help without also `useCallback`-ing `onSelect` and hoisting `onGoTo`.
- `CenterPanel.tsx:816-818` — `sourceFunction(xref)` is called *inside* the `.map` and does two O(n) `funcs.find` calls per row, so O(rows x funcs). MED.
- `GraphPanel.tsx:249` — `insns: (graph.blocks ?? []).flatMap(blk => blk.ops ?? [])` is recomputed **per node** inside `toGraph`'s `.map`, so the whole function's ops are flattened once per basic block. O(blocks x ops).
- `DataRegionsPanel.tsx:256-369` — `sectionsPane` / `segmentsPane` / `boundariesPane` JSX elements are rebuilt every render and handed to `StackSplit`. Every keystroke in a filter input rebuilds all three pane trees.
- `DebugPanel.tsx:232-244` — a `button()` closure factory invoked inline, creating new function identities per render.

### 1.3 `useEffect` dependency problems

`GraphPanel.tsx:311-339` is the notable one — `funcs` is a dep of a network
effect:

```tsx
useEffect(() => {
  // ...
  api.functionGraph(addr).then(g => {
    const { nodes: ns, edges: es } = toGraph(g, byAddr);
    setNodes(layout(ns, es));   // dagre.layout on the main thread
    setEdges(es);
  });
}, [addr, setNodes, setEdges, funcs]);   // <- funcs
```

`funcs` changes identity on every indexing poll tick and on every
`renameFunction` (`analysisStore.ts:124-128`). So the CFG is re-fetched over IPC,
re-built through `toGraph`, and re-laid out through dagre — while the analyst
types in a filter, once a second and a half.

**Fix:** drop `funcs` from the deps and read `useAnalysisStore.getState().funcs`
inside the effect, or key the refetch on `[addr]` and re-resolve targets in a
separate cheap effect.

Other effects are clean. `AgentChat.tsx:55-60` correctly uses a `prevBusy` ref
to detect the busy->idle edge instead of a second effect. `stack-split.tsx:129-151`
deliberately runs its measuring layout effect once per pane arrangement, with an
explicit eslint-disable and a comment.

Heavy sync work in effects:

- `DebugCpu.tsx:132-134` — `pcRow.current?.scrollIntoView({ block: "nearest" })` on `[anchor, rows.length, cursorAt]`. Forced layout, and it can scroll the window if the table is short. Correctly gated to "only when needed", but should be rAF-wrapped.
- `DebugCpu.tsx:141-148` — `funcNames` rebuilds a `Map` over all functions when `funcs` changes. Bounded by the index poll. MED.
- `DebugCpu.tsx:180-191` — `dataTargets` is `[...out]`, a new array identity each time `rows` changes, so the effect re-fires on every disasm merge. Saved by `ensureDataNames` early-returning (`debugStore.ts:777-778`). LOW.

### 1.4 Debugger poll design

There is **no `setInterval` anywhere** (`rg setInterval src` -> 0 hits; the only
timer is `binaryStore.ts:57` `setTimeout(resolve, 1500)` inside a `while` loop for
the index poll, plus one-shot `setTimeout(..., 0)` at `App.tsx:103` and
`commands.ts:131`). `DebugPanel.tsx:527-536` documents the design:

```
// One channel for the life of the view: the session pushes a view of itself
// at every stop and the debuggee's output as it is printed, so there is no
// interval here to tune...
```

That is architecturally right. The rate is whatever the debuggee prints, and the
frontend has no rate limiting. See H1.

One dead write, MED: `debugStore.ts:299-301, 554, 557` — `appendLog` does
`JSON.stringify(out)` on every debugger op into a capped `log` array that **no
component subscribes to** (`rg "s\.log" src/components src/App.tsx` -> no hits).
Pure waste. Delete `appendLog` and the `log` field.

---

## 2. Un-virtualized long lists

`@tanstack/react-virtual` is confirmed absent, and no `content-visibility` is
used anywhere. No windowing exists in the app.

| Component | Max simultaneous items | Virtualized? | Notes |
|---|---|---|---|
| `FunctionList.tsx:146-244` | all `funcs` (10k-50k) | no | See H4. |
| `CenterPanel.tsx:914-947` | all `asm.ops` | no | See H5. Per row: `DisasmInstr` tokenises with 5 regexes (`disasm.tsx:89-128`), `formatInstructionBytes` does replace + `match(/.{1,2}/g)` + join (`disasm.tsx:33-39`), plus a `VarNameChip`. |
| `CenterPanel.tsx:988-1006` | 2,000 (hard `CAP`, `:441`) | no | 3 `<td>`s per row; `title={s.string}` on every row. The comment at `:437-438` names the 113k-string youki case — the cap *was* the fix for a freeze. MED-HIGH. |
| `CenterPanel.tsx:1051-1061` | all `imports` | no | Same shape, uncapped. MED. |
| `CenterPanel.tsx:816-856` | all xrefs | no | `sourceFunction` = 2x O(funcs) per row. MED. |
| `DisasmBytes.tsx:147-174` | 16,384 bytes / 16 = 1,024 rows (`CenterPanel.tsx:47`) | no | 3 spans + a `.map().join()` per row. MED. |
| `HexPanel.tsx:191-243` | up to 4,096 `<input>`s | no | See H9. |
| `FindingsPanel.tsx:130-294` | `capabilities` / `classes` / `driver_ioctls` / `firmware` uncapped; only `dwarf_functions` is capped at 200 (`:269`) | no | capa on a large binary runs to hundreds. MED. |
| `R2Console.tsx:117-134` | 400 lines (`MAX_LINES`, `:13`) | no | Each `l.out` is `JSON.stringify(out, null, 1)` (`:55`) — one `aflj` on a big binary is megabytes in a single `<pre>`, 400 deep. MED. |
| `ToolCallCard.tsx` | one per tool call | no | Collapsed by default (`:283-287`), so the expensive `<pre>` bodies are not mounted. Good call. But `classifyToolCall`/`getToolResultFacts` still run per card per render. MED. |
| `CommandPalette.tsx:46-51` | 30 (`slice(0, 30)`) | capped | But the filter runs *first*: a full O(funcs) scan with a `.toLowerCase()` per item per keystroke. Should `break` at 30. MED. |
| `VariableList.tsx:143-178` | args + frame slots of one function | n/a | Bounded. Fine. |
| `DebugCpu.tsx:248-351` | <= 69 rows (`context + 1 + DISASM_AFTER`) | n/a | Bounded. Fine. |
| `DataRegionsPanel` | all sections/segments/boundaries | no | Usually tens-hundreds. LOW. |
| `ProjectScreen.tsx:118-162` | all projects | no | Typically < 20. LOW. |
| `ReconPanel.tsx:187-296` | ~30 fields | n/a | Fine. |

`lib/disasm.tsx` is only the tokenizer/colouriser (`tokenizeAsm`, `DisasmInstr`,
`DisasmComment`) — it renders one instruction. The *view* is
`CenterPanel.tsx:914-947`. `lib/disasmMenu.ts` is pure metadata and renders
nothing; `CenterPanel.tsx:549-596` re-runs `disasmMenuSections(...)` (allocating
~20 `MenuItem` objects) whenever any of its 15 deps change, which is acceptable.

---

## 3. Layout thrash and forced synchronous layout

Full inventory of layout-forcing reads:

| Location | Call | In a loop? | In a scroll handler? | rAF? | Verdict |
|---|---|---|---|---|---|
| `ui/resizable-column.tsx:151` | `grid.getBoundingClientRect()` | no | no | no | Forced reflow per pointermove. The read at 151 and the write at 88 alternate every event. MED-HIGH. |
| `ui/stack-split.tsx:218` | `box.getBoundingClientRect()` | no | no | no | Same. Plus `paint()` writes `el.style.flexBasis` and `remember()` hits localStorage. HIGH. |
| `ui/split.tsx:106` | `container.current.getBoundingClientRect()` | no | no | no | Same, but the component is dead code. |
| `ui/stack-split.tsx:120` | `frames().map(el => el.scrollHeight)` | yes, N=3 | no | in a `useLayoutEffect` | Acceptable — 3 forced reads pre-paint, correct hook. |
| `DebugPanel.tsx:540` | `outputRef.current.scrollHeight` | no | no | no | Forced layout per stdout chunk. HIGH. |
| `AgentChat.tsx:63` | `scrollRef.current.scrollHeight` | no | no | no | Forced layout per token. HIGH. |
| `CenterPanel.tsx:511` | `scrollRef.current?.scrollTo({ top: 0 })` | no | no | n/a | Correct — pre-paint, on a real state change. |
| `DebugCpu.tsx:133` | `pcRow.current?.scrollIntoView(...)` | no | no | no | Forced layout + possible window scroll per step. MED. |
| `ModelPicker.tsx:484-489` | `querySelector` + `scrollIntoView` | no | no | no | `querySelector` per arrow-key press. Dialog-only, bounded list. LOW. |
| `R2Console.tsx:40` | `endRef.current?.scrollIntoView(...)` | no | no | no | Per command; can scroll the window if the container is short. LOW. |

### Pointer-drag handlers

`resizable-column.tsx` — the drag path is correct and worth reading as the
reference implementation:

```tsx
// A drag writes the width to a CSS variable on the grid rather than through
// state: moving a divider is a layout change, and a re-render per pointer move
// would re-render the code listing and the chat sixty times a second to move a
// border. The value in state is committed once, on release...
const paint = useCallback((next) => {
  grid?.style.setProperty(variable, `${next}px`);
}, [grid, variable]);

const onPointerMove = useCallback((e) => {
  if (!dragging.current) return;
  const next = fromPointer(e.clientX);   // reads getBoundingClientRect
  if (next !== null) paint(next);        // writes a CSS var, no setState
}, [fromPointer, paint]);
```

`setPointerCapture` at `:173`, released at `:194-196`, window-level
`pointerup`/`pointercancel` guards at `:209-224`, handlers `useCallback`-stable
(with a comment at `:159-161` explaining the capture-rebinding hazard). The only
fix needed is to cache the grid rect at `onPointerDown`.

`stack-split.tsx` — also writes to elements, not state (`paint` at `:88-96`,
`flexBasis` at `:92`; `aria-valuenow` deliberately omitted with a comment at
`:294-301`). `setPointerCapture` at `:210`, release at `:241-243`, window guards
at `:249-257`. But it persists on every move (H3) and re-reads the rect per move.

`split.tsx` — the outlier: `setState` *and* `localStorage` per `pointermove`
(`:84-110`), and it animates `flexBasis` (a layout-triggering property) at
`:159`. It is **never imported**. Delete it.

### Auto-scroll during drag

The premise does not apply. `lib/dragSelect.ts` is 38 lines with no pointer
handlers, no loop, no interval, no rAF — it only adds/removes a body class
(`beginDragSuppressSelect`). The CSS counterpart is `chrome.css:203-213`
(`user-select: none; cursor: col-resize`). There is no auto-scroll-during-drag
feature in this codebase, and its two consumers call it correctly (begin on
pointerdown, end on pointerup *and* on the window-level fallback).

### The App grid

`App.tsx:137-144` writes the divider widths into `grid-template-columns`:

```tsx
gridTemplateColumns: chatOpen
  ? `var(--recurse-sidebar, ${SIDEBAR_DEFAULT}px) 4px minmax(0, 1fr) 4px var(--recurse-chat, ${CHAT_DEFAULT}px)`
  : `var(--recurse-sidebar, ${SIDEBAR_DEFAULT}px) 4px minmax(0, 1fr)`,
```

`grid-template-columns` is a layout property, so a drag relayouts the whole grid
per frame. That is inherent to a CSS-grid column resize and is the right choice
over JS-driven `flex-basis` here — it gets the `CENTRE_MIN` floor for free via
`minmax(0, 1fr)` and `fitColumn`'s `windowWidth - floor - reserved`
(`resizableColumn.ts:129-150`). No `transition` is set on it, which is correct.
The residual cost is the 60Hz forced read at `resizable-column.tsx:151`.

`lib/sidebarWidth.ts` and `lib/chatWidth.ts` are pure arithmetic with no DOM
reads. Clean.

---

## 4. Animation and CSS

```
$ rg "transition" src   -> chrome.css:177,259,594; ui/dialog.tsx:18,35;
                           ui/scroll-area.tsx:34; ui/button.tsx:8; ui/badge.tsx:7;
                           ui/dropdown-menu.tsx:42,92; ui/input.tsx:12;
                           ToolCallCard.tsx:117,139,271; NewProjectDialog.tsx:73,100,109;
                           ProjectScreen.tsx:124,142
$ rg "animate-" src     -> index.css:2 (the import) + 13x animate-spin + 1x animate-pulse
```

### `tw-animate-css` is imported but entirely unused — LOW

`index.css:2`. Its dist defines `--animate-in`/`--animate-out`, `fade-in`,
`zoom-in`, `slide-in-from-*`, `animate-accordion-*`, `animate-caret-blink`, and
~90 `@property` registrations. None are used. The only `animate-*` classes in the
codebase are `animate-spin` (13x) and `animate-pulse` (1x, `AgentChat.tsx:341`) —
both Tailwind v4 core utilities. Delete the import and the devDependency.

### What is animated

Compositor-only (good):

- `chrome.css:177` — `transition: background 120ms ease` on the 1px divider line. Paint-only, 1px element.
- `chrome.css:259-261` — `transition: color, background 120ms` on `.ui-window-button`. Paint-only.
- `chrome.css:594` — `transition: color 0.12s ease` on activity-bar buttons. Paint-only.
- `ui/dialog.tsx:18,35` — `transition-opacity duration-150`, opacity only, on overlay and content. Deliberate and correct.
- `ToolCallCard.tsx:139` — `transition-transform … ${expanded ? "rotate-180" : ""}`. Transform. Correctly chosen.
- `ProjectScreen.tsx:142` — `transition-opacity group-hover:opacity-100`. Opacity.

Paint-only (acceptable): `transition-colors` on `ui/button.tsx:8`,
`ui/badge.tsx:7`, `ui/input.tsx:12`, `ui/dropdown-menu.tsx:42,92`,
`ToolCallCard.tsx:117,271`, `NewProjectDialog.tsx:73,100,109`,
`ProjectScreen.tsx:124`. A hover repaint of a ~100x28px box. Not a real finding.

The one genuine offender, `ui/scroll-area.tsx:34` `transition-colors` on
`ScrollAreaScrollbar`, is moot — `ScrollArea` is never imported.

`ui/dropdown-menu.tsx:18-22` carries an explicit comment that there is
deliberately no open/close animation. Sensible for a menu bar.

### Missing smoothness affordances

- **`prefers-reduced-motion` is entirely absent.** The 13 `animate-spin` loaders
  and the `animate-pulse` thinking ellipsis (`AgentChat.tsx:341`) run for
  vestibular-sensitive users with no escape. LOW-MED.
  Fix: `@media (prefers-reduced-motion: reduce) { *, ::before, ::after {
  animation-duration: .01ms !important; animation-iteration-count: 1 !important;
  transition-duration: .01ms !important; } }`
- **No `content-visibility` anywhere.** For the long lists in section 2 this is
  the cheapest 80% win without adding a dependency: `content-visibility: auto;
  contain-intrinsic-size: 0 18px` on list rows would let the browser skip layout
  and paint for off-screen rows. MED.
- **No `will-change` anywhere** — and that is correct. Blanket `will-change` on
  scrolling lists costs memory and can hurt. The right fix for the spinners is to
  not have them spin during a fast operation.
- **No loading/pending affordance** in places where work is long and synchronous:
  `FunctionList` shows "analyzing..." only while `busy && filtered.length === 0`
  (`:139-143`); `DataRegionsPanel`/`Sidebar` have none; the command palette shows
  no busy state for `buildCommands()`. LOW.

### `index.css` and `chrome.css` notes

`index.css:88-90` sets `border-color: var(--border)` on every element via
`* { @apply border-border }`. Standard shadcn/Tailwind-v4 idiom; it means every
`hover:border-*` repaints through it. Not a real problem.

`index.css:140` re-declares `scrollbar-width`/`scrollbar-color` on a second
universal selector. Minor duplication, no perf impact.

`chrome.css:126-153` — `.data-row-2` uses a **container query**
(`@container (min-width: 460px)`) rather than a media query, so the sidebar's
two-line/one-line row flip responds to panel width, not window width. Correct
choice, but it means dragging the sidebar divider re-evaluates container queries
across the whole sidebar every frame. LOW, and the right design.

---

## 5. Heavy libraries and expensive work

### `@xyflow/react` — `GraphPanel.tsx` (per-function CFG): MED-HIGH

- `layout()` at `:281-302` builds a `dagre.graphlib.Graph` and calls
  `dagre.layout(g)` **inline** inside the `.then()` of `api.functionGraph(addr)`
  (`:325-327`). A 500-block CFG is a multi-hundred-ms main-thread block.
  Contrast `CallGraphPanel`, which correctly moves ELK into a Worker.
- Refetched on `funcs` change. See 1.3.
- **`onlyRenderVisibleElements` is MISSING** at `:356-375` (`CallGraphPanel.tsx:272`
  has it). A large CFG renders every node's full instruction list via
  `BlockNodeComponent` (`:145-201`), all mounted, all in the DOM.
- `fitView` re-runs on every address change with `key={addr}` (`:357, 363, 390`).
  Deliberate, documented at `:385-386`, and correct — remounting per function is
  the right way to reset.
- `BlockNodeComponent:114-123` memoizes a `frameOps` map of `data.insns` per node,
  and `data.insns` is itself `(graph.blocks ?? []).flatMap(...)` computed **per
  node** at `toGraph:249` — the whole function's ops flattened once per block.
- `blockWidth`/`addrColumns`/`bytesColumns` (`:81-112`) each iterate all ops, called
  from `toGraph` per node. O(ops) per node is fine for one-shot layout; it would
  be a problem if recomputed per render, which it is not.

### `@xyflow/react` — `CallGraphPanel.tsx` (whole-binary): mostly good

- `elkjs` runs in a real Worker (`:72-75`), `layout()` is async awaiting
  `elk.layout(graph)`, documented at `:77-80`. This is the right way to do it.
- `onlyRenderVisibleElements` present (`:272`).
- `graphNeedsTopView(nodes, edges)` (`:123-136`) runs on every render with four
  `Math.min/max(...nodes.map(...))` spreads, but is guarded by an early return at
  `:124` (`nodes.length > 300`), so it is safe from stack overflow. Still four
  array allocations per render; `useMemo` it.
- `useEffect(..., [flow, largeGraph, nodes])` at `:207-218` calls
  `flow.setCenter(..., { duration: 250 })`. `nodes` is a loose dep — if
  `onNodesChange` fires (node measurement after `fitView`), it re-centers. The rAF
  is cancelled properly, but the dep on the whole `nodes` array is broad.
- `MiniMap` (`:294-308`) re-renders on every viewport change. Gated behind
  `largeGraph`. Acceptable.

Neither panel thrashes `onNodesChange`/`onEdgesChange` — both use
`useNodesState`/`useEdgesState` with `nodesDraggable={false}` and
`nodesConnectable={false}`, so changes are dimension events, not drag spam.

### `react-markdown` + `remark-gfm` in `Markdown.tsx`

Not memoized; re-parses on every render. `components={components}` (`:29-91`) is
a module-level object, which is correct. But `remarkPlugins={[remarkGfm]}` (`:96`)
is a new array literal every render, which defeats remark's identity-keyed plugin
cache and makes micromark rebuild its pipeline. Called from `AgentChat.tsx:333`
for every content block, in a component that re-renders per token. See H2.

### xterm

**Neither `Console.tsx` nor `R2Console.tsx` uses xterm**, despite `@xterm/xterm`
and `@xterm/addon-fit` being dependencies. `R2Console` is a hand-rolled
`<div className="scroll-host … overflow-auto">` + `<pre>` transcript (`:106-136`)
with a `<textarea>` input and `endRef.current?.scrollIntoView({ block: "end" })`
in a `[lines]` effect (`:39-41`). `Console.tsx` is dead code. Drop both
dependencies. If a real terminal is added later, `fit()` belongs in a
`ResizeObserver` callback, never in a render body or an `onScroll` handler.

### lucide-react icons

`ToolCallCard.tsx:33-41` — `FAMILY_ICONS` is a module-level `Record` of components
(correct), but the element is created fresh per card per render. LOW.
`ActivityBar.tsx:60-81` — 10 icons, re-rendered on every `App` render, and
`VIEWS.filter()` allocates a new array each render. LOW.
`ModelPicker.tsx:625-679` — up to 2-3 icons per model row x the full catalog
(OpenRouter has thousands), un-virtualized. MED.
`FunctionList` and the disassembly rows use text only, no icons. Good.

### `JSON.stringify` of large state

| Location | What | Verdict |
|---|---|---|
| `debugStore.ts:554, 557` | `JSON.stringify(args)` / `JSON.stringify(out)` on every debugger op into an unread `log` array | MED, pure waste. Delete. |
| `analysisStore.ts:221` | `JSON.stringify(out, null, 2)` on a decompile result | Fine, once per decompile. |
| `toolCalls.ts:178, 759` | `JSON.stringify` in `formatToolOutput` | Runs per `ToolCallCard` render. See H2. |
| `R2Console.tsx:55` | `JSON.stringify(out, null, 1)` of a raw engine response | `aflj` on a big binary is megabytes. Once per command. MED. |
| `ui/stack-split.tsx:111` | `JSON.stringify(next)` (a 3-number array) per pointermove | HIGH. See H3. |
| `ui/resizable-column.tsx:111` | `localStorage.setItem` once per pointerup | Fine. |
| `DisasmBytes.tsx:57` | 8-boolean object, on option toggle only | Fine. |

---

## 6. Scroll performance

**Zero `onScroll`, `onWheel`, and `onMouseWheel` handlers in the entire app.** No
scroll-driven `setState`, so no scroll jank from that direction. The app attaches
no scroll/wheel/touch listeners at all — all 14 `addEventListener` calls are
`keydown`, `click`, `pointerup`, `pointercancel`, or `resize`, none of which
benefit from `{ passive: true }`.

Scroll containers, all native overflow: `CenterPanel.tsx:717, 787, 1079`,
`FunctionList.tsx:137`, `DataRegionsPanel.tsx:278, 314, 355`,
`VariableList.tsx:258`, `AgentChat.tsx:136`, `DebugCpu.tsx:240`,
`DebugPanel.tsx:202, 326, 414, 737`, `HexPanel.tsx:183`, `R2Console.tsx:108`,
`FindingsPanel.tsx:109`, `ReconPanel.tsx:167`, `CommandPalette.tsx:124`,
`ModelPicker.tsx:509, 618`.

`scroll-host` usage is consistent. `FunctionList.tsx:135-136` even documents the
`pr-2.5` gutter reservation so the overlay scrollbar never covers the rename
button. Two places miss it: `CenterPanel.tsx:718` is fine; `ProjectScreen.tsx:60`
uses `overflow-auto` without `scroll-host`, which is harmless (it is a page, not a
data list).

**`scroll-behavior: smooth` is not set anywhere**, which is correct. All
programmatic scrolls are instant: `CenterPanel.tsx:511` on function switch,
`AgentChat.tsx:63` (which would be *wrong* to smooth at token rate),
`DebugCpu.tsx:133` with `block: "nearest"` (right, and documented at `:130-131`:
"without yanking the view when it is already visible"), `R2Console.tsx:40` and
`ModelPicker.tsx:488`.

---

## 7. Startup

`main.tsx` is 10 lines with no blockers: no `flushSync`, no pre-render work, no
module-scope `localStorage`. Keep `StrictMode` — the code is written to tolerate
it.

`App.tsx:44-52` fires five async `invoke`s (`init`, `initZoom`, `initTheme`,
`initBackend`, `loadProjects`), none of which block first paint.

`store/settingsStore.ts:148-151, 274` runs four `localStorage.getItem` calls and a
`matchMedia` at store-creation (import) time. Microseconds, and correct — it
avoids a light-mode flash, as the comment at `:271-273` explains.

`R2Console.tsx:15-25` and `DisasmBytes.tsx:35-45` do `JSON.parse` of small
`localStorage` payloads as `useState` lazy initializers, so they only run when
their tab is opened. Fine.

### Suspense boundaries — partial

Lazy-loaded, each in its own `<Suspense>` with a text fallback: `R2Console`,
`GraphPanel`, `CallGraphPanel`, `FindingsPanel`, `HexPanel`
(`CenterPanel.tsx:49-71`, boundaries at `673/683/693/703/1113`). This correctly
keeps `@xyflow/react`, `elkjs`, `dagre` and `@xterm` out of the initial chunk.

Gaps:

- **`ProjectScreen.tsx`** is the literal first screen on every launch
  (`App.tsx:130`) yet is imported eagerly at `App.tsx:11`, pulling in `Logo`
  (2 PNGs), `api`, and `projectStore` -> `binaryStore` -> `analysisStore` ->
  `sessionStore`. `lazy()` it.
- **`Sidebar` -> `DataRegionsPanel`** — `Sidebar.tsx:4-5` eagerly imports both, and
  `DataRegionsPanel` pulls `StackSplit` + `stackSplit` + `debugDisasm` for a tab
  that is off-screen by default. `lazy()` it.
- **`DebugPanel`** is statically imported at `CenterPanel.tsx:16` and is never
  lazy, unlike its five siblings. `lazy()` it. (`ReconPanel` at `:24` is the
  default tab — keep it eager.)
- **`MenuBar`** calls `buildCommands()` on every render (`:177`) — ~20 `Command`
  allocations plus 5x `sectionsFor()` loops, then `MENU_ORDER.filter(...)`. Not a
  startup cost, but a per-App-render cost that H10 multiplies.
- `CommandPalette`, `NewProjectDialog`, `DebuggerSettingsDialog` are mounted
  unconditionally at `App.tsx:166-171` (correct for hotkeys; each returns `null`
  when closed, `CommandPalette.tsx:97`). Cheap.

There is no app-level `Suspense` boundary, so there is no fallback if a chunk is
slow to arrive.

---

## Appendix: dead code

| Path | Evidence |
|---|---|
| `components/ui/split.tsx` (192 lines) | `SplitView` never imported. Contains the worst per-pointermove case: `setState` + `localStorage` + `getBoundingClientRect` + a layout-animating `flexBasis`. Delete. |
| `components/ui/scroll-area.tsx` (48 lines) | `ScrollArea`/`ScrollBar` never imported. Delete + drop `@radix-ui/react-scroll-area`. |
| `components/Console.tsx` (83 lines) | Never imported. Delete. |
| `components/SessionMenu.tsx` | `export function SessionMenu()` at `:13`, never imported. Delete. |
| `tw-animate-css` | `index.css:2`, zero utilities used. Delete import + devDependency. |
| `@xterm/xterm`, `@xterm/addon-fit` | `package.json:36-37`, zero usage in `src`. Delete. |
| `debugStore.log` + `appendLog` | Written at `debugStore.ts:300/554/557`, no reader. Delete. |

## Appendix: prioritized fix queue

**Tier 1 — mechanical, no behavior change (done)**

1. `CenterPanel.tsx:181-189` — hoisted `frameOps` out of `OpRow` into a single
   `useMemo` over `asm?.ops` (`frameOpsFor`). O(n^2) -> O(n) per function select.
2. `CenterPanel.tsx:102-133` — `highlight()` is now memoized on
   `[decompiled, decompiledAnnotations]`.
3. `Markdown.tsx:96` — `REMARK_PLUGINS` hoisted to module scope; the component is
   wrapped in `memo`.
4. `lib/debugVars.ts:238` — `frameSlotPattern` builds the two register patterns
   once into `RSP_SLOT` / `RBP_SLOT`; `frameSlot` now takes a `RegExp`.
5. `ui/stack-split.tsx:191` — `move` takes a `persist` flag; the pointer path
   passes `false` and `release()` does the one write. The container height is
   also captured at pointerdown, so a drag no longer calls
   `getBoundingClientRect` per move.
6. `ui/resizable-column.tsx:151` — the grid's edges are captured into an `origin`
   ref on the first move and reused; cleared on both release paths.
7. `CommandPalette.tsx:48` — a `for` loop that `break`s at `PALETTE_LIMIT`
   instead of a full scan plus `slice`.
8. `ToolCallCard.tsx:247,252` — `view` and `facts` are `useMemo`'d on the call's
   own fields, so a streaming reply does not re-`JSON.parse` every card.
9. Deleted `ui/split.tsx`, `ui/scroll-area.tsx`, `Console.tsx`,
   `SessionMenu.tsx`; dropped `tw-animate-css`, `@xterm/xterm`,
   `@xterm/addon-fit`, `@radix-ui/react-scroll-area`. Each was confirmed
   unreferenced (`rg` over `src`) before deletion, and each had no test file.
   The `debugStore.appendLog`/`log` removal is listed under Tier 2, since it
   belongs with that file's other changes.

Two incidental fixes were needed to keep the changes clean:

- `stack-split.tsx` `release` is now a `useCallback` on `[remember]`, with
  `release` added to the window-listener effect's deps. Without this the
  linter's `exhaustive-deps` warned, because `release` started closing over a
  hook value.
- `dataRegions.test.ts:5` referenced `SplitView` in a comment; the docstring now
  describes a stack divider, which is what the bounds actually mirror.

**Tier 2 — event coalescing (done)**

10. **`lib/frameBatch.ts` (new).** `createFrameBatch<T>(apply)` — collects pushes
    and commits once a frame, preserving order exactly. Has `flush()` for
    terminal paths and `drop()` for an abandoned stream. Two details that are
    not incidental:
    - It schedules **both** `requestAnimationFrame` and a `FRAME_FLOOR_MS` (100ms)
      timer, first one wins. A Tauri window that is occluded, minimized, or on
      another workspace stops being given frames at all, so a frame-only
      scheduler would hold a stream for as long as the window stays hidden. Found
      while writing it, not after.
    - `commit` takes the buffer *before* calling `apply`, so an `apply` that
      pushes again queues onto a fresh buffer instead of mutating the array
      being read. Covered by a test.
11. **`agentStore.ts`** — `channel.onmessage` pushes to a per-`send` batch
    instead of calling `set` per event. Extracted
    `applyEvents(events, sessionId, set)`, which applies a whole batch inside one
    `set` and returns state unchanged if every event in it was stale. `runSession`
    is now read **once** at the top of `send` rather than per event, so a
    mid-stream session switch cannot change which run an event counts as. The
    batch is flushed when `api.agentChat` resolves (the host is done sending) and
    dropped if it rejects.
12. **`debugStore.ts`** — `applyEvent`'s `"output"` case pushes to a
    module-level batch carrying `{gen, text}`. `commitOutput` re-applies the
    generation filter at commit time, so a chunk queued before a relaunch cannot
    land in the new process's transcript. The buffer is `drop()`ped at every
    process boundary: `clearProcessState`, the `detach`/`kill` branch, `reset`,
    and `disconnect`.
13. **`DebugPanel.tsx`** — the per-chunk `scrollTop = scrollHeight` read is gone.
    Tail-follow is now a `ResizeObserver` on the transcript's `<pre>`, which
    fires *after* layout so reading `scrollHeight` inside it is free. A passive
    `scroll` listener tracks whether the analyst has scrolled back, so following
    the tail no longer yanks them away from history they are reading — a
    behavior fix that came free with the perf one.
14. **`appendLog` / `log` deleted** from `debugStore`. It `JSON.stringify`'d every
    debugger op's full result into a capped array with no reader.
15. **`React.memo`** on `AssistantMessage`, `ToolCallCard`, `Markdown` (from
    Tier 1), and the `Button`, `Badge`, `Input`, `Textarea`, `Separator`
    primitives. The honest limit: this only helps where props are referentially
    stable. The real wins are the message components, whose props are data —
    `blocks` and `call` objects the store only reallocates when that turn
    actually changes. The primitives help where a caller passes no inline
    handler; many call sites pass `onClick={() => ...}`, a new identity every
    render, which defeats the comparison.
16. **An ordering bug was found and fixed during this work.** Routing program
    output through a queue while `sendStdin`'s echo was written straight through
    meant an echo could commit *ahead* of output the debuggee had already
    printed — putting the analyst's own line above the line that prompted it.
    Caught by an existing test (`tags the echo apart from what the debuggee
    printed`, which asserted `[false, true]` and got `[true, false]`). The echo
    now goes through the same queue, stamped with the same `eventGen` the queue
    filters on. Pinned by a new test, `does not let an echo jump ahead of output
    already printed`.

**Not done, deliberately: the running total in `trimOutput`.** The audit called
this out; on re-reading the code the measurement does not support it.
`appendOutput` merges into the last chunk when the kind matches, and program
output is uniformly `echo: false`, so a real transcript is *one* chunk plus one
per occasion the analyst types. The `O(chunks)` re-sum is over ~1–3 items and is
noise next to the render it was riding on. Carrying a total would have meant
changing the shape of `output`, `appendOutput`, and its (excellent) test suite
for no measurable gain. Revisit only if a transcript is ever seen with many
hundreds of chunks.

**Tier 3 — making big binaries usable (done)**

13. **`HexPanel` redesigned.** It rendered one controlled `<input>` per byte — up
    to 4,096 of them, so typing a single hex digit re-reconciled all 4,096. Bytes
    are now text; clicking one swaps in the *only* live input in the view, with
    the half-typed value held in a `draft` rather than in `edits`. A staged edit
    is a fact about the file and a draft is a fact about the field, so a
    half-typed nibble can no longer be mistaken for a byte. `parseByte` returns
    null for anything that is not yet a byte, and Enter/blur commits, Escape
    reverts.
14. **`FunctionList` windowed** with `@tanstack/react-virtual` (new dependency).
    Rows are a fixed `chrome.row` height, which is what makes them windowable at
    all; `overscan: 12` keeps a fast scroll from showing gaps. The row is
    extracted to a memoized `FunctionRow` and the rename handlers are
    `useCallback`, so a keystroke in the filter or a background indexing tick
    does not re-render every visible row.
15. **The search key is memoized.** The filter used to call `.toLowerCase()` per
    function *per keystroke*; `searchable` now holds `{f, key}` pairs built once
    per list rebuild, and the filter is a loop over them.
16. **`.offscreen-row`** in `chrome.css` — `content-visibility: auto` with
    `contain-intrinsic-size: auto var(--row-h)` — applied to the disassembly rows,
    the strings and imports tables, the xref list, and `DisasmBytes`. This is the
    no-dependency answer for the lists that are long but bounded, and it is
    deliberately *not* a row virtualizer: disassembly rows are not a fixed height
    (comments, byte columns, named variables, and the `wideSpacing` toggle all
    change it), and a virtualizer with a wrong height estimate makes rows jump as
    you scroll, which is worse than slow.
17. **Uncapped lists capped.** `imports` had no cap at all; it is now capped at
    2,000 with the same "(capped at 2,000 — refine the filter)" note the strings
    table already used. In `FindingsPanel`, the `slice(0, 200)` that only
    `dwarf_functions` had is now a shared `capped()` helper and an `<Overflow>`
    note, applied to capabilities, C++ classes, driver IOCTLs, firmware, and DWARF.
18. **The xref list is no longer quadratic.** `sourceFunction` did two linear
    scans over every function in the binary *per reference row*. There is now a
    name map plus a binary search over size-annotated functions sorted by
    address.

**Tier 4 — graph and tree-wide re-renders (mostly done)**

19. **`GraphPanel` no longer refetches on every index tick.** `funcs` was a
    dependency of the effect that fetches and lays out the graph, so the
    background indexer's 1.5s poll re-fetched the CFG over IPC and re-ran layout
    every time. The function list is now read with `getState()` at fetch time and
    the effect depends on `[addr]` alone. A `cancelled` check was added after the
    now-async layout, so a graph that took a moment cannot land after the analyst
    has moved on.
20. **`onlyRenderVisibleElements`** added to the CFG's `<ReactFlow>`. Every node
    renders its block's instructions, so with all nodes mounted a large function
    meant the whole function's disassembly in the DOM at once. `CallGraphPanel`
    already had this.
21. **Dagre moved into a Worker** (`lib/dagreLayout.worker.ts` +
    `lib/dagreLayout.ts`), mirroring how `CallGraphPanel` runs ELK. Dagre has no
    worker of its own, so the module is the worker entry. The client builds the
    worker on first use — not at module scope, since the graph panel is imported
    eagerly at mount — tags each request with an id, and settles every in-flight
    call on `onerror` so a failure cannot leave a caller awaiting a frame that
    never arrives. `layoutInline` is the fallback for an environment with no
    `Worker`, and the panel falls back to it. Verified in the build output as its
    own 12.9 kB chunk.
22. **`toGraph` no longer flattens the function's ops once per basic block.**
    Every node carries the function's whole instruction list, and it was
    recomputing that list inside the `.map` over blocks.

**Tier 5 — polish (done, with one deliberate omission)**

23. **`prefers-reduced-motion`** in `index.css`. Durations are flattened to
    0.01ms rather than removed, so a transition still *ends* where it would have
    — an element finishing in a different state than it started would snap.
24. **`DebugPanel` and `DataRegionsPanel` lazy-loaded**, each with a text
    fallback, matching the five panels that already were. This moves 28 kB out of
    the initial chunk and into the tab that needs it.
25. **`graphNeedsTopView` memoized** in `CallGraphPanel`, and rewritten from four
    `Math.max(...nodes.map(...))` spreads (four array allocations per render, on a
    panel that re-renders on every pan) to one pass with four running bounds.
26. **`ProjectScreen` was NOT lazy-loaded**, though the audit recommended it. It
    is the first screen on every launch, so deferring it does not let anything
    paint sooner — it only inserts a round trip between launch and first paint.
    The recommendation was wrong; the other two were right.

## What the numbers actually say

Measured, not estimated — the initial chunk before this batch was 664.29 kB and
after it is 663.87 kB, so **the initial payload is flat**. The virtualizer added
~13 kB to the eager path, which offset the 28 kB moved out of it. The honest
framing: nothing got smaller at startup, but 28 kB of debugger and memory-map
code is now only parsed when its tab is opened, and the CSS grew ~1 kB for the
two new rules. The wins in Tiers 3 and 4 are in *runtime* cost on large inputs,
not in bundle size.

## Still open

- `resizable-column.tsx:121` — window resize still calls `setWidth`, re-rendering
  `App` and everything under it at 60Hz. Offered as part of item 2 of the "what
  else" round and not taken up yet; the value is only used for `aria-valuenow`.
- `VarNameChip.tsx:38` — still one store subscription per instruction row, so a
  rename re-renders every chip in the listing.
- `R2Console.tsx` and `ModelPicker.tsx` — both un-capped, and `ModelPicker`'s
  catalog is the whole of OpenRouter.
- The one pre-existing lint error, and `DebugCpu.tsx`'s per-step
  `scrollIntoView`.
