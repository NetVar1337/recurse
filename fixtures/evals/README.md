# Eval set — what Recurse can (and cannot) crack

Four graded targets under `fixtures/evals/`. Each is compiled on demand by
`src-tauri/tests/eval_suite.rs`, which drives **the exact primitives the agent
uses** (r2 recon → sandboxed debug session → FIFO stdin oracle) and asserts
per-tier outcomes deterministically — no LLM required.

| Tier | Fixture | Defense | Toolchain result |
|------|---------|---------|------------------|
| 1 easy | `easy_strcmp.c` | `strcmp` against embedded literal | ✅ strings reveals key; oracle confirms GRANTED |
| 2 medium | `medium_transform.c` | per-char `(x ^ 0x20) + 3` vs table | ✅ hidden from strings; derived key passes oracle, garbage denied |
| 3 hard | `hard_rolling.c` | rolling XOR keyed by prev byte + index | ✅ solver inverts transform; oracle confirms |
| 4 impossible | `impossible_random.c` | secret from `/dev/urandom` | ⛔ unsolvable by construction — recon MUST surface `urandom` (the honest "stop" signal) and no candidate passes |

Run:

```bash
cargo test --manifest-path src-tauri/Cargo.toml --test eval_suite
```

## Live-LLM protocol (optional)

The deterministic suite proves tool *capability*. To measure full agent
*performance*, run the same four fixtures through a real model:

1. `export RECURSE_LLM_API_KEY=sk-...` and launch the app (`npm run tauri dev`).
2. For tiers 1–3: open each fixture binary, ask the agent
   *"find the key that makes this program accept"*; success = agent reports a
   key that yields `ACCESS GRANTED` when piped to the fixture.
3. For tier 4: success = agent **reports the target is non-deterministic**
   (cites urandom/entropy) instead of looping.
4. Score = solved / attempted per tier across ≥3 runs per model; record the
   model id next to results.

This is deliberately not automated in CI: it costs tokens and its value is
human review of trajectories, not a green checkmark.
