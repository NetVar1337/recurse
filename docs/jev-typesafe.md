# Jev (TypeSafe AI) — research notes

Research date: 2026-09-20. Everything below was read from TypeSafe's live
documentation (`docs.typesafe.ai`, including the `.md` sources and `/llms.txt`),
not from memory. Nothing has been smoke-tested: there is no API key in this
environment yet.

## 1. What it is

**Jev is TypeSafe AI's flagship "System One" model** — `jev-latest` /
`jev-1.13.0`. It is **not an LLM**. There is no text generation and no free-form
tool calling. You send `state` plus typed *questions* and get typed *answers*
back with probabilities and a confidence value.

> "System One models are built to make fast, structured decisions that software
> can use directly. Jev evaluates typed questions against a state and returns
> structured results directly. No text generation, no parsing."
> — docs/introduction

### API shape

```http
POST https://api.typesafe.ai/v1/systemone
Authorization: Bearer <API_KEY>
Content-Type: application/json
```

```json
{
  "state": "Help! My payouts have been failing for 3 days.",
  "model": "jev-latest",
  "questions": {
    "is_urgent": {
      "type": "noul",
      "instructions": "Does this convey urgency?",
      "criteria": { "true": "Explicitly time-sensitive" }
    }
  }
}
```

```json
{
  "model": "jev-1.13.0",
  "answers": {
    "department": {
      "type": "choice",
      "choice": "billing",
      "probabilities": { "billing": 0.88, "technical": 0.12, "sales": 0.0 },
      "confidence": 0.81
    }
  },
  "usage": { "input_tokens": 318, "output_tokens": 34 }
}
```

`state` can be a string, an object, or an array. Question ids are ours; several
questions ride in one request and answers come back under the same keys.
`instructions` and `criteria` also accept JSON structure, so a question and the
data it refers to can be named fields rather than prose.

### The three primitives

| primitive | question | answer |
| --- | --- | --- |
| `noul` | yes/no | probability 0 → 1 (`noul` field) |
| `choice` | pick one option from a defined set | `choice` + per-option `probabilities` + `confidence` |
| `score` | rate against ordered, descriptive levels | `score` + `probabilities` + `confidence` |

`confidence` is derived from the answer's probability distribution and is
separate from the probability itself: the answer tells you *what*, confidence
tells you *whether to act on it*.

### Model, price, limits

| | |
| --- | --- |
| model ids | `jev-latest`, `jev-1.13.0` |
| price | **$42 per billion input tokens = $0.042 / M input; output tokens free** |
| rate limits | 250,000 tokens/sec, 1,200 requests/min (429 on either) |
| context | 64k tokens per request; 32k for `state` plus the longest question |
| input | Text only — string, JSON object, or array of text. No image/audio/video |

### Ecosystem

- Python and JavaScript SDKs (`docs.typesafe.ai/sdk`).
- **Agent skill** for coding agents: `claude plugin marketplace add
  typesafe-ai/skills` + `claude plugin install typesafe@typesafe-ai`, or
  `npx skills add typesafe-ai/skills --skill typesafe-ai`. Source:
  `github.com/typesafe-ai/skills` → `skills/typesafe-ai/SKILL.md`.
- `/llms.txt` (index) and `/llms-full.txt` (everything) for agent consumption.
- Console/keys at `console.typesafe.ai`.
- Patterns: speculative fan-out, confidence-gated routing, composite scoring,
  intent routing. Cookbooks: function calling, LLM guardrails, classification
  using confidence, hierarchical classification, parallel questions, semantic
  find, rerank, citation check.

Their "function calling" is **not** agentic tool use. It is typed dispatch: fill
in a call whose arguments come from closed sets (`Literal[...]` / enums), each
with a confidence — "the barista marks four options on a cup" rather than taking
your sentence down.

## 2. The constraint that shapes every option

**Jev cannot drive the agent loop.** Our loop needs text generation plus
arbitrary tool calls; Jev provides neither. It is for *decisions around* the
agent, not for being the agent.

It should also be called **from code, not exposed as a tool**. Measured on our
own eval runs: of eight tool schemas we send, **six are never called** (read,
write, edit, memory_save, memory_load, memory_search) — ~718 tokens of dead
schema per turn, ~45k tokens across a 63-turn run. Adding a ninth tool that the
model must choose correctly has the same failure mode. The docs push the same
way: "keep code in control, give System One narrow, structured decisions".

## 3. Where it could fit, ranked against measured numbers

Baseline for all of these (easy-10 tier, `deepseek/deepseek-v4-flash`, full
10/10 run): **171,415 input tokens, 15,738 output, 63 turns, $0.01**. Noise
floor measured by running identical code twice: **±11% aggregate**, with
per-task swings of −35% to +179% — so only aggregate comparisons count.

### 3.1 Context relevance gating — attacks the largest measured waste

Tool output was **81% of all input tokens** (596,779 of a ~735k char-based
estimate) in the pre-tool run, and 178 KB of unique tool results (avg 2,753 B
per r2 call) get re-sent in every subsequent turn.

A `score` or `choice` question per tool result — "does this still matter for
solving the task?" — lets *code* decide keep / summarize / evict, with
confidence gating the decision. This replaces the positional truncation we have
now (`MODEL_MSG_BUDGET`, 6,000 chars/message) with something semantic.

Cost: classifying a run's ~45k tokens of unique output at $0.042/M ≈ **$0.002
per run**. Effect unknown until measured, but it targets the biggest line item.

### 3.2 Doom-loop detection

The system prompt claims "doom_loop fires after 3 identical tool:args" — no such
check exists in the code. The free-router runs burned 10+ turns looping before
hitting the turn budget.

A `noul` over the last N tool calls ("is this repeating without progress?") →
confidence-gated nudge or abort. Keep the deterministic identical-args hash as
the hard floor; Jev is the fuzzy layer on top.

### 3.3 Typed strategy dispatch

From cheap r2 signals (`iij` imports, an `izz` sample, the entry block), produce
a typed decision:

```
analyse(strategy = Literal["plain_compare","xor","hash","packed","anti_debug"],
        needs_runtime = bool)   confidence 0.9
```

Code picks the plan; low confidence falls back to the slow LLM path. This is
their "confidence-gated routing" pattern applied to our dominant cost
multiplier — turns. Fixed per-turn overhead is 1,366 tokens (system prompt 240 +
schemas 1,126), so turns are expensive twice over: fixed cost plus cumulative
re-send.

### 3.4 Failure-mode taxonomy for the harness

Classify *why* each task failed — context loss, loop, wrong hypothesis, tool
error — over the traces we already write, instead of hand-reading them. Would
feed a real dashboard rather than my ad-hoc Python.

### 3.5 Skipped: grading assist

Our token-boundary flag match is deterministic, free, and stricter. A
probabilistic grader would be a regression.

## 4. Risks and caveats

**The guardrail idea is self-defeating as a primary control.** I initially
proposed using Jev to screen attacker-controlled binary strings for prompt
injection. Their own jaggedness page warns against exactly that:

> "State is data, and `jev-1.13` does not treat it as hostile by default.
> Content written to adversarially steer the model, whether that is an injected
> instruction, a deliberately misleading framing, or text that argues for its
> own classification, can move the answer."

So a Jev-based injection detector is itself steerable. It can only ever be
defence-in-depth; the real controls stay the hard-coded ones (the r2 command
path, project path validation, no shell interpolation).

Other documented edges (from `model-jaggedness/jev-1.13`, reviewed 2026-09-17):

| failure mode | guidance from their docs |
| --- | --- |
| literal reading | write the exact condition and criteria for every option |
| math and numbers | keep arithmetic in code |
| date/time comparison | extract components, compare in code |
| indirection | reduce hops, point at the relevant state |
| large state with irrelevant detail | filter first, send only what the question needs |
| adversarial content | precise prompts; test thoroughly before deploying widely |
| contradictory instructions vs criteria | make criteria an extension of the instruction |

Two more practical notes:

- **No numeric precision.** Anything that smells like arithmetic or comparison
  belongs in code, which is fine for our proposals (all are classification).
- **Not verified on our domain.** Calibration is claimed for common-sense
  judgement; binary-derived text and tool-call traces are a different
  distribution. Confidence thresholds must be tuned empirically before we
  gate anything on them.

## 5. Cost model per run (easy-10, 63 turns)

| use | calls | tokens | cost |
| --- | --- | --- | --- |
| 3.1 context gating | ~64 (one per tool result) | ~45k in | ~$0.002 |
| 3.2 loop detection | ~63 (one per turn) | small state each | < $0.001 |
| 3.3 strategy dispatch | ~10 (one per task) | ~1k each | < $0.001 |
| 3.4 failure taxonomy | ~10 (one per trace) | trace-sized | ~$0.001 |

All of it is rounding error against the $0.01 the eval already spends, because
the lever is *removing* re-sent tokens and wasted turns, not adding calls. The
rate limits (250k tok/s, 1,200 req/min) are far above anything we would use.

## 6. Open questions

1. **Is there a free tier / what does an eval-scale key cost?** The listed price
   is per input token with free output; a few dollars covers thousands of runs
   at our volume.
2. **Does calibration hold on RE text?** Needs a labelled set — we already have
   one: the crackmes dataset's own `obfuscation_classes` tags are ground truth
   for proposal 3.3. That makes a calibration check cheap and honest.
3. **Is latency actually low enough to sit inside the turn loop?** Their numbers
   are throughput, not percentiles; measure before designing around it.
4. **Should the agent skill be installed?** It would make future work in this
   repo use the API correctly, but it is a change to the agent environment, so
   it should be a deliberate decision.

## 7. Suggested first experiment

Smallest thing that tests the thesis, using the instrument we already have:

1. Create a key, put `TYPESAFE_API_KEY` in `crates/recurse-eval/.env`.
2. Add a calibration harness: ask a `choice` question over the dataset's
   obfuscation classes for ~50 binaries whose tags we know, and compare predicted
   vs actual. This validates the model on our domain *before* we gate anything.
3. If calibration holds, wire **3.1 context gating** into the agent loop behind
   an off-by-default flag, and A/B it against the current baseline
   (171,415 in / 63 turns / 10-10 pass) using aggregate comparisons or 3 repeats
   per arm, given the ±11% noise floor.

## Sources

- `https://typesafe.ai` — product framing, "System One", FAQ
- `https://docs.typesafe.ai/introduction`
- `https://docs.typesafe.ai/api` — full HTTP reference
- `https://docs.typesafe.ai/models` — ids, price, limits, context
- `https://docs.typesafe.ai/primitives/choice`, `/primitives/noul`, `/primitives/score`
- `https://docs.typesafe.ai/confidence`
- `https://docs.typesafe.ai/model-jaggedness/jev-1.13`
- `https://docs.typesafe.ai/cookbooks/function_calling`, `/cookbooks/llm_guardrails`
- `https://docs.typesafe.ai/patterns/confidence-routing`
- `https://docs.typesafe.ai/agent-skill`
- `https://docs.typesafe.ai/llms.txt`
