# Architecture

## The two-tier escalation design, and why

The policy engine (`src/lib/guard/`) runs detectors in two cost tiers:

- **Rules tier** — regexes, entropy/checksum checks, structural validation. Sub-millisecond,
  deterministic, always runs, in parallel.
- **LLM tier** — `generateObject`-style classification against a small/fast model, temperature 0.
  Costs a provider round-trip: tens to hundreds of milliseconds, real tokens, subject to a free-tier
  rate limit.

The naive designs both fail. Rules-only misses anything that depends on intent rather than surface
pattern (`llm-injection-judge` exists because "How do I defend against prompt injection?" and
"Ignore all previous instructions" share vocabulary but not intent). Always-LLM is slow, expensive, and
burns a free-tier daily quota in one afternoon of testing.

Aegis instead runs the rules tier first, combines its detector outputs into a single score via
noisy-OR (`combineScores` in `router.ts`), and partitions on two policy-configured thresholds:

```
     0                lowThreshold        highThreshold              1
     |-- confident allow --|-- ESCALATE to LLM --|-- confident block --|
         (no LLM call)        (one LLM call)         (no LLM call)
```

Only the middle band costs a provider call. `Decision.escalatedToLlm` is recorded on every decision,
which is what lets the harness report the escalation rate and the resulting token/latency saving
against an always-LLM baseline — see `runs/<id>/report.md`'s "Cost of the two-tier design" section. In
a representative `--mock` run across all three shipped policies, escalation rate was 22–28% and judge
tokens were 72–78% lower than an always-escalate baseline would have spent, at 0% ASR / 11–23% FPR
depending on policy.

Both thresholds live in `Policy.escalation` and are swept by the harness
(`sweepThresholds` in `score.ts`) to plot the resulting ASR-vs-FPR trade-off curve with an ROC-style
AUC — that curve is the headline research output this project exists to produce. Collapsing the router
into "always call the LLM" would delete the measurement entirely, which is why `router.ts` treats the
band logic as the single most important design decision in the codebase.

## The escalation router does not silently degrade

An LLM-tier detector never throws. `LlmJudge.classify` (`src/lib/providers/index.ts`) catches every
provider failure — missing key, unverified model, HTTP 4xx/5xx, timeout, quota exhaustion, schema
mismatch — and returns `{ ok: false, error }`. Each LLM detector turns that into
`{ triggered: false, unavailable: true, explanation: "<detector> could not run: <reason>. This is NOT
a clean verdict…" }`, and the router sets `Decision.llmUnavailable = true` and appends an explicit
reason. A dead provider therefore never looks like "the LLM tier checked and found nothing" — the
dashboard and the harness report both surface it, and `tests/router.escalation.test.ts` asserts the
whole chain.

## The streaming sliding-window guard

Output detectors are the last line of defence, but a streaming response arrives in chunks whose
boundaries are chosen by the tokenizer, not by the guard. A secret, a canary token, or an exfiltration
URL can span a chunk boundary — `"...key is AKIAIOSFOD"` / `"NN7EXAMPLE, keep safe"` — and a naive
per-chunk scan (`scanPerChunk` in `stream-guard.ts`, kept in the codebase specifically to demonstrate
this) matches neither half.

`createStreamGuard` (`src/lib/stream-guard.ts`) fixes this with a sliding buffer: it never releases the
most recent `policy.streamWindowChars` characters, and after every chunk it rescans the *entire*
accumulated text — not just the new chunk — so a pattern spanning any number of boundaries is seen
whole before its first byte reaches the client. On a trigger it aborts the upstream provider call,
discards the withheld tail (where the offending text still lives), emits the policy's refusal text, and
closes the stream. `tests/stream-guard.test.ts` proves this with a secret deliberately split across two
chunks: a per-chunk scan misses it, the windowed guard catches it, and a `windowChars: 0` configuration
demonstrably leaks the prefix — the window is not decorative.

Only the rules tier runs on every chunk (`streamWithGuard` in `pipeline.ts`); the full guard, LLM tier
included, runs once over the complete text when the stream closes via a `tee()`, because an LLM
round-trip per chunk would defeat the latency the window is protecting.

### The trade-off, measured

A larger window catches more (a leak longer than the window can still straddle the release boundary at
any window size, but a larger window shrinks that residual risk) at the cost of time-to-first-token: no
byte is ever released until `windowChars` characters have accumulated. Measured directly against
`createStreamGuard` with a synthetic 47-char-per-chunk source (`tests/stream-guard.test.ts`, "window
size versus time-to-first-token"):

| `windowChars` | chars before first release |
|---|---|
| 0 (naive) | 45 |
| 120 | 135 |
| 240 (balanced/strict default region) | 270 |
| 512 | 540 |
| 1024 | 1035 |

The relationship is linear in the window size, as it has to be: the guard withholds exactly
`windowChars` characters at steady state. Translated into wall-clock time at a generation rate this
build actually observed against Groq's free tier (`openai/gpt-oss-20b`, 32 completion tokens in 35.6ms
≈ 900 tok/s ≈ 3,600 chars/s — a single sample, not a benchmark, but the right order of magnitude for a
small model on Groq), a 240-char window adds roughly **75ms** to time-to-first-token versus unwindowed
release, and a 1024-char window adds roughly **290ms**. `permissive.json` ships a 120-char window,
`balanced.json` 240, `strict.json` 512 — the policy is where this trade-off is made explicit rather
than hardcoded.

## The taint model

Every message part carries a `Trust` label: `system`, `user`, `tool`, or `retrieved`
(`src/lib/guard/types.ts`). `tool` and `retrieved` are **untrusted** — content that reached the model
from a data source an attacker can plausibly influence (a search result, a fetched document, a
database row a customer wrote into). The gateway lets a caller assert taint per message via the
`x-aegis-trust` header; the harness assigns it from the corpus case's `delivery` field
(`indirect-doc` → `retrieved`, `tool-result` → `tool`).

Taint changes detector behaviour, not just labelling: `injection-heuristics` scores the same payload
higher when it arrives as `tool`/`retrieved` content (`tests/detectors.injection.test.ts` asserts this
directly), and `tool-call-policy` specifically checks whether a requested tool call's arguments contain
text lifted from untrusted content — the mechanism by which an indirect injection becomes an action in
the world rather than just misleading text.

**Spotlighting** (`applySpotlight` in `spotlight.ts`, after Hines et al.) makes the trust boundary
explicit to the model itself: untrusted parts are wrapped in a random, unguessable delimiter, optionally
datamarked (spaces replaced with a marker character throughout the fenced region), with a system
preamble stating that fenced content is data and must never be followed as an instruction. **Sandwiching**
(`applySandwich`) restates the real task after the untrusted content, so the last thing in context is
the legitimate instruction rather than whatever an attacker appended. Both are per-policy toggles
(`Policy.mitigations`), and the harness runs the same corpus with each on and off
(`--mitigations spotlight:on,spotlight:off`) to isolate its effect — see `runs/<id>/report.md`'s
"By configuration" table, which pairs rows that differ only in one mitigation.

## Threat model

**In scope**, and what each defence targets:

| Threat | Defence |
|---|---|
| Direct prompt injection (user tries to override instructions) | `injection-heuristics` + `llm-injection-judge`, both stages |
| Indirect injection via a retrieved document or tool result | taint labelling + spotlighting + `tool-call-policy`'s tainted-argument check |
| System-prompt / instruction disclosure | `canary-leak` (definitive) + `llm-output-audit` (heuristic) |
| Credential / PII leakage, in either direction | `secret-scanner`, `pii-detector` |
| Data exfiltration via a rendered link or auto-loading image | `url-allowlist` (output stage), `injection-heuristics`'s exfil-pattern family |
| Obfuscated payloads (zero-width chars, bidi overrides, homoglyphs, base64/ROT13/hex smuggling) | `unicode-hygiene` (sanitizing transform) + `injection-heuristics`'s encoding family |
| Refusal suppression / compliance-phrase priming | `injection-heuristics`'s refusal-suppression family |
| Malicious or malformed tool calls | `tool-call-policy` (allowlist + Zod argument schema) |
| Off-schema output when a schema was requested | `output-schema` |
| A leak that spans a stream chunk boundary | the sliding-window guard |

**Explicitly out of scope — be honest about what this does not defend against:**

- **Multimodal attacks.** Every detector here is text-only. An injection embedded in an image, audio
  clip, or PDF layout is invisible to this engine entirely.
- **Semantic attacks the LLM judge itself is fooled by.** The LLM tier is a small, fast model chosen
  for cost, not the strongest available judge; a sufficiently novel or well-crafted attack can fool it
  the same way it fools the target model. The regex tier has the opposite failure mode — it is
  syntactic and can be evaded by sufficiently creative phrasing that carries no recognizable pattern.
  Aegis reduces both failure rates by combining tiers; it does not eliminate either.
- **Model-weight-level attacks** (fine-tuning poisoning, weight extraction, adversarial suffixes tuned
  against a specific open-weight model's tokenizer). Aegis operates entirely at the API boundary.
- **Confused-deputy attacks that don't touch text.** If a tool itself is compromised or over-privileged
  independent of what the model says to call it, `tool-call-policy`'s allowlist and schema help, but
  Aegis has no visibility into what the tool implementation actually does once invoked.
- **A determined attacker with knowledge of the exact policy in use.** Policies are versioned and
  hashed for attribution, not secrecy — nothing here assumes the attacker doesn't know the thresholds,
  and `strict.json`'s low escalation band is a deliberately narrow target for exactly this reason.
- **Volume-based abuse** (spam, scraping, billing exhaustion via legitimate-looking traffic). The rate
  limiter protects Aegis's own provider spend, not the downstream application from its users.
- **Novel attack families not represented in the corpus.** The harness measures against 83 hand-authored
  attacks across 13 documented families; it is a lower bound on robustness, not a certificate. See
  `RESEARCH.md` for the loader interface intended for adding public datasets.

## Reproducibility

Every harness run embeds git SHA, a dirty-tree flag, the full policy JSON (not just its name — policies
are mutable files), a corpus content hash, resolved model IDs (with `unverified` flagged), provider
response metadata, a seed, and the harness version, all in `runs/<id>/meta.json` and repeated in
`report.md`'s "Reproducibility" section so a number can always be traced back to the exact configuration
that produced it.
