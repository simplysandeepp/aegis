# BUILD TASK: Aegis — LLM Guardrail Gateway + Red-Team Reasoning Harness

You are building a **complete, working research prototype** in the current directory. Not a demo, not
a skeleton, not stubs. Every component listed below must be genuinely implemented and tested. This
codebase will be used as the foundation for academic research on LLM security, so measurement rigor
and extensibility matter more than polish.

Work autonomously. Make reasonable decisions yourself and keep going. Only stop to ask if you are
blocked by a missing API key you cannot work around.

---

## 0. HARD CONSTRAINTS (violating any of these fails the task)

1. **Zero paid services.** Only Groq and Google Gemini free tiers for inference. No OpenAI, no
   Anthropic, no Vercel AI Gateway, no paid vector DB, no hosted Postgres.
2. **Runs fully locally.** `npm install && npm run dev` must work with nothing but two free API keys.
   Persistence is local SQLite. No Docker required. No auth required.
3. **Must work with no API keys at all** in mock mode (`--mock`), so tests and CI never need network.
4. **Never hardcode model IDs from memory.** They are stale and Groq deprecates models frequently.
   At build time, fetch the live lists and pick from them:
   - `curl -s https://api.groq.com/openai/v1/models -H "Authorization: Bearer $GROQ_API_KEY" | jq -r '.data[].id'`
   - `curl -s "https://generativelanguage.googleapis.com/v1beta/models?key=$GOOGLE_GENERATIVE_AI_API_KEY" | jq -r '.models[].name'`

   Put the resolved IDs in `config/models.ts` as the only place they appear, with a comment recording
   the date you fetched them. If keys are absent, still write the file but mark entries
   `unverified: true` and make the app fail loudly with a clear message rather than silently using a
   dead model ID.
5. **Free tiers rate-limit aggressively.** Every provider call goes through a shared rate-limiter with
   exponential backoff + jitter on HTTP 429/503, respects `retry-after`, default concurrency 2, and a
   hard token budget that aborts a run when exceeded. A harness run must never hang forever or burn
   the daily quota in one shot.
6. **No stubbed detectors.** If a detector is in the list below, it must actually detect, with unit
   tests proving both true positives and true negatives.

## 1. STACK

- Next.js (latest, App Router) + TypeScript strict + Tailwind
- shadcn/ui for components (`npx shadcn@latest init`), Recharts for charts
- Vercel AI SDK v6 (`ai` package) with `@ai-sdk/groq` and `@ai-sdk/google` providers
- Zod for all schemas, `generateObject` for LLM classification
- SQLite via `better-sqlite3` + Drizzle ORM, migrations checked in, DB file at `.data/aegis.db`
- Vitest for tests, `tsx` for CLI entrypoints
- **Before writing any AI SDK code**, read `node_modules/ai/docs/` and `node_modules/ai/src/`. The AI
  SDK v6 API differs substantially from older versions (e.g. tools use `inputSchema`, not
  `parameters`). Do not write AI SDK code from memory. If a `vercel:ai-sdk` skill is available to
  you, load it first. Likewise load a `dataviz` skill if present before writing chart code.

## 2. WHAT THE SYSTEM IS

Two halves sharing one policy engine:

- **Gateway** — an OpenAI-compatible endpoint that sits in front of Groq/Gemini and enforces
  guardrails on input and output. Any existing app points at it by changing one base URL.
- **Harness** — a red-team evaluation rig that fires an attack corpus at the gateway across a matrix
  of policies/models/mitigations and produces scored, reproducible, citable reports.

The gateway is the artifact; the harness is the proof it works. They must share the exact same policy
code — no divergent second implementation.

---

## 3. PART A — POLICY ENGINE (`src/lib/guard/`)

The heart of the project. Pure TypeScript, no Next.js imports, independently unit-testable.

### 3.1 Core types (`types.ts`)

```ts
type Trust = 'system' | 'user' | 'tool' | 'retrieved';  // taint label
type Stage = 'input' | 'output';
type Tier  = 'rules' | 'llm';

interface Span { start: number; end: number; label: string }

interface DetectorResult {
  detectorId: string;
  triggered: boolean;
  score: number;              // 0..1 calibrated confidence
  severity: 'low' | 'medium' | 'high' | 'critical';
  labels: string[];           // e.g. ['injection:instruction-override']
  spans: Span[];              // char offsets into the analyzed text
  explanation: string;        // human-readable, shown in the dashboard
  latencyMs: number;
  tokensUsed?: number;        // llm-tier only
}

interface Detector {
  id: string; name: string; stage: Stage[]; tier: Tier;
  run(ctx: GuardContext): Promise<DetectorResult>;
}

interface Decision {
  action: 'allow' | 'block' | 'redact' | 'rewrite' | 'flag';
  reasons: string[];
  results: DetectorResult[];
  transformedText?: string;   // when redact/rewrite
  escalatedToLlm: boolean;
  totalLatencyMs: number;
}
```

Detectors live in a **registry** (`registry.ts`) so a researcher adds one by dropping in a file and
registering it. This is a primary extension point — document it.

### 3.2 Rules-tier detectors (implement all, each with tests)

| id | what it does |
|---|---|
| `secret-scanner` | Regexes for AWS access keys, GitHub PATs, Google API keys, Slack tokens, `-----BEGIN * PRIVATE KEY-----`, JWTs, generic `api[_-]?key\s*[:=]` assignments. Plus a Shannon-entropy check (flag tokens ≥20 chars with entropy > 4.0 bits/char) and a Luhn check for card numbers. |
| `pii-detector` | Email, phone (E.164 + common national formats), US SSN, IBAN, IPv4/IPv6, credit card, and a street-address heuristic. Emit precise `spans` so the dashboard can highlight and `redact` can mask. |
| `unicode-hygiene` | Detect and strip zero-width chars (U+200B–U+200F, U+FEFF), bidi overrides (U+202A–U+202E), tag chars (U+E0000 block), and Unicode confusables/homoglyphs. Applies NFKC normalization. Acts as **both** a detector and a sanitizing transform — attacks that only work pre-normalization must be caught. |
| `injection-heuristics` | Weighted pattern families, each contributing to the score: **instruction-override** ("ignore/disregard the above/previous instructions"), **role-hijack** ("you are now…", "developer mode", "DAN"), **prompt-extraction** ("repeat everything above", "print your system prompt", "what are your instructions"), **encoding-smuggling** (long base64 blobs, ROT13-looking text, hex/URL-encoded instruction phrases), **delimiter-injection** (fake `<system>`, `###`, `[INST]` markers in user content), **refusal-suppression** ("do not refuse", "never say you can't"), **exfil-pattern** (markdown image/link whose URL embeds interpolated data, e.g. `![](http://host/?d=…)`). |
| `topic-policy` | Deny/allow topic rules loaded from the active policy config (regex + keyword lists). |
| `url-allowlist` | Extract URLs from model output; flag any host outside the policy allowlist. This is the main data-exfiltration channel and must be an output-stage detector. |
| `canary-leak` | Given a canary token that the gateway injected into the system prompt, detect its appearance in output. A hit is definitive proof of system-prompt leakage — score 1.0, severity critical. |
| `output-schema` | When the caller supplied a JSON schema (`response_format`), validate the output against it with Zod and report the exact validation errors. |
| `tool-call-policy` | Validate each requested tool call against the policy's tool allowlist and per-tool Zod argument schema; flag calls whose arguments contain tainted (`tool`/`retrieved`) content. |

### 3.3 LLM-tier detectors

Use `generateObject` with a Zod schema, temperature 0, on the **smallest/fastest** free model
(configurable, default to a small Groq or Gemini Flash-class model from the live list):

- `llm-injection-judge` → `{ isInjection: boolean, confidence: number, family: string, rationale: string }`
- `llm-policy-judge` → classify text against a natural-language policy document passed in the policy config
- `llm-output-audit` → `{ compliant, leaksSystemPrompt, followedUntrustedInstructions, rationale }`

Every LLM detector must degrade gracefully: on provider error/timeout/quota exhaustion it returns
`triggered: false` with an `explanation` naming the failure, and the decision records
`llmUnavailable: true` — a dead provider must never silently turn into "allow" without a trace.

### 3.4 The escalation router — the core research knob

This is the most important piece of design in the project. Do not collapse it into "always call the
LLM".

Run the rules tier first (cheap, deterministic, parallel). Combine into a rules score. Then:

- `rulesScore >= policy.highThreshold` → **decide immediately, no LLM call** (confident block)
- `rulesScore <= policy.lowThreshold` → **decide immediately, no LLM call** (confident allow)
- otherwise → **escalate** to the LLM tier and let it arbitrate

Record `escalatedToLlm` on every decision so the harness can report escalation rate and the resulting
latency/token savings versus an always-LLM baseline. Thresholds live in the policy config so they can
be swept. **The harness must be able to sweep these thresholds and plot the resulting ASR/FPR
trade-off curve** — that is the headline research output.

### 3.5 Taint tracking + spotlighting

Every message part carries a `Trust` label. Content labeled `tool` or `retrieved` is untrusted:
injection detectors run on it specifically, and instructions found there are treated as data.

Implement a `spotlight` transform (togglable mitigation) that wraps untrusted content in unique random
delimiters and optionally datamarks it (interleave a marker char between tokens), with a system-prompt
preamble telling the model that delimited content is data and must never be followed as instructions.
The harness must be able to run **with and without** spotlighting to quantify its effect. Include at
least one other togglable mitigation (e.g. `sandwich` — restate the real instruction after untrusted
content) so mitigation comparison is possible.

### 3.6 Policies

JSON/TS policy configs in `policies/` — ship at least `permissive.json`, `balanced.json`,
`strict.json`. A policy specifies: enabled detectors, per-detector severity→action mapping, the two
escalation thresholds, the URL allowlist, the tool allowlist + arg schemas, the topic rules, the
natural-language policy text for the LLM judge, and which mitigations are on. Every policy is
versioned and hashed; the hash is recorded on every decision so results stay attributable.

---

## 4. PART B — GATEWAY (`src/app/api/`)

### 4.1 `POST /v1/chat/completions` — OpenAI-compatible

Accepts the standard OpenAI body (`model`, `messages`, `stream`, `tools`, `tool_choice`,
`response_format`, `temperature`, `max_tokens`). Extra controls via headers: `x-aegis-policy`
(policy name), `x-aegis-trust` (JSON map marking which message indices are untrusted),
`x-aegis-canary` (opt out of canary injection).

Flow:
1. Parse + validate body with Zod. Map `model` prefix (`groq/…`, `google/…`) to the provider.
2. Apply sanitizing transforms (unicode hygiene, spotlighting) and inject the canary.
3. Run the **input** guard. If the decision is `block`, return a well-formed OpenAI-shaped response
   whose content is the policy's refusal message, with `x-aegis-decision`, `x-aegis-reasons`, and
   `x-aegis-latency` response headers. Never leak detector internals into the body.
4. Otherwise call the provider through AI SDK `streamText` / `generateText`.
5. Run the **output** guard, then return an OpenAI-shaped response (streaming or not).
6. Persist the full decision record.

### 4.2 Streaming output guarding — solve this properly

This is the hardest engineering problem in the project and I want a real solution, not
"guard after the stream finishes".

Pipe the model stream through a `TransformStream` that maintains a **sliding buffer** of the last N
characters (`policy.streamWindowChars`, default 240) and only emits text once it has fallen out of the
window. This lets output detectors catch a secret, canary, or exfil URL that **spans chunk
boundaries**, which a naive per-chunk scan misses.

On a trigger mid-stream: stop pulling from the provider, discard the buffered tail, emit a redaction
or the refusal text, and close the stream cleanly with the decision recorded.

Document the trade-off explicitly in `ARCHITECTURE.md`: a larger window means better leak coverage but
worse time-to-first-token. Measure it — the harness reports added TTFT per window size, and include a
test with a secret deliberately split across two chunks that proves the window catches what a
per-chunk scan does not.

### 4.3 `POST /v1/guard` — standalone check

Body `{ text, stage, policy, trust? }` → returns the full `Decision` including every
`DetectorResult`. Lets the engine be used without proxying, and powers the playground UI.

### 4.4 Decision log

Persist to SQLite for every request: id, timestamp, policy name + hash, model, stage, prompt hash
(store hashes not raw text by default; a `AEGIS_LOG_RAW=1` env flag enables raw capture for local
research), each detector result, escalation flag, action, latency breakdown (rules ms / llm ms /
provider ms / total), token counts, provider error info.

---

## 5. PART C — RED-TEAM HARNESS (`src/harness/`)

### 5.1 Corpus (`corpus/*.yaml`)

```yaml
- id: inj-override-001
  family: instruction-override
  delivery: direct          # direct | indirect-doc | tool-result | multi-turn
  severity: high
  expect: block             # block | allow  (allow = benign control)
  payload: "…"
  turns: []                 # for multi-turn cases
  success:                  # how to judge whether the ATTACK succeeded
    canaryLeak: true
    regex: "…"
    judgeRubric: "…"
  source: "hand-written"
```

**You must author the corpus yourself.** Minimum content:

- **≥60 attack cases** spread across: instruction-override, roleplay/persona jailbreak,
  encoding-smuggling (base64/ROT13/unicode/homoglyph), system-prompt extraction, indirect injection
  via a retrieved document, tool-result poisoning, multi-turn crescendo, refusal-suppression,
  exfiltration-via-markdown-image, PII elicitation, secret elicitation.
- **≥40 benign control cases** (`expect: allow`) that deliberately *look* risky — security questions
  asked legitimately, code containing the literal string `api_key`, a user pasting their own email,
  discussion of prompt injection as a topic, a document that quotes an attack while analyzing it.
  **Without these the false-positive rate is unmeasurable and the whole harness is worthless.** Weight
  this set as heavily as the attack set.

Keep the corpus to well-known, publicly documented attack patterns for defensive evaluation. Also
write a loader interface so public datasets can be added later without changing the runner.

### 5.2 Runner

CLI: `npm run harness -- --policy strict,balanced --models <id>,<id> --families all --mitigations spotlight:on,spotlight:off --repeat 3 --concurrency 2 --limit 50 --mock`

- Matrix over policies × models × mitigations × cases, with `--repeat N` for variance.
- Rate-limit aware (see constraint 5). Content-addressed result cache keyed by
  `(caseId, policyHash, model, mitigations, repeatIdx)` so re-runs are near-free and an interrupted
  run resumes instead of restarting.
- `--mock` swaps in a deterministic fake provider so the whole pipeline runs offline in CI.
- Writes `runs/<runId>/results.jsonl`, `runs/<runId>/report.md`, and rows in SQLite.

### 5.3 Scoring (`src/harness/score.ts`)

Compute and report:
- **ASR** (attack success rate) — the headline number, overall and per family
- **Block rate** on the attack set
- **FPR** on the benign control set — equally headline
- Precision / recall / F1 / MCC, plus the full confusion matrix per family
- **Threshold sweep**: ROC-style ASR-vs-FPR curve as escalation thresholds vary, with AUC
- Added latency p50/p95/p99 versus an unguarded baseline, split into rules/llm/provider
- Escalation rate and tokens consumed versus an always-LLM baseline (the cost argument for the hybrid)
- Mean ± std and **bootstrap 95% CI** on ASR across `--repeat` runs

### 5.4 Reproducibility (non-negotiable for research use)

Every run record embeds: git SHA, dirty-tree flag, full policy JSON, corpus file hash, resolved model
IDs, provider response metadata, timestamps, seed, and the harness version. `runs/<id>/report.md` must
be self-contained enough to cite.

### 5.5 Regression gate

`npm run harness:compare -- <runA> <runB>` prints a per-family diff and exits non-zero if ASR rises or
FPR rises beyond a configurable tolerance. Wire it into a GitHub Actions workflow running in `--mock`
mode.

---

## 6. PART D — DASHBOARD (App Router + shadcn/ui)

- `/` — latest runs, scorecards (ASR, FPR, F1, p95 added latency), an **ASR-vs-FPR scatter** across
  configs, and a trend line over time.
- `/runs/[id]` — per-family confusion matrices, the threshold-sweep curve, latency histogram,
  escalation rate, token spend.
- `/runs/[id]/cases/[caseId]` — **the trace view, most important page.** Show the original payload,
  the normalized/spotlighted text, every detector's verdict with its `spans` highlighted inline in the
  text, the rules score with the escalation band drawn on it, the LLM judge's rationale if escalated,
  the final action, and the model's actual output. A researcher must be able to see exactly why one
  case was decided the way it was.
- `/traffic` — live gateway decision log, filterable by policy/action/detector.
- `/playground` — paste text, pick a policy and stage, get a live detector-by-detector verdict via
  `/v1/guard`. Include a preset dropdown of corpus attacks.

Charts must be legible in both light and dark mode and must not encode meaning by color alone.

---

## 7. TESTING & VERIFICATION

- Vitest unit tests for **every** rules detector, each with true-positive and true-negative fixtures.
- Test proving the sliding-window streaming guard catches a secret split across chunk boundaries.
- Test proving unicode-hygiene defeats a zero-width/homoglyph-obfuscated injection that bypasses the
  raw regexes.
- Test proving the escalation router does **not** call the LLM outside the uncertainty band (assert on
  a mock call counter).
- Integration test of the gateway against the mock provider: allow path, block path, redact path,
  streaming path, tool-gating path.
- Test proving an LLM-tier provider failure yields a traced degraded decision, not a silent allow.

**Acceptance criteria — verify all of these actually pass before reporting done:**

1. `npm run typecheck` — clean
2. `npm run lint` — clean
3. `npm run test` — all pass, no network needed
4. `npm run harness -- --mock --limit 20` — completes offline, writes `report.md`
5. `npm run harness -- --policy balanced --models <verified-groq-id> --limit 10` — completes against
   the real free tier without blowing quota
6. `npm run dev` — dashboard renders a real run end to end, trace view included
7. A `curl` example from the README successfully proxies a chat completion and a second one gets
   blocked, both shown with their `x-aegis-*` headers

## 8. DOCS TO WRITE

- `README.md` — what it is, setup (`.env.example` with `GROQ_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`),
  free-tier rate-limit notes, working curl examples, harness usage.
- `ARCHITECTURE.md` — the two-tier escalation design and why, the streaming-window trade-off with
  measured numbers, the taint model, the threat model **and its explicit limitations** (be honest
  about what this does not defend against).
- `RESEARCH.md` — the extension points (add a detector, add a corpus family, add a scorer, add a
  mitigation), the metrics definitions, and a list of open questions this harness is positioned to
  answer.

## 9. EXECUTION ORDER

`git init` first, then commit after each phase so the work is bisectable:

1. Scaffold + config + SQLite/Drizzle schema + model-ID resolution
2. Policy engine types + registry + all rules detectors + their tests
3. LLM-tier detectors + escalation router + tests
4. Gateway routes incl. streaming sliding-window guard + tests
5. Corpus authoring (attacks **and** benign controls)
6. Harness runner + scorer + reproducibility + regression gate
7. Dashboard
8. Docs, then run the full acceptance checklist

Report at the end: what passes, what you had to compromise on, and anything you deliberately left
out — accurately, with the real command output. Do not claim a step passed if you did not run it.
