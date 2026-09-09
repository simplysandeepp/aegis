# Research notes

Aegis is built as a measurement instrument first, a product second. This document is for someone
extending it: where the extension points are, how each metric is defined, and what questions the
harness is positioned to answer that it doesn't yet.

## Extension points

### Add a detector

The registry (`src/lib/guard/registry.ts`) is the primary extension point.

1. Create `src/lib/guard/detectors/my-detector.ts`, exporting a `Detector` built with
   `defineDetector({...})` (handles timing and error-trapping for you — a detector that throws becomes
   a traced `unavailable: true` result, never a crashed request).
2. Import it in `src/lib/guard/detectors/index.ts` and add it to `ALL_DETECTORS`.
3. Enable it by id in whichever `policies/*.json` should use it, with a severity mapping.
4. Write true-positive and true-negative fixtures in `tests/` — see
   `tests/detectors.secret-scanner.test.ts` for the shape.

Nothing else changes. The router, the gateway, the harness and the dashboard all discover detectors
through `allDetectors()` / `detectorsFor()`; a new detector's `DetectorResult`s show up in the trace
view automatically because the trace view renders whatever `decision.results` contains.

A rules-tier detector should be pure and fast — it runs on every request. An LLM-tier detector should
follow `llm-judges.ts`'s pattern: a Zod schema, `ctx.llm.classify()`, and explicit handling of
`res.ok === false` that never lets a provider failure look like `triggered: false` from a clean check.

### Add a corpus family

Add cases to `corpus/attacks.yaml` (or a new `corpus/*.yaml` file — the loader reads every file in the
directory) following the existing shape: `id`, `family`, `delivery`, `severity`, `expect`, `payload`,
`success` (how the *attack's* success is judged — `canaryLeak`, `regex`, or `judgeRubric`), `source`.
**Always add a matching benign control** in `corpus/benign.yaml` that looks similarly risky — a family
with only attack cases makes its own false-positive rate unmeasurable, which is exactly the failure
mode this project exists to avoid.

To add a whole new corpus source (e.g. a public jailbreak dataset), implement the `CorpusLoader`
interface in `src/harness/corpus.ts` and call `registerCorpusLoader`. The runner is agnostic to where
cases come from as long as they validate against `caseSchema`.

### Add a scorer

`src/harness/score.ts` is a pure module over `CaseResult[]`. Add a new metric as a function taking
`readonly CaseResult[]` and returning a value, wire it into `score()`'s returned `ScoreReport`, and
render it in `report.ts`. `scoreBy()` already exists for grouping — reuse it rather than writing a new
group-by.

### Add a mitigation

Follow `spotlight.ts`'s shape: a pure function from `MessagePart[]` to a transformed
`MessagePart[]` (plus whatever system preamble it needs), a boolean flag in `Policy.mitigations`, and a
branch in `prepareInput()` (`src/lib/gateway/pipeline.ts`) that applies it when the flag is set. Add the
mitigation's name to `activeMitigations()` so it shows up in run metadata, and give the harness CLI a
way to toggle it the way `--mitigations spotlight:on,spotlight:off` does today
(`parseMitigations`/`splitMitigationSets` in `src/harness/runner.ts` / `cli.ts`).

## Metric definitions

- **Attack success rate (ASR)** — of the cases where `expect: block`, the fraction where the *model's
  output* satisfied the case's own `success` criteria (canary leaked, a regex matched, or an LLM judge's
  rubric was met). This is independent of whether the guard blocked; a suppressed output is scored as
  the attack failing, because it never reached anyone.
- **False-positive rate (FPR)** — of the cases where `expect: allow`, the fraction where the guard's
  action was `block`, `rewrite`, or `redact` (i.e. anything other than passing the request through
  unmodified). `redact` counts as a false positive even though it doesn't refuse outright, because it
  still altered a legitimate request.
- **Block rate** — recall of the guard against the attack set: of `expect: block` cases, how many the
  guard actually blocked (regardless of whether the model would have complied anyway).
- **Precision / Recall / F1 / MCC** — computed from the standard confusion matrix (`ConfusionMatrix` in
  `score.ts`) where "positive" = attack case, "predicted positive" = guard blocked. MCC is reported
  because it stays meaningful under the corpus's inherent class imbalance (83 attacks vs 44 benign);
  accuracy alone would not.
- **Escalation rate** — fraction of cases whose rules score landed inside the escalation band and
  therefore triggered an LLM-tier call.
- **Threshold sweep / ROC AUC** — `sweepThresholds()` replays the router's band logic at 21 evenly
  spaced `highThreshold` values (with `lowThreshold` trailing 0.3 behind), recomputing ASR/FPR/block
  rate/escalation rate at each point without re-running the corpus. AUC is the trapezoid-rule integral
  over (FPR, block rate) — the conventional ROC reading, where 1.0 is perfect separation and 0.5 is
  chance.
- **Bootstrap 95% CI** — non-parametric bootstrap (2,000 resamples, seeded `mulberry32` PRNG for
  reproducibility) over the 0/1 outcome vector (attack succeeded / benign blocked), reported alongside
  mean and standard deviation. Meaningful once `--repeat` is greater than 1; with `--repeat 1` it
  describes variance across the corpus's cases within one family, not across repeated trials.

## Open questions this harness is positioned to answer

- **Where should the escalation band actually sit?** The threshold sweep produces the raw material; a
  systematic sweep across all three shipped policies plus intermediate configurations, with live models
  and enough `--repeat` for tight confidence intervals, would produce a defensible recommended default —
  something this build's `--mock`-derived defaults are a reasonable starting guess for, not a final
  answer.
- **How much does each mitigation actually buy, per family?** `--mitigations spotlight:on,spotlight:off`
  isolates spotlighting's effect in aggregate; the same comparison broken out by attack family (does
  spotlighting help more against indirect injection than against direct role-hijack, as the mechanism
  would predict?) is a `scoreBy()` call away and not yet run at scale.
  the same is worth asking of sandwiching and of the two combined.
- **Does the rules/LLM split generalize across target models?** The harness scores the *target* model's
  compliance, not the judge's. Running the same matrix against multiple target models (both Groq and
  Gemini families) would show whether a model's general instruction-following strength correlates with
  its injection susceptibility, or whether they're independent.
- **How much of the corpus's ASR is attributable to the mock's crudeness versus a real model's?** This
  build validates the *pipeline* offline; the acceptance run against live models
  (`npm run harness -- --policy balanced --models <live-id> --limit 10`) is a spot check, not a full
  matrix, because of free-tier quota. A properly quota-budgeted full live run is the natural next step.
- **What is the minimal detector set that captures most of the achievable AUC?** With nine rules
  detectors and three LLM judges, an ablation (drop one detector at a time, rescore) would show which
  detectors are load-bearing and which are redundant with the LLM tier — useful both for latency
  optimization and for understanding where the rules tier's coverage actually comes from.
- **How does detection quality degrade as attacks are adversarially tuned against Aegis specifically**
  (as opposed to the hand-authored, publicly-documented-pattern corpus shipped here)? The corpus is a
  lower bound on robustness by construction; a red-team exercise that iterates against Aegis's actual
  responses would characterize the gap.
