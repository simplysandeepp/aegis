/**
 * The escalation router — the core research knob of the project.
 *
 * The rules tier is cheap, deterministic and always runs. Its combined score
 * partitions requests into three bands:
 *
 *      0                lowThreshold        highThreshold              1
 *      |-- confident allow --|-- ESCALATE to LLM --|-- confident block --|
 *          (no LLM call)        (one LLM call)         (no LLM call)
 *
 * Only the middle band costs a provider call. `escalatedToLlm` is recorded on
 * every decision so the harness can report the escalation rate and the
 * resulting latency and token savings against an always-LLM baseline — that
 * saving is the entire cost argument for the hybrid design.
 *
 * Both thresholds live in the policy, so the harness can sweep them and plot
 * the ASR-versus-FPR trade-off curve. Collapsing this into "always call the
 * LLM" would delete the measurement the project exists to make.
 */

import { detectorsFor } from './registry';
import { installDetectors } from './detectors';
import { mergeSpans, noisyOr, redactSpans } from './util';
import type {
  Action,
  Decision,
  DetectorResult,
  GuardContext,
  LlmJudge,
  MessagePart,
  Policy,
  Severity,
  Span,
  Stage,
  ToolCallRequest,
} from './types';
import { mostRestrictive } from './types';

export interface RunGuardOptions {
  stage: Stage;
  text: string;
  rawText?: string;
  parts?: MessagePart[];
  policy: Policy;
  policyHash: string;
  llm: LlmJudge;
  canary?: string;
  responseSchema?: unknown;
  toolCalls?: ToolCallRequest[];
  signal?: AbortSignal;
  /** Time already spent in the upstream provider, for the latency breakdown. */
  providerMs?: number;
  /**
   * Force the escalation decision. Used by the harness to measure the
   * always-LLM and never-LLM baselines against the hybrid.
   */
  forceEscalation?: 'always' | 'never';
}

/** An LLM judge that is never reachable — used for the never-escalate baseline. */
export const NULL_JUDGE: LlmJudge = {
  async classify() {
    return { ok: false, error: 'llm tier disabled for this run', modelId: 'none' };
  },
};

function weightFor(policy: Policy, r: DetectorResult): number {
  const cfg = policy.detectors[r.detectorId];
  const severityWeight = policy.severityWeights[r.severity] ?? 0.5;
  const detectorWeight = cfg?.weight ?? 1;
  return r.score * severityWeight * detectorWeight;
}

/** Noisy-OR over the weighted contributions of the triggered detectors. */
export function combineScores(policy: Policy, results: readonly DetectorResult[]): number {
  return noisyOr(results.filter((r) => r.triggered).map((r) => weightFor(policy, r)));
}

export type Band = 'allow' | 'escalate' | 'block';

export function bandFor(policy: Policy, score: number): Band {
  if (score >= policy.escalation.highThreshold) return 'block';
  if (score <= policy.escalation.lowThreshold) return 'allow';
  return 'escalate';
}

function actionFor(policy: Policy, results: readonly DetectorResult[]): Action {
  const actions = results
    .filter((r) => r.triggered)
    .map((r) => policy.severityActions[r.severity] ?? 'flag');
  return mostRestrictive(actions);
}

/** Spans that name something worth masking rather than merely suspicious. */
const REDACTABLE = /^(pii:|secret:|canary:|exfil:)/;

function redactableSpans(results: readonly DetectorResult[]): Span[] {
  const spans: Span[] = [];
  for (const r of results) {
    if (!r.triggered) continue;
    for (const s of r.spans) if (REDACTABLE.test(s.label)) spans.push(s);
  }
  return mergeSpans(spans);
}

export async function runGuard(opts: RunGuardOptions): Promise<Decision> {
  installDetectors();
  const t0 = performance.now();
  const { policy, stage } = opts;

  const ctx: GuardContext = {
    stage,
    text: opts.text,
    rawText: opts.rawText ?? opts.text,
    parts: opts.parts ?? [],
    policy,
    canary: opts.canary,
    responseSchema: opts.responseSchema,
    toolCalls: opts.toolCalls,
    llm: opts.llm,
    signal: opts.signal,
  };

  // --- tier 1: rules (cheap, deterministic, parallel) --------------------
  const rulesStart = performance.now();
  const rulesDetectors = detectorsFor(policy, stage, 'rules');
  const rulesResults = await Promise.all(rulesDetectors.map((d) => d.run(ctx)));
  const rulesMs = performance.now() - rulesStart;

  const rulesScore = combineScores(policy, rulesResults);

  // --- the escalation decision -------------------------------------------
  const naturalBand = bandFor(policy, rulesScore);
  const band: Band =
    opts.forceEscalation === 'always'
      ? 'escalate'
      : opts.forceEscalation === 'never'
        ? naturalBand === 'escalate'
          ? // Without an LLM the uncertain band has to fall back on the rules
            // verdict alone. Falling back to "allow" is the honest reading of
            // "the cheap tier was not confident enough to block".
            'allow'
          : naturalBand
        : naturalBand;

  const escalatedToLlm = band === 'escalate';

  let llmResults: DetectorResult[] = [];
  let llmMs = 0;
  let llmUnavailable = false;

  if (escalatedToLlm) {
    const llmStart = performance.now();
    const llmDetectors = detectorsFor(policy, stage, 'llm');
    llmResults = await Promise.all(llmDetectors.map((d) => d.run(ctx)));
    llmMs = performance.now() - llmStart;
    llmUnavailable = llmResults.some((r) => r.unavailable === true);
  }

  const results = [...rulesResults, ...llmResults];
  const finalScore = escalatedToLlm ? combineScores(policy, results) : rulesScore;

  // --- action ------------------------------------------------------------
  let action: Action;
  const reasons: string[] = [];

  if (band === 'block') {
    action = actionFor(policy, rulesResults);
    reasons.push(
      `Rules score ${rulesScore.toFixed(3)} >= highThreshold ${policy.escalation.highThreshold} — decided at the rules tier without an LLM call.`,
    );
  } else if (band === 'allow') {
    action = 'allow';
    reasons.push(
      `Rules score ${rulesScore.toFixed(3)} <= lowThreshold ${policy.escalation.lowThreshold} — decided at the rules tier without an LLM call.`,
    );
    // A low-band score can still contain a lone low-severity hit worth noting.
    const flagged = rulesResults.filter((r) => r.triggered);
    if (flagged.length > 0) {
      action = 'flag';
      reasons.push(
        `Below the escalation band but ${flagged.length} low-weight detector(s) fired: ${flagged.map((r) => r.detectorId).join(', ')}.`,
      );
    }
  } else {
    action = actionFor(policy, results);
    reasons.push(
      `Rules score ${rulesScore.toFixed(3)} is inside the escalation band (${policy.escalation.lowThreshold}, ${policy.escalation.highThreshold}) — escalated to the LLM tier.`,
    );
    if (llmUnavailable) {
      reasons.push(
        'The LLM tier was unavailable. The decision falls back to the rules tier and is recorded with llmUnavailable=true — it is not a clean allow.',
      );
    }
  }

  for (const r of results) {
    if (r.triggered) reasons.push(`${r.detectorId}: ${r.explanation}`);
  }

  // --- transformation ----------------------------------------------------
  let transformedText: string | undefined;
  if (action === 'redact') {
    const spans = redactableSpans(results);
    if (spans.length > 0) {
      transformedText = redactSpans(ctx.text, spans);
    } else {
      // Nothing maskable — a redact mapping with no spans must not silently
      // pass the original text through.
      action = 'block';
      reasons.push('Action was redact but no maskable spans were produced, so the request is blocked instead.');
    }
  } else if (action === 'rewrite') {
    transformedText = policy.refusalMessage;
  }

  const totalMs = performance.now() - t0;

  return {
    action,
    reasons,
    results,
    transformedText,
    escalatedToLlm,
    totalLatencyMs: totalMs,
    stage,
    rulesScore,
    finalScore,
    llmUnavailable,
    policyName: policy.name,
    policyHash: opts.policyHash,
    latency: {
      rulesMs,
      llmMs,
      providerMs: opts.providerMs ?? 0,
      totalMs,
    },
    tokensUsed: results.reduce((n, r) => n + (r.tokensUsed ?? 0), 0),
  };
}

export type { Severity };
