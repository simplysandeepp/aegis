/**
 * Core types for the Aegis policy engine.
 *
 * This module is pure TypeScript with no Next.js, no database and no provider
 * imports, so the whole engine can be unit-tested in isolation and reused
 * verbatim by both halves of the system: the gateway and the red-team harness.
 * There is exactly one implementation of policy — the harness measures the
 * same code path that protects live traffic.
 */

import type { ZodType } from 'zod';

/**
 * Taint label attached to every message part.
 *
 * `system` and `user` are what the operator and the human actually said.
 * `tool` and `retrieved` are attacker-reachable: a tool result or a retrieved
 * document can contain text written by whoever controls that data source, so
 * any instruction found there is data, never a command.
 */
export type Trust = 'system' | 'user' | 'tool' | 'retrieved';

/** Untrusted taint labels — content an attacker can plausibly control. */
export const UNTRUSTED_TRUST: readonly Trust[] = ['tool', 'retrieved'];

export function isUntrusted(trust: Trust): boolean {
  return UNTRUSTED_TRUST.includes(trust);
}

/** Which side of the model call a detector inspects. */
export type Stage = 'input' | 'output';

/**
 * Detector cost tier.
 * `rules` is deterministic, sub-millisecond and always runs.
 * `llm` costs a provider call and only runs inside the escalation band.
 */
export type Tier = 'rules' | 'llm';

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_ORDER: readonly Severity[] = ['low', 'medium', 'high', 'critical'];

export type Action = 'allow' | 'block' | 'redact' | 'rewrite' | 'flag';

/**
 * Action precedence, least to most restrictive. When several detectors fire,
 * the most restrictive mapped action wins.
 */
export const ACTION_ORDER: readonly Action[] = ['allow', 'flag', 'redact', 'rewrite', 'block'];

export function mostRestrictive(actions: readonly Action[]): Action {
  let best: Action = 'allow';
  for (const a of actions) {
    if (ACTION_ORDER.indexOf(a) > ACTION_ORDER.indexOf(best)) best = a;
  }
  return best;
}

/** Character offsets into the analyzed text, used for highlighting and redaction. */
export interface Span {
  start: number;
  end: number;
  label: string;
}

export interface DetectorResult {
  detectorId: string;
  triggered: boolean;
  /** Calibrated confidence in [0,1]. */
  score: number;
  severity: Severity;
  /** Machine-readable tags, e.g. ['injection:instruction-override']. */
  labels: string[];
  /** Char offsets into the analyzed text. */
  spans: Span[];
  /** Human-readable rationale, surfaced verbatim in the dashboard trace view. */
  explanation: string;
  latencyMs: number;
  /** LLM tier only. */
  tokensUsed?: number;
  /**
   * Set when an LLM-tier detector could not reach its provider. The decision
   * carries this upward as `llmUnavailable` so a dead provider is never
   * silently indistinguishable from a clean verdict.
   */
  unavailable?: boolean;
}

/** A single message in the conversation, carrying its taint label. */
export interface MessagePart {
  index: number;
  role: 'system' | 'user' | 'assistant' | 'tool';
  trust: Trust;
  text: string;
}

/** A tool call the model asked for, checked by `tool-call-policy`. */
export interface ToolCallRequest {
  id: string;
  name: string;
  /** Parsed arguments. Raw string kept for span reporting. */
  args: unknown;
  argsRaw: string;
}

/** Result of an LLM-tier classification, with failure made explicit. */
export type LlmClassifyResult<T> =
  | { ok: true; value: T; tokensUsed: number; modelId: string }
  | { ok: false; error: string; modelId: string };

/**
 * The provider surface the LLM-tier detectors are allowed to use.
 *
 * Deliberately tiny: it takes a Zod schema and returns either a validated
 * object or a named failure. It never throws, so a quota-exhausted provider
 * degrades into a traced non-verdict instead of an exception or a silent allow.
 */
export interface LlmJudge {
  classify<T>(opts: {
    schema: ZodType<T>;
    system: string;
    prompt: string;
    /** Overrides the policy's judge model. */
    modelId?: string;
    signal?: AbortSignal;
  }): Promise<LlmClassifyResult<T>>;
}

/** Everything a detector is allowed to look at. */
export interface GuardContext {
  stage: Stage;
  /**
   * The text under analysis. On the input stage this is the concatenation of
   * the analyzable message parts after sanitizing transforms; on the output
   * stage it is the model's completion. All `Span` offsets index into this.
   */
  text: string;
  /** The same text before unicode normalization / spotlighting. */
  rawText: string;
  /** Full conversation with taint labels. Empty on the output stage. */
  parts: MessagePart[];
  policy: Policy;
  /** Canary injected into the system prompt, if canary injection is enabled. */
  canary?: string;
  /** JSON Schema supplied by the caller via `response_format`. */
  responseSchema?: unknown;
  /** Tool calls requested by the model, for the output stage. */
  toolCalls?: ToolCallRequest[];
  llm: LlmJudge;
  signal?: AbortSignal;
}

export interface Detector {
  id: string;
  name: string;
  stage: Stage[];
  tier: Tier;
  /** One-line description shown in the dashboard and RESEARCH.md. */
  description: string;
  run(ctx: GuardContext): Promise<DetectorResult>;
}

/**
 * A sanitizing transform that runs before detection (unicode hygiene) or a
 * prompt-level mitigation that restructures the conversation (spotlighting,
 * sandwiching). Mitigations are togglable per policy so the harness can
 * measure each one's effect in isolation.
 */
export interface Mitigation {
  id: string;
  name: string;
  description: string;
}

export interface LatencyBreakdown {
  rulesMs: number;
  llmMs: number;
  /** Time spent in the upstream provider. 0 for a standalone guard check. */
  providerMs: number;
  totalMs: number;
}

export interface Decision {
  action: Action;
  reasons: string[];
  results: DetectorResult[];
  /** Present when the action is `redact` or `rewrite`. */
  transformedText?: string;
  escalatedToLlm: boolean;
  totalLatencyMs: number;

  // --- attribution and measurement (consumed by the harness + dashboard) ---
  stage: Stage;
  /** Combined rules-tier score in [0,1] that drove the escalation choice. */
  rulesScore: number;
  /** Combined score after the LLM tier arbitrated. Absent if not escalated. */
  finalScore: number;
  /** True when an LLM-tier detector was asked but its provider failed. */
  llmUnavailable: boolean;
  policyName: string;
  /** SHA-256 of the canonicalized policy, so a result stays attributable. */
  policyHash: string;
  latency: LatencyBreakdown;
  tokensUsed: number;
}

// ---------------------------------------------------------------------------
// Policy
// ---------------------------------------------------------------------------

/** A JSON-Schema subset used for tool arguments and `response_format`. */
export interface JsonSchemaNode {
  type?: 'object' | 'array' | 'string' | 'number' | 'integer' | 'boolean' | 'null';
  properties?: Record<string, JsonSchemaNode>;
  required?: string[];
  items?: JsonSchemaNode;
  enum?: unknown[];
  additionalProperties?: boolean;
  description?: string;
  /** Pattern applied to string values. */
  pattern?: string;
  minimum?: number;
  maximum?: number;
}

export interface TopicRule {
  id: string;
  /** Case-insensitive keywords; any hit counts. */
  keywords?: string[];
  /** Regex sources, compiled case-insensitively. */
  patterns?: string[];
  severity: Severity;
  description: string;
}

export interface Policy {
  name: string;
  version: string;
  description: string;

  /** Detector id -> per-policy settings. A detector absent here is disabled. */
  detectors: Record<string, { enabled: boolean; weight?: number; severityOverride?: Severity }>;

  /** Severity -> action taken when a detector at that severity fires. */
  severityActions: Record<Severity, Action>;

  /** Severity -> contribution weight when combining detector scores. */
  severityWeights: Record<Severity, number>;

  escalation: {
    /** At or above this combined rules score, block without asking the LLM. */
    highThreshold: number;
    /** At or below this, allow without asking the LLM. */
    lowThreshold: number;
    /** Model id for LLM-tier detectors. Defaults to config/models.ts judge. */
    judgeModel?: string;
  };

  /** Hosts the model's output is permitted to link to. Supports `*.example.com`. */
  urlAllowlist: string[];

  tools: {
    allowlist: string[];
    /** Tool name -> JSON-Schema subset for its arguments. */
    schemas: Record<string, JsonSchemaNode>;
  };

  topics: {
    deny: TopicRule[];
    /**
     * When non-empty, content matching none of these is treated as
     * off-topic and flagged at `offTopicSeverity`.
     */
    allow: TopicRule[];
    offTopicSeverity: Severity;
  };

  /** Natural-language policy document handed to `llm-policy-judge`. */
  llmPolicyText: string;

  mitigations: {
    /** NFKC-normalize and strip invisible characters before detection. */
    unicodeNormalize: boolean;
    /** Wrap untrusted content in random delimiters + datamark it. */
    spotlight: boolean;
    /** Restate the real instruction after untrusted content. */
    sandwich: boolean;
    /** Inject a canary into the system prompt to detect prompt leakage. */
    canary: boolean;
  };

  /**
   * Sliding-window size for the streaming output guard, in characters.
   * Larger windows catch leaks that span chunk boundaries at the cost of
   * time-to-first-token. See ARCHITECTURE.md for measured numbers.
   */
  streamWindowChars: number;

  /** Returned to the caller when the action is `block`. */
  refusalMessage: string;
}

/** A policy plus its content hash. */
export interface LoadedPolicy {
  policy: Policy;
  hash: string;
}
