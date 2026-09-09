/** Harness data model. */

import type { Decision } from '../lib/guard/types';

export type Delivery = 'direct' | 'indirect-doc' | 'tool-result' | 'multi-turn';
export type Expect = 'block' | 'allow';

export interface SuccessCriteria {
  /** The canary planted in the system prompt appears in the output. */
  canaryLeak?: boolean;
  /** The output matches a pattern only a compromised model would emit. */
  regex?: string;
  /** Natural-language rubric for the LLM success judge. */
  judgeRubric?: string;
}

export interface CorpusCase {
  id: string;
  family: string;
  delivery: Delivery;
  severity: string;
  /** What the GUARD is expected to do. */
  expect: Expect;
  payload: string;
  turns: string[];
  success: SuccessCriteria;
  source: string;
  notes?: string;
  /** Taint label for the payload. Defaults from `delivery`. */
  trust?: 'user' | 'tool' | 'retrieved';
}

export interface MitigationSet {
  spotlight: boolean;
  sandwich: boolean;
  /** Canonical string used in the cache key and the report. */
  key: string;
}

export interface CaseResult {
  caseId: string;
  family: string;
  delivery: Delivery;
  expect: Expect;
  policyName: string;
  policyHash: string;
  model: string;
  mitigations: string;
  repeatIdx: number;

  /** What the guard did. */
  guardAction: string;
  blocked: boolean;
  /** Did the attack succeed end-to-end, judged by the case's own criteria. */
  attackSucceeded: boolean;
  successBy?: string;

  escalated: boolean;
  llmUnavailable: boolean;
  rulesScore: number;
  finalScore: number;

  rulesMs: number;
  llmMs: number;
  providerMs: number;
  totalMs: number;
  ttftMs?: number;
  /** Total tokens: judge + provider. */
  tokensUsed: number;
  /** LLM-tier (escalation) tokens only — the cost the two-tier design saves. */
  judgeTokens: number;
  /** Upstream model tokens, which every configuration pays equally. */
  providerTokens: number;

  /** Full trace for the dashboard's case view. */
  inputDecision: Decision;
  outputDecision?: Decision;
  modelOutput: string;
  preparedText: string;
  error?: string;
  cached: boolean;
}

export interface RunMeta {
  runId: string;
  harnessVersion: string;
  startedAt: string;
  finishedAt?: string;
  gitSha: string;
  gitDirty: boolean;
  corpusHash: string;
  corpusFiles: string[];
  seed: string;
  argv: string[];
  mock: boolean;
  nodeVersion: string;
  models: Array<{ id: string; provider: string; providerId: string; unverified: boolean }>;
  /** Full policy JSON, so a result stays reproducible after the file changes. */
  policies: Record<string, unknown>;
  limiter?: Record<string, number>;
}

export interface Matrix {
  policies: string[];
  models: string[];
  mitigations: MitigationSet[];
  repeat: number;
  limit?: number;
  families?: string[];
}
