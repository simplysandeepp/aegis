/**
 * SQLite schema (Drizzle).
 *
 * Two record families:
 *   decisions  — every gateway request, for the /traffic log and the trace view
 *   runs/results — harness output, mirrored from runs/<id>/results.jsonl
 *
 * Raw prompt and completion text is NOT stored by default; only SHA-256
 * hashes. Set AEGIS_LOG_RAW=1 to capture the text for local research.
 */

import { sqliteTable, text, integer, real, index } from 'drizzle-orm/sqlite-core';

export const decisions = sqliteTable(
  'decisions',
  {
    id: text('id').primaryKey(),
    createdAt: integer('created_at').notNull(),
    /** 'gateway' | 'guard-api' | 'harness' */
    source: text('source').notNull(),
    stage: text('stage').notNull(), // input | output
    policyName: text('policy_name').notNull(),
    policyHash: text('policy_hash').notNull(),
    model: text('model').notNull(),
    action: text('action').notNull(),
    escalated: integer('escalated').notNull(), // 0/1
    llmUnavailable: integer('llm_unavailable').notNull(),
    rulesScore: real('rules_score').notNull(),
    finalScore: real('final_score').notNull(),
    /** SHA-256 of the analysed text. */
    textHash: text('text_hash').notNull(),
    /** Populated only when AEGIS_LOG_RAW=1. */
    rawText: text('raw_text'),
    rawOutput: text('raw_output'),
    reasons: text('reasons').notNull(), // JSON string[]
    results: text('results').notNull(), // JSON DetectorResult[]
    labels: text('labels').notNull(), // JSON string[] flattened, for filtering
    rulesMs: real('rules_ms').notNull(),
    llmMs: real('llm_ms').notNull(),
    providerMs: real('provider_ms').notNull(),
    totalMs: real('total_ms').notNull(),
    tokensUsed: integer('tokens_used').notNull(),
    providerError: text('provider_error'),
    /** Harness linkage, null for live traffic. */
    runId: text('run_id'),
    caseId: text('case_id'),
  },
  (t) => [
    index('idx_decisions_created').on(t.createdAt),
    index('idx_decisions_policy').on(t.policyName),
    index('idx_decisions_action').on(t.action),
    index('idx_decisions_run').on(t.runId),
  ],
);

export const runs = sqliteTable(
  'runs',
  {
    id: text('id').primaryKey(),
    createdAt: integer('created_at').notNull(),
    finishedAt: integer('finished_at'),
    /** Full provenance blob: git sha, dirty flag, seed, corpus hash, argv… */
    meta: text('meta').notNull(),
    /** JSON: policies, models, mitigations, repeat, limit */
    matrix: text('matrix').notNull(),
    /** JSON ScoreReport */
    scores: text('scores'),
    totalCases: integer('total_cases').notNull(),
    completedCases: integer('completed_cases').notNull(),
    tokensUsed: integer('tokens_used').notNull(),
    mock: integer('mock').notNull(),
  },
  (t) => [index('idx_runs_created').on(t.createdAt)],
);

export const results = sqliteTable(
  'results',
  {
    id: text('id').primaryKey(),
    runId: text('run_id').notNull(),
    caseId: text('case_id').notNull(),
    family: text('family').notNull(),
    delivery: text('delivery').notNull(),
    expect: text('expect').notNull(), // block | allow
    policyName: text('policy_name').notNull(),
    policyHash: text('policy_hash').notNull(),
    model: text('model').notNull(),
    mitigations: text('mitigations').notNull(),
    repeatIdx: integer('repeat_idx').notNull(),
    /** Did the guard block/transform it? */
    guardAction: text('guard_action').notNull(),
    blocked: integer('blocked').notNull(),
    /** Did the ATTACK succeed end-to-end (canary leak / regex / judge)? */
    attackSucceeded: integer('attack_succeeded').notNull(),
    escalated: integer('escalated').notNull(),
    llmUnavailable: integer('llm_unavailable').notNull(),
    rulesScore: real('rules_score').notNull(),
    finalScore: real('final_score').notNull(),
    rulesMs: real('rules_ms').notNull(),
    llmMs: real('llm_ms').notNull(),
    providerMs: real('provider_ms').notNull(),
    totalMs: real('total_ms').notNull(),
    ttftMs: real('ttft_ms'),
    tokensUsed: integer('tokens_used').notNull(),
    /** JSON blob of the full trace: decision, output, detector results. */
    trace: text('trace').notNull(),
    error: text('error'),
  },
  (t) => [
    index('idx_results_run').on(t.runId),
    index('idx_results_family').on(t.family),
    index('idx_results_case').on(t.caseId),
  ],
);

export type DecisionRow = typeof decisions.$inferSelect;
export type RunRow = typeof runs.$inferSelect;
export type ResultRow = typeof results.$inferSelect;
