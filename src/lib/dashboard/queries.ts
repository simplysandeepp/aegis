/** Server-side reads for the dashboard. */

import 'server-only';
import { desc, eq, and, like, sql } from 'drizzle-orm';
import { getDb, decisions, results, runs } from '../db';
import type { ScoreReport } from '../../harness/score';
import type { CaseResult, RunMeta } from '../../harness/types';

export interface RunSummary {
  id: string;
  createdAt: number;
  finishedAt: number | null;
  mock: boolean;
  totalCases: number;
  tokensUsed: number;
  meta: RunMeta;
  scores: ScoreReport | null;
}

function safeParse<T>(s: string | null): T | null {
  if (!s) return null;
  try {
    return JSON.parse(s) as T;
  } catch {
    return null;
  }
}

export function listRuns(limit = 25): RunSummary[] {
  const rows = getDb().select().from(runs).orderBy(desc(runs.createdAt)).limit(limit).all();
  return rows.map((r) => ({
    id: r.id,
    createdAt: r.createdAt,
    finishedAt: r.finishedAt,
    mock: r.mock === 1,
    totalCases: r.totalCases,
    tokensUsed: r.tokensUsed,
    meta: safeParse<RunMeta>(r.meta) ?? ({} as RunMeta),
    scores: safeParse<ScoreReport>(r.scores),
  }));
}

export function getRun(id: string): RunSummary | undefined {
  return listRuns(500).find((r) => r.id === id);
}

export interface ResultRowLite {
  id: string;
  caseId: string;
  family: string;
  delivery: string;
  expect: string;
  policyName: string;
  model: string;
  mitigations: string;
  repeatIdx: number;
  guardAction: string;
  blocked: boolean;
  attackSucceeded: boolean;
  escalated: boolean;
  llmUnavailable: boolean;
  rulesScore: number;
  finalScore: number;
  totalMs: number;
  rulesMs: number;
  llmMs: number;
  providerMs: number;
  tokensUsed: number;
  error: string | null;
}

export function getRunResults(runId: string): ResultRowLite[] {
  const rows = getDb().select().from(results).where(eq(results.runId, runId)).all();
  return rows.map((r) => ({
    id: r.id,
    caseId: r.caseId,
    family: r.family,
    delivery: r.delivery,
    expect: r.expect,
    policyName: r.policyName,
    model: r.model,
    mitigations: r.mitigations,
    repeatIdx: r.repeatIdx,
    guardAction: r.guardAction,
    blocked: r.blocked === 1,
    attackSucceeded: r.attackSucceeded === 1,
    escalated: r.escalated === 1,
    llmUnavailable: r.llmUnavailable === 1,
    rulesScore: r.rulesScore,
    finalScore: r.finalScore,
    totalMs: r.totalMs,
    rulesMs: r.rulesMs,
    llmMs: r.llmMs,
    providerMs: r.providerMs,
    tokensUsed: r.tokensUsed,
    error: r.error,
  }));
}

export interface CaseTrace {
  row: ResultRowLite;
  trace: {
    inputDecision: CaseResult['inputDecision'];
    outputDecision?: CaseResult['outputDecision'];
    modelOutput: string;
    preparedText: string;
    successBy?: string;
  };
}

export function getCaseTrace(runId: string, caseId: string): CaseTrace | undefined {
  const row = getDb()
    .select()
    .from(results)
    .where(and(eq(results.runId, runId), eq(results.caseId, caseId)))
    .get();
  if (!row) return undefined;
  const trace = safeParse<CaseTrace['trace']>(row.trace);
  if (!trace) return undefined;
  const lite = getRunResults(runId).find((r) => r.id === row.id);
  return lite ? { row: lite, trace } : undefined;
}

export interface TrafficFilter {
  policy?: string;
  action?: string;
  detector?: string;
  limit?: number;
}

export function listDecisions(f: TrafficFilter = {}) {
  const db = getDb();
  const conds = [];
  if (f.policy) conds.push(eq(decisions.policyName, f.policy));
  if (f.action) conds.push(eq(decisions.action, f.action));
  if (f.detector) conds.push(like(decisions.results, `%"${f.detector}"%`));

  const q = db
    .select()
    .from(decisions)
    .where(conds.length ? and(...conds) : undefined)
    .orderBy(desc(decisions.createdAt))
    .limit(f.limit ?? 200);

  return q.all().map((d) => ({
    ...d,
    escalated: d.escalated === 1,
    llmUnavailable: d.llmUnavailable === 1,
    labels: safeParse<string[]>(d.labels) ?? [],
    reasons: safeParse<string[]>(d.reasons) ?? [],
    resultsParsed: safeParse<CaseResult['inputDecision']['results']>(d.results) ?? [],
  }));
}

export function decisionFacets() {
  const db = getDb();
  const policies = db
    .select({ v: decisions.policyName, n: sql<number>`count(*)` })
    .from(decisions)
    .groupBy(decisions.policyName)
    .all();
  const actions = db
    .select({ v: decisions.action, n: sql<number>`count(*)` })
    .from(decisions)
    .groupBy(decisions.action)
    .all();
  return { policies, actions };
}
