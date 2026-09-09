/** Shared fixtures for the detector and router tests. */

import { loadPolicy, withOverrides } from '@/lib/guard/policy';
import { installDetectors } from '@/lib/guard/detectors';
import { runGuard } from '@/lib/guard/router';
import { createMockJudge } from '@/lib/providers';
import type {
  Decision,
  Detector,
  DetectorResult,
  GuardContext,
  LlmJudge,
  MessagePart,
  Policy,
  Stage,
  ToolCallRequest,
  Trust,
} from '@/lib/guard/types';

installDetectors();

export function policy(name: 'permissive' | 'balanced' | 'strict' = 'balanced'): Policy {
  return loadPolicy(name).policy;
}

export function policyHash(name: 'permissive' | 'balanced' | 'strict' = 'balanced'): string {
  return loadPolicy(name).hash;
}

export interface CtxOptions {
  stage?: Stage;
  rawText?: string;
  parts?: MessagePart[];
  trust?: Trust;
  policy?: Policy;
  canary?: string;
  responseSchema?: unknown;
  toolCalls?: ToolCallRequest[];
  llm?: LlmJudge;
}

export function ctx(text: string, o: CtxOptions = {}): GuardContext {
  const trust = o.trust ?? 'user';
  return {
    stage: o.stage ?? 'input',
    text,
    rawText: o.rawText ?? text,
    parts: o.parts ?? [{ index: 0, role: trust === 'tool' ? 'tool' : 'user', trust, text }],
    policy: o.policy ?? policy(),
    canary: o.canary,
    responseSchema: o.responseSchema,
    toolCalls: o.toolCalls,
    llm: o.llm ?? createMockJudge(),
  };
}

export async function run(d: Detector, text: string, o: CtxOptions = {}): Promise<DetectorResult> {
  return d.run(ctx(text, o));
}

/** Wraps an LlmJudge and counts how many times it was consulted. */
export function countingJudge(inner: LlmJudge = createMockJudge()): LlmJudge & { calls: number } {
  const j = {
    calls: 0,
    async classify(args: Parameters<LlmJudge['classify']>[0]) {
      j.calls++;
      return inner.classify(args);
    },
  };
  return j as LlmJudge & { calls: number };
}

/** An LlmJudge that always fails, for the degraded-path tests. */
export function failingJudge(error = 'simulated 503 from provider'): LlmJudge {
  return {
    async classify() {
      return { ok: false, error, modelId: 'test' };
    },
  };
}

export async function guard(
  text: string,
  o: CtxOptions & { policyName?: 'permissive' | 'balanced' | 'strict' } = {},
): Promise<Decision> {
  const name = o.policyName ?? 'balanced';
  const p = o.policy ?? policy(name);
  const trust = o.trust ?? 'user';
  return runGuard({
    stage: o.stage ?? 'input',
    text,
    rawText: o.rawText ?? text,
    parts: o.parts ?? [{ index: 0, role: trust === 'tool' ? 'tool' : 'user', trust, text }],
    policy: p,
    policyHash: policyHash(name),
    llm: o.llm ?? createMockJudge(),
    canary: o.canary,
    responseSchema: o.responseSchema,
    toolCalls: o.toolCalls,
  });
}

/** Build a policy variant, e.g. to force a specific escalation band. */
export function variant(base: Policy, patch: Parameters<typeof withOverrides>[1]) {
  return withOverrides(base, patch);
}
