/**
 * Policy loading, validation, hashing, and the JSON-Schema -> Zod bridge.
 *
 * Every policy is versioned and content-hashed. The hash is stamped on every
 * decision so a result in `runs/` stays attributable to the exact configuration
 * that produced it, even after the policy file changes.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { z } from 'zod';
import { canonicalJson } from './util';
import type { JsonSchemaNode, LoadedPolicy, Policy } from './types';

const severitySchema = z.enum(['low', 'medium', 'high', 'critical']);
const actionSchema = z.enum(['allow', 'block', 'redact', 'rewrite', 'flag']);

const jsonSchemaNodeSchema: z.ZodType<JsonSchemaNode> = z.lazy(() =>
  z.object({
    type: z.enum(['object', 'array', 'string', 'number', 'integer', 'boolean', 'null']).optional(),
    properties: z.record(z.string(), jsonSchemaNodeSchema).optional(),
    required: z.array(z.string()).optional(),
    items: jsonSchemaNodeSchema.optional(),
    enum: z.array(z.unknown()).optional(),
    additionalProperties: z.boolean().optional(),
    description: z.string().optional(),
    pattern: z.string().optional(),
    minimum: z.number().optional(),
    maximum: z.number().optional(),
  }),
);

const topicRuleSchema = z.object({
  id: z.string(),
  keywords: z.array(z.string()).optional(),
  patterns: z.array(z.string()).optional(),
  severity: severitySchema,
  description: z.string(),
});

export const policySchema = z.object({
  name: z.string().min(1),
  version: z.string().min(1),
  description: z.string(),
  detectors: z.record(
    z.string(),
    z.object({
      enabled: z.boolean(),
      weight: z.number().min(0).max(1).optional(),
      severityOverride: severitySchema.optional(),
    }),
  ),
  severityActions: z.object({
    low: actionSchema,
    medium: actionSchema,
    high: actionSchema,
    critical: actionSchema,
  }),
  severityWeights: z.object({
    low: z.number().min(0).max(1),
    medium: z.number().min(0).max(1),
    high: z.number().min(0).max(1),
    critical: z.number().min(0).max(1),
  }),
  escalation: z
    .object({
      highThreshold: z.number().min(0).max(1),
      lowThreshold: z.number().min(0).max(1),
      judgeModel: z.string().optional(),
    })
    .refine((e) => e.lowThreshold <= e.highThreshold, {
      message: 'escalation.lowThreshold must be <= escalation.highThreshold',
    }),
  urlAllowlist: z.array(z.string()),
  tools: z.object({
    allowlist: z.array(z.string()),
    schemas: z.record(z.string(), jsonSchemaNodeSchema),
  }),
  topics: z.object({
    deny: z.array(topicRuleSchema),
    allow: z.array(topicRuleSchema),
    offTopicSeverity: severitySchema,
  }),
  llmPolicyText: z.string(),
  mitigations: z.object({
    unicodeNormalize: z.boolean(),
    spotlight: z.boolean(),
    sandwich: z.boolean(),
    canary: z.boolean(),
  }),
  streamWindowChars: z.number().int().min(0).max(8192),
  refusalMessage: z.string(),
}) satisfies z.ZodType<Policy, unknown>;

export function hashPolicy(policy: Policy): string {
  return createHash('sha256').update(canonicalJson(policy)).digest('hex').slice(0, 16);
}

export function parsePolicy(raw: unknown): LoadedPolicy {
  const policy = policySchema.parse(raw) as Policy;
  return { policy, hash: hashPolicy(policy) };
}

const POLICY_DIR = resolve(process.cwd(), 'policies');

const cache = new Map<string, LoadedPolicy>();

export function policyDir(): string {
  return POLICY_DIR;
}

export function listPolicyNames(): string[] {
  if (!existsSync(POLICY_DIR)) return [];
  return readdirSync(POLICY_DIR)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''))
    .sort();
}

export class UnknownPolicyError extends Error {
  constructor(name: string) {
    super(
      `Unknown policy "${name}". Available: ${listPolicyNames().join(', ') || '(none found in policies/)'}`,
    );
    this.name = 'UnknownPolicyError';
  }
}

export function loadPolicy(name: string): LoadedPolicy {
  const cached = cache.get(name);
  if (cached) return cached;
  const file = join(POLICY_DIR, `${name}.json`);
  if (!existsSync(file)) throw new UnknownPolicyError(name);
  const loaded = parsePolicy(JSON.parse(readFileSync(file, 'utf8')));
  cache.set(name, loaded);
  return loaded;
}

/** Test/harness helper: derive a variant policy without touching disk. */
export function withOverrides(base: Policy, patch: DeepPartial<Policy>): LoadedPolicy {
  const merged = deepMerge(base, patch) as Policy;
  return { policy: merged, hash: hashPolicy(merged) };
}

export type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K];
};

function deepMerge(a: unknown, b: unknown): unknown {
  if (b === undefined) return a;
  if (Array.isArray(b) || b === null || typeof b !== 'object') return b;
  if (a === null || typeof a !== 'object' || Array.isArray(a)) return b;
  const out: Record<string, unknown> = { ...(a as Record<string, unknown>) };
  for (const [k, v] of Object.entries(b as Record<string, unknown>)) {
    out[k] = deepMerge((a as Record<string, unknown>)[k], v);
  }
  return out;
}

// ---------------------------------------------------------------------------
// JSON Schema -> Zod
// ---------------------------------------------------------------------------

/**
 * Converts the JSON-Schema subset used in policies (tool argument schemas) and
 * in OpenAI `response_format.json_schema` into a Zod schema, so both the
 * `tool-call-policy` and `output-schema` detectors validate through Zod and can
 * report precise, path-qualified errors.
 */
export function jsonSchemaToZod(node: JsonSchemaNode | undefined): z.ZodTypeAny {
  if (!node || typeof node !== 'object') return z.unknown();

  if (Array.isArray(node.enum) && node.enum.length > 0) {
    const values = node.enum;
    return z.custom<unknown>((v) => values.some((e) => Object.is(e, v) || e === v), {
      message: `expected one of ${JSON.stringify(values)}`,
    });
  }

  switch (node.type) {
    case 'string': {
      let s = z.string();
      if (node.pattern) {
        try {
          s = s.regex(new RegExp(node.pattern));
        } catch {
          /* an invalid pattern in a policy must not crash the gateway */
        }
      }
      return s;
    }
    case 'integer': {
      let n = z.number().int();
      if (node.minimum !== undefined) n = n.min(node.minimum);
      if (node.maximum !== undefined) n = n.max(node.maximum);
      return n;
    }
    case 'number': {
      let n = z.number();
      if (node.minimum !== undefined) n = n.min(node.minimum);
      if (node.maximum !== undefined) n = n.max(node.maximum);
      return n;
    }
    case 'boolean':
      return z.boolean();
    case 'null':
      return z.null();
    case 'array':
      return z.array(jsonSchemaToZod(node.items));
    case 'object': {
      const shape: Record<string, z.ZodTypeAny> = {};
      const required = new Set(node.required ?? []);
      for (const [k, v] of Object.entries(node.properties ?? {})) {
        const inner = jsonSchemaToZod(v);
        shape[k] = required.has(k) ? inner : inner.optional();
      }
      const obj = z.object(shape);
      return node.additionalProperties === false ? obj.strict() : obj;
    }
    default:
      return z.unknown();
  }
}

/** Flatten a ZodError into readable `path: message` lines. */
export function formatZodIssues(err: z.ZodError): string[] {
  return err.issues.map((i) => {
    const path = i.path.length ? i.path.join('.') : '(root)';
    return `${path}: ${i.message}`;
  });
}
