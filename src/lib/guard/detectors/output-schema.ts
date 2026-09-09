/**
 * Output schema conformance.
 *
 * When the caller supplied `response_format: { type: 'json_schema', ... }`, the
 * output is validated against that schema through Zod and every validation
 * error is reported with its path. Beyond correctness this is a security
 * signal: a successfully injected model very often abandons the requested
 * output shape in order to say whatever the attacker asked it to say.
 */

import { defineDetector, noHit } from '../registry';
import { formatZodIssues, jsonSchemaToZod } from '../policy';
import type { JsonSchemaNode } from '../types';
import { z } from 'zod';

/** Pull JSON out of a response that may be fenced or have prose around it. */
export function extractJson(text: string): { ok: true; value: unknown } | { ok: false; error: string } {
  const trimmed = text.trim();
  const candidates: string[] = [trimmed];

  const fence = /```(?:json)?\s*([\s\S]*?)```/i.exec(trimmed);
  if (fence?.[1]) candidates.unshift(fence[1].trim());

  const first = trimmed.search(/[[{]/);
  const last = Math.max(trimmed.lastIndexOf('}'), trimmed.lastIndexOf(']'));
  if (first !== -1 && last > first) candidates.push(trimmed.slice(first, last + 1));

  for (const c of candidates) {
    try {
      return { ok: true, value: JSON.parse(c) };
    } catch {
      /* try the next candidate */
    }
  }
  return { ok: false, error: 'output is not parseable JSON' };
}

export const outputSchemaDetector = defineDetector({
  id: 'output-schema',
  name: 'Output schema conformance',
  description:
    'When the caller supplied a JSON schema via response_format, validates the model output against it with Zod and reports the exact path-qualified validation errors.',
  stage: ['output'],
  tier: 'rules',
  defaultSeverity: 'medium',
  async detect(ctx) {
    const schemaNode = ctx.responseSchema as JsonSchemaNode | undefined;
    if (!schemaNode) {
      return noHit('Caller did not supply a response_format schema, so there is nothing to validate against.');
    }

    const parsed = extractJson(ctx.text);
    if (!parsed.ok) {
      return {
        triggered: true,
        score: 0.7,
        severity: 'medium' as const,
        labels: ['schema:unparseable'],
        spans: [{ start: 0, end: Math.min(ctx.text.length, 200), label: 'schema:unparseable' }],
        explanation: `A JSON schema was requested but the ${parsed.error}.`,
      };
    }

    const zodSchema = jsonSchemaToZod(schemaNode);
    const result = zodSchema.safeParse(parsed.value);
    if (result.success) {
      return noHit('Output is valid JSON and conforms to the caller-supplied schema.');
    }

    const issues = formatZodIssues(result.error as z.ZodError);
    return {
      triggered: true,
      score: Math.min(0.9, 0.5 + 0.08 * issues.length),
      severity: 'medium' as const,
      labels: ['schema:violation'],
      spans: [{ start: 0, end: Math.min(ctx.text.length, 200), label: 'schema:violation' }],
      explanation:
        `Output does not conform to the requested schema (${issues.length} error${issues.length === 1 ? '' : 's'}): ` +
        issues.slice(0, 8).join('; ') +
        (issues.length > 8 ? ` …and ${issues.length - 8} more` : ''),
    };
  },
});
