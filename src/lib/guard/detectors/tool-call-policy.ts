/**
 * Tool-call gating.
 *
 * Three independent checks per requested call:
 *   1. the tool is on the policy allowlist at all;
 *   2. its arguments validate against the policy's Zod schema for that tool;
 *   3. its arguments do not carry text that came from tainted (`tool` /
 *      `retrieved`) content.
 *
 * Check 3 is the one that matters for injection. A model that has read a
 * poisoned document will happily pass a string lifted straight out of that
 * document into a tool call — that is how an indirect injection becomes an
 * action in the world rather than just some misleading text.
 */

import { defineDetector, noHit } from '../registry';
import { formatZodIssues, jsonSchemaToZod } from '../policy';
import { isUntrusted } from '../types';
import type { Severity, Span } from '../types';
import { z } from 'zod';

/** Distinctive substrings lifted from untrusted parts, for taint matching. */
function taintedFragments(parts: { trust: string; text: string }[]): string[] {
  const out: string[] = [];
  for (const p of parts) {
    if (!isUntrusted(p.trust as never)) continue;
    // Sentence-ish and token-ish fragments long enough to be distinctive.
    for (const frag of p.text.split(/[\n.!?;]+/)) {
      const t = frag.trim();
      if (t.length >= 16) out.push(t.toLowerCase());
    }
    for (const tok of p.text.match(/\b[\w@:/.+-]{12,}\b/g) ?? []) {
      out.push(tok.toLowerCase());
    }
  }
  return out;
}

export const toolCallPolicyDetector = defineDetector({
  id: 'tool-call-policy',
  name: 'Tool-call policy',
  description:
    'Validates each requested tool call against the policy tool allowlist and per-tool Zod argument schema, and flags calls whose arguments contain text originating in tainted tool/retrieved content.',
  stage: ['output'],
  tier: 'rules',
  defaultSeverity: 'high',
  async detect(ctx) {
    const calls = ctx.toolCalls ?? [];
    if (calls.length === 0) return noHit('The model requested no tool calls.');

    const { allowlist, schemas } = ctx.policy.tools;
    const labels = new Set<string>();
    const spans: Span[] = [];
    const problems: string[] = [];
    let severity: Severity = 'low';
    let score = 0;

    const fragments = taintedFragments(ctx.parts);

    for (const call of calls) {
      if (!allowlist.includes(call.name)) {
        labels.add('tool:not-allowlisted');
        problems.push(`"${call.name}" is not on the tool allowlist (${allowlist.join(', ') || 'empty'})`);
        severity = 'critical';
        score = Math.max(score, 0.95);
        continue;
      }

      const schemaNode = schemas[call.name];
      if (schemaNode) {
        const result = jsonSchemaToZod(schemaNode).safeParse(call.args);
        if (!result.success) {
          const issues = formatZodIssues(result.error as z.ZodError);
          labels.add('tool:invalid-arguments');
          problems.push(`"${call.name}" arguments failed validation — ${issues.join('; ')}`);
          if (rank(severity) < rank('high')) severity = 'high';
          score = Math.max(score, 0.8);
        }
      }

      const argsLower = call.argsRaw.toLowerCase();
      const tainted = fragments.filter((f) => f.length >= 16 && argsLower.includes(f));
      if (tainted.length > 0) {
        labels.add('tool:tainted-arguments');
        problems.push(
          `"${call.name}" arguments contain ${tainted.length} fragment(s) lifted from untrusted tool/retrieved content`,
        );
        if (rank(severity) < rank('critical')) severity = 'critical';
        score = Math.max(score, 0.9);
        spans.push({ start: 0, end: Math.min(call.argsRaw.length, 200), label: 'tool:tainted-arguments' });
      }
    }

    if (problems.length === 0) {
      return noHit(`All ${calls.length} tool call(s) are allowlisted, schema-valid and free of tainted arguments.`);
    }

    return {
      triggered: true,
      score,
      severity,
      labels: [...labels],
      spans,
      explanation: `Tool-call policy violations: ${problems.join('. ')}.`,
    };
  },
});

function rank(s: Severity): number {
  return ['low', 'medium', 'high', 'critical'].indexOf(s);
}
