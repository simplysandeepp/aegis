/** Deny/allow topic rules loaded from the active policy configuration. */

import { defineDetector, noHit } from '../registry';
import { escapeRe, matchSpans, mergeSpans } from '../util';
import type { Severity, Span, TopicRule } from '../types';

function ruleSpans(text: string, rule: TopicRule): Span[] {
  const spans: Span[] = [];
  for (const kw of rule.keywords ?? []) {
    spans.push(...matchSpans(text, new RegExp(`\\b${escapeRe(kw)}\\b`, 'gi'), `topic:${rule.id}`));
  }
  for (const pat of rule.patterns ?? []) {
    try {
      spans.push(...matchSpans(text, new RegExp(pat, 'gi'), `topic:${rule.id}`));
    } catch {
      // A malformed pattern in a policy must not take the gateway down.
    }
  }
  return spans;
}

const SEVERITY_SCORE: Record<Severity, number> = { low: 0.3, medium: 0.55, high: 0.8, critical: 0.95 };

export const topicPolicyDetector = defineDetector({
  id: 'topic-policy',
  name: 'Topic policy',
  description:
    'Applies the active policy’s deny and allow topic rules (keyword and regex lists). When an allow list is configured, content matching none of it is flagged as off-topic.',
  stage: ['input', 'output'],
  tier: 'rules',
  defaultSeverity: 'medium',
  async detect(ctx) {
    const { deny, allow, offTopicSeverity } = ctx.policy.topics;
    const spans: Span[] = [];
    const labels: string[] = [];
    let severity: Severity = 'low';
    let score = 0;
    const matched: string[] = [];

    for (const rule of deny) {
      const hits = ruleSpans(ctx.text, rule);
      if (hits.length === 0) continue;
      spans.push(...hits);
      labels.push(`topic:deny:${rule.id}`);
      matched.push(rule.id);
      const s = SEVERITY_SCORE[rule.severity];
      if (s > score) {
        score = s;
        severity = rule.severity;
      }
    }

    if (matched.length > 0) {
      return {
        triggered: true,
        score: Math.min(1, score + 0.05 * (matched.length - 1)),
        severity,
        labels,
        spans: mergeSpans(spans),
        explanation: `Matched denied topic rule(s): ${matched.join(', ')}.`,
      };
    }

    if (allow.length > 0) {
      const onTopic = allow.some((rule) => ruleSpans(ctx.text, rule).length > 0);
      if (!onTopic) {
        return {
          triggered: true,
          score: SEVERITY_SCORE[offTopicSeverity],
          severity: offTopicSeverity,
          labels: ['topic:off-topic'],
          spans: [],
          explanation: `Content matched none of the ${allow.length} permitted topic rule(s), so it is off-topic for this policy.`,
        };
      }
    }

    return noHit('No denied topics matched and the content is within the permitted topic set.');
  },
});
