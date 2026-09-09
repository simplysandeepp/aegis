/**
 * PII detector with precise spans, so the dashboard can highlight each hit
 * inline and the `redact` action can mask exactly the offending characters
 * without destroying the surrounding text.
 */

import { defineDetector, noHit } from '../registry';
import { luhnValid, matchSpans, mergeSpans } from '../util';
import type { Severity, Span } from '../types';

interface PiiRule {
  label: string;
  re: RegExp;
  severity: Severity;
  confirm?: (m: string, text: string, index: number) => boolean;
}

// A US SSN has structural constraints: no 000/666/900-999 area, no 00 group,
// no 0000 serial. Enforcing them keeps ordinary 9-digit numbers from firing.
const SSN_RE = /\b(?!000|666|9\d\d)(\d{3})[- ]?(?!00)(\d{2})[- ]?(?!0000)(\d{4})\b/g;

const RULES: PiiRule[] = [
  {
    label: 'pii:email',
    re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24}\b/g,
    severity: 'medium',
  },
  {
    label: 'pii:ssn',
    re: SSN_RE,
    severity: 'critical',
  },
  {
    label: 'pii:iban',
    re: /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g,
    severity: 'high',
    confirm: (m) => ibanChecksumValid(m),
  },
  {
    label: 'pii:phone-e164',
    re: /\+[1-9]\d{7,14}\b/g,
    severity: 'medium',
  },
  {
    label: 'pii:phone-national',
    // (555) 123-4567 | 555-123-4567 | 555.123.4567 | 020 7946 0958
    re: /(?<![\d.])(?:\(\d{2,4}\)[ .-]?\d{3,4}[ .-]?\d{3,4}|\b\d{3}[ .-]\d{3}[ .-]\d{4}\b|\b\d{4}[ ]\d{3}[ ]\d{4}\b)(?![\d.])/g,
    severity: 'medium',
  },
  {
    label: 'pii:ipv4',
    re: /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g,
    severity: 'low',
    // Loopback and RFC1918 addresses are not personal data.
    confirm: (m) =>
      !/^(?:127\.|0\.|10\.|192\.168\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|255\.)/.test(m),
  },
  {
    label: 'pii:ipv6',
    re: /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:(?:[0-9A-Fa-f]{1,4})?\b/g,
    severity: 'low',
    confirm: (m) => m.includes(':') && !/^(?:::1?|fe80:)/i.test(m),
  },
  {
    label: 'pii:credit-card',
    re: /\b(?:\d[ -]?){12,19}\b/g,
    severity: 'high',
    confirm: (m) => luhnValid(m),
  },
  {
    label: 'pii:street-address',
    // number + street words + a type suffix. Heuristic by design.
    re: /\b\d{1,6}\s+(?:[A-Z][A-Za-z.'-]*\s+){0,4}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Terrace|Ter|Place|Pl|Parkway|Pkwy|Circle|Cir)\b\.?/g,
    severity: 'medium',
  },
];

/** ISO 13616 mod-97 checksum. Without it every ISO-ish string is an "IBAN". */
function ibanChecksumValid(raw: string): boolean {
  const s = raw.replace(/\s+/g, '').toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  const rearranged = s.slice(4) + s.slice(0, 4);
  let remainder = 0;
  for (const ch of rearranged) {
    const code = ch.charCodeAt(0);
    const digits =
      code >= 65 && code <= 90 ? String(code - 55) : code >= 48 && code <= 57 ? ch : null;
    if (digits === null) return false;
    for (const d of digits) remainder = (remainder * 10 + Number(d)) % 97;
  }
  return remainder === 1;
}

const SEVERITY_SCORE: Record<Severity, number> = {
  low: 0.25,
  medium: 0.5,
  high: 0.75,
  critical: 0.95,
};

export const piiDetector = defineDetector({
  id: 'pii-detector',
  name: 'PII detector',
  description:
    'Email, E.164 and national phone formats, US SSN (with structural validation), IBAN (mod-97 checked), IPv4/IPv6 (public only), Luhn-valid card numbers, and a street-address heuristic. Emits precise spans for highlighting and redaction.',
  stage: ['input', 'output'],
  tier: 'rules',
  defaultSeverity: 'medium',
  async detect(ctx) {
    const text = ctx.text;
    const spans: Span[] = [];
    const labels = new Set<string>();
    let severity: Severity = 'low';
    let best = 0;

    for (const rule of RULES) {
      for (const span of matchSpans(text, rule.re, rule.label)) {
        const matched = text.slice(span.start, span.end);
        if (rule.confirm && !rule.confirm(matched, text, span.start)) continue;
        // An SSN-shaped run inside a longer card number is the card, not an SSN.
        if (rule.label === 'pii:ssn' && spans.some((s) => s.start <= span.start && s.end >= span.end)) {
          continue;
        }
        spans.push(span);
        labels.add(rule.label);
        best = Math.max(best, SEVERITY_SCORE[rule.severity]);
        if (SEVERITY_SCORE[rule.severity] >= SEVERITY_SCORE[severity]) severity = rule.severity;
      }
    }

    if (spans.length === 0) return noHit('No personally identifiable information detected.');

    const kinds = [...labels].map((l) => l.replace('pii:', '')).join(', ');
    return {
      triggered: true,
      score: Math.min(1, best + 0.03 * (spans.length - 1)),
      severity,
      labels: [...labels],
      spans: mergeSpans(spans),
      explanation: `Found ${spans.length} PII item${spans.length === 1 ? '' : 's'} (${kinds}).`,
    };
  },
});
