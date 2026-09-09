/**
 * Secret scanner: provider-specific credential formats, plus two
 * format-agnostic checks (Shannon entropy and Luhn) that catch keys whose
 * shape we do not know in advance.
 *
 * Runs on both stages. On input it stops a user pasting live credentials into
 * a third-party model; on output it is the last line of defence against the
 * model reciting a secret it was given earlier in the context.
 */

import { defineDetector, noHit } from '../registry';
import { luhnValid, matchSpans, mergeSpans, shannonEntropy } from '../util';
import type { Severity, Span } from '../types';

interface SecretRule {
  label: string;
  re: RegExp;
  severity: Severity;
  /** Extra confirmation beyond the regex. */
  confirm?: (match: string) => boolean;
}

const RULES: SecretRule[] = [
  {
    label: 'secret:aws-access-key',
    re: /\b((?:AKIA|ASIA|ABIA|ACCA|AIDA|AGPA|AROA|ANPA|ANVA)[0-9A-Z]{16})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:aws-secret-key',
    re: /\baws_secret_access_key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: 'critical',
  },
  {
    label: 'secret:github-pat',
    re: /\b(gh[pousr]_[A-Za-z0-9]{36,255})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:github-fine-grained-pat',
    re: /\b(github_pat_[A-Za-z0-9_]{60,255})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:google-api-key',
    re: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:slack-token',
    re: /\b(xox[baprs]-[0-9A-Za-z-]{10,})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:slack-webhook',
    re: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z]+\/B[0-9A-Za-z]+\/[0-9A-Za-z]+/g,
    severity: 'high',
  },
  {
    label: 'secret:openai-key',
    re: /\b(sk-[A-Za-z0-9_-]{20,})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:groq-key',
    re: /\b(gsk_[A-Za-z0-9]{20,})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:stripe-key',
    re: /\b((?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{20,})\b/g,
    severity: 'critical',
  },
  {
    label: 'secret:private-key-block',
    re: /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/g,
    severity: 'critical',
  },
  {
    label: 'secret:jwt',
    // Three base64url segments; the header must decode to JSON with "alg".
    re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\b/g,
    severity: 'high',
    confirm: (m) => {
      const head = m.split('.')[0];
      try {
        const json = JSON.parse(Buffer.from(head, 'base64url').toString('utf8')) as unknown;
        return !!json && typeof json === 'object' && 'alg' in (json as Record<string, unknown>);
      } catch {
        return false;
      }
    },
  },
  {
    label: 'secret:generic-api-key-assignment',
    // `api_key: "..."`, `apiKey = '...'`, `API-KEY=...`
    re: /\b(?:api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key)\b\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{12,})["']?/gi,
    severity: 'high',
    // Reject obvious placeholders so documentation and sample code do not fire.
    confirm: (m) => !PLACEHOLDER_RE.test(m),
  },
];

/**
 * Placeholders that show up constantly in docs, tests and tutorials. Without
 * this the benign control set in the corpus lights up and the false-positive
 * rate becomes meaningless.
 */
const PLACEHOLDER_RE =
  /(your[_-]?(api[_-]?)?key|xxx+|<[^>]{1,40}>|\{\{?[a-z_.]{1,40}\}?\}|example|placeholder|redacted|dummy|sample|changeme|todo|insert[_-]?key|my[_-]?secret|s3cr3t|abc123|test[_-]?key|fake|process\.env|os\.environ|\$\{?[A-Z_]{3,}\}?)/i;

/** Tokens that look random enough to be a credential regardless of format. */
function entropyFindings(text: string): Span[] {
  const spans: Span[] = [];
  const tokenRe = /[A-Za-z0-9+/=_\-]{20,}/g;
  let m: RegExpExecArray | null;
  while ((m = tokenRe.exec(text)) !== null) {
    const tok = m[0];
    if (PLACEHOLDER_RE.test(tok)) continue;
    // Require real character-class mixing: long lowercase words (base64 of
    // prose, hex hashes of public data, UUID-ish ids) are not credentials.
    const classes =
      (/[a-z]/.test(tok) ? 1 : 0) +
      (/[A-Z]/.test(tok) ? 1 : 0) +
      (/[0-9]/.test(tok) ? 1 : 0) +
      (/[+/=_\-]/.test(tok) ? 1 : 0);
    if (classes < 3) continue;
    if (shannonEntropy(tok) <= 4.0) continue;
    spans.push({ start: m.index, end: m.index + tok.length, label: 'secret:high-entropy-token' });
  }
  return spans;
}

/** Digit runs that pass Luhn — payment card numbers. */
function luhnFindings(text: string): Span[] {
  const spans: Span[] = [];
  const re = /\b(?:\d[ -]?){12,19}\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text)) !== null) {
    if (luhnValid(m[0])) {
      spans.push({ start: m.index, end: m.index + m[0].length, label: 'secret:card-number' });
    }
  }
  return spans;
}

export const secretScannerDetector = defineDetector({
  id: 'secret-scanner',
  name: 'Secret scanner',
  description:
    'Provider credential formats (AWS, GitHub, Google, Slack, Stripe, JWT, PEM private keys), generic api_key assignments, a Shannon-entropy check for unknown key formats, and a Luhn check for card numbers.',
  stage: ['input', 'output'],
  tier: 'rules',
  defaultSeverity: 'critical',
  async detect(ctx) {
    const text = ctx.text;
    const spans: Span[] = [];
    const labels = new Set<string>();
    let severity: Severity = 'low';
    let hits = 0;

    for (const rule of RULES) {
      for (const span of matchSpans(text, rule.re, rule.label)) {
        const matched = text.slice(span.start, span.end);
        if (rule.confirm && !rule.confirm(matched)) continue;
        spans.push(span);
        labels.add(rule.label);
        hits++;
        if (rule.severity === 'critical') severity = 'critical';
        else if (severity !== 'critical') severity = rule.severity;
      }
    }

    for (const span of entropyFindings(text)) {
      // Do not double-report a token a named rule already claimed.
      if (spans.some((s) => s.start <= span.start && s.end >= span.end)) continue;
      spans.push(span);
      labels.add(span.label);
      hits++;
      if (severity === 'low') severity = 'medium';
    }

    for (const span of luhnFindings(text)) {
      spans.push(span);
      labels.add(span.label);
      hits++;
      if (severity !== 'critical') severity = 'high';
    }

    if (hits === 0) return noHit('No credential formats, high-entropy tokens or Luhn-valid card numbers found.');

    // Named-format hits are near-certain; entropy-only hits are weaker.
    const named = [...labels].some((l) => l !== 'secret:high-entropy-token');
    const score = named ? Math.min(1, 0.85 + 0.05 * hits) : Math.min(0.7, 0.4 + 0.1 * hits);

    return {
      triggered: true,
      score,
      severity,
      labels: [...labels],
      spans: mergeSpans(spans),
      explanation: `Found ${hits} candidate secret${hits === 1 ? '' : 's'}: ${[...labels].join(', ')}.`,
    };
  },
});
