/** Small pure helpers shared by the detectors and the router. */

import type { Action, Severity, Span } from './types';

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (!s.length) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

/** Luhn checksum, used to separate real card numbers from any 16-digit run. */
export function luhnValid(digits: string): boolean {
  const d = digits.replace(/[^0-9]/g, '');
  if (d.length < 12 || d.length > 19) return false;
  let sum = 0;
  let alt = false;
  for (let i = d.length - 1; i >= 0; i--) {
    let n = d.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

/**
 * Noisy-OR combination of weighted detector scores.
 *
 * Chosen over a max or a plain sum because it is bounded in [0,1], is monotone
 * in every input, and lets several weak signals accumulate into a confident
 * verdict without any single one saturating the score. That accumulation is
 * what puts genuinely ambiguous prompts into the escalation band instead of
 * resolving them at the rules tier.
 */
export function noisyOr(weighted: readonly number[]): number {
  let inv = 1;
  for (const w of weighted) inv *= 1 - Math.min(1, Math.max(0, w));
  return 1 - inv;
}

/** Merge overlapping/adjacent spans so highlighting and redaction stay sane. */
export function mergeSpans(spans: readonly Span[]): Span[] {
  if (spans.length === 0) return [];
  const sorted = [...spans].sort((a, b) => a.start - b.start || a.end - b.end);
  const out: Span[] = [{ ...sorted[0] }];
  for (let i = 1; i < sorted.length; i++) {
    const cur = sorted[i];
    const last = out[out.length - 1];
    if (cur.start <= last.end) {
      last.end = Math.max(last.end, cur.end);
      if (!last.label.includes(cur.label)) last.label = `${last.label}+${cur.label}`;
    } else {
      out.push({ ...cur });
    }
  }
  return out;
}

/** Replace each span with a fixed-width mask that names what was removed. */
export function redactSpans(text: string, spans: readonly Span[]): string {
  const merged = mergeSpans(spans);
  let out = '';
  let cursor = 0;
  for (const s of merged) {
    const start = Math.max(0, Math.min(s.start, text.length));
    const end = Math.max(start, Math.min(s.end, text.length));
    if (start < cursor) continue;
    out += text.slice(cursor, start);
    out += `[REDACTED:${s.label}]`;
    cursor = end;
  }
  out += text.slice(cursor);
  return out;
}

/** All non-overlapping matches of a global regex, as spans. */
export function matchSpans(text: string, re: RegExp, label: string): Span[] {
  const spans: Span[] = [];
  const rx = new RegExp(re.source, re.flags.includes('g') ? re.flags : `${re.flags}g`);
  let m: RegExpExecArray | null;
  while ((m = rx.exec(text)) !== null) {
    if (m[0].length === 0) {
      rx.lastIndex++;
      continue;
    }
    spans.push({ start: m.index, end: m.index + m[0].length, label });
  }
  return spans;
}

export function severityAtLeast(a: Severity, b: Severity): boolean {
  const order: Severity[] = ['low', 'medium', 'high', 'critical'];
  return order.indexOf(a) >= order.indexOf(b);
}

export function maxSeverity(a: Severity, b: Severity): Severity {
  return severityAtLeast(a, b) ? a : b;
}

/** Escapes a string for safe embedding in a RegExp. */
export function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Host matcher supporting a single leading wildcard label, e.g. `*.corp.com`
 * matches `a.corp.com` and `corp.com` but never `evilcorp.com`.
 */
export function hostMatches(host: string, pattern: string): boolean {
  const h = host.toLowerCase().replace(/\.$/, '');
  const p = pattern.toLowerCase().replace(/\.$/, '');
  if (p.startsWith('*.')) {
    const base = p.slice(2);
    return h === base || h.endsWith(`.${base}`);
  }
  return h === p;
}

export const ACTION_RANK: Record<Action, number> = {
  allow: 0,
  flag: 1,
  redact: 2,
  rewrite: 3,
  block: 4,
};

/** Deterministic stable stringify so policy hashes do not depend on key order. */
export function canonicalJson(value: unknown): string {
  const walk = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(walk);
    if (v && typeof v === 'object') {
      const o = v as Record<string, unknown>;
      const out: Record<string, unknown> = {};
      for (const k of Object.keys(o).sort()) out[k] = walk(o[k]);
      return out;
    }
    return v;
  };
  return JSON.stringify(walk(value));
}
