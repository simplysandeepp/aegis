/**
 * Prompt-injection heuristics.
 *
 * Structured as weighted pattern *families* rather than one flat regex list, so
 * the harness can report which family a case was caught by, and so a researcher
 * can retune one family without disturbing the others. Each family contributes
 * independently and the contributions combine with noisy-OR, which means two
 * moderate signals (a role hijack plus refusal suppression) land in the
 * escalation band rather than being decided by either one alone.
 *
 * The dampener at the bottom matters as much as the patterns: text that
 * *discusses* prompt injection — documentation, a security question, a paper
 * quoting a payload — contains the same strings as text that *performs* it.
 * Without dampening, the benign control set in the corpus lights up and the
 * measured false-positive rate is worthless.
 */

import { defineDetector, noHit } from '../registry';
import { matchSpans, mergeSpans, noisyOr } from '../util';
import type { Severity, Span } from '../types';

export type InjectionFamily =
  | 'instruction-override'
  | 'role-hijack'
  | 'prompt-extraction'
  | 'encoding-smuggling'
  | 'delimiter-injection'
  | 'refusal-suppression'
  | 'exfil-pattern';

interface FamilySpec {
  family: InjectionFamily;
  /** Contribution to the combined score when this family fires. */
  weight: number;
  severity: Severity;
  patterns: RegExp[];
  /** Programmatic detectors that regexes express badly. */
  scan?: (text: string) => Span[];
}

const FAMILIES: FamilySpec[] = [
  {
    family: 'instruction-override',
    weight: 0.85,
    severity: 'high',
    patterns: [
      /\b(?:ignore|disregard|forget|discard|override|bypass)\b[^.\n]{0,40}\b(?:all\s+)?(?:the\s+)?(?:above|previous|prior|earlier|preceding|foregoing|initial|original|system)\b[^.\n]{0,30}\b(?:instruction|prompt|direction|rule|guideline|message|context|constraint)s?\b/gi,
      /\b(?:ignore|disregard|forget)\b\s+(?:everything|all)\b[^.\n]{0,30}\b(?:before|above|prior|so\s+far)\b/gi,
      /\bnew\s+(?:instruction|directive|task|system\s+prompt)s?\s*:/gi,
      /\byour\s+(?:previous|prior|earlier|original)\s+instructions?\s+(?:are|is|were)\s+(?:now\s+)?(?:void|invalid|cancelled|canceled|revoked|obsolete|superseded)\b/gi,
      /\bthis\s+(?:message|prompt)\s+(?:overrides|supersedes|replaces)\b/gi,
    ],
  },
  {
    family: 'role-hijack',
    weight: 0.75,
    severity: 'high',
    patterns: [
      /\byou\s+are\s+now\s+(?:a|an|the)\b[^.\n]{0,60}/gi,
      /\bfrom\s+now\s+on[, ]+you\s+(?:are|will|must|shall)\b/gi,
      /\b(?:enter|enable|activate|switch\s+to)\s+(?:developer|debug|god|admin|root|sudo|unrestricted|jailbreak|dan)\s*mode\b/gi,
      /\bdeveloper\s+mode\s+(?:enabled|on|activated)\b/gi,
      /\bDAN\b(?=[^a-z]|$)[^.\n]{0,40}\b(?:mode|prompt|jailbreak|do\s+anything)\b/g,
      /\bdo\s+anything\s+now\b/gi,
      /\bpretend\s+(?:to\s+be|you\s+are|that\s+you\s+are)\b[^.\n]{0,60}\b(?:no|without|free\s+of|unbound|unrestricted|unfiltered)\b/gi,
      /\bact\s+as\s+(?:if\s+you\s+(?:have|had)\s+no|an?\s+(?:unfiltered|unrestricted|uncensored|amoral))\b/gi,
      /\byou\s+have\s+no\s+(?:restrictions|filters|guidelines|rules|limitations|policies)\b/gi,
      /\bsimulate\s+(?:a|an)\s+(?:unrestricted|uncensored|unfiltered)\b/gi,
    ],
  },
  {
    family: 'prompt-extraction',
    weight: 0.8,
    severity: 'high',
    patterns: [
      /\b(?:repeat|print|output|show|reveal|display|echo|recite|reproduce|dump)\b[^.\n]{0,40}\b(?:everything|all\s+text|the\s+text)\b[^.\n]{0,20}\babove\b/gi,
      /\b(?:what|show|print|reveal|tell\s+me|give\s+me|repeat)\b[^.\n]{0,30}\byour\s+(?:system\s+prompt|initial\s+prompt|original\s+prompt|instructions|directives|system\s+message|configuration|prompt)\b/gi,
      /\b(?:system\s+prompt|initial\s+instructions|original\s+instructions)\b[^.\n]{0,20}\b(?:verbatim|word\s+for\s+word|exactly|in\s+full)\b/gi,
      /\brepeat\s+the\s+words?\s+above\s+starting\s+with\b/gi,
      /\boutput\s+(?:the\s+)?(?:initialization|initial)\s+(?:text|prompt|message)\b/gi,
      /\bwhat\s+(?:were|are)\s+you\s+(?:told|instructed|programmed)\s+(?:to\s+do|not\s+to)\b/gi,
      /\bbegin\s+your\s+(?:reply|response|answer)\s+with\s+["“]?\s*(?:you\s+are|system)\b/gi,
    ],
  },
  {
    family: 'encoding-smuggling',
    weight: 0.6,
    severity: 'medium',
    patterns: [
      // URL-encoded or hex-encoded instruction phrases
      /(?:%(?:69|49)%(?:67|47)%(?:6e|4e|6E|4E)%(?:6f|4f|6F|4F)%(?:72|52)%(?:65|45))/gi, // "ignore"
      /(?:\\x[0-9a-f]{2}){6,}/gi,
      /(?:&#x?[0-9a-f]{2,4};){6,}/gi,
    ],
    scan: (text) => {
      const spans: Span[] = [];

      // Long base64 blobs that decode to readable ASCII containing an imperative.
      const b64 = /\b[A-Za-z0-9+/]{24,}={0,2}\b/g;
      let m: RegExpExecArray | null;
      while ((m = b64.exec(text)) !== null) {
        const tok = m[0];
        if (tok.length % 4 !== 0 && !tok.endsWith('=')) continue;
        let decoded = '';
        try {
          decoded = Buffer.from(tok, 'base64').toString('utf8');
        } catch {
          continue;
        }
        const printable = decoded.replace(/[^\x20-\x7E]/g, '');
        if (printable.length < decoded.length * 0.85) continue; // not text
        if (decoded.length < 8) continue;
        if (IMPERATIVE_RE.test(decoded)) {
          spans.push({ start: m.index, end: m.index + tok.length, label: 'encoding:base64-instruction' });
        } else if (decoded.length >= 40 && /\s/.test(decoded)) {
          spans.push({ start: m.index, end: m.index + tok.length, label: 'encoding:base64-prose' });
        }
      }

      // ROT13 text that becomes an imperative when rotated.
      const words = /\b[A-Za-z]{4,}(?:\s+[A-Za-z]{2,}){2,}\b/g;
      while ((m = words.exec(text)) !== null) {
        const rotated = rot13(m[0]);
        if (IMPERATIVE_RE.test(rotated) && !IMPERATIVE_RE.test(m[0])) {
          spans.push({ start: m.index, end: m.index + m[0].length, label: 'encoding:rot13-instruction' });
        }
      }

      return spans;
    },
  },
  {
    family: 'delimiter-injection',
    weight: 0.55,
    severity: 'medium',
    patterns: [
      /<\/?(?:system|assistant|instructions?|admin|developer)\s*>/gi,
      /\[\/?INST\]/g,
      /<\|(?:im_start|im_end|system|endoftext|eot_id|start_header_id)\|>/g,
      /^\s*#{3,}\s*(?:system|instruction|admin|new\s+prompt|important)\b/gim,
      /\b(?:BEGIN|END)\s+SYSTEM\s+(?:PROMPT|MESSAGE)\b/gi,
      /^\s*(?:system|assistant)\s*:\s*(?=\S)/gim,
    ],
  },
  {
    family: 'refusal-suppression',
    weight: 0.65,
    severity: 'high',
    patterns: [
      /\b(?:do\s+not|don't|never)\s+(?:refuse|decline|apologize|say\s+(?:no|you\s+can'?t)|warn|caution|lecture)\b/gi,
      /\bnever\s+say\s+(?:you\s+)?(?:can'?t|cannot|won'?t|unable)\b/gi,
      /\b(?:without|no)\s+(?:any\s+)?(?:warnings?|disclaimers?|caveats?|moralizing|ethical\s+considerations?)\b/gi,
      /\bdo\s+not\s+mention\s+(?:your\s+)?(?:guidelines|policies|restrictions|rules|training)\b/gi,
      /\byou\s+must\s+(?:comply|obey|answer)\b[^.\n]{0,30}\b(?:regardless|no\s+matter|whatever)\b/gi,
      /\bstart\s+your\s+(?:response|reply|answer)\s+with\s+["“]?(?:sure|certainly|absolutely|of\s+course)\b/gi,
    ],
  },
  {
    family: 'exfil-pattern',
    weight: 0.9,
    severity: 'critical',
    patterns: [],
    scan: (text) => {
      const spans: Span[] = [];
      // Markdown image or link whose URL carries interpolated data:
      //   ![](http://host/?d={{secret}})  or  [x](https://h/log?data=<the key>)
      const md = /!?\[[^\]]*\]\(\s*(https?:\/\/[^\s)]+)\s*\)/gi;
      let m: RegExpExecArray | null;
      while ((m = md.exec(text)) !== null) {
        const url = m[1] ?? '';
        const carriesData =
          /[?&#][^=]*=(?:[^&)\s]*(?:\{\{|\{%|<[a-z_]|\$\{|%7B|\[\[))/i.test(url) ||
          /[?&](?:d|q|data|payload|body|content|text|msg|dump|leak|exfil|key|token|secret|prompt)=/i.test(url);
        if (carriesData) {
          spans.push({ start: m.index, end: m.index + m[0].length, label: 'exfil:markdown-url' });
        }
      }
      // Bare instruction to fetch/append data to a URL.
      const fetchIns =
        /\b(?:send|post|upload|append|attach|include|encode|transmit|leak|exfiltrate)\b[^.\n]{0,60}\b(?:to|into|in)\b[^.\n]{0,20}(?:https?:\/\/\S+|the\s+url|this\s+link)/gi;
      for (const s of matchSpans(text, fetchIns, 'exfil:send-to-url')) spans.push(s);
      return spans;
    },
  },
];

const IMPERATIVE_RE =
  /\b(?:ignore|disregard|forget|override|reveal|print|output|repeat|execute|you\s+are\s+now|system\s+prompt|instructions?|bypass|jailbreak|do\s+anything)\b/i;

function rot13(s: string): string {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= 'Z' ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}

/**
 * Signals that the text is *about* prompt injection rather than *performing*
 * it. Each hit reduces the combined score multiplicatively.
 *
 * This is the single biggest lever on the false-positive rate, and it is the
 * reason ambiguous cases reach the LLM tier instead of being auto-blocked.
 */
const META_SIGNALS: RegExp[] = [
  /\b(?:prompt\s+injection|jailbreak(?:ing)?|adversarial\s+prompt|red[- ]team(?:ing)?|attack\s+(?:vector|pattern|technique|surface))\b/i,
  /\b(?:for\s+example|e\.g\.|such\s+as|an?\s+example\s+of|sample\s+payload|test\s+case|illustrat(?:es?|ing)|demonstrat(?:es?|ing))\b/i,
  /\b(?:how\s+(?:do|can|would|should)\s+(?:i|we|you|one)\b|what\s+is\b|why\s+(?:does|do|is)\b|explain\b|describe\b)/i,
  /\b(?:defend|defence|defense|mitigat(?:e|ion)|protect|prevent|detect(?:ion)?|guard(?:rail)?s?|filter(?:ing)?|sanitiz)/i,
  /\b(?:paper|blog\s+post|article|documentation|research|study|owasp|cwe|cve|benchmark|dataset)\b/i,
  /\b(?:my\s+(?:app|application|system|chatbot|agent|service)|our\s+(?:app|application|system|product))\b/i,
];

/** Quoted or fenced content: an attack string inside a quote is usually a citation. */
function quotedFraction(text: string): number {
  let quoted = 0;
  for (const re of [/```[\s\S]*?```/g, /"[^"\n]{20,}"/g, /'[^'\n]{20,}'/g, /^>\s.*$/gm]) {
    for (const m of text.matchAll(re)) quoted += m[0].length;
  }
  return text.length ? Math.min(1, quoted / text.length) : 0;
}

export const injectionHeuristicsDetector = defineDetector({
  id: 'injection-heuristics',
  name: 'Injection heuristics',
  description:
    'Weighted pattern families: instruction-override, role-hijack, prompt-extraction, encoding-smuggling (base64/ROT13/hex/URL), delimiter-injection, refusal-suppression and exfiltration-via-markdown-URL. Dampened when the text is discussing injection rather than performing it.',
  stage: ['input', 'output'],
  tier: 'rules',
  defaultSeverity: 'high',
  async detect(ctx) {
    const text = ctx.text;
    const spans: Span[] = [];
    const labels: string[] = [];
    const contributions: number[] = [];
    const hitFamilies: InjectionFamily[] = [];
    let severity: Severity = 'low';

    for (const fam of FAMILIES) {
      const famSpans: Span[] = [];
      for (const re of fam.patterns) {
        famSpans.push(...matchSpans(text, re, `injection:${fam.family}`));
      }
      if (fam.scan) famSpans.push(...fam.scan(text));
      if (famSpans.length === 0) continue;

      hitFamilies.push(fam.family);
      labels.push(`injection:${fam.family}`);
      spans.push(...famSpans);
      // Repeats within a family add a little, but never as much as a new family.
      contributions.push(Math.min(1, fam.weight * (1 + 0.08 * (famSpans.length - 1))));
      if (rank(fam.severity) > rank(severity)) severity = fam.severity;
    }

    if (hitFamilies.length === 0) {
      return noHit('No instruction-override, role-hijack, extraction, smuggling, delimiter, refusal-suppression or exfiltration patterns matched.');
    }

    let score = noisyOr(contributions);

    // --- dampening -------------------------------------------------------
    const metaHits = META_SIGNALS.filter((re) => re.test(text)).length;
    const qf = quotedFraction(text);
    const dampen = Math.pow(0.72, metaHits) * (1 - 0.35 * qf);
    const dampened = score * dampen;
    const notes: string[] = [];
    if (metaHits > 0) notes.push(`${metaHits} meta-discussion signal(s)`);
    if (qf > 0.15) notes.push(`${Math.round(qf * 100)}% of the text is quoted or fenced`);
    score = dampened;

    // Untrusted provenance pushes the other way: an instruction that arrives
    // inside a retrieved document or a tool result has no legitimate reason to
    // be there at all, so indirect injection is scored harder than direct.
    const untrustedParts = ctx.parts.filter((p) => p.trust === 'tool' || p.trust === 'retrieved');
    if (untrustedParts.length > 0) {
      score = Math.min(1, score * 1.35 + 0.1);
      labels.push('injection:untrusted-provenance');
      notes.push('payload arrived in tool/retrieved content, which must never carry instructions');
      if (rank(severity) < rank('high')) severity = 'high';
    }

    // Several independent families firing at once is qualitatively different
    // from one pattern matching: it is the signature of a deliberately
    // constructed attack rather than an unlucky turn of phrase. Without this
    // promotion a single high-severity detector caps its own contribution at
    // severityWeights.high and can never reach a confident block on its own.
    if (hitFamilies.length >= 3 && score >= 0.85) {
      severity = 'critical';
      labels.push('injection:multi-family');
      notes.push(`${hitFamilies.length} independent families co-occur`);
    }

    return {
      triggered: score > 0.05,
      score: Math.max(0, Math.min(1, score)),
      severity,
      labels,
      spans: mergeSpans(spans),
      explanation:
        `Matched ${hitFamilies.length} injection family/families: ${hitFamilies.join(', ')}.` +
        (notes.length ? ` Adjusted for: ${notes.join('; ')}.` : ''),
    };
  },
});

function rank(s: Severity): number {
  return ['low', 'medium', 'high', 'critical'].indexOf(s);
}
