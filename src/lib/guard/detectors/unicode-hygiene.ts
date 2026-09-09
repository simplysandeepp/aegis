/**
 * Unicode hygiene: detector *and* sanitizing transform.
 *
 * Attacks routinely hide instructions from naive regexes using characters that
 * render as nothing or render as something else:
 *   - zero-width joiners/spaces sprinkled inside "ignore previous instructions"
 *   - RTL/LTR bidi overrides that reorder displayed text away from its bytes
 *   - Unicode TAG characters (U+E0000 block), invisible in every renderer
 *   - Cyrillic/Greek homoglyphs that look identical to ASCII letters
 *
 * `sanitizeText` produces the normalized form the rest of the pipeline analyses,
 * so a payload that only works pre-normalization is caught by the downstream
 * regex detectors rather than sliding past them.
 */

import { defineDetector, noHit } from '../registry';
import { mergeSpans } from '../util';
import type { Span } from '../types';

/** Zero-width and invisible formatting characters. */
const ZERO_WIDTH = /[​-‏⁠-⁤﻿­]/g;
/** Bidirectional override / embedding controls. */
const BIDI = /[‪-‮⁦-⁩]/g;
/** Unicode TAG block — entirely invisible, used to smuggle ASCII. */
const TAG_CHARS = /[\u{E0000}-\u{E007F}]/gu;
/** Variation selectors, also usable as an invisible channel. */
const VARIATION = /[︀-️\u{E0100}-\u{E01EF}]/gu;

/**
 * Confusable -> ASCII map. Deliberately restricted to the Latin-lookalike
 * letters that actually appear in injection payloads; a full UTR-39 table
 * would add a lot of surface for very little benefit here.
 */
const CONFUSABLES: Record<string, string> = {
  // Cyrillic
  а: 'a', в: 'b', с: 'c', е: 'e', ѕ: 's', і: 'i', ј: 'j', к: 'k', м: 'm',
  н: 'h', о: 'o', р: 'p', т: 't', у: 'y', х: 'x', г: 'r', ԁ: 'd', ո: 'n',
  А: 'A', В: 'B', С: 'C', Е: 'E', Н: 'H', К: 'K', М: 'M', О: 'O', Р: 'P',
  Ѕ: 'S', Т: 'T', У: 'Y', Х: 'X', І: 'I', Ј: 'J',
  // Greek
  ο: 'o', α: 'a', ρ: 'p', τ: 't', υ: 'u', ν: 'v', ι: 'i', κ: 'k', ε: 'e',
  Ο: 'O', Α: 'A', Ρ: 'P', Τ: 'T', Υ: 'Y', Ι: 'I', Κ: 'K', Ε: 'E', Ν: 'N',
  Β: 'B', Ζ: 'Z', Η: 'H', Μ: 'M', Χ: 'X',
  // Fullwidth
  ａ: 'a', ｅ: 'e', ｉ: 'i', ｏ: 'o', ｎ: 'n', ｇ: 'g', ｒ: 'r', ｓ: 's', ｔ: 't',
  // Mathematical / letterlike
  ℯ: 'e', ℴ: 'o', ⅰ: 'i', ⅼ: 'l', ⲟ: 'o',
};

const CONFUSABLE_RE = new RegExp(`[${Object.keys(CONFUSABLES).join('')}]`, 'gu');

export interface SanitizeReport {
  text: string;
  changed: boolean;
  zeroWidth: number;
  bidi: number;
  tagChars: number;
  variation: number;
  confusables: number;
  nfkcChanged: boolean;
  /** Offsets into the ORIGINAL text where suspicious characters were found. */
  spans: Span[];
}

/**
 * Strip invisible characters, fold confusables to ASCII, then NFKC-normalize.
 *
 * Order matters: invisible characters are removed first so that NFKC does not
 * merge them into neighbouring graphemes, and confusables are folded before
 * NFKC so the ASCII result is stable.
 */
export function sanitizeText(input: string): SanitizeReport {
  const spans: Span[] = [];
  const count = (re: RegExp, label: string): number => {
    let n = 0;
    const rx = new RegExp(re.source, re.flags);
    let m: RegExpExecArray | null;
    while ((m = rx.exec(input)) !== null) {
      spans.push({ start: m.index, end: m.index + m[0].length, label });
      n++;
      if (m[0].length === 0) rx.lastIndex++;
    }
    return n;
  };

  const zeroWidth = count(ZERO_WIDTH, 'unicode:zero-width');
  const bidi = count(BIDI, 'unicode:bidi-override');
  const tagChars = count(TAG_CHARS, 'unicode:tag-char');
  const variation = count(VARIATION, 'unicode:variation-selector');
  const confusables = count(CONFUSABLE_RE, 'unicode:confusable');

  let text = input
    .replace(ZERO_WIDTH, '')
    .replace(BIDI, '')
    .replace(TAG_CHARS, '')
    .replace(VARIATION, '')
    .replace(CONFUSABLE_RE, (ch) => CONFUSABLES[ch] ?? ch);

  const beforeNfkc = text;
  text = text.normalize('NFKC');
  const nfkcChanged = text !== beforeNfkc;

  return {
    text,
    changed: text !== input,
    zeroWidth,
    bidi,
    tagChars,
    variation,
    confusables,
    nfkcChanged,
    spans: mergeSpans(spans),
  };
}

export const unicodeHygieneDetector = defineDetector({
  id: 'unicode-hygiene',
  name: 'Unicode hygiene',
  description:
    'Detects and strips zero-width characters, bidi overrides, Unicode tag characters and homoglyph confusables, then applies NFKC normalization.',
  stage: ['input', 'output'],
  tier: 'rules',
  defaultSeverity: 'medium',
  async detect(ctx) {
    // Analyse the raw text: by the time `ctx.text` is built the pipeline may
    // already have normalized it, and we want to report on what came in.
    const report = sanitizeText(ctx.rawText);

    const findings: string[] = [];
    if (report.zeroWidth) findings.push(`${report.zeroWidth} zero-width character(s)`);
    if (report.bidi) findings.push(`${report.bidi} bidirectional override(s)`);
    if (report.tagChars) findings.push(`${report.tagChars} Unicode TAG character(s)`);
    if (report.variation) findings.push(`${report.variation} variation selector(s)`);
    if (report.confusables) findings.push(`${report.confusables} homoglyph confusable(s)`);

    if (findings.length === 0) {
      return noHit(
        report.nfkcChanged
          ? 'No obfuscation characters; NFKC normalization changed only compatibility forms.'
          : 'Text is already NFKC-normal with no invisible or confusable characters.',
      );
    }

    const labels = ['unicode:obfuscation'];
    if (report.tagChars) labels.push('unicode:tag-chars');
    if (report.bidi) labels.push('unicode:bidi');
    if (report.zeroWidth) labels.push('unicode:zero-width');
    if (report.confusables) labels.push('unicode:homoglyph');

    // TAG characters and bidi overrides have essentially no legitimate use in
    // a chat payload; zero-width and confusables occasionally do (copy-paste
    // from a PDF, non-Latin prose), so they score lower on their own.
    const weight =
      report.tagChars > 0 || report.bidi > 0
        ? 0.9
        : Math.min(0.75, 0.25 + 0.05 * (report.zeroWidth + report.confusables));

    return {
      triggered: true,
      score: weight,
      severity: report.tagChars > 0 || report.bidi > 0 ? ('high' as const) : ('medium' as const),
      labels,
      spans: report.spans,
      explanation:
        `Found ${findings.join(', ')}. Text was normalized before further analysis, so any ` +
        `payload relying on this obfuscation is now visible to the other detectors.`,
    };
  },
});
