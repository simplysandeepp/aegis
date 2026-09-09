/**
 * URL allowlist — an OUTPUT-stage detector.
 *
 * A model that has been successfully injected exfiltrates by emitting a link or
 * an image whose URL encodes the data it was told to leak. Rendering clients
 * fetch images automatically, so the user never has to click anything. This is
 * the primary data-egress channel from an LLM application, which is why the
 * check lives on the output side and why an off-allowlist host is treated as
 * high severity even when the URL looks harmless.
 */

import { defineDetector, noHit } from '../registry';
import { hostMatches, mergeSpans } from '../util';
import type { Span } from '../types';

const URL_RE = /\b(?:https?:\/\/|\/\/)[^\s<>"'`)\]]+/gi;

export const urlAllowlistDetector = defineDetector({
  id: 'url-allowlist',
  name: 'URL allowlist',
  description:
    'Extracts every URL from model output and flags any host outside the policy allowlist. Auto-loading markdown images are scored highest because they exfiltrate with no user interaction.',
  stage: ['output'],
  tier: 'rules',
  defaultSeverity: 'high',
  async detect(ctx) {
    const allowlist = ctx.policy.urlAllowlist;
    const text = ctx.text;
    const spans: Span[] = [];
    const offenders: string[] = [];
    const labels = new Set<string>();
    let autoLoading = false;

    let m: RegExpExecArray | null;
    const rx = new RegExp(URL_RE.source, 'gi');
    while ((m = rx.exec(text)) !== null) {
      const raw = m[0].replace(/[.,;:]+$/, '');
      let host: string;
      try {
        host = new URL(raw.startsWith('//') ? `https:${raw}` : raw).hostname;
      } catch {
        continue;
      }
      const allowed = allowlist.some((p) => hostMatches(host, p));
      if (allowed) continue;

      offenders.push(host);
      labels.add('exfil:off-allowlist-host');
      spans.push({ start: m.index, end: m.index + raw.length, label: 'exfil:off-allowlist-host' });

      // Is this URL inside a markdown image? Those fetch without a click.
      const before = text.slice(Math.max(0, m.index - 120), m.index);
      if (/!\[[^\]]*\]\($/.test(before)) {
        autoLoading = true;
        labels.add('exfil:auto-loading-image');
      }
      // Does the URL carry a payload in its query string?
      if (/[?&][^=]+=.{8,}/.test(raw)) labels.add('exfil:url-carries-data');
    }

    if (offenders.length === 0) {
      return noHit(
        allowlist.length
          ? `All URLs in the output are on the allowlist (${allowlist.join(', ')}).`
          : 'No URLs found in the output.',
      );
    }

    const unique = [...new Set(offenders)];
    return {
      triggered: true,
      score: Math.min(1, (autoLoading ? 0.95 : 0.7) + 0.05 * (unique.length - 1)),
      severity: autoLoading ? ('critical' as const) : ('high' as const),
      labels: [...labels],
      spans: mergeSpans(spans),
      explanation:
        `Output links to ${unique.length} host(s) outside the allowlist: ${unique.join(', ')}.` +
        (autoLoading
          ? ' At least one is a markdown image, which a rendering client fetches automatically — this exfiltrates without any user interaction.'
          : ''),
    };
  },
});
