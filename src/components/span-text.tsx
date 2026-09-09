import type { Span } from '@/lib/guard/types';

/**
 * Renders text with detector spans highlighted inline.
 *
 * Highlighting carries a visible label and an underline, not just a background
 * tint, so which detector claimed which characters is readable without relying
 * on colour.
 */
export function SpanText({ text, spans }: { text: string; spans: Span[] }) {
  if (!text) return <span className="text-muted-foreground">(empty)</span>;

  const sorted = [...spans]
    .filter((s) => s.start < s.end && s.start >= 0)
    .sort((a, b) => a.start - b.start);

  const nodes: React.ReactNode[] = [];
  let cursor = 0;

  for (const [i, s] of sorted.entries()) {
    const start = Math.max(cursor, Math.min(s.start, text.length));
    const end = Math.max(start, Math.min(s.end, text.length));
    if (start > cursor) nodes.push(<span key={`t${i}`}>{text.slice(cursor, start)}</span>);
    if (end > start) {
      nodes.push(
        <mark
          key={`m${i}`}
          title={s.label}
          className="rounded-sm bg-amber-200/70 px-0.5 underline decoration-amber-700 decoration-2 underline-offset-2 dark:bg-amber-500/25 dark:decoration-amber-400"
        >
          {text.slice(start, end)}
          <sup className="ml-0.5 font-mono text-[9px] text-amber-900 dark:text-amber-200">{s.label}</sup>
        </mark>,
      );
    }
    cursor = Math.max(cursor, end);
  }
  if (cursor < text.length) nodes.push(<span key="tail">{text.slice(cursor)}</span>);

  return (
    <pre className="whitespace-pre-wrap break-words rounded-md border border-border bg-muted/30 p-3 font-mono text-xs leading-relaxed">
      {nodes}
    </pre>
  );
}
