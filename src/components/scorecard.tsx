import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';

/**
 * A stat tile, not a chart: a single number with the direction of "good" spelled
 * out, because ASR and FPR both improve downward and that is not guessable.
 */
export function Scorecard({
  label,
  value,
  hint,
  tone = 'neutral',
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: 'neutral' | 'good' | 'warn' | 'bad';
}) {
  const toneClass =
    tone === 'good'
      ? 'text-[#008300] dark:text-[#4fb14f]'
      : tone === 'warn'
        ? 'text-[#8a5d00] dark:text-[#eda100]'
        : tone === 'bad'
          ? 'text-[#b8322f] dark:text-[#e66767]'
          : 'text-foreground';

  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className={`font-mono text-3xl font-semibold tabular-nums ${toneClass}`}>{value}</div>
        {hint ? <p className="mt-1 text-xs leading-snug text-muted-foreground">{hint}</p> : null}
      </CardContent>
    </Card>
  );
}
