import Link from 'next/link';
import { listRuns } from '@/lib/dashboard/queries';
import { Scorecard } from '@/components/scorecard';
import { Empty } from '@/components/empty';
import { AsrFprScatter, TrendChart, type ScatterPoint } from '@/components/charts';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';

export const dynamic = 'force-dynamic';

const pct = (v: number | undefined): string => (v === undefined ? '—' : `${(v * 100).toFixed(1)}%`);

export default function OverviewPage() {
  const runs = listRuns(25);
  const scored = runs.filter((r) => r.scores);
  const latest = scored[0];

  if (!latest?.scores) {
    return (
      <Empty
        title="No harness runs yet"
        hint={
          <>
            Run the offline harness to populate this dashboard:
            <pre className="mt-3 inline-block rounded bg-muted px-3 py-2 text-left font-mono text-xs">
              npm run harness -- --mock
            </pre>
          </>
        }
      />
    );
  }

  const s = latest.scores;

  // One point per configuration in the latest run, grouped by policy so the
  // three-slot palette is never exceeded.
  const points: ScatterPoint[] = scored.slice(0, 12).map((r) => ({
    fpr: r.scores?.fpr ?? 0,
    asr: r.scores?.asr ?? 0,
    label: r.id.slice(4, 14),
    group: r.mock ? 'mock' : 'live',
  }));

  const trend = [...scored]
    .reverse()
    .slice(-15)
    .map((r) => ({
      label: new Date(r.createdAt).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }),
      asr: r.scores?.asr ?? 0,
      fpr: r.scores?.fpr ?? 0,
    }));

  return (
    <div className="space-y-8">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Latest run <Link href={`/runs/${latest.id}`} className="font-mono underline underline-offset-2">{latest.id}</Link>
          {' · '}
          {latest.mock ? 'mock provider' : 'live providers'}
          {' · '}
          {s.n} results ({s.attacks} attacks, {s.benign} benign controls)
        </p>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Scorecard
          label="Attack success rate"
          value={pct(s.asr)}
          hint="Share of attacks the model actually complied with. Lower is better."
          tone={s.asr <= 0.05 ? 'good' : s.asr <= 0.2 ? 'warn' : 'bad'}
        />
        <Scorecard
          label="False-positive rate"
          value={pct(s.fpr)}
          hint="Share of benign controls the guard blocked. Lower is better."
          tone={s.fpr <= 0.05 ? 'good' : s.fpr <= 0.15 ? 'warn' : 'bad'}
        />
        <Scorecard label="F1" value={s.derived.f1.toFixed(3)} hint={`MCC ${s.derived.mcc.toFixed(3)} · precision ${s.derived.precision.toFixed(2)}`} />
        <Scorecard
          label="p95 added latency"
          value={`${s.latency.addedOverUnguarded.p95.toFixed(0)}ms`}
          hint={`Guard overhead over unguarded. Escalation rate ${pct(s.escalationRate)}.`}
        />
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Attack success vs false positives</CardTitle>
            <p className="text-xs text-muted-foreground">
              One point per run. Bottom-left is better on both axes; moving left costs coverage and moving down costs usability.
            </p>
          </CardHeader>
          <CardContent>
            <AsrFprScatter points={points} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Trend over time</CardTitle>
            <p className="text-xs text-muted-foreground">
              Both series improve downward. A drop in ASR that comes with a rise in FPR is not an improvement.
            </p>
          </CardHeader>
          <CardContent>
            <TrendChart points={trend} />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-base">Runs</CardTitle>
          <p className="text-xs text-muted-foreground">
            The same numbers as the charts above, as a table.
          </p>
        </CardHeader>
        <CardContent className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Run</TableHead>
                <TableHead>When</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead className="text-right">ASR</TableHead>
                <TableHead className="text-right">FPR</TableHead>
                <TableHead className="text-right">F1</TableHead>
                <TableHead className="text-right">Escalation</TableHead>
                <TableHead className="text-right">Cases</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {runs.map((r) => (
                <TableRow key={r.id}>
                  <TableCell>
                    <Link href={`/runs/${r.id}`} className="font-mono text-xs underline underline-offset-2">
                      {r.id}
                    </Link>
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">
                    {new Date(r.createdAt).toLocaleString()}
                  </TableCell>
                  <TableCell>
                    <Badge variant={r.mock ? 'secondary' : 'default'}>{r.mock ? 'mock' : 'live'}</Badge>
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{pct(r.scores?.asr)}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{pct(r.scores?.fpr)}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">
                    {r.scores ? r.scores.derived.f1.toFixed(3) : '—'}
                  </TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{pct(r.scores?.escalationRate)}</TableCell>
                  <TableCell className="text-right font-mono tabular-nums">{r.totalCases}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
