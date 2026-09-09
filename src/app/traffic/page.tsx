import Link from 'next/link';
import { listDecisions, decisionFacets } from '@/lib/dashboard/queries';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Badge } from '@/components/ui/badge';
import { Empty } from '@/components/empty';

export const dynamic = 'force-dynamic';

const ACTIONS = ['allow', 'flag', 'redact', 'rewrite', 'block'];

export default async function TrafficPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>;
}) {
  const sp = await searchParams;
  const one = (k: string): string | undefined => {
    const v = sp[k];
    return Array.isArray(v) ? v[0] : v;
  };

  const filter = { policy: one('policy'), action: one('action'), detector: one('detector'), limit: 200 };
  const rows = listDecisions(filter);
  const facets = decisionFacets();

  const detectorIds = [...new Set(rows.flatMap((r) => r.resultsParsed.map((d) => d.detectorId)))].sort();

  const chip = (label: string, key: string, value?: string) => {
    const next = new URLSearchParams(
      Object.entries({ ...filter, [key]: value }).filter(([, v]) => v && typeof v === 'string') as [string, string][],
    );
    next.delete('limit');
    const active = (filter as Record<string, unknown>)[key] === value;
    return (
      <Link
        key={`${key}:${value ?? 'all'}`}
        href={`/traffic?${next.toString()}`}
        className={`rounded-full border px-2.5 py-1 text-xs transition-colors ${
          active ? 'border-foreground bg-foreground text-background' : 'border-border hover:bg-muted'
        }`}
      >
        {label}
      </Link>
    );
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Traffic</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Live gateway decision log. Prompt text is stored as a SHA-256 hash unless{' '}
          <span className="font-mono">AEGIS_LOG_RAW=1</span>.
        </p>
      </div>

      <div className="space-y-2">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-xs text-muted-foreground">policy</span>
          {chip('all', 'policy', undefined)}
          {facets.policies.map((p) => chip(`${p.v} (${p.n})`, 'policy', p.v))}
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-xs text-muted-foreground">action</span>
          {chip('all', 'action', undefined)}
          {ACTIONS.filter((a) => facets.actions.some((f) => f.v === a)).map((a) =>
            chip(`${a} (${facets.actions.find((f) => f.v === a)?.n ?? 0})`, 'action', a),
          )}
        </div>
        {detectorIds.length ? (
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs text-muted-foreground">detector</span>
            {chip('all', 'detector', undefined)}
            {detectorIds.map((d) => chip(d, 'detector', d))}
          </div>
        ) : null}
      </div>

      {rows.length === 0 ? (
        <Empty
          title="No gateway traffic yet"
          hint={
            <>
              Send a request through the gateway, or use the{' '}
              <Link href="/playground" className="underline underline-offset-2">playground</Link>.
            </>
          }
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">{rows.length} most recent decisions</CardTitle>
          </CardHeader>
          <CardContent className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>When</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Stage</TableHead>
                  <TableHead>Policy</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead className="text-right">Rules</TableHead>
                  <TableHead>Escalated</TableHead>
                  <TableHead>Labels</TableHead>
                  <TableHead className="text-right">Total</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rows.map((d) => (
                  <TableRow key={d.id}>
                    <TableCell className="whitespace-nowrap text-xs text-muted-foreground">
                      {new Date(d.createdAt).toLocaleTimeString()}
                    </TableCell>
                    <TableCell className="text-xs">{d.source}</TableCell>
                    <TableCell className="text-xs">{d.stage}</TableCell>
                    <TableCell className="text-xs">{d.policyName}</TableCell>
                    <TableCell>
                      <Badge variant={d.action === 'block' ? 'destructive' : d.action === 'allow' ? 'secondary' : 'default'}>
                        {d.action}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{d.rulesScore.toFixed(3)}</TableCell>
                    <TableCell className="text-xs">
                      {d.escalated ? 'yes' : 'no'}
                      {d.llmUnavailable ? <Badge variant="destructive" className="ml-1">degraded</Badge> : null}
                    </TableCell>
                    <TableCell className="max-w-[280px]">
                      <div className="flex flex-wrap gap-1">
                        {d.labels.slice(0, 4).map((l) => (
                          <span key={l} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]">{l}</span>
                        ))}
                        {d.labels.length > 4 ? (
                          <span className="text-[10px] text-muted-foreground">+{d.labels.length - 4}</span>
                        ) : null}
                      </div>
                    </TableCell>
                    <TableCell className="text-right font-mono text-xs tabular-nums">{d.totalMs.toFixed(1)}ms</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
