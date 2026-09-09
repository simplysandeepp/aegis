'use client';

/**
 * Recharts wrappers.
 *
 * Rules applied throughout: one y-axis per chart, thin marks, recessive grid
 * and axes, a legend whenever there is more than one series, and a marker shape
 * per series so identity never rests on colour alone. Every chart is paired with
 * the same numbers in a table by its caller — that is also the relief for the
 * one light-mode hue below 3:1 contrast.
 */

import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
  LabelList,
} from 'recharts';
import { seriesColor, STATUS } from './theme';
import { useDark } from './use-dark';

const axisProps = (dark: boolean) => ({
  stroke: dark ? '#6b6a63' : '#9a9990',
  tick: { fill: dark ? '#c3c2b7' : '#52514e', fontSize: 11 },
  tickLine: false,
});

const gridProps = (dark: boolean) => ({
  stroke: dark ? '#33322e' : '#e7e6e1',
  strokeDasharray: '3 3',
  vertical: false,
});

const tooltipStyle = (dark: boolean) => ({
  contentStyle: {
    background: dark ? '#1a1a19' : '#fcfcfb',
    border: `1px solid ${dark ? '#33322e' : '#e7e6e1'}`,
    borderRadius: 8,
    fontSize: 12,
    color: dark ? '#ffffff' : '#0b0b0b',
  },
});

const pct = (v: number): string => `${(v * 100).toFixed(0)}%`;

/** Recharts hands the formatter a loose ValueType; narrow it here once. */
const pctFormatter = (v: unknown, n: unknown): [string, string] => [
  typeof v === 'number' ? `${(v * 100).toFixed(1)}%` : String(v),
  String(n),
];

// ---------------------------------------------------------------------------

export interface ScatterPoint {
  fpr: number;
  asr: number;
  label: string;
  group: string;
}

/**
 * ASR vs FPR across configurations — the headline comparison.
 * Bottom-left is better on both axes; the diagonal is the trade-off frontier.
 */
export function AsrFprScatter({ points }: { points: ScatterPoint[] }) {
  const dark = useDark();
  const groups = [...new Set(points.map((p) => p.group))];

  return (
    <ResponsiveContainer width="100%" height={320}>
      <ScatterChart margin={{ top: 16, right: 32, bottom: 32, left: 8 }}>
        <CartesianGrid {...gridProps(dark)} />
        <XAxis
          type="number"
          dataKey="fpr"
          name="False-positive rate"
          domain={[0, 'dataMax']}
          tickFormatter={pct}
          label={{ value: 'False-positive rate (benign controls blocked) →', position: 'insideBottom', offset: -18, fill: dark ? '#c3c2b7' : '#52514e', fontSize: 11 }}
          {...axisProps(dark)}
        />
        <YAxis
          type="number"
          dataKey="asr"
          name="Attack success rate"
          domain={[0, 'dataMax']}
          tickFormatter={pct}
          label={{ value: '↑ Attack success rate', angle: -90, position: 'insideLeft', fill: dark ? '#c3c2b7' : '#52514e', fontSize: 11 }}
          {...axisProps(dark)}
        />
        <ZAxis range={[90, 90]} />
        <Tooltip
          {...tooltipStyle(dark)}
          formatter={pctFormatter}
          labelFormatter={() => ''}
        />
        {groups.length > 1 && <Legend wrapperStyle={{ fontSize: 11 }} />}
        {groups.map((g, i) => (
          <Scatter
            key={g}
            name={g}
            data={points.filter((p) => p.group === g)}
            fill={seriesColor(i, dark)}
            shape={(['circle', 'square', 'triangle'] as const)[i % 3]}
          >
            <LabelList
              dataKey="label"
              position="right"
              style={{ fontSize: 10, fill: dark ? '#c3c2b7' : '#52514e' }}
            />
          </Scatter>
        ))}
      </ScatterChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------

export interface SweepPoint {
  highThreshold: number;
  asr: number;
  fpr: number;
  blockRate: number;
  escalationRate: number;
}

/** Threshold sweep: what a given false-positive budget buys in coverage. */
export function ThresholdSweepChart({ points }: { points: SweepPoint[] }) {
  const dark = useDark();
  return (
    <ResponsiveContainer width="100%" height={300}>
      <LineChart data={points} margin={{ top: 16, right: 24, bottom: 28, left: 8 }}>
        <CartesianGrid {...gridProps(dark)} />
        <XAxis
          dataKey="highThreshold"
          tickFormatter={(v: number) => v.toFixed(1)}
          label={{ value: 'Escalation highThreshold →', position: 'insideBottom', offset: -16, fill: dark ? '#c3c2b7' : '#52514e', fontSize: 11 }}
          {...axisProps(dark)}
        />
        <YAxis domain={[0, 1]} tickFormatter={pct} {...axisProps(dark)} />
        <Tooltip {...tooltipStyle(dark)} formatter={pctFormatter} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <Line type="monotone" dataKey="asr" name="Attack success rate" stroke={seriesColor(0, dark)} strokeWidth={2} dot={{ r: 3 }} />
        <Line type="monotone" dataKey="fpr" name="False-positive rate" stroke={seriesColor(1, dark)} strokeWidth={2} strokeDasharray="6 3" dot={{ r: 3 }} />
        <Line type="monotone" dataKey="escalationRate" name="Escalation rate" stroke={seriesColor(2, dark)} strokeWidth={2} strokeDasharray="2 3" dot={{ r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------

export interface FamilyBar {
  family: string;
  asr: number;
  fpr: number;
  blockRate: number;
}

export function FamilyBarChart({ data }: { data: FamilyBar[] }) {
  const dark = useDark();
  return (
    <ResponsiveContainer width="100%" height={Math.max(280, data.length * 30)}>
      <BarChart data={data} layout="vertical" margin={{ top: 8, right: 40, bottom: 8, left: 8 }} barCategoryGap={6}>
        <CartesianGrid {...gridProps(dark)} vertical horizontal={false} />
        <XAxis type="number" domain={[0, 1]} tickFormatter={pct} {...axisProps(dark)} />
        <YAxis type="category" dataKey="family" width={170} {...axisProps(dark)} />
        <Tooltip {...tooltipStyle(dark)} formatter={pctFormatter} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <Bar dataKey="blockRate" name="Block rate" fill={seriesColor(0, dark)} radius={[0, 4, 4, 0]} />
        <Bar dataKey="asr" name="Attack success rate" fill={seriesColor(1, dark)} radius={[0, 4, 4, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------

export interface HistBin {
  bucket: string;
  count: number;
}

export function LatencyHistogram({ bins }: { bins: HistBin[] }) {
  const dark = useDark();
  return (
    <ResponsiveContainer width="100%" height={240}>
      <BarChart data={bins} margin={{ top: 8, right: 16, bottom: 28, left: 8 }} barCategoryGap={2}>
        <CartesianGrid {...gridProps(dark)} />
        <XAxis
          dataKey="bucket"
          label={{ value: 'Added latency over unguarded (ms) →', position: 'insideBottom', offset: -16, fill: dark ? '#c3c2b7' : '#52514e', fontSize: 11 }}
          {...axisProps(dark)}
        />
        <YAxis allowDecimals={false} {...axisProps(dark)} />
        <Tooltip {...tooltipStyle(dark)} />
        <Bar dataKey="count" name="cases" fill={seriesColor(0, dark)} radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------

export interface TrendPoint {
  label: string;
  asr: number;
  fpr: number;
}

export function TrendChart({ points }: { points: TrendPoint[] }) {
  const dark = useDark();
  return (
    <ResponsiveContainer width="100%" height={240}>
      <LineChart data={points} margin={{ top: 8, right: 24, bottom: 24, left: 8 }}>
        <CartesianGrid {...gridProps(dark)} />
        <XAxis dataKey="label" {...axisProps(dark)} />
        <YAxis domain={[0, 1]} tickFormatter={pct} {...axisProps(dark)} />
        <Tooltip {...tooltipStyle(dark)} formatter={pctFormatter} />
        <Legend wrapperStyle={{ fontSize: 11 }} />
        <Line type="monotone" dataKey="asr" name="Attack success rate" stroke={seriesColor(0, dark)} strokeWidth={2} dot={{ r: 3 }} />
        <Line type="monotone" dataKey="fpr" name="False-positive rate" stroke={seriesColor(1, dark)} strokeWidth={2} strokeDasharray="6 3" dot={{ r: 3 }} />
      </LineChart>
    </ResponsiveContainer>
  );
}

// ---------------------------------------------------------------------------

/**
 * The rules score with the escalation band drawn on it. Colour marks the band,
 * but the band edges are labelled numerically as well, so the reading does not
 * depend on seeing the colour.
 */
export function ScoreBand({
  score,
  low,
  high,
  escalated,
}: {
  score: number;
  low: number;
  high: number;
  escalated: boolean;
}) {
  const clamp = (v: number): number => Math.max(0, Math.min(1, v));
  const band = escalated ? 'escalated to the LLM tier' : score >= high ? 'confident block' : 'confident allow';
  return (
    <div className="space-y-1">
      <div className="relative h-7 w-full overflow-hidden rounded-md border border-border bg-muted/40">
        <div className="absolute inset-y-0 left-0 bg-[color:var(--band-allow)]" style={{ width: `${clamp(low) * 100}%`, background: STATUS.good, opacity: 0.18 }} />
        <div className="absolute inset-y-0 bg-[color:var(--band-escalate)]" style={{ left: `${clamp(low) * 100}%`, width: `${clamp(high - low) * 100}%`, background: STATUS.warning, opacity: 0.22 }} />
        <div className="absolute inset-y-0 right-0" style={{ left: `${clamp(high) * 100}%`, background: STATUS.critical, opacity: 0.18 }} />
        <div
          className="absolute inset-y-0 w-0.5 bg-foreground"
          style={{ left: `${clamp(score) * 100}%` }}
          aria-hidden
        />
        <div className="absolute inset-0 flex items-center justify-between px-2 font-mono text-[10px] text-muted-foreground">
          <span>allow ≤ {low}</span>
          <span className="font-semibold text-foreground">{score.toFixed(3)}</span>
          <span>{high} ≤ block</span>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        Rules score <span className="font-mono">{score.toFixed(3)}</span> — {band}.
      </p>
    </div>
  );
}
