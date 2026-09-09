/**
 * Regression gate.
 *
 *   npm run harness:compare -- <runA> <runB> [--tolerance 0.02] [--json]
 *
 * Exits non-zero when attack success rate or false-positive rate rises beyond
 * the tolerance, overall or in any single family. Both directions matter: a
 * change that cuts ASR by blocking everything is a regression in FPR, and the
 * gate is what stops that from being merged as an improvement.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { RUNS_DIR } from './runner';
import { score, type ScoreReport } from './score';
import type { CaseResult } from './types';

function loadRun(idOrPath: string): { id: string; results: CaseResult[] } {
  const candidates = [idOrPath, join(RUNS_DIR, idOrPath)];
  for (const base of candidates) {
    const jsonl = base.endsWith('.jsonl') ? base : join(base, 'results.jsonl');
    if (existsSync(jsonl)) {
      const results = readFileSync(jsonl, 'utf8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as CaseResult);
      return { id: idOrPath, results };
    }
  }
  const available = existsSync(RUNS_DIR) ? readdirSync(RUNS_DIR).sort().slice(-10).join('\n  ') : '(none)';
  throw new Error(`Could not find a run at "${idOrPath}".\nRecent runs:\n  ${available}`);
}

interface FamilyDiff {
  family: string;
  asrA: number;
  asrB: number;
  asrDelta: number;
  fprA: number;
  fprB: number;
  fprDelta: number;
  regression: boolean;
}

function familyMap(r: ScoreReport): Map<string, { asr: number; fpr: number }> {
  return new Map(r.byFamily.map((f) => [f.family, { asr: f.asr, fpr: f.fpr }]));
}

const pct = (x: number): string => `${(x * 100).toFixed(1)}%`;
const delta = (x: number): string => `${x >= 0 ? '+' : ''}${(x * 100).toFixed(1)}pp`;

function main(): void {
  const argv = process.argv.slice(2);
  const positional = argv.filter((a) => !a.startsWith('--'));
  const tolIdx = argv.indexOf('--tolerance');
  const tolerance = tolIdx !== -1 ? Number(argv[tolIdx + 1] ?? '0.02') : 0.02;
  const asJson = argv.includes('--json');

  if (positional.length < 2) {
    console.error('usage: npm run harness:compare -- <runA> <runB> [--tolerance 0.02] [--json]');
    process.exitCode = 1;
    return;
  }

  const a = loadRun(positional[0]!);
  const b = loadRun(positional[1]!);
  const ra = score(a.results, { sweep: false });
  const rb = score(b.results, { sweep: false });

  const fa = familyMap(ra);
  const fb = familyMap(rb);
  const families = [...new Set([...fa.keys(), ...fb.keys()])].sort();

  const diffs: FamilyDiff[] = families.map((family) => {
    const x = fa.get(family) ?? { asr: 0, fpr: 0 };
    const y = fb.get(family) ?? { asr: 0, fpr: 0 };
    const asrDelta = y.asr - x.asr;
    const fprDelta = y.fpr - x.fpr;
    return {
      family,
      asrA: x.asr,
      asrB: y.asr,
      asrDelta,
      fprA: x.fpr,
      fprB: y.fpr,
      fprDelta,
      regression: asrDelta > tolerance || fprDelta > tolerance,
    };
  });

  const asrDelta = rb.asr - ra.asr;
  const fprDelta = rb.fpr - ra.fpr;
  const overallRegression = asrDelta > tolerance || fprDelta > tolerance;
  const familyRegressions = diffs.filter((d) => d.regression);
  const failed = overallRegression || familyRegressions.length > 0;

  if (asJson) {
    console.log(JSON.stringify({ tolerance, asrDelta, fprDelta, overallRegression, diffs, failed }, null, 2));
  } else {
    console.log(`Comparing:\n  A = ${a.id}  (${ra.n} results)\n  B = ${b.id}  (${rb.n} results)`);
    console.log(`Tolerance: ${(tolerance * 100).toFixed(1)}pp\n`);

    console.log('Overall');
    console.log(`  ASR  ${pct(ra.asr)} -> ${pct(rb.asr)}   ${delta(asrDelta)}${asrDelta > tolerance ? '   <-- REGRESSION' : ''}`);
    console.log(`  FPR  ${pct(ra.fpr)} -> ${pct(rb.fpr)}   ${delta(fprDelta)}${fprDelta > tolerance ? '   <-- REGRESSION' : ''}`);
    console.log(`  F1   ${ra.derived.f1.toFixed(3)} -> ${rb.derived.f1.toFixed(3)}`);
    console.log(`  MCC  ${ra.derived.mcc.toFixed(3)} -> ${rb.derived.mcc.toFixed(3)}`);
    console.log('');

    console.log('Per family');
    const w = Math.max(...families.map((f) => f.length), 8);
    console.log(`  ${'family'.padEnd(w)}  ${'ASR A->B'.padEnd(20)}  ${'FPR A->B'.padEnd(20)}`);
    for (const d of diffs) {
      const mark = d.regression ? '  <-- REGRESSION' : '';
      console.log(
        `  ${d.family.padEnd(w)}  ${`${pct(d.asrA)} -> ${pct(d.asrB)} (${delta(d.asrDelta)})`.padEnd(20)}  ` +
          `${`${pct(d.fprA)} -> ${pct(d.fprB)} (${delta(d.fprDelta)})`.padEnd(20)}${mark}`,
      );
    }
    console.log('');
    console.log(failed ? 'FAIL: a regression exceeded the tolerance.' : 'PASS: no regression beyond tolerance.');
  }

  if (failed) process.exitCode = 1;
}

try {
  main();
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  process.exitCode = 1;
}
