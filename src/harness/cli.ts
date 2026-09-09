/**
 * Harness CLI.
 *
 *   npm run harness -- --policy strict,balanced --models groq/... \
 *     --families all --mitigations spotlight:on,spotlight:off \
 *     --repeat 3 --concurrency 2 --limit 50 --mock
 */

import { writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { loadEnv } from '../lib/providers/env';
import { resetSharedLimiter } from '../lib/providers/ratelimit';
import { defaultTargetModel, MODELS } from '../../config/models';
import { listPolicyNames } from '../lib/guard/policy';
import { corpusStats, loadYamlCorpus } from './corpus';
import { parseMitigations, persistRun, runMatrix, HARNESS_VERSION } from './runner';
import { renderReport } from './report';
import { score } from './score';
import type { Matrix, MitigationSet } from './types';

loadEnv();

interface Args {
  policy: string[];
  models: string[];
  families: string[] | 'all';
  mitigations: MitigationSet[];
  repeat: number;
  concurrency: number;
  limit?: number;
  mock: boolean;
  noCache: boolean;
  seed: string;
  expect?: 'block' | 'allow';
  quiet: boolean;
}

function parseArgs(argv: string[]): Args {
  const get = (name: string): string | undefined => {
    const i = argv.indexOf(`--${name}`);
    if (i === -1) return undefined;
    const v = argv[i + 1];
    return v && !v.startsWith('--') ? v : 'true';
  };
  const has = (name: string): boolean => argv.includes(`--${name}`);

  const mitSpec = get('mitigations');
  // "spotlight:on,spotlight:off" means two runs, not one combined set.
  const mitigations: MitigationSet[] = mitSpec
    ? splitMitigationSets(mitSpec)
    : [parseMitigations('')];

  return {
    policy: (get('policy') ?? 'balanced').split(',').map((s) => s.trim()).filter(Boolean),
    models: (get('models') ?? (has('mock') ? 'mock/deterministic' : defaultTargetModel().id))
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
    families: get('families') === 'all' || !get('families') ? 'all' : get('families')!.split(',').map((s) => s.trim()),
    mitigations,
    repeat: Number(get('repeat') ?? 1),
    concurrency: Number(get('concurrency') ?? 2),
    limit: get('limit') ? Number(get('limit')) : undefined,
    mock: has('mock'),
    noCache: has('no-cache'),
    seed: get('seed') ?? '42',
    expect: get('expect') as 'block' | 'allow' | undefined,
    quiet: has('quiet'),
  };
}

/**
 * `spotlight:on,spotlight:off` describes two configurations to compare;
 * `spotlight:on,sandwich:on` describes one configuration with both enabled.
 * Split on repeated mitigation names.
 */
function splitMitigationSets(spec: string): MitigationSet[] {
  const parts = spec.split(',').map((s) => s.trim()).filter(Boolean);
  const seen = new Map<string, string[]>();
  for (const p of parts) {
    const name = p.split(':')[0] ?? p;
    const list = seen.get(name) ?? [];
    list.push(p);
    seen.set(name, list);
  }
  const maxVariants = Math.max(1, ...[...seen.values()].map((v) => v.length));
  if (maxVariants === 1) return [parseMitigations(spec)];

  const sets: MitigationSet[] = [];
  for (let i = 0; i < maxVariants; i++) {
    const combo = [...seen.values()].map((v) => v[Math.min(i, v.length - 1)]).filter(Boolean);
    sets.push(parseMitigations(combo.join(',')));
  }
  // de-duplicate by canonical key
  const byKey = new Map(sets.map((s) => [s.key, s]));
  return [...byKey.values()];
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.includes('--help') || argv.includes('-h')) {
    console.log(`aegis harness v${HARNESS_VERSION}

  --policy      comma-separated policy names            (default: balanced)
                available: ${listPolicyNames().join(', ')}
  --models      comma-separated model ids               (default: ${defaultTargetModel().id})
                available: ${MODELS.map((m) => m.id).join(', ')}
  --families    comma-separated families, or "all"      (default: all)
  --mitigations e.g. spotlight:on,spotlight:off         (default: policy default)
  --repeat      runs per cell, for variance             (default: 1)
  --concurrency parallel cases                          (default: 2)
  --limit       cap the number of corpus cases          (default: all)
  --expect      only run cases expecting block|allow
  --seed        seed recorded in the run metadata       (default: 42)
  --mock        deterministic offline provider, no keys needed
  --no-cache    ignore the content-addressed result cache
  --quiet       suppress per-case progress
`);
    return;
  }

  const args = parseArgs(argv);
  const corpus = loadYamlCorpus();
  if (corpus.cases.length === 0) {
    console.error('No corpus cases found in corpus/*.yaml');
    process.exitCode = 1;
    return;
  }

  let cases = corpus.cases;
  if (args.families !== 'all') cases = cases.filter((c) => (args.families as string[]).includes(c.family));
  if (args.expect) cases = cases.filter((c) => c.expect === args.expect);
  if (args.limit) {
    // Keep the attack/benign balance when truncating, otherwise a --limit run
    // reports a false-positive rate computed from almost no controls.
    const attacks = cases.filter((c) => c.expect === 'block');
    const benign = cases.filter((c) => c.expect === 'allow');
    const half = Math.max(1, Math.floor(args.limit / 2));
    cases = [...attacks.slice(0, half), ...benign.slice(0, args.limit - Math.min(half, attacks.length))];
  }

  const stats = corpusStats(cases);
  const matrix: Matrix = {
    policies: args.policy,
    models: args.models,
    mitigations: args.mitigations,
    repeat: args.repeat,
    limit: args.limit,
    families: args.families === 'all' ? undefined : args.families,
  };

  const total =
    cases.length * args.policy.length * args.models.length * args.mitigations.length * args.repeat;

  console.log(
    `[harness] ${stats.total} cases (${stats.attacks} attacks, ${stats.benign} benign) ` +
      `x ${args.policy.length} policies x ${args.models.length} models x ${args.mitigations.length} mitigation sets x repeat ${args.repeat} = ${total} runs`,
  );
  console.log(`[harness] mode: ${args.mock ? 'MOCK (offline)' : 'LIVE providers'}  concurrency: ${args.concurrency}`);

  resetSharedLimiter({ concurrency: args.concurrency });

  const started = Date.now();
  const outcome = await runMatrix({
    cases,
    corpusHash: corpus.hash,
    corpusFiles: corpus.files,
    matrix,
    mock: args.mock,
    seed: args.seed,
    argv: ['npm', 'run', 'harness', '--', ...argv],
    concurrency: args.concurrency,
    noCache: args.noCache,
    onProgress: args.quiet
      ? undefined
      : (done, all, last) => {
          if (done % 10 === 0 || done === all) {
            process.stdout.write(
              `\r[harness] ${done}/${all}  last=${last.caseId} ${last.guardAction}${last.cached ? ' (cached)' : ''}   `,
            );
          }
        },
  });
  if (!args.quiet) process.stdout.write('\n');

  if (outcome.aborted) {
    console.error(`[harness] ABORTED: ${outcome.aborted}`);
  }

  const report = score(outcome.results, { seed: Number(args.seed) || 42, repeats: args.repeat });

  const md = renderReport({ meta: outcome.meta, matrix, results: outcome.results, report });
  writeFileSync(join(outcome.dir, 'report.md'), md, 'utf8');
  writeFileSync(join(outcome.dir, 'scores.json'), JSON.stringify(report, null, 2), 'utf8');

  persistRun(outcome, matrix, report);

  const secs = ((Date.now() - started) / 1000).toFixed(1);
  console.log('');
  console.log(`[harness] run ${outcome.runId} finished in ${secs}s`);
  console.log(`[harness]   ASR  ${(report.asr * 100).toFixed(1)}%   (attack success rate — lower is better)`);
  console.log(`[harness]   FPR  ${(report.fpr * 100).toFixed(1)}%   (false positives on benign controls — lower is better)`);
  console.log(`[harness]   block rate ${(report.blockRate * 100).toFixed(1)}%   F1 ${report.derived.f1.toFixed(3)}   MCC ${report.derived.mcc.toFixed(3)}`);
  console.log(`[harness]   escalation ${(report.escalationRate * 100).toFixed(1)}%   judge tokens ${report.judgeTokens} vs ${report.alwaysLlmTokensEstimate} if always-LLM (${report.tokenSavingPct.toFixed(1)}% saved)`);
  console.log(`[harness]   p95 added latency ${report.latency.addedOverUnguarded.p95.toFixed(1)}ms`);
  console.log(`[harness] wrote ${join(outcome.dir, 'report.md')}`);
  console.log(`[harness]       ${join(outcome.dir, 'results.jsonl')}`);

  if (outcome.aborted) process.exitCode = 2;
}

void main().catch((err) => {
  console.error('[harness] fatal:', err instanceof Error ? err.stack : err);
  process.exitCode = 1;
});
