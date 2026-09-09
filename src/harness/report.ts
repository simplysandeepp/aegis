/**
 * Self-contained Markdown report.
 *
 * `runs/<id>/report.md` has to stand on its own well enough to cite: the exact
 * git SHA, whether the tree was dirty, the corpus hash, the resolved model IDs
 * and the full policy configuration are all embedded, so a number in the table
 * can always be traced back to the configuration that produced it.
 */

import type { ScoreReport } from './score';
import type { CaseResult, Matrix, RunMeta } from './types';
import { scoreBy } from './score';

const pct = (x: number): string => `${(x * 100).toFixed(1)}%`;
const ms = (x: number): string => `${x.toFixed(1)}ms`;

/** Cell contents may legitimately contain a pipe (config keys do), so escape. */
const cell = (s: string): string => s.replace(/\|/g, '\\|');

function table(headers: string[], rows: string[][]): string {
  const out = [
    `| ${headers.map(cell).join(' | ')} |`,
    `|${headers.map(() => '---').join('|')}|`,
  ];
  for (const r of rows) out.push(`| ${r.map(cell).join(' | ')} |`);
  return out.join('\n');
}

export function renderReport(args: {
  meta: RunMeta;
  matrix: Matrix;
  results: CaseResult[];
  report: ScoreReport;
}): string {
  const { meta, matrix, results, report } = args;
  const L: string[] = [];

  L.push(`# Aegis harness run \`${meta.runId}\``);
  L.push('');
  L.push(
    `${meta.mock ? '**Mock provider** (offline, deterministic).' : '**Live providers.**'} ` +
      `${report.n} results across ${matrix.policies.length} polic${matrix.policies.length === 1 ? 'y' : 'ies'}, ` +
      `${matrix.models.length} model(s), ${matrix.mitigations.length} mitigation set(s), repeat=${matrix.repeat}.`,
  );
  L.push('');

  // ---- headline -----------------------------------------------------------
  L.push('## Headline');
  L.push('');
  L.push(
    table(
      ['Metric', 'Value', 'What it means'],
      [
        ['**Attack success rate (ASR)**', `**${pct(report.asr)}**`, 'Of the attack cases, how often the model actually did what the attacker wanted'],
        ['**False-positive rate (FPR)**', `**${pct(report.fpr)}**`, 'Of the benign controls, how often the guard blocked or transformed'],
        ['Block rate on attacks', pct(report.blockRate), 'Recall of the guard against the attack set'],
        ['F1', report.derived.f1.toFixed(3), 'Harmonic mean of precision and recall'],
        ['MCC', report.derived.mcc.toFixed(3), 'Correlation coefficient, robust to class imbalance'],
        ['Precision', report.derived.precision.toFixed(3), 'Of everything blocked, how much was actually an attack'],
        ['Escalation rate', pct(report.escalationRate), 'Fraction of cases that cost an LLM-tier call'],
        ['LLM unavailable', pct(report.llmUnavailableRate), 'Cases where the judge could not be reached (degraded, traced)'],
      ],
    ),
  );
  L.push('');
  if (report.asrBootstrap) {
    const b = report.asrBootstrap;
    L.push(
      `ASR ${pct(b.mean)} ± ${(b.std * 100).toFixed(1)}pp, bootstrap 95% CI [${pct(b.ci95[0])}, ${pct(b.ci95[1])}] over ${b.samples} resamples.`,
    );
  }
  if (report.fprBootstrap) {
    const b = report.fprBootstrap;
    L.push(
      `FPR ${pct(b.mean)} ± ${(b.std * 100).toFixed(1)}pp, bootstrap 95% CI [${pct(b.ci95[0])}, ${pct(b.ci95[1])}].`,
    );
  }
  L.push('');

  // ---- confusion ----------------------------------------------------------
  const c = report.confusion;
  L.push('## Confusion matrix');
  L.push('');
  L.push(
    table(
      ['', 'Guard blocked', 'Guard allowed'],
      [
        ['**Attack** (expect block)', `${c.tp} (TP)`, `${c.fn} (FN)`],
        ['**Benign** (expect allow)', `${c.fp} (FP)`, `${c.tn} (TN)`],
      ],
    ),
  );
  L.push('');

  // ---- per family ---------------------------------------------------------
  L.push('## By family');
  L.push('');
  L.push(
    table(
      ['Family', 'n', 'attacks', 'benign', 'ASR', 'block rate', 'FPR', 'F1', 'MCC', 'TP/FP/TN/FN'],
      report.byFamily.map((f) => [
        f.family,
        String(f.n),
        String(f.attacks),
        String(f.benign),
        f.attacks ? pct(f.asr) : '—',
        f.attacks ? pct(f.blockRate) : '—',
        f.benign ? pct(f.fpr) : '—',
        f.f1.toFixed(2),
        f.mcc.toFixed(2),
        `${f.confusion.tp}/${f.confusion.fp}/${f.confusion.tn}/${f.confusion.fn}`,
      ]),
    ),
  );
  L.push('');

  // ---- per configuration --------------------------------------------------
  const perConfig = scoreBy(results, (r) => `${r.policyName} | ${r.model} | ${r.mitigations}`, { sweep: false });
  if (perConfig.length > 1) {
    L.push('## By configuration');
    L.push('');
    L.push(
      table(
        ['policy | model | mitigations', 'ASR', 'FPR', 'block rate', 'F1', 'escalation', 'judge tokens', 'p95 added latency'],
        perConfig.map(({ key, report: r }) => [
          key,
          pct(r.asr),
          pct(r.fpr),
          pct(r.blockRate),
          r.derived.f1.toFixed(2),
          pct(r.escalationRate),
          String(r.judgeTokens),
          ms(r.latency.addedOverUnguarded.p95),
        ]),
      ),
    );
    L.push('');
    L.push('_Comparing rows that differ only in their mitigation column isolates that mitigation\'s effect._');
    L.push('');
  }

  // ---- threshold sweep ----------------------------------------------------
  if (report.sweep) {
    L.push('## Escalation threshold sweep');
    L.push('');
    L.push(`ROC-style AUC over (FPR, block rate): **${report.sweep.auc.toFixed(3)}**`);
    L.push('');
    L.push(
      table(
        ['lowThreshold', 'highThreshold', 'ASR', 'FPR', 'block rate', 'escalation rate'],
        report.sweep.points
          .filter((_, i) => i % 2 === 0)
          .map((p) => [
            p.lowThreshold.toFixed(2),
            p.highThreshold.toFixed(2),
            pct(p.asr),
            pct(p.fpr),
            pct(p.blockRate),
            pct(p.escalationRate),
          ]),
      ),
    );
    L.push('');
    L.push(
      '_This is the headline research output: it shows what a given false-positive budget buys in attack coverage, and how much escalation (and therefore cost) each operating point implies._',
    );
    L.push('');
  }

  // ---- cost ---------------------------------------------------------------
  L.push('## Cost of the two-tier design');
  L.push('');
  L.push(
    table(
      ['Metric', 'Value'],
      [
        ['Escalation rate', pct(report.escalationRate)],
        ['Escalation (judge) tokens spent', String(report.judgeTokens)],
        ['Judge tokens if every case escalated', String(report.alwaysLlmTokensEstimate)],
        ['**Judge-token saving vs always-LLM**', `**${report.tokenSavingPct.toFixed(1)}%**`],
        ['Upstream provider tokens', String(report.providerTokens)],
        ['Total tokens', String(report.tokensUsed)],
      ],
    ),
  );
  L.push('');

  // ---- latency ------------------------------------------------------------
  L.push('## Latency');
  L.push('');
  L.push(
    table(
      ['Component', 'p50', 'p95', 'p99', 'mean'],
      [
        ['Rules tier', ms(report.latency.rules.p50), ms(report.latency.rules.p95), ms(report.latency.rules.p99), ms(report.latency.rules.mean)],
        ['LLM tier', ms(report.latency.llm.p50), ms(report.latency.llm.p95), ms(report.latency.llm.p99), ms(report.latency.llm.mean)],
        ['Provider', ms(report.latency.provider.p50), ms(report.latency.provider.p95), ms(report.latency.provider.p99), ms(report.latency.provider.mean)],
        ['**Added over unguarded**', ms(report.latency.addedOverUnguarded.p50), ms(report.latency.addedOverUnguarded.p95), ms(report.latency.addedOverUnguarded.p99), ms(report.latency.addedOverUnguarded.mean)],
      ],
    ),
  );
  L.push('');

  // ---- failures -----------------------------------------------------------
  const missed = results.filter((r) => r.expect === 'block' && r.attackSucceeded);
  if (missed.length) {
    L.push(`## Attacks that succeeded (${missed.length})`);
    L.push('');
    L.push(
      table(
        ['case', 'family', 'delivery', 'policy', 'mitigations', 'guard action', 'succeeded by'],
        missed.slice(0, 40).map((r) => [r.caseId, r.family, r.delivery, r.policyName, r.mitigations, r.guardAction, r.successBy ?? '—']),
      ),
    );
    if (missed.length > 40) L.push(`\n_…and ${missed.length - 40} more; see results.jsonl._`);
    L.push('');
  }

  const falsePositives = results.filter((r) => r.expect === 'allow' && r.blocked);
  if (falsePositives.length) {
    L.push(`## False positives (${falsePositives.length})`);
    L.push('');
    L.push(
      table(
        ['case', 'family', 'policy', 'mitigations', 'action', 'rules score', 'escalated'],
        falsePositives.slice(0, 40).map((r) => [
          r.caseId,
          r.family,
          r.policyName,
          r.mitigations,
          r.guardAction,
          r.rulesScore.toFixed(3),
          String(r.escalated),
        ]),
      ),
    );
    if (falsePositives.length > 40) L.push(`\n_…and ${falsePositives.length - 40} more._`);
    L.push('');
  }

  const errors = results.filter((r) => r.error);
  if (errors.length) {
    L.push(`## Errors (${errors.length})`);
    L.push('');
    for (const e of errors.slice(0, 15)) L.push(`- \`${e.caseId}\` (${e.model}): ${e.error}`);
    L.push('');
  }

  // ---- provenance ---------------------------------------------------------
  L.push('## Reproducibility');
  L.push('');
  L.push(
    table(
      ['Field', 'Value'],
      [
        ['Run ID', `\`${meta.runId}\``],
        ['Harness version', meta.harnessVersion],
        ['Started / finished', `${meta.startedAt} / ${meta.finishedAt ?? '(incomplete)'}`],
        ['Git SHA', `\`${meta.gitSha}\`${meta.gitDirty ? ' **(dirty working tree — results are not reproducible from this commit alone)**' : ''}`],
        ['Corpus hash', `\`${meta.corpusHash}\` (${meta.corpusFiles.join(', ')})`],
        ['Seed', `\`${meta.seed}\``],
        ['Node', meta.nodeVersion],
        ['Mock provider', String(meta.mock)],
        ['Command', `\`${meta.argv.join(' ')}\``],
      ],
    ),
  );
  L.push('');
  L.push('### Resolved models');
  L.push('');
  L.push(
    table(
      ['id', 'provider', 'provider id', 'unverified'],
      meta.models.map((m) => [`\`${m.id}\``, m.provider, `\`${m.providerId}\``, String(m.unverified)]),
    ),
  );
  L.push('');
  if (meta.limiter) {
    L.push(
      `Rate limiter: ${meta.limiter['calls']} calls, ${meta.limiter['retries']} retries, ` +
        `${meta.limiter['waitedMs']}ms spent backing off, ${meta.limiter['tokensSpent']}/${meta.limiter['tokenBudget']} tokens.`,
    );
    L.push('');
  }
  L.push('### Policy configuration (verbatim)');
  L.push('');
  L.push('<details><summary>Full policy JSON</summary>');
  L.push('');
  L.push('```json');
  L.push(JSON.stringify(meta.policies, null, 2));
  L.push('```');
  L.push('');
  L.push('</details>');
  L.push('');

  return L.join('\n');
}
