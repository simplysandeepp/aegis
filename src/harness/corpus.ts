/**
 * Corpus loading.
 *
 * `CorpusLoader` is the extension point: a public dataset can be added by
 * implementing this interface and registering it, without touching the runner.
 * See RESEARCH.md.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import type { CorpusCase } from './types';

const caseSchema = z.object({
  id: z.string().min(1),
  family: z.string().min(1),
  delivery: z.enum(['direct', 'indirect-doc', 'tool-result', 'multi-turn']),
  severity: z.string(),
  expect: z.enum(['block', 'allow']),
  payload: z.string(),
  turns: z.array(z.string()).default([]),
  success: z
    .object({
      canaryLeak: z.boolean().optional(),
      regex: z.string().optional(),
      judgeRubric: z.string().optional(),
    })
    .default({}),
  source: z.string().default('unknown'),
  notes: z.string().optional(),
  trust: z.enum(['user', 'tool', 'retrieved']).optional(),
});

export interface CorpusLoader {
  id: string;
  description: string;
  load(): Promise<CorpusCase[]>;
}

export const CORPUS_DIR = resolve(process.cwd(), 'corpus');

/** Default loader: every `*.yaml` in `corpus/`. */
export const yamlCorpusLoader: CorpusLoader = {
  id: 'yaml',
  description: 'Hand-authored YAML cases in corpus/*.yaml',
  async load() {
    return loadYamlCorpus().cases;
  },
};

const loaders = new Map<string, CorpusLoader>([[yamlCorpusLoader.id, yamlCorpusLoader]]);

export function registerCorpusLoader(l: CorpusLoader): void {
  loaders.set(l.id, l);
}

export function getCorpusLoader(id: string): CorpusLoader | undefined {
  return loaders.get(id);
}

export function listCorpusLoaders(): CorpusLoader[] {
  return [...loaders.values()];
}

export interface LoadedCorpus {
  cases: CorpusCase[];
  files: string[];
  /** SHA-256 over the raw file contents, recorded in the run meta. */
  hash: string;
}

export function loadYamlCorpus(dir = CORPUS_DIR): LoadedCorpus {
  if (!existsSync(dir)) return { cases: [], files: [], hash: 'none' };
  const files = readdirSync(dir)
    .filter((f) => f.endsWith('.yaml') || f.endsWith('.yml'))
    .sort();

  const hasher = createHash('sha256');
  const cases: CorpusCase[] = [];
  const seen = new Set<string>();

  for (const f of files) {
    const raw = readFileSync(join(dir, f), 'utf8');
    hasher.update(`${f}\n${raw}`);
    const parsed = parse(raw) as unknown;
    if (!Array.isArray(parsed)) continue;
    for (const [i, entry] of parsed.entries()) {
      const r = caseSchema.safeParse(entry);
      if (!r.success) {
        throw new Error(`corpus/${f} entry ${i} is invalid: ${r.error.issues.map((x) => `${x.path.join('.')} ${x.message}`).join('; ')}`);
      }
      if (seen.has(r.data.id)) throw new Error(`Duplicate corpus case id "${r.data.id}" in corpus/${f}`);
      seen.add(r.data.id);
      cases.push(r.data as CorpusCase);
    }
  }

  return { cases, files, hash: hasher.digest('hex').slice(0, 16) };
}

/** Taint label implied by how the payload is delivered. */
export function trustFor(c: CorpusCase): 'user' | 'tool' | 'retrieved' {
  if (c.trust) return c.trust;
  if (c.delivery === 'indirect-doc') return 'retrieved';
  if (c.delivery === 'tool-result') return 'tool';
  return 'user';
}

export function corpusStats(cases: readonly CorpusCase[]) {
  const byFamily = new Map<string, number>();
  for (const c of cases) byFamily.set(c.family, (byFamily.get(c.family) ?? 0) + 1);
  return {
    total: cases.length,
    attacks: cases.filter((c) => c.expect === 'block').length,
    benign: cases.filter((c) => c.expect === 'allow').length,
    families: [...byFamily.entries()].sort((a, b) => b[1] - a[1]),
  };
}
