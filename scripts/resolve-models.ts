/**
 * Resolves live model IDs from the Groq and Google free tiers and rewrites
 * `config/models.ts`.
 *
 * Model IDs are NEVER hardcoded from memory anywhere else in this repo —
 * `config/models.ts` is the single source of truth and this script is the only
 * thing that writes it. Groq in particular deprecates models frequently, so
 * re-run this whenever calls start failing with `model_decommissioned`.
 *
 *   npx tsx scripts/resolve-models.ts
 *
 * With no API keys present the script still writes the file, but every entry is
 * marked `unverified: true` so the runtime refuses to make a real call instead
 * of silently hitting a dead model ID.
 */
import { writeFileSync, existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Load .env.local / .env without pulling in a dotenv dependency.
for (const f of ['.env.local', '.env']) {
  const p = resolve(process.cwd(), f);
  if (!existsSync(p)) continue;
  for (const line of readFileSync(p, 'utf8').split('\n')) {
    const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

type Provider = 'groq' | 'google';
type Role = 'target' | 'judge';

interface Candidate {
  providerId: string;
  provider: Provider;
  contextWindow?: number;
  ownedBy?: string;
}

const GROQ_KEY = process.env.GROQ_API_KEY ?? '';
const GOOGLE_KEY = process.env.GOOGLE_GENERATIVE_AI_API_KEY ?? '';

async function fetchGroq(): Promise<Candidate[]> {
  if (!GROQ_KEY) return [];
  const res = await fetch('https://api.groq.com/openai/v1/models', {
    headers: { Authorization: `Bearer ${GROQ_KEY}` },
  });
  if (!res.ok) {
    console.error(`[groq] model list failed: ${res.status} ${await res.text()}`);
    return [];
  }
  const json = (await res.json()) as {
    data: Array<{ id: string; context_window?: number; owned_by?: string; active?: boolean }>;
  };
  return json.data
    .filter((m) => m.active !== false)
    .map((m) => ({
      providerId: m.id,
      provider: 'groq' as const,
      contextWindow: m.context_window,
      ownedBy: m.owned_by,
    }));
}

async function fetchGoogle(): Promise<Candidate[]> {
  if (!GOOGLE_KEY) return [];
  const out: Candidate[] = [];
  let pageToken = '';
  do {
    const url = new URL('https://generativelanguage.googleapis.com/v1beta/models');
    url.searchParams.set('key', GOOGLE_KEY);
    url.searchParams.set('pageSize', '200');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const res = await fetch(url);
    if (!res.ok) {
      console.error(`[google] model list failed: ${res.status} ${await res.text()}`);
      return out;
    }
    const json = (await res.json()) as {
      models?: Array<{
        name: string;
        inputTokenLimit?: number;
        supportedGenerationMethods?: string[];
challenge?: unknown;
      }>;
      nextPageToken?: string;
    };
    for (const m of json.models ?? []) {
      const methods = m.supportedGenerationMethods ?? [];
      if (methods.length && !methods.includes('generateContent')) continue;
      out.push({
        providerId: m.name.replace(/^models\//, ''),
        provider: 'google',
        contextWindow: m.inputTokenLimit,
      });
    }
    pageToken = json.nextPageToken ?? '';
  } while (pageToken);
  return out;
}

/**
 * Split an ID into comparable tokens: `gemini-3.8-flash` -> [gemini, 3, 8, flash].
 *
 * Token matching matters more than it looks: a naive substring test for "mini"
 * matches every *ge-mini* model, and "lite" would match nothing useful without
 * knowing where the word boundaries are.
 */
function tokens(id: string): string[] {
  return id.toLowerCase().split(/[-_./]/).filter(Boolean);
}

/**
 * Reject anything that is not a general-purpose text chat model. The live
 * catalogs are full of TTS, image, audio, robotics and deep-research endpoints
 * that would be meaningless in a text guardrail benchmark.
 */
const BAD_TOKENS = new Set([
  // modality / task-specific endpoints
  'whisper', 'tts', 'transcribe', 'speech', 'audio', 'orpheus', 'realtime',
  'embedding', 'embed', 'rerank', 'imagen', 'veo', 'image', 'lyria', 'omni',
  'robotics', 'video',
  // classifier / moderation heads, not chat models
  'guard', 'safeguard', 'moderation', 'safety', 'aqa',
  // agentic harnesses that browse the web — not a clean target for measuring
  // prompt-injection resistance, since they add their own tool surface
  'compound', 'antigravity', 'customtools',
  // language-specialised or legacy
  'allam', 'learnlm', 'bison',
]);

const BAD_PHRASES = ['deep-research', 'nano-banana', 'computer-use', 'prompt-guard'];

function isChatty(c: Candidate): boolean {
  const id = c.providerId.toLowerCase();
  if (BAD_PHRASES.some((b) => id.includes(b))) return false;
  return !tokens(id).some((t) => BAD_TOKENS.has(t));
}

/** Parameter count in billions, parsed from ids like `gpt-oss-120b`. */
function paramsB(id: string): number | undefined {
  const m = /(?:^|[^a-z0-9])(\d{1,3})b(?:[^a-z0-9]|$)/.exec(id);
  return m ? Number(m[1]) : undefined;
}

/** Highest `major.minor` version mentioned in the id (3.8 -> 3.08 so 3.10 > 3.8 is false but 3.8 > 3.1 is true). */
function version(id: string): number {
  let best = 0;
  for (const m of id.matchAll(/(\d+)\.(\d+)/g)) {
    best = Math.max(best, Number(m[1]) + Number(m[2]) / 100);
  }
  if (best === 0) {
    const solo = /(?:^|[^\d.])(\d)(?:[^\d.]|$)/.exec(id.replace(/\d+b/g, ''));
    if (solo) best = Number(solo[1]);
  }
  return best;
}

/**
 * Collapse a model ID to its family, dropping only the version numbers:
 *   gemini-3.8-flash        -> gemini-flash
 *   gemini-2.5-flash-lite   -> gemini-flash-lite
 *   qwen/qwen3.8-27b        -> qwen-27b
 *   openai/gpt-oss-120b     -> gpt-oss-120b
 *
 * Version numbers are only comparable WITHIN a family — "gemma-4" is not newer
 * than "gemini-3.8" in any meaningful sense. So we rank by version inside a
 * family, then rank families against each other purely on role fit.
 */
function familyKey(id: string): string {
  const bare = id.toLowerCase().split('/').pop() ?? id;
  return bare
    .split(/[-_.]/)
    .map((t) => t.replace(/^\d+$/, ''))            // bare version token
    .map((t) => t.replace(/(?<=[a-z])\d+$/, ''))   // qwen3 -> qwen
    .filter(Boolean)
    .join('-');
}

/**
 * How well a model suits its role, independent of version.
 *   target — the system under test; capable, flash/large class
 *   judge  — the LLM-tier detectors; must be small and fast because the
 *            escalation router calls it on every uncertain request
 */
function roleFit(c: Candidate, role: Role): number {
  const id = c.providerId.toLowerCase();
  let s = 0;

  const t = tokens(id);
  const isLite =
    t.includes('lite') || t.includes('mini') || t.includes('small') || t.includes('instant');
  const isFlash = t.includes('flash');
  const isPro = t.includes('pro');
  const p = paramsB(id);

  if (role === 'judge') {
    if (isLite) s += 40;
    if (isFlash) s += 15;
    if (isPro) s -= 40;
    if (p !== undefined) s += Math.max(0, 40 - p / 2); // smaller wins
  } else {
    if (isFlash) s += 20; // flash-class is what a free tier actually affords
    if (isPro) s += 10;
    if (isLite) s -= 25;
    if (p !== undefined) s += Math.min(40, p / 4); // bigger wins
  }

  // Reproducibility: pinned stable versions beat moving aliases and previews.
  if (t.includes('latest')) s -= 30;
  if (t.some((x) => ['preview', 'exp', 'experimental', 'beta'].includes(x))) s -= 35;
  if (/-\d{2}-\d{4}$/.test(id)) s -= 10; // dated snapshot
  if (/deprecated/.test(id)) s -= 500;

  if (c.contextWindow) s += Math.min(8, Math.log10(c.contextWindow));
  return s;
}

/**
 * Pick the best candidate for a role: newest member of each family, then the
 * best-fitting family. `exclude` keeps the judge and target slots distinct.
 */
function pick(
  cands: Candidate[],
  provider: Provider,
  role: Role,
  exclude: Set<string> = new Set(),
): Candidate | undefined {
  const pool = cands.filter(
    (c) => c.provider === provider && isChatty(c) && !exclude.has(c.providerId),
  );

  // newest within each family
  const byFamily = new Map<string, Candidate>();
  for (const c of pool) {
    const k = familyKey(c.providerId);
    const cur = byFamily.get(k);
    if (!cur || version(c.providerId) > version(cur.providerId)) byFamily.set(k, c);
  }

  return [...byFamily.values()].sort((a, b) => roleFit(b, role) - roleFit(a, role))[0];
}

/** Used only when a provider's live list is unavailable. Marked unverified. */
const PLACEHOLDERS: Record<string, { providerId: string; note: string }> = {
  'groq:target': {
    providerId: 'UNRESOLVED-groq-target',
    note: 'No GROQ_API_KEY at resolve time. Run `npm run models:resolve` with a key.',
  },
  'groq:judge': {
    providerId: 'UNRESOLVED-groq-judge',
    note: 'No GROQ_API_KEY at resolve time. Run `npm run models:resolve` with a key.',
  },
  'google:target': {
    providerId: 'UNRESOLVED-google-target',
    note: 'No GOOGLE_GENERATIVE_AI_API_KEY at resolve time. Run `npm run models:resolve` with a key.',
  },
  'google:judge': {
    providerId: 'UNRESOLVED-google-judge',
    note: 'No GOOGLE_GENERATIVE_AI_API_KEY at resolve time. Run `npm run models:resolve` with a key.',
  },
};

async function main() {
  const [groq, google] = await Promise.all([fetchGroq(), fetchGoogle()]);
  const all = [...groq, ...google];
  console.log(`[resolve] groq: ${groq.length} models, google: ${google.length} models`);

  const rows: string[] = [];
  const combos: Array<[Provider, Role]> = [
    ['groq', 'target'],
    ['groq', 'judge'],
    ['google', 'target'],
    ['google', 'judge'],
  ];

  // Judge is the constrained slot (small + fast), so choose it first and keep
  // the target distinct from it.
  const chosenByKey = new Map<string, Candidate | undefined>();
  for (const provider of ['groq', 'google'] as Provider[]) {
    const judge = pick(all, provider, 'judge');
    chosenByKey.set(`${provider}:judge`, judge);
    chosenByKey.set(
      `${provider}:target`,
      pick(all, provider, 'target', new Set(judge ? [judge.providerId] : [])),
    );
  }

  for (const [provider, role] of combos) {
    const key = `${provider}:${role}`;
    const chosen = chosenByKey.get(key);
    if (chosen) {
      rows.push(
        `  {\n` +
          `    key: '${key}',\n` +
          `    id: '${provider}/${chosen.providerId}',\n` +
          `    provider: '${provider}',\n` +
          `    providerId: '${chosen.providerId}',\n` +
          `    role: '${role}',\n` +
          `    contextWindow: ${chosen.contextWindow ?? 'undefined'},\n` +
          `    unverified: false,\n` +
          `  },`,
      );
    } else {
      const ph = PLACEHOLDERS[key];
      rows.push(
        `  {\n` +
          `    key: '${key}',\n` +
          `    id: '${provider}/${ph.providerId}',\n` +
          `    provider: '${provider}',\n` +
          `    providerId: '${ph.providerId}',\n` +
          `    role: '${role}',\n` +
          `    contextWindow: undefined,\n` +
          `    unverified: true,\n` +
          `    note: ${JSON.stringify(ph.note)},\n` +
          `  },`,
      );
    }
  }

  const stamp = new Date().toISOString();
  const listing = all.length
    ? all.map((c) => ` *   ${c.provider}/${c.providerId}`).join('\n')
    : ' *   (none — no API keys were present when this file was generated)';

  const file = `/**
 * GENERATED FILE — do not edit by hand.
 * Written by \`scripts/resolve-models.ts\` (npm run models:resolve).
 *
 * Model IDs fetched live at: ${stamp}
 *
 * This is the ONLY place in the repository where a concrete model ID appears.
 * Groq deprecates models on short notice; if you see \`model_decommissioned\`
 * errors, re-run the resolver rather than editing this file.
 *
 * Full live listing at resolve time:
${listing}
 */

export type ModelProvider = 'groq' | 'google';
export type ModelRole = 'target' | 'judge';

export interface ModelEntry {
  /** Stable slot name, e.g. 'groq:judge'. */
  key: string;
  /** Provider-qualified ID used everywhere in Aegis, e.g. 'groq/llama-x'. */
  id: string;
  provider: ModelProvider;
  /** Raw ID handed to the provider SDK. */
  providerId: string;
  role: ModelRole;
  contextWindow: number | undefined;
  /**
   * True when the ID could not be confirmed against the provider's live model
   * list. Any attempt to make a real (non-mock) call with an unverified model
   * throws — see \`assertModelVerified\`.
   */
  unverified: boolean;
  note?: string;
}

export const MODELS_RESOLVED_AT = ${JSON.stringify(stamp)};

export const MODELS: ModelEntry[] = [
${rows.join('\n')}
];

export function findModel(idOrKey: string): ModelEntry | undefined {
  return MODELS.find((m) => m.id === idOrKey || m.key === idOrKey);
}

/** Default model used by the LLM-tier detectors (smallest / fastest). */
export function defaultJudgeModel(): ModelEntry {
  const verified = MODELS.find((m) => m.role === 'judge' && !m.unverified);
  return verified ?? MODELS.filter((m) => m.role === 'judge')[0];
}

/** Default model proxied by the gateway when the caller does not name one. */
export function defaultTargetModel(): ModelEntry {
  const verified = MODELS.find((m) => m.role === 'target' && !m.unverified);
  return verified ?? MODELS.filter((m) => m.role === 'target')[0];
}

export class UnverifiedModelError extends Error {
  constructor(entry: ModelEntry) {
    super(
      [
        \`Aegis refuses to call the unverified model "\${entry.id}".\`,
        entry.note ? \`  Reason: \${entry.note}\` : '',
        '',
        '  Model IDs in config/models.ts were generated without provider access,',
        '  so this ID is a placeholder and would fail at the provider anyway.',
        '',
        '  Fix: put GROQ_API_KEY / GOOGLE_GENERATIVE_AI_API_KEY in .env.local and run',
        '    npm run models:resolve',
        '',
        '  Or run offline with the deterministic mock provider:',
        '    npm run harness -- --mock',
      ]
        .filter(Boolean)
        .join('\\n'),
    );
    this.name = 'UnverifiedModelError';
  }
}

/** Throws loudly rather than letting a dead model ID reach the network. */
export function assertModelVerified(entry: ModelEntry): void {
  if (entry.unverified) throw new UnverifiedModelError(entry);
}
`;

  writeFileSync(resolve(process.cwd(), 'config/models.ts'), file, 'utf8');
  console.log('[resolve] wrote config/models.ts');
  for (const [provider, role] of combos) {
    const c = chosenByKey.get(`${provider}:${role}`);
    console.log(`  ${provider}:${role} -> ${c ? c.providerId : '(unresolved)'}`);
  }
}

void main();
