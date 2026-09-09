/**
 * Environment loading.
 *
 * Reads `.env.local` then `.env` without adding a dotenv dependency, and
 * accepts short aliases (`GROQ`, `GEMINI`) alongside the canonical provider
 * variable names, because those are what people actually paste in.
 */

import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

let loaded = false;

export function loadEnv(): void {
  if (loaded) return;
  loaded = true;
  for (const file of ['.env.local', '.env']) {
    const p = resolve(process.cwd(), file);
    if (!existsSync(p)) continue;
    for (const line of readFileSync(p, 'utf8').split('\n')) {
      const m = /^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line);
      if (!m || line.trimStart().startsWith('#')) continue;
      const key = m[1];
      if (!key || process.env[key]) continue;
      process.env[key] = (m[2] ?? '').replace(/^["']|["']$/g, '');
    }
  }
}

function firstEnv(...names: string[]): string | undefined {
  loadEnv();
  for (const n of names) {
    const v = process.env[n];
    if (v && v.trim()) return v.trim();
  }
  return undefined;
}

export function groqApiKey(): string | undefined {
  return firstEnv('GROQ_API_KEY', 'GROQ');
}

export function googleApiKey(): string | undefined {
  return firstEnv('GOOGLE_GENERATIVE_AI_API_KEY', 'GEMINI', 'GOOGLE_API_KEY', 'GEMINI_API_KEY');
}

export function envNumber(name: string, fallback: number): number {
  loadEnv();
  const v = process.env[name];
  const n = v ? Number(v) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

export function envFlag(name: string): boolean {
  loadEnv();
  const v = process.env[name];
  return v === '1' || v === 'true' || v === 'yes';
}

export function logRawEnabled(): boolean {
  return envFlag('AEGIS_LOG_RAW');
}
