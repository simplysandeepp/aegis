/**
 * Database handle.
 *
 * better-sqlite3 in WAL mode at `.data/aegis.db`. The schema is created
 * idempotently at first touch so `npm run dev` works on a clean checkout with
 * no migration step; `npm run db:migrate` runs the same DDL explicitly and is
 * what CI uses.
 */

import Database from 'better-sqlite3';
import { drizzle, type BetterSQLite3Database } from 'drizzle-orm/better-sqlite3';
import { mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import * as schema from './schema';
import { loadEnv } from '../providers/env';

export const MIGRATION_SQL = `
CREATE TABLE IF NOT EXISTS decisions (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  source TEXT NOT NULL,
  stage TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  model TEXT NOT NULL,
  action TEXT NOT NULL,
  escalated INTEGER NOT NULL,
  llm_unavailable INTEGER NOT NULL,
  rules_score REAL NOT NULL,
  final_score REAL NOT NULL,
  text_hash TEXT NOT NULL,
  raw_text TEXT,
  raw_output TEXT,
  reasons TEXT NOT NULL,
  results TEXT NOT NULL,
  labels TEXT NOT NULL,
  rules_ms REAL NOT NULL,
  llm_ms REAL NOT NULL,
  provider_ms REAL NOT NULL,
  total_ms REAL NOT NULL,
  tokens_used INTEGER NOT NULL,
  provider_error TEXT,
  run_id TEXT,
  case_id TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_created ON decisions(created_at);
CREATE INDEX IF NOT EXISTS idx_decisions_policy  ON decisions(policy_name);
CREATE INDEX IF NOT EXISTS idx_decisions_action  ON decisions(action);
CREATE INDEX IF NOT EXISTS idx_decisions_run     ON decisions(run_id);

CREATE TABLE IF NOT EXISTS runs (
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  finished_at INTEGER,
  meta TEXT NOT NULL,
  matrix TEXT NOT NULL,
  scores TEXT,
  total_cases INTEGER NOT NULL,
  completed_cases INTEGER NOT NULL,
  tokens_used INTEGER NOT NULL,
  mock INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_runs_created ON runs(created_at);

CREATE TABLE IF NOT EXISTS results (
  id TEXT PRIMARY KEY,
  run_id TEXT NOT NULL,
  case_id TEXT NOT NULL,
  family TEXT NOT NULL,
  delivery TEXT NOT NULL,
  expect TEXT NOT NULL,
  policy_name TEXT NOT NULL,
  policy_hash TEXT NOT NULL,
  model TEXT NOT NULL,
  mitigations TEXT NOT NULL,
  repeat_idx INTEGER NOT NULL,
  guard_action TEXT NOT NULL,
  blocked INTEGER NOT NULL,
  attack_succeeded INTEGER NOT NULL,
  escalated INTEGER NOT NULL,
  llm_unavailable INTEGER NOT NULL,
  rules_score REAL NOT NULL,
  final_score REAL NOT NULL,
  rules_ms REAL NOT NULL,
  llm_ms REAL NOT NULL,
  provider_ms REAL NOT NULL,
  total_ms REAL NOT NULL,
  ttft_ms REAL,
  tokens_used INTEGER NOT NULL,
  trace TEXT NOT NULL,
  error TEXT
);
CREATE INDEX IF NOT EXISTS idx_results_run    ON results(run_id);
CREATE INDEX IF NOT EXISTS idx_results_family ON results(family);
CREATE INDEX IF NOT EXISTS idx_results_case   ON results(case_id);
`;

export type Db = BetterSQLite3Database<typeof schema>;

let cached: { db: Db; raw: Database.Database; path: string } | undefined;

export function dbPath(): string {
  loadEnv();
  return resolve(process.cwd(), process.env['AEGIS_DB_PATH'] || '.data/aegis.db');
}

export function getDb(path = dbPath()): Db {
  if (cached && cached.path === path) return cached.db;
  mkdirSync(dirname(path), { recursive: true });
  const raw = new Database(path);
  raw.pragma('journal_mode = WAL');
  raw.pragma('busy_timeout = 5000');
  raw.exec(MIGRATION_SQL);
  const db = drizzle(raw, { schema });
  cached = { db, raw, path };
  return db;
}

export function rawDb(path = dbPath()): Database.Database {
  getDb(path);
  if (!cached) throw new Error('database not initialised');
  return cached.raw;
}

export function closeDb(): void {
  cached?.raw.close();
  cached = undefined;
}

export { schema };
export * from './schema';
