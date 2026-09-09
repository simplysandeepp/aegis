/**
 * Shared rate limiter for every provider call in the process.
 *
 * Free tiers rate-limit aggressively and a red-team matrix is exactly the shape
 * of traffic that trips them: hundreds of small requests as fast as the client
 * will emit them. Everything that talks to a provider goes through
 * `limiter.run()`, which enforces
 *
 *   - a concurrency cap (default 2, AEGIS_CONCURRENCY)
 *   - exponential backoff with full jitter on 429 and 503
 *   - `retry-after` when the provider sends one, in preference to our own backoff
 *   - a hard token budget that aborts the run rather than draining the daily quota
 *   - a per-attempt timeout, so a hung socket cannot stall a whole harness run
 *
 * Full jitter (rather than fixed backoff) matters with concurrency > 1: without
 * it, parallel workers that get 429'd retry in lockstep and trip the limit again.
 */

import { envNumber } from './env';

export class TokenBudgetExceededError extends Error {
  constructor(
    readonly spent: number,
    readonly budget: number,
  ) {
    super(
      `Aegis token budget exhausted: spent ${spent} of ${budget}. ` +
        `The run was aborted rather than continuing to consume free-tier quota. ` +
        `Raise AEGIS_TOKEN_BUDGET or narrow the matrix with --limit.`,
    );
    this.name = 'TokenBudgetExceededError';
  }
}

export interface RateLimiterOptions {
  concurrency?: number;
  maxRetries?: number;
  baseDelayMs?: number;
  maxDelayMs?: number;
  tokenBudget?: number;
  timeoutMs?: number;
  /** Injected for deterministic tests. */
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
}

export interface ProviderCallError extends Error {
  status?: number;
  retryAfterMs?: number;
}

/** Pull a status code out of whatever shape the provider SDK threw. */
export function statusOf(err: unknown): number | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const e = err as Record<string, unknown>;
  for (const k of ['status', 'statusCode']) {
    const v = e[k];
    if (typeof v === 'number') return v;
  }
  const resp = e['response'];
  if (resp && typeof resp === 'object') {
    const v = (resp as Record<string, unknown>)['status'];
    if (typeof v === 'number') return v;
  }
  const msg = typeof e['message'] === 'string' ? (e['message'] as string) : '';
  const m = /\b(429|503|500|502|504|401|403|404)\b/.exec(msg);
  return m?.[1] ? Number(m[1]) : undefined;
}

/** Honour an explicit `retry-after`, in seconds or as an HTTP date. */
export function retryAfterMsOf(err: unknown): number | undefined {
  if (!err || typeof err !== 'object') return undefined;
  const e = err as Record<string, unknown>;
  const headers = (e['responseHeaders'] ?? e['headers']) as Record<string, string> | undefined;
  const raw =
    headers?.['retry-after'] ??
    headers?.['Retry-After'] ??
    headers?.['x-ratelimit-reset-requests'] ??
    headers?.['x-ratelimit-reset-tokens'];
  if (!raw) return undefined;
  const secs = Number(raw);
  if (Number.isFinite(secs)) return Math.max(0, secs * 1000);
  const m = /^([\d.]+)(ms|s|m)$/.exec(String(raw).trim());
  if (m?.[1]) {
    const n = Number(m[1]);
    const unit = m[2];
    return unit === 'ms' ? n : unit === 'm' ? n * 60_000 : n * 1000;
  }
  const date = Date.parse(String(raw));
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : undefined;
}

const RETRYABLE = new Set([408, 409, 425, 429, 500, 502, 503, 504]);

export class RateLimiter {
  private readonly concurrency: number;
  private readonly maxRetries: number;
  private readonly baseDelayMs: number;
  private readonly maxDelayMs: number;
  private readonly timeoutMs: number;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly random: () => number;

  private active = 0;
  private queue: Array<() => void> = [];

  tokenBudget: number;
  private tokensSpent = 0;
  private callCount = 0;
  private retryCount = 0;
  private waitedMs = 0;

  constructor(opts: RateLimiterOptions = {}) {
    this.concurrency = Math.max(1, opts.concurrency ?? envNumber('AEGIS_CONCURRENCY', 2));
    this.maxRetries = opts.maxRetries ?? 5;
    this.baseDelayMs = opts.baseDelayMs ?? 500;
    this.maxDelayMs = opts.maxDelayMs ?? 30_000;
    this.tokenBudget = opts.tokenBudget ?? envNumber('AEGIS_TOKEN_BUDGET', 200_000);
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
    this.random = opts.random ?? Math.random;
  }

  stats() {
    return {
      calls: this.callCount,
      retries: this.retryCount,
      tokensSpent: this.tokensSpent,
      tokenBudget: this.tokenBudget,
      waitedMs: Math.round(this.waitedMs),
    };
  }

  chargeTokens(n: number): void {
    this.tokensSpent += Math.max(0, n);
  }

  get remainingTokens(): number {
    return Math.max(0, this.tokenBudget - this.tokensSpent);
  }

  assertBudget(): void {
    if (this.tokensSpent >= this.tokenBudget) {
      throw new TokenBudgetExceededError(this.tokensSpent, this.tokenBudget);
    }
  }

  private async acquire(): Promise<void> {
    if (this.active < this.concurrency) {
      this.active++;
      return;
    }
    await new Promise<void>((resolve) => this.queue.push(resolve));
    this.active++;
  }

  private release(): void {
    this.active--;
    const next = this.queue.shift();
    if (next) next();
  }

  /** Full-jitter exponential backoff: random in [0, min(cap, base * 2^n)]. */
  private backoffMs(attempt: number): number {
    const ceiling = Math.min(this.maxDelayMs, this.baseDelayMs * 2 ** attempt);
    return Math.floor(this.random() * ceiling);
  }

  /**
   * Run a provider call under the concurrency cap, retrying transient failures.
   * `fn` receives an AbortSignal wired to the per-attempt timeout.
   */
  async run<T>(fn: (signal: AbortSignal) => Promise<T>, label = 'provider'): Promise<T> {
    this.assertBudget();
    await this.acquire();
    try {
      let lastErr: unknown;
      for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(new Error(`${label} timed out after ${this.timeoutMs}ms`)), this.timeoutMs);
        try {
          this.callCount++;
          return await fn(ac.signal);
        } catch (err) {
          lastErr = err;
          const status = statusOf(err);
          const retryable = status === undefined ? isNetworkish(err) : RETRYABLE.has(status);
          if (!retryable || attempt === this.maxRetries) throw err;
          const explicit = retryAfterMsOf(err);
          const delay = explicit ?? this.backoffMs(attempt);
          this.retryCount++;
          this.waitedMs += delay;
          await this.sleep(delay);
        } finally {
          clearTimeout(timer);
        }
      }
      throw lastErr;
    } finally {
      this.release();
    }
  }
}

function isNetworkish(err: unknown): boolean {
  const msg = err instanceof Error ? err.message : String(err);
  return /(ECONNRESET|ETIMEDOUT|ENOTFOUND|EAI_AGAIN|socket hang up|network|fetch failed|timed out|aborted)/i.test(msg);
}

/** Process-wide limiter. Both the gateway and the harness share it. */
let shared: RateLimiter | undefined;

export function sharedLimiter(): RateLimiter {
  if (!shared) shared = new RateLimiter();
  return shared;
}

export function resetSharedLimiter(opts?: RateLimiterOptions): RateLimiter {
  shared = new RateLimiter(opts);
  return shared;
}
