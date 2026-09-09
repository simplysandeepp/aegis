/**
 * Provider resolution and the LLM-tier judge client.
 *
 * Model IDs are provider-qualified everywhere in Aegis (`groq/…`, `google/…`)
 * and are only ever read from `config/models.ts`. Nothing here hardcodes one.
 */

import { createGroq } from '@ai-sdk/groq';
import { createGoogleGenerativeAI } from '@ai-sdk/google';
import { generateText, Output } from 'ai';
import type { LanguageModel } from 'ai';
import type { ZodType } from 'zod';

import {
  MODELS,
  assertModelVerified,
  defaultJudgeModel,
  findModel,
  type ModelEntry,
} from '@config/models';
import { googleApiKey, groqApiKey } from './env';
import { sharedLimiter, statusOf, type RateLimiter } from './ratelimit';
import { createMockModel, type MockOptions } from './mock';
import type { LlmClassifyResult, LlmJudge } from '../guard/types';

export class MissingApiKeyError extends Error {
  constructor(provider: string, envName: string) {
    super(
      `No API key for provider "${provider}". Set ${envName} in .env.local (see .env.example), ` +
        `or run offline with --mock.`,
    );
    this.name = 'MissingApiKeyError';
  }
}

export class UnknownModelError extends Error {
  constructor(id: string) {
    super(
      `Unknown model "${id}". Known ids: ${MODELS.map((m) => m.id).join(', ')}. ` +
        `Model IDs come only from config/models.ts — run \`npm run models:resolve\` to refresh them.`,
    );
    this.name = 'UnknownModelError';
  }
}

export function resolveModelEntry(id: string): ModelEntry {
  const entry = findModel(id);
  if (!entry) throw new UnknownModelError(id);
  return entry;
}

/** Build an AI SDK model for a provider-qualified id. */
export function getLanguageModel(id: string, mock?: MockOptions | false): LanguageModel {
  if (mock) return createMockModel(mock);
  const entry = resolveModelEntry(id);
  // Refuses loudly rather than letting a placeholder ID reach the network.
  assertModelVerified(entry);

  if (entry.provider === 'groq') {
    const apiKey = groqApiKey();
    if (!apiKey) throw new MissingApiKeyError('groq', 'GROQ_API_KEY');
    return createGroq({ apiKey })(entry.providerId);
  }
  const apiKey = googleApiKey();
  if (!apiKey) throw new MissingApiKeyError('google', 'GOOGLE_GENERATIVE_AI_API_KEY');
  return createGoogleGenerativeAI({ apiKey })(entry.providerId);
}

export interface JudgeOptions {
  /** Default judge model id. Falls back to config/models.ts. */
  modelId?: string;
  mock?: MockOptions | false;
  limiter?: RateLimiter;
  /** Cap on the judge's own output; keeps escalation cheap. */
  maxOutputTokens?: number;
}

/**
 * The `LlmJudge` used by the LLM-tier detectors.
 *
 * Contract: it NEVER throws. Every failure path — missing key, unverified
 * model, provider 5xx, rate limit exhaustion, timeout, schema mismatch, token
 * budget — comes back as `{ ok: false, error }`, which the detectors turn into
 * a traced degraded result. That is what keeps a dead provider from silently
 * becoming an "allow".
 */
export function createJudge(opts: JudgeOptions = {}): LlmJudge {
  const limiter = opts.limiter ?? sharedLimiter();

  return {
    async classify<T>(args: {
      schema: ZodType<T>;
      system: string;
      prompt: string;
      modelId?: string;
      signal?: AbortSignal;
    }): Promise<LlmClassifyResult<T>> {
      const modelId = args.modelId ?? opts.modelId ?? defaultJudgeModel().id;
      try {
        const model = getLanguageModel(modelId, opts.mock);

        const result = await limiter.run(async (signal) => {
          const merged = args.signal
            ? AbortSignal.any([signal, args.signal])
            : signal;
          return generateText({
            model,
            system: args.system,
            prompt: args.prompt,
            temperature: 0,
            maxOutputTokens: opts.maxOutputTokens ?? 1024,
            maxRetries: 0, // retries are the limiter's job, not the SDK's
            abortSignal: merged,
            output: Output.object({ schema: args.schema }),
          });
        }, `judge:${modelId}`);

        const tokensUsed = result.usage?.totalTokens ?? 0;
        limiter.chargeTokens(tokensUsed);

        const value = result.output as T | undefined;
        if (value === undefined) {
          return { ok: false, error: 'judge returned no structured output', modelId };
        }
        return { ok: true, value, tokensUsed, modelId };
      } catch (err) {
        const status = statusOf(err);
        const msg = err instanceof Error ? err.message : String(err);
        return {
          ok: false,
          error: status ? `HTTP ${status}: ${msg}` : msg,
          modelId,
        };
      }
    },
  };
}

/**
 * A judge backed by the deterministic mock, for tests and `--mock` runs.
 * It classifies with the same rules the mock model uses, so offline results
 * are stable and still non-trivial.
 */
export function createMockJudge(opts: { fail?: string } = {}): LlmJudge {
  return {
    async classify<T>(args: { schema: ZodType<T>; prompt: string }): Promise<LlmClassifyResult<T>> {
      if (opts.fail) return { ok: false, error: opts.fail, modelId: 'mock' };

      const text = args.prompt;
      const performing =
        /(ignore|disregard|forget)[^.\n]{0,40}(previous|above|prior|all)[^.\n]{0,30}(instruction|prompt|rule)/i.test(text) ||
        /(you are now|developer mode|do anything now|jailbreak)/i.test(text) ||
        /(system prompt|your instructions|repeat everything above)/i.test(text);
      const discussing =
        /(prompt injection|how (do|can|would)|explain|defend|mitigat|for example|research|paper|documentation)/i.test(text);
      const isInjection = performing && !discussing;

      const candidate = {
        isInjection,
        confidence: isInjection ? 0.86 : 0.8,
        family: isInjection ? 'instruction-override' : 'none',
        rationale: isInjection
          ? 'The text issues a directive to the model rather than describing one.'
          : 'The text discusses or merely mentions the technique; it does not issue a directive.',
        // llm-policy-judge shape
        violates: isInjection,
        clause: isInjection ? '1' : 'none',
        // llm-output-audit shape
        compliant: !isInjection,
        leaksSystemPrompt: /AEGIS-CANARY|here are my (full )?instructions/i.test(text),
        followedUntrustedInstructions: isInjection,
      };

      const parsed = args.schema.safeParse(candidate);
      if (!parsed.success) {
        return { ok: false, error: 'mock judge could not satisfy the requested schema', modelId: 'mock' };
      }
      return { ok: true, value: parsed.data, tokensUsed: 0, modelId: 'mock' };
    },
  };
}

export { MODELS, findModel, defaultJudgeModel };
export { createMockModel, createFailingModel } from './mock';
export type { ModelEntry };
