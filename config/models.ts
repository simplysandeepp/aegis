/**
 * GENERATED FILE — do not edit by hand.
 * Written by `scripts/resolve-models.ts` (npm run models:resolve).
 *
 * Model IDs fetched live at: 2026-09-09T08:02:33.129Z
 *
 * This is the ONLY place in the repository where a concrete model ID appears.
 * Groq deprecates models on short notice; if you see `model_decommissioned`
 * errors, re-run the resolver rather than editing this file.
 *
 * Full live listing at resolve time:
 *   groq/canopylabs/orpheus-arabic-saudi
 *   groq/whisper-large-v3-turbo
 *   groq/qwen/qwen3.8-27b
 *   groq/groq/compound-mini
 *   groq/canopylabs/orpheus-v1-english
 *   groq/allam-2-7b
 *   groq/meta-llama/llama-prompt-guard-2-86m
 *   groq/openai/gpt-oss-20b
 *   groq/meta-llama/llama-prompt-guard-2-22m
 *   groq/groq/compound
 *   groq/openai/gpt-oss-120b
 *   groq/openai/gpt-oss-safeguard-20b
 *   groq/whisper-large-v3
 *   groq/qwen/qwen3.6-27b
 *   google/gemini-2.5-flash
 *   google/gemini-2.5-pro
 *   google/gemini-2.5-flash-preview-tts
 *   google/gemini-2.5-pro-preview-tts
 *   google/gemma-4-26b-a4b-it
 *   google/gemma-4-31b-it
 *   google/gemini-flash-latest
 *   google/gemini-flash-lite-latest
 *   google/gemini-pro-latest
 *   google/gemini-2.5-flash-lite
 *   google/gemini-2.5-flash-image
 *   google/gemini-3-flash-preview
 *   google/gemini-3.1-pro-preview
 *   google/gemini-3.1-pro-preview-customtools
 *   google/gemini-3.1-flash-lite-preview
 *   google/gemini-3.1-flash-lite
 *   google/gemini-3-pro-image-preview
 *   google/gemini-3-pro-image
 *   google/nano-banana-pro-preview
 *   google/gemini-3.1-flash-image-preview
 *   google/gemini-3.1-flash-image
 *   google/gemini-3.1-flash-lite-image
 *   google/gemini-3.5-flash
 *   google/gemini-3.5-flash-lite
 *   google/gemini-omni-flash-preview
 *   google/gemini-omni-1.1-flash
 *   google/gemini-3.5-transcribe
 *   google/gemini-3.6-flash
 *   google/gemini-3.7-flash
 *   google/gemini-3.8-flash
 *   google/lyria-3-clip-preview
 *   google/lyria-3-pro-preview
 *   google/lyria-3.5
 *   google/gemini-3.1-flash-tts-preview
 *   google/gemini-robotics-er-2-preview
 *   google/gemini-2.5-computer-use-preview-10-2025
 *   google/antigravity-preview-05-2026
 *   google/deep-research-max-preview-04-2026
 *   google/deep-research-preview-04-2026
 *   google/deep-research-pro-preview-12-2025
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
   * throws — see `assertModelVerified`.
   */
  unverified: boolean;
  note?: string;
}

export const MODELS_RESOLVED_AT = "2026-09-09T08:02:33.129Z";

export const MODELS: ModelEntry[] = [
  {
    key: 'groq:target',
    id: 'groq/openai/gpt-oss-120b',
    provider: 'groq',
    providerId: 'openai/gpt-oss-120b',
    role: 'target',
    contextWindow: 131072,
    unverified: false,
  },
  {
    key: 'groq:judge',
    id: 'groq/openai/gpt-oss-20b',
    provider: 'groq',
    providerId: 'openai/gpt-oss-20b',
    role: 'judge',
    contextWindow: 131072,
    unverified: false,
  },
  {
    key: 'google:target',
    id: 'google/gemini-3.8-flash',
    provider: 'google',
    providerId: 'gemini-3.8-flash',
    role: 'target',
    contextWindow: 1048576,
    unverified: false,
  },
  {
    key: 'google:judge',
    id: 'google/gemini-3.5-flash-lite',
    provider: 'google',
    providerId: 'gemini-3.5-flash-lite',
    role: 'judge',
    contextWindow: 1048576,
    unverified: false,
  },
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
        `Aegis refuses to call the unverified model "${entry.id}".`,
        entry.note ? `  Reason: ${entry.note}` : '',
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
        .join('\n'),
    );
    this.name = 'UnverifiedModelError';
  }
}

/** Throws loudly rather than letting a dead model ID reach the network. */
export function assertModelVerified(entry: ModelEntry): void {
  if (entry.unverified) throw new UnverifiedModelError(entry);
}
