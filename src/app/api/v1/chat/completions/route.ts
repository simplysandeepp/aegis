/**
 * POST /v1/chat/completions — OpenAI-compatible guarded proxy.
 *
 * Any existing OpenAI-client app points at this by changing one base URL.
 *
 * Extra controls, all optional, via headers:
 *   x-aegis-policy  policy name (default: balanced)
 *   x-aegis-trust   JSON map of message index -> trust label, e.g. {"2":"retrieved"}
 *   x-aegis-canary  "off" to opt out of canary injection
 *   x-aegis-mock    "1" to use the deterministic mock provider
 *
 * Response headers on every reply:
 *   x-aegis-decision  the action taken
 *   x-aegis-reasons   short reason codes (never detector internals)
 *   x-aegis-latency   total guard time in ms
 *   x-aegis-escalated whether the LLM tier was consulted
 *   x-aegis-policy-hash
 */

import { NextResponse } from 'next/server';
import { randomUUID } from 'node:crypto';

import { loadPolicy, UnknownPolicyError } from '@/lib/guard/policy';
import { runGuard } from '@/lib/guard/router';
import { createJudge, createMockJudge, getLanguageModel } from '@/lib/providers';
import { defaultTargetModel } from '@config/models';
import {
  callProvider,
  guardOutput,
  persistDecision,
  prepareInput,
  redactableSpansOf,
  redactParts,
  streamWithGuard,
  toProviderMessages,
} from '@/lib/gateway/pipeline';
import {
  chatCompletionRequestSchema,
  trustHeaderSchema,
  type ChatCompletionRequest,
} from '@/lib/gateway/types';
import type { Decision, Trust } from '@/lib/guard/types';
import { ACTION_RANK } from '@/lib/guard/util';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/** Short, non-revealing reason codes. Detector internals stay server-side. */
function reasonCodes(decision: Decision): string {
  const codes = new Set<string>();
  for (const r of decision.results) {
    if (!r.triggered) continue;
    for (const l of r.labels) codes.add(l.split(':').slice(0, 2).join(':'));
  }
  if (decision.llmUnavailable) codes.add('llm:unavailable');
  return [...codes].slice(0, 12).join(',') || 'none';
}

function aegisHeaders(decision: Decision, extra: Record<string, string> = {}): Record<string, string> {
  return {
    'x-aegis-decision': decision.action,
    'x-aegis-reasons': reasonCodes(decision),
    'x-aegis-latency': decision.latency.totalMs.toFixed(1),
    'x-aegis-escalated': String(decision.escalatedToLlm),
    'x-aegis-rules-score': decision.rulesScore.toFixed(3),
    'x-aegis-policy': decision.policyName,
    'x-aegis-policy-hash': decision.policyHash,
    'x-aegis-llm-unavailable': String(decision.llmUnavailable),
    ...extra,
  };
}

function openAiResponse(args: {
  id: string;
  model: string;
  content: string;
  finishReason: string;
  promptTokens?: number;
  completionTokens?: number;
}) {
  return {
    id: args.id,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: args.model,
    choices: [
      {
        index: 0,
        message: { role: 'assistant', content: args.content },
        finish_reason: args.finishReason,
      },
    ],
    usage: {
      prompt_tokens: args.promptTokens ?? 0,
      completion_tokens: args.completionTokens ?? 0,
      total_tokens: (args.promptTokens ?? 0) + (args.completionTokens ?? 0),
    },
  };
}

function sseChunk(id: string, model: string, delta: string, finish: string | null): string {
  return `data: ${JSON.stringify({
    id,
    object: 'chat.completion.chunk',
    created: Math.floor(Date.now() / 1000),
    model,
    choices: [{ index: 0, delta: finish ? {} : { content: delta }, finish_reason: finish }],
  })}\n\n`;
}

export async function POST(req: Request): Promise<Response> {
  const id = `chatcmpl-${randomUUID()}`;

  // ---- parse + validate -------------------------------------------------
  let body: ChatCompletionRequest;
  try {
    body = chatCompletionRequestSchema.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: { message: `Invalid request body: ${err instanceof Error ? err.message : String(err)}`, type: 'invalid_request_error' } },
      { status: 400 },
    );
  }

  const policyName = req.headers.get('x-aegis-policy') ?? 'balanced';
  let loaded;
  try {
    loaded = loadPolicy(policyName);
  } catch (err) {
    const status = err instanceof UnknownPolicyError ? 400 : 500;
    return NextResponse.json(
      { error: { message: err instanceof Error ? err.message : String(err), type: 'invalid_request_error' } },
      { status },
    );
  }
  const { policy, hash: policyHash } = loaded;

  let trustOverrides: Record<string, Trust> | undefined;
  const trustHeader = req.headers.get('x-aegis-trust');
  if (trustHeader) {
    try {
      trustOverrides = trustHeaderSchema.parse(JSON.parse(trustHeader));
    } catch {
      return NextResponse.json(
        { error: { message: 'x-aegis-trust must be a JSON object mapping message index to one of: system, user, tool, retrieved', type: 'invalid_request_error' } },
        { status: 400 },
      );
    }
  }

  const mock = req.headers.get('x-aegis-mock') === '1';
  const canaryOff = req.headers.get('x-aegis-canary') === 'off';
  const modelId = body.model ?? defaultTargetModel().id;
  const responseSchema =
    body.response_format?.type === 'json_schema'
      ? body.response_format.json_schema?.schema
      : undefined;

  // ---- prepare: sanitize, mitigate, plant the canary --------------------
  const prepared = prepareInput({
    messages: body.messages,
    trustOverrides,
    policy: canaryOff ? { ...policy, mitigations: { ...policy.mitigations, canary: false } } : policy,
  });

  const llm = mock ? createMockJudge() : createJudge();

  // ---- input guard ------------------------------------------------------
  const inputDecision = await runGuard({
    stage: 'input',
    text: prepared.analyzedText,
    rawText: prepared.rawText,
    parts: prepared.parts,
    policy,
    policyHash,
    llm,
    canary: prepared.canary,
  });

  persistDecision({
    source: 'gateway',
    model: modelId,
    decision: inputDecision,
    analyzedText: prepared.analyzedText,
  });

  if (inputDecision.action === 'block' || inputDecision.action === 'rewrite') {
    // A well-formed OpenAI response so existing clients keep working.
    return NextResponse.json(
      openAiResponse({
        id,
        model: modelId,
        content: inputDecision.transformedText ?? policy.refusalMessage,
        finishReason: 'content_filter',
      }),
      { status: 200, headers: aegisHeaders(inputDecision, { 'x-aegis-stage': 'input' }) },
    );
  }

  // ---- provider ---------------------------------------------------------
  let model;
  try {
    model = getLanguageModel(modelId, mock ? { canary: prepared.canary } : false);
  } catch (err) {
    return NextResponse.json(
      { error: { message: err instanceof Error ? err.message : String(err), type: 'server_error' } },
      { status: 502, headers: aegisHeaders(inputDecision) },
    );
  }

  // A `redact` verdict on the input must actually rewrite the messages before
  // they go upstream, otherwise the secret is forwarded and the action is a lie.
  let inputRedacted = false;
  if (inputDecision.action === 'redact') {
    const spans = redactableSpansOf(inputDecision);
    if (spans.length > 0) {
      prepared.parts = redactParts(prepared.parts, spans);
      inputRedacted = true;
    }
  }

  const providerPrompt = toProviderMessages(prepared);

  // ---- streaming path ---------------------------------------------------
  if (body.stream) {
    const { stream, done } = streamWithGuard({
      model,
      prompt: providerPrompt,
      temperature: body.temperature,
      maxOutputTokens: body.max_tokens,
      policy,
      policyHash,
      llm,
      parts: prepared.parts,
      canary: prepared.canary,
      responseSchema,
    });

    const encoder = new TextEncoder();
    const sse = new ReadableStream<Uint8Array>({
      async start(controller) {
        const reader = stream.getReader();
        try {
          for (;;) {
            const { done: d, value } = await reader.read();
            if (d) break;
            if (value) controller.enqueue(encoder.encode(sseChunk(id, modelId, value, null)));
          }
          const { decision } = await done;
          persistDecision({
            source: 'gateway',
            model: modelId,
            decision,
            analyzedText: prepared.analyzedText,
            outputText: decision.transformedText,
          });
          controller.enqueue(
            encoder.encode(
              sseChunk(id, modelId, '', decision.action === 'allow' || decision.action === 'flag' ? 'stop' : 'content_filter'),
            ),
          );
          controller.enqueue(encoder.encode('data: [DONE]\n\n'));
        } finally {
          controller.close();
        }
      },
    });

    return new Response(sse, {
      status: 200,
      headers: {
        'Content-Type': 'text/event-stream; charset=utf-8',
        'Cache-Control': 'no-cache, no-transform',
        Connection: 'keep-alive',
        ...aegisHeaders(inputDecision, {
          'x-aegis-stage': 'input',
          'x-aegis-stream-window': String(policy.streamWindowChars),
        }),
      },
    });
  }

  // ---- non-streaming path ----------------------------------------------
  const provider = await callProvider({
    model,
    prompt: providerPrompt,
    temperature: body.temperature,
    maxOutputTokens: body.max_tokens,
    label: `gateway:${modelId}`,
  });

  if (provider.error) {
    return NextResponse.json(
      { error: { message: `Upstream provider failed: ${provider.error}`, type: 'server_error' } },
      { status: 502, headers: aegisHeaders(inputDecision, { 'x-aegis-provider-error': '1' }) },
    );
  }

  const outputDecision = await guardOutput(provider.text, {
    policy,
    policyHash,
    llm,
    parts: prepared.parts,
    canary: prepared.canary,
    responseSchema,
    toolCalls: provider.toolCalls,
    providerMs: provider.providerMs,
  });

  persistDecision({
    source: 'gateway',
    model: modelId,
    decision: outputDecision,
    analyzedText: prepared.analyzedText,
    outputText: provider.text,
  });

  const content =
    outputDecision.action === 'block'
      ? policy.refusalMessage
      : (outputDecision.transformedText ?? provider.text);

  // The reported action is the most restrictive across both stages, so a
  // redaction applied to the input is visible to the caller even when the
  // output itself came back clean.
  const reported = ACTION_RANK[inputDecision.action] > ACTION_RANK[outputDecision.action]
    ? { ...outputDecision, action: inputDecision.action }
    : outputDecision;

  return NextResponse.json(
    openAiResponse({
      id,
      model: modelId,
      content,
      finishReason: outputDecision.action === 'allow' || outputDecision.action === 'flag' ? 'stop' : 'content_filter',
      completionTokens: provider.tokensUsed,
    }),
    {
      status: 200,
      headers: aegisHeaders(reported, {
        'x-aegis-stage': 'output',
        'x-aegis-input-decision': inputDecision.action,
        'x-aegis-input-redacted': String(inputRedacted),
      }),
    },
  );
}
