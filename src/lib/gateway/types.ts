/** OpenAI-compatible request/response shapes, validated with Zod. */

import { z } from 'zod';

export const chatMessageSchema = z.object({
  role: z.enum(['system', 'user', 'assistant', 'tool', 'developer']),
  content: z.union([
    z.string(),
    z.array(
      z.object({
        type: z.string(),
        text: z.string().optional(),
      }),
    ),
    z.null(),
  ]),
  name: z.string().optional(),
  tool_call_id: z.string().optional(),
  tool_calls: z
    .array(
      z.object({
        id: z.string(),
        type: z.literal('function').optional(),
        function: z.object({ name: z.string(), arguments: z.string() }),
      }),
    )
    .optional(),
});

export const chatCompletionRequestSchema = z.object({
  model: z.string().optional(),
  messages: z.array(chatMessageSchema).min(1),
  stream: z.boolean().optional(),
  temperature: z.number().min(0).max(2).optional(),
  max_tokens: z.number().int().positive().max(32_000).optional(),
  top_p: z.number().min(0).max(1).optional(),
  tools: z
    .array(
      z.object({
        type: z.literal('function').optional(),
        function: z.object({
          name: z.string(),
          description: z.string().optional(),
          parameters: z.unknown().optional(),
        }),
      }),
    )
    .optional(),
  tool_choice: z.unknown().optional(),
  response_format: z
    .object({
      type: z.enum(['text', 'json_object', 'json_schema']),
      json_schema: z
        .object({
          name: z.string().optional(),
          strict: z.boolean().optional(),
          schema: z.unknown(),
        })
        .optional(),
    })
    .optional(),
});

export type ChatCompletionRequest = z.infer<typeof chatCompletionRequestSchema>;
export type ChatMessage = z.infer<typeof chatMessageSchema>;

/** `x-aegis-trust`: JSON map of message index -> trust label. */
export const trustHeaderSchema = z.record(
  z.string(),
  z.enum(['system', 'user', 'tool', 'retrieved']),
);

export const guardRequestSchema = z.object({
  text: z.string(),
  stage: z.enum(['input', 'output']).default('input'),
  policy: z.string().default('balanced'),
  trust: z.enum(['system', 'user', 'tool', 'retrieved']).default('user'),
  canary: z.string().optional(),
  mock: z.boolean().optional(),
});

/** Flatten OpenAI content (string or parts array) into plain text. */
export function messageText(m: ChatMessage): string {
  if (typeof m.content === 'string') return m.content;
  if (Array.isArray(m.content)) {
    return m.content.map((p) => p.text ?? '').filter(Boolean).join('\n');
  }
  return '';
}
