/**
 * POST /v1/guard — standalone policy check, no proxying.
 *
 * Body: { text, stage?, policy?, trust?, canary?, mock? }
 * Returns the full Decision including every DetectorResult, which is what the
 * playground renders and what lets the engine be embedded without the gateway.
 */

import { NextResponse } from 'next/server';
import { loadPolicy, UnknownPolicyError, listPolicyNames } from '@/lib/guard/policy';
import { runGuard } from '@/lib/guard/router';
import { installDetectors } from '@/lib/guard/detectors';
import { allDetectors } from '@/lib/guard/registry';
import { createJudge, createMockJudge } from '@/lib/providers';
import { persistDecision } from '@/lib/gateway/pipeline';
import { guardRequestSchema } from '@/lib/gateway/types';
import type { MessagePart } from '@/lib/guard/types';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

export async function GET(): Promise<Response> {
  installDetectors();
  return NextResponse.json({
    policies: listPolicyNames(),
    detectors: allDetectors().map((d) => ({
      id: d.id,
      name: d.name,
      tier: d.tier,
      stage: d.stage,
      description: d.description,
    })),
  });
}

export async function POST(req: Request): Promise<Response> {
  let body;
  try {
    body = guardRequestSchema.parse(await req.json());
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: 400 },
    );
  }

  let loaded;
  try {
    loaded = loadPolicy(body.policy);
  } catch (err) {
    return NextResponse.json(
      { error: err instanceof Error ? err.message : String(err) },
      { status: err instanceof UnknownPolicyError ? 400 : 500 },
    );
  }

  const parts: MessagePart[] = [
    { index: 0, role: body.trust === 'tool' ? 'tool' : 'user', trust: body.trust, text: body.text },
  ];

  const decision = await runGuard({
    stage: body.stage,
    text: body.text,
    rawText: body.text,
    parts,
    policy: loaded.policy,
    policyHash: loaded.hash,
    llm: body.mock ? createMockJudge() : createJudge(),
    canary: body.canary,
  });

  persistDecision({
    source: 'guard-api',
    model: 'n/a',
    decision,
    analyzedText: body.text,
  });

  return NextResponse.json(decision, {
    headers: {
      'x-aegis-decision': decision.action,
      'x-aegis-escalated': String(decision.escalatedToLlm),
      'x-aegis-policy-hash': decision.policyHash,
    },
  });
}
