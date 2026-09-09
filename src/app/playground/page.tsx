import { listPolicyNames, loadPolicy } from '@/lib/guard/policy';
import { PlaygroundClient } from './playground-client';
import { presets } from './presets';

export const dynamic = 'force-dynamic';

export default function PlaygroundPage() {
  const policies = listPolicyNames();
  const thresholds: Record<string, { low: number; high: number }> = {};
  for (const p of policies) {
    try {
      const { policy } = loadPolicy(p);
      thresholds[p] = { low: policy.escalation.lowThreshold, high: policy.escalation.highThreshold };
    } catch {
      /* skip a policy that fails to load rather than breaking the page */
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Playground</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Runs text through <span className="font-mono">POST /v1/guard</span> — the same policy engine the gateway and
          the harness use. Pick a corpus preset to reproduce a specific case.
        </p>
      </div>
      <PlaygroundClient policies={policies} presets={presets()} thresholds={thresholds} />
    </div>
  );
}
