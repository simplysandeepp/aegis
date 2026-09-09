/**
 * Detector registry — the primary extension point of the project.
 *
 * A researcher adds a detector by dropping a file in `detectors/`, exporting a
 * `Detector`, and registering it in `detectors/index.ts`. Nothing else in the
 * engine, the gateway or the harness needs to change: the router discovers
 * detectors from here, policies enable them by id, and the dashboard renders
 * whatever `DetectorResult`s come back.
 *
 * See RESEARCH.md for the full walkthrough.
 */

import type { Detector, DetectorResult, GuardContext, Severity, Stage, Tier } from './types';

const registry = new Map<string, Detector>();

export function registerDetector(d: Detector): void {
  if (registry.has(d.id)) {
    throw new Error(`Detector id "${d.id}" is already registered`);
  }
  registry.set(d.id, d);
}

export function getDetector(id: string): Detector | undefined {
  return registry.get(id);
}

export function allDetectors(): Detector[] {
  return [...registry.values()];
}

export function clearRegistry(): void {
  registry.clear();
}

/** Detectors enabled by the policy, filtered to a stage and tier. */
export function detectorsFor(
  policy: { detectors: Record<string, { enabled: boolean }> },
  stage: Stage,
  tier: Tier,
): Detector[] {
  return allDetectors().filter(
    (d) => d.tier === tier && d.stage.includes(stage) && policy.detectors[d.id]?.enabled === true,
  );
}

/**
 * Helper for authoring detectors: builds a `DetectorResult` and times the body.
 * Keeps every detector's timing measured the same way.
 */
export function defineDetector(spec: {
  id: string;
  name: string;
  description: string;
  stage: Stage[];
  tier: Tier;
  defaultSeverity: Severity;
  detect(ctx: GuardContext): Promise<Omit<DetectorResult, 'detectorId' | 'latencyMs' | 'severity'> & {
    severity?: Severity;
  }>;
}): Detector {
  return {
    id: spec.id,
    name: spec.name,
    description: spec.description,
    stage: spec.stage,
    tier: spec.tier,
    async run(ctx: GuardContext): Promise<DetectorResult> {
      const t0 = performance.now();
      try {
        const partial = await spec.detect(ctx);
        const override = ctx.policy.detectors[spec.id]?.severityOverride;
        return {
          detectorId: spec.id,
          latencyMs: performance.now() - t0,
          severity: override ?? partial.severity ?? spec.defaultSeverity,
          ...partial,
        } as DetectorResult;
      } catch (err) {
        // A crashing detector must not take the gateway down, but it must also
        // never be mistaken for a clean verdict.
        return {
          detectorId: spec.id,
          triggered: false,
          score: 0,
          severity: 'low',
          labels: ['detector:error'],
          spans: [],
          explanation: `Detector threw: ${err instanceof Error ? err.message : String(err)}`,
          latencyMs: performance.now() - t0,
          unavailable: true,
        };
      }
    },
  };
}

/** A clean non-detection. */
export function noHit(explanation: string): Omit<DetectorResult, 'detectorId' | 'latencyMs' | 'severity'> {
  return { triggered: false, score: 0, labels: [], spans: [], explanation };
}
