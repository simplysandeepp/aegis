/**
 * Detector registration.
 *
 * ADDING A DETECTOR (the primary extension point):
 *   1. create `src/lib/guard/detectors/my-detector.ts`
 *   2. export a `Detector` built with `defineDetector({...})`
 *   3. import it here and add it to `ALL_DETECTORS`
 *   4. enable it in the policies that should use it, by id
 *   5. add true-positive and true-negative fixtures in `tests/`
 *
 * Nothing else changes: the router, the gateway, the harness and the dashboard
 * all discover detectors through the registry. See RESEARCH.md.
 */

import { registerDetector, allDetectors, clearRegistry } from '../registry';
import type { Detector } from '../types';

import { unicodeHygieneDetector } from './unicode-hygiene';
import { secretScannerDetector } from './secret-scanner';
import { piiDetector } from './pii-detector';
import { injectionHeuristicsDetector } from './injection-heuristics';
import { topicPolicyDetector } from './topic-policy';
import { urlAllowlistDetector } from './url-allowlist';
import { canaryLeakDetector } from './canary-leak';
import { outputSchemaDetector } from './output-schema';
import { toolCallPolicyDetector } from './tool-call-policy';
import { llmInjectionJudge, llmPolicyJudge, llmOutputAudit } from './llm-judges';

export const ALL_DETECTORS: Detector[] = [
  // rules tier
  unicodeHygieneDetector,
  secretScannerDetector,
  piiDetector,
  injectionHeuristicsDetector,
  topicPolicyDetector,
  urlAllowlistDetector,
  canaryLeakDetector,
  outputSchemaDetector,
  toolCallPolicyDetector,
  // llm tier
  llmInjectionJudge,
  llmPolicyJudge,
  llmOutputAudit,
];

let installed = false;

/** Idempotent: safe to call from a route handler, a test and the CLI alike. */
export function installDetectors(): void {
  if (installed && allDetectors().length === ALL_DETECTORS.length) return;
  clearRegistry();
  for (const d of ALL_DETECTORS) registerDetector(d);
  installed = true;
}

export function resetDetectors(): void {
  clearRegistry();
  installed = false;
}

export {
  unicodeHygieneDetector,
  secretScannerDetector,
  piiDetector,
  injectionHeuristicsDetector,
  topicPolicyDetector,
  urlAllowlistDetector,
  canaryLeakDetector,
  outputSchemaDetector,
  toolCallPolicyDetector,
  llmInjectionJudge,
  llmPolicyJudge,
  llmOutputAudit,
};
export { sanitizeText } from './unicode-hygiene';
export { makeCanary, CANARY_PREFIX } from './canary-leak';
