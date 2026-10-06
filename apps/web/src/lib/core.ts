/**
 * Engine constants the UI renders verbatim (methodology page, drawers).
 * Imported from the engine source so the UI never restates a formula.
 */
export {
  METRIC_DEFINITIONS,
  VDP_CRITERIA,
  PLEDGE_VDP_CRITERIA,
  VDP_CRITERION_LABELS,
  COVERAGE_SLOTS,
  BENCHMARK_METRIC_IDS,
  METRIC_CHANGES_BY_VERSION,
  TRACKED_CWE_CLASSES,
  CONFIDENCE_RULES,
  MIN_PEERS_FOR_POSITION,
  comparableAcrossVersions,
} from '../../../../packages/core/src/measure/definitions.ts'
// Direct file imports (not the package index) so a page loads only the engine code it uses.
export { GOALS, PLEDGE_SOURCE_URL, goalById, OBSERVABLE_GOAL_IDS, UNVERIFIABLE_GOAL_IDS } from '../../../../packages/core/src/methodology/goals.ts'
export { METHODOLOGY_VERSIONS, CURRENT_METHODOLOGY_VERSION } from '../../../../packages/core/src/methodology/versions.ts'
