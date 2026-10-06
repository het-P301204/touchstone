// Public surface of @touchstone/core.
export type * from './model/index.ts'
export { DISPUTE_TRANSITIONS } from './model/index.ts'

// Goal model and methodology
export { GOALS, PLEDGE_SOURCE_URL, goalById, OBSERVABLE_GOAL_IDS, UNVERIFIABLE_GOAL_IDS } from './methodology/goals.ts'
export { METHODOLOGY_VERSIONS, CURRENT_METHODOLOGY_VERSION, methodologyVersion } from './methodology/versions.ts'
export {
  METRIC_DEFINITIONS,
  metricDefinition,
  VDP_CRITERION_LABELS,
  COVERAGE_SLOTS,
  BENCHMARK_METRIC_IDS,
  METRIC_CHANGES_BY_VERSION,
  TRACKED_CWE_CLASSES,
  CONFIDENCE_RULES,
} from './measure/definitions.ts'

// Normalization, identity and VDP assessment
export { normalizeCveRecord, parseCwe, parseCpe23, CVE_ID_PATTERN, DEMO_ID_PATTERN, CWE_PLACEHOLDERS } from './normalize/cve.ts'
export { normalizeCsafAdvisory } from './normalize/csaf.ts'
export { parseSignerList } from './normalize/signers.ts'
export { parseSecurityTxt, securityTxtExpired } from './normalize/security-txt.ts'
export { snapshotId, failedSnapshotId } from './normalize/snapshot-id.ts'
export { htmlToText } from './text/html.ts'
export { detectIdentityConflicts, attributeCves, matchSignatories, normalizeName } from './identity/index.ts'
export { assessVdp, VDP_CRITERIA, PLEDGE_VDP_CRITERIA, VDP_RULES, VDP_STRUCTURAL_RULES, pledgeElementsMet } from './vdp/assess.ts'

// Runs, publication, freshness, reports
export { executeRun, reproduceRun, computeInputsHash, computeOutputsHash, runIdFor, STAGES } from './run/run.ts'
export { canonicalJson } from './run/canonical.ts'
export { splitForPublication, historySeries } from './publish/split.ts'
export { computeFreshness, worstFreshness } from './freshness/freshness.ts'
export { vendorReport } from './report/vendor-report.ts'
export { POSITIONING } from './report/document.ts'

// Utilities
export { sha256, sha256Text, shortHash } from './util/sha256.ts'
export { stripInvisible, cleanText } from './util/sanitize.ts'
