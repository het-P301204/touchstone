/**
 * Metric definitions, evidence coverage slots, tracked weakness classes and
 * the documented confidence rules. Everything a reader needs to re-derive a
 * figure by hand is here as data: the docs, the UI's "How was this
 * calculated?" panel and the reports all render these strings verbatim.
 *
 * There is no composite score. Three metrics carry a dimension figure
 * (vdp.criteria_met, cve.complete_records, cve.timely_issuance); every other
 * metric is a component, context or data-quality count.
 */

import type { MetricDefinition, VdpCriterionId } from '../model/index.ts'

export const METRIC_DEFINITIONS: MetricDefinition[] = [
  {
    id: 'vdp.criteria_met',
    name: 'VDP criteria met',
    goalId: 'G5',
    dimension: 'VDP',
    unit: 'PERCENT',
    formula:
      '(criteria MET + 0.5 × criteria PARTIAL) ÷ 8 criteria × 100. NOT_MET, CONTRADICTED and UNKNOWN count 0; every UNKNOWN criterion is listed by name. Not reported when no criterion could be determined.',
    numeratorLabel: 'Criteria MET + 0.5 × criteria PARTIAL',
    denominatorLabel: 'Criteria assessed (8)',
    eligibility:
      'Vendors with a VDP observation in the run (security.txt and/or a policy page). A security.txt file on its own is not counted as a policy.',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: true,
  },
  {
    id: 'vdp.pledge_elements_met',
    name: 'Pledge VDP elements met',
    goalId: 'G5',
    unit: 'COUNT',
    formula:
      'Count of the four pledge elements (reporting channel, testing authorized, good-faith safe harbor, public disclosure allowed) assessed MET. PARTIAL, NOT_MET, CONTRADICTED and UNKNOWN are not counted. Not reported when all four are UNKNOWN.',
    numeratorLabel: 'Pledge elements MET',
    denominatorLabel: 'Pledge elements (4)',
    eligibility: 'Vendors with a VDP observation in the run.',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: false,
  },
  {
    id: 'cve.cwe_coverage',
    name: 'CNA-supplied CWE coverage',
    goalId: 'G6',
    unit: 'PERCENT',
    formula:
      'Eligible records whose CNA container lists a usable CWE ÷ eligible records × 100. A usable CWE is a CWE-<n> identifier; NVD-CWE-noinfo and NVD-CWE-Other count as usable only when the methodology parameter placeholderCweCountsAsPopulated is true (1.0.0: true, 1.1.0: false). CWEs supplied only by an ADP container (CISA-ADP, NVD) are not credited.',
    numeratorLabel: 'Eligible records with a usable CNA CWE',
    denominatorLabel: 'Eligible records',
    eligibility:
      'CVE records attributed to the vendor (not excluded), in state PUBLISHED, with datePublished within cveWindowDays before asOf. Reported only when the denominator reaches minimumEligibleRecords.',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: true,
  },
  {
    id: 'cve.cpe_coverage',
    name: 'CNA-supplied CPE coverage',
    goalId: 'G6',
    unit: 'PERCENT',
    formula:
      'Eligible records whose CNA container lists at least one well-formed CPE 2.3 name ÷ eligible records × 100. CPEs supplied only by an ADP container are not credited.',
    numeratorLabel: 'Eligible records with a well-formed CNA CPE',
    denominatorLabel: 'Eligible records',
    eligibility:
      'CVE records attributed to the vendor (not excluded), in state PUBLISHED, with datePublished within cveWindowDays before asOf. Reported only when the denominator reaches minimumEligibleRecords.',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: true,
  },
  {
    id: 'cve.cpe_namespace_consistency',
    name: 'CPE vendor namespace consistency',
    goalId: 'G6',
    unit: 'PERCENT',
    formula:
      'Records with at least one well-formed CNA CPE whose vendor field matches one of the vendor’s registered CPE_VENDOR aliases ÷ records with at least one well-formed CNA CPE × 100. Not reported when the registry lists no CPE_VENDOR alias for the vendor.',
    numeratorLabel: 'Records with a CNA CPE in the vendor’s namespace',
    denominatorLabel: 'Eligible records with a well-formed CNA CPE',
    eligibility:
      'Eligible records (as for cve.cwe_coverage) that carry at least one well-formed CNA CPE. Reported only when that count reaches minimumEligibleRecords.',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: true,
  },
  {
    id: 'cve.complete_records',
    name: 'Complete CVE records (CNA-supplied)',
    goalId: 'G6',
    dimension: 'CVE_QUALITY',
    unit: 'PERCENT',
    formula:
      'Eligible records whose CNA container has BOTH a usable CWE AND a well-formed CPE in the vendor’s CPE namespace ÷ eligible records × 100. The pledge asks for CWE and CPE in every record, so this is the CVE record quality figure.',
    numeratorLabel: 'Eligible records complete in the CNA container',
    denominatorLabel: 'Eligible records',
    eligibility:
      'As for cve.cwe_coverage. Not reported when the registry lists no CPE_VENDOR alias for the vendor (namespace cannot be checked).',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: false,
  },
  {
    id: 'cve.enriched_only',
    name: 'Fields supplied only by third-party enrichment',
    goalId: 'G6',
    unit: 'PERCENT',
    formula:
      'Eligible records lacking a usable CNA CWE or a well-formed CNA CPE for which an ADP container (for example CISA-ADP) supplies the missing field ÷ eligible records × 100. Context only: never credited to the vendor.',
    numeratorLabel: 'Eligible records completed only by ADP data',
    denominatorLabel: 'Eligible records',
    eligibility: 'As for cve.cwe_coverage.',
    direction: 'NEUTRAL',
    coverageSlot: false,
  },
  {
    id: 'cve.duplicate_conflicts',
    name: 'Duplicate CVE records with conflicting content',
    goalId: 'G6',
    unit: 'COUNT',
    formula:
      'Count of CVE ids that appear more than once in the snapshot with different content hashes and name this vendor as a candidate. Both copies are excluded from every metric. Data quality, not a quality signal.',
    eligibility: 'Attribution exclusions with reason DUPLICATE_CONFLICT whose candidate vendors include this vendor.',
    direction: 'NEUTRAL',
    coverageSlot: false,
  },
  {
    id: 'cve.excluded_records',
    name: 'Records excluded from attribution',
    goalId: 'G6',
    unit: 'COUNT',
    formula:
      'Count of CVE records naming this vendor as a candidate that were excluded by an attribution rule (ambiguous vendor, identity conflict, rejected record, duplicate conflict). Data quality, not a quality signal.',
    eligibility: 'Attribution exclusions whose candidate vendors include this vendor.',
    direction: 'NEUTRAL',
    coverageSlot: false,
  },
  {
    id: 'cve.high_impact_with_cve',
    name: 'High-impact advisories with a CVE record',
    goalId: 'G6',
    unit: 'PERCENT',
    formula:
      'High-impact advisories listing at least one CVE id that exists as a PUBLISHED record in the snapshot ÷ high-impact advisories × 100. High impact = the advisory’s stated severity is in highImpactSeverities (CRITICAL, HIGH).',
    numeratorLabel: 'High-impact advisories with a CVE record in the snapshot',
    denominatorLabel: 'High-impact advisories',
    eligibility:
      'The vendor’s machine-readable advisories (CSAF) published within cveWindowDays before asOf with a stated CRITICAL or HIGH severity, de-duplicated by advisory id. A CVE counts only if it was published by asOf. An advisory listing a CVE that appears twice in the snapshot with conflicting content is set aside as undetermined (listed in the breakdown, not in the denominator). No advisories at all: not measured (NO_SOURCE), not zero. A failed CVE source: not measured (SOURCE_FAILED).',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: true,
  },
  {
    id: 'cve.timely_issuance',
    name: 'Timely CVE issuance for high-impact advisories',
    goalId: 'G6',
    dimension: 'CVE_TIMELINESS',
    unit: 'PERCENT',
    formula:
      'High-impact advisories where every listed CVE exists in the snapshot and was published no later than timelinessToleranceDays after the advisory ÷ high-impact advisories × 100. The tolerance is a TOUCHSTONE methodology parameter, not a CISA threshold. An advisory listing no CVE, or a CVE absent from the snapshot, is not counted as timely. The comparison uses exact times, not rounded days. Below minimumHighImpactAdvisories the value is reported with LOW confidence and cannot make the goal VERIFIED.',
    numeratorLabel: 'High-impact advisories with all CVEs published within tolerance',
    denominatorLabel: 'High-impact advisories',
    eligibility: 'As for cve.high_impact_with_cve.',
    direction: 'HIGHER_IS_STRONGER_EVIDENCE',
    coverageSlot: false,
  },
  {
    id: 'cve.publication_latency',
    name: 'CVE publication latency after advisory',
    goalId: 'G6',
    unit: 'DAYS',
    formula:
      'Per high-impact advisory: the latest datePublished among its listed CVE records minus the advisory’s initial release date, in days (sign kept: negative means the CVE was public before the advisory). Reported as median, 75th and 95th percentile (nearest-rank) over advisories; the value is the median.',
    eligibility: 'High-impact advisories (as above) with at least one listed CVE present in the snapshot with a datePublished.',
    direction: 'NEUTRAL',
    coverageSlot: true,
  },
  {
    id: 'g3.class_share_trend',
    name: 'Tracked weakness-class share, change over 12 months',
    goalId: 'G3',
    unit: 'PERCENT',
    formula:
      'Share of the vendor’s records with a CNA-supplied CWE identifier that fall in a tracked class (memory safety, injection, authentication and credentials), latest 12 months minus prior 12 months, in percentage points. Per-class shares are in the breakdown. A signal about disclosed records only; it cannot establish a change in prevalence.',
    numeratorLabel: 'Latest-period records in a tracked class',
    denominatorLabel: 'Latest-period records with a CNA CWE identifier',
    eligibility:
      'Attributed PUBLISHED records with at least one CNA CWE identifier (placeholders name no class and never contribute). Latest period: the 365 days up to asOf; prior period: the 365 days before that. Reported only when each period has at least minimumRecordsPerTrendPeriod records.',
    direction: 'NEUTRAL',
    coverageSlot: true,
  },
]

export function metricDefinition(id: string): MetricDefinition | undefined {
  return METRIC_DEFINITIONS.find((m) => m.id === id)
}

/** The eight VDP criteria, in display order. */
export const VDP_CRITERIA: VdpCriterionId[] = [
  'POLICY_DISCOVERABLE',
  'SECURITY_CONTACT',
  'REPORTING_CHANNEL',
  'TESTING_AUTHORIZED',
  'GOOD_FAITH_SAFE_HARBOR',
  'PUBLIC_DISCLOSURE_ALLOWED',
  'SCOPE_DEFINED',
  'CURRENT',
]

/** The four elements the pledge text names for Goal 5. */
export const PLEDGE_VDP_CRITERIA: VdpCriterionId[] = [
  'REPORTING_CHANNEL',
  'TESTING_AUTHORIZED',
  'GOOD_FAITH_SAFE_HARBOR',
  'PUBLIC_DISCLOSURE_ALLOWED',
]

export const VDP_CRITERION_LABELS: Record<VdpCriterionId, string> = {
  POLICY_DISCOVERABLE: 'Policy discoverable',
  SECURITY_CONTACT: 'Security contact',
  REPORTING_CHANNEL: 'Reporting channel',
  TESTING_AUTHORIZED: 'Testing authorized',
  GOOD_FAITH_SAFE_HARBOR: 'Good-faith safe harbor',
  PUBLIC_DISCLOSURE_ALLOWED: 'Public disclosure allowed',
  SCOPE_DEFINED: 'Scope defined',
  CURRENT: 'Current',
}

export const vdpSlotId = (c: VdpCriterionId): string => `vdp.criterion.${c}`

/** The 14 evidence coverage slots. */
export const COVERAGE_SLOTS: string[] = [
  ...VDP_CRITERIA.map(vdpSlotId),
  'cve.cwe_coverage',
  'cve.cpe_coverage',
  'cve.cpe_namespace_consistency',
  'cve.high_impact_with_cve',
  'cve.publication_latency',
  'g3.class_share_trend',
]

/** Metrics compared against peers. Rates, shares and medians only: never raw counts (vendor size would dominate). */
export const BENCHMARK_METRIC_IDS: string[] = [
  'vdp.criteria_met',
  'cve.cwe_coverage',
  'cve.cpe_coverage',
  'cve.cpe_namespace_consistency',
  'cve.complete_records',
  'cve.high_impact_with_cve',
  'cve.timely_issuance',
  'cve.publication_latency',
]

/**
 * Metrics whose formula changed in a methodology version. A historical value
 * is compared with a current one only when no version between them changed
 * the metric. Kept in step with `changes` in methodology/versions.ts.
 */
export const METRIC_CHANGES_BY_VERSION: Record<string, string[]> = {
  '1.1.0': ['cve.cwe_coverage', 'cve.complete_records'],
}

function versionKey(v: string): number[] {
  return v.split('.').map((x) => Number.parseInt(x, 10) || 0)
}

export function compareVersions(a: string, b: string): number {
  const x = versionKey(a)
  const y = versionKey(b)
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const d = (x[i] ?? 0) - (y[i] ?? 0)
    if (d !== 0) return d
  }
  return 0
}

/** True when a value computed under version `a` is comparable with one computed under `b` for this metric. */
export function comparableAcrossVersions(metricId: string, a: string, b: string): boolean {
  if (a === b) return true
  const [lo, hi] = compareVersions(a, b) < 0 ? [a, b] : [b, a]
  for (const [version, metrics] of Object.entries(METRIC_CHANGES_BY_VERSION)) {
    if (compareVersions(version, lo) > 0 && compareVersions(version, hi) <= 0 && metrics.includes(metricId)) return false
  }
  return true
}

/**
 * Goal 3 tracked weakness classes. A record is in a class when any of its
 * CNA-supplied CWE identifiers is in the class set. These sets are a
 * TOUCHSTONE methodology choice, published so they can be disputed.
 */
export const TRACKED_CWE_CLASSES: { id: string; label: string; cwes: string[] }[] = [
  {
    id: 'MEMORY_SAFETY',
    label: 'Memory safety',
    cwes: [119, 120, 121, 122, 123, 124, 125, 126, 127, 131, 415, 416, 476, 562, 590, 761, 762, 763, 787, 788, 805, 822, 823, 824, 825, 843].map(
      (n) => `CWE-${n}`,
    ),
  },
  {
    id: 'INJECTION',
    label: 'Injection',
    cwes: [74, 77, 78, 79, 80, 88, 89, 90, 91, 94, 95, 96, 643, 652, 917, 1336].map((n) => `CWE-${n}`),
  },
  {
    id: 'AUTH_CREDENTIALS',
    label: 'Authentication and credentials',
    cwes: [255, 259, 287, 288, 290, 294, 303, 304, 306, 307, 521, 522, 523, 620, 640, 798, 1390, 1391, 1392, 1393].map((n) => `CWE-${n}`),
  },
]

/** Peers needed before a cohort position is stated. */
export const MIN_PEERS_FOR_POSITION = 3
/** Peers needed before the UNUSUAL percentile rule is evaluated. */
export const MIN_PEERS_FOR_PERCENTILE = 10

/**
 * Confidence rules. Each metric starts HIGH; each rule that fires caps it and
 * adds its reason. The lowest cap wins. No weighting, no arithmetic.
 */
export const CONFIDENCE_RULES: { id: string; cap: 'MEDIUM' | 'LOW'; rule: string }[] = [
  { id: 'C1.ATTRIBUTION', cap: 'MEDIUM', rule: 'At least one contributing record was attributed by affected-vendor name only (MEDIUM attribution).' },
  { id: 'C2.SAMPLE', cap: 'LOW', rule: 'An advisory-based metric is reported over fewer high-impact advisories than minimumHighImpactAdvisories (CVE record metrics are not reported below minimumEligibleRecords at all).' },
  { id: 'C3.STALE', cap: 'MEDIUM', rule: 'A source feeding the metric is STALE under the methodology freshness bands.' },
  { id: 'C3.UNKNOWN_FRESHNESS', cap: 'LOW', rule: 'A source feeding the metric has no successful snapshot, so its age is unknown.' },
  { id: 'C4.CARRIED', cap: 'MEDIUM', rule: 'The observation was carried forward from an earlier snapshot after a refresh did not succeed.' },
  { id: 'C5.UNDETERMINED', cap: 'MEDIUM', rule: 'Part of the input could not be determined (UNKNOWN criteria are counted as 0).' },
  { id: 'C6.NOT_MEASURED', cap: 'LOW', rule: 'No value could be measured.' },
  { id: 'C7.TOO_SHORT', cap: 'LOW', rule: 'The policy text read is shorter than vdpMinimumPolicyWords; the goal is capped at PARTIAL.' },
]
