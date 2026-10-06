/**
 * Goals, metrics, evidence and assessments.
 *
 * Integrity rules encoded in these types:
 *  - UNKNOWN is never PASS. A metric with no evidence has value null and a
 *    `gap`; it is never 0 and never 100.
 *  - NOT_EXTERNALLY_VERIFIABLE is never NON-COMPLIANT. It is a property of
 *    the goal and the public evidence boundary, not of the vendor.
 *  - There is no composite "security score". Each measured dimension stands
 *    alone with its own formula, numerator and denominator.
 *  - A dispute never overwrites an observation. `status` is the original
 *    result; dispute state is carried alongside it.
 */

import type { Confidence } from './vendor.ts'
import type { FieldGap } from './cve.ts'

export type VerificationMode = 'PUBLICLY_MEASURABLE' | 'PARTIALLY_MEASURABLE' | 'NOT_EXTERNALLY_VERIFIABLE'

export type EvidenceRequirement = {
  id: string
  description: string
  /** Is this requirement satisfiable from public sources at all? */
  publiclyAvailable: boolean
}

export type Methodology = {
  summary: string
  /** Metric ids measured for this goal (empty when not externally verifiable). */
  metricIds: string[]
  /** Exact rule for the goal-level status, in words. */
  statusRule: string
  /** What would be needed to verify this goal, when it cannot be verified today. */
  evidenceNeeded: string[]
  limitations: string[]
}

export type SecurityCommitmentGoal = {
  id: string // "G1".."G7"
  number: number
  name: string
  shortName: string
  /** Pledge text, quoted verbatim from CISA. */
  pledgeText: string
  description: string
  verificationMode: VerificationMode
  evidenceRequirements: EvidenceRequirement[]
  methodology: Methodology
}

/** The measured dimensions. Exactly these carry a "verified evidence" figure. */
export type DimensionId = 'VDP' | 'CVE_QUALITY' | 'CVE_TIMELINESS'

export type MetricUnit = 'PERCENT' | 'COUNT' | 'DAYS' | 'RATIO' | 'STATE'

export type MetricDefinition = {
  id: string // e.g. "cve.cwe_coverage"
  name: string
  goalId: string
  dimension?: DimensionId
  unit: MetricUnit
  /** Human formula, rendered verbatim in "How was this calculated?". */
  formula: string
  numeratorLabel?: string
  denominatorLabel?: string
  eligibility: string
  /** Higher is better? Used only for cohort position wording, never for a composite. */
  direction: 'HIGHER_IS_STRONGER_EVIDENCE' | 'LOWER_IS_STRONGER_EVIDENCE' | 'NEUTRAL'
  /** True when the metric counts toward evidence coverage slots. */
  coverageSlot: boolean
}

export type GoalStatus =
  | 'VERIFIED' // evidence directly supports the measurement
  | 'PARTIAL' // evidence supports only part of the measurement
  | 'NOT_VERIFIED' // insufficient public evidence to establish it
  | 'NOT_EXTERNALLY_VERIFIABLE' // public evidence cannot meaningfully answer the goal
  | 'DATA_ERROR' // source or mapping problem prevents measurement

/** Display state = original status, plus DISPUTED as an overlay. */
export type DisplayState = GoalStatus | 'DISPUTED'

export type MetricValue = {
  metricId: string
  /** null = could not be measured. Never coerced to 0. */
  value: number | null
  numerator?: number
  denominator?: number
  /** When value is null: why. */
  gap?: FieldGap | 'NO_ELIGIBLE_RECORDS' | 'NO_SOURCE' | 'SOURCE_FAILED' | 'BELOW_MINIMUM_SAMPLE'
  /** For distributions (latency). */
  distribution?: { median: number; p75: number; p95: number; n: number }
  confidence: Confidence
  confidenceReasons: string[]
  /** Evidence item ids that support this value. */
  evidenceIds: string[]
  /** Exact, re-runnable description of the query over the snapshot. */
  query: string
  /** Rendered formula with numbers substituted, e.g. "414 / 428 = 96.73%". */
  calculation: string
  /** Extra breakdowns (e.g. gap counts by FieldGap). */
  breakdown?: Record<string, number>
}

export type EvidenceInterpretation =
  | 'SUPPORTS' // the item supports the metric
  | 'DOES_NOT_SUPPORT' // the item counts against (e.g. a record missing CWE)
  | 'EXCLUDED' // the item was examined and excluded by an eligibility rule
  | 'CONTEXT' // context only (e.g. third-party enrichment, a vendor claim)

export type EvidenceItem = {
  /** "EV-" + 10 hex of sha256(runId-independent content): stable across identical re-runs. */
  id: string
  vendorId: string
  metricId: string
  sourceId: string
  snapshotId: string
  /** Record or document the evidence is about, e.g. a CVE id, a policy URL. */
  subject: string
  /** Timestamp of the snapshot the evidence was read from. */
  collectedAt: string
  /** The exact field(s) extracted. */
  extracted: Record<string, string | number | boolean | null | string[]>
  interpretation: EvidenceInterpretation
  /** One-sentence plain reading, e.g. "CNA container lists CWE-79". */
  reading: string
  confidence: Confidence
  methodologyVersion: string
}

export type GoalAssessment = {
  vendorId: string
  goalId: string
  status: GoalStatus
  /** Why the status is what it is, in measurement language (never "compliant"). */
  statusReason: string
  metrics: MetricValue[]
  evidenceIds: string[]
  /** Vendor's self-reported claims for this goal, shown as unverified context. */
  claimCount: number
}

export type DimensionFigure = {
  dimension: DimensionId
  /** 0-100, or null when not measurable for this vendor. */
  value: number | null
  metricId: string
  status: GoalStatus
}

export type CohortPosition = 'ABOVE_PEER_MEDIAN' | 'AT_PEER_MEDIAN' | 'BELOW_PEER_MEDIAN' | 'NOT_COMPARABLE'

export type Benchmark = {
  metricId: string
  current: number | null
  vendorHistoricalMedian: number | null
  peerMedian: number | null
  peerGroup: string // "ALL_SIGNATORIES" or a category id
  peerCount: number
  position: CohortPosition
  /** Careful wording, e.g. "Above peer median on this observable metric." */
  wording: string
}

export type EvidenceCoverage = {
  /** Slots with an evidence-backed determination / total slots. 0-100. */
  percent: number
  observedSlots: number
  totalSlots: number
  sourcesEvaluated: number
  evidenceBackedMeasurements: number
  unverifiableGoals: number
  /** Ids of slots that could not be determined, with reasons. */
  unobserved: { metricId: string; reason: string }[]
}

export type AnomalyKind = 'UNUSUAL' | 'CHANGE_DETECTED' | 'LATENCY_OUTLIER' | 'DATA_QUALITY'

export type Anomaly = {
  id: string
  vendorId: string
  kind: AnomalyKind
  metricId?: string
  /** "Observed deviation" language, never a judgement. */
  headline: string
  detail: string
  /** The rule and threshold that fired, from the methodology parameters. */
  rule: string
  evidenceIds: string[]
}

export type VdpChange = {
  vendorId: string
  fromSnapshotId: string
  toSnapshotId: string
  fromObservedAt: string
  toObservedAt: string
  textChanged: boolean
  criteria: { criterion: string; before: string; after: string }[]
  /** "Review recommended" when a pledge-required criterion changed state. */
  reviewRecommended: boolean
}
