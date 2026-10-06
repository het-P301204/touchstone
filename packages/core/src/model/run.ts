/**
 * Runs, methodology versions, disputes and the published dataset.
 *
 * A run is the unit of reproducibility: a methodology version applied to a
 * fixed set of snapshots. Re-running the same inputs with the same
 * methodology must produce byte-identical outputs (same outputsHash).
 * Reopening a historical run reproduces it from ITS snapshots and ITS
 * methodology version, never from today's data.
 */

import type { Advisory, Attribution, AttributionExclusion, CveRecord } from './cve.ts'
import type {
  Anomaly,
  Benchmark,
  DimensionFigure,
  EvidenceCoverage,
  EvidenceItem,
  GoalAssessment,
  MetricDefinition,
  SecurityCommitmentGoal,
  VdpChange,
} from './assessment.ts'
import type { Snapshot, SourceFreshness, SourceRef } from './source.ts'
import type { IdentityConflict, Vendor } from './vendor.ts'
import type { VdpObservation } from './vdp.ts'

export type DatasetMode = 'DEMO' | 'LIVE'

export type MethodologyParameters = {
  /** CVE eligibility window: records published within this many days before asOf. */
  cveWindowDays: number
  /** Whether NVD-CWE-noinfo / NVD-CWE-Other count as a populated CWE. */
  placeholderCweCountsAsPopulated: boolean
  /** Timeliness tolerance: a CVE published within N days after the advisory is "timely". A methodology choice, not a CISA threshold. */
  timelinessToleranceDays: number
  /** Severities treated as "critical or high impact" for Goal 6 issuance. */
  highImpactSeverities: string[]
  /** Minimum eligible records before a CVE metric is reported (else BELOW_MINIMUM_SAMPLE). */
  minimumEligibleRecords: number
  /** Minimum records per period for the Goal 3 class-trend signal. */
  minimumRecordsPerTrendPeriod: number
  /** A policy without a stated or observed update within this many days fails CURRENT. */
  vdpCurrentWithinDays: number
  /** Freshness bands per source family, in hours: [current <=, aging <=], else stale. */
  freshnessHours: Record<string, [number, number]>
  /** UNUSUAL fires when a metric is below this cohort percentile. */
  unusualBelowPercentile: number
  /** LATENCY_OUTLIER fires when current median latency exceeds historical median by this factor AND by at least minDays. */
  latencyOutlierFactor: number
  latencyOutlierMinDays: number
  /** Policies with fewer extracted words are TOO_SHORT: assessed, but G5 is at most PARTIAL. */
  vdpMinimumPolicyWords: number
  /** Minimum high-impact advisories before timeliness metrics are reported (else BELOW_MINIMUM_SAMPLE). */
  minimumHighImpactAdvisories: number
}

export type MethodologyVersion = {
  version: string // semver, e.g. "1.1.0"
  releasedOn: string
  /** What changed relative to the previous version, and its expected effect on outputs. */
  changes: string[]
  parameters: MethodologyParameters
  parserVersion: string
  scoringVersion: string
}

export type RunInputs = {
  mode: DatasetMode
  /** Dataset snapshot label, e.g. "2026-10-06". */
  datasetVersion: string
  /** The analysis reference date (ISO). All windows and ages are computed from it. */
  asOf: string
  methodologyVersion: string
  vendors: Vendor[]
  cves: CveRecord[]
  advisories: Advisory[]
  vdp: VdpObservation[]
  /** Previous VDP observations, for change detection. */
  previousVdp: VdpObservation[]
  snapshots: Snapshot[]
  sources: SourceRef[]
  /** Earlier runs' per-vendor figures, for historical baselines. */
  history: HistoricalPoint[]
  /**
   * Signer-list parse result (declared vs parsed count, warnings), when a
   * signer-list snapshot was available. Optional: added by the pipeline.
   */
  signatoryList?: { declaredCount: number | null; parsedCount: number; snapshotId?: string; warnings: string[] }
}

export type HistoricalPoint = {
  runId: string
  datasetVersion: string
  asOf: string
  methodologyVersion: string
  vendorId: string
  metrics: Record<string, number | null>
  vdpCriteria?: Record<string, string>
}

export type RunManifest = {
  /** "TS-YYYY-MM-DD-XXXX": date of asOf + 4 hex of inputsHash. */
  runId: string
  mode: DatasetMode
  datasetVersion: string
  asOf: string
  methodologyVersion: string
  parserVersion: string
  scoringVersion: string
  /** sha256 over the canonical JSON of the inputs (snapshot ids + hashes + methodology version). */
  inputsHash: string
  /** sha256 over the canonical JSON of the outputs (assessments, metrics, evidence). */
  outputsHash: string
  snapshotIds: string[]
  /** Pipeline stage log: FETCH, SNAPSHOT, NORMALIZE, IDENTITY, VALIDATE, MEASURE, SCORE, EVIDENCE, PUBLISH. */
  stages: { stage: string; status: 'OK' | 'WARN' | 'FAILED' | 'SKIPPED'; detail: string }[]
  /** Pre-publication quality gate results (methodology section "Quality checks"). */
  qualityChecks: { id: string; question: string; passed: boolean; detail: string }[]
}

export type VendorResult = {
  vendor: Vendor
  goals: GoalAssessment[]
  dimensions: DimensionFigure[]
  coverage: EvidenceCoverage
  benchmarks: Benchmark[]
  anomalies: Anomaly[]
  vdp?: VdpObservation
  vdpChanges: VdpChange[]
  attributedCveIds: string[]
  advisoryIds: string[]
  /** Interpretable explanation of where the vendor sits for each dimension. */
  rankingNotes: Record<string, string>
}

export type CohortSummary = {
  peerGroup: string
  vendorCount: number
  medians: Record<string, number | null>
  /** Coverage histogram: bucket label -> count. */
  coverageDistribution: { bucket: string; count: number }[]
  vdpStatusCounts: Record<string, number>
}

export type RunOutput = {
  manifest: RunManifest
  goals: SecurityCommitmentGoal[]
  metricDefinitions: MetricDefinition[]
  vendors: VendorResult[]
  evidence: EvidenceItem[]
  cves: CveRecord[]
  attributions: Attribution[]
  exclusions: AttributionExclusion[]
  identityConflicts: IdentityConflict[]
  advisories: Advisory[]
  freshness: SourceFreshness[]
  cohort: CohortSummary[]
  sources: SourceRef[]
  snapshots: Snapshot[]
  /** Signer-list count as declared by the source and as parsed (carried from RunInputs). */
  signatoryList?: { declaredCount: number | null; parsedCount: number; snapshotId?: string; warnings: string[] }
}

// ---------------------------------------------------------------- disputes

export type DisputeReason =
  | 'INCORRECT_PRODUCT_MAPPING'
  | 'INCORRECT_VENDOR_ATTRIBUTION'
  | 'INCORRECT_CVE_MAPPING'
  | 'OUTDATED_SOURCE'
  | 'MISSING_SOURCE'
  | 'METHODOLOGY_ERROR'

export type DisputeStatus = 'OPEN' | 'UNDER_REVIEW' | 'CONFIRMED' | 'CORRECTED' | 'DISMISSED'

/** Allowed transitions. CONFIRMED = original finding stands; CORRECTED = a later run corrects it. */
export const DISPUTE_TRANSITIONS: Record<DisputeStatus, DisputeStatus[]> = {
  OPEN: ['UNDER_REVIEW', 'DISMISSED'],
  UNDER_REVIEW: ['CONFIRMED', 'CORRECTED', 'DISMISSED'],
  CONFIRMED: [],
  CORRECTED: [],
  DISMISSED: [],
}

export type Dispute = {
  id: string // "DSP-0001"
  vendorId: string
  /** What is challenged: a goal, metric, evidence item or CVE id. */
  target: { kind: 'GOAL' | 'METRIC' | 'EVIDENCE' | 'CVE' | 'IDENTITY'; id: string }
  runId: string
  reason: DisputeReason
  submitterRole: 'VENDOR' | 'RESEARCHER' | 'OTHER'
  /** Free text, length-limited and sanitized. */
  statement: string
  evidenceUrls: string[]
  status: DisputeStatus
  createdAt: string
  /** Append-only audit history. Nothing is deleted. */
  history: DisputeEvent[]
  synthetic: boolean
}

export type DisputeEvent = {
  at: string
  from: DisputeStatus | null
  to: DisputeStatus
  actor: string
  note: string
  /** When CORRECTED: the run that carries the corrected result. */
  correctedInRunId?: string
}

export type NotebookEntry = {
  id: string
  vendorId?: string
  title: string
  observation: string
  resolution?: string
  createdAt: string
  tags: string[]
  synthetic: boolean
}
