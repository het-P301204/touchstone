/**
 * Published shapes: what the API returns and what the static site bundles.
 * A run's full RunOutput is split into one summary (everything the overview,
 * directory, leaderboard, comparison and profile header need) and one detail
 * file per vendor (evidence, CVE records, advisories), loaded on demand.
 *
 * Static layout (apps/web/public/data/), mirrored by the API:
 *   index.json                                RunIndex          GET /api/runs
 *   runs/<runId>/summary.json                 RunSummary        GET /api/runs/:id
 *   runs/<runId>/vendors/<vendorId>.json      VendorDetail      GET /api/vendors/:id/evidence?run=
 *   history.json                              HistorySeries[]   GET /api/vendors/:id/history (filtered)
 *   inputs/<datasetVersion>.json              RunInputs         GET /api/runs/:id/inputs  (reproduce)
 *   disputes.json                             Dispute[]         GET /api/disputes
 *   notebook.json                             NotebookEntry[]   GET /api/notebook
 */

import type { Advisory, Attribution, AttributionExclusion, CveRecord } from './cve.ts'
import type {
  Anomaly,
  Benchmark,
  DimensionFigure,
  EvidenceCoverage,
  EvidenceItem,
  GoalAssessment,
  GoalStatus,
  MetricDefinition,
  SecurityCommitmentGoal,
  VdpChange,
} from './assessment.ts'
import type { CohortSummary, DatasetMode, MethodologyVersion, RunManifest } from './run.ts'
import type { Snapshot, SourceFreshness, SourceRef } from './source.ts'
import type { IdentityConflict, Vendor } from './vendor.ts'
import type { VdpObservation } from './vdp.ts'

export type RunIndexEntry = {
  runId: string
  datasetVersion: string
  asOf: string
  methodologyVersion: string
  mode: DatasetMode
  outputsHash: string
  inputsHash: string
}

export type RunIndex = {
  mode: DatasetMode
  latestRunId: string
  runs: RunIndexEntry[]
  /** Generator/build provenance of the published bundle. */
  builtFrom: string
}

/** A goal assessment without per-record evidence (metrics keep their numbers, query and calculation). */
export type GoalSummary = Omit<GoalAssessment, 'evidenceIds'> & { evidenceCount: number }

export type VendorSummary = {
  vendor: Vendor
  goals: GoalSummary[]
  dimensions: DimensionFigure[]
  coverage: EvidenceCoverage
  benchmarks: Benchmark[]
  anomalies: Anomaly[]
  vdp?: VdpObservation
  vdpChanges: VdpChange[]
  cveCount: number
  advisoryCount: number
  rankingNotes: Record<string, string>
  /** Counts of goals by status, for the profile header. */
  statusCounts: Record<GoalStatus, number>
}

export type RunSummary = {
  manifest: RunManifest
  methodology: MethodologyVersion
  goals: SecurityCommitmentGoal[]
  metricDefinitions: MetricDefinition[]
  vendors: VendorSummary[]
  cohort: CohortSummary[]
  freshness: SourceFreshness[]
  sources: SourceRef[]
  /**
   * Source-level snapshots only: signer list, VDP, security.txt, advisory feeds, and every
   * snapshot that is not OK (of any kind). Successful per-record CVE snapshots are published
   * in each VendorDetail.snapshots instead; snapshotCounts gives the full count per sourceId.
   */
  snapshots: Snapshot[]
  /** Number of snapshots in the run per sourceId (including per-record snapshots not listed above). */
  snapshotCounts?: Record<string, number>
  identityConflicts: IdentityConflict[]
  exclusionCount: number
  /** Signatory count as declared by the signer-list source, and as parsed. */
  signatoryList: { declaredCount: number | null; parsedCount: number; snapshotId?: string }
}

export type VendorDetail = {
  runId: string
  vendorId: string
  goals: GoalAssessment[]
  evidence: EvidenceItem[]
  cves: CveRecord[]
  attributions: Attribution[]
  exclusions: AttributionExclusion[]
  advisories: Advisory[]
  /** Per-record (CVE_PROGRAM / NVD) snapshots referenced by this vendor's evidence and records, sorted by id. */
  snapshots?: Snapshot[]
}

export type HistorySeries = {
  vendorId: string
  metricId: string
  points: { runId: string; datasetVersion: string; methodologyVersion: string; value: number | null }[]
}
