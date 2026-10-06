/**
 * A run: one methodology version applied to one fixed set of inputs.
 *
 * executeRun is pure and deterministic: no clock (asOf comes from the
 * inputs), no randomness, no I/O, stable ordering everywhere. The same
 * inputs under the same methodology always produce the same outputsHash; a
 * different methodology version always produces a different one (the
 * version is part of the hashed outputs and of every evidence item).
 */

import type {
  Attribution,
  AttributionExclusion,
  CveRecord,
  MetricValue,
  RunInputs,
  RunManifest,
  RunOutput,
  SourceFreshness,
  VendorResult,
} from '../model/index.ts'
import { detectIdentityConflicts, attributeCves } from '../identity/index.ts'
import { GOALS } from '../methodology/goals.ts'
import { methodologyVersion } from '../methodology/versions.ts'
import { sha256Text } from '../util/sha256.ts'
import { EvidenceLedger } from '../evidence/ledger.ts'
import { computeFreshness } from '../freshness/freshness.ts'
import { METRIC_DEFINITIONS } from '../measure/definitions.ts'
import type { AttributedRecord, MeasureContext } from '../measure/context.ts'
import { measureCveQuality } from '../measure/cve-quality.ts'
import { measureTimeliness } from '../measure/timeliness.ts'
import { measureVdp } from '../measure/vdp.ts'
import { measureClassShare } from '../measure/class-share.ts'
import { toMs } from '../measure/stats.ts'
import { assessGoals, dimensionFigures } from '../assess/goals.ts'
import { computeCoverage } from '../assess/coverage.ts'
import type { CohortRow } from '../assess/cohort.ts'
import { benchmarksFor, cohortSummaries, rankingNotes } from '../assess/cohort.ts'
import { detectAnomalies } from '../assess/anomalies.ts'
import { detectVdpChange } from '../assess/vdp-change.ts'
import { canonicalJson } from './canonical.ts'
import { runQualityChecks } from './quality-gate.ts'

// The contract lists canonicalJson under run/run.ts; it lives in canonical.ts (the evidence ledger needs it too).
export { canonicalJson }

const byStr = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0)

export const STAGES = ['FETCH', 'SNAPSHOT', 'NORMALIZE', 'IDENTITY', 'VALIDATE', 'MEASURE', 'SCORE', 'EVIDENCE', 'PUBLISH'] as const

/** sha256 over the canonical JSON of the full inputs. */
export function computeInputsHash(inputs: RunInputs): string {
  return sha256Text(canonicalJson(inputs))
}

/** "TS-YYYY-MM-DD-XXXX": date of asOf + first 4 hex (upper case) of the inputs hash. */
export function runIdFor(asOf: string, inputsHash: string): string {
  return `TS-${asOf.slice(0, 10)}-${inputsHash.slice(0, 4).toUpperCase()}`
}

/** sha256 over the canonical JSON of what the run measured (everything except the manifest). */
export function computeOutputsHash(out: Omit<RunOutput, 'manifest'> & { manifest?: RunManifest }, methodology: { version: string; parserVersion: string; scoringVersion: string }): string {
  return sha256Text(
    canonicalJson({
      methodologyVersion: methodology.version,
      parserVersion: methodology.parserVersion,
      scoringVersion: methodology.scoringVersion,
      vendors: out.vendors,
      evidence: out.evidence,
      attributions: out.attributions,
      exclusions: out.exclusions,
      identityConflicts: out.identityConflicts,
      freshness: out.freshness,
      cohort: out.cohort,
    }),
  )
}

const CVE_ID = /^CVE-\d{4}-\d{4,}$/
const DEMO_ID = /^DEMO-\d{4}-\d{4,}$/

export function executeRun(inputs: RunInputs): RunOutput {
  const methodology = methodologyVersion(inputs.methodologyVersion)
  const params = methodology.parameters
  const asOfMs = toMs(inputs.asOf)
  if (asOfMs === null) throw new Error(`asOf is not a valid ISO date: ${inputs.asOf}`)

  const inputsHash = computeInputsHash(inputs)
  const runId = runIdFor(inputs.asOf, inputsHash)

  const vendors = [...inputs.vendors].sort((a, b) => byStr(a.id, b.id))
  const cves = [...inputs.cves].sort((a, b) => byStr(a.id, b.id) || byStr(a.sourceHash, b.sourceHash))
  const advisories = [...inputs.advisories].sort((a, b) => byStr(a.vendorId, b.vendorId) || byStr(a.id, b.id))
  const sources = [...inputs.sources].sort((a, b) => byStr(a.id, b.id))
  const snapshots = [...inputs.snapshots].sort((a, b) => byStr(a.id, b.id))

  // IDENTITY (pipeline-owned rules)
  const identityConflicts = [...detectIdentityConflicts(vendors)].sort((a, b) => byStr(a.id, b.id))
  const attr = attributeCves(cves, vendors, identityConflicts)
  const attributions: Attribution[] = [...attr.attributions].sort((a, b) => byStr(a.cveId, b.cveId) || byStr(a.vendorId, b.vendorId))
  const exclusions: AttributionExclusion[] = [...attr.exclusions].sort((a, b) => byStr(a.cveId, b.cveId) || byStr(a.reason, b.reason))

  // VALIDATE: duplicate ids with conflicting content are set aside everywhere.
  const hashesById = new Map<string, Set<string>>()
  for (const r of cves) hashesById.set(r.id, (hashesById.get(r.id) ?? new Set()).add(r.sourceHash))
  const duplicateIds = new Set<string>([
    ...[...hashesById.entries()].filter(([, h]) => h.size > 1).map(([id]) => id),
    ...exclusions.filter((x) => x.reason === 'DUPLICATE_CONFLICT').map((x) => x.cveId),
  ])
  const cvesById = new Map<string, CveRecord>()
  for (const r of cves) if (!duplicateIds.has(r.id) && !cvesById.has(r.id)) cvesById.set(r.id, r)
  const recordSnapshotIds = new Map<string, string>()
  for (const r of cves) {
    const cur = recordSnapshotIds.get(r.id)
    if (cur === undefined || r.snapshotId < cur) recordSnapshotIds.set(r.id, r.snapshotId)
  }

  const freshness = computeFreshness(snapshots, sources, inputs.asOf, params)
  const freshnessBySource = new Map(freshness.map((f) => [f.sourceId, f]))
  const snapshotsById = new Map(snapshots.map((s) => [s.id, s]))
  const cveSourceIds = new Set(sources.filter((s) => s.family === 'CVE_PROGRAM').map((s) => s.id))
  const cveSnaps = snapshots.filter((s) => cveSourceIds.has(s.sourceId))
  const cveSourceFailed = cveSnaps.length > 0 && !cveSnaps.some((s) => s.status === 'OK')

  const ledger = new EvidenceLedger()
  const excludedIds = new Set(exclusions.map((x) => x.cveId))

  type Measured = { metrics: Map<string, MetricValue>; attributed: AttributedRecord[]; ctx: MeasureContext }
  const measured = new Map<string, Measured>()

  // MEASURE
  for (const vendor of vendors) {
    const seen = new Set<string>()
    const attributed: AttributedRecord[] = []
    for (const a of attributions) {
      if (a.vendorId !== vendor.id || seen.has(a.cveId) || excludedIds.has(a.cveId) || duplicateIds.has(a.cveId)) continue
      const record = cvesById.get(a.cveId)
      if (!record) continue
      seen.add(a.cveId)
      attributed.push({ record, attribution: a })
    }
    const ctx: MeasureContext = {
      vendor,
      asOf: inputs.asOf,
      asOfMs,
      methodology,
      attributed,
      exclusions: exclusions.filter((x) => x.candidateVendorIds.includes(vendor.id)),
      cvesById,
      duplicateIds,
      recordSnapshotIds,
      advisories: advisories.filter((a) => a.vendorId === vendor.id),
      snapshotsById,
      sources,
      freshnessBySource,
      cveSourceFailed,
      ledger,
    }
    const vdp = inputs.vdp.find((o) => o.vendorId === vendor.id)
    if (vdp) ctx.vdp = vdp
    const metrics = new Map<string, MetricValue>()
    for (const m of measureVdp(ctx).metrics) metrics.set(m.metricId, m)
    for (const m of measureCveQuality(ctx).metrics) metrics.set(m.metricId, m)
    for (const m of measureTimeliness(ctx).metrics) metrics.set(m.metricId, m)
    const g3 = measureClassShare(ctx)
    metrics.set(g3.metricId, g3)
    measured.set(vendor.id, { metrics, attributed, ctx })
  }

  const evidence = ledger.list()
  const evidenceByVendor = new Map<string, typeof evidence>()
  for (const e of evidence) evidenceByVendor.set(e.vendorId, [...(evidenceByVendor.get(e.vendorId) ?? []), e])

  // SCORE: goals, figures, coverage
  const rows: (CohortRow & { goals: ReturnType<typeof assessGoals> })[] = vendors.map((vendor) => {
    const m = measured.get(vendor.id)!
    const goals = assessGoals({
      vendor,
      metrics: m.metrics,
      ...(m.ctx.vdp ? { vdp: m.ctx.vdp } : {}),
      cveSourceFailed,
      minimumEligibleRecords: params.minimumEligibleRecords,
      minimumRecordsPerTrendPeriod: params.minimumRecordsPerTrendPeriod,
    })
    const coverage = computeCoverage(m.metrics, m.ctx.vdp, evidenceByVendor.get(vendor.id) ?? [])
    return { vendor, metrics: m.metrics, coverage, g5Status: goals.find((g) => g.goalId === 'G5')!.status, goals }
  })

  const cohort = cohortSummaries(rows)
  const vendorResults: VendorResult[] = rows.map((row) => {
    const m = measured.get(row.vendor.id)!
    const benchmarks = benchmarksFor(row, rows, inputs.history, inputs.asOf, methodology.version)
    const prev = inputs.previousVdp.find((o) => o.vendorId === row.vendor.id)
    const vdpChanges = detectVdpChange(prev, m.ctx.vdp)
    const vendorSourceIds = new Set((evidenceByVendor.get(row.vendor.id) ?? []).map((e) => e.sourceId))
    const vendorSourceFreshness: SourceFreshness[] = freshness.filter(
      (f) => vendorSourceIds.has(f.sourceId) && (f.family === 'VENDOR_VDP' || f.family === 'SECURITY_TXT' || f.family === 'VENDOR_ADVISORY'),
    )
    const anomalies = detectAnomalies({
      vendor: row.vendor,
      metrics: row.metrics,
      rows,
      history: inputs.history,
      params,
      asOf: inputs.asOf,
      methodologyVersion: methodology.version,
      exclusions: m.ctx.exclusions,
      identityConflicts,
      ...(m.ctx.vdp ? { vdp: m.ctx.vdp } : {}),
      vdpChanges,
      vendorSourceFreshness,
    })
    const result: VendorResult = {
      vendor: row.vendor,
      goals: row.goals,
      dimensions: dimensionFigures(row.goals, row.metrics),
      coverage: row.coverage,
      benchmarks,
      anomalies,
      vdpChanges,
      attributedCveIds: m.attributed.map((a) => a.record.id).sort(),
      advisoryIds: m.ctx.advisories.map((a) => a.id).sort(),
      rankingNotes: rankingNotes(row, benchmarks),
    }
    if (m.ctx.vdp) result.vdp = m.ctx.vdp
    return result
  })

  const body: Omit<RunOutput, 'manifest'> = {
    goals: GOALS,
    metricDefinitions: METRIC_DEFINITIONS,
    vendors: vendorResults,
    evidence,
    cves,
    attributions,
    exclusions,
    identityConflicts,
    advisories,
    freshness,
    cohort,
    sources,
    snapshots,
    ...(inputs.signatoryList ? { signatoryList: inputs.signatoryList } : {}),
  }
  const outputsHash = computeOutputsHash(body, methodology)

  // Stage log
  const failedSnaps = snapshots.filter((s) => s.status !== 'OK')
  const substituted = snapshots.filter((s) => s.substitutedBy)
  const badIds = cves.filter((r) => !(CVE_ID.test(r.id) || (r.synthetic && DEMO_ID.test(r.id)))).map((r) => r.id)
  const noDate = cves.filter((r) => r.state === 'PUBLISHED' && toMs(r.datePublished) === null).length
  const allMetricValues = vendorResults.flatMap((v) => v.goals.flatMap((g) => g.metrics))
  const nullMetrics = allMetricValues.filter((x) => x.value === null).length
  const statusCounts: Record<string, number> = {}
  for (const v of vendorResults) for (const g of v.goals) statusCounts[g.status] = (statusCounts[g.status] ?? 0) + 1
  const stages: RunManifest['stages'] = [
    {
      stage: 'FETCH',
      status: failedSnaps.length ? 'WARN' : 'OK',
      detail: `${snapshots.length} snapshot(s) from ${sources.length} source(s); ${snapshots.length - failedSnaps.length} OK, ${failedSnaps.length} not OK.`,
    },
    {
      stage: 'SNAPSHOT',
      status: substituted.length ? 'WARN' : 'OK',
      detail: substituted.length
        ? `${substituted.length} unsuccessful fetch(es) substituted by an earlier snapshot: ${substituted.map((s) => `${s.id} -> ${s.substitutedBy}`).join(', ')}.`
        : 'No substitutions.',
    },
    {
      stage: 'NORMALIZE',
      status: badIds.length ? 'WARN' : 'OK',
      detail: `${cves.length} CVE record(s), ${advisories.length} advisory(ies), ${inputs.vdp.length} VDP observation(s).${badIds.length ? ` ${badIds.length} id(s) outside the accepted patterns.` : ''}`,
    },
    {
      stage: 'IDENTITY',
      status: identityConflicts.length ? 'WARN' : 'OK',
      detail: `${vendors.length} vendor(s); ${attributions.length} attribution(s); ${exclusions.length} exclusion(s); ${identityConflicts.length} identity conflict(s).`,
    },
    {
      stage: 'VALIDATE',
      status: duplicateIds.size || noDate ? 'WARN' : 'OK',
      detail: `${duplicateIds.size} duplicate id(s) with conflicting content set aside; ${noDate} published record(s) without a datePublished.`,
    },
    { stage: 'MEASURE', status: 'OK', detail: `${allMetricValues.length} metric value(s); ${nullMetrics} not measured (each with a gap reason).` },
    {
      stage: 'SCORE',
      status: 'OK',
      detail: `Goal statuses per statusRule: ${Object.keys(statusCounts)
        .sort()
        .map((k) => `${k} ${statusCounts[k]}`)
        .join(', ')}. No composite score.`,
    },
    {
      stage: 'EVIDENCE',
      status: ledger.collisions ? 'WARN' : 'OK',
      detail: `${evidence.length} evidence item(s)${ledger.collisions ? `; ${ledger.collisions} id prefix collision(s) disambiguated` : ''}.`,
    },
  ]
  const manifest: RunManifest = {
    runId,
    mode: inputs.mode,
    datasetVersion: inputs.datasetVersion,
    asOf: inputs.asOf,
    methodologyVersion: methodology.version,
    parserVersion: methodology.parserVersion,
    scoringVersion: methodology.scoringVersion,
    inputsHash,
    outputsHash,
    snapshotIds: snapshots.map((s) => s.id),
    stages,
    qualityChecks: [],
  }
  const out: RunOutput = { manifest, ...body }
  const checks = runQualityChecks(out, inputs)
  manifest.qualityChecks = checks
  const passed = checks.filter((c) => c.passed).length
  stages.push({
    stage: 'PUBLISH',
    status: passed === checks.length ? 'OK' : 'WARN',
    detail: `Quality gate: ${passed} of ${checks.length} checks passed${passed === checks.length ? '' : `; needs review: ${checks.filter((c) => !c.passed).map((c) => c.id).join(', ')}`}.`,
  })
  return out
}

export function reproduceRun(
  inputs: RunInputs,
  expected: RunManifest,
): { reproduced: boolean; outputsHash: string; inputsHash: string; mismatches: string[] } {
  const out = executeRun(inputs)
  const m = out.manifest
  const mismatches: string[] = []
  const cmp = (field: keyof RunManifest) => {
    const a = canonicalJson(m[field])
    const b = canonicalJson(expected[field])
    if (a !== b) mismatches.push(`${field}: expected ${b.length > 80 ? `${b.slice(0, 77)}...` : b}, got ${a.length > 80 ? `${a.slice(0, 77)}...` : a}`)
  }
  for (const f of ['runId', 'datasetVersion', 'asOf', 'methodologyVersion', 'parserVersion', 'scoringVersion', 'inputsHash', 'outputsHash', 'snapshotIds'] as const) cmp(f)
  return { reproduced: mismatches.length === 0, outputsHash: m.outputsHash, inputsHash: m.inputsHash, mismatches }
}
