/**
 * Split a RunOutput into the published shapes (model/publish.ts): one
 * RunSummary for the overview, directory, comparison and profile header,
 * and one VendorDetail per vendor carrying its evidence, records and
 * advisories. Nothing is recomputed here: the split only selects.
 */

import type {
  GoalStatus,
  GoalSummary,
  HistorySeries,
  MethodologyVersion,
  RunOutput,
  RunSummary,
  Snapshot,
  VendorDetail,
  VendorSummary,
} from '../model/index.ts'
import { METRIC_DEFINITIONS } from '../measure/definitions.ts'
import { toMs } from '../measure/stats.ts'

const STATUSES: GoalStatus[] = ['VERIFIED', 'PARTIAL', 'NOT_VERIFIED', 'NOT_EXTERNALLY_VERIFIABLE', 'DATA_ERROR']

export function splitForPublication(out: RunOutput, methodology: MethodologyVersion): { summary: RunSummary; vendors: Record<string, VendorDetail> } {
  if (methodology.version !== out.manifest.methodologyVersion)
    throw new Error(`Methodology ${methodology.version} does not match the run's methodology ${out.manifest.methodologyVersion}`)

  const vendorSummaries: VendorSummary[] = out.vendors.map((v) => {
    const goals: GoalSummary[] = v.goals.map((g) => ({
      vendorId: g.vendorId,
      goalId: g.goalId,
      status: g.status,
      statusReason: g.statusReason,
      metrics: g.metrics,
      claimCount: g.claimCount,
      evidenceCount: g.evidenceIds.length,
    }))
    const statusCounts = Object.fromEntries(STATUSES.map((s) => [s, 0])) as Record<GoalStatus, number>
    for (const g of v.goals) statusCounts[g.status]++
    const s: VendorSummary = {
      vendor: v.vendor,
      goals,
      dimensions: v.dimensions,
      coverage: v.coverage,
      benchmarks: v.benchmarks,
      anomalies: v.anomalies,
      vdpChanges: v.vdpChanges,
      cveCount: v.attributedCveIds.length,
      advisoryCount: v.advisoryIds.length,
      rankingNotes: v.rankingNotes,
      statusCounts,
    }
    if (v.vdp) s.vdp = v.vdp
    return s
  })

  // Signer list: the count the source declares ("387 Companies") and the
  // count parsed from it. When the run did not carry it, declared is null (unknown).
  const pledgeSources = new Set(out.sources.filter((s) => s.family === 'CISA_PLEDGE').map((s) => s.id))
  const pledgeSnap = out.snapshots
    .filter((s) => pledgeSources.has(s.sourceId) && s.status === 'OK')
    .sort((a, b) => (toMs(a.fetchedAt) ?? 0) - (toMs(b.fetchedAt) ?? 0))
    .at(-1)
  const signatoryList: RunSummary['signatoryList'] = out.signatoryList
    ? { declaredCount: out.signatoryList.declaredCount, parsedCount: out.signatoryList.parsedCount }
    : { declaredCount: null, parsedCount: out.vendors.filter((v) => v.vendor.signatoryStatus === 'LISTED').length }
  const signerSnapshotId = out.signatoryList?.snapshotId ?? pledgeSnap?.id
  if (signerSnapshotId) signatoryList.snapshotId = signerSnapshotId

  // Per-record snapshots (one per CVE record) go to the vendor detail files;
  // the summary keeps source-level snapshots and every snapshot that is not OK.
  const perRecordSources = new Set(out.sources.filter((s) => s.family === 'CVE_PROGRAM' || s.family === 'NVD').map((s) => s.id))
  const isPerRecord = (s: Snapshot): boolean => perRecordSources.has(s.sourceId) && s.status === 'OK'
  const snapshotCounts: Record<string, number> = {}
  for (const s of out.snapshots) snapshotCounts[s.sourceId] = (snapshotCounts[s.sourceId] ?? 0) + 1
  const sortedCounts: Record<string, number> = {}
  for (const k of Object.keys(snapshotCounts).sort()) sortedCounts[k] = snapshotCounts[k]!
  const perRecordById = new Map(out.snapshots.filter(isPerRecord).map((s) => [s.id, s]))

  const summary: RunSummary = {
    manifest: out.manifest,
    methodology,
    goals: out.goals,
    metricDefinitions: out.metricDefinitions,
    vendors: vendorSummaries,
    cohort: out.cohort,
    freshness: out.freshness,
    sources: out.sources,
    snapshots: out.snapshots.filter((s) => !isPerRecord(s)),
    snapshotCounts: sortedCounts,
    identityConflicts: out.identityConflicts,
    exclusionCount: out.exclusions.length,
    signatoryList,
  }

  const vendors: Record<string, VendorDetail> = {}
  for (const v of out.vendors) {
    const id = v.vendor.id
    const exclusions = out.exclusions.filter((x) => x.candidateVendorIds.includes(id))
    const cveIds = new Set([...v.attributedCveIds, ...exclusions.map((x) => x.cveId)])
    const evidence = out.evidence.filter((e) => e.vendorId === id)
    const cves = out.cves.filter((r) => cveIds.has(r.id))
    const snapIds = new Set([...evidence.map((e) => e.snapshotId), ...cves.map((r) => r.snapshotId)])
    const snapshots = [...snapIds].sort().flatMap((sid) => {
      const s = perRecordById.get(sid)
      return s ? [s] : []
    })
    vendors[id] = {
      runId: out.manifest.runId,
      vendorId: id,
      goals: v.goals,
      evidence,
      cves,
      attributions: out.attributions.filter((a) => a.vendorId === id),
      exclusions,
      advisories: out.advisories.filter((a) => a.vendorId === id),
      snapshots,
    }
  }
  return { summary, vendors }
}

/** Per vendor, per metric: the value in each run, ordered by asOf. Methodology version travels with each point. */
export function historySeries(outputs: RunOutput[]): HistorySeries[] {
  const runs = [...outputs].sort(
    (a, b) => (toMs(a.manifest.asOf) ?? 0) - (toMs(b.manifest.asOf) ?? 0) || (a.manifest.runId < b.manifest.runId ? -1 : 1),
  )
  const series = new Map<string, HistorySeries>()
  const metricIds = METRIC_DEFINITIONS.map((m) => m.id)
  for (const out of runs) {
    for (const v of out.vendors) {
      const values = new Map(v.goals.flatMap((g) => g.metrics.map((m) => [m.metricId, m.value] as const)))
      for (const metricId of metricIds) {
        if (!values.has(metricId)) continue
        const key = `${v.vendor.id}|${metricId}`
        let s = series.get(key)
        if (!s) {
          s = { vendorId: v.vendor.id, metricId, points: [] }
          series.set(key, s)
        }
        s.points.push({
          runId: out.manifest.runId,
          datasetVersion: out.manifest.datasetVersion,
          methodologyVersion: out.manifest.methodologyVersion,
          value: values.get(metricId) ?? null,
        })
      }
    }
  }
  return [...series.values()].sort((a, b) => (a.vendorId < b.vendorId ? -1 : a.vendorId > b.vendorId ? 1 : a.metricId < b.metricId ? -1 : a.metricId > b.metricId ? 1 : 0))
}
