/**
 * Cohort summaries and per-vendor benchmarks.
 *
 *  - Only rates, shares and medians are compared, never raw CVE counts: a
 *    large vendor publishes more records, which says nothing about quality.
 *  - Peer medians use only vendors with a non-null value; the peer count is
 *    always reported. The vendor itself is included in its peer group.
 *  - ALL_SIGNATORIES is every vendor in the run's registry; category groups
 *    use Vendor.category.
 *  - Position is stated only with at least MIN_PEERS_FOR_POSITION values.
 *  - Wording describes position on an observable metric, never a judgement.
 */

import type { Benchmark, CohortPosition, CohortSummary, EvidenceCoverage, GoalStatus, HistoricalPoint, MetricValue, Vendor } from '../model/index.ts'
import { BENCHMARK_METRIC_IDS, MIN_PEERS_FOR_POSITION, comparableAcrossVersions, metricDefinition } from '../measure/definitions.ts'
import { fmt, median, toMs } from '../measure/stats.ts'

export const ALL_SIGNATORIES = 'ALL_SIGNATORIES'

export type CohortRow = {
  vendor: Vendor
  metrics: Map<string, MetricValue>
  coverage: EvidenceCoverage
  g5Status: GoalStatus
}

export function peerGroupsOf(v: Vendor): string[] {
  return [ALL_SIGNATORIES, v.category]
}

function members(rows: CohortRow[], group: string): CohortRow[] {
  return group === ALL_SIGNATORIES ? rows : rows.filter((r) => r.vendor.category === group)
}

function values(rows: CohortRow[], metricId: string): number[] {
  return rows.flatMap((r) => {
    const v = r.metrics.get(metricId)?.value
    return v === null || v === undefined ? [] : [v]
  })
}

const COVERAGE_BUCKETS: [string, number, number][] = [
  ['0-24', 0, 25],
  ['25-49', 25, 50],
  ['50-74', 50, 75],
  ['75-100', 75, 100.0001],
]

export function cohortSummaries(rows: CohortRow[]): CohortSummary[] {
  const groups = [ALL_SIGNATORIES, ...[...new Set(rows.map((r) => r.vendor.category))].sort()]
  return groups.map((group) => {
    const m = members(rows, group)
    const medians: Record<string, number | null> = {}
    for (const id of BENCHMARK_METRIC_IDS) medians[id] = median(values(m, id))
    medians['coverage.percent'] = median(m.map((r) => r.coverage.percent))
    const vdpStatusCounts: Record<string, number> = {}
    for (const r of m) vdpStatusCounts[r.g5Status] = (vdpStatusCounts[r.g5Status] ?? 0) + 1
    return {
      peerGroup: group,
      vendorCount: m.length,
      medians,
      coverageDistribution: COVERAGE_BUCKETS.map(([bucket, lo, hi]) => ({
        bucket,
        count: m.filter((r) => r.coverage.percent >= lo && r.coverage.percent < hi).length,
      })),
      vdpStatusCounts,
    }
  })
}

/** Median of the vendor's earlier values for a metric, comparable under the current methodology. */
export function historicalMedian(history: HistoricalPoint[], vendorId: string, metricId: string, asOf: string, methodologyVersion: string): number | null {
  const asOfMs = toMs(asOf) ?? Number.POSITIVE_INFINITY
  const vals = history.flatMap((p) => {
    if (p.vendorId !== vendorId) return []
    if ((toMs(p.asOf) ?? Number.POSITIVE_INFINITY) >= asOfMs) return []
    if (!comparableAcrossVersions(metricId, p.methodologyVersion, methodologyVersion)) return []
    const v = p.metrics[metricId]
    return v === null || v === undefined || !Number.isFinite(v) ? [] : [v]
  })
  return median(vals)
}

export const POSITION_WORDING: Record<CohortPosition, string> = {
  ABOVE_PEER_MEDIAN: 'Above peer median on this observable metric.',
  AT_PEER_MEDIAN: 'At peer median on this observable metric.',
  BELOW_PEER_MEDIAN: 'Below peer median on this observable metric.',
  NOT_COMPARABLE: 'Not comparable on this observable metric.',
}

export function benchmarksFor(row: CohortRow, rows: CohortRow[], history: HistoricalPoint[], asOf: string, methodologyVersion: string): Benchmark[] {
  const out: Benchmark[] = []
  for (const metricId of BENCHMARK_METRIC_IDS) {
    const current = row.metrics.get(metricId)?.value ?? null
    const hist = historicalMedian(history, row.vendor.id, metricId, asOf, methodologyVersion)
    for (const group of peerGroupsOf(row.vendor)) {
      const vals = values(members(rows, group), metricId)
      const peerMedian = median(vals)
      let position: CohortPosition = 'NOT_COMPARABLE'
      let wording: string
      if (current === null) wording = 'Not comparable: no value for this vendor on this observable metric.'
      else if (vals.length < MIN_PEERS_FOR_POSITION || peerMedian === null)
        wording = `Not comparable: fewer than ${MIN_PEERS_FOR_POSITION} vendors in this peer group have a value on this observable metric.`
      else {
        position = current > peerMedian ? 'ABOVE_PEER_MEDIAN' : current < peerMedian ? 'BELOW_PEER_MEDIAN' : 'AT_PEER_MEDIAN'
        wording = POSITION_WORDING[position]
      }
      out.push({ metricId, current, vendorHistoricalMedian: hist, peerMedian, peerGroup: group, peerCount: vals.length, position, wording })
    }
  }
  return out
}

const DIMENSION_METRICS: [string, string][] = [
  ['VDP', 'vdp.criteria_met'],
  ['CVE_QUALITY', 'cve.complete_records'],
  ['CVE_TIMELINESS', 'cve.timely_issuance'],
]

/** One interpretable sentence per dimension: value, formula numbers, peer position. */
export function rankingNotes(row: CohortRow, benchmarks: Benchmark[]): Record<string, string> {
  const notes: Record<string, string> = {}
  for (const [dim, metricId] of DIMENSION_METRICS) {
    const m = row.metrics.get(metricId)
    const def = metricDefinition(metricId)!
    const b = benchmarks.find((x) => x.metricId === metricId && x.peerGroup === ALL_SIGNATORIES)
    if (!m || m.value === null) {
      notes[dim] = `${def.name}: not measured (${m?.gap ?? 'no data'}). Not placed relative to peers.`
      continue
    }
    const nums = m.numerator !== undefined && m.denominator !== undefined ? ` (${fmt(m.numerator)} of ${fmt(m.denominator)})` : ''
    const peer =
      b && b.position !== 'NOT_COMPARABLE'
        ? `${b.wording.replace(/\.$/, '')} (peer median ${fmt(b.peerMedian!)}%, ${b.peerCount} vendors with a value).`
        : (b?.wording ?? '')
    notes[dim] = `${def.name}: ${fmt(m.value)}%${nums}. ${peer}`.trim()
  }
  return notes
}
