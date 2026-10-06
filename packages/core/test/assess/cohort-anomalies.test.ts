import { describe, expect, it } from 'vitest'
import { benchmarksFor, cohortSummaries, historicalMedian, ALL_SIGNATORIES } from '../../src/assess/cohort.ts'
import type { CohortRow } from '../../src/assess/cohort.ts'
import { detectAnomalies } from '../../src/assess/anomalies.ts'
import { detectVdpChange } from '../../src/assess/vdp-change.ts'
import { comparableAcrossVersions } from '../../src/measure/definitions.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { AS_OF, daysAgo, makeVdp, makeVendor } from '../fixtures/builders.ts'
import type { EvidenceCoverage, HistoricalPoint, MetricValue, VendorCategory } from '../../src/model/index.ts'

const cov: EvidenceCoverage = { percent: 50, observedSlots: 7, totalSlots: 14, sourcesEvaluated: 2, evidenceBackedMeasurements: 3, unverifiableGoals: 4, unobserved: [] }
const mv = (metricId: string, value: number | null): MetricValue => ({ metricId, value, confidence: 'HIGH', confidenceReasons: [], evidenceIds: [], query: 'q', calculation: 'c' })

function row(id: string, values: Record<string, number | null>, category: VendorCategory = 'CLOUD'): CohortRow {
  return { vendor: makeVendor(id, { category }), metrics: new Map(Object.entries(values).map(([k, v]) => [k, mv(k, v)])), coverage: cov, g5Status: 'PARTIAL' }
}

describe('cohort and benchmarks', () => {
  const rows = [
    row('a', { 'cve.complete_records': 90 }),
    row('b', { 'cve.complete_records': 60 }),
    row('c', { 'cve.complete_records': 70 }, 'NETWORKING'),
    row('d', { 'cve.complete_records': null }),
    row('e', { 'cve.complete_records': 40 }, 'NETWORKING'),
  ]
  it('peer medians use only non-null values and report peerCount', () => {
    const b = benchmarksFor(rows[0]!, rows, [], AS_OF, '1.1.0').filter((x) => x.metricId === 'cve.complete_records')
    const all = b.find((x) => x.peerGroup === ALL_SIGNATORIES)!
    // values 90, 60, 70, 40 -> median 65
    expect(all).toMatchObject({ peerMedian: 65, peerCount: 4, position: 'ABOVE_PEER_MEDIAN', wording: 'Above peer median on this observable metric.' })
    // CLOUD: a=90, b=60 (d null) -> 2 peers: not comparable
    const cloud = b.find((x) => x.peerGroup === 'CLOUD')!
    expect(cloud).toMatchObject({ peerCount: 2, position: 'NOT_COMPARABLE' })
  })
  it('a vendor without a value is never placed', () => {
    const b = benchmarksFor(rows[3]!, rows, [], AS_OF, '1.1.0').find((x) => x.metricId === 'cve.complete_records' && x.peerGroup === ALL_SIGNATORIES)!
    expect(b.position).toBe('NOT_COMPARABLE')
  })
  it('never benchmarks raw counts', () => {
    const b = benchmarksFor(rows[0]!, rows, [], AS_OF, '1.1.0')
    expect(b.some((x) => ['cve.excluded_records', 'cve.duplicate_conflicts', 'vdp.pledge_elements_met'].includes(x.metricId))).toBe(false)
  })
  it('cohort summary per group', () => {
    const s = cohortSummaries(rows)
    expect(s.map((x) => x.peerGroup)).toEqual([ALL_SIGNATORIES, 'CLOUD', 'NETWORKING'])
    expect(s[0]!.medians['cve.complete_records']).toBe(65)
    expect(s[0]!.vendorCount).toBe(5)
    expect(s[0]!.coverageDistribution.find((x) => x.bucket === '50-74')!.count).toBe(5)
  })
  it('historical median uses only earlier, comparable points', () => {
    const pt = (asOf: string, mvv: string, v: number): HistoricalPoint => ({ runId: 'r', datasetVersion: asOf.slice(0, 10), asOf, methodologyVersion: mvv, vendorId: 'a', metrics: { 'cve.complete_records': v, 'cve.publication_latency': v } })
    const history = [pt(daysAgo(270), '1.0.0', 10), pt(daysAgo(180), '1.0.0', 20), pt(daysAgo(90), '1.1.0', 30), pt(daysAgo(-10), '1.1.0', 99)]
    // complete_records changed in 1.1.0: only the 1.1.0 point before asOf counts
    expect(historicalMedian(history, 'a', 'cve.complete_records', AS_OF, '1.1.0')).toBe(30)
    // latency did not change: all three earlier points count
    expect(historicalMedian(history, 'a', 'cve.publication_latency', AS_OF, '1.1.0')).toBe(20)
    expect(comparableAcrossVersions('cve.cwe_coverage', '1.0.0', '1.1.0')).toBe(false)
    expect(comparableAcrossVersions('vdp.criteria_met', '1.0.0', '1.1.0')).toBe(true)
  })
})

describe('anomalies', () => {
  const params = methodologyVersion('1.1.0').parameters
  const baseInp = { history: [], params, asOf: AS_OF, methodologyVersion: '1.1.0', exclusions: [], identityConflicts: [], vdpChanges: [], vendorSourceFreshness: [] }

  it('UNUSUAL fires strictly below the cohort percentile, with >= 10 vendors', () => {
    const rows = Array.from({ length: 12 }, (_, i) => row(`v${i}`, { 'cve.complete_records': 50 + i * 4 }))
    rows.push(row('low', { 'cve.complete_records': 5 }))
    const low = rows.at(-1)!
    const a = detectAnomalies({ ...baseInp, vendor: low.vendor, metrics: low.metrics, rows })
    const u = a.filter((x) => x.kind === 'UNUSUAL')
    expect(u).toHaveLength(1)
    expect(u[0]!.headline.startsWith('Observed deviation')).toBe(true)
    expect(u[0]!.rule).toContain('unusualBelowPercentile = 10')
    // too few peers: no percentile rule
    const few = detectAnomalies({ ...baseInp, vendor: low.vendor, metrics: low.metrics, rows: rows.slice(-5) })
    expect(few.filter((x) => x.kind === 'UNUSUAL')).toHaveLength(0)
  })

  it('LATENCY_OUTLIER against own history', () => {
    const r = row('x', { 'cve.publication_latency': 30 })
    const history: HistoricalPoint[] = [5, 6, 4].map((v, i) => ({ runId: `r${i}`, datasetVersion: 'd', asOf: daysAgo(90 * (i + 1)), methodologyVersion: '1.0.0', vendorId: 'x', metrics: { 'cve.publication_latency': v } }))
    const a = detectAnomalies({ ...baseInp, history, vendor: r.vendor, metrics: r.metrics, rows: [r] })
    expect(a.filter((x) => x.kind === 'LATENCY_OUTLIER')).toHaveLength(1)
    // 9 days vs median 5: factor 2 met but only +4 days -> no outlier
    const r2 = row('x', { 'cve.publication_latency': 9 })
    expect(detectAnomalies({ ...baseInp, history, vendor: r2.vendor, metrics: r2.metrics, rows: [r2] }).filter((x) => x.kind === 'LATENCY_OUTLIER')).toHaveLength(0)
  })

  it('ids are stable', () => {
    const r = row('x', {})
    const inp = { ...baseInp, vendor: r.vendor, metrics: r.metrics, rows: [r], vdp: makeVdp('x', {}, { carriedFrom: 'SN-1' }) }
    expect(detectAnomalies(inp).map((a) => a.id)).toEqual(detectAnomalies(inp).map((a) => a.id))
    expect(detectAnomalies(inp)[0]!.id).toMatch(/^AN-[0-9a-f]{10}$/)
  })
})

describe('VDP change detection', () => {
  it('reports per-criterion before/after and recommends review on a pledge criterion', () => {
    const prev = makeVdp('n', {}, { textHash: 'h1', observedAt: daysAgo(90) })
    const cur = makeVdp('n', { TESTING_AUTHORIZED: 'PARTIAL', SCOPE_DEFINED: 'PARTIAL' }, { textHash: 'h2' })
    const [ch] = detectVdpChange(prev, cur)
    expect(ch).toMatchObject({ textChanged: true, reviewRecommended: true })
    expect(ch!.criteria).toEqual([
      { criterion: 'TESTING_AUTHORIZED', before: 'MET', after: 'PARTIAL' },
      { criterion: 'SCOPE_DEFINED', before: 'MET', after: 'PARTIAL' },
    ])
  })
  it('no change, no record; no previous, no record', () => {
    expect(detectVdpChange(makeVdp('n'), makeVdp('n'))).toEqual([])
    expect(detectVdpChange(undefined, makeVdp('n'))).toEqual([])
  })
})
