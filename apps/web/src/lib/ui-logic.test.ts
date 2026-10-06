import { describe, expect, it } from 'vitest'
import type { HistorySeries, VendorSummary } from '@touchstone/core/model'
import { bucket20, lastComparableDelta, median } from './history.ts'
import { date, minusDays, pct } from './format.ts'
import { GOAL_STATUS, CRITERION_STATE } from './status.ts'
import { BANNED_WORDS, breakdownLabel } from './vocab.ts'
import { sanitizeDispute } from '../data/source.ts'
import { sortVendors } from '../features/vendorTable.tsx'
import { compareSentence } from '../pages/app/Compare.tsx'

function vendor(id: string, dims: Partial<Record<'VDP' | 'CVE_QUALITY' | 'CVE_TIMELINESS', number | null>>, coverage = 50): VendorSummary {
  return {
    vendor: { id, canonicalName: id, aliases: [], signatoryStatus: 'LISTED', category: 'CLOUD', domains: [], claims: [], synthetic: true },
    goals: [],
    dimensions: (['VDP', 'CVE_QUALITY', 'CVE_TIMELINESS'] as const).map((d) => ({ dimension: d, value: dims[d] ?? null, metricId: d, status: dims[d] === null || dims[d] === undefined ? 'NOT_VERIFIED' : 'PARTIAL' })),
    coverage: { percent: coverage, observedSlots: 7, totalSlots: 14, sourcesEvaluated: 1, evidenceBackedMeasurements: 1, unverifiableGoals: 4, unobserved: [] },
    benchmarks: [],
    anomalies: [],
    vdpChanges: [],
    cveCount: 0,
    advisoryCount: 0,
    rankingNotes: {},
    statusCounts: { VERIFIED: 0, PARTIAL: 0, NOT_VERIFIED: 0, NOT_EXTERNALLY_VERIFIABLE: 4, DATA_ERROR: 0 },
  }
}

describe('missing data is never a number', () => {
  it('formats null as a placeholder, not 0', () => {
    expect(pct(null)).toBe('—')
    expect(pct(0)).toBe('0.0%')
  })
  it('sorts not-measured last in both directions', () => {
    const list = [vendor('a', { CVE_QUALITY: null }), vendor('b', { CVE_QUALITY: 10 }), vendor('c', { CVE_QUALITY: 90 })]
    const summary = { freshness: [] } as never
    expect(sortVendors(list, 'quality', 'desc', summary).map((v) => v.vendor.id)).toEqual(['c', 'b', 'a'])
    expect(sortVendors(list, 'quality', 'asc', summary).map((v) => v.vendor.id)).toEqual(['b', 'c', 'a'])
  })
  it('keeps nulls in their own histogram bucket', () => {
    const b = bucket20([null, 0, 19.9, 20, 100])
    expect(b.find((x) => x.bucket === 'not measured')!.count).toBe(1)
    expect(b.find((x) => x.bucket === '0–20')!.count).toBe(2)
    expect(b.find((x) => x.bucket === '80–100')!.count).toBe(1)
  })
  it('computes a median over present values only', () => {
    expect(median([])).toBeNull()
    expect(median([1, 3, 2])).toBe(2)
    expect(median([1, 2, 3, 4])).toBe(2.5)
  })
})

describe('history deltas respect methodology changes', () => {
  const series = (metricId: string, versions: string[], values: (number | null)[]): HistorySeries => ({
    vendorId: 'v',
    metricId,
    points: values.map((value, i) => ({ runId: `R${i}`, datasetVersion: `2026-0${i + 1}-06`, methodologyVersion: versions[i]!, value })),
  })
  it('refuses to compare a metric across the version that changed its formula', () => {
    expect(lastComparableDelta(series('cve.cwe_coverage', ['1.0.0', '1.1.0'], [90, 70]))).toBeNull()
  })
  it('compares a metric whose formula did not change', () => {
    expect(lastComparableDelta(series('vdp.criteria_met', ['1.0.0', '1.1.0'], [50, 75]))!.delta).toBe(25)
  })
  it('skips null points rather than reading them as zero', () => {
    expect(lastComparableDelta(series('vdp.criteria_met', ['1.0.0', '1.0.0', '1.0.0'], [40, 60, null]))!.delta).toBe(20)
  })
})

describe('comparison wording', () => {
  it('names a leader only when it is ahead on every comparable dimension', () => {
    const a = vendor('Alpha', { VDP: 100, CVE_QUALITY: 90, CVE_TIMELINESS: null })
    const b = vendor('Beta', { VDP: 80, CVE_QUALITY: 70, CVE_TIMELINESS: 100 })
    expect(compareSentence([a, b])).toMatch(/^Alpha demonstrates stronger publicly observable evidence on the measured dimensions/)
  })
  it('names no leader when the vendors split', () => {
    const a = vendor('Alpha', { VDP: 100, CVE_QUALITY: 50 })
    const b = vendor('Beta', { VDP: 80, CVE_QUALITY: 70 })
    expect(compareSentence([a, b])).toMatch(/^No selected vendor/)
  })
  it('never says "more secure"', () => {
    const s = compareSentence([vendor('A', { VDP: 1 }), vendor('B', { VDP: 2 })])
    expect(s.toLowerCase()).not.toMatch(/secure|compliant/)
  })
})

describe('display vocabulary', () => {
  it('uses measurement language for every status and criterion', () => {
    const labels = [...Object.values(GOAL_STATUS), ...Object.values(CRITERION_STATE)].map((m) => `${m.label} ${m.description}`.toLowerCase())
    for (const text of labels) for (const word of BANNED_WORDS) expect(text.split(/[^a-z-]+/)).not.toContain(word)
  })
  it('gives every state an icon and a text label', () => {
    for (const m of Object.values(GOAL_STATUS)) {
      expect(m.label.length).toBeGreaterThan(0)
      expect(m.icon).toBeTruthy()
    }
  })
  it('labels breakdown keys', () => {
    expect(breakdownLabel('gap.NOT_PROVIDED')).toBe('Not provided')
    expect(breakdownLabel('missing_cwe')).toBe('Missing cwe')
  })
})

describe('dispute input', () => {
  it('strips bidi controls, bounds the statement and keeps only https links', () => {
    const rlo = String.fromCodePoint(0x202e)
    const d = sanitizeDispute({
      vendorId: 'v',
      target: { kind: 'GOAL', id: 'G6' },
      runId: 'R',
      reason: 'METHODOLOGY_ERROR',
      submitterRole: 'OTHER',
      statement: `abc${rlo}def`.padEnd(5000, 'x'),
      evidenceUrls: ['https://ok.example/a', 'javascript:alert(1)', 'http://plain.example', `https://x.example/${rlo}`],
    })
    expect(d.statement.includes(rlo)).toBe(false)
    expect(d.statement.length).toBe(2000)
    expect(d.evidenceUrls).toEqual(['https://ok.example/a', 'https://x.example/'])
  })
})

describe('dates', () => {
  it('formats the date part without time-zone drift', () => {
    expect(date('2026-10-06T23:59:00Z')).toBe('6 Oct 2026')
    expect(minusDays('2026-10-06T12:00:00Z', 730)).toBe('2024-10-06')
  })
})
