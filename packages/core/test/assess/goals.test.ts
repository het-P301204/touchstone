import { describe, expect, it } from 'vitest'
import { assessG3, assessG5, assessG6, assessGoals, dimensionFigures } from '../../src/assess/goals.ts'
import { computeCoverage } from '../../src/assess/coverage.ts'
import { findBannedTerms } from '../../src/assess/language.ts'
import { COVERAGE_SLOTS } from '../../src/measure/definitions.ts'
import { makeVdp, makeVendor } from '../fixtures/builders.ts'
import type { MetricValue } from '../../src/model/index.ts'

const mv = (metricId: string, value: number | null, extra: Partial<MetricValue> = {}): MetricValue => ({
  metricId,
  value,
  confidence: 'HIGH',
  confidenceReasons: [],
  evidenceIds: value === null ? [] : [`EV-${metricId}`],
  query: 'q',
  calculation: value === null ? 'Nothing. Not measured.' : 'c',
  ...(value !== null ? { numerator: value, denominator: 100 } : {}),
  ...extra,
})

const base = (metrics: MetricValue[], extra: Partial<Parameters<typeof assessG5>[0]> = {}) => ({
  vendor: makeVendor('northwind', { claims: [{ goalId: 'G2', summary: 'Unique credentials per device.' }, { goalId: 'G2', summary: 'More.' }] }),
  metrics: new Map(metrics.map((m) => [m.metricId, m])),
  cveSourceFailed: false,
  minimumEligibleRecords: 5,
  minimumRecordsPerTrendPeriod: 10,
  ...extra,
})

describe('G5 status rule', () => {
  it('VERIFIED only when all four pledge elements are MET', () => {
    expect(assessG5(base([], { vdp: makeVdp('northwind') })).status).toBe('VERIFIED')
    expect(assessG5(base([], { vdp: makeVdp('northwind', { SCOPE_DEFINED: 'NOT_MET', CURRENT: 'UNKNOWN' }) })).status).toBe('VERIFIED')
  })
  it('PARTIAL when a policy was found and at least one pledge element is MET', () => {
    const r = assessG5(base([], { vdp: makeVdp('northwind', { GOOD_FAITH_SAFE_HARBOR: 'CONTRADICTED', TESTING_AUTHORIZED: 'UNKNOWN' }) }))
    expect(r.status).toBe('PARTIAL')
    expect(r.reason).toContain('observed deviation')
    expect(r.reason).toContain('Could not be determined: Testing authorized')
  })
  it('NOT_VERIFIED when no policy was found or no pledge element is MET', () => {
    expect(assessG5(base([], { vdp: makeVdp('northwind', {}, { found: false, default: 'NOT_MET' }) })).status).toBe('NOT_VERIFIED')
    expect(assessG5(base([], { vdp: makeVdp('northwind', { REPORTING_CHANNEL: 'NOT_MET', TESTING_AUTHORIZED: 'NOT_MET', GOOD_FAITH_SAFE_HARBOR: 'PARTIAL', PUBLIC_DISCLOSURE_ALLOWED: 'NOT_MET' }) })).status).toBe('NOT_VERIFIED')
    expect(assessG5(base([])).status).toBe('NOT_VERIFIED')
  })
  it('DATA_ERROR when the policy could not be retrieved and nothing was carried', () => {
    expect(assessG5(base([], { vdp: makeVdp('northwind', {}, { default: 'UNKNOWN', found: true, retrieval: 'FETCH_FAILED' }) })).status).toBe('DATA_ERROR')
    // a carried-forward observation is not a data error
    expect(assessG5(base([], { vdp: makeVdp('northwind', {}, { carriedFrom: 'SN-old' }) })).status).toBe('VERIFIED')
  })
})

describe('G6 status rule', () => {
  it('VERIFIED needs both dimensions at 100%', () => {
    expect(assessG6(base([mv('cve.complete_records', 100), mv('cve.timely_issuance', 100)])).status).toBe('VERIFIED')
    expect(assessG6(base([mv('cve.complete_records', 100), mv('cve.timely_issuance', null, { gap: 'NO_SOURCE' })])).status).toBe('PARTIAL')
    expect(assessG6(base([mv('cve.complete_records', 99.5), mv('cve.timely_issuance', 100)])).status).toBe('PARTIAL')
  })
  it('NOT_VERIFIED below minimum sample with no high-impact advisories', () => {
    const r = assessG6(base([mv('cve.complete_records', null, { gap: 'BELOW_MINIMUM_SAMPLE', denominator: 3 }), mv('cve.timely_issuance', null, { gap: 'NO_SOURCE' })]))
    expect(r.status).toBe('NOT_VERIFIED')
    expect(r.reason).toContain('minimum sample of 5')
  })
  it('neither part measured: NOT_VERIFIED only for sample reasons, DATA_ERROR for a mapping problem, reason names it', () => {
    const none = assessG6(base([mv('cve.complete_records', null, { gap: 'NO_ELIGIBLE_RECORDS' }), mv('cve.timely_issuance', null, { gap: 'NO_ELIGIBLE_RECORDS' })]))
    expect(none.status).toBe('NOT_VERIFIED')
    expect(none.reason).toContain('no high-impact advisories in the window')
    const mapping = assessG6(base([mv('cve.complete_records', null, { gap: 'NOT_APPLICABLE' }), mv('cve.timely_issuance', null, { gap: 'NO_SOURCE' })]))
    expect(mapping.status).toBe('DATA_ERROR')
    expect(mapping.reason).toContain('no CPE vendor namespace')
    // records measurable but timeliness not: PARTIAL, never NOT_VERIFIED
    expect(assessG6(base([mv('cve.complete_records', 40), mv('cve.timely_issuance', null, { gap: 'NO_SOURCE' })])).status).toBe('PARTIAL')
  })

  it('DATA_ERROR when the CVE source failed with no earlier snapshot', () => {
    expect(assessG6(base([mv('cve.complete_records', null, { gap: 'SOURCE_FAILED' })], { cveSourceFailed: true })).status).toBe('DATA_ERROR')
  })
})

describe('G3 and unverifiable goals', () => {
  it('G3 is at most PARTIAL', () => {
    expect(assessG3(base([mv('g3.class_share_trend', -12, { breakdown: { prior_records: 20, latest_records: 20 } })])).status).toBe('PARTIAL')
    expect(assessG3(base([mv('g3.class_share_trend', null, { gap: 'BELOW_MINIMUM_SAMPLE' })])).status).toBe('NOT_VERIFIED')
  })
  it('G1/G2/G4/G7 are always NOT_EXTERNALLY_VERIFIABLE with claimCount from vendor claims', () => {
    const goals = assessGoals(base([mv('cve.complete_records', 100), mv('cve.timely_issuance', 100)], { vdp: makeVdp('northwind') }))
    for (const id of ['G1', 'G2', 'G4', 'G7']) {
      const g = goals.find((x) => x.goalId === id)!
      expect(g.status).toBe('NOT_EXTERNALLY_VERIFIABLE')
      expect(g.metrics).toEqual([])
    }
    expect(goals.find((g) => g.goalId === 'G2')!.claimCount).toBe(2)
    for (const g of goals) expect(findBannedTerms(g.statusReason)).toEqual([])
  })
  it('dimension figures stand alone; no composite', () => {
    const metrics = [mv('vdp.criteria_met', 75), mv('cve.complete_records', null, { gap: 'BELOW_MINIMUM_SAMPLE' }), mv('cve.timely_issuance', 100)]
    const inp = base(metrics, { vdp: makeVdp('northwind', { SCOPE_DEFINED: 'NOT_MET', CURRENT: 'NOT_MET' }) })
    const figs = dimensionFigures(assessGoals(inp), inp.metrics)
    expect(figs).toEqual([
      { dimension: 'VDP', value: 75, metricId: 'vdp.criteria_met', status: 'VERIFIED' },
      { dimension: 'CVE_QUALITY', value: null, metricId: 'cve.complete_records', status: 'NOT_VERIFIED' },
      { dimension: 'CVE_TIMELINESS', value: 100, metricId: 'cve.timely_issuance', status: 'VERIFIED' },
    ])
  })
})

describe('evidence coverage', () => {
  it('counts 14 slots; determined VDP criteria and measured values observe a slot', () => {
    expect(COVERAGE_SLOTS).toHaveLength(14)
    const vdp = makeVdp('northwind', { CURRENT: 'UNKNOWN', SCOPE_DEFINED: 'NOT_MET' })
    const metrics = new Map(
      [mv('cve.cwe_coverage', 80), mv('cve.cpe_coverage', null, { gap: 'BELOW_MINIMUM_SAMPLE' }), mv('cve.publication_latency', 2, { denominator: undefined, numerator: undefined, distribution: { median: 2, p75: 3, p95: 4, n: 3 } })].map((m) => [m.metricId, m]),
    )
    const c = computeCoverage(metrics, vdp, [])
    // 7 VDP criteria determined + cwe_coverage + publication_latency = 9 of 14
    expect(c.observedSlots).toBe(9)
    expect(c.percent).toBe(64.3)
    expect(c.unverifiableGoals).toBe(4)
    expect(c.unobserved.map((u) => u.metricId)).toContain('vdp.criterion.CURRENT')
    expect(c.unobserved.find((u) => u.metricId === 'cve.cpe_coverage')!.reason).toBe('below the minimum sample')
  })
})

describe('language', () => {
  it('flags judgement words but allows "Secure by Design"', () => {
    expect(findBannedTerms('The vendor is compliant.')).toEqual(['compliant'])
    expect(findBannedTerms('Measured against the Secure by Design Pledge.')).toEqual([])
    expect(findBannedTerms('An insecure product; the check failed.')).toEqual(['insecure', 'failed'])
    expect(findBannedTerms('Above peer median on this observable metric.')).toEqual([])
  })
})
