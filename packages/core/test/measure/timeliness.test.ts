import { describe, expect, it } from 'vitest'
import { measureTimeliness, timeAdvisory } from '../../src/measure/timeliness.ts'
import { METRIC_DEFINITIONS } from '../../src/measure/definitions.ts'
import { daysAgo, makeAdvisory, makeCtx, makeCve, makeVendor } from '../fixtures/builders.ts'
import type { MetricValue } from '../../src/model/index.ts'

const get = (ms: MetricValue[], id: string) => ms.find((m) => m.metricId === id)!

describe('issuance timeliness', () => {
  it('no advisories: NOT measured with gap NO_SOURCE, never zero', () => {
    const vendor = makeVendor('brightwater', { csaf: false })
    const { metrics } = measureTimeliness(makeCtx({ vendor }))
    for (const id of ['cve.high_impact_with_cve', 'cve.timely_issuance', 'cve.publication_latency']) {
      expect(get(metrics, id)).toMatchObject({ value: null, gap: 'NO_SOURCE' })
    }
    expect(get(metrics, 'cve.timely_issuance').calculation).toContain('No machine-readable advisory feed')
  })

  it('classifies advisories and keeps the latency sign', () => {
    const vendor = makeVendor('northwind')
    // Advisories released 40 days ago; CVEs published relative to that.
    const cves = [
      makeCve('DEMO-2026-0101', { datePublished: daysAgo(40) }), // 0 days: timely
      makeCve('DEMO-2026-0102', { datePublished: daysAgo(39.5) }), // +0.5: timely (tolerance 1)
      makeCve('DEMO-2026-0103', { datePublished: daysAgo(10) }), // +30: late
      makeCve('DEMO-2026-0104', { datePublished: daysAgo(45) }), // -5: CVE before advisory, timely
    ]
    const advisories = [
      makeAdvisory('northwind', 'NW-1', { cveIds: ['DEMO-2026-0101'] }),
      makeAdvisory('northwind', 'NW-2', { cveIds: ['DEMO-2026-0102'] }),
      makeAdvisory('northwind', 'NW-3', { cveIds: ['DEMO-2026-0103'] }),
      makeAdvisory('northwind', 'NW-4', { cveIds: ['DEMO-2026-0104'] }),
      makeAdvisory('northwind', 'NW-5', { cveIds: [] }), // no CVE listed
      makeAdvisory('northwind', 'NW-6', { cveIds: ['DEMO-2026-9999'] }), // not in snapshot
      makeAdvisory('northwind', 'NW-7', { severity: 'MEDIUM', cveIds: ['DEMO-2026-0103'] }), // not high impact
      makeAdvisory('northwind', 'NW-8', { cveIds: ['DEMO-2026-0101'], publishedDaysAgo: 800 }), // outside window
    ]
    const { metrics, timings } = measureTimeliness(makeCtx({ vendor, advisories, allCves: cves }))
    expect(timings.map((t) => t.outcome)).toEqual(['TIMELY', 'TIMELY', 'LATE', 'TIMELY', 'NO_CVE_LISTED', 'CVE_NOT_IN_SNAPSHOT'])
    // 6 high-impact advisories in window; 4 list a CVE present in the snapshot = 66.67%
    expect(get(metrics, 'cve.high_impact_with_cve')).toMatchObject({ value: 66.67, numerator: 4, denominator: 6 })
    // timely: 3 of 6 = 50%
    expect(get(metrics, 'cve.timely_issuance')).toMatchObject({ value: 50, numerator: 3, denominator: 6 })
    expect(get(metrics, 'cve.timely_issuance').breakdown).toMatchObject({ timely: 3, late: 1, no_cve_listed: 1, cve_not_in_snapshot: 1, tolerance_days: 1 })
    // latencies [-5, 0, 0.5, 30]: median 0.25, p75 rank ceil(3) = 0.5, p95 rank ceil(3.8) = 30
    const lat = get(metrics, 'cve.publication_latency')
    expect(lat.value).toBe(0.25)
    expect(lat.distribution).toEqual({ median: 0.25, p75: 0.5, p95: 30, n: 4 })
    expect(lat.breakdown?.['cve_before_advisory']).toBe(1)
  })

  it('a listed CVE missing from the snapshot is never counted as timely', () => {
    const a = makeAdvisory('northwind', 'NW-X', { cveIds: ['DEMO-2026-0201', 'DEMO-2026-0202'] })
    const cves = new Map([['DEMO-2026-0201', makeCve('DEMO-2026-0201', { datePublished: daysAgo(40) })]])
    expect(timeAdvisory(a, cves, 1).outcome).toBe('CVE_NOT_IN_SNAPSHOT')
  })

  it('labels the tolerance as a methodology parameter, not a CISA threshold', () => {
    const def = METRIC_DEFINITIONS.find((d) => d.id === 'cve.timely_issuance')!
    expect(def.formula).toContain('methodology parameter, not a CISA threshold')
    const vendor = makeVendor('northwind')
    const cves = [makeCve('DEMO-2026-0301', { datePublished: daysAgo(40) })]
    const ctx = makeCtx({ vendor, advisories: [makeAdvisory('northwind', 'NW-9', { cveIds: ['DEMO-2026-0301'] })], allCves: cves })
    measureTimeliness(ctx)
    const ev = ctx.ledger.list().find((e) => e.metricId === 'cve.timely_issuance')!
    expect(ev.reading).toContain('not a CISA threshold')
  })

  it('few advisories lower confidence (rule C2) but are still reported', () => {
    const vendor = makeVendor('northwind')
    const cves = [makeCve('DEMO-2026-0401', { datePublished: daysAgo(40) })]
    const { metrics } = measureTimeliness(makeCtx({ vendor, advisories: [makeAdvisory('northwind', 'NW-A', { cveIds: ['DEMO-2026-0401'] })], allCves: cves }))
    const m = get(metrics, 'cve.timely_issuance')
    expect(m.value).toBe(100)
    expect(m.confidence).toBe('LOW')
    expect(m.confidenceReasons[0]).toMatch(/^C2\.SAMPLE/)
  })
})
