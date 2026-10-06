import { describe, expect, it } from 'vitest'
import { measureClassShare, classesOf } from '../../src/measure/class-share.ts'
import { TRACKED_CWE_CLASSES } from '../../src/measure/definitions.ts'
import { makeCtx, makeCve, makeVendor } from '../fixtures/builders.ts'

const vendor = makeVendor('northwind')

function records(prefix: string, daysAgoBase: number, cwes: string[][]) {
  return cwes.map((c, i) => makeCve(`DEMO-2026-${prefix}${String(i).padStart(2, '0')}`, { cwes: c, publishedDaysAgo: daysAgoBase + i }))
}

describe('Goal 3 class-share signal', () => {
  it('tracked classes are published as data', () => {
    expect(TRACKED_CWE_CLASSES.map((c) => c.id)).toEqual(['MEMORY_SAFETY', 'INJECTION', 'AUTH_CREDENTIALS'])
    expect(classesOf(['CWE-787'])).toEqual(['MEMORY_SAFETY'])
    expect(classesOf(['CWE-79', 'CWE-798'])).toEqual(['INJECTION', 'AUTH_CREDENTIALS'])
    expect(classesOf(['CWE-20'])).toEqual([])
  })

  it('latest minus prior share, in percentage points', () => {
    // prior (days 400..409): 6 of 10 in a tracked class = 60%
    const prior = records('7', 400, [['CWE-787'], ['CWE-79'], ['CWE-89'], ['CWE-416'], ['CWE-798'], ['CWE-78'], ['CWE-20'], ['CWE-200'], ['CWE-400'], ['CWE-20']])
    // latest (days 10..19): 3 of 10 = 30%; one placeholder record is ignored
    const latest = records('8', 10, [['CWE-787'], ['CWE-79'], ['CWE-287'], ['CWE-20'], ['CWE-20'], ['CWE-200'], ['CWE-400'], ['CWE-20'], ['CWE-352'], ['CWE-601']])
    const placeholder = makeCve('DEMO-2026-8999', { cwes: ['NVD-CWE-noinfo'], publishedDaysAgo: 5 })
    const m = measureClassShare(makeCtx({ vendor, records: [...prior, ...latest, placeholder], methodology: '1.0.0' }))
    expect(m.value).toBe(-30)
    expect(m).toMatchObject({ numerator: 3, denominator: 10 })
    expect(m.breakdown).toMatchObject({ prior_records: 10, latest_records: 10, prior_share_pct: 60, latest_share_pct: 30 })
    expect(m.calculation).toContain('-30')
  })

  it('below the per-period minimum: null with BELOW_MINIMUM_SAMPLE', () => {
    const latest = records('9', 10, [['CWE-787'], ['CWE-79']])
    const m = measureClassShare(makeCtx({ vendor, records: latest }))
    expect(m.value).toBeNull()
    expect(m.gap).toBe('BELOW_MINIMUM_SAMPLE')
    expect(m.breakdown).toMatchObject({ prior_records: 0, latest_records: 2 })
  })
})
