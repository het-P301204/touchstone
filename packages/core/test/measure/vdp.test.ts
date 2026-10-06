import { describe, expect, it } from 'vitest'
import fc from 'fast-check'
import { measureVdp } from '../../src/measure/vdp.ts'
import { VDP_CRITERIA } from '../../src/measure/definitions.ts'
import { makeCtx, makeVdp, makeVendor } from '../fixtures/builders.ts'
import type { CriterionState, MetricValue, VdpCriterionId } from '../../src/model/index.ts'

const vendor = makeVendor('halcyon')
const get = (ms: MetricValue[], id: string) => ms.find((m) => m.metricId === id)!

describe('VDP figures', () => {
  it('criteria_met: MET 1, PARTIAL 0.5, others 0, over 8', () => {
    const vdp = makeVdp('halcyon', { SCOPE_DEFINED: 'PARTIAL', CURRENT: 'NOT_MET', GOOD_FAITH_SAFE_HARBOR: 'CONTRADICTED', SECURITY_CONTACT: 'UNKNOWN' })
    const ctx = makeCtx({ vendor, vdp })
    const { metrics } = measureVdp(ctx)
    // 4 MET + 0.5 × 1 PARTIAL = 4.5 / 8 = 56.25%
    const m = get(metrics, 'vdp.criteria_met')
    expect(m).toMatchObject({ value: 56.25, numerator: 4.5, denominator: 8 })
    expect(m.calculation).toContain('UNKNOWN (counted 0): SECURITY_CONTACT')
    expect(m.confidence).toBe('MEDIUM')
    // pledge: REPORTING_CHANNEL, TESTING_AUTHORIZED, PUBLIC_DISCLOSURE MET; SAFE_HARBOR CONTRADICTED -> 3
    expect(get(metrics, 'vdp.pledge_elements_met')).toMatchObject({ value: 3, denominator: 4 })
    // one evidence item per criterion
    expect(ctx.ledger.list().filter((e) => e.metricId === 'vdp.criteria_met')).toHaveLength(8)
  })

  it('no observation: null with NO_SOURCE', () => {
    const { metrics } = measureVdp(makeCtx({ vendor }))
    expect(get(metrics, 'vdp.criteria_met')).toMatchObject({ value: null, gap: 'NO_SOURCE' })
  })

  it('every criterion UNKNOWN: not measured (SOURCE_FAILED), never 0', () => {
    const { metrics } = measureVdp(makeCtx({ vendor, vdp: makeVdp('halcyon', {}, { default: 'UNKNOWN', found: false }) }))
    expect(get(metrics, 'vdp.criteria_met')).toMatchObject({ value: null, gap: 'SOURCE_FAILED' })
    expect(get(metrics, 'vdp.pledge_elements_met')).toMatchObject({ value: null, gap: 'SOURCE_FAILED' })
  })

  it('carried-forward observation lowers confidence (rule C4)', () => {
    const { metrics } = measureVdp(makeCtx({ vendor, vdp: makeVdp('halcyon', {}, { carriedFrom: 'SN-old' }) }))
    const m = get(metrics, 'vdp.criteria_met')
    expect(m.value).toBe(100)
    expect(m.confidence).toBe('MEDIUM')
    expect(m.confidenceReasons[0]).toMatch(/^C4\.CARRIED/)
  })

  it('property: turning any criterion into UNKNOWN never raises either figure', () => {
    const stateArb = fc.constantFrom<CriterionState>('MET', 'PARTIAL', 'NOT_MET', 'CONTRADICTED', 'UNKNOWN')
    fc.assert(
      fc.property(fc.array(stateArb, { minLength: 8, maxLength: 8 }), fc.integer({ min: 0, max: 7 }), (states, idx) => {
        const map = Object.fromEntries(VDP_CRITERIA.map((c, i) => [c, states[i]!])) as Record<VdpCriterionId, CriterionState>
        const before = measureVdp(makeCtx({ vendor, vdp: makeVdp('halcyon', map) })).metrics
        const after = measureVdp(makeCtx({ vendor, vdp: makeVdp('halcyon', { ...map, [VDP_CRITERIA[idx]!]: 'UNKNOWN' }) })).metrics
        for (const id of ['vdp.criteria_met', 'vdp.pledge_elements_met']) {
          const b = get(before, id).value
          const a = get(after, id).value
          if (a !== null) expect(a).toBeLessThanOrEqual(b ?? Number.POSITIVE_INFINITY)
        }
      }),
      { numRuns: 200 },
    )
  })

  it('property: an UNKNOWN criterion never yields a higher figure than MET', () => {
    fc.assert(
      fc.property(fc.integer({ min: 0, max: 7 }), (idx) => {
        const met = measureVdp(makeCtx({ vendor, vdp: makeVdp('halcyon') })).metrics
        const unk = measureVdp(makeCtx({ vendor, vdp: makeVdp('halcyon', { [VDP_CRITERIA[idx]!]: 'UNKNOWN' }) })).metrics
        expect(get(unk, 'vdp.criteria_met').value!).toBeLessThan(get(met, 'vdp.criteria_met').value!)
      }),
    )
  })
})
