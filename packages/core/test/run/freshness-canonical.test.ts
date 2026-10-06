import { describe, expect, it } from 'vitest'
import fc from 'fast-check'
import { computeFreshness } from '../../src/freshness/freshness.ts'
import { canonicalJson } from '../../src/run/canonical.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { AS_OF, CVE_SOURCE, daysAgo, snapshot, vdpSource } from '../fixtures/builders.ts'

const params = methodologyVersion('1.1.0').parameters

describe('computeFreshness', () => {
  it('computes freshness from the last success; bands per family', () => {
    const vdp = vdpSource('northwind') // VENDOR_VDP: current <= 7 days, aging <= 45 days
    const f = computeFreshness([snapshot('SN-a', vdp.id, daysAgo(3)), snapshot('SN-b', CVE_SOURCE.id, daysAgo(3))], [vdp, CVE_SOURCE], AS_OF, params)
    expect(f.find((x) => x.sourceId === vdp.id)).toMatchObject({ state: 'CURRENT', ageHours: 72, usedSnapshotId: 'SN-a' })
    // CVE_PROGRAM: current <= 24 h, aging <= 7 days
    expect(f.find((x) => x.sourceId === CVE_SOURCE.id)).toMatchObject({ state: 'AGING', ageHours: 72 })
  })

  it('a failed latest attempt shows the failure and the age of the snapshot actually used, never CURRENT', () => {
    const vdp = vdpSource('halcyon')
    const snaps = [
      snapshot('SN-old', vdp.id, daysAgo(2)),
      snapshot('SN-fail', vdp.id, daysAgo(0.1), 'FAILED', { error: 'timeout', substitutedBy: 'SN-old' }),
    ]
    const [f] = computeFreshness(snaps, [vdp], AS_OF, params)
    expect(f).toMatchObject({ lastStatus: 'FAILED', usedSnapshotId: 'SN-old', ageHours: 48, state: 'AGING', lastSuccessAt: daysAgo(2), lastAttemptAt: daysAgo(0.1) })
    expect(f!.note).toContain('did not succeed')
    expect(f!.note).toContain('SN-old')
  })

  it('a stale substitute stays STALE', () => {
    const vdp = vdpSource('halcyon')
    const [f] = computeFreshness([snapshot('SN-old', vdp.id, daysAgo(90)), snapshot('SN-fail', vdp.id, daysAgo(0.1), 'FAILED', { substitutedBy: 'SN-old' })], [vdp], AS_OF, params)
    expect(f!.state).toBe('STALE')
  })

  it('no successful snapshot: UNKNOWN; no attempt: UNKNOWN', () => {
    const vdp = vdpSource('sparrow')
    const [f] = computeFreshness([snapshot('SN-f', vdp.id, daysAgo(1), 'FAILED')], [vdp], AS_OF, params)
    expect(f).toMatchObject({ state: 'UNKNOWN', lastStatus: 'FAILED' })
    expect(f!.usedSnapshotId).toBeUndefined()
    expect(computeFreshness([], [vdp], AS_OF, params)[0]!.state).toBe('UNKNOWN')
  })

  it('ignores snapshots fetched after asOf', () => {
    const vdp = vdpSource('n')
    const [f] = computeFreshness([snapshot('SN-future', vdp.id, daysAgo(-5))], [vdp], AS_OF, params)
    expect(f!.state).toBe('UNKNOWN')
  })
})

describe('canonicalJson', () => {
  it('sorts keys, drops undefined members, no whitespace', () => {
    expect(canonicalJson({ b: 1, a: [1, undefined, 'x'], c: undefined, d: { z: null, y: true } })).toBe('{"a":[1,null,"x"],"b":1,"d":{"y":true,"z":null}}')
  })
  it('is independent of insertion order and matches JSON.parse round trip', () => {
    fc.assert(
      fc.property(fc.jsonValue(), (v) => {
        const c = canonicalJson(v)
        expect(canonicalJson(JSON.parse(c))).toBe(c)
        if (v && typeof v === 'object' && !Array.isArray(v)) {
          const reversed = Object.fromEntries(Object.entries(v).reverse())
          expect(canonicalJson(reversed)).toBe(c)
        }
      }),
    )
  })
})
