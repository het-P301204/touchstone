/**
 * Adversarial: Goal 6 issuance timeliness (packages/core/src/measure/timeliness.ts)
 * and the G6 status rule (packages/core/src/assess/goals.ts).
 */

import { describe, expect, it } from 'vitest'
import { AS_OF, advisory, completeRecords, daysAgo, dimOf, goalOf, inputs, metricOf, record, run, vendor, vr } from './helpers.ts'

const DAY = 86_400_000
const iso = (ms: number) => new Date(ms).toISOString()

describe('CVE source failure', () => {
  // Defect: measureTimeliness never looks at ctx.cveSourceFailed. When the CVE source
  // failed (no usable snapshot), every listed CVE is "not present as a published record
  // in the snapshot", so high_impact_with_cve = 0% and timely_issuance = 0% are
  // published as measured values (denominator > 0, DOES_NOT_SUPPORT evidence). The
  // CVE_TIMELINESS figure is 0, the coverage slot counts as observed, the 0 enters the
  // cohort median, and UNUSUAL can fire. Correct: value null, gap SOURCE_FAILED.
  const v = vendor('acme')
  const advs = [1, 2, 3].map((i) => advisory('acme', `ACME-SA-${i}`, { cveIds: [`CVE-2026-100${i}`], publishedDaysAgo: 40 + i }))
  const out = run(inputs({ vendors: [v], cves: [], advisories: advs, cveSnapshotStatus: 'FAILED' }))

  it('handled: G6 is DATA_ERROR and record quality is null', () => {
    expect(goalOf(out, 'acme', 'G6').status).toBe('DATA_ERROR')
    expect(metricOf(out, 'acme', 'cve.complete_records').value).toBeNull()
  })
  it('DEFECT timeliness-zero-on-cve-source-failure: timely_issuance must be null (SOURCE_FAILED), not 0', () => {
    expect(metricOf(out, 'acme', 'cve.timely_issuance')).toMatchObject({ value: null, gap: 'SOURCE_FAILED' })
  })
  it('DEFECT timeliness-zero-on-cve-source-failure: high_impact_with_cve must be null, not 0', () => {
    expect(metricOf(out, 'acme', 'cve.high_impact_with_cve').value).toBeNull()
  })
  it('DEFECT timeliness-zero-on-cve-source-failure: CVE_TIMELINESS figure must be null, not 0', () => {
    expect(dimOf(out, 'acme', 'CVE_TIMELINESS').value).toBeNull()
  })
  it('DEFECT timeliness-zero-on-cve-source-failure: the high_impact_with_cve coverage slot must not count as observed', () => {
    expect(vr(out, 'acme').coverage.unobserved.map((u) => u.metricId)).toContain('cve.high_impact_with_cve')
  })
})

describe('advisory denominators', () => {
  // Defect: advisories are not de-duplicated by id. The same CSAF document listed twice
  // (a ROLIE feed and an index, or a re-fetch) is counted twice. Here one timely advisory
  // appears three times next to one late advisory: published 75% (3/4); correct 50% (1/2).
  it('DEFECT advisory-duplicates-counted-twice: the same advisory id must count once', () => {
    const v = vendor('acme')
    const cves = [record('CVE-2026-2001', { cna: 'acme-cna', publishedDaysAgo: 40 }), record('CVE-2026-2002', { cna: 'acme-cna', publishedDaysAgo: 10 })]
    const timely = advisory('acme', 'ACME-SA-1', { cveIds: ['CVE-2026-2001'], publishedDaysAgo: 40 })
    const late = advisory('acme', 'ACME-SA-2', { cveIds: ['CVE-2026-2002'], publishedDaysAgo: 40 })
    const out = run(inputs({ vendors: [v], cves, advisories: [timely, { ...timely }, { ...timely }, late] }))
    expect(metricOf(out, 'acme', 'cve.timely_issuance')).toMatchObject({ value: 50, denominator: 2 })
  })

  // Defect: a CVE id listed by an advisory whose record exists twice with conflicting
  // content is dropped from cvesById, so the advisory is read as "lists X, not present as
  // a published record in the snapshot" and counts against high_impact_with_cve. The
  // record IS present (twice). The published demo shows exactly this for quillmark-labs
  // (DEMO-2024-1168, DEMO-2025-1124), which then gets an UNUSUAL anomaly.
  // Correct: the advisory is set aside (outcome unknown) or counted as having a CVE; it
  // must not be read as "no CVE record exists".
  it('DEFECT advisory-cve-duplicate-conflict-read-as-absent: a conflicting-duplicate CVE must not count as "not present"', () => {
    const v = vendor('acme')
    const a = record('CVE-2026-3001', { cna: 'acme-cna', publishedDaysAgo: 40, sourceHash: 'h1' })
    const b = record('CVE-2026-3001', { cna: 'acme-cna', publishedDaysAgo: 40, sourceHash: 'h2', cwes: ['CWE-787'] })
    const out = run(inputs({ vendors: [v], cves: [a, b], advisories: [advisory('acme', 'ACME-SA-9', { cveIds: ['CVE-2026-3001'], publishedDaysAgo: 40 })] }))
    const m = metricOf(out, 'acme', 'cve.high_impact_with_cve')
    expect(m.value === null || m.value === 100).toBe(true)
    const ev = out.evidence.filter((e) => e.metricId === 'cve.high_impact_with_cve' && e.vendorId === 'acme')
    for (const e of ev) expect(e.reading).not.toMatch(/not present as a published record/)
  })

  it('handled: an advisory listing a REJECTED CVE is not timely (record rejected, no CVE issued)', () => {
    const v = vendor('acme')
    const out = run(
      inputs({
        vendors: [v],
        cves: [record('CVE-2026-4001', { cna: 'acme-cna', state: 'REJECTED', publishedDaysAgo: 40 })],
        advisories: [advisory('acme', 'ACME-SA-4', { cveIds: ['CVE-2026-4001'], publishedDaysAgo: 40 })],
      }),
    )
    expect(metricOf(out, 'acme', 'cve.timely_issuance')).toMatchObject({ value: 0, denominator: 1 })
  })

  it('handled: an advisory with several CVEs is timely only when the LATEST is within tolerance', () => {
    const v = vendor('acme')
    const cves = [record('CVE-2026-5001', { cna: 'acme-cna', publishedDaysAgo: 40 }), record('CVE-2026-5002', { cna: 'acme-cna', publishedDaysAgo: 20 })]
    const out = run(inputs({ vendors: [v], cves, advisories: [advisory('acme', 'ACME-SA-5', { cveIds: ['CVE-2026-5001', 'CVE-2026-5002'], publishedDaysAgo: 40 })] }))
    expect(metricOf(out, 'acme', 'cve.timely_issuance').value).toBe(0)
    expect(metricOf(out, 'acme', 'cve.publication_latency').value).toBe(20)
  })

  it('handled: no CSAF feed -> timeliness null NO_SOURCE, never 0, G6 never VERIFIED', () => {
    const v = vendor('acme', { csaf: false })
    const out = run(inputs({ vendors: [v], cves: completeRecords(v, 6) }))
    expect(metricOf(out, 'acme', 'cve.timely_issuance')).toMatchObject({ value: null, gap: 'NO_SOURCE' })
    expect(metricOf(out, 'acme', 'cve.complete_records').value).toBe(100)
    expect(goalOf(out, 'acme', 'G6').status).toBe('PARTIAL')
  })

  it('handled: advisories with UNKNOWN or MEDIUM severity are outside the high-impact denominator', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], advisories: [advisory('acme', 'A1', { severity: 'UNKNOWN', cveIds: ['CVE-2026-9999'] }), advisory('acme', 'A2', { severity: 'MEDIUM' })] }))
    expect(metricOf(out, 'acme', 'cve.timely_issuance')).toMatchObject({ value: null, gap: 'NO_ELIGIBLE_RECORDS' })
  })
})

describe('time boundaries', () => {
  // Defect: a CVE published AFTER asOf is "found" by timeAdvisory (no asOf check), so an
  // advisory released 12 hours before asOf whose CVE appears 12 hours after asOf is
  // TIMELY and counts in high_impact_with_cve. At the analysis date no CVE existed.
  // (Quality metrics do exclude PUBLISHED_AFTER_AS_OF; timeliness does not.)
  it('DEFECT timeliness-future-cve-credited: a CVE published after asOf must not make an advisory timely', () => {
    const v = vendor('acme')
    const out = run(
      inputs({
        vendors: [v],
        cves: [record('CVE-2026-6001', { cna: 'acme-cna', datePublished: iso(Date.parse(AS_OF) + DAY / 2) })],
        advisories: [advisory('acme', 'ACME-SA-6', { cveIds: ['CVE-2026-6001'], publishedAt: iso(Date.parse(AS_OF) - DAY / 2) })],
      }),
    )
    expect(metricOf(out, 'acme', 'cve.timely_issuance').value).toBe(0)
    expect(metricOf(out, 'acme', 'cve.high_impact_with_cve').value).toBe(0)
  })

  // Defect: latency is rounded to 0.01 day BEFORE the tolerance comparison
  // (daysBetween -> round2). 1 day + 7 minutes = 1.00486 days rounds to 1.00 <= 1:
  // TIMELY although the CVE came after the tolerance. Compare on raw milliseconds.
  it('DEFECT timeliness-rounding-before-tolerance: 1 day + 7 minutes is beyond a 1-day tolerance', () => {
    const v = vendor('acme')
    const advMs = Date.parse(daysAgo(40))
    const out = run(
      inputs({
        vendors: [v],
        cves: [record('CVE-2026-7001', { cna: 'acme-cna', datePublished: iso(advMs + DAY + 7 * 60_000) })],
        advisories: [advisory('acme', 'ACME-SA-7', { cveIds: ['CVE-2026-7001'], publishedAt: iso(advMs) })],
      }),
    )
    expect(metricOf(out, 'acme', 'cve.timely_issuance').value).toBe(0)
  })

  it('handled: exactly 1 day after the advisory is within the 1-day tolerance', () => {
    const v = vendor('acme')
    const advMs = Date.parse(daysAgo(40))
    const out = run(
      inputs({
        vendors: [v],
        cves: [record('CVE-2026-7101', { cna: 'acme-cna', datePublished: iso(advMs + DAY) })],
        advisories: [advisory('acme', 'ACME-SA-71', { cveIds: ['CVE-2026-7101'], publishedAt: iso(advMs) })],
      }),
    )
    expect(metricOf(out, 'acme', 'cve.timely_issuance').value).toBe(100)
  })

  it('handled: timezone offsets are honoured (CVE public 3 hours before an advisory stamped in UTC-5)', () => {
    const v = vendor('acme')
    const out = run(
      inputs({
        vendors: [v],
        cves: [record('CVE-2026-7201', { cna: 'acme-cna', datePublished: '2026-08-02T01:00:00.000Z' })],
        advisories: [advisory('acme', 'ACME-SA-72', { cveIds: ['CVE-2026-7201'], publishedAt: '2026-08-01T23:00:00-05:00' })],
      }),
    )
    // -3 hours = -0.125 days (round2 gives -0.12: Math.round rounds half toward +Infinity)
    expect(metricOf(out, 'acme', 'cve.publication_latency').value).toBeCloseTo(-0.125, 1)
    expect(metricOf(out, 'acme', 'cve.timely_issuance').value).toBe(100)
  })
})

describe('G6 status rule', () => {
  // Defect (policy question, failing test): timely_issuance has minimum 0, so ONE timely
  // advisory gives 100% and G6 / CVE_TIMELINESS become VERIFIED. The C2.SAMPLE rule only
  // lowers confidence. Record metrics refuse to report below minimumEligibleRecords; the
  // advisory dimension carries a VERIFIED status from a sample of 1. The published demo
  // has this: basalt-infrastructure G6 VERIFIED on 4 advisories (< 5), and
  // CVE_TIMELINESS VERIFIED for wrenfield-software on 2 advisories.
  // Correct: below the minimum sample, timeliness may be shown but cannot make G6 VERIFIED.
  it('DEFECT g6-verified-below-advisory-sample: one advisory must not make G6 VERIFIED', () => {
    const v = vendor('acme')
    const cves = completeRecords(v, 6)
    const out = run(inputs({ vendors: [v], cves, advisories: [advisory('acme', 'ACME-SA-1', { cveIds: [cves[0]!.id], publishedAt: cves[0]!.datePublished! })] }))
    expect(metricOf(out, 'acme', 'cve.timely_issuance')).toMatchObject({ value: 100, denominator: 1, confidence: 'LOW' })
    expect(goalOf(out, 'acme', 'G6').status).not.toBe('VERIFIED')
    expect(dimOf(out, 'acme', 'CVE_TIMELINESS').status).not.toBe('VERIFIED')
  })

  // Defect (wording): when both dimensions are measured at 0% the reason reads
  // "Evidence supports part of the goal." Nothing supports it.
  it('DEFECT g6-partial-wording-at-zero: 0% complete and 0% timely must not say "Evidence supports part of the goal"', () => {
    const v = vendor('acme')
    const cves = Array.from({ length: 6 }, (_, i) => record(`CVE-2026-80${10 + i}`, { cna: 'acme-cna', cwes: [], cpes: [], publishedDaysAgo: 10 + i }))
    const out = run(inputs({ vendors: [v], cves, advisories: [advisory('acme', 'ACME-SA-8', { cveIds: ['CVE-2026-8010'], publishedDaysAgo: 200 })] }))
    expect(metricOf(out, 'acme', 'cve.complete_records').value).toBe(0)
    expect(metricOf(out, 'acme', 'cve.timely_issuance').value).toBe(0)
    expect(goalOf(out, 'acme', 'G6').statusReason).not.toMatch(/Evidence supports part of the goal/)
  })

  it('handled: 100% complete and no high-impact advisories is PARTIAL, not VERIFIED (no vacuous truth)', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], cves: completeRecords(v, 6), advisories: [advisory('acme', 'M1', { severity: 'MEDIUM' })] }))
    expect(metricOf(out, 'acme', 'cve.complete_records').value).toBe(100)
    expect(goalOf(out, 'acme', 'G6').status).toBe('PARTIAL')
  })
})
