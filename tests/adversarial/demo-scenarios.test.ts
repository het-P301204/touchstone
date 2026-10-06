/**
 * Adversarial: the published demo bundle (apps/web/public/data, built by
 * `node scripts/build-demo.ts`) against fixtures/demo/SCENARIOS.md.
 *
 * Passing tests pin a scenario the bundle meets. Failing tests are published
 * outcomes that are wrong; each comment says whether the engine or the
 * expectation is at fault.
 */

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'

const root = fileURLToPath(new URL('../../apps/web/public/data/', import.meta.url))
const index = JSON.parse(readFileSync(join(root, 'index.json'), 'utf8')) as { runs: { runId: string; datasetVersion: string; methodologyVersion: string }[] }
type Any = any
const summaries = new Map<string, Any>(index.runs.map((r) => [r.datasetVersion, JSON.parse(readFileSync(join(root, 'runs', r.runId, 'summary.json'), 'utf8'))]))
const detail = (version: string, vendorId: string): Any => {
  const r = index.runs.find((x) => x.datasetVersion === version)!
  return JSON.parse(readFileSync(join(root, 'runs', r.runId, 'vendors', `${vendorId}.json`), 'utf8'))
}
const V = (version: string, id: string): Any => summaries.get(version).vendors.find((v: Any) => v.vendor.id === id)
const goal = (version: string, id: string, g: string): string => V(version, id).goals.find((x: Any) => x.goalId === g).status
const metric = (version: string, id: string, m: string): Any => V(version, id).goals.flatMap((g: Any) => g.metrics).find((x: Any) => x.metricId === m)
const crit = (version: string, id: string, c: string): Any => V(version, id).vdp.criteria.find((x: Any) => x.criterion === c)
const LATEST = '2026-10-06'
const VERSIONS = index.runs.map((r) => r.datasetVersion)

describe('demo scenarios that the bundle meets (pinned)', () => {
  it('northwind-systems: G5 VERIFIED 8/8, G6 VERIFIED at 100%, G3 PARTIAL with a falling share', () => {
    expect(goal(LATEST, 'northwind-systems', 'G5')).toBe('VERIFIED')
    expect(goal(LATEST, 'northwind-systems', 'G6')).toBe('VERIFIED')
    expect(metric(LATEST, 'northwind-systems', 'cve.complete_records').value).toBe(100)
    expect(goal(LATEST, 'northwind-systems', 'G3')).toBe('PARTIAL')
    expect(metric(LATEST, 'northwind-systems', 'g3.class_share_trend').value).toBeLessThan(0)
  })
  it('lanternfish-security: CWE coverage drops at the 1.1.0 boundary; 1.0.0 runs keep their figures', () => {
    expect(metric('2026-04-06', 'lanternfish-security', 'cve.cwe_coverage').value).toBeGreaterThan(90)
    expect(metric('2026-07-06', 'lanternfish-security', 'cve.cwe_coverage').value).toBeLessThan(60)
    expect(metric('2026-07-06', 'lanternfish-security', 'cve.cwe_coverage').breakdown['gap.PLACEHOLDER']).toBeGreaterThan(0)
  })
  it('quillmark-labs: 3 duplicate conflicts excluded', () => {
    expect(metric(LATEST, 'quillmark-labs', 'cve.duplicate_conflicts').value).toBe(3)
  })
  it('kestrel/ferrous: CPE_NAMESPACE_SHARED conflict; Kestrel record quality below sample', () => {
    expect(summaries.get(LATEST).identityConflicts.some((c: Any) => c.kind === 'CPE_NAMESPACE_SHARED' && c.value === 'kestrel')).toBe(true)
    expect(metric(LATEST, 'kestrel-controls', 'cve.complete_records').gap).toBe('BELOW_MINIMUM_SAMPLE')
  })
  it('copperleaf-learning: CURRENT MET until 2026-01-06, NOT_MET (EXPIRED) from 2026-04-06; timeliness not measured', () => {
    expect(crit('2026-01-06', 'copperleaf-learning', 'CURRENT').state).toBe('MET')
    for (const v of ['2026-04-06', '2026-07-06', '2026-10-06']) expect(crit(v, 'copperleaf-learning', 'CURRENT')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.CURRENT.EXPIRED' })
    expect(metric(LATEST, 'copperleaf-learning', 'cve.timely_issuance')).toMatchObject({ value: null, gap: 'NO_SOURCE' })
  })
  it('tessellate-data: G5 PARTIAL, safe harbor NOT_MET by VDP.NO_MATCH, 3/4 elements', () => {
    expect(goal(LATEST, 'tessellate-data', 'G5')).toBe('PARTIAL')
    expect(crit(LATEST, 'tessellate-data', 'GOOD_FAITH_SAFE_HARBOR')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.NO_MATCH' })
    expect(metric(LATEST, 'tessellate-data', 'vdp.pledge_elements_met').value).toBe(3)
  })
  it('gravelpoint-civic: three CONTRADICTED elements each with a ProhibitiveFinding; reporting channel MET', () => {
    for (const c of ['TESTING_AUTHORIZED', 'GOOD_FAITH_SAFE_HARBOR', 'PUBLIC_DISCLOSURE_ALLOWED']) {
      expect(crit(LATEST, 'gravelpoint-civic', c).state).toBe('CONTRADICTED')
      expect(V(LATEST, 'gravelpoint-civic').vdp.prohibitive.some((p: Any) => p.againstCriterion === c)).toBe(true)
    }
    expect(crit(LATEST, 'gravelpoint-civic', 'REPORTING_CHANNEL').state).toBe('MET')
    expect(['PARTIAL', 'NOT_VERIFIED']).toContain(goal(LATEST, 'gravelpoint-civic', 'G5'))
  })
  it('orchard-lane-robotics: every VDP criterion NOT_MET (not UNKNOWN), G5 NOT_VERIFIED', () => {
    expect(V(LATEST, 'orchard-lane-robotics').vdp.criteria.every((c: Any) => c.state === 'NOT_MET')).toBe(true)
    expect(goal(LATEST, 'orchard-lane-robotics', 'G5')).toBe('NOT_VERIFIED')
  })
  it('saltmarsh-software: timeliness not measurable, CURRENT NOT_MET by POLICY_OLD', () => {
    expect(metric(LATEST, 'saltmarsh-software', 'cve.timely_issuance').value).toBeNull()
    expect(crit(LATEST, 'saltmarsh-software', 'CURRENT')).toMatchObject({ state: 'NOT_MET', ruleId: 'VDP.CURRENT.POLICY_OLD' })
  })
  it('ember-oak-devices: 2026-07-06 change TESTING and SCOPE MET -> PARTIAL, review recommended', () => {
    const ch = V('2026-07-06', 'ember-oak-devices').vdpChanges[0]
    expect(ch).toMatchObject({ textChanged: true, reviewRecommended: true })
    expect(ch.criteria.map((c: Any) => `${c.criterion}:${c.before}->${c.after}`).sort()).toEqual(['SCOPE_DEFINED:MET->PARTIAL', 'TESTING_AUTHORIZED:MET->PARTIAL'])
  })
  it('palisade-mobile: VDP, security.txt and CSAF sources STALE in the freshness table', () => {
    for (const v of VERSIONS)
      for (const s of ['vdp', 'security-txt', 'csaf']) expect(summaries.get(v).freshness.find((f: Any) => f.sourceId === `vendor.palisade-mobile.${s}`).state).toBe('STALE')
  })
  it('wrenfield-software: 2026-10-06 policy FAILED with substitutedBy, observation carried, criteria unchanged, never CURRENT', () => {
    const f = summaries.get(LATEST).freshness.find((x: Any) => x.sourceId === 'vendor.wrenfield-software.vdp')
    expect(f.lastStatus).toBe('FAILED')
    expect(['AGING', 'STALE']).toContain(f.state)
    expect(V(LATEST, 'wrenfield-software').vdp.carriedFromSnapshotId).toBeTruthy()
    expect(V(LATEST, 'wrenfield-software').vdp.criteria.map((c: Any) => c.state)).toEqual(V('2026-07-06', 'wrenfield-software').vdp.criteria.map((c: Any) => c.state))
  })
  it('tinderbox-studio: CVE metrics null BELOW_MINIMUM_SAMPLE (never 0 or 100)', () => {
    for (const v of VERSIONS) for (const m of ['cve.cwe_coverage', 'cve.complete_records']) expect(metric(v, 'tinderbox-studio', m)).toMatchObject({ value: null, gap: 'BELOW_MINIMUM_SAMPLE' })
  })
  it('larkspur-cloud: CNA-only coverage low, enriched_only high', () => {
    expect(metric(LATEST, 'larkspur-cloud', 'cve.cwe_coverage').value).toBeLessThan(25)
    expect(metric(LATEST, 'larkspur-cloud', 'cve.enriched_only').value).toBeGreaterThan(50)
  })
  it('foxglove-identity: NOT_LISTED in 2025-10-06, LISTED afterwards', () => {
    expect(V('2025-10-06', 'foxglove-identity').vendor.signatoryStatus).toBe('NOT_LISTED')
    for (const v of VERSIONS.slice(1)) expect(V(v, 'foxglove-identity').vendor.signatoryStatus).toBe('LISTED')
  })
  it('basalt-infrastructure: discoverable via security.txt Policy:, host is the platform, G5 VERIFIED', () => {
    expect(crit(LATEST, 'basalt-infrastructure', 'POLICY_DISCOVERABLE')).toMatchObject({ state: 'MET', ruleId: 'VDP.DISCOVERABLE.STXT' })
    expect(V(LATEST, 'basalt-infrastructure').vdp.policy.host).toBe('disclosure-platform.example')
    expect(goal(LATEST, 'basalt-infrastructure', 'G5')).toBe('VERIFIED')
  })
  it('signer list 2026-01-06: declared 63, parsed 62, both published', () => {
    expect(summaries.get('2026-01-06').signatoryList).toMatchObject({ declaredCount: 63, parsedCount: 62 })
  })
  it('every run passes its own quality gate', () => {
    for (const v of VERSIONS) for (const q of summaries.get(v).manifest.qualityChecks) expect(q.passed, `${v} ${q.id}`).toBe(true)
  })
})

describe('demo outcomes that are wrong', () => {
  // ENGINE defect (see timeliness.test.ts advisory-cve-duplicate-conflict-read-as-absent).
  // quillmark-labs' advisories list DEMO-2024-1168 and DEMO-2025-1124. Both records ARE in
  // the snapshot (twice, with conflicting content), yet the published evidence reads
  // "not present as a published record in the snapshot", high_impact_with_cve is 80%,
  // and an UNUSUAL anomaly ("below the cohort's 10th percentile") is published.
  it('DEMO quillmark-dup-conflict-read-as-absent: no evidence may say a duplicate-conflict CVE is "not present"', () => {
    const d = detail(LATEST, 'quillmark-labs')
    const dupIds = new Set(d.exclusions.filter((x: Any) => x.reason === 'DUPLICATE_CONFLICT').map((x: Any) => x.cveId))
    const wrong = d.evidence.filter((e: Any) => e.metricId === 'cve.high_impact_with_cve' && (e.extracted.missingCves as string[]).some((id) => dupIds.has(id)))
    expect(wrong.map((e: Any) => e.reading)).toEqual([])
  })

  // ENGINE defect (see timeliness.test.ts g6-verified-below-advisory-sample).
  // basalt-infrastructure is G6 VERIFIED on 4 high-impact advisories, below
  // minimumEligibleRecords (5); timely_issuance carries confidence LOW (C2.SAMPLE).
  it('DEMO basalt-g6-verified-below-sample: G6 must not be VERIFIED when timeliness rests on fewer advisories than the minimum', () => {
    const t = metric(LATEST, 'basalt-infrastructure', 'cve.timely_issuance')
    expect(t.denominator).toBeLessThan(5)
    expect(goal(LATEST, 'basalt-infrastructure', 'G6')).not.toBe('VERIFIED')
  })

  // ENGINE defect (see repro-freshness-cohort.test.ts stale-security-txt-not-flagged).
  it('DEMO palisade-stale-security-txt-not-flagged: the STALE security.txt must appear as a DATA_QUALITY anomaly', () => {
    expect(V(LATEST, 'palisade-mobile').anomalies.some((a: Any) => a.headline.includes('vendor.palisade-mobile.security-txt'))).toBe(true)
  })

  // ENGINE defect (see repro-freshness-cohort.test.ts freshness-per-record-order).
  // One legacy record rejected by the normalizer makes the whole cve.mirror source
  // "not refreshed" (AGING) in 2026-04-06, but not in the later runs that contain the
  // same rejected record, because there it was not the last record fetched.
  it('DEMO cve-mirror-freshness-order: cve.mirror freshness must not flip on which record was fetched last', () => {
    const states = ['2026-04-06', '2026-07-06', '2026-10-06'].map((v) => summaries.get(v).freshness.find((f: Any) => f.sourceId === 'cve.mirror').state)
    expect(new Set(states).size).toBe(1)
  })

  // EXPECTATION drift (generator, not engine): brightwater-networks "CPE coverage about
  // 35%" - the generator drew CPEs for 9 of 36 records (25%); published 20.8-29.2% across
  // runs. The engine counts correctly (verified against the raw records). Tolerance here
  // is +/-10 points, so this pins the drift rather than failing on it.
  it('expectation drift (generator): brightwater CPE coverage is 20-30%, below the stated "about 35%"', () => {
    for (const v of VERSIONS) {
      const x = metric(v, 'brightwater-networks', 'cve.cpe_coverage').value
      expect(x).toBeGreaterThanOrEqual(20)
      expect(x).toBeLessThanOrEqual(30)
    }
  })
})
