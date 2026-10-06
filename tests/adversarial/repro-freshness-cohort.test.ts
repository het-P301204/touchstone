/**
 * Adversarial: reproducibility (run/run.ts, run/canonical.ts), freshness
 * (freshness/freshness.ts), cohort and anomalies (assess/cohort.ts,
 * assess/anomalies.ts) and the banned-wording gate (assess/language.ts).
 */

import { describe, expect, it } from 'vitest'
import { computeFreshness } from '../../packages/core/src/freshness/freshness.ts'
import { findBannedTerms } from '../../packages/core/src/assess/language.ts'
import { cohortSummaries, ALL_SIGNATORIES } from '../../packages/core/src/assess/cohort.ts'
import { BENCHMARK_METRIC_IDS, metricDefinition } from '../../packages/core/src/measure/definitions.ts'
import { METHODOLOGY_VERSIONS } from '../../packages/core/src/methodology/versions.ts'
import { reproduceRun } from '../../packages/core/src/run/run.ts'
import { canonicalJson } from '../../packages/core/src/run/canonical.ts'
import { sha256Text } from '../../packages/core/src/util/sha256.ts'
import type { RunInputs, SourceRef } from '../../packages/core/src/model/index.ts'
import {
  AS_OF,
  STRONG_POLICY,
  advisory,
  completeRecords,
  daysAgo,
  daysAfter,
  inputs,
  metricOf,
  params,
  record,
  reorder,
  run,
  snap,
  vdpFromText,
  vendor,
  vr,
} from './helpers.ts'

function cohort(): RunInputs {
  const vs = ['alpha', 'bravo', 'charlie', 'delta'].map((id, i) => vendor(id, { category: i % 2 ? 'CLOUD' : 'NETWORKING' }))
  const cves = vs.flatMap((v, i) => completeRecords(v, 6, 1000 + i * 100))
  const advs = vs.map((v, i) => advisory(v.id, `${v.id}-SA-1`, { cveIds: [cves[i * 6]!.id], publishedAt: cves[i * 6]!.datePublished! }))
  return inputs({ vendors: vs, cves, advisories: advs, vdp: vs.map((v) => vdpFromText(v.id, STRONG_POLICY)) })
}

describe('reproducibility', () => {
  it('handled: the same inputs in a different array order give the same outputsHash', () => {
    const a = cohort()
    const b: RunInputs = { ...a, vendors: reorder(a.vendors), cves: reorder(a.cves), advisories: reorder(a.advisories), vdp: reorder(a.vdp), snapshots: reorder(a.snapshots), sources: reorder(a.sources) }
    expect(run(b).manifest.outputsHash).toBe(run(a).manifest.outputsHash)
  })

  // Defect: inputsHash is sha256(canonicalJson(inputs)) over the arrays in the order the
  // loader produced them. canonicalJson sorts object keys, not arrays. The same snapshot
  // set read in a different directory order gives a different inputsHash and therefore a
  // different runId (TS-YYYY-MM-DD-XXXX), and reproduceRun reports "not reproduced" for a
  // byte-identical dataset. The contract defines inputsHash over snapshot ids + hashes +
  // methodology version. Correct: hash a canonical (sorted) projection of the inputs.
  it('DEFECT inputs-hash-order-dependent: reordering inputs must not change inputsHash / runId', () => {
    const a = cohort()
    const b: RunInputs = { ...a, cves: reorder(a.cves), snapshots: reorder(a.snapshots) }
    expect(run(b).manifest.inputsHash).toBe(run(a).manifest.inputsHash)
    expect(reproduceRun(b, run(a).manifest).reproduced).toBe(true)
  })

  // Defect: the registry's alias order is echoed into VendorResult.vendor and hashed, so
  // the same registry with aliases listed in another order changes outputsHash.
  it('DEFECT outputs-hash-alias-order: the same registry with reordered aliases must give the same outputsHash', () => {
    const a = cohort()
    const b: RunInputs = { ...a, vendors: a.vendors.map((v) => ({ ...v, aliases: reorder(v.aliases) })) }
    expect(run(b).manifest.outputsHash).toBe(run(a).manifest.outputsHash)
  })

  // Defect: executeRun takes inputs.vdp.find(o => o.vendorId === id): with two
  // observations for one vendor (e.g. a carried copy and a fresh one) the FIRST in input
  // order wins, so G5 flips with array order. Correct: a deterministic choice (latest
  // observedAt, then snapshot id) or a DATA_QUALITY flag; never order-dependent.
  it('DEFECT duplicate-vdp-observation-order: two observations for one vendor must not make G5 depend on input order', () => {
    const v = vendor('acme')
    const strong = vdpFromText('acme', STRONG_POLICY, { observedAt: daysAgo(0.2) })
    const weak = vdpFromText('acme', 'Please report issues to security@acme.example by email.', { observedAt: daysAgo(0.4) })
    const g5 = (vdp: typeof strong[]) => run(inputs({ vendors: [v], vdp })).vendors[0]!.goals.find((g) => g.goalId === 'G5')!.status
    expect(g5([weak, strong])).toBe(g5([strong, weak]))
  })

  // Methodology parameters are not part of inputsHash or outputsHash (only the version
  // string is). The comment in methodology/versions.ts says "tests/regression" pins each
  // version's output; that directory does not exist. This pin fails as soon as a
  // parameter changes without a new version entry.
  it('handled (pin): methodology parameters per version are frozen', () => {
    const fp = Object.fromEntries(METHODOLOGY_VERSIONS.map((m) => [m.version, sha256Text(canonicalJson(m.parameters)).slice(0, 16)]))
    expect(fp).toEqual(PINNED_PARAMETER_FINGERPRINTS)
  })

  // Defect (robustness): change a parameter in place (no version bump) and the manifest
  // cannot tell: same methodologyVersion, same inputsHash, same runId, different figures.
  // Correct: the manifest (inputsHash or a parametersHash) must cover the parameters.
  it('DEFECT parameters-not-hashed: a parameter change without a version bump must change the run identity', () => {
    const base = cohort()
    const before = run(base).manifest
    const m = METHODOLOGY_VERSIONS.find((x) => x.version === '1.1.0')!
    const saved = m.parameters
    try {
      m.parameters = { ...saved, timelinessToleranceDays: 0 }
      const after = run(base).manifest
      expect(after.outputsHash).not.toBe(before.outputsHash) // the figures did change
      expect(after.inputsHash === before.inputsHash && after.runId === before.runId).toBe(false)
    } finally {
      m.parameters = saved
    }
  })
})

// Re-pinned once, before the 0.1.0 release, when vdpMinimumPolicyWords and
// minimumHighImpactAdvisories were added to both versions in response to this
// suite. After release, any change here needs a new methodology version.
const PINNED_PARAMETER_FINGERPRINTS: Record<string, string> = {
  '1.0.0': 'd31ba6cfaf4abf2a',
  '1.1.0': 'b3c3ba55b9a12654',
}

describe('freshness', () => {
  const src: SourceRef = { id: 'vendor.acme.vdp', family: 'VENDOR_VDP', title: 'acme VDP', url: 'https://acme.example/vdp', publisher: 'acme', attribution: 'x', retention: 'EXTRACT_ONLY' }
  const other: SourceRef = { ...src, id: 'vendor.globex.vdp', title: 'globex VDP' }

  it('handled: a failed latest fetch is never CURRENT; age is the age of the snapshot used', () => {
    const f = computeFreshness([snap('S1', src.id, daysAgo(3)), snap('S2', src.id, daysAgo(0.1), 'FAILED', { substitutedBy: 'S1' })], [src], AS_OF, params())
    expect(f[0]).toMatchObject({ state: 'AGING', usedSnapshotId: 'S1', ageHours: 72, lastStatus: 'FAILED' })
  })
  it('handled: no successful snapshot -> UNKNOWN; a snapshot fetched after asOf is ignored', () => {
    const f = computeFreshness([snap('S1', src.id, daysAgo(1), 'FAILED'), snap('S2', src.id, daysAfter(1))], [src], AS_OF, params())
    expect(f[0]!.state).toBe('UNKNOWN')
  })

  // Defect (robustness): substitutedBy is trusted without checking that the substitute
  // belongs to the same source or existed at asOf. A failed fetch "substituted" by a
  // fresh snapshot of ANOTHER source reports that source's age (0.1 h), and a substitute
  // fetched after asOf reports age 0. Correct: ignore an invalid substitution (fall back
  // to the source's own last success, else UNKNOWN) and flag it.
  it('DEFECT freshness-substitution-not-validated: a substitute from another source must not supply the age', () => {
    const f = computeFreshness(
      [snap('S1', src.id, daysAgo(40)), snap('S2', src.id, daysAgo(0.05), 'FAILED', { substitutedBy: 'G1' }), snap('G1', other.id, daysAgo(0.01))],
      [src, other],
      AS_OF,
      params(),
    )
    const mine = f.find((x) => x.sourceId === src.id)!
    expect(mine.usedSnapshotId).toBe('S1')
    expect(mine.ageHours).toBe(960)
  })
  it('DEFECT freshness-substitution-not-validated: a substitute fetched after asOf must not supply the age', () => {
    const f = computeFreshness([snap('S1', src.id, daysAgo(40)), snap('S2', src.id, daysAgo(0.05), 'FAILED', { substitutedBy: 'S3' }), snap('S3', src.id, daysAfter(5))], [src], AS_OF, params())
    expect(f[0]!.usedSnapshotId).toBe('S1')
  })

  // Defect (robustness): for a per-record source (one snapshot per CVE record) the
  // "latest attempt" is whichever record happened to be fetched last. Identical
  // snapshot sets differing only in fetch order give CURRENT or AGING ("not refreshed").
  // The published demo shows it: cve.mirror is AGING in the 2026-04-06 run only (CURRENT in 2026-07-06 and 2026-10-06), because the
  // rejected legacy record was the last one fetched that quarter.
  it('DEFECT freshness-per-record-order: per-record source state must not depend on which record was fetched last', () => {
    const cve: SourceRef = { id: 'cve.mirror', family: 'CVE_PROGRAM', title: 'mirror', url: 'https://m.example/{id}', publisher: 'm', attribution: 'x', retention: 'RAW' }
    const t1 = daysAgo(0.3)
    const t2 = daysAgo(0.2)
    const okLast = computeFreshness([snap('R1', cve.id, t1, 'REJECTED'), snap('R2', cve.id, t2)], [cve], AS_OF, params())[0]!
    const badLast = computeFreshness([snap('R1', cve.id, t2, 'REJECTED'), snap('R2', cve.id, t1)], [cve], AS_OF, params())[0]!
    expect(badLast.state).toBe(okLast.state)
  })

  // Defect (robustness): a STALE security.txt never produces a DATA_QUALITY anomaly,
  // because anomalies only consider sources the vendor has evidence items from, and VDP
  // evidence is filed under the policy source. Demo: palisade-mobile's security.txt is
  // STALE in every run but only its vdp and csaf sources are flagged.
  it('DEFECT stale-security-txt-not-flagged: a STALE security.txt source must raise a DATA_QUALITY anomaly', () => {
    const v = vendor('acme')
    const base = inputs({ vendors: [v], vdp: [vdpFromText('acme', STRONG_POLICY)] })
    base.snapshots = base.snapshots.map((s) => (s.id === 'SN-stxt-acme' ? { ...s, fetchedAt: daysAgo(60) } : s))
    const out = run(base)
    expect(out.freshness.find((f) => f.sourceId === 'vendor.acme.security-txt')!.state).toBe('STALE')
    expect(vr(out, 'acme').anomalies.some((a) => a.kind === 'DATA_QUALITY' && a.headline.includes('vendor.acme.security-txt'))).toBe(true)
  })
})

describe('cohort and anomalies', () => {
  it('handled: vendors with null values do not enter medians as 0, and peer counts are reported', () => {
    const i = cohort()
    i.vendors.push(vendor('echo', { csaf: false }))
    i.vdp.push(vdpFromText('echo', undefined, { fetchFailed: true }))
    const out = run(i)
    const all = out.cohort.find((c) => c.peerGroup === ALL_SIGNATORIES)!
    expect(all.medians['cve.timely_issuance']).toBe(100)
    const b = vr(out, 'alpha').benchmarks.find((x) => x.metricId === 'cve.timely_issuance' && x.peerGroup === ALL_SIGNATORIES)!
    expect(b.peerCount).toBe(4)
  })
  it('handled: tiny cohorts are NOT_COMPARABLE and UNUSUAL never fires on an unknown value or below 10 peers', () => {
    const out = run(cohort())
    const b = vr(out, 'alpha').benchmarks.filter((x) => x.peerGroup === 'NETWORKING')
    expect(b.every((x) => x.position === 'NOT_COMPARABLE')).toBe(true)
    expect(out.vendors.flatMap((v) => v.anomalies).filter((a) => a.kind === 'UNUSUAL')).toEqual([])
  })
  it('handled: no raw count is benchmarked (vendor size never acts as a quality signal)', () => {
    for (const id of BENCHMARK_METRIC_IDS) expect(['PERCENT', 'DAYS']).toContain(metricDefinition(id)!.unit)
  })

  // Defect (wording): the cohort labelled ALL_SIGNATORIES contains every vendor in the
  // registry, including NOT_LISTED vendors (foxglove-identity in the 2025-10-06 demo run).
  // A non-signatory's figures shape the "signatory" medians it is compared with.
  it('DEFECT all-signatories-includes-non-signatories: NOT_LISTED vendors must not be counted in ALL_SIGNATORIES', () => {
    const i = cohort()
    i.vendors[0] = { ...i.vendors[0]!, signatoryStatus: 'NOT_LISTED' }
    const out = run(i)
    expect(out.cohort.find((c) => c.peerGroup === ALL_SIGNATORIES)!.vendorCount).toBe(3)
    expect(typeof cohortSummaries).toBe('function')
  })

  it('handled: a vendor with no CSAF feed is not placed relative to peers on timeliness', () => {
    const i = cohort()
    i.vendors.push(vendor('echo', { csaf: false }))
    const out = run(i)
    expect(vr(out, 'echo').rankingNotes['CVE_TIMELINESS']).toMatch(/not measured/)
    expect(metricOf(out, 'echo', 'cve.timely_issuance').value).toBeNull()
  })
})

describe('banned wording gate', () => {
  // Defect: findBannedTerms treats "-" as a word character, so "non-compliance",
  // "compliance-ready" and "insecure-by-default" are not caught, and "noncompliance",
  // "fail", "violated", "insecurely" are not in the list. The Q8 quality gate relies on
  // this scanner to keep judgement words out of status reasons, anomalies and notes.
  it.each(['Observed non-compliance with the pledge.', 'The vendor shows noncompliance.', 'A compliance-ready policy.', 'Insecure-by-default configuration.', 'The vendor violated the pledge.', 'Records fail the check.'])(
    'DEFECT banned-terms-gaps: %s must be flagged',
    (text) => {
      expect(findBannedTerms(text).length).toBeGreaterThan(0)
    },
  )
  it('handled: "Secure by Design" is allowed; "secure" and "compliant" are flagged', () => {
    expect(findBannedTerms('The Secure by Design Pledge')).toEqual([])
    expect(findBannedTerms('The vendor is compliant and secure.').sort()).toEqual(['compliant', 'secure'])
  })
  it('handled: generated status reasons, anomalies, benchmarks and notes in a mixed run carry no banned term', () => {
    const i = cohort()
    i.vendors.push(vendor('echo', { csaf: false }))
    i.vdp.push(vdpFromText('echo', 'You must not disclose any vulnerability. We reserve the right to pursue legal action. Testing requires prior written permission.'))
    i.cves.push(record('CVE-2026-9000', { cna: 'echo-cna', state: 'REJECTED' }))
    const out = run(i)
    const texts = out.vendors.flatMap((v) => [...v.goals.map((g) => g.statusReason), ...v.anomalies.flatMap((a) => [a.headline, a.detail]), ...v.benchmarks.map((b) => b.wording), ...Object.values(v.rankingNotes)])
    expect(texts.flatMap((t) => findBannedTerms(t))).toEqual([])
    expect(out.manifest.qualityChecks.find((q) => q.id === 'Q8')!.passed).toBe(true)
  })
})
