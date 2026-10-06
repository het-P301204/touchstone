/**
 * Adversarial: attribution (packages/core/src/identity/index.ts), CVE normalization
 * (packages/core/src/normalize/cve.ts) and CNA-only crediting
 * (packages/core/src/measure/cve-quality.ts).
 */

import { describe, expect, it } from 'vitest'
import { attributeCves, detectIdentityConflicts, matchSignatories, normalizeName } from '../../packages/core/src/identity/index.ts'
import { normalizeCveRecord } from '../../packages/core/src/normalize/cve.ts'
import { alias, AS_OF, completeRecords, containerOf, cpeFor, inputs, metricOf, record, run, vendor, vr } from './helpers.ts'

const attr = (cves: Parameters<typeof attributeCves>[0], vendors: Parameters<typeof attributeCves>[1]) =>
  attributeCves(cves, vendors, detectIdentityConflicts(vendors))

function rawCve(id: string, o: { cna?: Record<string, unknown>; adp?: Record<string, unknown>[]; datePublished?: string; state?: string } = {}): Record<string, unknown> {
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: { cveId: id, assignerOrgId: '00000000-0000-4000-8000-000000000001', assignerShortName: 'acme-cna', state: o.state ?? 'PUBLISHED', datePublished: o.datePublished ?? '2026-05-01T10:00:00.000Z' },
    containers: {
      cna: { providerMetadata: { orgId: '00000000-0000-4000-8000-000000000001', shortName: 'acme-cna' }, affected: [{ vendor: 'Acme', product: 'Widget' }], ...(o.cna ?? {}) },
      ...(o.adp ? { adp: o.adp } : {}),
    },
  }
}

describe('attribution rules', () => {
  // Defect: rule 1 (ASSIGNER_IS_VENDOR_CNA) returns as soon as the assigner matches, and
  // never looks at affected[].vendor. When vendor A is the CNA of record for a product
  // that the record's structured fields name as vendor B's (B registered, with its own
  // AFFECTED_VENDOR alias and CPE namespace), the record is attributed to A with HIGH
  // confidence: it counts in A's denominators (as "CPE outside namespace") and is missing
  // from B's. The structured evidence points at two registered vendors; the contract's
  // rule is "ambiguity/conflict excludes rather than guesses".
  // Correct: AMBIGUOUS_VENDOR exclusion (or attribution to B), never a silent HIGH to A.
  it('DEFECT cna-of-record-for-other-vendor: assigner A + affected/CPE vendor B must not attribute silently to A', () => {
    const a = vendor('acme', { cna: 'acme-cna', cpeNs: 'acme' })
    const b = vendor('globex', { cna: null, cpeNs: 'globex', affected: 'Globex' })
    const r = record('CVE-2026-0101', { cna: 'acme-cna', affected: [{ vendor: 'Globex', product: 'Router' }], cpes: [cpeFor('globex', 'router')] })
    const res = attr([r], [a, b])
    const toA = res.attributions.find((x) => x.cveId === r.id && x.vendorId === 'acme')
    expect(toA).toBeUndefined()
  })

  it('handled: an affected[] naming two registered vendors is AMBIGUOUS_VENDOR, never split or first-match', () => {
    const a = vendor('summit-a', { cna: null, affected: 'Summit' })
    const b = vendor('summit-b', { cna: null, affected: 'Summit' })
    const res = attr([record('CVE-2026-0102', { affected: [{ vendor: 'SUMMIT ', product: 'x' }] })], [a, b])
    expect(res.attributions).toEqual([])
    expect(res.exclusions[0]).toMatchObject({ reason: 'AMBIGUOUS_VENDOR', candidateVendorIds: ['summit-a', 'summit-b'] })
  })

  it('handled: a CNA short name registered for two vendors is an IDENTITY_CONFLICT exclusion', () => {
    const a = vendor('acme', { cna: 'shared-cna' })
    const b = vendor('globex', { cna: 'Shared-CNA' })
    const res = attr([record('CVE-2026-0103', { cna: 'shared-cna' })], [a, b])
    expect(res.attributions).toEqual([])
    expect(res.exclusions[0]).toMatchObject({ reason: 'IDENTITY_CONFLICT' })
  })

  it('handled: case, whitespace and corporate suffix games match the same vendor', () => {
    expect(normalizeName('  ACME   Widgets, Inc. ')).toBe(normalizeName('Acme Widgets'))
    expect(normalizeName('Acme Widgets GmbH')).toBe('acme widgets')
    const v = vendor('acme', { cna: null, affected: 'Acme Widgets' })
    const res = attr([record('CVE-2026-0104', { affected: [{ vendor: 'ACME  widgets LLC', product: 'x' }] })], [v])
    expect(res.attributions[0]).toMatchObject({ vendorId: 'acme', rule: 'AFFECTED_VENDOR_ONLY', confidence: 'MEDIUM' })
  })

  it('handled: two vendors whose names differ only by suffix are a NAME_COLLISION, not a merge', () => {
    const a = vendor('acme-us', { extra: [alias('LEGAL_NAME', 'Acme Inc')] })
    const b = vendor('acme-de', { extra: [alias('LEGAL_NAME', 'Acme GmbH')] })
    expect(detectIdentityConflicts([a, b]).some((c) => c.kind === 'NAME_COLLISION' && c.value === 'acme')).toBe(true)
  })

  it('handled: a Cyrillic look-alike name does not attribute (excluded by non-match, not guessed)', () => {
    const v = vendor('acme', { cna: null, affected: 'Acme' })
    const res = attr([record('CVE-2026-0105', { affected: [{ vendor: 'Аcme', product: 'x' }] })], [v]) // first letter is U+0410
    expect(res.attributions).toEqual([])
  })

  it('handled: a title naming the vendor never attributes (FREE_TEXT_ONLY)', () => {
    const v = vendor('acme', { cna: null, affected: 'Acme Widgets' })
    const res = attr([record('CVE-2026-0106', { title: 'Overflow in Acme Widgets router', affected: [{ vendor: 'Unlisted Co', product: 'x' }] })], [v])
    expect(res.attributions).toEqual([])
    expect(res.exclusions[0]).toMatchObject({ reason: 'FREE_TEXT_ONLY' })
  })

  it('handled: REJECTED and conflicting duplicates are excluded; identical duplicates collapse to one', () => {
    const v = vendor('acme')
    const recs = [
      record('CVE-2026-0107', { cna: 'acme-cna', state: 'REJECTED' }),
      record('CVE-2026-0108', { cna: 'acme-cna', sourceHash: 'x1' }),
      record('CVE-2026-0108', { cna: 'acme-cna', sourceHash: 'x2' }),
      record('CVE-2026-0109', { cna: 'acme-cna', sourceHash: 'same' }),
      record('CVE-2026-0109', { cna: 'acme-cna', sourceHash: 'same' }),
    ]
    const res = attr(recs, [v])
    expect(res.exclusions.map((x) => `${x.cveId}:${x.reason}`).sort()).toEqual(['CVE-2026-0107:REJECTED_RECORD', 'CVE-2026-0108:DUPLICATE_CONFLICT'])
    expect(res.attributions.map((x) => x.cveId)).toEqual(['CVE-2026-0109'])
  })

  it('handled: a signer listing shared by two vendors is ambiguous, not matched', () => {
    const a = vendor('acme-a')
    const b = vendor('acme-b', { extra: [alias('SIGNATORY_LISTING', 'acme-a Holdings, Inc.')] })
    expect(matchSignatories(['ACME-A HOLDINGS'], [a, b]).ambiguous).toHaveLength(1)
  })
})

describe('CNA-only crediting', () => {
  it('handled: CWE and CPE supplied only by CISA-ADP are not credited and are reported as enriched_only', () => {
    const v = vendor('acme')
    const cves = Array.from({ length: 5 }, (_, i) =>
      record(`CVE-2026-020${i}`, { cna: 'acme-cna', cwes: [], cpes: [], adp: [containerOf('CISA-ADP', ['CWE-79'], [cpeFor('acme')])], publishedDaysAgo: 20 + i }),
    )
    const out = run(inputs({ vendors: [v], cves }))
    expect(metricOf(out, 'acme', 'cve.cwe_coverage').value).toBe(0)
    expect(metricOf(out, 'acme', 'cve.cpe_coverage').value).toBe(0)
    expect(metricOf(out, 'acme', 'cve.complete_records').value).toBe(0)
    expect(metricOf(out, 'acme', 'cve.enriched_only').value).toBe(100)
  })

  it('handled: an ADP container whose providerMetadata.shortName is "CNA" is still not credited', () => {
    const raw = rawCve('CVE-2026-0301', {
      cna: { problemTypes: [] },
      adp: [{ providerMetadata: { orgId: 'x', shortName: 'CNA' }, problemTypes: [{ descriptions: [{ lang: 'en', cweId: 'CWE-79', type: 'CWE', description: 'XSS' }] }], affected: [{ vendor: 'Acme', product: 'Widget', cpes: [cpeFor('acme')] }] }],
    })
    const n = normalizeCveRecord(raw, { snapshotId: 'SN-x', synthetic: false })
    expect(n.ok).toBe(true)
    if (!n.ok) return
    expect(n.record.cna.cwes).toEqual([])
    expect(n.record.cna.cpes).toEqual([])
    expect(n.record.adp[0]!.provider).toBe('CNA')
  })

  // Defect (wording): the spoofed ADP provider name flows into the enriched_only evidence
  // reading: "CWE supplied by CNA, CPE supplied by CNA; not credited to the vendor." The
  // reader is told the CNA supplied data that was not credited. ADP provider labels must
  // be distinguishable from the CNA (e.g. prefix "ADP:" or reject a reserved name).
  it('DEFECT adp-provider-named-cna-wording: evidence must not say a field was "supplied by CNA" when an ADP supplied it', () => {
    const v = vendor('acme')
    const cves = Array.from({ length: 5 }, (_, i) =>
      record(`CVE-2026-031${i}`, { cna: 'acme-cna', cwes: [], cpes: [], adp: [containerOf('CNA', ['CWE-79'], [cpeFor('acme')])], publishedDaysAgo: 20 + i }),
    )
    const out = run(inputs({ vendors: [v], cves }))
    expect(metricOf(out, 'acme', 'cve.cwe_coverage').value).toBe(0) // not credited (correct)
    const readings = out.evidence.filter((e) => e.metricId === 'cve.enriched_only').map((e) => e.reading)
    expect(readings.length).toBe(5)
    for (const r of readings) expect(r).not.toMatch(/supplied by CNA\b/)
  })

  it('handled: the same CPE in affected[].cpes and cpeApplicability is one CPE, and ADP cpeApplicability stays in ADP', () => {
    const c = cpeFor('acme')
    const raw = rawCve('CVE-2026-0302', {
      cna: { affected: [{ vendor: 'Acme', product: 'Widget', cpes: [c] }], cpeApplicability: [{ nodes: [{ operator: 'OR', cpeMatch: [{ vulnerable: true, criteria: c }] }] }] },
      adp: [{ providerMetadata: { shortName: 'CISA-ADP' }, cpeApplicability: [{ nodes: [{ cpeMatch: [{ criteria: cpeFor('acme', 'other') }] }] }] }],
    })
    const n = normalizeCveRecord(raw, { snapshotId: 'SN-x', synthetic: false })
    expect(n.ok && n.record.cna.cpes.map((x) => x.raw)).toEqual([c])
    expect(n.ok && n.record.adp[0]!.cpes.length).toBe(1)
  })

  it('handled: placeholder CWEs stop counting under 1.1.0 and count under 1.0.0', () => {
    const v = vendor('acme')
    const cves = completeRecords(v, 6).map((r, i) => (i < 3 ? { ...r, cna: containerOf('CNA', ['NVD-CWE-noinfo'], r.cna.cpes.map((p) => p.raw)) } : r))
    expect(metricOf(run(inputs({ vendors: [v], cves })), 'acme', 'cve.cwe_coverage').value).toBe(50)
    expect(metricOf(run(inputs({ vendors: [v], cves, methodologyVersion: '1.0.0' })), 'acme', 'cve.cwe_coverage').value).toBe(100)
  })
})

describe('eligibility and denominators', () => {
  it('handled: window boundary is (asOf - 730d, asOf]; future-dated records are excluded', () => {
    const v = vendor('acme')
    const ns = cpeFor('acme')
    const mk = (id: string, datePublished: string) => record(id, { cna: 'acme-cna', cpes: [ns], datePublished })
    const asOfMs = Date.parse(AS_OF)
    const cves = [
      mk('CVE-2026-0401', new Date(asOfMs - 730 * 86_400_000).toISOString()), // exactly 730 days: outside
      mk('CVE-2026-0402', new Date(asOfMs - 730 * 86_400_000 + 1000).toISOString()), // inside
      mk('CVE-2026-0403', AS_OF), // exactly asOf: inside
      mk('CVE-2026-0404', new Date(asOfMs + 1000).toISOString()), // after asOf: outside
      ...completeRecords(v, 4, 2000),
    ]
    const m = metricOf(run(inputs({ vendors: [v], cves })), 'acme', 'cve.cwe_coverage')
    expect(m.denominator).toBe(6)
    expect(m.breakdown).toBeDefined()
  })

  it('handled: excluded, rejected and duplicate records never enter a denominator', () => {
    const v = vendor('acme')
    const cves = [
      ...completeRecords(v, 5),
      record('CVE-2026-0501', { cna: 'acme-cna', state: 'REJECTED', cwes: [], cpes: [] }),
      record('CVE-2026-0502', { cna: 'acme-cna', sourceHash: 'p', cwes: [] }),
      record('CVE-2026-0502', { cna: 'acme-cna', sourceHash: 'q', cwes: [] }),
    ]
    const out = run(inputs({ vendors: [v], cves }))
    expect(metricOf(out, 'acme', 'cve.complete_records')).toMatchObject({ value: 100, denominator: 5 })
    expect(metricOf(out, 'acme', 'cve.duplicate_conflicts').value).toBe(1)
    expect(vr(out, 'acme').attributedCveIds).toHaveLength(5)
  })

  it('handled: below the minimum sample every record metric is null, never 0 or 100', () => {
    const v = vendor('acme')
    const out = run(inputs({ vendors: [v], cves: completeRecords(v, 4) }))
    for (const id of ['cve.cwe_coverage', 'cve.cpe_coverage', 'cve.complete_records', 'cve.cpe_namespace_consistency'])
      expect(metricOf(out, 'acme', id)).toMatchObject({ value: null, gap: 'BELOW_MINIMUM_SAMPLE' })
  })

  // Robustness: isoDate validates the shape with a regex, then Date.parse rolls an
  // impossible calendar date forward (2026-02-30 -> 2026-03-02). A malformed date is
  // silently replaced by a different, valid-looking one, which can move a record across
  // the eligibility window or change a latency. Correct: reject (no datePublished ->
  // NO_DATE_PUBLISHED eligibility gap).
  it('DEFECT isodate-calendar-rollover: datePublished "2026-02-30" must not normalize to 2026-03-02', () => {
    const n = normalizeCveRecord(rawCve('CVE-2026-0601', { datePublished: '2026-02-30T00:00:00Z' }), { snapshotId: 'SN-x', synthetic: false })
    expect(n.ok).toBe(true)
    if (n.ok) expect(n.record.datePublished).toBeUndefined()
  })

  it('handled: a record with no datePublished is excluded with NO_DATE_PUBLISHED, not counted', () => {
    const v = vendor('acme')
    const bare = record('CVE-2026-0602', { cna: 'acme-cna' })
    delete bare.datePublished
    const out = run(inputs({ vendors: [v], cves: [...completeRecords(v, 5), bare] }))
    expect(metricOf(out, 'acme', 'cve.complete_records').denominator).toBe(5)
    expect(metricOf(out, 'acme', 'cve.complete_records').breakdown?.['not_eligible.NO_DATE_PUBLISHED']).toBe(1)
  })
})
