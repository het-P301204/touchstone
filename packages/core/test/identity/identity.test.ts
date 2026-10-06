import { describe, expect, it } from 'vitest'
import type { Alias, AliasKind, CveRecord, Vendor } from '../../src/model/index.ts'
import { attributeCves, detectIdentityConflicts, matchSignatories, normalizeName } from '../../src/identity/index.ts'
import { parseCpe23 } from '../../src/normalize/cve.ts'

const alias = (kind: AliasKind, value: string): Alias => ({ kind, value, confidence: 'HIGH', evidence: [{ statement: 'test' }] })

function vendor(id: string, aliases: [AliasKind, string][]): Vendor {
  return { id, canonicalName: id, aliases: aliases.map(([k, v]) => alias(k, v)), signatoryStatus: 'UNKNOWN', category: 'OTHER', domains: [], claims: [], synthetic: true }
}

function cve(id: string, over: Partial<CveRecord> & { cpes?: string[] } = {}): CveRecord {
  const { cpes, ...rest } = over
  return {
    id,
    state: 'PUBLISHED',
    assigner: { orgId: 'org-third', shortName: 'thirdparty' },
    affected: [],
    cna: { provider: 'CNA', cwes: [], cpes: (cpes ?? []).map(parseCpe23), cvss: [] },
    adp: [],
    dataVersion: '5.1',
    snapshotId: 'SN-1',
    sourceHash: `hash-${id}`,
    synthetic: true,
    ...rest,
  }
}

const northwind = vendor('northwind', [
  ['LEGAL_NAME', 'Northwind Systems, Inc.'],
  ['BRAND', 'Northwind Systems'],
  ['SIGNATORY_LISTING', 'Northwind Systems'],
  ['CNA_SHORT_NAME', 'northwind'],
  ['CNA_ORG_ID', 'ORG-NW'],
  ['AFFECTED_VENDOR', 'Northwind Systems'],
  ['CPE_VENDOR', 'northwind'],
])
const halcyon = vendor('halcyon', [
  ['LEGAL_NAME', 'Halcyon Cloud LLC'],
  ['SIGNATORY_LISTING', 'Halcyon Cloud'],
  ['AFFECTED_VENDOR', 'Halcyon Cloud'],
  ['AFFECTED_VENDOR', 'Summit'],
  ['CPE_VENDOR', 'halcyon'],
])
const summit = vendor('summit', [
  ['LEGAL_NAME', 'Summit Analytics Corp.'],
  ['AFFECTED_VENDOR', 'Summit Analytics'],
  ['AFFECTED_VENDOR', 'Summit'],
  ['CPE_VENDOR', 'summit_analytics'],
])
const ferrous = vendor('ferrous', [
  ['LEGAL_NAME', 'Ferrous Industrial AG'],
  ['CNA_SHORT_NAME', 'ferrous'],
  ['AFFECTED_VENDOR', 'Ferrous Industrial'],
  ['CPE_VENDOR', 'ferrous'],
  ['CPE_VENDOR', 'kestrel'],
])
const kestrel = vendor('kestrel', [
  ['LEGAL_NAME', 'Kestrel Controls, Inc.'],
  ['AFFECTED_VENDOR', 'Kestrel Controls'],
  ['CPE_VENDOR', 'kestrel'],
])
const vendors = [northwind, halcyon, summit, ferrous, kestrel]

describe('normalizeName', () => {
  it('case-folds, trims, collapses spaces and strips corporate suffixes', () => {
    expect(normalizeName('  Northwind   Systems, Inc. ')).toBe('northwind systems')
    expect(normalizeName('Halcyon Cloud LLC')).toBe('halcyon cloud')
    expect(normalizeName('Ferrous Industrial AG')).toBe('ferrous industrial')
    expect(normalizeName('Acme Corp.')).toBe('acme')
    expect(normalizeName('Acme Holdings Corporation')).toBe('acme holdings')
    expect(normalizeName('Quillmark Labs GmbH')).toBe('quillmark labs')
    expect(normalizeName('Acme Ltd, Inc.')).toBe('acme')
  })
  it('never reduces a name to nothing and does not strip suffix-like words inside a name', () => {
    expect(normalizeName('AG')).toBe('ag')
    expect(normalizeName('Incline Systems')).toBe('incline systems')
    expect(normalizeName('Corpus Data')).toBe('corpus data')
  })
  it('removes invisible characters', () => {
    expect(normalizeName(`North${String.fromCodePoint(0x200b)}wind`)).toBe('northwind')
  })
})

describe('detectIdentityConflicts', () => {
  it('reports a CPE namespace shared after an acquisition', () => {
    const c = detectIdentityConflicts(vendors)
    expect(c).toHaveLength(1)
    expect(c[0]).toMatchObject({ kind: 'CPE_NAMESPACE_SHARED', value: 'kestrel', aliasKind: 'CPE_VENDOR', vendorIds: ['ferrous', 'kestrel'] })
    expect(c[0]!.id).toMatch(/^IC-[0-9a-f]{12}$/)
  })
  it('reports name collisions across name kinds after normalization, and shared CNAs', () => {
    const a = vendor('a', [['LEGAL_NAME', 'Acme Corp'], ['CNA_SHORT_NAME', 'ACME']])
    const b = vendor('b', [['BRAND', 'acme'], ['CNA_SHORT_NAME', 'acme ']])
    const kinds = detectIdentityConflicts([a, b]).map((c) => c.kind).sort()
    expect(kinds).toEqual(['CNA_SHARED', 'NAME_COLLISION'])
  })
  it('does not treat a shared AFFECTED_VENDOR name as an identity conflict', () => {
    expect(detectIdentityConflicts([halcyon, summit])).toEqual([])
  })
  it('is order-independent', () => {
    expect(detectIdentityConflicts([...vendors].reverse())).toEqual(detectIdentityConflicts(vendors))
  })
})

describe('attributeCves', () => {
  const conflicts = detectIdentityConflicts(vendors)

  it('ASSIGNER_IS_VENDOR_CNA: resolves the CNA short name or org id to the canonical vendor (HIGH)', () => {
    const { attributions, exclusions } = attributeCves(
      [cve('CVE-2026-0001', { assigner: { orgId: 'org-nw', shortName: 'Northwind' } }), cve('CVE-2026-0002', { assigner: { orgId: 'ORG-NW', shortName: 'renamed' } })],
      vendors,
      conflicts,
    )
    expect(exclusions).toEqual([])
    expect(attributions.map((a) => [a.cveId, a.vendorId, a.rule, a.confidence])).toEqual([
      ['CVE-2026-0001', 'northwind', 'ASSIGNER_IS_VENDOR_CNA', 'HIGH'],
      ['CVE-2026-0002', 'northwind', 'ASSIGNER_IS_VENDOR_CNA', 'HIGH'],
    ])
  })

  it('AFFECTED_VENDOR_AND_CPE (HIGH) when a CNA CPE uses the vendor namespace; AFFECTED_VENDOR_ONLY (MEDIUM) otherwise', () => {
    const { attributions } = attributeCves(
      [
        cve('CVE-2026-0010', { affected: [{ vendor: 'HALCYON CLOUD', product: 'Compute' }], cpes: ['cpe:2.3:a:halcyon:compute:1.0:*:*:*:*:*:*:*'] }),
        cve('CVE-2026-0011', { affected: [{ vendor: 'Halcyon Cloud', product: 'Compute' }], cpes: ['cpe:2.3:a:other_ns:compute:1.0:*:*:*:*:*:*:*'] }),
        cve('CVE-2026-0012', { affected: [{ vendor: 'Halcyon Cloud', product: 'Compute' }], cpes: ['cpe:/a:halcyon:compute:1.0'] }),
      ],
      vendors,
      conflicts,
    )
    expect(attributions.map((a) => [a.cveId, a.rule, a.confidence])).toEqual([
      ['CVE-2026-0010', 'AFFECTED_VENDOR_AND_CPE', 'HIGH'],
      ['CVE-2026-0011', 'AFFECTED_VENDOR_ONLY', 'MEDIUM'],
      ['CVE-2026-0012', 'AFFECTED_VENDOR_ONLY', 'MEDIUM'],
    ])
    expect(attributions[0]!.matched).toEqual([
      { kind: 'AFFECTED_VENDOR', value: 'HALCYON CLOUD' },
      { kind: 'CPE_VENDOR', value: 'halcyon' },
    ])
  })

  it('never attributes from free text; a title mention is reported as FREE_TEXT_ONLY', () => {
    const { attributions, exclusions } = attributeCves(
      [
        cve('CVE-2026-0020', { title: 'Plugin for Northwind Systems Ledger leaks tokens', affected: [{ vendor: 'Unlisted Widgets', product: 'Bridge' }], cpes: ['cpe:2.3:a:northwind:ledger:1:*:*:*:*:*:*:*'] }),
        cve('CVE-2026-0021', { title: 'Northwindsystems unrelated' }),
      ],
      vendors,
      conflicts,
    )
    expect(attributions).toEqual([])
    expect(exclusions).toEqual([expect.objectContaining({ cveId: 'CVE-2026-0020', reason: 'FREE_TEXT_ONLY', candidateVendorIds: ['northwind'] })])
  })

  it('AMBIGUOUS_VENDOR when an affected name fits more than one vendor', () => {
    const { attributions, exclusions } = attributeCves([cve('CVE-2026-0030', { affected: [{ vendor: 'Summit', product: 'Connector' }] })], vendors, conflicts)
    expect(attributions).toEqual([])
    expect(exclusions[0]).toMatchObject({ reason: 'AMBIGUOUS_VENDOR', candidateVendorIds: ['halcyon', 'summit'] })
  })

  it('AMBIGUOUS_VENDOR when one record names two different registered vendors', () => {
    const { exclusions } = attributeCves([cve('CVE-2026-0031', { affected: [{ vendor: 'Halcyon Cloud', product: 'x' }, { vendor: 'Kestrel Controls', product: 'y' }] })], vendors, conflicts)
    expect(exclusions[0]).toMatchObject({ reason: 'AMBIGUOUS_VENDOR', candidateVendorIds: ['halcyon', 'kestrel'] })
  })

  it('IDENTITY_CONFLICT when attribution depends on a conflicted alias; CNA attribution is unaffected', () => {
    const { attributions, exclusions } = attributeCves(
      [
        cve('CVE-2026-0040', { affected: [{ vendor: 'Kestrel Controls', product: 'RTU' }], cpes: ['cpe:2.3:o:kestrel:rtu:1.0:*:*:*:*:*:*:*'] }),
        cve('CVE-2026-0041', { affected: [{ vendor: 'Kestrel Controls', product: 'RTU' }] }),
        cve('CVE-2026-0042', { assigner: { orgId: 'x', shortName: 'ferrous' }, cpes: ['cpe:2.3:o:kestrel:rtu:1.0:*:*:*:*:*:*:*'] }),
      ],
      vendors,
      conflicts,
    )
    expect(exclusions).toEqual([expect.objectContaining({ cveId: 'CVE-2026-0040', reason: 'IDENTITY_CONFLICT', candidateVendorIds: ['ferrous', 'kestrel'] })])
    expect(attributions.map((a) => [a.cveId, a.vendorId, a.rule])).toEqual([
      ['CVE-2026-0041', 'kestrel', 'AFFECTED_VENDOR_ONLY'],
      ['CVE-2026-0042', 'ferrous', 'ASSIGNER_IS_VENDOR_CNA'],
    ])
  })

  it('REJECTED records are excluded', () => {
    const { attributions, exclusions } = attributeCves([cve('CVE-2026-0050', { state: 'REJECTED', assigner: { orgId: 'ORG-NW', shortName: 'northwind' } })], vendors, conflicts)
    expect(attributions).toEqual([])
    expect(exclusions[0]).toMatchObject({ reason: 'REJECTED_RECORD', candidateVendorIds: ['northwind'] })
  })

  it('DUPLICATE_CONFLICT excludes every copy when content differs; identical copies collapse', () => {
    const nw = { assigner: { orgId: 'ORG-NW', shortName: 'northwind' } }
    const { attributions, exclusions } = attributeCves(
      [
        cve('CVE-2026-0060', { ...nw, sourceHash: 'h1' }),
        cve('CVE-2026-0060', { ...nw, sourceHash: 'h2' }),
        cve('CVE-2026-0061', { ...nw, sourceHash: 'same' }),
        cve('CVE-2026-0061', { ...nw, sourceHash: 'same' }),
      ],
      vendors,
      conflicts,
    )
    expect(exclusions).toEqual([expect.objectContaining({ cveId: 'CVE-2026-0060', reason: 'DUPLICATE_CONFLICT', candidateVendorIds: ['northwind'] })])
    expect(attributions.map((a) => a.cveId)).toEqual(['CVE-2026-0061'])
  })

  it('records with no matching alias produce neither an attribution nor an exclusion', () => {
    expect(attributeCves([cve('CVE-2026-0070', { affected: [{ vendor: 'Nobody', product: 'x' }] })], vendors, conflicts)).toEqual({ attributions: [], exclusions: [] })
  })

  it('output is independent of input order', () => {
    const recs = [
      cve('CVE-2026-0002', { assigner: { orgId: 'ORG-NW', shortName: 'northwind' } }),
      cve('CVE-2026-0001', { affected: [{ vendor: 'Summit', product: 'x' }] }),
      cve('CVE-2026-0003', { affected: [{ vendor: 'Halcyon Cloud', product: 'x' }] }),
    ]
    expect(attributeCves([...recs].reverse(), vendors, conflicts)).toEqual(attributeCves(recs, vendors, conflicts))
  })
})

describe('matchSignatories', () => {
  it('matches SIGNATORY_LISTING aliases exactly after normalization', () => {
    const r = matchSignatories(['Northwind Systems', 'HALCYON CLOUD, INC.', 'Northwind', 'Unknown Co'], vendors)
    expect(r.matched).toEqual([
      { vendorId: 'northwind', listedName: 'Northwind Systems' },
      { vendorId: 'halcyon', listedName: 'HALCYON CLOUD, INC.' },
    ])
    expect(r.unmatchedNames).toEqual(['Northwind', 'Unknown Co'])
    expect(r.ambiguous).toEqual([])
  })
  it('reports a listing that fits two vendors as ambiguous, never picking one', () => {
    const a = vendor('a', [['SIGNATORY_LISTING', 'Twin Co']])
    const b = vendor('b', [['SIGNATORY_LISTING', 'Twin Co.']])
    expect(matchSignatories(['Twin Co'], [a, b]).ambiguous).toEqual([{ listedName: 'Twin Co', vendorIds: ['a', 'b'] }])
  })
})

describe('assigner vs structured evidence', () => {
  const acme = vendor('acme', [['CNA_SHORT_NAME', 'acme-cna'], ['CPE_VENDOR', 'acme'], ['AFFECTED_VENDOR', 'Acme']])
  const globex = vendor('globex', [['CPE_VENDOR', 'globex'], ['AFFECTED_VENDOR', 'Globex']])
  const both = [acme, globex]
  const assigned = (over: Partial<CveRecord> & { cpes?: string[] }) => cve('CVE-2026-0900', { assigner: { orgId: 'x', shortName: 'acme-cna' }, ...over })
  it('excludes as AMBIGUOUS_VENDOR when affected/CPE data names another registered vendor and not the assigner', () => {
    const { attributions, exclusions } = attributeCves([assigned({ affected: [{ vendor: 'Globex', product: 'Router' }], cpes: ['cpe:2.3:a:globex:router:1:*:*:*:*:*:*:*'] })], both, [])
    expect(attributions).toEqual([])
    expect(exclusions[0]).toMatchObject({ reason: 'AMBIGUOUS_VENDOR', candidateVendorIds: ['acme', 'globex'] })
  })
  it('keeps the assigner rule when the structured data names the assigner or no registered vendor', () => {
    expect(attributeCves([assigned({ affected: [{ vendor: 'Acme', product: 'x' }] })], both, []).attributions[0]!.vendorId).toBe('acme')
    expect(attributeCves([assigned({ affected: [{ vendor: 'Nobody', product: 'x' }] })], both, []).attributions[0]!.vendorId).toBe('acme')
    expect(attributeCves([assigned({ affected: [{ vendor: 'Acme', product: 'x' }, { vendor: 'Globex', product: 'y' }] })], both, []).attributions[0]!.vendorId).toBe('acme')
  })
})
