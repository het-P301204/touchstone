/**
 * Hand-built RunInputs fixtures for the scoring tests. Every vendor is
 * fictional, every URL uses the reserved .example TLD, and every value is
 * chosen so the expected figures can be worked out by hand (the tests state
 * the arithmetic next to each expectation).
 */

import type {
  Advisory,
  Alias,
  AliasKind,
  Attribution,
  ContainerData,
  CpeRef,
  CriterionState,
  CveRecord,
  CweRef,
  RunInputs,
  Snapshot,
  SourceRef,
  VdpCriterionId,
  VdpObservation,
  Vendor,
  VendorCategory,
} from '../../src/model/index.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { EvidenceLedger } from '../../src/evidence/ledger.ts'
import { computeFreshness } from '../../src/freshness/freshness.ts'
import type { MeasureContext } from '../../src/measure/context.ts'

export const AS_OF = '2026-10-06T00:00:00.000Z'

/** ISO timestamp `days` before AS_OF (fractional days allowed). */
export function daysAgo(days: number, from = AS_OF): string {
  return new Date(Date.parse(from) - days * 86_400_000).toISOString()
}

export function cweRef(raw: string): CweRef {
  if (/^CWE-\d+$/.test(raw)) return { raw, id: raw, placeholder: false }
  if (raw === 'NVD-CWE-noinfo' || raw === 'NVD-CWE-Other') return { raw, id: null, placeholder: true }
  return { raw, id: null, placeholder: false }
}

export function cpeRef(raw: string): CpeRef {
  const parts = raw.split(':')
  if (parts.length === 13 && parts[0] === 'cpe' && parts[1] === '2.3' && ['a', 'o', 'h'].includes(parts[2]!) && parts[3] && parts[4]) {
    return { raw, part: parts[2] as 'a' | 'o' | 'h', vendor: parts[3], product: parts[4], wellFormed: true }
  }
  return { raw, wellFormed: false }
}

export const cpe = (vendor: string, product = 'product'): string => `cpe:2.3:a:${vendor}:${product}:1.0:*:*:*:*:*:*:*`

export function container(provider: string, cwes: string[] = [], cpes: string[] = []): ContainerData {
  return { provider, cwes: cwes.map(cweRef), cpes: cpes.map(cpeRef), cvss: [] }
}

function alias(kind: AliasKind, value: string): Alias {
  return { kind, value, confidence: 'HIGH', evidence: [{ statement: `Fixture: ${kind} ${value}`, url: 'https://registry.example/fixture' }] }
}

export function makeVendor(
  id: string,
  opts: { category?: VendorCategory; cna?: string; cpeVendor?: string | null; affected?: string; claims?: { goalId: string; summary: string }[]; csaf?: boolean } = {},
): Vendor {
  const aliases: Alias[] = [alias('LEGAL_NAME', `${id} Holdings`), alias('SIGNATORY_LISTING', `${id} Holdings`)]
  aliases.push(alias('CNA_SHORT_NAME', opts.cna ?? `${id}-cna`))
  if (opts.cpeVendor !== null) aliases.push(alias('CPE_VENDOR', opts.cpeVendor ?? id.replace(/-/g, '_')))
  aliases.push(alias('AFFECTED_VENDOR', opts.affected ?? `${id} affected`))
  const v: Vendor = {
    id,
    canonicalName: `${id} Holdings`,
    aliases,
    signatoryStatus: 'LISTED',
    category: opts.category ?? 'ENTERPRISE_SOFTWARE',
    domains: [`${id}.example`],
    claims: (opts.claims ?? []).map((c) => ({ ...c, url: `https://${id}.example/pledge` })),
    synthetic: true,
  }
  if (opts.csaf !== false) v.csafProviderUrl = `https://${id}.example/.well-known/csaf/provider-metadata.json`
  return v
}

export const CVE_SOURCE: SourceRef = {
  id: 'cve.record',
  family: 'CVE_PROGRAM',
  title: 'CVE records',
  url: 'https://cveawg.mitre.example/api/cve/{id}',
  publisher: 'CVE Program',
  attribution: 'CVE terms of use',
  retention: 'RAW',
}

export function vdpSource(vendorId: string): SourceRef {
  return { id: `vendor.${vendorId}.vdp`, family: 'VENDOR_VDP', title: `${vendorId} VDP`, url: `https://${vendorId}.example/security/vdp`, publisher: vendorId, attribution: 'Quoted for analysis', retention: 'EXTRACT_ONLY' }
}

export function advisorySource(vendorId: string): SourceRef {
  return { id: `vendor.${vendorId}.csaf`, family: 'VENDOR_ADVISORY', title: `${vendorId} CSAF`, url: `https://${vendorId}.example/csaf`, publisher: vendorId, attribution: 'CSAF', retention: 'RAW' }
}

export function snapshot(id: string, sourceId: string, fetchedAt: string, status: Snapshot['status'] = 'OK', extra: Partial<Snapshot> = {}): Snapshot {
  const s: Snapshot = { id, sourceId, url: `https://fixture.example/${sourceId}`, fetchedAt, status, parserVersion: '1.0.0', ...extra }
  if (status === 'OK' && !s.sha256) s.sha256 = 'a'.repeat(64)
  return s
}

export const CVE_SNAPSHOT = snapshot('SN-cve000000001', 'cve.record', daysAgo(0.5))

export function makeCve(
  id: string,
  opts: {
    cna?: string
    publishedDaysAgo?: number
    datePublished?: string
    cwes?: string[]
    cpes?: string[]
    adp?: ContainerData[]
    affected?: { vendor: string; product: string }[]
    state?: CveRecord['state']
    sourceHash?: string
    title?: string
  } = {},
): CveRecord {
  const r: CveRecord = {
    id,
    state: opts.state ?? 'PUBLISHED',
    assigner: { orgId: `org-${opts.cna ?? 'none'}`, shortName: opts.cna ?? 'unknown-cna' },
    affected: opts.affected ?? [],
    cna: container('CNA', opts.cwes ?? [], opts.cpes ?? []),
    adp: opts.adp ?? [],
    dataVersion: '5.1',
    snapshotId: CVE_SNAPSHOT.id,
    sourceHash: opts.sourceHash ?? `hash-${id}`,
    synthetic: true,
  }
  const dp = opts.datePublished ?? daysAgo(opts.publishedDaysAgo ?? 30)
  r.datePublished = dp
  if (opts.title) r.title = opts.title
  return r
}

export function makeAdvisory(vendorId: string, id: string, opts: { severity?: Advisory['severity']; publishedDaysAgo?: number; cveIds?: string[] } = {}): Advisory {
  return {
    id,
    vendorId,
    url: `https://${vendorId}.example/advisories/${id}`,
    title: `Advisory ${id}`,
    publishedAt: daysAgo(opts.publishedDaysAgo ?? 40),
    severity: opts.severity ?? 'HIGH',
    cveIds: opts.cveIds ?? [],
    snapshotId: `SN-adv-${vendorId}`,
    synthetic: true,
  }
}

const ALL_CRITERIA: VdpCriterionId[] = [
  'POLICY_DISCOVERABLE',
  'SECURITY_CONTACT',
  'REPORTING_CHANNEL',
  'TESTING_AUTHORIZED',
  'GOOD_FAITH_SAFE_HARBOR',
  'PUBLIC_DISCLOSURE_ALLOWED',
  'SCOPE_DEFINED',
  'CURRENT',
]

export function makeVdp(
  vendorId: string,
  states: Partial<Record<VdpCriterionId, CriterionState>> = {},
  opts: { found?: boolean; textHash?: string; carriedFrom?: string; observedAt?: string; default?: CriterionState } = {},
): VdpObservation {
  const o: VdpObservation = {
    vendorId,
    observedAt: opts.observedAt ?? daysAgo(1),
    securityTxt: {
      present: true,
      url: `https://${vendorId}.example/.well-known/security.txt`,
      contacts: [`mailto:security@${vendorId}.example`],
      policyUrls: [`https://${vendorId}.example/security/vdp`],
      canonical: [],
      warnings: [],
      signed: false,
    },
    policy: {
      found: opts.found ?? true,
      url: `https://${vendorId}.example/security/vdp`,
      snapshotId: `SN-vdp-${vendorId}`,
      textHash: opts.textHash ?? `text-${vendorId}`,
      host: `${vendorId}.example`,
      wordCount: 600,
    },
    criteria: ALL_CRITERIA.map((c) => {
      const state = states[c] ?? opts.default ?? 'MET'
      return { criterion: c, state, ruleId: `VDP.${c}.R1`, quotes: state === 'MET' || state === 'PARTIAL' ? [`Quoted sentence for ${c}.`] : [] }
    }),
    prohibitive: [],
  }
  if (opts.carriedFrom) o.carriedFromSnapshotId = opts.carriedFrom
  return o
}

/** Sources and snapshots for a set of vendors (all fetched half a day before AS_OF). */
export function sourcesFor(vendorIds: string[]): { sources: SourceRef[]; snapshots: Snapshot[] } {
  const sources: SourceRef[] = [CVE_SOURCE]
  const snapshots: Snapshot[] = [CVE_SNAPSHOT]
  for (const id of vendorIds) {
    sources.push(vdpSource(id), advisorySource(id))
    snapshots.push(snapshot(`SN-vdp-${id}`, `vendor.${id}.vdp`, daysAgo(0.5)), snapshot(`SN-adv-${id}`, `vendor.${id}.csaf`, daysAgo(0.5)))
  }
  return { sources, snapshots }
}

export function makeInputs(parts: Partial<RunInputs> & { vendors: Vendor[] }): RunInputs {
  const ids = parts.vendors.map((v) => v.id)
  const s = sourcesFor(ids)
  return {
    mode: 'DEMO',
    datasetVersion: '2026-10-06',
    asOf: AS_OF,
    methodologyVersion: '1.1.0',
    cves: [],
    advisories: [],
    vdp: [],
    previousVdp: [],
    snapshots: s.snapshots,
    sources: s.sources,
    history: [],
    ...parts,
  }
}

/**
 * A MeasureContext for unit-testing one measure without the identity
 * module: every record is attributed to the vendor with the given rule.
 */
export function makeCtx(opts: {
  vendor: Vendor
  records?: CveRecord[]
  methodology?: string
  advisories?: Advisory[]
  vdp?: VdpObservation
  allCves?: CveRecord[]
  rule?: Attribution['rule']
  asOf?: string
}): MeasureContext {
  const methodology = methodologyVersion(opts.methodology ?? '1.1.0')
  const asOf = opts.asOf ?? AS_OF
  const s = sourcesFor([opts.vendor.id])
  const freshness = computeFreshness(s.snapshots, s.sources, asOf, methodology.parameters)
  const rule = opts.rule ?? 'ASSIGNER_IS_VENDOR_CNA'
  const records = opts.records ?? []
  const all = opts.allCves ?? records
  const ctx: MeasureContext = {
    vendor: opts.vendor,
    asOf,
    asOfMs: Date.parse(asOf),
    methodology,
    attributed: records.map((record) => ({
      record,
      attribution: { cveId: record.id, vendorId: opts.vendor.id, rule, confidence: rule === 'AFFECTED_VENDOR_ONLY' ? 'MEDIUM' : 'HIGH', matched: [{ kind: 'CNA_SHORT_NAME', value: record.assigner.shortName }] },
    })),
    exclusions: [],
    cvesById: new Map(all.map((r) => [r.id, r])),
    duplicateIds: new Set(),
    advisories: opts.advisories ?? [],
    snapshotsById: new Map(s.snapshots.map((x) => [x.id, x])),
    sources: s.sources,
    freshnessBySource: new Map(freshness.map((f) => [f.sourceId, f])),
    cveSourceFailed: false,
    ledger: new EvidenceLedger(),
  }
  if (opts.vdp) ctx.vdp = opts.vdp
  return ctx
}

/**
 * The placeholder-CWE fixture behind the 1.0.0 -> 1.1.0 regression test.
 * Six eligible records, all with a well-formed CNA CPE in the vendor's namespace:
 *   2 real CWE, 2 NVD-CWE-noinfo / NVD-CWE-Other placeholders, 1 no CWE, 1 malformed CWE.
 *   1.0.0: usable CWE = 2 + 2 = 4 -> 4/6 = 66.67%
 *   1.1.0: usable CWE = 2         -> 2/6 = 33.33%
 */
export function placeholderFixture(vendor: Vendor): CveRecord[] {
  const ns = vendor.aliases.find((a) => a.kind === 'CPE_VENDOR')!.value
  const cna = vendor.aliases.find((a) => a.kind === 'CNA_SHORT_NAME')!.value
  const p = [cpe(ns)]
  return [
    makeCve('DEMO-2026-1001', { cna, cwes: ['CWE-79'], cpes: p }),
    makeCve('DEMO-2026-1002', { cna, cwes: ['CWE-787'], cpes: p }),
    makeCve('DEMO-2026-1003', { cna, cwes: ['NVD-CWE-noinfo'], cpes: p }),
    makeCve('DEMO-2026-1004', { cna, cwes: ['NVD-CWE-Other'], cpes: p }),
    makeCve('DEMO-2026-1005', { cna, cwes: [], cpes: p }),
    makeCve('DEMO-2026-1006', { cna, cwes: ['weakness 79'], cpes: p }),
  ]
}
