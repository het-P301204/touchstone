/**
 * Builders for the adversarial suite. Independent of packages/core/test/fixtures
 * so these tests do not move when the scoring fixtures change. Records are built
 * through the engine's own parsers (parseCwe, parseCpe23, normalizeCveRecord,
 * assessVdp) wherever possible, so an attack exercises the real parsing path.
 *
 * Every vendor is fictional and every URL uses the reserved .example TLD.
 */

import type {
  Advisory,
  Alias,
  AliasKind,
  ContainerData,
  CveRecord,
  MetricValue,
  RunInputs,
  RunOutput,
  SecurityTxt,
  Snapshot,
  SourceRef,
  VdpObservation,
  Vendor,
  VendorCategory,
  VendorResult,
} from '../../packages/core/src/model/index.ts'
import { parseCpe23, parseCwe } from '../../packages/core/src/normalize/cve.ts'
import { assessVdp } from '../../packages/core/src/vdp/assess.ts'
import { methodologyVersion } from '../../packages/core/src/methodology/versions.ts'
import { executeRun } from '../../packages/core/src/run/run.ts'

export const AS_OF = '2026-10-06T12:00:00.000Z'
const DAY = 86_400_000

export const daysAgo = (d: number, from = AS_OF): string => new Date(Date.parse(from) - d * DAY).toISOString()
export const daysAfter = (d: number, from = AS_OF): string => new Date(Date.parse(from) + d * DAY).toISOString()

export const params = (version = '1.1.0') => methodologyVersion(version).parameters

// ------------------------------------------------------------------ vendors

export function alias(kind: AliasKind, value: string): Alias {
  return { kind, value, confidence: 'HIGH', evidence: [{ statement: `Adversarial fixture: ${kind} ${value}`, url: 'https://registry.example/adv' }] }
}

export function vendor(
  id: string,
  o: { cna?: string | null; cpeNs?: string | null; affected?: string | null; category?: VendorCategory; extra?: Alias[]; csaf?: boolean; status?: Vendor['signatoryStatus'] } = {},
): Vendor {
  const aliases: Alias[] = [alias('LEGAL_NAME', `${id} Holdings`), alias('SIGNATORY_LISTING', `${id} Holdings`)]
  if (o.cna !== null) aliases.push(alias('CNA_SHORT_NAME', o.cna ?? `${id}-cna`))
  if (o.cpeNs !== null) aliases.push(alias('CPE_VENDOR', o.cpeNs ?? id.replace(/-/g, '_')))
  if (o.affected !== null) aliases.push(alias('AFFECTED_VENDOR', o.affected ?? `${id} affected`))
  aliases.push(...(o.extra ?? []))
  const v: Vendor = {
    id,
    canonicalName: `${id} Holdings`,
    aliases,
    signatoryStatus: o.status ?? 'LISTED',
    category: o.category ?? 'ENTERPRISE_SOFTWARE',
    domains: [`${id}.example`],
    claims: [],
    synthetic: true,
  }
  if (o.csaf !== false) v.csafProviderUrl = `https://${id}.example/.well-known/csaf/provider-metadata.json`
  return v
}

// ------------------------------------------------------------------ records

export const cpeFor = (ns: string, product = 'product'): string => `cpe:2.3:a:${ns}:${product}:1.0:*:*:*:*:*:*:*`

export function containerOf(provider: string, cwes: string[] = [], cpes: string[] = []): ContainerData {
  return { provider, cwes: cwes.map(parseCwe), cpes: cpes.map(parseCpe23), cvss: [] }
}

export const CVE_SNAP_ID = 'SN-advcve000001'

export function record(
  id: string,
  o: {
    cna?: string
    orgId?: string
    publishedDaysAgo?: number
    datePublished?: string
    cwes?: string[]
    cpes?: string[]
    adp?: ContainerData[]
    affected?: { vendor: string; product: string }[]
    state?: CveRecord['state']
    sourceHash?: string
    title?: string
    snapshotId?: string
  } = {},
): CveRecord {
  const r: CveRecord = {
    id,
    state: o.state ?? 'PUBLISHED',
    assigner: { orgId: o.orgId ?? `org-${o.cna ?? 'none'}`, shortName: o.cna ?? 'third-party-cna' },
    affected: o.affected ?? [],
    cna: containerOf('CNA', o.cwes ?? ['CWE-79'], o.cpes ?? []),
    adp: o.adp ?? [],
    dataVersion: '5.1',
    snapshotId: o.snapshotId ?? CVE_SNAP_ID,
    sourceHash: o.sourceHash ?? `hash-${id}`,
    synthetic: true,
  }
  r.datePublished = o.datePublished ?? daysAgo(o.publishedDaysAgo ?? 30)
  if (o.title) r.title = o.title
  return r
}

/** n complete records for a vendor (own CNA, CWE-79, CPE in namespace), ids DEMO-2026-<start..>. */
export function completeRecords(v: Vendor, n: number, start = 1000, o: { publishedDaysAgo?: number } = {}): CveRecord[] {
  const cna = v.aliases.find((a) => a.kind === 'CNA_SHORT_NAME')!.value
  const ns = v.aliases.find((a) => a.kind === 'CPE_VENDOR')!.value
  return Array.from({ length: n }, (_, i) =>
    record(`DEMO-2026-${start + i}`, { cna, cwes: ['CWE-79'], cpes: [cpeFor(ns)], publishedDaysAgo: o.publishedDaysAgo ?? 30 + i }),
  )
}

export function advisory(vendorId: string, id: string, o: { severity?: Advisory['severity']; publishedAt?: string; publishedDaysAgo?: number; cveIds?: string[] } = {}): Advisory {
  return {
    id,
    vendorId,
    url: `https://${vendorId}.example/advisories/${id}`,
    title: `Advisory ${id}`,
    publishedAt: o.publishedAt ?? daysAgo(o.publishedDaysAgo ?? 40),
    severity: o.severity ?? 'HIGH',
    cveIds: o.cveIds ?? [],
    snapshotId: `SN-adv-${vendorId}`,
    synthetic: true,
  }
}

// ------------------------------------------------------------------ VDP

export function stxt(o: Partial<SecurityTxt> = {}): SecurityTxt {
  return { present: true, url: 'https://v.example/.well-known/security.txt', snapshotId: 'SN-stxt', contacts: ['mailto:security@v.example'], policyUrls: [], canonical: [], warnings: [], signed: false, expires: daysAfter(200), ...o }
}

export const NO_STXT: SecurityTxt = { present: false, contacts: [], policyUrls: [], canonical: [], warnings: [], signed: false }

/** A policy that meets all eight criteria under the current phrase rules. */
export const STRONG_POLICY = [
  'Last updated: 2026-06-01',
  'This policy applies to all products and services offered by the company.',
  'We authorize good-faith security testing of our products by members of the public.',
  'We will not pursue legal action against researchers who follow this policy in good faith.',
  'Please report vulnerabilities by email to security@v.example or through our web form.',
  'We support coordinated disclosure and you may publish your findings after a fix is released or after 90 days.',
].join('\n')

export function vdpFromText(
  vendorId: string,
  text: string | undefined,
  o: { securityTxt?: SecurityTxt; found?: boolean; fetchFailed?: boolean; snapshotId?: string; observedAt?: string; asOf?: string } = {},
): VdpObservation {
  const policy: { found: boolean; url?: string; snapshotId?: string; text?: string; fetchFailed?: boolean } = {
    found: o.found ?? true,
    url: `https://${vendorId}.example/security/vdp`,
  }
  if (o.snapshotId !== undefined || policy.found) policy.snapshotId = o.snapshotId ?? `SN-vdp-${vendorId}`
  if (text !== undefined) policy.text = text
  if (o.fetchFailed) policy.fetchFailed = true
  return assessVdp({
    vendorId,
    observedAt: o.observedAt ?? daysAgo(0.5),
    asOf: o.asOf ?? AS_OF,
    securityTxt: o.securityTxt ?? stxt({ snapshotId: `SN-stxt-${vendorId}` }),
    policy,
    params: params(),
  })
}

export const stateOf = (o: VdpObservation, c: string) => o.criteria.find((x) => x.criterion === c)!

// ------------------------------------------------------------------ sources and inputs

export const CVE_SOURCE: SourceRef = {
  id: 'cve.record',
  family: 'CVE_PROGRAM',
  title: 'CVE records',
  url: 'https://cve.example/api/cve/{id}',
  publisher: 'CVE Program (fixture)',
  attribution: 'fixture',
  retention: 'RAW',
}

export function snap(id: string, sourceId: string, fetchedAt: string, status: Snapshot['status'] = 'OK', extra: Partial<Snapshot> = {}): Snapshot {
  const s: Snapshot = { id, sourceId, url: `https://fixture.example/${sourceId}`, fetchedAt, status, parserVersion: '1.0.0', ...extra }
  if (status === 'OK' && !s.sha256) s.sha256 = 'b'.repeat(64)
  return s
}

export function vendorSources(ids: string[]): { sources: SourceRef[]; snapshots: Snapshot[] } {
  const sources: SourceRef[] = []
  const snapshots: Snapshot[] = []
  for (const id of ids) {
    sources.push(
      { id: `vendor.${id}.vdp`, family: 'VENDOR_VDP', title: `${id} VDP`, url: `https://${id}.example/security/vdp`, publisher: id, attribution: 'fixture', retention: 'EXTRACT_ONLY' },
      { id: `vendor.${id}.security-txt`, family: 'SECURITY_TXT', title: `${id} security.txt`, url: `https://${id}.example/.well-known/security.txt`, publisher: id, attribution: 'fixture', retention: 'RAW' },
      { id: `vendor.${id}.csaf`, family: 'VENDOR_ADVISORY', title: `${id} CSAF`, url: `https://${id}.example/csaf`, publisher: id, attribution: 'fixture', retention: 'RAW' },
    )
    snapshots.push(
      snap(`SN-vdp-${id}`, `vendor.${id}.vdp`, daysAgo(0.5)),
      snap(`SN-stxt-${id}`, `vendor.${id}.security-txt`, daysAgo(0.5)),
      snap(`SN-adv-${id}`, `vendor.${id}.csaf`, daysAgo(0.5)),
    )
  }
  return { sources, snapshots }
}

export function inputs(parts: Partial<RunInputs> & { vendors: Vendor[]; cveSnapshotStatus?: Snapshot['status'] }): RunInputs {
  const { cveSnapshotStatus, ...rest } = parts
  const vs = vendorSources(parts.vendors.map((v) => v.id))
  return {
    mode: 'DEMO',
    datasetVersion: '2026-10-06',
    asOf: AS_OF,
    methodologyVersion: '1.1.0',
    cves: [],
    advisories: [],
    vdp: [],
    previousVdp: [],
    snapshots: [snap(CVE_SNAP_ID, 'cve.record', daysAgo(0.5), cveSnapshotStatus ?? 'OK'), ...vs.snapshots],
    sources: [CVE_SOURCE, ...vs.sources],
    history: [],
    ...rest,
  }
}

// ------------------------------------------------------------------ result accessors

export const run = (i: RunInputs): RunOutput => executeRun(i)
export const vr = (out: RunOutput, id: string): VendorResult => out.vendors.find((v) => v.vendor.id === id)!
export const metricOf = (out: RunOutput, id: string, metricId: string): MetricValue =>
  vr(out, id).goals.flatMap((g) => g.metrics).find((m) => m.metricId === metricId)!
export const goalOf = (out: RunOutput, id: string, goalId: string) => vr(out, id).goals.find((g) => g.goalId === goalId)!
export const dimOf = (out: RunOutput, id: string, dim: string) => vr(out, id).dimensions.find((d) => d.dimension === dim)!

/** Deterministic shuffle (reverse + rotate) so order-independence tests need no randomness. */
export function reorder<T>(xs: T[]): T[] {
  const r = [...xs].reverse()
  return r.length > 2 ? [...r.slice(1), r[0]!] : r
}
