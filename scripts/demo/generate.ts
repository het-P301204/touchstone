/**
 * Deterministic generator for the TOUCHSTONE demo dataset.
 *
 *   node scripts/demo/generate.ts            write fixtures/demo/**
 *   node scripts/demo/generate.ts --check    regenerate in memory; exit 1 if any file differs
 *
 * Everything is synthetic: fictional vendors (scripts/demo/vendors.ts),
 * .example URLs, DEMO-YYYY-NNNN record ids. Randomness comes from a seeded
 * PRNG (mulberry32) keyed per vendor, so the output is byte-identical on
 * every run and adding a vendor does not reshuffle the others.
 *
 * Layout (paths relative to fixtures/demo):
 *   registry/vendors.json                       Vendor[] (signatoryStatus is set by the loader from the signer page)
 *   records/cve/<id>-<sha8>.json                CVE JSON 5.1 records, one file per distinct content
 *   records/csaf/<vendorId>/<trackingId>.json   CSAF 2.0 advisories
 *   <version>/manifest.json                     sources + snapshot list (sourceId, url, fetchedAt, status, file, sha256)
 *   <version>/cisa/signers.html                 signer page, same structure as the real CISA page
 *   <version>/vdp/<vendorId>/security.txt       RFC 9116 file
 *   <version>/vdp/<vendorId>/policy.html        policy page
 *   SCENARIOS.md                                vendor -> scenario -> expected outcome
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { Alias, SourceRef, Vendor } from '../../packages/core/src/model/index.ts'
import { sha256Text } from '../../packages/core/src/util/sha256.ts'
import { failedSnapshotId, snapshotId } from '../../packages/core/src/normalize/snapshot-id.ts'
import { COPPERLEAF_EXPIRES, FILLER_SIGNATORIES, NARROWING_FROM, THIRD_PARTY_CNA, VENDORS } from './vendors.ts'
import type { VendorSpec } from './vendors.ts'

export const DATASET_VERSIONS = ['2025-10-06', '2026-01-06', '2026-04-06', '2026-07-06', '2026-10-06']
const SEED = 20261006
const DAY = 86_400_000
const TIMELINE_START = Date.UTC(2023, 9, 1)
const TIMELINE_END = Date.UTC(2026, 8, 30)
const ENRICHMENT_DELAY_DAYS = 30
const COUNT_MISMATCH_VERSION = '2026-01-06'
const LEGACY_RECORD_FROM = '2026-04-06'

// ------------------------------------------------------------------ deterministic helpers

function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6d2b79f5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function rngFor(key: string): () => number {
  return mulberry32(parseInt(sha256Text(`${SEED}:${key}`).slice(0, 8), 16))
}

function uuidFor(key: string): string {
  const h = sha256Text(`uuid:${key}`)
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-4${h.slice(13, 16)}-8${h.slice(17, 20)}-${h.slice(20, 32)}`
}

const iso = (ms: number) => new Date(ms).toISOString()
const versionMs = (v: string) => Date.parse(`${v}T00:00:00Z`)
const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December']
const longDate = (ymd: string) => {
  const [y, m, d] = ymd.split('-').map(Number)
  return `${MONTHS[m! - 1]} ${d}, ${y}`
}
const slug = (s: string) => s.toLowerCase().replace(/&/g, 'and').replace(/[^a-z0-9]+/g, '_').replace(/^_|_$/g, '')
const escapeHtml = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

// ------------------------------------------------------------------ CWE pools

const MEMORY_SAFETY = ['CWE-787', 'CWE-416', 'CWE-125', 'CWE-120']
const OTHER_CWES = ['CWE-79', 'CWE-89', 'CWE-78', 'CWE-22', 'CWE-287', 'CWE-352', 'CWE-862', 'CWE-20', 'CWE-400', 'CWE-502', 'CWE-918', 'CWE-798']
const CWE_NAMES: Record<string, string> = {
  'CWE-787': 'Out-of-bounds Write', 'CWE-416': 'Use After Free', 'CWE-125': 'Out-of-bounds Read', 'CWE-120': 'Classic Buffer Overflow',
  'CWE-79': 'Cross-site Scripting', 'CWE-89': 'SQL Injection', 'CWE-78': 'OS Command Injection', 'CWE-22': 'Path Traversal',
  'CWE-287': 'Improper Authentication', 'CWE-352': 'Cross-Site Request Forgery', 'CWE-862': 'Missing Authorization',
  'CWE-20': 'Improper Input Validation', 'CWE-400': 'Uncontrolled Resource Consumption', 'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-918': 'Server-Side Request Forgery', 'CWE-798': 'Use of Hard-coded Credentials',
}
const IMPACT: Record<string, string> = {
  'CWE-787': 'may allow remote code execution', 'CWE-416': 'may allow code execution', 'CWE-125': 'may disclose memory contents',
  'CWE-120': 'may allow code execution', 'CWE-79': 'allows script injection in the web console', 'CWE-89': 'allows SQL injection',
  'CWE-78': 'allows command injection', 'CWE-22': 'allows reading files outside the intended directory', 'CWE-287': 'allows authentication bypass',
  'CWE-352': 'allows cross-site request forgery', 'CWE-862': 'allows unauthorized actions', 'CWE-20': 'allows a crafted request to crash the service',
  'CWE-400': 'allows denial of service', 'CWE-502': 'allows code execution through crafted serialized data', 'CWE-918': 'allows server-side request forgery',
  'CWE-798': 'contains hard-coded credentials',
}

type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

// ------------------------------------------------------------------ record specs

type CweKind = 'REAL' | 'PLACEHOLDER' | 'NONE' | 'TEXT_ONLY'
type CpeKind = 'GOOD' | 'WRONG_NS' | 'MALFORMED' | 'NONE'

type RecSpec = {
  key: string
  id: string
  vendorId: string | null
  published: number
  severity: Severity
  score: number
  cwe: string
  cweKind: CweKind
  cpeKind: CpeKind
  adpCwe: boolean
  adpCpe: boolean
  assigner: { shortName: string; orgId: string }
  affectedVendor: string
  product: string
  cpeVendor: string
  cpePart: 'a' | 'o' | 'h'
  version: string
  fixed: string
  domain: string
  useApplicability: boolean
  title: string
  state: 'PUBLISHED' | 'REJECTED'
  mirror?: 'IDENTICAL' | 'CONFLICTING'
  legacy?: boolean
}

const cnaOrg = (shortName: string) => uuidFor(`cna:${shortName}`)
const THIRD = { shortName: THIRD_PARTY_CNA.shortName, orgId: cnaOrg(THIRD_PARTY_CNA.shortName) }
const CISA_ADP_ORG = '134c704f-9b21-4f2e-91b3-4a467353bcc0'

function pickSeverity(r: () => number): { severity: Severity; score: number } {
  const x = r()
  const span = (lo: number, hi: number) => Math.round((lo + r() * (hi - lo)) * 10) / 10
  if (x < 0.15) return { severity: 'CRITICAL', score: span(9.0, 9.8) }
  if (x < 0.5) return { severity: 'HIGH', score: span(7.0, 8.8) }
  if (x < 0.9) return { severity: 'MEDIUM', score: span(4.0, 6.9) }
  return { severity: 'LOW', score: span(2.0, 3.9) }
}

function pick<T>(r: () => number, xs: readonly T[]): T {
  return xs[Math.floor(r() * xs.length) % xs.length]!
}

function vendorRecords(v: VendorSpec): RecSpec[] {
  const r = rngFor(`records:${v.id}`)
  const out: RecSpec[] = []
  const span = TIMELINE_END - TIMELINE_START
  for (let i = 0; i < v.records; i++) {
    const jitter = (r() - 0.5) * 20 * DAY
    const published = Math.round(TIMELINE_START + ((i + 0.5) / v.records) * span + jitter) - (Math.round(TIMELINE_START + ((i + 0.5) / v.records) * span + jitter) % 60000)
    const { severity, score } = pickSeverity(r)
    const progress = (published - TIMELINE_START) / span
    const memShare = v.classShift ? 0.5 - 0.42 * progress : 0.25
    const cwe = r() < memShare ? pick(r, MEMORY_SAFETY) : pick(r, OTHER_CWES)
    const c = r()
    const cweKind: CweKind = c < v.cwe.real ? 'REAL' : c < v.cwe.real + v.cwe.placeholder ? 'PLACEHOLDER' : r() < 0.5 ? 'TEXT_ONLY' : 'NONE'
    let cpeKind: CpeKind = 'NONE'
    if (r() < v.cpe.rate) {
      const q = r()
      cpeKind = q < v.cpe.quality.good ? 'GOOD' : q < v.cpe.quality.good + v.cpe.quality.wrongNamespace ? 'WRONG_NS' : 'MALFORMED'
    }
    const adpCwe = cweKind !== 'REAL' && r() < v.adpEnrichment.cwe
    const adpCpe = cpeKind !== 'GOOD' && r() < v.adpEnrichment.cpe
    const product = pick(r, v.products)
    const major = 1 + Math.floor(r() * 6)
    const minor = Math.floor(r() * 10)
    const assigner = v.cna ? { shortName: v.cna.shortName, orgId: cnaOrg(v.cna.shortName) } : THIRD
    // Kestrel: records with a CPE use the shared "kestrel" namespace (identity conflict).
    const cpeVendor = v.cpeVendors[0]!
    out.push({
      key: `${v.id}:${i}`,
      id: '',
      vendorId: v.id,
      published,
      severity,
      score,
      cwe,
      cweKind,
      cpeKind,
      adpCwe,
      adpCpe,
      assigner,
      affectedVendor: v.affectedNames[0]!,
      product,
      cpeVendor,
      cpePart: v.cpePart,
      version: `${major}.${minor}.0`,
      fixed: `${major}.${minor}.${1 + Math.floor(r() * 9)}`,
      domain: v.domain,
      useApplicability: v.cpeApplicability === true,
      title: `${product} ${CWE_NAMES[cwe]!.toLowerCase()} ${IMPACT[cwe]!}`,
      state: 'PUBLISHED',
    })
  }
  return out
}

function extraRecords(): RecSpec[] {
  const r = rngFor('extra')
  const base = (key: string, published: number, over: Partial<RecSpec>): RecSpec => {
    const { severity, score } = pickSeverity(r)
    const cwe = pick(r, OTHER_CWES)
    return {
      key, id: '', vendorId: null, published, severity, score, cwe, cweKind: 'REAL', cpeKind: 'NONE', adpCwe: false, adpCpe: false,
      assigner: THIRD, affectedVendor: '', product: '', cpeVendor: '', cpePart: 'a', version: '2.1.0', fixed: '2.1.4', domain: 'coordination.example',
      useApplicability: false, title: '', state: 'PUBLISHED', ...over,
    }
  }
  const out: RecSpec[] = []
  const at = (ymd: string) => Date.parse(`${ymd}T15:30:00Z`)
  // Ambiguous: only "Summit" in affected[].vendor, from a third-party CNA.
  for (const [k, d] of ['2024-02-12', '2024-09-03', '2025-03-18', '2025-08-27', '2026-02-09', '2026-08-04'].entries()) {
    out.push(base(`ambiguous:${k}`, at(d), { affectedVendor: 'Summit', product: 'Summit Connector', title: 'Summit Connector improper certificate validation in the update client' }))
  }
  // Free text only: the title names a registered vendor, the structured fields do not.
  for (const [k, d] of ['2024-11-20', '2026-05-14'].entries()) {
    out.push(
      base(`freetext:${k}`, at(d), {
        affectedVendor: 'Unlisted Widgets Co',
        product: 'Widget Bridge',
        title: 'Widget Bridge plugin for Northwind Systems Ledger Suite stores API tokens in plain text',
      }),
    )
  }
  // Unrelated: an unregistered vendor (no attribution, no exclusion).
  for (const [k, d] of ['2024-03-05', '2024-12-11', '2025-06-30', '2026-03-23'].entries()) {
    out.push(base(`unrelated:${k}`, at(d), { affectedVendor: 'Hollowmere Apps', product: 'Hollowmere Notes', title: 'Hollowmere Notes cross-site scripting in shared notebooks' }))
  }
  // REJECTED records from vendor CNAs.
  out.push(base('rejected:northwind', at('2025-01-22'), { assigner: { shortName: 'northwind', orgId: cnaOrg('northwind') }, state: 'REJECTED', vendorId: 'northwind-systems' }))
  out.push(base('rejected:halcyon', at('2025-11-04'), { assigner: { shortName: 'halcyon', orgId: cnaOrg('halcyon') }, state: 'REJECTED', vendorId: 'halcyon-cloud' }))
  // A legacy CVE JSON 4.0 document served by the mirror: the normalizer must reject it.
  out.push(base('legacy:0', at('2026-03-02'), { legacy: true, affectedVendor: 'Hollowmere Apps', product: 'Hollowmere Sync', title: 'Hollowmere Sync legacy-format record' }))
  return out
}

function allRecords(): RecSpec[] {
  const recs = [...VENDORS.flatMap(vendorRecords), ...extraRecords()]
  recs.sort((a, b) => a.published - b.published || (a.key < b.key ? -1 : 1))
  const seq = new Map<number, number>()
  for (const rec of recs) {
    const y = new Date(rec.published).getUTCFullYear()
    const n = (seq.get(y) ?? 1000) + 1
    seq.set(y, n)
    rec.id = `DEMO-${y}-${n}`
  }
  // Quillmark: three ids conflict with the mirror copy, two are identical on the mirror.
  const quill = recs.filter((x) => x.vendorId === 'quillmark-labs' && x.state === 'PUBLISHED')
  for (const [i, rec] of quill.entries()) {
    if (i === 3 || i === 9 || i === 15) rec.mirror = 'CONFLICTING'
    if (i === 6 || i === 12) rec.mirror = 'IDENTICAL'
  }
  return recs
}

// ------------------------------------------------------------------ CVE JSON

function cpeString(rec: RecSpec, kind: CpeKind, vendorOverride?: string): string {
  const product = slug(rec.product)
  const ns = vendorOverride ?? rec.cpeVendor
  if (kind === 'WRONG_NS') return `cpe:2.3:${rec.cpePart}:${ns.replace(/_/g, '')}:${product}:${rec.version}:*:*:*:*:*:*:*`
  if (kind === 'MALFORMED') {
    return rec.key.length % 2 === 0 ? `cpe:/${rec.cpePart}:${ns}:${product}:${rec.version}` : `cpe:2.3:${rec.cpePart}:${ns}:${product}:${rec.version}`
  }
  return `cpe:2.3:${rec.cpePart}:${ns}:${product}:${rec.version}:*:*:*:*:*:*:*`
}

function cvss(rec: RecSpec) {
  const vector = rec.severity === 'CRITICAL' ? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' : rec.severity === 'HIGH' ? 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N' : rec.severity === 'MEDIUM' ? 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N' : 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N'
  return { version: '3.1', baseScore: rec.score, baseSeverity: rec.severity, vectorString: vector }
}

function cnaContainer(rec: RecSpec, variant: 'PRIMARY' | 'MIRROR_CONFLICT') {
  const providerMetadata = { orgId: rec.assigner.orgId, shortName: rec.assigner.shortName, dateUpdated: iso(rec.published) }
  if (rec.state === 'REJECTED') {
    return { providerMetadata, rejectedReasons: [{ lang: 'en', value: 'This candidate is unused by its CNA. Notes: none. (synthetic)' }] }
  }
  const affected: Record<string, unknown> = {
    vendor: rec.affectedVendor,
    product: rec.product,
    defaultStatus: 'unaffected',
    versions: [{ version: rec.version, lessThan: rec.fixed, status: 'affected', versionType: 'semver' }],
  }
  const cpeKind: CpeKind = variant === 'MIRROR_CONFLICT' ? 'NONE' : rec.cpeKind
  const cpe = cpeKind === 'NONE' ? null : cpeString(rec, cpeKind)
  if (cpe && !rec.useApplicability) affected.cpes = [cpe]
  const container: Record<string, unknown> = {
    providerMetadata,
    title: rec.title,
    datePublic: iso(rec.published - (rec.published % DAY)),
    descriptions: [{ lang: 'en', value: `${rec.title.charAt(0).toUpperCase()}${rec.title.slice(1)} in versions before ${rec.fixed}. Synthetic record for the TOUCHSTONE demo.` }],
    affected: [affected],
  }
  if (cpe && rec.useApplicability) {
    container.cpeApplicability = [{ nodes: [{ operator: 'OR', negate: false, cpeMatch: [{ vulnerable: true, criteria: cpeString(rec, cpeKind).replace(`:${rec.version}:`, ':*:'), versionStartIncluding: rec.version, versionEndExcluding: rec.fixed }] }] }]
  }
  const cweKind: CweKind = variant === 'MIRROR_CONFLICT' ? 'NONE' : rec.cweKind
  if (cweKind === 'REAL') {
    container.problemTypes = [{ descriptions: [{ lang: 'en', type: 'CWE', cweId: rec.cwe, description: `${rec.cwe} ${CWE_NAMES[rec.cwe]}` }] }]
  } else if (cweKind === 'PLACEHOLDER') {
    container.problemTypes = [{ descriptions: [{ lang: 'en', type: 'CWE', description: 'NVD-CWE-noinfo' }] }]
  } else if (cweKind === 'TEXT_ONLY') {
    container.problemTypes = [{ descriptions: [{ lang: 'en', type: 'text', description: IMPACT[rec.cwe]! }] }]
  }
  container.metrics = [{ format: 'CVSS', scenarios: [{ lang: 'en', value: 'GENERAL' }], cvssV3_1: cvss(rec) }]
  container.references = [{ url: `https://${rec.domain}/security/advisories/${rec.id.toLowerCase()}`, tags: ['vendor-advisory'] }]
  container.x_synthetic = true
  return container
}

function adpContainer(rec: RecSpec) {
  const c: Record<string, unknown> = {
    providerMetadata: { orgId: CISA_ADP_ORG, shortName: 'CISA-ADP', dateUpdated: iso(rec.published + ENRICHMENT_DELAY_DAYS * DAY) },
    title: 'CISA ADP Vulnrichment',
    metrics: [{ other: { type: 'ssvc', content: { id: rec.id, role: 'CISA Coordinator', version: '2.0.3', timestamp: iso(rec.published + ENRICHMENT_DELAY_DAYS * DAY), options: [{ Exploitation: 'none' }, { Automatable: rec.severity === 'CRITICAL' ? 'yes' : 'no' }, { 'Technical Impact': rec.severity === 'LOW' ? 'partial' : 'total' }] } } }],
  }
  if (rec.adpCwe) c.problemTypes = [{ descriptions: [{ lang: 'en', type: 'CWE', cweId: rec.cwe, description: `${rec.cwe} ${CWE_NAMES[rec.cwe]}` }] }]
  if (rec.adpCpe) c.affected = [{ vendor: rec.cpeVendor, product: slug(rec.product), cpes: [cpeString(rec, 'GOOD')], defaultStatus: 'unknown', versions: [{ version: rec.version, lessThan: rec.fixed, status: 'affected', versionType: 'semver' }] }]
  return c
}

/** The record as served at a dataset version (ADP enrichment appears 30 days after publication). */
function recordJson(rec: RecSpec, versionDate: string, variant: 'PRIMARY' | 'MIRROR_CONFLICT' = 'PRIMARY'): unknown {
  if (rec.legacy) {
    return {
      data_type: 'CVE',
      data_format: 'MITRE',
      data_version: '4.0',
      CVE_data_meta: { ID: rec.id, ASSIGNER: 'cve@coordination.example', STATE: 'PUBLIC' },
      affects: { vendor: { vendor_data: [{ vendor_name: rec.affectedVendor, product: { product_data: [{ product_name: rec.product }] } }] } },
      description: { description_data: [{ lang: 'eng', value: rec.title }] },
    }
  }
  const enriched = (rec.adpCwe || rec.adpCpe) && versionMs(versionDate) >= rec.published + ENRICHMENT_DELAY_DAYS * DAY
  const updated = enriched ? rec.published + ENRICHMENT_DELAY_DAYS * DAY : variant === 'MIRROR_CONFLICT' ? rec.published - 2 * DAY : rec.published
  const containers: Record<string, unknown> = { cna: cnaContainer(rec, variant) }
  if (enriched) containers.adp = [adpContainer(rec)]
  return {
    dataType: 'CVE_RECORD',
    dataVersion: '5.1',
    cveMetadata: {
      cveId: rec.id,
      assignerOrgId: rec.assigner.orgId,
      assignerShortName: rec.assigner.shortName,
      state: rec.state,
      dateReserved: iso(rec.published - 21 * DAY),
      datePublished: iso(rec.published),
      dateUpdated: iso(updated),
    },
    containers,
  }
}

// ------------------------------------------------------------------ CSAF

type AdvSpec = { vendorId: string; trackingId: string; released: number; severity: Severity; rec: RecSpec | null; title: string; aggregateText: string | null }

function advisories(recs: RecSpec[]): AdvSpec[] {
  const out: AdvSpec[] = []
  for (const v of VENDORS) {
    if (!v.csaf) continue
    const r = rngFor(`advisories:${v.id}`)
    const prefix = (v.cna?.shortName ?? v.id.split('-')[0]!).toUpperCase().slice(0, 6)
    const seq = new Map<number, number>()
    const nextId = (ms: number) => {
      const y = new Date(ms).getUTCFullYear()
      const n = (seq.get(y) ?? 0) + 1
      seq.set(y, n)
      return `${prefix}-SA-${y}-${String(n).padStart(3, '0')}`
    }
    const items: AdvSpec[] = []
    for (const rec of recs.filter((x) => x.vendorId === v.id && x.state === 'PUBLISHED' && !x.legacy)) {
      const high = rec.severity === 'CRITICAL' || rec.severity === 'HIGH'
      if (!high && r() > 0.25) continue
      const timely = r() < v.timelyShare
      // delta = CVE publication minus advisory release, in days (negative: the CVE came first).
      const delta = timely ? pick(r, [0, 0, 0, 1, -1]) : 5 + Math.floor(r() * 40)
      const words: Record<Severity, string[]> = { CRITICAL: ['Critical'], HIGH: ['High', 'Important'], MEDIUM: ['Medium', 'Moderate'], LOW: ['Low'] }
      items.push({ vendorId: v.id, trackingId: '', released: rec.published - delta * DAY, severity: rec.severity, rec, title: `Security update for ${rec.product}`, aggregateText: r() < 0.7 ? pick(r, words[rec.severity]) : null })
    }
    for (let k = 0; k < (v.advisoriesWithoutCve ?? 0); k++) {
      const released = TIMELINE_START + Math.floor(((k + 1) / ((v.advisoriesWithoutCve ?? 0) + 1)) * (TIMELINE_END - TIMELINE_START))
      items.push({ vendorId: v.id, trackingId: '', released: released - (released % DAY) + 14 * 3600_000, severity: 'HIGH', rec: null, title: `Security hardening update for ${v.products[0]}`, aggregateText: 'High' })
    }
    items.sort((a, b) => a.released - b.released)
    for (const it of items) it.trackingId = nextId(it.released)
    out.push(...items)
  }
  return out
}

function csafJson(a: AdvSpec): unknown {
  const v = VENDORS.find((x) => x.id === a.vendorId)!
  const doc: Record<string, unknown> = {
    category: 'csaf_security_advisory',
    csaf_version: '2.0',
    publisher: { category: 'vendor', name: v.name, namespace: `https://${v.domain}` },
    title: a.title,
    tracking: {
      id: a.trackingId,
      status: 'final',
      version: '1',
      initial_release_date: iso(a.released),
      current_release_date: iso(a.released),
      revision_history: [{ number: '1', date: iso(a.released), summary: 'Initial release.' }],
    },
    notes: [{ category: 'legal_disclaimer', text: 'Synthetic advisory for the TOUCHSTONE demo dataset.' }],
  }
  if (a.aggregateText) doc.aggregate_severity = { text: a.aggregateText }
  const productId = `${slug(a.rec?.product ?? v.products[0]!)}-affected`
  const vulnerabilities = a.rec
    ? [{ cve: a.rec.id, title: a.rec.title, scores: [{ products: [productId], cvss_v3: cvss(a.rec) }], product_status: { known_affected: [productId] } }]
    : [{ title: a.title, scores: [{ products: [productId], cvss_v3: { version: '3.1', baseScore: 7.5, baseSeverity: 'HIGH', vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' } }], product_status: { known_affected: [productId] } }]
  return {
    document: doc,
    product_tree: { full_product_names: [{ product_id: productId, name: a.rec?.product ?? v.products[0]! }] },
    vulnerabilities,
  }
}

// ------------------------------------------------------------------ VDP documents

const policyUrl = (v: VendorSpec) => (v.vdp === 'PLATFORM' ? `https://disclosure-platform.example/programs/${v.id.split('-')[0]}` : `https://${v.domain}/security/vulnerability-disclosure`)

function page(title: string, bodyHtml: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>body{font-family:sans-serif} .nav a{margin-right:1em}</style>
<script>window.analytics = { track: function () { /* synthetic page: never executed by TOUCHSTONE */ } };</script>
</head>
<body>
<nav class="nav"><a href="/">Home</a><a href="/products">Products</a><a href="/security">Security</a></nav>
<main>
${bodyHtml}
</main>
<footer><p>&copy; Synthetic demo data. Not a real company.</p></footer>
</body>
</html>
`
}

function policyHtml(v: VendorSpec, version: string): string | null {
  const name = escapeHtml(v.name)
  const d = v.domain
  const products = v.products.map((p) => `<li>${escapeHtml(p)}</li>`).join('')
  const reporting = `<h2>Reporting</h2><p>Report vulnerabilities by email to security@${d} or through our web form at https://${d}/security/report.</p><p>Please include the affected product, version and steps to reproduce.</p>`
  const safeHarbor = `<h2>Safe harbor</h2><p>If you make a good faith effort to comply with this policy during your security research, we will not recommend or pursue legal action related to your research.</p>`
  const disclosure = `<h2>Disclosure</h2><p>We support coordinated disclosure. You may publicly disclose your findings after we release a fix or 90 days after your report, whichever comes first.</p>`
  switch (v.vdp) {
    case 'NONE':
      return null
    case 'STRONG':
    case 'UNDATED_EXPIRED':
    case 'OLD_NO_STXT': {
      const dated = v.vdp === 'STRONG' ? `<p>Last updated: ${longDate('2025-03-17')}</p>` : v.vdp === 'OLD_NO_STXT' ? `<p>Last updated: ${longDate('2023-05-02')}</p>` : ''
      return page(
        `${v.name} Vulnerability Disclosure Policy`,
        `<h1>Vulnerability Disclosure Policy</h1>${dated}
<h2>Scope</h2><p>This policy applies to all ${name} products, services and web properties, including:</p><ul>${products}</ul>
<h2>Authorization</h2><p>We authorize security testing by members of the public of any system or product in scope, provided you follow this policy.</p>
${reporting}
${safeHarbor}
${disclosure}
<p>Thank you for helping keep our customers safe&nbsp;&mdash; we&rsquo;re grateful.</p>`,
      )
    }
    case 'STRONG_ALT':
      return page(
        `${v.name} Security Research Policy`,
        `<h1>Security Research Policy</h1><p>Last revised on 2025-02-11.</p>
<h2>Scope</h2><p>The following products are in scope: ${v.products.map(escapeHtml).join(', ')}. Third-party services are out of scope.</p>
<h2>Our commitment</h2><p>We welcome good-faith security research on our products and consider such research authorized under this policy.</p>
<p>Activities conducted in good faith and consistent with this policy are covered by our safe harbor.</p>
<h2>How to report</h2><p>Submit reports through https://${d}/security/submit or email psirt@${d}.</p>
<h2>Disclosure</h2><p>Please give us a reasonable time to fix the issue before public disclosure; we coordinate disclosure dates with reporters.</p>`,
      )
    case 'WEAK_NO_SAFE_HARBOR':
      return page(
        `${v.name} Vulnerability Reporting`,
        `<h1>Vulnerability Reporting</h1><p>Last updated: 2025-08-01</p>
<p>This policy applies to all ${name} products and services.</p>
<p>You are authorized to test ${name} products for security vulnerabilities in accordance with this policy.</p>
<p>Report suspected vulnerabilities by email to security@${d}.</p>
<p>We ask that you allow us 60 days to remediate before you publish details of the issue.</p>
<p>${name} will review reports and respond at its discretion.</p>
<h2>What to include</h2><p>A good report describes the issue, the affected product and version, and the steps needed to reproduce it.</p>
<p>We aim to acknowledge each report within five business days and to keep the reporter informed of our progress until the issue is resolved.</p>
<p>Thank you for helping us protect our customers and their data.</p>`,
      )
    case 'PROHIBITIVE':
      return page(
        `${v.name} Responsible Disclosure`,
        `<h1>Responsible Disclosure</h1><p>Effective date: ${longDate('2025-01-15')}</p>
<p>This policy applies to ${name} products and hosted services.</p>
<p>Researchers must obtain prior written permission from Gravelpoint before testing any system.</p>
<p>Report vulnerabilities by email to security@${d}.</p>
<p>Gravelpoint reserves the right to pursue legal action against anyone who accesses its systems without authorization.</p>
<p>You must not disclose any vulnerability information to third parties without our written consent.</p>
<h2>What to include</h2><p>A good report describes the issue, the affected product and version, and the steps needed to reproduce it.</p>
<p>We aim to acknowledge each report within five business days and to keep the reporter informed of our progress until the issue is resolved.</p>
<p>Thank you for helping us protect our customers and their data.</p>`,
      )
    case 'NARROWING': {
      if (version < NARROWING_FROM) {
        return page(
          `${v.name} Vulnerability Disclosure Policy`,
          `<h1>Vulnerability Disclosure Policy</h1><p>Last updated: ${longDate('2025-03-17')}</p>
<h2>Scope</h2><p>This policy applies to all ${name} products, services and web properties, including:</p><ul>${products}</ul>
<h2>Authorization</h2><p>We authorize security testing by members of the public of any system or product in scope, provided you follow this policy.</p>
${reporting}
${safeHarbor}
${disclosure}`,
        )
      }
      return page(
        `${v.name} Vulnerability Disclosure Policy`,
        `<h1>Vulnerability Disclosure Policy</h1><p>Last updated: ${longDate('2026-06-20')}</p>
<h2>Scope</h2><p>This policy applies only to the web properties listed below; devices and firmware are no longer covered.</p><ul><li>www.${d}</li><li>account.${d}</li></ul>
<p>Devices and firmware are out of scope.</p>
<h2>Authorization</h2><p>You are authorized to test only the web properties listed in this policy.</p>
${reporting}
${safeHarbor}
${disclosure}`,
      )
    }
    case 'PLATFORM':
      return page(
        `${v.name} Vulnerability Disclosure Program`,
        `<h1>${name} Vulnerability Disclosure Program</h1><p>Program last updated 2025-11-03</p>
<p>In scope: ${v.products.map(escapeHtml).join(', ')} and ${d} web properties.</p>
<p>${name} authorizes good-faith security testing of in-scope assets.</p>
<p>Submit findings through this platform&rsquo;s report form.</p>
<p>${name} will not take legal action against researchers who follow this policy.</p>
<p>Reporters may publish their findings 90 days after submission or once a fix is released.</p>
<h2>What to include</h2><p>A good report describes the issue, the affected product and version, and the steps needed to reproduce it.</p>
<p>We aim to acknowledge each report within five business days and to keep the reporter informed of our progress until the issue is resolved.</p>
<p>Thank you for helping us protect our customers and their data.</p>`,
      )
  }
}

function securityTxt(v: VendorSpec, fetchedMs: number): string | null {
  if (v.vdp === 'NONE' || v.vdp === 'OLD_NO_STXT') return null
  const expires = v.vdp === 'UNDATED_EXPIRED' ? COPPERLEAF_EXPIRES.replace('T00:00:00Z', 'T00:00:00.000Z') : iso(fetchedMs - (fetchedMs % DAY) + 200 * DAY)
  const lines = [
    `# Security contact for ${v.name} (synthetic demo data)`,
    `Contact: mailto:security@${v.domain}`,
    `Contact: https://${v.domain}/security/report`,
    `Expires: ${expires}`,
    `Encryption: https://${v.domain}/security/pgp-key.txt`,
    'Preferred-Languages: en',
    `Canonical: https://${v.domain}/.well-known/security.txt`,
    `Policy: ${policyUrl(v)}`,
  ]
  if (v.csaf) lines.push(`CSAF: https://${v.domain}/.well-known/csaf/provider-metadata.json`)
  if (v.id === 'halcyon-cloud') {
    return ['-----BEGIN PGP SIGNED MESSAGE-----', 'Hash: SHA256', '', ...lines, '-----BEGIN PGP SIGNATURE-----', '', 'c3ludGhldGljIHNpZ25hdHVyZSBmb3IgZGVtbyBkYXRh', '=demo', '-----END PGP SIGNATURE-----', ''].join('\n')
  }
  return lines.join('\n') + '\n'
}

// ------------------------------------------------------------------ signer page

function signerPage(version: string): string {
  const listed = VENDORS.filter((v) => !v.listedFrom || v.listedFrom <= version).map((v) => v.listing)
  const names = [...listed, ...FILLER_SIGNATORIES].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase(), 'en'))
  const declared = version === COUNT_MISMATCH_VERSION ? names.length + 1 : names.length
  const cells = names.map((n, i) => `<td>${escapeHtml(n)}${i % 17 === 5 ? '&nbsp;' : ''}</td>`)
  while (cells.length % 7 !== 0) cells.push('<td>&nbsp;</td>')
  const rows: string[] = []
  for (let i = 0; i < cells.length; i += 7) rows.push(`<tr>${cells.slice(i, i + 7).join('')}</tr>`)
  return `<!DOCTYPE html>
<html lang="en" dir="ltr">
<head>
<meta charset="utf-8" />
<link rel="canonical" href="https://cisa-pledge.example/securebydesign/pledge/secure-design-pledge-signers" />
<title>Secure by Design Pledge Signers (synthetic)</title>
<script>var dataLayer = [];</script>
</head>
<body>
<div class="c-page-title"><h1>Secure by Design Pledge Signers</h1></div>
<div class="l-full__main">
<div class="c-field c-field--name-body"><p>Synthetic demo page modelled on the structure of the CISA signer list. All names are fictional.</p></div>
<div class="c-field">
  <div class="c-field__content"><h4>${declared} Companies</h4><table><tbody>${rows.join('')}</tbody></table></div></div>
</div>
</body>
</html>
`
}

// ------------------------------------------------------------------ registry

function registry(): Vendor[] {
  const ev = (statement: string, url: string) => [{ statement, url }]
  return VENDORS.map((v) => {
    const aliases: Alias[] = [
      { kind: 'LEGAL_NAME', value: v.legalName, confidence: 'HIGH', evidence: ev('Legal name on the company imprint.', `https://${v.domain}/legal/imprint`) },
      { kind: 'BRAND', value: v.name, confidence: 'HIGH', evidence: ev('Brand used on the company website.', `https://${v.domain}/`) },
      { kind: 'SIGNATORY_LISTING', value: v.listing, confidence: 'HIGH', evidence: ev('Name as printed on the signer list.', 'https://cisa-pledge.example/securebydesign/pledge/secure-design-pledge-signers') },
      ...v.affectedNames.map((n): Alias => ({ kind: 'AFFECTED_VENDOR', value: n, confidence: n === v.name ? 'HIGH' : 'MEDIUM', evidence: ev(`"${n}" is used for ${v.name} products in CVE affected[] entries.`, `https://${v.domain}/security/advisories`) })),
      ...v.cpeVendors.map((c): Alias => ({
        kind: 'CPE_VENDOR',
        value: c,
        confidence: 'HIGH',
        evidence: ev(v.id === 'ferrous-industrial' && c === 'kestrel' ? 'Ferrous Industrial acquired the Kestrel controller product line and publishes its CPEs under "kestrel".' : `CPE vendor namespace used in ${v.name} records.`, v.id === 'ferrous-industrial' && c === 'kestrel' ? 'https://ferrous.example/news/kestrel-acquisition' : `https://${v.domain}/security/advisories`),
      })),
      { kind: 'ADVISORY_DOMAIN', value: v.domain, confidence: 'HIGH', evidence: ev('Advisories are published on this domain.', `https://${v.domain}/security/advisories`) },
    ]
    if (v.cna) {
      aliases.push(
        { kind: 'CNA_SHORT_NAME', value: v.cna.shortName, confidence: 'HIGH', evidence: ev(`${v.name} is a CNA with this short name.`, 'https://cve.example/partners') },
        { kind: 'CNA_ORG_ID', value: cnaOrg(v.cna.shortName), confidence: 'HIGH', evidence: ev('CNA organisation id in the partner list.', 'https://cve.example/partners') },
      )
    }
    const vendor: Vendor = {
      id: v.id,
      canonicalName: v.name,
      aliases,
      signatoryStatus: 'UNKNOWN',
      category: v.category,
      // A shared disclosure platform is never one of the vendor's domains; the program URL is tied
      // to the vendor through vdpPolicyUrl instead.
      domains: [v.domain],
      claims: [],
      synthetic: true,
    }
    if (v.signedOn) vendor.signedOn = v.signedOn
    if (v.sizeBand) vendor.sizeBand = v.sizeBand
    if (v.region) vendor.region = v.region
    if (v.industry) vendor.industry = v.industry
    if (v.csaf) vendor.csafProviderUrl = `https://${v.domain}/.well-known/csaf/provider-metadata.json`
    if (v.vdp !== 'NONE') vendor.vdpPolicyUrl = policyUrl(v)
    if (v.id === 'northwind-systems') {
      vendor.claims.push({ goalId: 'G1', summary: 'Vendor states MFA is enabled by default for all new administrator accounts.', url: 'https://northwind.example/blog/secure-by-design-progress', publishedOn: '2025-05-08' })
    }
    if (v.id === 'halcyon-cloud') {
      vendor.claims.push({ goalId: 'G2', summary: 'Vendor states default passwords were removed from all appliance images.', url: 'https://halcyon.example/trust/pledge', publishedOn: '2025-06-02' })
    }
    return vendor
  })
}

// ------------------------------------------------------------------ sources and manifests

type ManifestSnapshot = {
  id: string
  kind: 'CISA_SIGNERS' | 'CVE_RECORD' | 'CSAF_ADVISORY' | 'SECURITY_TXT' | 'VDP_POLICY'
  vendorId?: string
  sourceId: string
  url: string
  fetchedAt: string
  status: 'OK' | 'FAILED' | 'REJECTED'
  httpStatus?: number
  contentType?: string
  sha256?: string
  bytes?: number
  file?: string
  error?: string
  substitutedBy?: string
}

function sources(): SourceRef[] {
  const out: SourceRef[] = [
    { id: 'cisa.signers', family: 'CISA_PLEDGE', title: 'Secure by Design Pledge signers (synthetic page)', url: 'https://cisa-pledge.example/securebydesign/pledge/secure-design-pledge-signers', publisher: 'Synthetic demo source', attribution: 'Synthetic page modelled on the CISA signer list structure. Fictional names.', retention: 'RAW' },
    { id: 'cve.record', family: 'CVE_PROGRAM', title: 'CVE records (synthetic CVE JSON 5.1)', url: 'https://cve.example/api/cve/{id}', publisher: 'Synthetic demo source', attribution: 'Synthetic records in CVE JSON 5.1 format. DEMO ids are not CVE ids.', retention: 'RAW' },
    { id: 'cve.mirror', family: 'CVE_PROGRAM', title: 'CVE bulk mirror (synthetic)', url: 'https://cve-mirror.example/records/{id}.json', publisher: 'Synthetic demo source', attribution: 'Synthetic third-party mirror; used to exercise duplicate and legacy-format handling.', retention: 'RAW' },
  ]
  for (const v of VENDORS) {
    out.push({ id: `vendor.${v.id}.security-txt`, family: 'SECURITY_TXT', title: `${v.name} security.txt`, url: `https://${v.domain}/.well-known/security.txt`, publisher: v.name, attribution: 'Synthetic demo data.', retention: 'RAW' })
    if (v.vdp !== 'NONE') out.push({ id: `vendor.${v.id}.vdp`, family: 'VENDOR_VDP', title: `${v.name} vulnerability disclosure policy`, url: policyUrl(v), publisher: v.name, attribution: 'Synthetic demo data.', retention: 'RAW' })
    if (v.csaf) out.push({ id: `vendor.${v.id}.csaf`, family: 'VENDOR_ADVISORY', title: `${v.name} CSAF advisories`, url: `https://${v.domain}/.well-known/csaf/provider-metadata.json`, publisher: v.name, attribution: 'Synthetic demo data.', retention: 'RAW' })
  }
  return out
}

/** Deterministic fetch time on a version day (01:00-05:59 UTC). */
function fetchTime(version: string, key: string, daysBefore = 0): number {
  const r = rngFor(`fetch:${version}:${key}`)
  return versionMs(version) - daysBefore * DAY + 3600_000 + Math.floor(r() * 5 * 3600) * 1000
}

// ------------------------------------------------------------------ build

type Files = Map<string, string>

function stableJson(v: unknown): string {
  return JSON.stringify(v)
}

export function build(): Files {
  const files: Files = new Map()
  const put = (path: string, content: string) => files.set(path, content)
  const recs = allRecords()
  const advs = advisories(recs)
  const srcs = sources()

  put('registry/vendors.json', JSON.stringify(registry(), null, 2) + '\n')

  const policySnapshotByVersion = new Map<string, Map<string, ManifestSnapshot>>()

  for (const version of DATASET_VERSIONS) {
    const vms = versionMs(version)
    const snaps: ManifestSnapshot[] = []
    const addFile = (path: string, content: string) => {
      put(path, content)
      return { sha256: sha256Text(content), bytes: Buffer.byteLength(content, 'utf8') }
    }

    // Signer page.
    {
      const html = signerPage(version)
      const file = `${version}/cisa/signers.html`
      const { sha256, bytes } = addFile(file, html)
      const url = srcs[0]!.url
      snaps.push({ id: snapshotId('cisa.signers', url, sha256), kind: 'CISA_SIGNERS', sourceId: 'cisa.signers', url, fetchedAt: iso(fetchTime(version, 'signers')), status: 'OK', httpStatus: 200, contentType: 'text/html; charset=utf-8', sha256, bytes, file })
    }

    // CVE records published before the version date.
    for (const rec of recs) {
      if (rec.published >= vms) continue
      if (rec.legacy && version < LEGACY_RECORD_FROM) continue
      const content = stableJson(recordJson(rec, version)) + '\n'
      const sha256 = sha256Text(content)
      const file = `records/cve/${rec.id}-${sha256.slice(0, 8)}.json`
      put(file, content)
      const bytes = Buffer.byteLength(content, 'utf8')
      const fetchedAt = iso(fetchTime(version, `cve:${rec.id}`))
      const sourceId = rec.legacy ? 'cve.mirror' : 'cve.record'
      const url = rec.legacy ? `https://cve-mirror.example/records/${rec.id}.json` : `https://cve.example/api/cve/${rec.id}`
      snaps.push({ id: snapshotId(sourceId, url, sha256), kind: 'CVE_RECORD', sourceId, url, fetchedAt, status: 'OK', httpStatus: 200, contentType: 'application/json', sha256, bytes, file })
      if (rec.mirror) {
        const mirrorContent = rec.mirror === 'IDENTICAL' ? content : stableJson(recordJson(rec, version, 'MIRROR_CONFLICT')) + '\n'
        const msha = sha256Text(mirrorContent)
        const mfile = `records/cve/${rec.id}-${msha.slice(0, 8)}.json`
        put(mfile, mirrorContent)
        const murl = `https://cve-mirror.example/records/${rec.id}.json`
        snaps.push({ id: snapshotId('cve.mirror', murl, msha), kind: 'CVE_RECORD', sourceId: 'cve.mirror', url: murl, fetchedAt: iso(fetchTime(version, `mirror:${rec.id}`)), status: 'OK', httpStatus: 200, contentType: 'application/json', sha256: msha, bytes: Buffer.byteLength(mirrorContent, 'utf8'), file: mfile })
      }
    }

    // Per-vendor sources.
    const policyByVendor = new Map<string, ManifestSnapshot>()
    for (const v of VENDORS) {
      const stale = v.staleDays ?? 0
      // CSAF advisories released before the (possibly stale) fetch time.
      if (v.csaf) {
        const fetchedMs = fetchTime(version, `csaf:${v.id}`, stale)
        for (const a of advs.filter((x) => x.vendorId === v.id && x.released < fetchedMs - (fetchedMs % DAY))) {
          const content = JSON.stringify(csafJson(a)) + '\n'
          const file = `records/csaf/${v.id}/${a.trackingId.toLowerCase()}.json`
          const { sha256, bytes } = addFile(file, content)
          const url = `https://${v.domain}/.well-known/csaf/${new Date(a.released).getUTCFullYear()}/${a.trackingId.toLowerCase()}.json`
          snaps.push({ id: snapshotId(`vendor.${v.id}.csaf`, url, sha256), kind: 'CSAF_ADVISORY', vendorId: v.id, sourceId: `vendor.${v.id}.csaf`, url, fetchedAt: iso(fetchedMs), status: 'OK', httpStatus: 200, contentType: 'application/json', sha256, bytes, file })
        }
      }
      // security.txt (404 recorded as an OK observation of absence).
      {
        const fetchedMs = fetchTime(version, `stxt:${v.id}`, stale)
        const url = `https://${v.domain}/.well-known/security.txt`
        const sourceId = `vendor.${v.id}.security-txt`
        const text = securityTxt(v, fetchedMs)
        if (text === null) {
          snaps.push({ id: snapshotId(sourceId, url, sha256Text('')), kind: 'SECURITY_TXT', vendorId: v.id, sourceId, url, fetchedAt: iso(fetchedMs), status: 'OK', httpStatus: 404, sha256: sha256Text(''), bytes: 0 })
        } else {
          const file = `${version}/vdp/${v.id}/security.txt`
          const { sha256, bytes } = addFile(file, text)
          snaps.push({ id: snapshotId(sourceId, url, sha256), kind: 'SECURITY_TXT', vendorId: v.id, sourceId, url, fetchedAt: iso(fetchedMs), status: 'OK', httpStatus: 200, contentType: 'text/plain; charset=utf-8', sha256, bytes, file })
        }
      }
      // Policy page.
      const html = policyHtml(v, version)
      if (html !== null) {
        const url = policyUrl(v)
        const sourceId = `vendor.${v.id}.vdp`
        const fetchedMs = fetchTime(version, `vdp:${v.id}`, stale)
        if (v.policyFetchFailsIn === version) {
          const prevVersion = DATASET_VERSIONS[DATASET_VERSIONS.indexOf(version) - 1]!
          const prev = policySnapshotByVersion.get(prevVersion)?.get(v.id)
          if (!prev) throw new Error(`no previous policy snapshot for ${v.id}`)
          snaps.push({ ...prev })
          const failedAt = iso(fetchedMs)
          snaps.push({ id: failedSnapshotId(sourceId, url, failedAt), kind: 'VDP_POLICY', vendorId: v.id, sourceId, url, fetchedAt: failedAt, status: 'FAILED', error: 'Timed out after 20000 ms waiting for a response (synthetic failure).', substitutedBy: prev.id })
          policyByVendor.set(v.id, prev)
        } else {
          const file = `${version}/vdp/${v.id}/policy.html`
          const { sha256, bytes } = addFile(file, html)
          const s: ManifestSnapshot = { id: snapshotId(sourceId, url, sha256), kind: 'VDP_POLICY', vendorId: v.id, sourceId, url, fetchedAt: iso(fetchedMs), status: 'OK', httpStatus: 200, contentType: 'text/html; charset=utf-8', sha256, bytes, file }
          snaps.push(s)
          policyByVendor.set(v.id, s)
        }
      }
    }
    policySnapshotByVersion.set(version, policyByVendor)

    snaps.sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.url < b.url ? -1 : a.url > b.url ? 1 : a.fetchedAt < b.fetchedAt ? -1 : 1))
    const manifest = {
      datasetVersion: version,
      asOf: `${version}T12:00:00Z`,
      methodologyVersion: version >= '2026-06-15' ? '1.1.0' : '1.0.0',
      synthetic: true,
      generator: `scripts/demo/generate.ts (seed ${SEED})`,
      sources: srcs,
      snapshots: snaps,
    }
    // One snapshot per line keeps the manifest diffable and small.
    const head = JSON.stringify({ ...manifest, sources: [], snapshots: [] }, null, 2)
    const body = head
      .replace('"sources": []', `"sources": [\n${srcs.map((s) => '    ' + JSON.stringify(s)).join(',\n')}\n  ]`)
      .replace('"snapshots": []', `"snapshots": [\n${snaps.map((s) => '    ' + JSON.stringify(s)).join(',\n')}\n  ]`)
    put(`${version}/manifest.json`, body + '\n')
  }

  put('SCENARIOS.md', scenariosMd(recs))
  return files
}

function scenariosMd(recs: RecSpec[]): string {
  const lines: string[] = [
    '# TOUCHSTONE demo dataset: scenarios',
    '',
    'Generated by `node scripts/demo/generate.ts` (deterministic, seed ' + SEED + '). Everything here is **synthetic**: fictional',
    'vendors, `.example` URLs, `DEMO-YYYY-NNNN` record ids. Do not edit by hand; change `scripts/demo/vendors.ts` and regenerate.',
    '',
    `Dataset versions: ${DATASET_VERSIONS.join(', ')}. Methodology 1.0.0 applies before 2026-06-15 (first three versions),`,
    '1.1.0 from 2026-07-06 (placeholder CWEs stop counting as populated).',
    '',
    'Expected outcomes below are stated at the level the pipeline determines (attribution, field gaps, VDP criterion',
    'states); the "Goal" lines are the intended reading under the scoring rules in docs/methodology.md.',
    '',
    '## Vendors',
    '',
    '| Vendor | Category | Scenario | Expected outcome |',
    '|---|---|---|---|',
  ]
  const cell = (s: string) => s.replace(/\|/g, '\\|')
  for (const v of VENDORS) {
    const n = recs.filter((r) => r.vendorId === v.id && r.state === 'PUBLISHED').length
    lines.push(`| \`${v.id}\` ${cell(v.name)} | ${v.category} | ${cell(v.scenario)} (${n} records generated) | ${v.expected.map(cell).join('<br>')} |`)
  }
  const ambiguous = recs.filter((r) => r.key.startsWith('ambiguous:')).map((r) => r.id)
  const freeText = recs.filter((r) => r.key.startsWith('freetext:')).map((r) => r.id)
  const rejected = recs.filter((r) => r.state === 'REJECTED').map((r) => r.id)
  const legacy = recs.filter((r) => r.legacy).map((r) => r.id)
  const unrelated = recs.filter((r) => r.key.startsWith('unrelated:')).map((r) => r.id)
  const dupConf = recs.filter((r) => r.mirror === 'CONFLICTING').map((r) => r.id)
  const dupSame = recs.filter((r) => r.mirror === 'IDENTICAL').map((r) => r.id)
  lines.push(
    '',
    '## Dataset-level scenarios',
    '',
    '| Scenario | Records / versions | Expected outcome |',
    '|---|---|---|',
    `| Ambiguous attribution: third-party CNA, affected vendor "Summit" only | ${ambiguous.join(', ')} | AMBIGUOUS_VENDOR, candidates summit-analytics + summit-peak-software |`,
    `| Free text only: title names Northwind Systems, structured fields name "Unlisted Widgets Co" | ${freeText.join(', ')} | FREE_TEXT_ONLY exclusion (candidate northwind-systems); never attributed |`,
    `| Unregistered vendor ("Hollowmere Apps") | ${unrelated.join(', ')} | no attribution, no exclusion |`,
    `| REJECTED records from vendor CNAs | ${rejected.join(', ')} | REJECTED_RECORD exclusion |`,
    `| Duplicate ids, conflicting content (Quillmark, cve.mirror) | ${dupConf.join(', ')} | DUPLICATE_CONFLICT, all copies excluded |`,
    `| Duplicate ids, identical content (Quillmark, cve.mirror) | ${dupSame.join(', ')} | collapsed to one record; attributed normally |`,
    `| Legacy CVE JSON 4.0 document on the mirror | ${legacy.join(', ')} (from ${LEGACY_RECORD_FROM}) | normalizer rejects it; snapshot status REJECTED with the parser error |`,
    `| Identity conflict: CPE namespace "kestrel" registered for two vendors | all versions | IdentityConflict CPE_NAMESPACE_SHARED; Kestrel records with a kestrel CPE excluded as IDENTITY_CONFLICT |`,
    `| Signer page declared count lags the table | ${COUNT_MISMATCH_VERSION} | parseSignerList warning COUNT_MISMATCH (declared = parsed + 1); both counts published |`,
    `| Late signer | 2025-10-06 | foxglove-identity NOT_LISTED; LISTED from 2026-01-06 |`,
    `| CISA-ADP enrichment arrives 30 days after publication | all versions | larkspur-cloud records newer than 30 days have no ADP container; older ones carry CISA-ADP CWE/CPE |`,
    `| Methodology change 1.0.0 -> 1.1.0 | 2026-07-06 | lanternfish-security CWE coverage drops; earlier runs unchanged |`,
    `| Source failure with explicit substitution | 2026-10-06 | wrenfield-software policy snapshot FAILED, substitutedBy the 2026-07-06 snapshot; observation carriedFromSnapshotId |`,
    `| Stale sources | all versions | palisade-mobile VDP, security.txt and CSAF fetched 52 days before the version date |`,
    `| VDP change | 2026-07-06 | ember-oak-devices scope and testing authorization narrow (MET -> PARTIAL) |`,
    `| Expired security.txt | 2026-04-06 onward | copperleaf-learning CURRENT NOT_MET |`,
    '',
    '## Regenerating',
    '',
    '```',
    'node scripts/demo/generate.ts           # write fixtures/demo/**',
    'node scripts/demo/generate.ts --check   # verify the committed files match the generator',
    '```',
    '',
  )
  return lines.join('\n')
}

// ------------------------------------------------------------------ main

function listFiles(dir: string): string[] {
  if (!existsSync(dir)) return []
  return readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name))
}

const isMain = process.argv[1] !== undefined && resolve(fileURLToPath(import.meta.url)).toLowerCase() === resolve(process.argv[1]).toLowerCase()
if (isMain) {
  const root = fileURLToPath(new URL('../../fixtures/demo/', import.meta.url))
  const check = process.argv.includes('--check')
  const files = build()
  const owned = [join(root, 'registry'), join(root, 'records'), join(root, 'SCENARIOS.md'), ...DATASET_VERSIONS.map((v) => join(root, v))]
  if (check) {
    const problems: string[] = []
    for (const [rel, content] of files) {
      const p = join(root, rel)
      if (!existsSync(p)) problems.push(`missing: ${rel}`)
      else if (readFileSync(p, 'utf8') !== content) problems.push(`differs: ${rel}`)
    }
    for (const dir of owned) {
      for (const p of existsSync(dir) && !dir.endsWith('.md') ? listFiles(dir) : []) {
        const rel = relative(root, p).split('\\').join('/')
        if (!files.has(rel)) problems.push(`stale: ${rel}`)
      }
    }
    if (problems.length > 0) {
      console.error(`fixtures/demo is out of date (${problems.length} problems). Run: node scripts/demo/generate.ts`)
      for (const p of problems.slice(0, 20)) console.error(`  ${p}`)
      process.exit(1)
    }
    console.log(`fixtures/demo up to date: ${files.size} files`)
  } else {
    for (const p of owned) rmSync(p, { recursive: true, force: true })
    let bytes = 0
    for (const [rel, content] of files) {
      const p = join(root, rel)
      mkdirSync(dirname(p), { recursive: true })
      writeFileSync(p, content)
      bytes += Buffer.byteLength(content, 'utf8')
    }
    console.log(`wrote ${files.size} files (${(bytes / 1024 / 1024).toFixed(2)} MB) to fixtures/demo`)
  }
}
