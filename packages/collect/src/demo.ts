/**
 * Demo dataset loader.
 *
 * Reads the RAW synthetic source documents under fixtures/demo/<version>/
 * (written by scripts/demo/generate.ts) and runs them through the same core
 * normalizers the live collectors use: parseSignerList + matchSignatories,
 * normalizeCveRecord, normalizeCsafAdvisory, parseSecurityTxt, htmlToText and
 * assessVdp. The demo therefore exercises the real parsing path; nothing is
 * pre-digested.
 *
 * Integrity: every file's sha256 is checked against the manifest and the
 * snapshot id is recomputed. A mismatch throws (the dataset was edited by
 * hand, or the generator and manifest disagree).
 */

import { existsSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import type {
  Advisory,
  CveRecord,
  HistoricalPoint,
  RunInputs,
  SecurityTxt,
  Snapshot,
  SnapshotStatus,
  SourceRef,
  VdpObservation,
  Vendor,
} from '../../core/src/model/index.ts'
import { methodologyVersion } from '../../core/src/methodology/versions.ts'
import { normalizeCveRecord } from '../../core/src/normalize/cve.ts'
import { normalizeCsafAdvisory } from '../../core/src/normalize/csaf.ts'
import { parseSecurityTxt } from '../../core/src/normalize/security-txt.ts'
import { parseSignerList } from '../../core/src/normalize/signers.ts'
import { failedSnapshotId, snapshotId } from '../../core/src/normalize/snapshot-id.ts'
import { matchSignatories } from '../../core/src/identity/index.ts'
import { htmlToText } from '../../core/src/text/html.ts'
import { assessVdp } from '../../core/src/vdp/assess.ts'
import { sha256 } from '../../core/src/util/sha256.ts'

export const DEMO_DATASET_VERSIONS: string[] = ['2025-10-06', '2026-01-06', '2026-04-06', '2026-07-06', '2026-10-06']

export type DemoManifestSnapshot = {
  id: string
  kind: 'CISA_SIGNERS' | 'CVE_RECORD' | 'CSAF_ADVISORY' | 'SECURITY_TXT' | 'VDP_POLICY'
  vendorId?: string
  sourceId: string
  url: string
  fetchedAt: string
  status: SnapshotStatus
  httpStatus?: number
  contentType?: string
  sha256?: string
  bytes?: number
  file?: string
  error?: string
  substitutedBy?: string
}

export type DemoManifest = {
  datasetVersion: string
  asOf: string
  methodologyVersion: string
  synthetic: boolean
  generator: string
  sources: SourceRef[]
  snapshots: DemoManifestSnapshot[]
}

/** Accept either the repository root or fixtures/demo itself. */
export function resolveDemoRoot(root: string): string {
  if (existsSync(join(root, 'registry', 'vendors.json'))) return resolve(root)
  const nested = resolve(root, 'fixtures', 'demo')
  if (existsSync(join(nested, 'registry', 'vendors.json'))) return nested
  throw new Error(`No demo dataset under ${root} (expected registry/vendors.json or fixtures/demo/registry/vendors.json)`)
}

const decoder = new TextDecoder('utf-8', { fatal: false })

type Loaded = {
  manifest: DemoManifest
  snapshots: Snapshot[]
  /** Raw text by snapshot id (OK snapshots with a file). */
  text: Map<string, string>
  entries: Map<string, DemoManifestSnapshot>
}

function loadVersion(root: string, datasetVersion: string, parserVersion: string): Loaded {
  if (!DEMO_DATASET_VERSIONS.includes(datasetVersion)) throw new Error(`Unknown demo dataset version ${datasetVersion}`)
  const manifest = JSON.parse(readFileSync(join(root, datasetVersion, 'manifest.json'), 'utf8')) as DemoManifest
  if (manifest.datasetVersion !== datasetVersion) throw new Error(`Manifest for ${datasetVersion} names ${manifest.datasetVersion}`)
  const snapshots: Snapshot[] = []
  const text = new Map<string, string>()
  const entries = new Map<string, DemoManifestSnapshot>()
  for (const e of manifest.snapshots) {
    if (e.file !== undefined && (e.file.includes('..') || e.file.startsWith('/') || e.file.includes(':'))) throw new Error(`Unsafe file path in manifest: ${e.file}`)
    let expectedId: string
    if (e.status === 'FAILED') {
      expectedId = failedSnapshotId(e.sourceId, e.url, e.fetchedAt)
    } else {
      if (e.file !== undefined) {
        const bytes = readFileSync(join(root, e.file))
        const actual = sha256(bytes)
        if (actual !== e.sha256) throw new Error(`sha256 mismatch for ${e.file}: manifest ${e.sha256}, file ${actual}`)
        text.set(e.id, decoder.decode(bytes))
      }
      expectedId = snapshotId(e.sourceId, e.url, e.sha256 ?? '')
    }
    if (expectedId !== e.id) throw new Error(`Snapshot id mismatch for ${e.url}: manifest ${e.id}, computed ${expectedId}`)
    const s: Snapshot = { id: e.id, sourceId: e.sourceId, url: e.url, fetchedAt: e.fetchedAt, status: e.status, parserVersion }
    if (e.httpStatus !== undefined) s.httpStatus = e.httpStatus
    if (e.contentType !== undefined) s.contentType = e.contentType
    if (e.sha256 !== undefined) s.sha256 = e.sha256
    if (e.bytes !== undefined) s.bytes = e.bytes
    if (e.file !== undefined) s.rawPath = e.file
    if (e.error !== undefined) s.error = e.error
    if (e.substitutedBy !== undefined) s.substitutedBy = e.substitutedBy
    // The same content can be served on two dataset dates (a carried snapshot); keep one entry per id.
    if (!entries.has(e.id)) {
      snapshots.push(s)
      entries.set(e.id, e)
    }
  }
  return { manifest, snapshots, text, entries }
}

function absentSecurityTxt(url: string, snapshotIdValue: string | undefined, warning: string): SecurityTxt {
  const s: SecurityTxt = { present: false, url, contacts: [], policyUrls: [], canonical: [], warnings: [warning], signed: false }
  if (snapshotIdValue) s.snapshotId = snapshotIdValue
  return s
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname
  } catch {
    return undefined
  }
}

function vdpObservations(loaded: Loaded, vendors: Vendor[], methodology: string): VdpObservation[] {
  const params = methodologyVersion(methodology).parameters
  const asOf = loaded.manifest.asOf
  const out: VdpObservation[] = []
  for (const v of vendors) {
    const mine = loaded.manifest.snapshots.filter((e) => e.vendorId === v.id)
    // security.txt
    const stxtEntry = mine.filter((e) => e.kind === 'SECURITY_TXT').sort((a, b) => (a.fetchedAt < b.fetchedAt ? 1 : -1))[0]
    let securityTxt: SecurityTxt
    let stxtObservedAt: string | undefined
    if (!stxtEntry) {
      securityTxt = absentSecurityTxt(`https://${v.domains[0] ?? 'unknown.example'}/.well-known/security.txt`, undefined, 'NOT_COLLECTED: no security.txt snapshot in this dataset version.')
    } else if (stxtEntry.status !== 'OK') {
      securityTxt = absentSecurityTxt(stxtEntry.url, stxtEntry.id, `FETCH_FAILED: ${stxtEntry.error ?? stxtEntry.status}`)
      stxtObservedAt = stxtEntry.fetchedAt
    } else if (stxtEntry.httpStatus === 404 || !loaded.text.has(stxtEntry.id)) {
      securityTxt = absentSecurityTxt(stxtEntry.url, stxtEntry.id, `NOT_FOUND: HTTP ${stxtEntry.httpStatus ?? 'no content'}.`)
      stxtObservedAt = stxtEntry.fetchedAt
    } else {
      securityTxt = parseSecurityTxt(loaded.text.get(stxtEntry.id)!, { url: stxtEntry.url, snapshotId: stxtEntry.id, asOf })
      stxtObservedAt = stxtEntry.fetchedAt
    }

    // Policy: the newest attempt decides; a FAILED attempt with substitutedBy is carried explicitly.
    const attempts = mine.filter((e) => e.kind === 'VDP_POLICY').sort((a, b) => (a.fetchedAt < b.fetchedAt ? 1 : -1))
    const latest = attempts[0]
    let policy: Parameters<typeof assessVdp>[0]['policy'] = { found: false }
    let carriedFrom: string | undefined
    let observedAt = stxtObservedAt ?? asOf
    if (latest) {
      let used = latest
      if (latest.status === 'FAILED' && latest.substitutedBy) {
        const sub = loaded.entries.get(latest.substitutedBy)
        if (!sub) throw new Error(`Snapshot ${latest.id} is substituted by ${latest.substitutedBy}, which is not in the manifest`)
        used = sub
        carriedFrom = sub.id
      }
      if (used.status === 'OK' && loaded.text.has(used.id)) {
        policy = { found: true, url: used.url, snapshotId: used.id, text: htmlToText(loaded.text.get(used.id)!).text }
        observedAt = used.fetchedAt
      } else if (used.status === 'OK' && used.httpStatus === 404) {
        policy = { found: false }
        observedAt = used.fetchedAt
      } else {
        policy = { found: true, url: used.url, snapshotId: used.id, fetchFailed: true }
        observedAt = used.fetchedAt
      }
      const host = hostOf(used.url)
      if (host) policy.host = host
    }
    const obs = assessVdp({ vendorId: v.id, observedAt, asOf, securityTxt, policy, params })
    if (carriedFrom) obs.carriedFromSnapshotId = carriedFrom
    out.push(obs)
  }
  return out
}

/**
 * Build RunInputs for one demo dataset version from its raw files.
 * `root` may be the repository root or fixtures/demo.
 */
export function loadDemoInputs(opts: { root: string; datasetVersion: string; methodologyVersion: string; history: HistoricalPoint[] }): RunInputs {
  const root = resolveDemoRoot(opts.root)
  const mv = methodologyVersion(opts.methodologyVersion)
  const loaded = loadVersion(root, opts.datasetVersion, mv.parserVersion)
  const vendors = JSON.parse(readFileSync(join(root, 'registry', 'vendors.json'), 'utf8')) as Vendor[]
  const snapshotById = new Map(loaded.snapshots.map((s) => [s.id, s]))
  const reject = (id: string, error: string) => {
    const s = snapshotById.get(id)
    if (s) {
      s.status = 'REJECTED'
      s.error = error
    }
  }

  // Signatory status from the signer page.
  let signatoryList: RunInputs['signatoryList']
  const signerEntry = loaded.manifest.snapshots.find((e) => e.kind === 'CISA_SIGNERS' && e.status === 'OK' && loaded.text.has(e.id))
  if (signerEntry) {
    const parsed = parseSignerList(loaded.text.get(signerEntry.id)!)
    const { matched } = matchSignatories(parsed.names, vendors)
    const listed = new Set(matched.map((m) => m.vendorId))
    for (const v of vendors) v.signatoryStatus = listed.has(v.id) ? 'LISTED' : 'NOT_LISTED'
    signatoryList = { declaredCount: parsed.declaredCount, parsedCount: parsed.names.length, snapshotId: signerEntry.id, warnings: parsed.warnings }
  } else {
    for (const v of vendors) v.signatoryStatus = 'UNKNOWN'
  }

  // CVE records.
  const cves: CveRecord[] = []
  for (const e of loaded.manifest.snapshots) {
    if (e.kind !== 'CVE_RECORD' || e.status !== 'OK') continue
    const raw = loaded.text.get(e.id)
    if (raw === undefined) continue
    let json: unknown
    try {
      json = JSON.parse(raw)
    } catch (err) {
      reject(e.id, `JSON parse error: ${(err as Error).message.slice(0, 200)}`)
      continue
    }
    const r = normalizeCveRecord(json, { snapshotId: e.id, synthetic: true })
    if (r.ok) cves.push(r.record)
    else reject(e.id, `CVE normalizer: ${r.error}`)
  }

  // CSAF advisories.
  const advisories: Advisory[] = []
  for (const e of loaded.manifest.snapshots) {
    if (e.kind !== 'CSAF_ADVISORY' || e.status !== 'OK' || !e.vendorId) continue
    const raw = loaded.text.get(e.id)
    if (raw === undefined) continue
    let json: unknown
    try {
      json = JSON.parse(raw)
    } catch (err) {
      reject(e.id, `JSON parse error: ${(err as Error).message.slice(0, 200)}`)
      continue
    }
    const r = normalizeCsafAdvisory(json, { vendorId: e.vendorId, snapshotId: e.id, url: e.url, synthetic: true })
    if (r.ok) advisories.push(r.advisory)
    else reject(e.id, `CSAF normalizer: ${r.error}`)
  }

  const vdp = vdpObservations(loaded, vendors, opts.methodologyVersion)
  const idx = DEMO_DATASET_VERSIONS.indexOf(opts.datasetVersion)
  const previousVersion = idx > 0 ? DEMO_DATASET_VERSIONS[idx - 1] : undefined
  const previousVdp = previousVersion ? vdpObservations(loadVersion(root, previousVersion, mv.parserVersion), vendors, opts.methodologyVersion) : []

  const byId = (a: { id: string }, b: { id: string }) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0)
  cves.sort((a, b) => byId(a, b) || (a.snapshotId < b.snapshotId ? -1 : a.snapshotId > b.snapshotId ? 1 : 0))
  advisories.sort((a, b) => byId(a, b) || (a.vendorId < b.vendorId ? -1 : 1))
  vendors.sort(byId)
  loaded.snapshots.sort(byId)

  return {
    mode: 'DEMO',
    datasetVersion: opts.datasetVersion,
    asOf: loaded.manifest.asOf,
    methodologyVersion: opts.methodologyVersion,
    vendors,
    cves,
    advisories,
    vdp,
    previousVdp,
    snapshots: loaded.snapshots,
    sources: [...loaded.manifest.sources].sort(byId),
    history: opts.history,
    ...(signatoryList ? { signatoryList } : {}),
  }
}
