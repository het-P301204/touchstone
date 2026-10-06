/**
 * CVE JSON 5.x normalization (dataVersion 5.0, 5.1, 5.1.x, 5.2).
 *
 * The manufacturer's own data is `containers.cna`; third parties (CISA-ADP
 * "Vulnrichment", the CVE Program container, others) add data in
 * `containers.adp[]`. The two are kept apart here so the pledge metric can
 * credit CNA-supplied CWE and CPE only, and report enrichment separately.
 *
 * CPEs are read from both places the schema allows:
 *   - affected[].cpes                          (5.0+)
 *   - cpeApplicability[].nodes[].cpeMatch[].criteria  (5.1.1+)
 * in the CNA container and in each ADP container.
 *
 * Nothing in a record's free text (descriptions, titles) is interpreted.
 */

import type { ContainerData, CpeRef, CveRecord, CveState, CvssRef, CweRef, FieldGap, Severity } from '../model/index.ts'
import { cleanText } from '../util/sanitize.ts'
import { sha256Text } from '../util/sha256.ts'
import { arr, canonicalStringify, isObject, isoDate, num, own, str } from './json.ts'

export const CVE_ID_PATTERN = /^CVE-\d{4}-\d{4,}$/
export const DEMO_ID_PATTERN = /^DEMO-\d{4}-\d{4,}$/

/** CWE placeholders: present in a record, but stating that no weakness was identified. */
export const CWE_PLACEHOLDERS: readonly string[] = ['NVD-CWE-noinfo', 'NVD-CWE-Other']

const MAX_TEXT = 500
const MAX_AFFECTED = 2_000
const MAX_CPES_PER_CONTAINER = 5_000

// ------------------------------------------------------------------ CWE

const CWE_PREFIX = /^CWE-(\d{1,7})(?=$|[\s:,;(])/i

/**
 * Parse a CWE reference as written in a record ("CWE-79", "CWE-79: Improper
 * Neutralization...", "NVD-CWE-noinfo"). Placeholders are recognised and
 * flagged; anything else that is not a CWE id has `id: null` (MALFORMED).
 */
export function parseCwe(raw: string): CweRef {
  const text = cleanText(String(raw)).trim().slice(0, MAX_TEXT)
  const placeholder = CWE_PLACEHOLDERS.find((p) => p.toLowerCase() === text.toLowerCase())
  if (placeholder) return { raw: text, id: null, placeholder: true }
  const m = CWE_PREFIX.exec(text)
  if (m) {
    const n = Number(m[1])
    if (n > 0) return { raw: text, id: `CWE-${n}`, placeholder: false }
  }
  return { raw: text, id: null, placeholder: false }
}

/**
 * The field gap for a container's CWE list, or null when at least one usable
 * CWE is present. Placeholder handling is a methodology parameter.
 */
export function cweFieldGap(cwes: CweRef[], placeholderCountsAsPopulated: boolean): FieldGap | null {
  if (cwes.length === 0) return 'NOT_PROVIDED'
  if (cwes.some((c) => c.id !== null)) return null
  if (cwes.some((c) => c.placeholder)) return placeholderCountsAsPopulated ? null : 'PLACEHOLDER'
  return 'MALFORMED'
}

// ------------------------------------------------------------------ CPE

/**
 * Split a CPE 2.3 formatted string on unescaped colons. Linear; a backslash
 * escapes the next character. Escapes are removed from the returned parts.
 */
function splitCpe(raw: string): string[] | null {
  const parts: string[] = []
  let cur = ''
  for (let i = 0; i < raw.length; i++) {
    const ch = raw[i]!
    if (ch === '\\') {
      const next = raw[i + 1]
      if (next === undefined) return null
      cur += next
      i++
    } else if (ch === ':') {
      parts.push(cur)
      cur = ''
    } else {
      cur += ch
    }
  }
  parts.push(cur)
  return parts
}

function hasBadChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i)
    if (c <= 0x20 || c === 0x7f) return true
  }
  return false
}

/**
 * Parse a CPE 2.3 formatted string (cpe:2.3:part:vendor:product:version:update:
 * edition:language:sw_edition:target_sw:target_hw:other). A CPE 2.2 URI
 * ("cpe:/a:..."), a wrong component count, an unknown part, or a vendor or
 * product that is empty or a wildcard is not well-formed.
 */
export function parseCpe23(raw: string): CpeRef {
  const text = cleanText(String(raw)).trim()
  if (text.length === 0 || text.length > 1_000 || hasBadChar(text)) return { raw: text.slice(0, MAX_TEXT), wellFormed: false }
  const parts = splitCpe(text)
  if (!parts || parts.length !== 13 || parts[0]!.toLowerCase() !== 'cpe' || parts[1] !== '2.3') return { raw: text, wellFormed: false }
  const part = parts[2]!.toLowerCase()
  const vendor = parts[3]!.toLowerCase()
  const product = parts[4]!.toLowerCase()
  if (part !== 'a' && part !== 'o' && part !== 'h') return { raw: text, wellFormed: false }
  const concrete = (v: string) => v.length > 0 && v !== '*' && v !== '-' && !v.includes('*') && !v.includes('?')
  if (!concrete(vendor) || !concrete(product)) return { raw: text, wellFormed: false }
  return { raw: text, part, vendor, product, wellFormed: true }
}

/** The field gap for a container's CPE list, or null when at least one well-formed CPE is present. */
export function cpeFieldGap(cpes: CpeRef[]): FieldGap | null {
  if (cpes.length === 0) return 'NOT_PROVIDED'
  return cpes.some((c) => c.wellFormed) ? null : 'MALFORMED'
}

// ------------------------------------------------------------------ CVSS

const SEVERITIES: readonly Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE']

export function severityFromScore(score: number): Severity {
  if (score >= 9) return 'CRITICAL'
  if (score >= 7) return 'HIGH'
  if (score >= 4) return 'MEDIUM'
  if (score > 0) return 'LOW'
  return 'NONE'
}

export function severityRank(s: Severity): number {
  return s === 'CRITICAL' ? 5 : s === 'HIGH' ? 4 : s === 'MEDIUM' ? 3 : s === 'LOW' ? 2 : s === 'NONE' ? 1 : 0
}

function readCvss(metrics: unknown[], provider: CvssRef['provider']): CvssRef[] {
  const out: CvssRef[] = []
  const keys: [string, string][] = [
    ['cvssV4_0', '4.0'],
    ['cvssV3_1', '3.1'],
    ['cvssV3_0', '3.0'],
    ['cvssV2_0', '2.0'],
  ]
  for (const m of metrics) {
    for (const [key, version] of keys) {
      const c = own(m, key)
      if (!isObject(c)) continue
      const score = num(c, 'baseScore')
      if (score === undefined || score < 0 || score > 10) continue
      const sevRaw = (str(c, 'baseSeverity') ?? '').toUpperCase()
      const severity = (SEVERITIES as readonly string[]).includes(sevRaw) ? (sevRaw as Severity) : severityFromScore(score)
      out.push({ version, baseScore: score, severity, provider })
    }
  }
  return out
}

// ------------------------------------------------------------------ containers

function readCwes(container: unknown): CweRef[] {
  const out: CweRef[] = []
  const seen = new Set<string>()
  for (const pt of arr(container, 'problemTypes', 200)) {
    for (const d of arr(pt, 'descriptions', 200)) {
      const cweId = str(d, 'cweId')
      const type = str(d, 'type')
      const description = str(d, 'description')
      let candidate: string | undefined
      if (cweId !== undefined) candidate = cweId
      else if (description !== undefined && (type === 'CWE' || /^(?:NVD-)?CWE-/i.test(description.trim()))) candidate = description
      if (candidate === undefined) continue // free-text problem type: not a CWE statement
      const ref = parseCwe(candidate)
      const key = ref.id ?? ref.raw.toLowerCase()
      if (seen.has(key)) continue
      seen.add(key)
      out.push(ref)
    }
  }
  return out
}

function readCpes(container: unknown): CpeRef[] {
  const raws: string[] = []
  for (const a of arr(container, 'affected', MAX_AFFECTED)) {
    for (const c of arr(a, 'cpes', MAX_CPES_PER_CONTAINER)) if (typeof c === 'string') raws.push(c)
  }
  for (const app of arr(container, 'cpeApplicability', 500)) {
    for (const node of arr(app, 'nodes', 500)) {
      for (const match of arr(node, 'cpeMatch', MAX_CPES_PER_CONTAINER)) {
        const criteria = str(match, 'criteria')
        if (criteria !== undefined) raws.push(criteria)
      }
    }
  }
  const out: CpeRef[] = []
  const seen = new Set<string>()
  for (const raw of raws) {
    if (out.length >= MAX_CPES_PER_CONTAINER) break
    const ref = parseCpe23(raw)
    if (seen.has(ref.raw)) continue
    seen.add(ref.raw)
    out.push(ref)
  }
  return out
}

function readContainer(container: unknown, provider: string, cvssProvider: CvssRef['provider']): ContainerData {
  return {
    provider,
    cwes: readCwes(container),
    cpes: readCpes(container),
    cvss: readCvss(arr(container, 'metrics', 100), cvssProvider),
  }
}

function text(v: unknown): string | undefined {
  if (typeof v !== 'string') return undefined
  const t = cleanText(v).replace(/\s+/g, ' ').trim()
  return t.length === 0 ? undefined : t.slice(0, MAX_TEXT)
}

// ------------------------------------------------------------------ record

export type NormalizeCveResult = { ok: true; record: CveRecord } | { ok: false; error: string; cveId?: string }

const DATA_VERSION = /^5\.[0-2](?:\.\d{1,3})?$/

/**
 * Normalize one CVE JSON 5.x record. Rejects anything that is not a CVE
 * record (wrong dataType, unsupported dataVersion, malformed id, unknown
 * state) with an error instead of guessing.
 */
export function normalizeCveRecord(json: unknown, ctx: { snapshotId: string; synthetic: boolean }): NormalizeCveResult {
  if (!isObject(json)) return { ok: false, error: 'record is not a JSON object' }
  const meta = own(json, 'cveMetadata')
  const rawId = str(meta, 'cveId')
  const cveId = rawId === undefined ? undefined : rawId.trim()
  const fail = (error: string): NormalizeCveResult => (cveId !== undefined && cveId.length <= 40 ? { ok: false, error, cveId } : { ok: false, error })

  const dataType = str(json, 'dataType')
  if (dataType !== undefined && dataType !== 'CVE_RECORD') return fail(`unexpected dataType ${JSON.stringify(dataType.slice(0, 40))}`)
  if (own(json, 'data_version') !== undefined || own(json, 'CVE_data_meta') !== undefined) {
    const legacyId = str(own(json, 'CVE_data_meta'), 'ID')
    const e = `legacy CVE JSON ${JSON.stringify(String(own(json, 'data_version') ?? '4.x').slice(0, 10))} record; only CVE JSON 5.x is supported`
    return legacyId !== undefined && legacyId.length <= 40 ? { ok: false, error: e, cveId: legacyId } : { ok: false, error: e }
  }
  const dataVersion = str(json, 'dataVersion')
  if (dataVersion === undefined || !DATA_VERSION.test(dataVersion)) return fail(`unsupported dataVersion ${JSON.stringify(String(dataVersion ?? '').slice(0, 20))}`)
  if (!isObject(meta)) return fail('cveMetadata missing')
  if (cveId === undefined) return fail('cveMetadata.cveId missing')
  const idOk = CVE_ID_PATTERN.test(cveId) || (ctx.synthetic && DEMO_ID_PATTERN.test(cveId))
  if (!idOk) return fail(ctx.synthetic ? 'id is neither CVE-YYYY-NNNN nor DEMO-YYYY-NNNN' : 'id is not CVE-YYYY-NNNN')

  const stateRaw = str(meta, 'state')
  if (stateRaw !== 'PUBLISHED' && stateRaw !== 'REJECTED') return fail(`unknown state ${JSON.stringify(String(stateRaw ?? '').slice(0, 20))}`)
  const state: CveState = stateRaw

  const containers = own(json, 'containers')
  const cnaRaw = own(containers, 'cna')
  if (!isObject(cnaRaw)) return fail('containers.cna missing')

  // Distinct vendor/product pairs as written (a pair repeated per platform is listed once).
  const affected: { vendor: string; product: string }[] = []
  const seenPairs = new Set<string>()
  for (const a of arr(cnaRaw, 'affected', MAX_AFFECTED)) {
    const vendor = text(own(a, 'vendor'))
    const product = text(own(a, 'product'))
    if (vendor === undefined && product === undefined) continue
    const pair = JSON.stringify([vendor ?? '', product ?? ''])
    if (seenPairs.has(pair)) continue
    seenPairs.add(pair)
    affected.push({ vendor: vendor ?? '', product: product ?? '' })
  }

  const adp: ContainerData[] = []
  for (const c of arr(containers, 'adp', 50)) {
    if (!isObject(c)) continue
    const pm = own(c, 'providerMetadata')
    const provider = text(str(pm, 'shortName')) ?? text(str(pm, 'orgId')) ?? 'UNKNOWN-ADP'
    adp.push(readContainer(c, provider, 'ADP'))
  }

  const record: CveRecord = {
    id: cveId,
    state,
    assigner: {
      orgId: (str(meta, 'assignerOrgId') ?? '').trim().toLowerCase().slice(0, 64),
      shortName: text(str(meta, 'assignerShortName')) ?? '',
    },
    affected,
    cna: readContainer(cnaRaw, 'CNA', 'CNA'),
    adp,
    dataVersion,
    snapshotId: ctx.snapshotId,
    sourceHash: sha256Text(canonicalStringify(json)),
    synthetic: ctx.synthetic,
  }
  const dateReserved = isoDate(own(meta, 'dateReserved'))
  const datePublished = isoDate(own(meta, 'datePublished'))
  const dateUpdated = isoDate(own(meta, 'dateUpdated'))
  const datePublic = isoDate(own(cnaRaw, 'datePublic'))
  const title = text(own(cnaRaw, 'title'))
  if (dateReserved) record.dateReserved = dateReserved
  if (datePublished) record.datePublished = datePublished
  if (dateUpdated) record.dateUpdated = dateUpdated
  if (datePublic) record.datePublic = datePublic
  if (title) record.title = title
  return { ok: true, record }
}
