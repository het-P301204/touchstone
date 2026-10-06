/**
 * Vendor identity: alias normalization, conflict detection, CVE attribution
 * and signatory matching.
 *
 * Principles:
 *  - Every link between a name and a vendor is an explicit alias in the
 *    registry, with evidence. Nothing is inferred from free text: CVE
 *    descriptions and titles are never used to attribute a record.
 *  - Two identities are never merged silently. A name that resolves to more
 *    than one vendor is reported as an IdentityConflict, and records whose
 *    attribution depends on that name are excluded until a registry decision
 *    resolves it.
 *  - A record that fits more than one vendor is excluded (AMBIGUOUS_VENDOR),
 *    never split or assigned to the first match.
 */

import type {
  AliasKind,
  Attribution,
  AttributionExclusion,
  CveRecord,
  IdentityConflict,
  Vendor,
} from '../model/index.ts'
import { cleanText } from '../util/sanitize.ts'
import { shortHash } from '../util/sha256.ts'

// ------------------------------------------------------------------ normalization

/** Corporate suffixes stripped from the end of a name, repeatedly. Exported for documentation. */
export const CORPORATE_SUFFIXES: readonly string[] = ['inc', 'llc', 'ltd', 'corp', 'corporation', 'gmbh', 'ag']

function collapse(s: string): string {
  return cleanText(s).normalize('NFKC').toLowerCase().replace(/\s+/g, ' ').trim()
}

/**
 * Normalize a company name for exact matching: Unicode NFKC, case-fold, trim,
 * collapse whitespace, then strip trailing corporate suffixes (Inc, LLC, Ltd,
 * Corp, Corporation, GmbH, AG), with or without a trailing period or a
 * preceding comma. A name is never reduced to nothing: "AG" stays "ag".
 */
export function normalizeName(name: string): string {
  let s = collapse(name)
  for (;;) {
    const before = s
    s = s.replace(/[\s,]+$/, '')
    const m = /(?:^|[\s,])([a-z]+)\.?$/.exec(s)
    if (m && CORPORATE_SUFFIXES.includes(m[1]!)) {
      const cut = s.slice(0, m.index).replace(/[\s,]+$/, '')
      if (cut.length > 0) s = cut
    }
    if (s === before) break
  }
  return s
}

/** Normalization used for an alias of the given kind. */
export function aliasKey(kind: AliasKind, value: string): string {
  switch (kind) {
    case 'CNA_ORG_ID':
    case 'CPE_VENDOR':
    case 'CNA_SHORT_NAME':
    case 'ADVISORY_DOMAIN':
    case 'GITHUB_ORG':
      return collapse(value)
    default:
      return normalizeName(value)
  }
}

/** Alias kinds that name the organisation itself; a shared value across vendors is a NAME_COLLISION. */
const IDENTITY_NAME_KINDS: readonly AliasKind[] = ['LEGAL_NAME', 'BRAND', 'SUBSIDIARY', 'SIGNATORY_LISTING']

type Namespace = 'NAME' | 'CNA_SHORT_NAME' | 'CNA_ORG_ID' | 'CPE_VENDOR'

function namespaceOf(kind: AliasKind): Namespace | null {
  if (IDENTITY_NAME_KINDS.includes(kind)) return 'NAME'
  if (kind === 'CNA_SHORT_NAME' || kind === 'CNA_ORG_ID' || kind === 'CPE_VENDOR') return kind
  return null
}

function conflictKindOf(ns: Namespace): IdentityConflict['kind'] {
  return ns === 'NAME' ? 'NAME_COLLISION' : ns === 'CPE_VENDOR' ? 'CPE_NAMESPACE_SHARED' : 'CNA_SHARED'
}

// ------------------------------------------------------------------ conflicts

/**
 * Detect names that resolve to more than one vendor:
 *  - NAME_COLLISION: a legal name, brand, subsidiary or signatory listing shared by two vendors;
 *  - CNA_SHARED: a CNA short name or org id claimed by two vendors;
 *  - CPE_NAMESPACE_SHARED: a CPE vendor namespace claimed by two vendors (e.g. after an acquisition).
 *
 * AFFECTED_VENDOR aliases are deliberately not conflicts: two companies can
 * legitimately be written the same way in `affected[].vendor`. Records that
 * hit such a name are excluded per record as AMBIGUOUS_VENDOR instead.
 *
 * `affectedRecordIds` is empty here (conflicts are a property of the
 * registry); the records excluded because of a conflict are listed by
 * attributeCves as IDENTITY_CONFLICT exclusions.
 */
export function detectIdentityConflicts(vendors: Vendor[]): IdentityConflict[] {
  const byKey = new Map<string, { ns: Namespace; kind: AliasKind; value: string; vendorIds: Set<string> }>()
  for (const v of vendors) {
    for (const a of v.aliases) {
      const ns = namespaceOf(a.kind)
      if (!ns) continue
      const key = aliasKey(a.kind, a.value)
      if (key.length === 0) continue
      const mapKey = `${ns}\u0000${key}`
      let entry = byKey.get(mapKey)
      if (!entry) {
        entry = { ns, kind: a.kind, value: key, vendorIds: new Set() }
        byKey.set(mapKey, entry)
      }
      entry.vendorIds.add(v.id)
    }
  }
  const out: IdentityConflict[] = []
  for (const e of byKey.values()) {
    if (e.vendorIds.size < 2) continue
    const vendorIds = [...e.vendorIds].sort()
    const kind = conflictKindOf(e.ns)
    out.push({
      id: `IC-${shortHash(`${kind}|${e.ns}|${e.value}`)}`,
      kind,
      value: e.value,
      aliasKind: e.kind,
      vendorIds,
      affectedRecordIds: [],
      note: `"${e.value}" is registered as a ${e.ns === 'NAME' ? 'name' : e.kind} for ${vendorIds.length} vendors (${vendorIds.join(', ')}). Records whose attribution depends on it are excluded until a registry decision resolves it.`,
    })
  }
  return out.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
}

// ------------------------------------------------------------------ attribution

function buildIndex(vendors: Vendor[]): Map<AliasKind, Map<string, Set<string>>> {
  const idx = new Map<AliasKind, Map<string, Set<string>>>()
  for (const v of vendors) {
    for (const a of v.aliases) {
      const key = aliasKey(a.kind, a.value)
      if (key.length === 0) continue
      let m = idx.get(a.kind)
      if (!m) idx.set(a.kind, (m = new Map()))
      let s = m.get(key)
      if (!s) m.set(key, (s = new Set()))
      s.add(v.id)
    }
  }
  return idx
}

function lookup(idx: Map<AliasKind, Map<string, Set<string>>>, kind: AliasKind, value: string): string[] {
  const key = aliasKey(kind, value)
  if (key.length === 0) return []
  return [...(idx.get(kind)?.get(key) ?? [])]
}

function conflictKeySet(conflicts: IdentityConflict[]): Set<string> {
  const s = new Set<string>()
  for (const c of conflicts) {
    const ns = namespaceOf(c.aliasKind)
    if (ns) s.add(`${ns}\u0000${aliasKey(c.aliasKind, c.value)}`)
  }
  return s
}

function isConflicted(conflictKeys: Set<string>, kind: AliasKind, value: string): boolean {
  const ns = namespaceOf(kind)
  return ns !== null && conflictKeys.has(`${ns}\u0000${aliasKey(kind, value)}`)
}

const sortedUnique = (xs: Iterable<string>) => [...new Set(xs)].sort()

/** Free-text mention check (report only, never attribution): whole-word, case-insensitive. */
function mentions(haystack: string, needle: string): boolean {
  if (needle.length < 4) return false
  const h = haystack.toLowerCase()
  const n = needle.toLowerCase()
  let from = 0
  for (;;) {
    const i = h.indexOf(n, from)
    if (i < 0) return false
    const before = i === 0 ? ' ' : h[i - 1]!
    const after = i + n.length >= h.length ? ' ' : h[i + n.length]!
    if (!/[a-z0-9]/.test(before) && !/[a-z0-9]/.test(after)) return true
    from = i + 1
  }
}

/**
 * Attribute CVE records to vendors. Rules, in order:
 *   1. ASSIGNER_IS_VENDOR_CNA (HIGH): the assigner short name or org id is the vendor's CNA alias.
 *   2. AFFECTED_VENDOR_AND_CPE (HIGH): a cna.affected vendor is the vendor's AFFECTED_VENDOR alias
 *      and a well-formed CNA CPE uses one of the vendor's CPE_VENDOR namespaces.
 *   3. AFFECTED_VENDOR_ONLY (MEDIUM): the affected vendor alias without a corroborating CNA CPE.
 * Exclusions: REJECTED_RECORD, DUPLICATE_CONFLICT (same id, different content: every copy
 * excluded), IDENTITY_CONFLICT (a matched alias is in a conflict), AMBIGUOUS_VENDOR (more than one
 * candidate vendor), FREE_TEXT_ONLY (no alias matched, the title mentions a registered name:
 * reported, never attributed).
 *
 * Output is sorted by CVE id and is independent of input order. Identical duplicate copies (same
 * id, same sourceHash) are collapsed to one.
 */
export function attributeCves(
  cves: CveRecord[],
  vendors: Vendor[],
  conflicts: IdentityConflict[],
): { attributions: Attribution[]; exclusions: AttributionExclusion[] } {
  const idx = buildIndex(vendors)
  const conflictKeys = conflictKeySet(conflicts)
  const vendorById = new Map(vendors.map((v) => [v.id, v]))
  const attributions: Attribution[] = []
  const exclusions: AttributionExclusion[] = []

  // Group by id to find duplicates.
  const byId = new Map<string, CveRecord[]>()
  for (const r of cves) {
    const list = byId.get(r.id)
    if (list) list.push(r)
    else byId.set(r.id, [r])
  }
  const ids = [...byId.keys()].sort()

  for (const id of ids) {
    const copies = byId.get(id)!
    const hashes = sortedUnique(copies.map((c) => c.sourceHash))
    if (hashes.length > 1) {
      const candidates = sortedUnique(copies.flatMap((c) => candidateVendors(c, idx)))
      exclusions.push({
        cveId: id,
        reason: 'DUPLICATE_CONFLICT',
        candidateVendorIds: candidates,
        note: `${copies.length} copies of ${id} with ${hashes.length} different contents (${hashes.map((h) => h.slice(0, 12)).join(', ')}); all copies excluded.`,
      })
      continue
    }
    const r = copies[0]!
    if (r.state === 'REJECTED') {
      exclusions.push({ cveId: id, reason: 'REJECTED_RECORD', candidateVendorIds: sortedUnique(candidateVendors(r, idx)), note: 'Record state is REJECTED.' })
      continue
    }

    // Rule 1: assigner is the vendor's CNA.
    const cnaMatches: { vendorId: string; kind: AliasKind; value: string }[] = []
    for (const [kind, value] of [
      ['CNA_SHORT_NAME', r.assigner.shortName],
      ['CNA_ORG_ID', r.assigner.orgId],
    ] as [AliasKind, string][]) {
      for (const vendorId of lookup(idx, kind, value)) cnaMatches.push({ vendorId, kind, value })
    }
    if (cnaMatches.length > 0) {
      const vendorIds = sortedUnique(cnaMatches.map((m) => m.vendorId))
      const conflicted = cnaMatches.filter((m) => isConflicted(conflictKeys, m.kind, m.value))
      if (conflicted.length > 0) {
        exclusions.push({
          cveId: id,
          reason: 'IDENTITY_CONFLICT',
          candidateVendorIds: vendorIds,
          note: `Assigner ${conflicted.map((m) => `${m.kind} "${m.value}"`).join(', ')} is claimed by more than one vendor.`,
        })
        continue
      }
      if (vendorIds.length > 1) {
        exclusions.push({ cveId: id, reason: 'AMBIGUOUS_VENDOR', candidateVendorIds: vendorIds, note: 'Assigner matches more than one vendor.' })
        continue
      }
      const vendorId = vendorIds[0]!
      attributions.push({
        cveId: id,
        vendorId,
        rule: 'ASSIGNER_IS_VENDOR_CNA',
        confidence: 'HIGH',
        matched: dedupeMatched(cnaMatches.map((m) => ({ kind: m.kind, value: m.value }))),
      })
      continue
    }

    // Rules 2 and 3: affected vendor alias.
    const affMatches: { vendorId: string; value: string }[] = []
    for (const a of r.affected) {
      for (const vendorId of lookup(idx, 'AFFECTED_VENDOR', a.vendor)) affMatches.push({ vendorId, value: a.vendor })
    }
    if (affMatches.length > 0) {
      const vendorIds = sortedUnique(affMatches.map((m) => m.vendorId))
      const conflictedAff = affMatches.filter((m) => isConflicted(conflictKeys, 'AFFECTED_VENDOR', m.value))
      if (conflictedAff.length > 0) {
        exclusions.push({ cveId: id, reason: 'IDENTITY_CONFLICT', candidateVendorIds: vendorIds, note: `Affected vendor "${conflictedAff[0]!.value}" is in an identity conflict.` })
        continue
      }
      if (vendorIds.length > 1) {
        exclusions.push({
          cveId: id,
          reason: 'AMBIGUOUS_VENDOR',
          candidateVendorIds: vendorIds,
          note: `Affected vendor name(s) ${sortedUnique(affMatches.map((m) => `"${m.value}"`)).join(', ')} match ${vendorIds.length} vendors (${vendorIds.join(', ')}).`,
        })
        continue
      }
      const vendorId = vendorIds[0]!
      const vendor = vendorById.get(vendorId)!
      const vendorNamespaces = new Set(vendor.aliases.filter((a) => a.kind === 'CPE_VENDOR').map((a) => aliasKey('CPE_VENDOR', a.value)))
      const cpeHits = r.cna.cpes.filter((c) => c.wellFormed && c.vendor !== undefined && vendorNamespaces.has(aliasKey('CPE_VENDOR', c.vendor)))
      const cpeConflicted = cpeHits.filter((c) => isConflicted(conflictKeys, 'CPE_VENDOR', c.vendor!))
      if (cpeConflicted.length > 0) {
        exclusions.push({
          cveId: id,
          reason: 'IDENTITY_CONFLICT',
          candidateVendorIds: sortedUnique([vendorId, ...lookup(idx, 'CPE_VENDOR', cpeConflicted[0]!.vendor!)]),
          note: `CPE vendor namespace "${cpeConflicted[0]!.vendor}" is claimed by more than one vendor.`,
        })
        continue
      }
      const matched = dedupeMatched(affMatches.map((m) => ({ kind: 'AFFECTED_VENDOR', value: m.value })))
      if (cpeHits.length > 0) {
        attributions.push({
          cveId: id,
          vendorId,
          rule: 'AFFECTED_VENDOR_AND_CPE',
          confidence: 'HIGH',
          matched: dedupeMatched([...matched, ...cpeHits.map((c) => ({ kind: 'CPE_VENDOR', value: c.vendor! }))]),
        })
      } else {
        attributions.push({ cveId: id, vendorId, rule: 'AFFECTED_VENDOR_ONLY', confidence: 'MEDIUM', matched })
      }
      continue
    }

    // No alias matched. Report (never attribute) a free-text mention in the title.
    if (r.title) {
      const mentioned: string[] = []
      for (const v of vendors) {
        const names = [v.canonicalName, ...v.aliases.filter((a) => a.kind === 'LEGAL_NAME' || a.kind === 'BRAND' || a.kind === 'AFFECTED_VENDOR').map((a) => a.value)]
        if (names.some((n) => mentions(r.title!, normalizeName(n)))) mentioned.push(v.id)
      }
      if (mentioned.length > 0) {
        exclusions.push({
          cveId: id,
          reason: 'FREE_TEXT_ONLY',
          candidateVendorIds: sortedUnique(mentioned),
          note: 'The title mentions a registered vendor name, but no structured field (assigner, affected vendor) matches. Free text is never used for attribution.',
        })
      }
    }
  }
  return { attributions, exclusions }
}

function candidateVendors(r: CveRecord, idx: Map<AliasKind, Map<string, Set<string>>>): string[] {
  const out: string[] = []
  out.push(...lookup(idx, 'CNA_SHORT_NAME', r.assigner.shortName), ...lookup(idx, 'CNA_ORG_ID', r.assigner.orgId))
  for (const a of r.affected) out.push(...lookup(idx, 'AFFECTED_VENDOR', a.vendor))
  return out
}

function dedupeMatched(xs: { kind: string; value: string }[]): { kind: string; value: string }[] {
  const seen = new Set<string>()
  const out: { kind: string; value: string }[] = []
  for (const x of xs) {
    const k = `${x.kind}\u0000${x.value}`
    if (seen.has(k)) continue
    seen.add(k)
    out.push(x)
  }
  return out
}

// ------------------------------------------------------------------ signatories

/**
 * Match names as listed on the CISA signer page to vendors through their
 * SIGNATORY_LISTING aliases (exact match after normalization).
 */
export function matchSignatories(
  listedNames: string[],
  vendors: Vendor[],
): { matched: { vendorId: string; listedName: string }[]; unmatchedNames: string[]; ambiguous: { listedName: string; vendorIds: string[] }[] } {
  const idx = buildIndex(vendors)
  const matched: { vendorId: string; listedName: string }[] = []
  const unmatchedNames: string[] = []
  const ambiguous: { listedName: string; vendorIds: string[] }[] = []
  for (const listedName of listedNames) {
    const ids = sortedUnique(lookup(idx, 'SIGNATORY_LISTING', listedName))
    if (ids.length === 0) unmatchedNames.push(listedName)
    else if (ids.length === 1) matched.push({ vendorId: ids[0]!, listedName })
    else ambiguous.push({ listedName, vendorIds: ids })
  }
  return { matched, unmatchedNames, ambiguous }
}
