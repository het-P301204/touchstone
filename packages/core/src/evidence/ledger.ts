/**
 * The evidence ledger. Every number TOUCHSTONE reports points at evidence
 * items: one per record per metric, one per VDP criterion, one per advisory
 * per metric. An item says which snapshot it was read from, the exact fields
 * extracted, and how the methodology interpreted them.
 *
 * Ids are content-derived ("EV-" + 10 hex of sha256 over the canonical JSON
 * of the item without its id), so the same inputs under the same methodology
 * produce the same ids on every re-run, and a run id never enters them.
 */

import type { EvidenceItem } from '../model/index.ts'
import { sha256Text } from '../util/sha256.ts'
import { cleanText } from '../util/sanitize.ts'
import { canonicalJson } from '../run/canonical.ts'

export type EvidenceDraft = Omit<EvidenceItem, 'id'>

type Extracted = EvidenceItem['extracted']

function cleanExtracted(x: Extracted): Extracted {
  const out: Extracted = {}
  for (const [k, v] of Object.entries(x)) {
    if (typeof v === 'string') out[k] = cleanText(v)
    else if (Array.isArray(v)) out[k] = v.map((s) => cleanText(s))
    else out[k] = v
  }
  return out
}

/** Normalize a draft: strip invisible/bidi characters from every human-readable string. */
export function normalizeDraft(d: EvidenceDraft): EvidenceDraft {
  return {
    vendorId: d.vendorId,
    metricId: d.metricId,
    sourceId: d.sourceId,
    snapshotId: d.snapshotId,
    subject: cleanText(d.subject),
    collectedAt: d.collectedAt,
    extracted: cleanExtracted(d.extracted),
    interpretation: d.interpretation,
    reading: cleanText(d.reading),
    confidence: d.confidence,
    methodologyVersion: d.methodologyVersion,
  }
}

/** "EV-" + first 10 hex of sha256(canonicalJson(draft)). */
export function evidenceId(draft: EvidenceDraft): string {
  return `EV-${sha256Text(canonicalJson(normalizeDraft(draft))).slice(0, 10)}`
}

export function makeEvidence(draft: EvidenceDraft): EvidenceItem {
  const d = normalizeDraft(draft)
  return { id: `EV-${sha256Text(canonicalJson(d)).slice(0, 10)}`, ...d }
}

/**
 * Collects evidence for a run. Identical items collapse to one id; two
 * different items that collide on the 10-hex prefix are disambiguated
 * deterministically by appending a counter (and the collision is counted so
 * the quality gate can report it).
 */
export class EvidenceLedger {
  private readonly items = new Map<string, EvidenceItem>()
  private readonly canon = new Map<string, string>()
  collisions = 0

  add(draft: EvidenceDraft): string {
    const d = normalizeDraft(draft)
    const c = canonicalJson(d)
    const base = `EV-${sha256Text(c).slice(0, 10)}`
    let id = base
    let n = 1
    while (this.canon.has(id) && this.canon.get(id) !== c) {
      if (n === 1) this.collisions++
      id = `${base}-${n++}`
    }
    if (!this.canon.has(id)) {
      this.canon.set(id, c)
      this.items.set(id, { id, ...d })
    }
    return id
  }

  get(id: string): EvidenceItem | undefined {
    return this.items.get(id)
  }

  /** All items sorted by id (deterministic output order). */
  list(): EvidenceItem[] {
    return [...this.items.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  }

  get size(): number {
    return this.items.size
  }
}
