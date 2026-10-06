/**
 * Per-vendor measurement context and the helpers the measures share:
 * source/snapshot resolution for evidence items and the documented
 * confidence rules (definitions.ts CONFIDENCE_RULES).
 */

import type {
  Advisory,
  Attribution,
  AttributionExclusion,
  Confidence,
  CveRecord,
  MethodologyVersion,
  Snapshot,
  SourceFamily,
  SourceFreshness,
  SourceRef,
  VdpObservation,
  Vendor,
} from '../model/index.ts'
import type { EvidenceLedger } from '../evidence/ledger.ts'
import { CONFIDENCE_RULES } from './definitions.ts'

export type AttributedRecord = { record: CveRecord; attribution: Attribution }

export type MeasureContext = {
  vendor: Vendor
  asOf: string
  asOfMs: number
  methodology: MethodologyVersion
  /** Records attributed to this vendor (one per CVE id), any state. */
  attributed: AttributedRecord[]
  /** Exclusions naming this vendor as a candidate. */
  exclusions: AttributionExclusion[]
  /** All records in the snapshot by id, excluding ids involved in a duplicate conflict. */
  cvesById: Map<string, CveRecord>
  /** Ids that appear more than once with conflicting content. */
  duplicateIds: Set<string>
  /** Snapshot id of every record id in the run, duplicates included (first by sorted snapshot id). */
  recordSnapshotIds?: Map<string, string>
  advisories: Advisory[]
  vdp?: VdpObservation
  snapshotsById: Map<string, Snapshot>
  sources: SourceRef[]
  freshnessBySource: Map<string, SourceFreshness>
  /** The CVE source family has snapshots, none usable. */
  cveSourceFailed: boolean
  ledger: EvidenceLedger
}

export type SourceResolution = {
  sourceId: string
  collectedAt: string
  freshness?: SourceFreshness
}

/** Resolve the source and collection time of a snapshot; falls back to the first source of the family. */
export function resolveSource(ctx: MeasureContext, snapshotId: string | undefined, family: SourceFamily): SourceResolution {
  const snap = snapshotId ? ctx.snapshotsById.get(snapshotId) : undefined
  if (snap) {
    const res: SourceResolution = { sourceId: snap.sourceId, collectedAt: snap.fetchedAt }
    const f = ctx.freshnessBySource.get(snap.sourceId)
    if (f) res.freshness = f
    return res
  }
  const src = ctx.sources.find((s) => s.family === family)
  const res: SourceResolution = { sourceId: src?.id ?? `unresolved.${family.toLowerCase()}`, collectedAt: 'unknown' }
  const f = src ? ctx.freshnessBySource.get(src.id) : undefined
  if (f) res.freshness = f
  return res
}

/** Freshness entries of every source in a family. */
export function familyFreshness(ctx: MeasureContext, family: SourceFamily): SourceFreshness[] {
  return ctx.sources.filter((s) => s.family === family).flatMap((s) => {
    const f = ctx.freshnessBySource.get(s.id)
    return f ? [f] : []
  })
}

const RANK: Record<Confidence, number> = { HIGH: 2, MEDIUM: 1, LOW: 0 }

/** Accumulates fired confidence rules. Starts HIGH; the lowest cap wins. */
export class ConfidenceTally {
  level: Confidence = 'HIGH'
  reasons: string[] = []

  fire(ruleId: string, detail: string): void {
    const rule = CONFIDENCE_RULES.find((r) => r.id === ruleId)
    if (!rule) throw new Error(`Unknown confidence rule ${ruleId}`)
    if (RANK[rule.cap] < RANK[this.level]) this.level = rule.cap
    const reason = `${ruleId}: ${detail}`
    if (!this.reasons.includes(reason)) this.reasons.push(reason)
  }

  /** Apply the freshness rules for a set of sources feeding a metric. */
  freshness(entries: (SourceFreshness | undefined)[]): void {
    const seen = new Set<string>()
    for (const f of entries) {
      if (!f || seen.has(f.sourceId)) continue
      seen.add(f.sourceId)
      if (f.state === 'STALE') this.fire('C3.STALE', `Source ${f.sourceId} is STALE (${f.ageHours ?? '?'} hours since the snapshot used).`)
      if (f.state === 'UNKNOWN') this.fire('C3.UNKNOWN_FRESHNESS', `Source ${f.sourceId} has no successful snapshot; its age is unknown.`)
    }
  }

  result(): { confidence: Confidence; confidenceReasons: string[] } {
    return { confidence: this.level, confidenceReasons: [...this.reasons] }
  }
}

export function minConfidence(a: Confidence, b: Confidence): Confidence {
  return RANK[a] <= RANK[b] ? a : b
}
