/**
 * Source freshness.
 *
 *  - Freshness is computed from the last SUCCESSFUL fetch, never from the
 *    last attempt.
 *  - When the latest attempt did not succeed and an older snapshot is used,
 *    the result shows the unsuccessful attempt AND the age of the snapshot
 *    actually used, and is never CURRENT: the source was not refreshed.
 *  - A substitution is honoured only when the substitute exists, belongs to
 *    the same source, is OK and was fetched on or before asOf; otherwise it is
 *    ignored (noted) and the source's own last success is used, else UNKNOWN.
 *  - Per-record sources (CVE_PROGRAM, NVD) use an order-independent
 *    definition: see perRecordFreshness.
 *  - No successful snapshot at all: UNKNOWN.
 */

import type { FreshnessState, MethodologyParameters, Snapshot, SourceFreshness, SourceRef } from '../model/index.ts'
import { round1, toMs } from '../measure/stats.ts'

const HOUR_MS = 3_600_000
/** Source families with one snapshot per record (see perRecordFreshness). */
const PER_RECORD_FAMILIES = new Set(['CVE_PROGRAM', 'NVD'])

function byFetchedAt(a: Snapshot, b: Snapshot): number {
  const x = toMs(a.fetchedAt) ?? 0
  const y = toMs(b.fetchedAt) ?? 0
  return x !== y ? x - y : a.id < b.id ? -1 : a.id > b.id ? 1 : 0
}

function band(ageHours: number, bands: [number, number] | undefined): FreshnessState {
  if (!bands) return 'UNKNOWN'
  if (ageHours <= bands[0]) return 'CURRENT'
  if (ageHours <= bands[1]) return 'AGING'
  return 'STALE'
}

function humanAge(hours: number): string {
  if (hours < 48) return `${round1(hours)} hours`
  return `${round1(hours / 24)} days`
}

export function computeFreshness(snapshots: Snapshot[], sources: SourceRef[], asOf: string, params: MethodologyParameters): SourceFreshness[] {
  const asOfMs = toMs(asOf)
  const out: SourceFreshness[] = []
  const sorted = [...sources].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
  const byId = new Map(snapshots.map((s) => [s.id, s]))

  for (const src of sorted) {
    // Snapshots fetched after asOf were not available at the analysis date.
    const attempts = snapshots
      .filter((s) => s.sourceId === src.id && (asOfMs === null || (toMs(s.fetchedAt) ?? 0) <= asOfMs))
      .sort(byFetchedAt)
    const base: SourceFreshness = { sourceId: src.id, title: src.title, family: src.family, state: 'UNKNOWN' }
    if (attempts.length === 0) {
      out.push({ ...base, note: 'No fetch attempt recorded for this source in the run.' })
      continue
    }
    if (PER_RECORD_FAMILIES.has(src.family)) {
      out.push(perRecordFreshness(base, attempts, asOfMs, params.freshnessHours[src.family]))
      continue
    }
    const latest = attempts[attempts.length - 1]!
    const successes = attempts.filter((s) => s.status === 'OK')
    const lastSuccess = successes[successes.length - 1]
    // The snapshot actually used: a VALID explicit substitution wins; otherwise the latest successful one.
    let used: Snapshot | undefined = lastSuccess
    let subNote = ''
    if (latest.status !== 'OK' && latest.substitutedBy) {
      const sub = byId.get(latest.substitutedBy)
      const problem = !sub
        ? 'it is not in the run'
        : sub.sourceId !== src.id
          ? `it belongs to another source (${sub.sourceId})`
          : sub.status !== 'OK'
            ? `its status is ${sub.status}`
            : asOfMs !== null && (toMs(sub.fetchedAt) ?? Number.POSITIVE_INFINITY) > asOfMs
              ? 'it was fetched after the analysis date'
              : ''
      if (problem) subNote = ` The recorded substitute ${latest.substitutedBy} was ignored because ${problem}.`
      else used = sub
    }
    const result: SourceFreshness = {
      ...base,
      lastAttemptAt: latest.fetchedAt,
      lastStatus: latest.status,
    }
    if (lastSuccess) result.lastSuccessAt = lastSuccess.fetchedAt
    if (!used || asOfMs === null) {
      result.state = 'UNKNOWN'
      result.note =
        latest.status === 'OK'
          ? 'The analysis date could not be parsed; age unknown.'
          : `Latest attempt at ${latest.fetchedAt} did not succeed (${latest.status}${latest.error ? `: ${latest.error}` : ''}); no usable successful snapshot exists, so freshness is unknown.${subNote}`
      out.push(result)
      continue
    }
    result.usedSnapshotId = used.id
    const usedMs = toMs(used.fetchedAt) ?? asOfMs
    const ageHours = round1(Math.max(0, asOfMs - usedMs) / HOUR_MS)
    result.ageHours = ageHours
    let state = band(ageHours, params.freshnessHours[src.family])
    if (latest.status !== 'OK') {
      // Not refreshed: never CURRENT, whatever the age of the substitute.
      if (state === 'CURRENT') state = 'AGING'
      result.note = `Latest attempt at ${latest.fetchedAt} did not succeed (${latest.status}${latest.error ? `: ${latest.error}` : ''}). Using snapshot ${used.id} fetched ${used.fetchedAt}, ${humanAge(ageHours)} before the analysis date.${subNote}`
    } else if (state === 'UNKNOWN') {
      result.note = `No freshness band is defined for source family ${src.family}.`
    }
    result.state = state
    out.push(result)
  }
  return out
}

/**
 * Per-record sources (CVE_PROGRAM, NVD) hold one snapshot per record, fetched
 * in one batch, so "the latest attempt" would be whichever record happened to
 * be fetched last. Their freshness is defined order-independently:
 *   - age = the OLDEST successful fetch among the records used (conservative:
 *     no record used is older than this);
 *   - lastStatus = OK when at least one record was fetched successfully,
 *     otherwise FAILED if any attempt FAILED, else REJECTED;
 *   - records that were not OK are counted in the note; a rejected or failed
 *     record is a record problem, not a stale source;
 *   - no successful record: UNKNOWN.
 */
function perRecordFreshness(base: SourceFreshness, attempts: Snapshot[], asOfMs: number | null, bands: [number, number] | undefined): SourceFreshness {
  const ok = attempts.filter((s) => s.status === 'OK')
  const notOk = attempts.filter((s) => s.status !== 'OK')
  const result: SourceFreshness = {
    ...base,
    lastAttemptAt: attempts[attempts.length - 1]!.fetchedAt,
    lastStatus: ok.length > 0 ? 'OK' : notOk.some((s) => s.status === 'FAILED') ? 'FAILED' : 'REJECTED',
  }
  const failNote = notOk.length ? ` ${notOk.length} of ${attempts.length} record fetch(es) were not OK.` : ''
  if (ok.length === 0 || asOfMs === null) {
    result.state = 'UNKNOWN'
    result.note = `No record of this per-record source was fetched successfully; freshness is unknown.${failNote}`
    return result
  }
  const oldest = ok[0]!
  result.lastSuccessAt = ok[ok.length - 1]!.fetchedAt
  result.usedSnapshotId = oldest.id
  const ageHours = round1(Math.max(0, asOfMs - (toMs(oldest.fetchedAt) ?? asOfMs)) / HOUR_MS)
  result.ageHours = ageHours
  result.state = band(ageHours, bands)
  result.note = `Per-record source: age of the oldest of ${ok.length} successful record fetch(es) (${oldest.fetchedAt}), ${humanAge(ageHours)} before the analysis date.${failNote}`
  return result
}

/** Worst state among a set (UNKNOWN < STALE < AGING < CURRENT). */
export function worstFreshness(states: FreshnessState[]): FreshnessState | undefined {
  const order: FreshnessState[] = ['UNKNOWN', 'STALE', 'AGING', 'CURRENT']
  let worst: FreshnessState | undefined
  for (const s of states) if (worst === undefined || order.indexOf(s) < order.indexOf(worst)) worst = s
  return worst
}
