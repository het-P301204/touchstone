/**
 * Source freshness.
 *
 *  - Freshness is computed from the last SUCCESSFUL fetch, never from the
 *    last attempt.
 *  - When the latest attempt did not succeed and an older snapshot is used,
 *    the result shows the unsuccessful attempt AND the age of the snapshot
 *    actually used, and is never CURRENT: the source was not refreshed.
 *  - No successful snapshot at all: UNKNOWN.
 */

import type { FreshnessState, MethodologyParameters, Snapshot, SourceFreshness, SourceRef } from '../model/index.ts'
import { round1, toMs } from '../measure/stats.ts'

const HOUR_MS = 3_600_000

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
    const latest = attempts[attempts.length - 1]!
    const successes = attempts.filter((s) => s.status === 'OK')
    const lastSuccess = successes[successes.length - 1]
    // The snapshot actually used: an explicit substitution wins; otherwise the latest successful one.
    let used: Snapshot | undefined = lastSuccess
    if (latest.status !== 'OK' && latest.substitutedBy) {
      const sub = byId.get(latest.substitutedBy)
      if (sub && sub.status === 'OK') used = sub
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
          : `Latest attempt at ${latest.fetchedAt} did not succeed (${latest.status}${latest.error ? `: ${latest.error}` : ''}); no successful snapshot exists, so freshness is unknown.`
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
      result.note = `Latest attempt at ${latest.fetchedAt} did not succeed (${latest.status}${latest.error ? `: ${latest.error}` : ''}). Using snapshot ${used.id} fetched ${used.fetchedAt}, ${humanAge(ageHours)} before the analysis date.`
    } else if (state === 'UNKNOWN') {
      result.note = `No freshness band is defined for source family ${src.family}.`
    }
    result.state = state
    out.push(result)
  }
  return out
}

/** Worst state among a set (UNKNOWN < STALE < AGING < CURRENT). */
export function worstFreshness(states: FreshnessState[]): FreshnessState | undefined {
  const order: FreshnessState[] = ['UNKNOWN', 'STALE', 'AGING', 'CURRENT']
  let worst: FreshnessState | undefined
  for (const s of states) if (worst === undefined || order.indexOf(s) < order.indexOf(worst)) worst = s
  return worst
}
