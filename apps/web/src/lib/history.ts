import type { HistorySeries } from '@touchstone/core/model'
import { comparableAcrossVersions } from './core.ts'

export type Delta = { vendorId: string; metricId: string; from: number; to: number; delta: number; fromRun: string; toRun: string }

/**
 * Change between the last two runs that both have a value, only when the
 * metric's formula did not change between their methodology versions.
 */
export function lastComparableDelta(series: HistorySeries): Delta | null {
  const pts = series.points.filter((p) => p.value !== null)
  if (pts.length < 2) return null
  const a = pts[pts.length - 2]!
  const b = pts[pts.length - 1]!
  if (!comparableAcrossVersions(series.metricId, a.methodologyVersion, b.methodologyVersion)) return null
  return { vendorId: series.vendorId, metricId: series.metricId, from: a.value!, to: b.value!, delta: b.value! - a.value!, fromRun: a.runId, toRun: b.runId }
}

export function deltas(history: HistorySeries[], metricIds: string[]): Delta[] {
  return history
    .filter((h) => metricIds.includes(h.metricId))
    .map(lastComparableDelta)
    .filter((d): d is Delta => d !== null)
}

export function median(values: number[]): number | null {
  if (!values.length) return null
  const s = [...values].sort((a, b) => a - b)
  const mid = Math.floor(s.length / 2)
  return s.length % 2 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2
}

/** Bucket 0-100 values into fixed 20-point bands, nulls kept as their own bucket. */
export function bucket20(values: (number | null)[]): { bucket: string; count: number }[] {
  const bands = ['0–20', '20–40', '40–60', '60–80', '80–100']
  const counts = bands.map((b) => ({ bucket: b, count: 0 }))
  let none = 0
  for (const v of values) {
    if (v === null) none++
    else counts[Math.min(4, Math.floor(v / 20))]!.count++
  }
  return [...counts, { bucket: 'not measured', count: none }]
}
