/**
 * The only statistics TOUCHSTONE uses: a share, a median and a nearest-rank
 * percentile. Nothing is weighted, smoothed or modelled.
 */

const DAY_MS = 86_400_000

/** Round to two decimals (percentages, days). */
export function round2(x: number): number {
  const r = Math.round(x * 100) / 100
  return Object.is(r, -0) ? 0 : r
}

/** Round to one decimal. */
export function round1(x: number): number {
  const r = Math.round(x * 10) / 10
  return Object.is(r, -0) ? 0 : r
}

/** numerator / denominator × 100, rounded to two decimals. Caller guarantees denominator > 0. */
export function percent(numerator: number, denominator: number): number {
  return round2((numerator / denominator) * 100)
}

/** Conventional median: the middle value, or the mean of the two middle values. Null for an empty list. */
export function median(values: number[]): number | null {
  if (values.length === 0) return null
  const s = [...values].sort((a, b) => a - b)
  const mid = s.length >> 1
  return s.length % 2 === 1 ? s[mid]! : round2((s[mid - 1]! + s[mid]!) / 2)
}

/** Nearest-rank percentile: the value at rank ceil(p/100 × n) of the sorted list. Null for an empty list. */
export function percentileNearestRank(values: number[], p: number): number | null {
  if (values.length === 0) return null
  const s = [...values].sort((a, b) => a - b)
  const rank = Math.max(1, Math.ceil((p / 100) * s.length))
  return s[Math.min(rank, s.length) - 1]!
}

/** Milliseconds since epoch for an ISO date or date-time, or null when unparseable. */
export function toMs(iso: string | undefined): number | null {
  if (!iso) return null
  const ms = Date.parse(iso)
  return Number.isFinite(ms) ? ms : null
}

/** (b - a) in days, two decimals. */
export function daysBetween(aMs: number, bMs: number): number {
  return round2((bMs - aMs) / DAY_MS)
}

/** ISO date (YYYY-MM-DD) `days` before the given ISO timestamp. */
export function isoDaysBefore(iso: string, days: number): string {
  const ms = toMs(iso)
  if (ms === null) return iso
  return new Date(ms - days * DAY_MS).toISOString()
}

/** True when `iso` falls in (asOf - days, asOf]. */
export function withinDaysBefore(iso: string | undefined, asOfMs: number, days: number): boolean {
  const ms = toMs(iso)
  if (ms === null) return false
  return ms <= asOfMs && ms > asOfMs - days * DAY_MS
}

export { DAY_MS }

/** Format a number for a calculation string: at most two decimals, trailing zeros dropped. */
export function fmt(x: number): string {
  if (Number.isInteger(x)) return String(x)
  const s = x.toFixed(2).replace(/0+$/, '').replace(/\.$/, '')
  return s === '-0' ? '0' : s
}
