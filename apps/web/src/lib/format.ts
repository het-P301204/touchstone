/**
 * Formatting. Every helper renders `null` as an explicit "not measured"
 * placeholder rather than 0: UNKNOWN is never a number.
 */

export const NOT_MEASURED = '—'

export function pct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return NOT_MEASURED
  return `${value.toFixed(digits)}%`
}

export function num(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return NOT_MEASURED
  return value.toLocaleString('en-US', { minimumFractionDigits: digits, maximumFractionDigits: digits })
}

export function days(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return NOT_MEASURED
  const v = Math.round(value * 10) / 10
  return `${v} ${Math.abs(v) === 1 ? 'day' : 'days'}`
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** "6 Oct 2026". Parses the date part only, so time zones never shift the day. */
export function date(iso: string | null | undefined): string {
  if (!iso) return NOT_MEASURED
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso)
  if (!m) return iso
  const month = MONTHS[Number(m[2]) - 1] ?? m[2]
  return `${Number(m[3])} ${month} ${m[1]}`
}

/** "6 Oct 2026, 14:05 UTC" */
export function dateTime(iso: string | null | undefined): string {
  if (!iso) return NOT_MEASURED
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})/.exec(iso)
  if (!m) return date(iso)
  return `${date(iso)}, ${m[4]}:${m[5]} UTC`
}

export function ageLabel(hours: number | null | undefined): string {
  if (hours === null || hours === undefined) return NOT_MEASURED
  if (hours < 1) return 'under an hour'
  if (hours < 48) return `${Math.round(hours)} h`
  const d = Math.round(hours / 24)
  return `${d} days`
}

export function shortHash(hash: string | undefined, n = 12): string {
  if (!hash) return NOT_MEASURED
  return hash.length > n ? `${hash.slice(0, n)}…` : hash
}

/** Subtract days from an ISO date (date part), returning YYYY-MM-DD. */
export function minusDays(iso: string, d: number): string {
  const m = /^(\d{4})-(\d{2})-(\d{2})/.exec(iso)
  if (!m) return iso
  const t = Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3])) - d * 86_400_000
  return new Date(t).toISOString().slice(0, 10)
}

export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n.toLocaleString('en-US')} ${n === 1 ? one : many}`
}

export function titleCase(s: string): string {
  return s
    .toLowerCase()
    .split(/[_\s]+/)
    .filter(Boolean)
    .map((w) => w[0]!.toUpperCase() + w.slice(1))
    .join(' ')
}
