/**
 * Candidate CVE ids from the NVD CVE API 2.0, by sourceIdentifier.
 *
 * NVD is used only to enumerate ids; the records themselves come from the
 * CVE Program (cve-records.ts), so NVD's own analysis never enters a metric.
 * The API limits publication-date ranges to 120 days, so the window is
 * split. Without an API key NVD allows 5 requests per rolling 30 seconds;
 * the caller's rate limiter for services.nvd.nist.gov should be >= 6 s.
 */

import type { Snapshot, SourceRef } from '../../../core/src/model/index.ts'
import { CVE_ID_PATTERN } from '../../../core/src/normalize/cve.ts'
import { decodeUtf8, fetchToSnapshot } from './common.ts'
import type { CollectContext } from './common.ts'

export const NVD_SOURCE: SourceRef = {
  id: 'nvd.cves',
  family: 'NVD',
  title: 'NVD CVE API 2.0 (id enumeration only)',
  url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
  publisher: 'National Institute of Standards and Technology',
  attribution: 'This product uses data from the NVD API but is not endorsed or certified by the NVD.',
  retention: 'RAW',
}

export const NVD_MAX_WINDOW_DAYS = 120
export const NVD_MIN_INTERVAL_MS = 6_500
const PAGE = 2_000
const DAY = 86_400_000

/** Split [from, to] into consecutive windows of at most `days` days. */
export function nvdWindows(fromIso: string, toIso: string, days = NVD_MAX_WINDOW_DAYS): { start: string; end: string }[] {
  const from = Date.parse(fromIso)
  const to = Date.parse(toIso)
  if (Number.isNaN(from) || Number.isNaN(to) || to < from) throw new Error(`bad window ${fromIso} .. ${toIso}`)
  const out: { start: string; end: string }[] = []
  for (let s = from; s <= to; s += days * DAY) {
    const e = Math.min(to, s + days * DAY - 1000)
    out.push({ start: new Date(s).toISOString(), end: new Date(e).toISOString() })
    if (e >= to) break
  }
  return out
}

export function nvdUrl(sourceIdentifier: string, window: { start: string; end: string }, startIndex: number): string {
  const u = new URL(NVD_SOURCE.url)
  u.searchParams.set('sourceIdentifier', sourceIdentifier)
  u.searchParams.set('pubStartDate', window.start)
  u.searchParams.set('pubEndDate', window.end)
  u.searchParams.set('resultsPerPage', String(PAGE))
  u.searchParams.set('startIndex', String(startIndex))
  return u.toString()
}

export async function enumerateNvdCveIds(
  ctx: CollectContext,
  opts: { sourceIdentifier: string; from: string; to: string; maxPages?: number },
): Promise<{ ids: string[]; snapshots: Snapshot[]; errors: string[] }> {
  if (!/^[A-Za-z0-9@._-]{1,128}$/.test(opts.sourceIdentifier)) throw new Error('invalid sourceIdentifier')
  const ids = new Set<string>()
  const snapshots: Snapshot[] = []
  const errors: string[] = []
  let pages = 0
  for (const w of nvdWindows(opts.from, opts.to)) {
    let startIndex = 0
    for (;;) {
      if (pages++ >= (opts.maxPages ?? 200)) {
        errors.push('page limit reached; enumeration incomplete')
        return { ids: [...ids].sort(), snapshots, errors }
      }
      const url = nvdUrl(opts.sourceIdentifier, w, startIndex)
      const r = await fetchToSnapshot(ctx, { sourceId: NVD_SOURCE.id, url, allowHosts: ['services.nvd.nist.gov'], allowedContentTypes: ['application/json'], retention: 'RAW', maxBytes: 64 * 1024 * 1024 })
      snapshots.push(...r.snapshots)
      if (!r.body || r.carried) {
        errors.push(`${w.start}..${w.end} @${startIndex}: ${r.error ?? 'no content'}`)
        break
      }
      let json: { totalResults?: unknown; vulnerabilities?: unknown }
      try {
        json = JSON.parse(decodeUtf8(r.body)) as typeof json
      } catch {
        errors.push(`${w.start}..${w.end} @${startIndex}: JSON parse error`)
        break
      }
      const vulns = Array.isArray(json.vulnerabilities) ? json.vulnerabilities : []
      for (const v of vulns) {
        const id = (v as { cve?: { id?: unknown } })?.cve?.id
        if (typeof id === 'string' && CVE_ID_PATTERN.test(id)) ids.add(id)
      }
      const total = typeof json.totalResults === 'number' ? json.totalResults : 0
      startIndex += vulns.length
      if (vulns.length === 0 || startIndex >= total) break
    }
  }
  return { ids: [...ids].sort(), snapshots, errors }
}
