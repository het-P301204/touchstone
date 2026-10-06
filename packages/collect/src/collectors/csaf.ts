/**
 * CSAF 2.0 advisories: provider-metadata.json -> ROLIE feeds or directory
 * (changes.csv) -> advisory documents. Only hosts on the vendor's own
 * domains (and subdomains) are fetched.
 */

import type { Advisory, Snapshot, SourceRef, Vendor } from '../../../core/src/model/index.ts'
import { normalizeCsafAdvisory } from '../../../core/src/normalize/csaf.ts'
import { decodeUtf8, fetchToSnapshot, vendorHosts } from './common.ts'
import type { CollectContext } from './common.ts'

export function csafSource(vendor: Vendor): SourceRef {
  return {
    id: `vendor.${vendor.id}.csaf`,
    family: 'VENDOR_ADVISORY',
    title: `${vendor.canonicalName} CSAF advisories`,
    url: vendor.csafProviderUrl ?? '',
    publisher: vendor.canonicalName,
    attribution: 'Vendor-published CSAF 2.0 advisories.',
    retention: 'RAW',
  }
}

function asObj(v: unknown): Record<string, unknown> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null
}

/** Advisory document URLs listed by a provider-metadata document. Exported for tests. */
export function feedUrlsFromProviderMetadata(json: unknown): { rolie: string[]; directories: string[] } {
  const rolie: string[] = []
  const directories: string[] = []
  const dists = asObj(json)?.distributions
  if (!Array.isArray(dists)) return { rolie, directories }
  for (const d of dists.slice(0, 50)) {
    const o = asObj(d)
    if (!o) continue
    if (typeof o.directory_url === 'string') directories.push(o.directory_url)
    const feeds = asObj(o.rolie)?.feeds
    if (Array.isArray(feeds)) for (const f of feeds.slice(0, 50)) if (typeof asObj(f)?.url === 'string') rolie.push(asObj(f)!.url as string)
  }
  return { rolie, directories }
}

/** Advisory URLs from a ROLIE feed (newest first as listed). */
export function advisoryUrlsFromRolie(json: unknown): string[] {
  const entries = asObj(asObj(json)?.feed)?.entry
  if (!Array.isArray(entries)) return []
  const out: string[] = []
  for (const e of entries) {
    const o = asObj(e)
    const src = asObj(o?.content)?.src
    if (typeof src === 'string') {
      out.push(src)
      continue
    }
    const links = o?.link
    if (Array.isArray(links)) {
      const self = links.map(asObj).find((l) => l && l.rel === 'self' && typeof l.href === 'string')
      if (self) out.push(self.href as string)
    }
  }
  return out
}

/** Paths from a CSAF directory changes.csv ("path","timestamp"), newest first. */
export function advisoryPathsFromChangesCsv(text: string): string[] {
  const rows: { path: string; time: string }[] = []
  for (const line of text.split(/\r?\n/).slice(0, 100_000)) {
    if (line.length > 1_000) continue
    const m = /^"?([^",]+)"?\s*,\s*"?([^",]+)"?$/.exec(line.trim())
    if (m && m[1]!.endsWith('.json')) rows.push({ path: m[1]!, time: m[2]! })
  }
  return rows.sort((a, b) => (a.time < b.time ? 1 : a.time > b.time ? -1 : 0)).map((r) => r.path)
}

/** Resolve a feed-supplied (vendor-controlled) URL; null when it does not parse. */
function resolveUrl(u: string, base: string): string | null {
  try {
    return new URL(u, base).toString()
  } catch {
    return null
  }
}

export async function collectCsaf(
  ctx: CollectContext,
  vendor: Vendor,
  opts: { maxAdvisories?: number } = {},
): Promise<{ snapshots: Snapshot[]; advisories: Advisory[]; errors: string[] }> {
  const snapshots: Snapshot[] = []
  const advisories: Advisory[] = []
  const errors: string[] = []
  if (!vendor.csafProviderUrl) return { snapshots, advisories, errors: ['no CSAF provider-metadata URL registered'] }
  const src = csafSource(vendor)
  const hosts = vendorHosts(vendor.domains)
  const max = opts.maxAdvisories ?? 100
  const getJson = async (url: string): Promise<{ json?: unknown; snapshotId?: string }> => {
    const r = await fetchToSnapshot(ctx, { sourceId: src.id, url, allowHosts: hosts, allowedContentTypes: ['application/json'], retention: 'RAW', maxBytes: 8 * 1024 * 1024 })
    snapshots.push(...r.snapshots)
    if (!r.body || !r.used) {
      errors.push(`${url}: ${r.error ?? 'not found'}`)
      return {}
    }
    try {
      return { json: JSON.parse(decodeUtf8(r.body)), snapshotId: r.used.id }
    } catch {
      errors.push(`${url}: JSON parse error`)
      return {}
    }
  }

  if (resolveUrl(vendor.csafProviderUrl, vendor.csafProviderUrl) === null) return { snapshots, advisories, errors: ['CSAF provider-metadata URL does not parse'] }
  const meta = await getJson(vendor.csafProviderUrl)
  if (meta.json === undefined) return { snapshots, advisories, errors }
  const { rolie, directories } = feedUrlsFromProviderMetadata(meta.json)
  const docUrls: string[] = []
  for (const feedUrl of rolie) {
    if (docUrls.length >= max) break
    const feed = await getJson(feedUrl)
    for (const u of advisoryUrlsFromRolie(feed.json)) {
      if (docUrls.length >= max) break
      const resolved = resolveUrl(u, feedUrl)
      if (resolved) docUrls.push(resolved)
      else errors.push(`${feedUrl}: unparseable advisory URL ${JSON.stringify(u.slice(0, 120))}`)
    }
  }
  for (const dir of directories) {
    if (docUrls.length >= max) break
    const base = dir.endsWith('/') ? dir : `${dir}/`
    const r = await fetchToSnapshot(ctx, { sourceId: src.id, url: `${base}changes.csv`, allowHosts: hosts, allowedContentTypes: ['text/csv', 'text/plain'], retention: 'RAW', maxBytes: 8 * 1024 * 1024 })
    snapshots.push(...r.snapshots)
    if (!r.body) {
      errors.push(`${base}changes.csv: ${r.error ?? 'not found'}`)
      continue
    }
    for (const p of advisoryPathsFromChangesCsv(decodeUtf8(r.body))) {
      if (docUrls.length >= max) break
      const resolved = resolveUrl(p, base)
      if (resolved) docUrls.push(resolved)
      else errors.push(`${base}changes.csv: unparseable advisory path ${JSON.stringify(p.slice(0, 120))}`)
    }
  }
  for (const url of [...new Set(docUrls)]) {
    const doc = await getJson(url)
    if (doc.json === undefined || !doc.snapshotId) continue
    const n = normalizeCsafAdvisory(doc.json, { vendorId: vendor.id, snapshotId: doc.snapshotId, url, synthetic: false })
    if (n.ok) advisories.push(n.advisory)
    else errors.push(`${url}: ${n.error}`)
  }
  return { snapshots, advisories, errors }
}
