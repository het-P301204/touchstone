/**
 * Vulnerability disclosure policy page.
 *
 * Fetched only from the vendor's own domains (and subdomains) or from a known
 * disclosure platform, and only when the host's robots.txt allows it for our
 * product token. Third-party policy pages are EXTRACT_ONLY: the raw HTML is
 * hashed, not kept; the extracted text is kept so a later failed fetch can be
 * carried forward explicitly.
 */

import type { SecurityTxt, Snapshot, SourceRef, Vendor } from '../../../core/src/model/index.ts'
import { htmlToText } from '../../../core/src/text/html.ts'
import { robotsAllows } from '../robots.ts'
import { hostAllowed } from '../safe-fetch.ts'
import { decodeUtf8, fetchToSnapshot, vendorHosts } from './common.ts'
import type { CollectContext } from './common.ts'

/** Disclosure platforms whose program pages may be fetched. */
export const KNOWN_VDP_PLATFORMS: readonly string[] = ['hackerone.com', 'bugcrowd.com', 'app.intigriti.com', 'yeswehack.com', 'responsibledisclosure.com']

export const ROBOTS_TOKEN = 'TOUCHSTONE'

export function vdpSource(vendor: Vendor, url: string): SourceRef {
  return {
    id: `vendor.${vendor.id}.vdp`,
    family: 'VENDOR_VDP',
    title: `${vendor.canonicalName} vulnerability disclosure policy`,
    url,
    publisher: vendor.canonicalName,
    attribution: 'Vendor policy page. Only a hash and the extracted text are retained.',
    retention: 'EXTRACT_ONLY',
  }
}

export function policyAllowHosts(vendor: Vendor): string[] {
  return [...vendorHosts(vendor.domains), ...KNOWN_VDP_PLATFORMS, ...KNOWN_VDP_PLATFORMS.map((p) => `*.${p}`)]
}

/** The first candidate policy URL that is https and on an allowed host. */
export function choosePolicyUrl(vendor: Vendor, securityTxt: SecurityTxt): string | undefined {
  const hosts = policyAllowHosts(vendor)
  for (const candidate of [...securityTxt.policyUrls, ...(vendor.vdpPolicyUrl ? [vendor.vdpPolicyUrl] : [])]) {
    try {
      const u = new URL(candidate)
      if (u.protocol === 'https:' && hostAllowed(u.hostname, hosts)) return u.toString()
    } catch {
      // not a URL
    }
  }
  return undefined
}

export type PolicyResult = {
  snapshots: Snapshot[]
  /** Input for assessVdp's `policy`. */
  policy: { found: boolean; url?: string; snapshotId?: string; text?: string; host?: string; fetchFailed?: boolean }
  carriedFromSnapshotId?: string
  observedAt?: string
  note?: string
}

export async function collectVdpPolicy(ctx: CollectContext, vendor: Vendor, securityTxt: SecurityTxt): Promise<PolicyResult> {
  const url = choosePolicyUrl(vendor, securityTxt)
  if (!url) return { snapshots: [], policy: { found: false }, note: 'No policy URL on an allowed host (vendor domain or known disclosure platform).' }
  const u = new URL(url)
  const hosts = policyAllowHosts(vendor)
  const snapshots: Snapshot[] = []

  // robots.txt: 404 means no restrictions; any other failure means do not fetch (RFC 9309 section 2.3.1.4).
  const robots = await fetchToSnapshot(ctx, { sourceId: `robots.${u.hostname}`, url: `https://${u.hostname}/robots.txt`, allowHosts: hosts, allowedContentTypes: ['text/plain'], retention: 'EXTRACT_ONLY', maxBytes: 512 * 1024 })
  if (!robots.absent) {
    if (!robots.body || robots.carried) {
      return { snapshots, policy: { found: true, url, host: u.hostname, fetchFailed: true }, note: `robots.txt unavailable (${robots.error ?? 'no content'}); policy not fetched.` }
    }
    if (!robotsAllows(decodeUtf8(robots.body), `${u.pathname}${u.search}`, ROBOTS_TOKEN)) {
      return { snapshots, policy: { found: true, url, host: u.hostname, fetchFailed: true }, note: 'robots.txt disallows this path for TOUCHSTONE; policy not fetched.' }
    }
  }

  const src = vdpSource(vendor, url)
  const r = await fetchToSnapshot(ctx, { sourceId: src.id, url, allowHosts: hosts, allowedContentTypes: ['text/html', 'application/xhtml+xml', 'text/plain'], retention: 'EXTRACT_ONLY', maxBytes: 2 * 1024 * 1024 })
  snapshots.push(...r.snapshots)
  if (r.absent) return { snapshots, policy: { found: false }, observedAt: r.used!.fetchedAt, note: `Policy URL returned HTTP ${r.used!.httpStatus}.` }
  if (r.used && r.carried) {
    const text = r.carriedText
    const out: PolicyResult = { snapshots, carriedFromSnapshotId: r.used.id, observedAt: r.used.fetchedAt, policy: text ? { found: true, url, snapshotId: r.used.id, text, host: u.hostname } : { found: true, url, host: u.hostname, fetchFailed: true } }
    return out
  }
  if (!r.body || !r.used) return { snapshots, policy: { found: true, url, host: u.hostname, fetchFailed: true }, note: r.error ?? 'no content' }
  const raw = decodeUtf8(r.body)
  const text = r.used.contentType?.startsWith('text/plain') ? raw : htmlToText(raw).text
  ctx.store.putExtract(r.used.id, text)
  return { snapshots, observedAt: r.used.fetchedAt, policy: { found: true, url, snapshotId: r.used.id, text, host: u.hostname } }
}
