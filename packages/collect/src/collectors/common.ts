/**
 * Shared plumbing for collectors: one fetch -> one recorded snapshot.
 *
 * Outcomes:
 *   - 2xx with an accepted content type: OK snapshot (raw bytes kept for RAW sources);
 *   - 404 / 410: OK snapshot with httpStatus and no content (an observation of absence);
 *   - anything else: FAILED snapshot. When an earlier OK snapshot of the same
 *     source+URL exists, it is named in `substitutedBy` and its content is
 *     returned with `carried: true`. The substitution is never silent.
 */

import type { RetentionMode, Snapshot } from '../../../core/src/model/index.ts'
import { safeFetch } from '../safe-fetch.ts'
import type { SafeFetchOptions, SafeFetchResult } from '../safe-fetch.ts'
import type { SnapshotStore } from '../store.ts'

export type Fetcher = (url: string, opts: SafeFetchOptions) => Promise<SafeFetchResult>

export type CollectContext = {
  store: SnapshotStore
  /** Base safe-fetch options (resolver, transport, rate limiter, UA); per-call fields override. */
  fetchDefaults: Partial<SafeFetchOptions>
  fetcher?: Fetcher
  parserVersion: string
}

export type FetchOutcome = {
  /** Every snapshot recorded by this call (a failure plus nothing, or one OK). */
  snapshots: Snapshot[]
  /** The snapshot whose content is used (the fresh one, or the substitute). */
  used?: Snapshot
  /** Content to parse, when any. */
  body?: Uint8Array
  /** Text kept for an EXTRACT_ONLY substitute. */
  carriedText?: string
  carried: boolean
  absent: boolean
  error?: string
}

const decoder = new TextDecoder('utf-8', { fatal: false })
export const decodeUtf8 = (b: Uint8Array) => decoder.decode(b)

export async function fetchToSnapshot(
  ctx: CollectContext,
  req: { sourceId: string; url: string; allowHosts: string[]; allowedContentTypes: string[]; retention: RetentionMode; maxBytes?: number },
): Promise<FetchOutcome> {
  const fetcher = ctx.fetcher ?? safeFetch
  const opts: SafeFetchOptions = { ...ctx.fetchDefaults, allowHosts: req.allowHosts, allowedContentTypes: req.allowedContentTypes }
  if (req.maxBytes !== undefined) opts.maxBytes = req.maxBytes
  const res = await fetcher(req.url, opts)
  if (res.ok) {
    const snap = ctx.store.record({
      sourceId: req.sourceId,
      url: req.url,
      fetchedAt: res.fetchedAt,
      body: res.body,
      retention: req.retention,
      parserVersion: ctx.parserVersion,
      httpStatus: res.status,
      contentType: res.contentType,
    })
    return { snapshots: [snap], used: snap, body: res.body, carried: false, absent: false }
  }
  if (res.code === 'HTTP_STATUS' && (res.status === 404 || res.status === 410)) {
    const snap = ctx.store.record({ sourceId: req.sourceId, url: req.url, fetchedAt: res.fetchedAt, body: new Uint8Array(0), retention: 'EXTRACT_ONLY', parserVersion: ctx.parserVersion, httpStatus: res.status })
    return { snapshots: [snap], used: snap, carried: false, absent: true }
  }
  const previous = ctx.store.latestOk(req.sourceId, req.url)
  const usable = previous && previous.httpStatus !== 404 && previous.httpStatus !== 410 ? previous : undefined
  const failure = ctx.store.recordFailure({
    sourceId: req.sourceId,
    url: req.url,
    fetchedAt: res.fetchedAt,
    error: `${res.code}: ${res.error}`,
    parserVersion: ctx.parserVersion,
    ...(res.status !== undefined ? { httpStatus: res.status } : {}),
    ...(usable ? { substitutedBy: usable.id } : {}),
  })
  if (!usable) return { snapshots: [failure], carried: false, absent: false, error: failure.error! }
  const out: FetchOutcome = { snapshots: [failure, usable], used: usable, carried: true, absent: false, error: failure.error! }
  if (usable.sha256 && usable.rawPath) {
    const body = ctx.store.get(usable.sha256)
    if (body) out.body = body
  }
  const text = ctx.store.getExtract(usable.id)
  if (text !== null) out.carriedText = text
  return out
}

/** Hosts a vendor's documents may be fetched from: its domains and their subdomains. */
export function vendorHosts(domains: string[]): string[] {
  return domains.flatMap((d) => [d, `*.${d}`])
}
