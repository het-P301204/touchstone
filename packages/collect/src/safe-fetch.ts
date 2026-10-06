/**
 * SSRF-safe outbound fetch for public-source collection.
 *
 * Every request, and every redirect hop, is checked before any byte leaves:
 *   - https only, port 443 only, no credentials in the URL;
 *   - the host must be on the caller's allowlist (exact host, or "*.domain"
 *     for subdomains); IP literals are refused;
 *   - the host is resolved once and EVERY returned address must be globally
 *     routable (no loopback, private, link-local, CGNAT, ULA, multicast,
 *     IPv4-mapped, NAT64, documentation ranges);
 *   - the connection is pinned to the validated address through the socket
 *     `lookup` hook, so a DNS answer that changes between validation and
 *     connect (DNS rebinding) cannot redirect the request;
 *   - redirects are followed manually, at most 3, each re-validated;
 *   - connect and total timeouts, a byte cap (Content-Length and streamed),
 *     a content-type allowlist, and identity encoding only;
 *   - an identifying User-Agent; no cookies, no Authorization, no Referer;
 *   - a per-host rate limit.
 *
 * The resolver and the transport are injectable so all of this is tested
 * without the network.
 */

import { lookup as dnsLookup } from 'node:dns/promises'
import { createHash } from 'node:crypto'
import https from 'node:https'
import type { LookupFunction } from 'node:net'
import { classifyAddress, isIpLiteral } from './ip.ts'

export const DEFAULT_USER_AGENT = 'TOUCHSTONE/0.1 (public-evidence research collector; +https://github.com/touchstone-research/touchstone)'
export const MAX_REDIRECTS = 3

export type ResolvedAddress = { address: string; family: 4 | 6 }
export type Resolver = (hostname: string) => Promise<ResolvedAddress[]>

export type TransportRequest = {
  url: URL
  /** The validated address the connection MUST use. */
  address: string
  family: 4 | 6
  headers: Record<string, string>
  signal: AbortSignal
  connectTimeoutMs: number
}

export type TransportResponse = {
  status: number
  headers: Record<string, string | string[] | undefined>
  body: AsyncIterable<Uint8Array>
  /** Abort reading the body (called on oversize, redirects and errors). */
  destroy: () => void
}

export type Transport = (req: TransportRequest) => Promise<TransportResponse>

export type SafeFetchErrorCode =
  | 'BAD_URL'
  | 'SCHEME'
  | 'PORT'
  | 'CREDENTIALS'
  | 'IP_LITERAL'
  | 'HOST_NOT_ALLOWED'
  | 'DNS'
  | 'BLOCKED_ADDRESS'
  | 'TOO_MANY_REDIRECTS'
  | 'BAD_REDIRECT'
  | 'HTTP_STATUS'
  | 'CONTENT_TYPE'
  | 'CONTENT_ENCODING'
  | 'TOO_LARGE'
  | 'TIMEOUT'
  | 'NETWORK'

export type SafeFetchOptions = {
  /** "host.example" (exact) or "*.example.org" (any subdomain, not the apex). */
  allowHosts: string[]
  /** Media types accepted (e.g. "application/json"); parameters are ignored. */
  allowedContentTypes: string[]
  maxBytes?: number
  timeoutMs?: number
  connectTimeoutMs?: number
  maxRedirects?: number
  userAgent?: string
  accept?: string
  resolver?: Resolver
  transport?: Transport
  rateLimiter?: HostRateLimiter
  now?: () => Date
}

export type SafeFetchSuccess = {
  ok: true
  url: string
  finalUrl: string
  status: number
  contentType: string
  body: Uint8Array
  sha256: string
  bytes: number
  redirects: string[]
  address: string
  fetchedAt: string
}

export type SafeFetchFailure = {
  ok: false
  url: string
  code: SafeFetchErrorCode
  error: string
  status?: number
  redirects: string[]
  fetchedAt: string
}

export type SafeFetchResult = SafeFetchSuccess | SafeFetchFailure

class FetchError extends Error {
  code: SafeFetchErrorCode
  status?: number
  constructor(code: SafeFetchErrorCode, message: string, status?: number) {
    super(message)
    this.code = code
    if (status !== undefined) this.status = status
  }
}

// ------------------------------------------------------------------ rate limit

/** Minimum interval between requests to the same host. Calls for one host are serialized. */
export class HostRateLimiter {
  intervalMs: number
  private next = new Map<string, number>()
  private clock: () => number
  private sleep: (ms: number) => Promise<void>
  constructor(intervalMs: number, clock: () => number = () => Date.now(), sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms))) {
    this.intervalMs = intervalMs
    this.clock = clock
    this.sleep = sleep
  }
  async wait(host: string): Promise<void> {
    const now = this.clock()
    const at = Math.max(now, this.next.get(host) ?? 0)
    this.next.set(host, at + this.intervalMs)
    if (at > now) await this.sleep(at - now)
  }
}

// ------------------------------------------------------------------ validation

export function hostAllowed(host: string, allowHosts: string[]): boolean {
  const h = host.toLowerCase().replace(/\.$/, '')
  for (const rule of allowHosts) {
    const r = rule.toLowerCase().replace(/\.$/, '')
    if (r.startsWith('*.')) {
      const base = r.slice(2)
      if (base.length > 0 && h.endsWith(`.${base}`) && h.length > base.length + 1) return true
    } else if (h === r) {
      return true
    }
  }
  return false
}

/** Validate a URL against everything that can be checked without DNS. Throws FetchError. */
export function validateUrl(raw: string, allowHosts: string[]): URL {
  let url: URL
  try {
    url = new URL(raw)
  } catch {
    throw new FetchError('BAD_URL', `not a valid URL: ${JSON.stringify(raw.slice(0, 200))}`)
  }
  if (url.protocol !== 'https:') throw new FetchError('SCHEME', `scheme ${url.protocol} refused: https only`)
  if (url.port !== '' && url.port !== '443') throw new FetchError('PORT', `port ${url.port} refused: 443 only`)
  if (url.username !== '' || url.password !== '') throw new FetchError('CREDENTIALS', 'credentials in URL refused')
  const host = url.hostname.replace(/\.$/, '')
  if (host.length === 0) throw new FetchError('BAD_URL', 'empty host')
  if (isIpLiteral(host)) throw new FetchError('IP_LITERAL', `IP literal host ${host} refused`)
  if (!hostAllowed(host, allowHosts)) throw new FetchError('HOST_NOT_ALLOWED', `host ${host} is not on the allowlist`)
  url.hash = ''
  return url
}

const defaultResolver: Resolver = async (hostname) => {
  const rows = await dnsLookup(hostname, { all: true, verbatim: true })
  return rows.map((r) => ({ address: r.address, family: r.family === 6 ? 6 : 4 }))
}

/** Resolve and require every address to be public. Returns the address to pin. */
async function resolvePublic(host: string, resolver: Resolver): Promise<ResolvedAddress> {
  let addrs: ResolvedAddress[]
  try {
    addrs = await resolver(host)
  } catch (err) {
    throw new FetchError('DNS', `DNS resolution failed for ${host}: ${(err as Error).message}`)
  }
  if (addrs.length === 0) throw new FetchError('DNS', `no addresses for ${host}`)
  let pinned: ResolvedAddress | undefined
  for (const a of addrs) {
    const v = classifyAddress(a.address)
    if (!v.ok) throw new FetchError('BLOCKED_ADDRESS', `${host} resolves to a non-public address: ${v.reason}`)
    pinned ??= { address: a.address, family: v.family }
  }
  return pinned!
}

// ------------------------------------------------------------------ default transport (node:https, pinned)

/** A socket lookup that ignores the hostname and always answers with the validated address. */
export function pinnedLookup(address: string, family: 4 | 6): LookupFunction {
  return (_hostname, options, callback) => {
    if (typeof options === 'object' && options !== null && (options as { all?: boolean }).all) {
      ;(callback as unknown as (e: null, a: { address: string; family: number }[]) => void)(null, [{ address, family }])
    } else {
      callback(null, address, family)
    }
  }
}

export const httpsTransport: Transport = (req) =>
  new Promise((resolve, reject) => {
    // Connect only to the address validated before the request (DNS rebinding defence).
    const pinned = pinnedLookup(req.address, req.family)
    const r = https.request(
      {
        host: req.url.hostname,
        servername: req.url.hostname,
        port: 443,
        method: 'GET',
        path: `${req.url.pathname}${req.url.search}`,
        headers: req.headers,
        lookup: pinned,
        agent: false,
        signal: req.signal,
      },
      (res) => {
        resolve({ status: res.statusCode ?? 0, headers: res.headers, body: res, destroy: () => res.destroy() })
      },
    )
    r.on('socket', (socket) => {
      const t = setTimeout(() => r.destroy(new Error(`connect timeout after ${req.connectTimeoutMs} ms`)), req.connectTimeoutMs)
      socket.once('secureConnect', () => clearTimeout(t))
      socket.once('close', () => clearTimeout(t))
    })
    r.on('error', reject)
    r.end()
  })

// ------------------------------------------------------------------ fetch

function header(h: TransportResponse['headers'], name: string): string | undefined {
  const v = h[name] ?? h[name.toLowerCase()]
  if (Array.isArray(v)) return v[0]
  return v
}

function withDeadline<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(new FetchError('TIMEOUT', 'deadline exceeded'))
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new FetchError('TIMEOUT', 'deadline exceeded'))
    signal.addEventListener('abort', onAbort, { once: true })
    p.then(
      (v) => {
        signal.removeEventListener('abort', onAbort)
        resolve(v)
      },
      (e) => {
        signal.removeEventListener('abort', onAbort)
        reject(e)
      },
    )
  })
}

export async function safeFetch(url: string, opts: SafeFetchOptions): Promise<SafeFetchResult> {
  const now = opts.now ?? (() => new Date())
  const fetchedAt = now().toISOString()
  const redirects: string[] = []
  const maxBytes = opts.maxBytes ?? 5 * 1024 * 1024
  const maxRedirects = Math.min(opts.maxRedirects ?? MAX_REDIRECTS, MAX_REDIRECTS)
  const resolver = opts.resolver ?? defaultResolver
  const transport = opts.transport ?? httpsTransport
  const allowedTypes = opts.allowedContentTypes.map((t) => t.toLowerCase())
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), opts.timeoutMs ?? 20_000)
  const headers: Record<string, string> = {
    'User-Agent': opts.userAgent ?? DEFAULT_USER_AGENT,
    Accept: opts.accept ?? (allowedTypes.join(', ') || '*/*'),
    'Accept-Encoding': 'identity',
  }

  let current = url
  try {
    for (let hop = 0; ; hop++) {
      const target = validateUrl(current, opts.allowHosts)
      const pinned = await withDeadline(resolvePublic(target.hostname.replace(/\.$/, ''), resolver), controller.signal)
      if (opts.rateLimiter) await withDeadline(opts.rateLimiter.wait(target.hostname), controller.signal)
      let res: TransportResponse
      try {
        res = await withDeadline(
          transport({ url: target, address: pinned.address, family: pinned.family, headers: { ...headers }, signal: controller.signal, connectTimeoutMs: opts.connectTimeoutMs ?? 5_000 }),
          controller.signal,
        )
      } catch (err) {
        if (err instanceof FetchError) throw err
        if (controller.signal.aborted) throw new FetchError('TIMEOUT', 'deadline exceeded')
        throw new FetchError('NETWORK', `request failed: ${(err as Error).message}`)
      }

      if ([301, 302, 303, 307, 308].includes(res.status)) {
        res.destroy()
        const location = header(res.headers, 'location')
        if (!location) throw new FetchError('BAD_REDIRECT', `redirect ${res.status} without Location`, res.status)
        if (hop >= maxRedirects) throw new FetchError('TOO_MANY_REDIRECTS', `more than ${maxRedirects} redirects`, res.status)
        let next: URL
        try {
          next = new URL(location, target)
        } catch {
          throw new FetchError('BAD_REDIRECT', `unparseable Location ${JSON.stringify(location.slice(0, 200))}`, res.status)
        }
        redirects.push(next.toString())
        current = next.toString()
        continue
      }
      if (res.status < 200 || res.status > 299) {
        res.destroy()
        throw new FetchError('HTTP_STATUS', `HTTP ${res.status}`, res.status)
      }
      const encoding = (header(res.headers, 'content-encoding') ?? 'identity').trim().toLowerCase()
      if (encoding !== '' && encoding !== 'identity') {
        res.destroy()
        throw new FetchError('CONTENT_ENCODING', `content-encoding ${encoding} refused (identity requested)`, res.status)
      }
      const contentType = (header(res.headers, 'content-type') ?? '').trim()
      const media = contentType.split(';')[0]!.trim().toLowerCase()
      if (!allowedTypes.includes(media)) {
        res.destroy()
        throw new FetchError('CONTENT_TYPE', `content-type ${JSON.stringify(contentType.slice(0, 100))} not in ${allowedTypes.join(', ')}`, res.status)
      }
      const declared = Number(header(res.headers, 'content-length'))
      if (Number.isFinite(declared) && declared > maxBytes) {
        res.destroy()
        throw new FetchError('TOO_LARGE', `Content-Length ${declared} exceeds ${maxBytes} bytes`, res.status)
      }
      const chunks: Uint8Array[] = []
      let total = 0
      try {
        for await (const chunk of res.body) {
          total += chunk.byteLength
          if (total > maxBytes) {
            res.destroy()
            throw new FetchError('TOO_LARGE', `body exceeds ${maxBytes} bytes`, res.status)
          }
          chunks.push(chunk)
          if (controller.signal.aborted) throw new FetchError('TIMEOUT', 'deadline exceeded while reading the body')
        }
      } catch (err) {
        if (err instanceof FetchError) throw err
        if (controller.signal.aborted) throw new FetchError('TIMEOUT', 'deadline exceeded while reading the body')
        throw new FetchError('NETWORK', `body read failed: ${(err as Error).message}`, res.status)
      }
      const body = new Uint8Array(total)
      let off = 0
      for (const c of chunks) {
        body.set(c, off)
        off += c.byteLength
      }
      return {
        ok: true,
        url,
        finalUrl: target.toString(),
        status: res.status,
        contentType,
        body,
        sha256: createHash('sha256').update(body).digest('hex'),
        bytes: total,
        redirects,
        address: pinned.address,
        fetchedAt,
      }
    }
  } catch (err) {
    const e = err instanceof FetchError ? err : new FetchError('NETWORK', (err as Error).message)
    const out: SafeFetchFailure = { ok: false, url, code: e.code, error: e.message, redirects, fetchedAt }
    if (e.status !== undefined) out.status = e.status
    return out
  } finally {
    clearTimeout(timer)
  }
}
