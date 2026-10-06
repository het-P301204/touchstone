/**
 * Request-level security: structured logs, security headers, Host and Origin
 * checks, a streaming body cap, rate limits and the admin bearer token.
 */
import { createHash, randomUUID, timingSafeEqual } from 'node:crypto'
import type { Context, MiddlewareHandler } from 'hono'
import type { Config, LogLevel } from './config.ts'

export type Env = { Variables: { requestId: string; started: number } }

/** A failure with a status and a stable machine code, rendered as the error envelope. */
export class HttpError extends Error {
  readonly status: number
  readonly code: string
  readonly details: unknown
  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message)
    this.status = status
    this.code = code
    this.details = details
  }
}

export type Log = (level: Exclude<LogLevel, 'silent'>, fields: Record<string, unknown>) => void

/** Structured JSON logs. Callers pass fields, never request bodies, headers or tokens. */
export function logger(level: LogLevel): Log {
  const rank = { debug: 0, info: 1, warn: 2, error: 3, silent: 4 } as const
  return (lvl, fields) => {
    if (rank[lvl] < rank[level]) return
    const line = JSON.stringify({ ts: new Date().toISOString(), level: lvl, service: 'touchstone-api', ...fields })
    if (lvl === 'error' || lvl === 'warn') console.error(line)
    else console.log(line)
  }
}

export function requestContext(log: Log): MiddlewareHandler<Env> {
  return async (c, next) => {
    const incoming = c.req.header('x-request-id')
    const requestId = incoming && /^[A-Za-z0-9-]{8,64}$/.test(incoming) ? incoming : randomUUID()
    c.set('requestId', requestId)
    c.set('started', performance.now())
    await next()
    c.header('X-Request-Id', requestId)
    log(c.res.status >= 500 ? 'error' : 'info', {
      requestId,
      method: c.req.method,
      // The matched route pattern, not the raw path: ids and query strings stay out of the logs.
      route: c.req.routePath,
      status: c.res.status,
      durationMs: Math.round(performance.now() - c.get('started')),
    })
  }
}

/**
 * The Content-Security-Policy for the served single-page app: everything
 * same-origin, fonts self-hosted, no inline scripts, no third-party origins,
 * no framing. Inline styles are allowed for the motion library's transforms.
 */
export const CONTENT_SECURITY_POLICY = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "manifest-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
].join('; ')

export function secureHeaders(config: Config): MiddlewareHandler<Env> {
  return async (c, next) => {
    await next()
    c.header('Content-Security-Policy', CONTENT_SECURITY_POLICY)
    c.header('X-Content-Type-Options', 'nosniff')
    c.header('X-Frame-Options', 'DENY')
    c.header('Referrer-Policy', 'no-referrer')
    c.header('Cross-Origin-Opener-Policy', 'same-origin')
    c.header('Cross-Origin-Resource-Policy', 'same-origin')
    c.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=()')
    c.header('X-Permitted-Cross-Domain-Policies', 'none')
    if (config.production) c.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    if (c.req.path.startsWith('/api/') && !c.res.headers.has('Cache-Control')) c.header('Cache-Control', 'no-store')
  }
}

/**
 * DNS-rebinding protection: when bound to loopback, a page on another site
 * that resolves its own name to 127.0.0.1 must not reach the API.
 */
export function hostCheck(config: Config): MiddlewareHandler<Env> {
  return async (c, next) => {
    if (config.allowedHosts.length) {
      const host = new URL(c.req.url).hostname.toLowerCase()
      const bracketed = host.includes(':') && !host.startsWith('[') ? `[${host}]` : host
      if (!config.allowedHosts.includes(host) && !config.allowedHosts.includes(bracketed)) {
        throw new HttpError(421, 'HOST_NOT_ALLOWED', 'This server does not answer for that host name.')
      }
    }
    await next()
  }
}

/**
 * CORS is off by default: the web app is served from the same origin. Origins
 * in TOUCHSTONE_CORS_ORIGINS get CORS headers. Any other cross-origin request
 * that would change state is rejected, so a page on another site cannot use a
 * simple (unpreflighted) form POST against the API.
 */
export function cors(config: Config): MiddlewareHandler<Env> {
  return async (c, next) => {
    const origin = c.req.header('origin')
    const self = new URL(c.req.url).origin
    const allowed = !!origin && config.corsOrigins.includes(origin)
    if (c.req.method === 'OPTIONS') {
      if (!allowed) return c.body(null, 204)
      c.header('Access-Control-Allow-Origin', origin)
      c.header('Access-Control-Allow-Methods', 'GET, POST')
      c.header('Access-Control-Allow-Headers', 'authorization, content-type, x-request-id')
      c.header('Access-Control-Max-Age', '600')
      c.header('Vary', 'Origin')
      return c.body(null, 204)
    }
    if (origin && origin !== self && !allowed && c.req.method !== 'GET' && c.req.method !== 'HEAD') {
      throw new HttpError(403, 'ORIGIN_REJECTED', 'Cross-origin request rejected.')
    }
    await next()
    if (allowed) {
      c.header('Access-Control-Allow-Origin', origin)
      c.header('Access-Control-Expose-Headers', 'content-disposition, x-request-id, retry-after')
      c.header('Vary', 'Origin')
    }
  }
}

/**
 * Request body cap enforced before and while reading. A declared
 * Content-Length over the cap is refused before a byte is read; a chunked
 * body without one is counted as the handler reads it and the stream errors
 * at the first chunk past the cap. Nothing is read here, so a request the
 * handler rejects early (no token, rate limited, wrong type) is never buffered.
 */
export function streamingBodyLimit(maxSize: number): MiddlewareHandler<Env> {
  const tooLarge = () => new HttpError(413, 'PAYLOAD_TOO_LARGE', `The request body exceeds the ${maxSize}-byte limit.`, { limitBytes: maxSize })
  return async (c, next) => {
    const raw = c.req.raw
    if (!raw.body) return next()
    const declared = raw.headers.get('content-length')
    if (declared !== null && !raw.headers.has('transfer-encoding')) {
      const n = Number(declared)
      if (!Number.isFinite(n) || n > maxSize) throw tooLarge()
    }
    const reader = raw.body.getReader()
    let size = 0
    const limited = new ReadableStream<Uint8Array>({
      async pull(ctrl) {
        const { done, value } = await reader.read()
        if (done) return ctrl.close()
        size += value.byteLength
        if (size > maxSize) {
          void reader.cancel().catch(() => {})
          ctrl.error(tooLarge())
          return
        }
        ctrl.enqueue(value)
      },
      cancel(reason) {
        return reader.cancel(reason)
      },
    })
    c.req.raw = new Request(raw, { body: limited, duplex: 'half' } as RequestInit)
    await next()
  }
}

function digest(s: string): Buffer {
  return createHash('sha256').update(s, 'utf8').digest()
}

/** Constant-time token comparison (hashing first makes the lengths equal). */
export function tokenMatches(presented: string, expected: string): boolean {
  return timingSafeEqual(digest(presented), digest(expected))
}

/**
 * Admin bearer token. Without TOUCHSTONE_ADMIN_TOKEN every admin endpoint is
 * 403 "administration disabled"; with it, a missing or wrong token is 401.
 * Runs before any body is read.
 */
export function adminAuth(config: Config): MiddlewareHandler<Env> {
  const expected = config.adminToken
  return async (c, next) => {
    if (!expected) throw new HttpError(403, 'ADMIN_DISABLED', 'administration disabled: set TOUCHSTONE_ADMIN_TOKEN to enable administrative endpoints.')
    const auth = c.req.header('authorization') ?? ''
    const m = /^Bearer[ \t]+([^\s]+)[ \t]*$/i.exec(auth)
    if (!m || !tokenMatches(m[1]!, expected)) {
      c.header('WWW-Authenticate', 'Bearer realm="touchstone-admin"')
      throw new HttpError(401, 'UNAUTHORIZED', 'A valid admin bearer token is required.')
    }
    await next()
  }
}

/** Most client keys a single limiter tracks; beyond this the oldest entry is evicted. */
export const RATE_LIMIT_MAX_KEYS = 10_000

/**
 * Fixed-window in-memory rate limit per client (per API instance).
 *
 * Clients are keyed by `rateLimitKey`: an IPv4 address as is, an IPv6 address
 * by its /64 (one host normally controls a whole /64, so rotating through it
 * must not buy fresh buckets). The map of keys is capped: expired windows are
 * swept first, then the oldest key is evicted, so an address flood cannot
 * grow memory without bound.
 */
export function rateLimit(
  bucket: string,
  limit: number,
  windowMs: number,
  trustProxy: boolean,
  now: () => number = Date.now,
  maxKeys: number = RATE_LIMIT_MAX_KEYS,
): MiddlewareHandler<Env> {
  const hits = new Map<string, { count: number; reset: number }>()
  let nextSweep = now() + windowMs
  const sweep = (t: number) => {
    for (const [k, v] of hits) if (v.reset <= t) hits.delete(k)
    nextSweep = t + windowMs
  }
  return async (c, next) => {
    const t = now()
    if (t >= nextSweep) sweep(t)
    const key = rateLimitKey(clientAddress(c, trustProxy))
    let h = hits.get(key)
    if (!h || h.reset <= t) {
      hits.delete(key)
      if (hits.size >= maxKeys) sweep(t)
      while (hits.size >= maxKeys) hits.delete(hits.keys().next().value!)
      h = { count: 0, reset: t + windowMs }
      hits.set(key, h)
    }
    h.count++
    c.header('RateLimit-Policy', `${limit};w=${Math.round(windowMs / 1000)};name="${bucket}"`)
    c.header('RateLimit-Limit', String(limit))
    c.header('RateLimit-Remaining', String(Math.max(0, limit - h.count)))
    if (h.count > limit) {
      c.header('Retry-After', String(Math.max(1, Math.ceil((h.reset - t) / 1000))))
      throw new HttpError(429, 'RATE_LIMITED', 'Too many requests. Try again later.', { bucket })
    }
    await next()
  }
}

/**
 * A server-wide ceiling per window, independent of client address: the
 * backstop for an actor spread across many addresses or prefixes. `check()`
 * runs before the work, `consume()` after it is accepted, so requests that
 * fail validation do not use up the ceiling for everyone else.
 */
export class GlobalCeiling {
  readonly bucket: string
  readonly limit: number
  readonly windowMs: number
  private readonly now: () => number
  private count = 0
  private reset = 0
  constructor(bucket: string, limit: number, windowMs: number, now: () => number = Date.now) {
    this.bucket = bucket
    this.limit = limit
    this.windowMs = windowMs
    this.now = now
  }
  private roll(): number {
    const t = this.now()
    if (t >= this.reset) {
      this.count = 0
      this.reset = t + this.windowMs
    }
    return t
  }
  /** Throws 429 RATE_LIMITED_GLOBAL when the ceiling is reached. */
  check(c?: Context<Env>): void {
    const t = this.roll()
    if (this.count >= this.limit) {
      c?.header('Retry-After', String(Math.max(1, Math.ceil((this.reset - t) / 1000))))
      throw new HttpError(429, 'RATE_LIMITED_GLOBAL', 'This server has reached its hourly limit for this operation. Try again later.', { bucket: this.bucket })
    }
  }
  consume(): void {
    this.roll()
    this.count++
  }
}

/**
 * Client address: the socket's remote address. Only when
 * TOUCHSTONE_TRUST_PROXY=true (one trusted reverse proxy in front) is the
 * right-most X-Forwarded-For entry used, the one that proxy appended; entries
 * to its left are client-supplied and forgeable.
 */
export function clientAddress(c: Context<Env>, trustProxy: boolean): string {
  const env = c.env as { incoming?: { socket?: { remoteAddress?: string } } } | undefined
  let addr = env?.incoming?.socket?.remoteAddress ?? 'local'
  if (trustProxy) {
    const chain = (c.req.header('x-forwarded-for') ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean)
    const picked = chain[chain.length - 1]
    if (picked && picked.length <= 64) addr = picked
  }
  return addr.replace(/^::ffff:(?=\d+\.\d+\.\d+\.\d+$)/i, '')
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/

/** Expand an IPv6 literal (optionally with an embedded IPv4 tail and/or zone) to 8 groups, or null. */
export function expandIPv6(input: string): number[] | null {
  let s = input.trim().toLowerCase()
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1)
  const zone = s.indexOf('%')
  if (zone >= 0) s = s.slice(0, zone)
  if (!s.includes(':')) return null
  // An embedded IPv4 tail (::ffff:192.0.2.1) becomes two hex groups.
  const lastColon = s.lastIndexOf(':')
  const maybeV4 = s.slice(lastColon + 1)
  if (maybeV4.includes('.')) {
    const m = IPV4_RE.exec(maybeV4)
    if (!m) return null
    const o = m.slice(1, 5).map(Number)
    if (o.some((x) => x > 255)) return null
    s = `${s.slice(0, lastColon + 1)}${((o[0]! << 8) | o[1]!).toString(16)}:${((o[2]! << 8) | o[3]!).toString(16)}`
  }
  const want = 8
  const parseGroups = (part: string): number[] | null => {
    if (part === '') return []
    const out: number[] = []
    for (const g of part.split(':')) {
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null
      out.push(parseInt(g, 16))
    }
    return out
  }
  let groups: number[]
  const dbl = s.indexOf('::')
  if (dbl >= 0) {
    if (s.indexOf('::', dbl + 1) >= 0) return null
    const head = parseGroups(s.slice(0, dbl))
    const rest = parseGroups(s.slice(dbl + 2))
    if (!head || !rest || head.length + rest.length > want - 1) return null
    groups = [...head, ...new Array<number>(want - head.length - rest.length).fill(0), ...rest]
  } else {
    const all = parseGroups(s)
    if (!all || all.length !== want) return null
    groups = all
  }
  return groups
}

/**
 * The rate-limit key for a client address: IPv4 as is; IPv4-mapped IPv6 as
 * its IPv4 address; any other IPv6 address as its /64 prefix. Anything that is
 * not an IP literal (e.g. "local" in tests) is used as given, bounded in length.
 */
export function rateLimitKey(addr: string): string {
  const a = addr.trim()
  if (IPV4_RE.test(a)) return a
  const g = expandIPv6(a)
  if (!g) return a.slice(0, 64)
  if (g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0xffff) {
    return `${g[6]! >> 8}.${g[6]! & 0xff}.${g[7]! >> 8}.${g[7]! & 0xff}`
  }
  return `${g.slice(0, 4).map((x) => x.toString(16)).join(':')}::/64`
}
