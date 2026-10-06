import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { Hono } from 'hono'
import { ConfigError, loadConfig } from '../src/config.ts'
import { CONTENT_SECURITY_POLICY, clientAddress, rateLimit, tokenMatches } from '../src/security.ts'
import type { Env, HttpError } from '../src/security.ts'
import { resolveInside } from '../src/static.ts'
import { NORTHWIND, RUN_2 } from './fixtures/bundle.ts'
import { ADMIN, makeApp } from './helpers.ts'

type Json = Record<string, any>

const dispute = () => ({
  vendorId: NORTHWIND,
  runId: RUN_2,
  target: { kind: 'GOAL', id: 'G5' },
  reason: 'OUTDATED_SOURCE',
  submitterRole: 'RESEARCHER',
  statement: 'The policy changed.',
  evidenceUrls: [],
})

describe('security headers', () => {
  const t = makeApp()
  afterAll(() => t.close())

  it('sets CSP, nosniff, frame-ancestors none and referrer policy on every response', async () => {
    for (const path of ['/api/health', '/api/runs', '/api/nope', '/nothing-here']) {
      const r = await t.app.request(path)
      expect(r.headers.get('content-security-policy'), path).toBe(CONTENT_SECURITY_POLICY)
      expect(r.headers.get('x-content-type-options')).toBe('nosniff')
      expect(r.headers.get('referrer-policy')).toBe('no-referrer')
      expect(r.headers.get('x-frame-options')).toBe('DENY')
    }
    expect(CONTENT_SECURITY_POLICY).toContain("frame-ancestors 'none'")
    expect(CONTENT_SECURITY_POLICY).toContain("script-src 'self'")
    expect(CONTENT_SECURITY_POLICY).not.toContain('unsafe-eval')
    expect((await t.app.request('/api/runs')).headers.get('cache-control')).toBe('no-store')
  })

  it('errors never include stack traces', async () => {
    const r = await t.app.request('/api/signatories?limit=abc')
    const text = await r.text()
    expect(r.status).toBe(400)
    expect(text).not.toMatch(/at .*\.ts:\d+/)
    expect(JSON.parse(text).error.code).toBe('VALIDATION_FAILED')
  })
})

describe('administration disabled (no TOUCHSTONE_ADMIN_TOKEN)', () => {
  const t = makeApp()
  afterAll(() => t.close())

  it('answers 403 "administration disabled" on every admin endpoint, with or without a token', async () => {
    const calls: [string, string, unknown][] = [
      ['POST', '/api/refresh', {}],
      ['POST', '/api/disputes/DSP-0001/transition', { to: 'UNDER_REVIEW', note: 'x' }],
      ['POST', '/api/notebook', { title: 't', observation: 'o' }],
    ]
    for (const [method, path, body] of calls) {
      for (const headers of [{}, { authorization: `Bearer ${ADMIN}` }] as Record<string, string>[]) {
        const r = await t.json(method, path, body, headers)
        expect(r.status, path).toBe(403)
        const e = ((await r.json()) as Json).error
        expect(e.code).toBe('ADMIN_DISABLED')
        expect(e.message).toContain('administration disabled')
      }
    }
    expect(((await (await t.app.request('/api/health')).json()) as Json).adminEnabled).toBe(false)
    // Public endpoints keep working.
    expect((await t.json('POST', '/api/disputes', dispute())).status).toBe(201)
  })
})

describe('admin token', () => {
  it('compares tokens of any length in constant time', () => {
    expect(tokenMatches(ADMIN, ADMIN)).toBe(true)
    expect(tokenMatches('', ADMIN)).toBe(false)
    expect(tokenMatches(ADMIN + ADMIN, ADMIN)).toBe(false)
  })

  it('accepts only "Bearer <token>"', async () => {
    const t = makeApp({ adminToken: ADMIN })
    for (const auth of [`Basic ${ADMIN}`, `Bearer`, `Bearer ${ADMIN} extra`, ADMIN, `Bearer ${ADMIN.slice(0, -1)}`]) {
      const r = await t.json('POST', '/api/notebook', { title: 't', observation: 'o' }, { authorization: auth })
      expect(r.status, auth).toBe(401)
      expect(r.headers.get('www-authenticate')).toContain('Bearer')
    }
    expect((await t.json('POST', '/api/notebook', { title: 't', observation: 'o' }, { authorization: `bearer ${ADMIN}` })).status).toBe(201)
    await t.close()
  })
})

describe('request body cap', () => {
  const t = makeApp({ maxBodyBytes: 4096 })
  afterAll(() => t.close())

  it('refuses a declared Content-Length over the cap before reading any of the body', async () => {
    let pulled = 0
    const body = new ReadableStream<Uint8Array>({
      pull(ctrl) {
        pulled++
        ctrl.enqueue(new Uint8Array(1024).fill(0x20))
      },
    })
    const r = await t.app.request('/api/disputes', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'content-length': String(10 * 1024 * 1024) },
      body,
      duplex: 'half',
    } as RequestInit)
    expect(r.status).toBe(413)
    expect(((await r.json()) as Json).error.code).toBe('PAYLOAD_TOO_LARGE')
    expect(pulled).toBeLessThanOrEqual(1) // a stream may pre-pull once on construction; nothing was consumed
  })

  it('cuts off a chunked body without Content-Length at the first chunk past the cap', async () => {
    let pulled = 0
    const body = new ReadableStream<Uint8Array>({
      pull(ctrl) {
        pulled++
        ctrl.enqueue(new Uint8Array(1024).fill(0x20))
      },
    })
    const r = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'application/json' }, body, duplex: 'half' } as RequestInit)
    expect(r.status).toBe(413)
    expect(pulled).toBeLessThanOrEqual(8)
  })

  it('does not read the body of a request it rejects for type or authorization', async () => {
    let pulled = 0
    const endless = () =>
      new ReadableStream<Uint8Array>({
        pull(ctrl) {
          pulled++
          ctrl.enqueue(new Uint8Array(1024).fill(0x20))
        },
      })
    const typed = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: endless(), duplex: 'half' } as RequestInit)
    expect(typed.status).toBe(415)
    const admin = await t.app.request('/api/notebook', { method: 'POST', headers: { 'content-type': 'application/json' }, body: endless(), duplex: 'half' } as RequestInit)
    expect(admin.status).toBe(403)
    // Each stream pre-fills its own small queue when constructed; nothing beyond that is consumed.
    expect(pulled).toBeLessThanOrEqual(4)
  })

  it('refuses any POST that declares a non-JSON body, on every route', async () => {
    for (const path of [`/api/runs/${RUN_2}/reproduce`, '/api/refresh', '/api/disputes', '/api/notebook']) {
      const r = await t.app.request(path, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded', 'content-length': '3' }, body: 'a=b' })
      expect(r.status, path).toBe(415)
      expect(((await r.json()) as Json).error.code).toBe('UNSUPPORTED_MEDIA_TYPE')
    }
  })

  it('accepts a body under the cap', async () => {
    expect((await t.json('POST', '/api/disputes', dispute())).status).toBe(201)
  })
})

describe('rate limiting', () => {
  it('limits dispute submissions per client address and answers 429 with Retry-After', async () => {
    const t = makeApp({ disputeRateLimitPerHour: 3 })
    const statuses: number[] = []
    for (let i = 0; i < 5; i++) statuses.push((await t.json('POST', '/api/disputes', dispute())).status)
    expect(statuses).toEqual([201, 201, 201, 429, 429])
    const r = await t.json('POST', '/api/disputes', dispute())
    expect(r.headers.get('retry-after')).toMatch(/^\d+$/)
    expect(((await r.json()) as Json).error.code).toBe('RATE_LIMITED')
    // Reads are on the general limit, not the dispute one.
    expect((await t.app.request('/api/disputes')).status).toBe(200)
    await t.close()
  })

  it('limits all API requests per minute', async () => {
    const t = makeApp({ rateLimitPerMinute: 5 })
    const statuses: number[] = []
    for (let i = 0; i < 7; i++) statuses.push((await t.app.request('/api/health')).status)
    expect(statuses.slice(0, 5).every((s) => s === 200)).toBe(true)
    expect(statuses.slice(5)).toEqual([429, 429])
    await t.close()
  })

  it('keys on the socket address and ignores X-Forwarded-For unless trust is configured', async () => {
    const app = new Hono<Env>()
    app.get('/a', (c) => c.text(clientAddress(c, false)))
    app.get('/b', (c) => c.text(clientAddress(c, true)))
    const env = { incoming: { socket: { remoteAddress: '::ffff:10.0.0.7' } } }
    const h = { 'x-forwarded-for': '6.6.6.6, 203.0.113.9' }
    expect(await (await app.request('/a', { headers: h }, env)).text()).toBe('10.0.0.7')
    expect(await (await app.request('/b', { headers: h }, env)).text()).toBe('203.0.113.9')

    // A spoofed X-Forwarded-For does not buy a fresh bucket when proxies are not trusted.
    const limited = new Hono<Env>()
    limited.onError((e, c) => c.text(e.message, (e as HttpError).status as 429))
    limited.use('*', rateLimit('t', 2, 60_000, false))
    limited.get('/', (c) => c.text('ok'))
    const statuses: number[] = []
    for (let i = 0; i < 4; i++) statuses.push((await limited.request('/', { headers: { 'x-forwarded-for': `198.51.100.${i}` } }, env)).status)
    expect(statuses).toEqual([200, 200, 429, 429])
  })
})

describe('CORS and origin', () => {
  it('is off by default: no CORS headers, cross-origin POST rejected', async () => {
    const t = makeApp()
    const r = await t.app.request('/api/runs', { headers: { origin: 'https://evil.example' } })
    expect(r.status).toBe(200)
    expect(r.headers.get('access-control-allow-origin')).toBeNull()
    const post = await t.json('POST', '/api/disputes', dispute(), { origin: 'https://evil.example' })
    expect(post.status).toBe(403)
    const pre = await t.app.request('/api/disputes', { method: 'OPTIONS', headers: { origin: 'https://evil.example', 'access-control-request-method': 'POST' } })
    expect(pre.headers.get('access-control-allow-origin')).toBeNull()
    await t.close()
  })

  it('allows configured origins only', async () => {
    const t = makeApp({ corsOrigins: ['https://research.example'] })
    const r = await t.app.request('/api/runs', { headers: { origin: 'https://research.example' } })
    expect(r.headers.get('access-control-allow-origin')).toBe('https://research.example')
    await t.close()
  })

  it('rejects unknown Host headers when bound to loopback (DNS rebinding)', async () => {
    const t = makeApp({ allowedHosts: ['127.0.0.1', 'localhost'] })
    expect((await t.app.request('http://localhost/api/health')).status).toBe(200)
    expect((await t.app.request('http://rebind.example/api/health')).status).toBe(421)
    await t.close()
  })
})

describe('static serving in production', () => {
  const root = mkdtempSync(join(tmpdir(), 'touchstone-dist-'))
  const dist = join(root, 'dist')
  mkdirSync(join(dist, 'assets'), { recursive: true })
  writeFileSync(join(dist, 'index.html'), '<!doctype html><title>TOUCHSTONE</title>')
  writeFileSync(join(dist, 'assets', 'app.js'), 'console.log(1)')
  writeFileSync(join(root, 'secret.txt'), 'outside dist')
  let symlinked = false
  try {
    symlinkSync(join(root, 'secret.txt'), join(dist, 'link.txt'))
    symlinked = true
  } catch {
    /* symlinks need privileges on Windows; that case is skipped */
  }
  const t = makeApp({ production: true, webDist: dist })
  afterAll(async () => {
    await t.close()
    rmSync(root, { recursive: true, force: true })
  })

  it('serves files, the SPA fallback, and 404 for missing assets', async () => {
    const js = await t.app.request('/assets/app.js')
    expect(js.status).toBe(200)
    expect(js.headers.get('content-type')).toContain('javascript')
    expect(js.headers.get('cache-control')).toContain('immutable')
    const route = await t.app.request('/vendors/northwind-systems')
    expect(route.status).toBe(200)
    expect(await route.text()).toContain('TOUCHSTONE')
    expect(route.headers.get('content-security-policy')).toBe(CONTENT_SECURITY_POLICY)
    expect((await t.app.request('/assets/missing.js')).status).toBe(404)
    // The API still answers on the same origin.
    expect((await t.app.request('/api/health')).status).toBe(200)
  })

  it('never serves a file outside dist (path traversal)', async () => {
    const attempts = [
      '/../secret.txt',
      '/%2e%2e/secret.txt',
      '/%2e%2e%2fsecret.txt',
      '/assets/..%2f..%2fsecret.txt',
      '/..%5csecret.txt',
      '/%252e%252e/secret.txt',
      '/assets/%00.js',
      `/${encodeURIComponent(join(root, 'secret.txt'))}`,
    ]
    for (const p of attempts) {
      const r = await t.app.request(p)
      const text = await r.text()
      expect(text, p).not.toContain('outside dist')
    }
    expect(resolveInside(dist, '/../secret.txt')).toBeNull()
    expect(resolveInside(dist, '/..\\secret.txt')).toBeNull()
    expect(resolveInside(dist, '/C:/Windows/win.ini')).toBeNull()
    expect(resolveInside(dist, '/%E0%A4%A')).toBeNull()
    expect(resolveInside(dist, '/assets/app.js')).not.toBeNull()
    if (symlinked) expect(resolveInside(dist, '/link.txt')).toBeNull()
  })
})

describe('configuration', () => {
  it('validates at start with clear errors naming the variable', () => {
    const bad = (env: Record<string, string>, pattern: RegExp) => {
      let err: unknown
      try {
        loadConfig(env, [])
      } catch (e) {
        err = e
      }
      expect(err).toBeInstanceOf(ConfigError)
      expect((err as Error).message).toMatch(pattern)
    }
    bad({ PORT: 'eighty' }, /PORT: must be an integer/)
    bad({ TOUCHSTONE_ADMIN_TOKEN: 'short' }, /TOUCHSTONE_ADMIN_TOKEN: must be at least 24/)
    bad({ TOUCHSTONE_MODE: 'turbo' }, /TOUCHSTONE_MODE/)
    bad({ TOUCHSTONE_TRUST_PROXY: 'maybe' }, /TOUCHSTONE_TRUST_PROXY: must be true or false/)
    bad({ TOUCHSTONE_CORS_ORIGINS: 'https://ok.example/path' }, /TOUCHSTONE_CORS_ORIGINS/)
    bad({ TOUCHSTONE_MODE: 'live' }, /TOUCHSTONE_LIVE_REGISTRY: required/)
    bad({ TOUCHSTONE_MAX_BODY_BYTES: '10' }, /TOUCHSTONE_MAX_BODY_BYTES/)
  })

  it('has safe defaults', () => {
    const c = loadConfig({}, [])
    expect(c.host).toBe('127.0.0.1')
    expect(c.mode).toBe('demo')
    expect(c.adminToken).toBeNull()
    expect(c.trustProxy).toBe(false)
    expect(c.corsOrigins).toEqual([])
    expect(c.production).toBe(false)
    expect(c.dataDir.replace(/\\/g, '/')).toMatch(/apps\/web\/public\/data$/)
    expect(c.allowedHosts).toEqual(['127.0.0.1', 'localhost', '[::1]'])
    expect(loadConfig({}, ['node', 'index.ts', '--production']).production).toBe(true)
    expect(loadConfig({ TOUCHSTONE_TRUST_PROXY: 'true' }, []).trustProxy).toBe(true)
  })
})
