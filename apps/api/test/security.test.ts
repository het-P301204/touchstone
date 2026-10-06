import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import { Hono } from 'hono'
import { ConfigError, loadConfig } from '../src/config.ts'
import { CONTENT_SECURITY_POLICY, clientAddress, rateLimit, rateLimitKey, tokenMatches } from '../src/security.ts'
import type { Env, HttpError } from '../src/security.ts'
import { pathScrubber } from '../src/refresh.ts'
import { resolveInside } from '../src/static.ts'
import { NORTHWIND, RUN_2 } from './fixtures/bundle.ts'
import { ADMIN, makeApp, stubEngine } from './helpers.ts'

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

describe('client keys, map cap and global ceilings', () => {
  const from = (t: ReturnType<typeof makeApp>, path: string, body: unknown, remoteAddress: string) =>
    t.app.request(
      path,
      { method: 'POST', headers: { 'content-type': 'application/json' }, body: body === undefined ? undefined : JSON.stringify(body) },
      { incoming: { socket: { remoteAddress } } },
    )

  it('keys IPv4 by address, IPv4-mapped IPv6 as IPv4, other IPv6 by /64', () => {
    expect(rateLimitKey('203.0.113.9')).toBe('203.0.113.9')
    expect(rateLimitKey('::ffff:203.0.113.9')).toBe('203.0.113.9')
    expect(rateLimitKey('::ffff:cb00:7109')).toBe('203.0.113.9')
    expect(rateLimitKey('2001:db8:1:2::5')).toBe('2001:db8:1:2::/64')
    expect(rateLimitKey('2001:DB8:1:2:aaaa:bbbb:cccc:dddd')).toBe('2001:db8:1:2::/64')
    expect(rateLimitKey('2001:db8:1:3::5')).toBe('2001:db8:1:3::/64')
    expect(rateLimitKey('fe80::1%eth0')).toBe('fe80:0:0:0::/64')
    expect(rateLimitKey('[2001:db8::1]')).toBe('2001:db8:0:0::/64')
    expect(rateLimitKey('local')).toBe('local')
  })

  it('a client spread across one /64 shares one bucket; another /64 has its own', async () => {
    const t = makeApp({ disputeRateLimitPerHour: 2 })
    const s: number[] = []
    for (let i = 1; i <= 3; i++) s.push((await from(t, '/api/disputes', dispute(), `2001:db8:1:2::${i}`)).status)
    s.push((await from(t, '/api/disputes', dispute(), '2001:db8:1:3::1')).status)
    expect(s).toEqual([201, 201, 429, 201])
    await t.close()
  })

  it('caps the number of tracked clients, evicting the oldest', async () => {
    const app = new Hono<Env>()
    app.onError((e, c) => c.text(e.message, (e as HttpError).status as 429))
    app.use('*', rateLimit('t', 1, 60_000, false, Date.now, 3))
    app.get('/', (c) => c.text('ok'))
    const hit = async (ip: string) => (await app.request('/', {}, { incoming: { socket: { remoteAddress: ip } } })).status
    expect(await hit('192.0.2.1')).toBe(200)
    expect(await hit('192.0.2.1')).toBe(429)
    for (const ip of ['192.0.2.2', '192.0.2.3', '192.0.2.4']) expect(await hit(ip)).toBe(200)
    // 192.0.2.1 was the oldest key and has been evicted: memory stays bounded at 3 keys.
    expect(await hit('192.0.2.1')).toBe(200)
  })

  it('enforces a server-wide hourly dispute ceiling across addresses; rejected bodies do not use it', async () => {
    const t = makeApp({ disputeGlobalLimitPerHour: 3 })
    expect((await from(t, '/api/disputes', { ...dispute(), reason: 'NOPE' }, '198.51.100.1')).status).toBe(400)
    const s: number[] = []
    for (let i = 2; i <= 6; i++) s.push((await from(t, '/api/disputes', dispute(), `198.51.100.${i}`)).status)
    expect(s).toEqual([201, 201, 201, 429, 429])
    const r = await from(t, '/api/disputes', dispute(), '198.51.100.99')
    expect(((await r.json()) as Json).error.code).toBe('RATE_LIMITED_GLOBAL')
    expect(r.headers.get('retry-after')).toMatch(/^\d+$/)
    await t.close()
  })

  it('enforces a server-wide hourly reproduce ceiling across addresses', async () => {
    const t = makeApp({ reproduceGlobalLimitPerHour: 2 })
    const s: number[] = []
    for (let i = 1; i <= 3; i++) s.push((await from(t, `/api/runs/${RUN_2}/reproduce`, undefined, `203.0.113.${i}`)).status)
    expect(s).toEqual([200, 200, 429])
    await t.close()
  })

  it('runs reproductions one at a time and answers 429 when the queue is full', async () => {
    const engine = stubEngine()
    const inner = engine.reproduceRun
    let running = 0
    let maxRunning = 0
    engine.reproduceRun = (inputs, expected) => {
      running++
      maxRunning = Math.max(maxRunning, running)
      const until = performance.now() + 30
      while (performance.now() < until) {
        /* CPU-bound, like the real engine */
      }
      running--
      return inner(inputs, expected)
    }
    const t = makeApp({ reproduceQueueLimit: 1 }, { engine })
    const rs = await Promise.all(Array.from({ length: 5 }, (_, i) => from(t, `/api/runs/${RUN_2}/reproduce`, undefined, `203.0.113.${i + 10}`)))
    const statuses = rs.map((r) => r.status)
    expect(statuses.filter((x) => x === 200)).toHaveLength(2) // one in flight + one queued
    expect(statuses.filter((x) => x === 429)).toHaveLength(3)
    for (const r of rs.filter((x) => x.status === 429)) expect(((await r.json()) as Json).error.code).toBe('REPRODUCE_BUSY')
    expect(maxRunning).toBe(1)
    // The queue drains: a later request is served.
    expect((await from(t, `/api/runs/${RUN_2}/reproduce`, undefined, '203.0.113.50')).status).toBe(200)
    await t.close()
  })
})

describe('refresh status contains no server paths', () => {
  it('scrubs configured directories, other absolute paths, and keeps URLs', () => {
    const scrub = pathScrubber({
      demoFixturesDir: 'C:\\srv\\touchstone\\fixtures\\demo',
      liveOutDir: '/var/lib/touchstone/live',
      liveRegistry: null,
      dataDir: '/srv/data',
      dbPath: ':memory:',
      webDist: '/srv/dist',
    })
    expect(scrub("ENOENT: no such file or directory, open 'C:\\srv\\touchstone\\fixtures\\demo\\2026-10-06\\manifest.json'")).toBe(
      "ENOENT: no such file or directory, open 'TOUCHSTONE_DEMO_FIXTURES\\2026-10-06\\manifest.json'",
    )
    expect(scrub('wrote /var/lib/touchstone/live/runs/x')).toBe('wrote TOUCHSTONE_LIVE_OUT/runs/x')
    expect(scrub('open /home/alice/secret.json failed')).toBe('open <path> failed')
    expect(scrub('open D:/other/place.json failed')).toBe('open <path> failed')
    expect(scrub('see https://cve.example/api/cve/x and 1/2 and runs/TS-1/')).toBe('see https://cve.example/api/cve/x and 1/2 and runs/TS-1/')
  })

  it('an engine error naming a path reaches the client scrubbed and the log in full', async () => {
    const engine = stubEngine()
    engine.loadDemoInputs = () => {
      throw new Error("ENOENT: no such file or directory, open '/home/runner/work/touchstone/fixtures/demo/registry/vendors.json'")
    }
    const t = makeApp({ adminToken: ADMIN }, { engine })
    const { jobId } = (await (await t.json('POST', '/api/refresh', {}, t.adminHeaders)).json()) as Json
    await t.refresh.idle()
    const text = await (await t.app.request(`/api/refresh/${jobId}`)).text()
    expect(text).toContain('ENOENT')
    expect(text).not.toContain('/home/')
    expect(t.store.getJob(jobId)!.error).toContain('/home/runner')
    await t.close()
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

  it('refuses a non-loopback bind without a Host allowlist, unless * is explicit', () => {
    expect(() => loadConfig({ HOST: '0.0.0.0' }, [])).toThrow(/TOUCHSTONE_ALLOWED_HOSTS: required when HOST=0\.0\.0\.0/)
    expect(() => loadConfig({ HOST: '192.168.1.20', TOUCHSTONE_ALLOWED_HOSTS: '' }, [])).toThrow(ConfigError)
    const listed = loadConfig({ HOST: '0.0.0.0', TOUCHSTONE_ALLOWED_HOSTS: 'Touchstone.Example.org,localhost' }, [])
    expect(listed.allowedHosts).toEqual(['touchstone.example.org', 'localhost'])
    expect(listed.anyHostAllowed).toBe(false)
    const any = loadConfig({ HOST: '0.0.0.0', TOUCHSTONE_ALLOWED_HOSTS: '*' }, [])
    expect(any.allowedHosts).toEqual([])
    expect(any.anyHostAllowed).toBe(true)
    // The Docker image's defaults keep working.
    expect(loadConfig({ HOST: '0.0.0.0', TOUCHSTONE_ALLOWED_HOSTS: '127.0.0.1,localhost,[::1]' }, []).allowedHosts).toEqual(['127.0.0.1', 'localhost', '[::1]'])
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
    expect(c.disputeGlobalLimitPerHour).toBe(200)
    expect(c.reproduceGlobalLimitPerHour).toBe(120)
    expect(c.reproduceQueueLimit).toBe(4)
  })
})
