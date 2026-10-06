/**
 * Security review: the REST API (apps/api).
 * Tests named "FINDING ..." demonstrate a confirmed issue and fail while it exists.
 */
import { mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { evidenceUrl, safeFileName } from '../../apps/api/src/app.ts'
import { loadConfig } from '../../apps/api/src/config.ts'
import { resolveInside } from '../../apps/api/src/static.ts'
import { NORTHWIND, RUN_2 } from '../../apps/api/test/fixtures/bundle.ts'
import { ADMIN, makeApp } from '../../apps/api/test/helpers.ts'

const dispute = (over: Record<string, unknown> = {}) => ({
  vendorId: NORTHWIND,
  runId: RUN_2,
  target: { kind: 'METRIC', id: 'cve.complete_records' },
  reason: 'INCORRECT_CVE_MAPPING',
  submitterRole: 'RESEARCHER',
  statement: 'Record belongs to a different product line.',
  evidenceUrls: [],
  ...over,
})

const post = (t: ReturnType<typeof makeApp>, path: string, body: unknown, remoteAddress: string, headers: Record<string, string> = {}) =>
  t.app.request(path, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) }, { incoming: { socket: { remoteAddress } } })

/* ------------------------------------------------------------------ pinned defences */

describe('admin authentication', () => {
  it('is disabled (403) without a configured token, before the body is read', async () => {
    const t = makeApp({ adminToken: null })
    const r = await t.json('POST', '/api/refresh', {}, { authorization: 'Bearer anything-at-all-anything-at-all' })
    expect(r.status).toBe(403)
    await t.close()
  })
  it('rejects missing, wrong, prefix, suffix and whitespace-padded tokens', async () => {
    const t = makeApp({ adminToken: ADMIN })
    for (const auth of ['', `Bearer ${ADMIN.slice(0, -1)}`, `Bearer ${ADMIN}x`, `Basic ${ADMIN}`, `Bearer ${ADMIN} x`, `Bearer\t\t${ADMIN}x`, ADMIN]) {
      const r = await t.json('POST', '/api/notebook', { title: 'x', observation: 'y' }, auth ? { authorization: auth } : {})
      expect([auth.slice(0, 12), r.status]).toEqual([auth.slice(0, 12), 401])
    }
    await t.close()
  })
  it('refuses short tokens at configuration time', () => {
    expect(() => loadConfig({ TOUCHSTONE_ADMIN_TOKEN: 'short-token' }, [])).toThrow(/24 characters/)
  })
})

describe('request bodies', () => {
  it('a chunked body with no Content-Length is cut off at the cap (413), not buffered', async () => {
    const t = makeApp({ maxBodyBytes: 4096 })
    let pulled = 0
    const body = new ReadableStream<Uint8Array>({
      pull(ctrl) {
        pulled++
        if (pulled > 1000) return ctrl.close()
        ctrl.enqueue(new TextEncoder().encode(' '.repeat(1024)))
      },
    })
    const r = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'application/json', 'transfer-encoding': 'chunked' }, body, duplex: 'half' } as RequestInit)
    expect(r.status).toBe(413)
    expect(pulled).toBeLessThan(20)
    await t.close()
  })
  it('a declared oversize Content-Length is refused before any handler', async () => {
    const t = makeApp({ maxBodyBytes: 4096 })
    const r = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'application/json', 'content-length': '999999' }, body: '{}' })
    expect(r.status).toBe(413)
    await t.close()
  })
})

describe('dispute validation', () => {
  it.each([
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'http://example.org/',
    'https://user:pw@example.org/',
    `https://example.org/${'a'.repeat(600)}`,
    'https://exa mple.org/',
    '//example.org/x',
    'JaVaScRiPt:alert(1)',
  ])('refuses evidence URL %s', (u) => {
    expect(evidenceUrl.safeParse(u.slice(0, 80) === u ? u : u).success).toBe(false)
  })
  it('stores statement text without bidi or control characters', async () => {
    const t = makeApp()
    const r = await post(t, '/api/disputes', dispute({ statement: `ok ${String.fromCodePoint(0x202e)}gnp.exe\u0007 end` }), '198.51.100.7')
    expect(r.status).toBe(201)
    const d = (await r.json()) as { statement: string }
    expect(d.statement).toBe('ok gnp.exe end')
    await t.close()
  })
  it('SQL metacharacters in filters are inert', async () => {
    const t = makeApp()
    const r = await t.app.request(`/api/notebook?vendor=${encodeURIComponent("x' OR '1'='1")}&tag=${encodeURIComponent('a"; DROP TABLE disputes;--')}`)
    expect(r.status).toBe(200)
    expect(await r.json()).toEqual([])
    expect((await t.app.request('/api/disputes')).status).toBe(200)
    await t.close()
  })
})

describe('reports', () => {
  it('Content-Disposition file names cannot carry quotes, CR/LF or path separators', () => {
    for (const s of ['a"; filename=evil.exe', 'a\r\nSet-Cookie: x=1', '../../etc/passwd', '..\\..\\x']) {
      expect(safeFileName(s)).toMatch(/^[A-Za-z0-9][A-Za-z0-9._-]*$/)
    }
  })
})

describe('static file serving', () => {
  const root = mkdtempSync(join(tmpdir(), 'ts-sec-static-'))
  mkdirSync(join(root, 'dist', 'assets'), { recursive: true })
  writeFileSync(join(root, 'dist', 'index.html'), 'app')
  writeFileSync(join(root, 'secret.txt'), 'secret')
  const dist = join(root, 'dist')
  it.each([
    '/../secret.txt',
    '/..%2fsecret.txt',
    '/%2e%2e%2fsecret.txt',
    '/..%5csecret.txt',
    '/assets/..%2f..%2fsecret.txt',
    '/index.html%00.png',
    `/${encodeURIComponent(join(root, 'secret.txt'))}`,
    '/C:%5cWindows%5cwin.ini',
    '/%5c%5cserver%5cshare%5cx',
    '/%E0%A4%A',
  ])('%s does not resolve outside dist', (p) => {
    const r = resolveInside(dist, p)
    expect(r === null || r.startsWith(dist)).toBe(true)
  })
  it('a symlink inside dist pointing outside is refused', () => {
    try {
      symlinkSync(join(root, 'secret.txt'), join(dist, 'assets', 'link.txt'))
    } catch {
      return // symlinks need privileges on Windows; nothing to test
    }
    expect(resolveInside(dist, '/assets/link.txt')).toBeNull()
    rmSync(join(dist, 'assets', 'link.txt'))
  })
})

describe('host and origin', () => {
  it('a rebinding Host is refused when an allowlist is configured', async () => {
    const t = makeApp({ allowedHosts: ['127.0.0.1', 'localhost'] })
    expect((await t.app.request('http://attacker.example:8787/api/health')).status).toBe(421)
    expect((await t.app.request('http://127.0.0.1:8787/api/health')).status).toBe(200)
    await t.close()
  })
  it('a cross-origin or opaque-origin POST is refused', async () => {
    const t = makeApp()
    for (const origin of ['https://evil.example', 'null']) {
      expect((await post(t, '/api/disputes', dispute(), '198.51.100.8', { origin })).status).toBe(403)
    }
    await t.close()
  })
})

/* ------------------------------------------------------------------ findings */

describe('FINDING: per-address rate limits are keyed on the full IPv6 address', () => {
  it('FINDING a client rotating addresses inside one /64 is not limited', async () => {
    const t = makeApp({ disputeRateLimitPerHour: 2 })
    const statuses: number[] = []
    for (let i = 1; i <= 5; i++) statuses.push((await post(t, '/api/disputes', dispute(), `2001:db8:1:2::${i.toString(16)}`)).status)
    // One host owns the whole /64; the third and later disputes should be limited.
    expect(statuses).toEqual([201, 201, 429, 429, 429])
    await t.close()
  })
})

describe('FINDING: unauthenticated refresh status leaks server filesystem paths', () => {
  it('FINDING GET /api/refresh/:id (no token) contains no absolute path', async () => {
    const missing = join(mkdtempSync(join(tmpdir(), 'ts-sec-nofix-')), 'not-there')
    const t = makeApp({ adminToken: ADMIN, demoFixturesDir: missing })
    const started = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    expect(started.status).toBe(202)
    const { jobId } = (await started.json()) as { jobId: string }
    await t.refresh.idle()
    const anon = await (await t.app.request(`/api/refresh/${jobId}`)).text()
    expect(anon).not.toContain(missing.replace(/\\/g, '\\\\'))
    expect(anon).not.toMatch(/[A-Za-z]:\\\\|\/tmp\/|\/home\/|\/app\//)
    await t.close()
  })
})
