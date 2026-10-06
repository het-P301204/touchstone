/**
 * Security review: outbound collection (packages/collect).
 *
 * Every network interaction goes through the injected resolver/transport or an
 * injected fetcher. Nothing here touches the network.
 *
 * Tests named "FINDING ..." demonstrate a confirmed issue and fail while it exists.
 * Everything else pins a defence that was attacked and held.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import type { Vendor } from '../../packages/core/src/model/index.ts'
import { classifyAddress } from '../../packages/collect/src/ip.ts'
import { hostAllowed, safeFetch, validateUrl } from '../../packages/collect/src/safe-fetch.ts'
import type { ResolvedAddress, SafeFetchOptions, SafeFetchResult, TransportRequest, TransportResponse } from '../../packages/collect/src/safe-fetch.ts'
import { robotsAllows } from '../../packages/collect/src/robots.ts'
import { SnapshotStore } from '../../packages/collect/src/store.ts'
import { collectCsaf } from '../../packages/collect/src/collectors/csaf.ts'
import { collectCveRecord } from '../../packages/collect/src/collectors/cve-records.ts'
import { choosePolicyUrl, policyAllowHosts } from '../../packages/collect/src/collectors/vdp-policy.ts'
import type { CollectContext, Fetcher } from '../../packages/collect/src/collectors/common.ts'
import { collectLive } from '../../packages/collect/src/live.ts'

const PUBLIC4 = '93.184.215.14'
const dirs: string[] = []
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'ts-sec-collect-'))
  dirs.push(d)
  return d
}
afterAll(() => {
  for (const d of dirs) rmSync(d, { recursive: true, force: true })
})

type Reply = { status?: number; headers?: Record<string, string>; chunks?: Uint8Array[] }

function harness(replies: Record<string, Reply>, dns: Record<string, ResolvedAddress[]> = {}) {
  const calls: TransportRequest[] = []
  const resolver = async (host: string) => dns[host] ?? [{ address: PUBLIC4, family: 4 as const }]
  const transport = async (req: TransportRequest): Promise<TransportResponse> => {
    calls.push(req)
    const r = replies[req.url.toString()]
    if (!r) throw new Error(`unexpected request to ${req.url}`)
    const chunks = r.chunks ?? [new TextEncoder().encode('{}')]
    return {
      status: r.status ?? 200,
      headers: { 'content-type': 'application/json', ...r.headers },
      body: (async function* () {
        for (const c of chunks) yield c
      })(),
      destroy: () => {},
    }
  }
  const opts = (over: Partial<SafeFetchOptions> = {}): SafeFetchOptions => ({
    allowHosts: ['vendor.example', '*.vendor.example'],
    allowedContentTypes: ['application/json'],
    resolver,
    transport,
    ...over,
  })
  return { calls, opts }
}

const fail = (r: SafeFetchResult) => (r.ok ? 'OK' : r.code)

/* ------------------------------------------------------------------ pinned defences */

describe('safeFetch: URL forms that name an internal host are refused before any connection', () => {
  it.each([
    ['http://vendor.example/x', 'SCHEME'],
    ['file:///etc/passwd', 'SCHEME'],
    ['https://vendor.example:8443/x', 'PORT'],
    ['https://vendor.example@evil.example/x', 'CREDENTIALS'],
    ['https://user:pw@vendor.example/x', 'CREDENTIALS'],
    ['https://vendor.example:443@evil.example/x', 'CREDENTIALS'],
    ['https://2130706433/', 'IP_LITERAL'], // decimal 127.0.0.1
    ['https://0x7f.1/', 'IP_LITERAL'],
    ['https://0177.0.0.1/', 'IP_LITERAL'],
    ['https://127.1/', 'IP_LITERAL'],
    ['https://[::ffff:7f00:1]/', 'IP_LITERAL'],
    ['https://[::127.0.0.1]/', 'IP_LITERAL'],
    ['https://[64:ff9b::7f00:1]/', 'IP_LITERAL'],
    ['https://evil.vendor.example.attacker.example/', 'HOST_NOT_ALLOWED'],
    ['https://xvendor.example/', 'HOST_NOT_ALLOWED'],
    ['https://vеndor.example/', 'HOST_NOT_ALLOWED'], // Cyrillic e: punycoded, not the allowlisted host
  ])('%s -> %s', async (url, code) => {
    const h = harness({})
    const r = await safeFetch(url, h.opts())
    expect(fail(r)).toBe(code)
    expect(h.calls).toHaveLength(0)
  })

  it('normalises case and a trailing dot to the same allowlisted host (no bypass, no false refusal)', () => {
    expect(validateUrl('https://VENDOR.Example./a', ['vendor.example']).hostname).toBe('vendor.example.')
    expect(hostAllowed('VENDOR.EXAMPLE.', ['vendor.example'])).toBe(true)
    expect(hostAllowed('vendor.example', ['*.vendor.example'])).toBe(false) // wildcard is subdomains only
  })
})

describe('safeFetch: DNS answers are validated, every address, every hop', () => {
  it.each([
    ['::ffff:169.254.169.254'],
    ['0:0:0:0:0:ffff:7f00:1'],
    ['::127.0.0.1'],
    ['64:ff9b::a9fe:a9fe'],
    ['2002:a9fe:a9fe::1'], // 6to4 embedding 169.254.169.254
    ['2001:0:a9fe:a9fe::1'], // Teredo
    ['fd00:ec2::254'], // AWS IMDS over IPv6 (ULA)
    ['100.100.100.200'], // Alibaba metadata (CGNAT)
    ['127.000.000.001'], // non-canonical: unparseable, refused
  ])('refuses a resolver answer of %s', async (addr) => {
    const h = harness({}, { 'vendor.example': [{ address: addr, family: addr.includes(':') ? 6 : 4 }] })
    const r = await safeFetch('https://vendor.example/x', h.opts())
    expect(fail(r)).toBe('BLOCKED_ADDRESS')
    expect(h.calls).toHaveLength(0)
  })

  it('refuses when any one of several answers is internal (no "first public answer wins")', async () => {
    const h = harness({}, { 'vendor.example': [{ address: PUBLIC4, family: 4 }, { address: '10.0.0.5', family: 4 }] })
    expect(fail(await safeFetch('https://vendor.example/x', h.opts()))).toBe('BLOCKED_ADDRESS')
  })

  it('pins the transport to the validated address (DNS rebinding)', async () => {
    const h = harness({ 'https://vendor.example/x': {} })
    const r = await safeFetch('https://vendor.example/x', h.opts())
    expect(r.ok).toBe(true)
    expect(h.calls[0]!.address).toBe(PUBLIC4)
  })

  it('re-validates a redirect: to http, to a non-allowlisted host, to an IP literal, or to a host resolving inside', async () => {
    for (const [location, code] of [
      ['http://vendor.example/y', 'SCHEME'],
      ['https://evil.example/y', 'HOST_NOT_ALLOWED'],
      ['https://169.254.169.254/latest/meta-data/', 'IP_LITERAL'],
      ['//evil.example/y', 'HOST_NOT_ALLOWED'],
      ['https://internal.vendor.example/y', 'BLOCKED_ADDRESS'],
    ] as const) {
      const h = harness({ 'https://vendor.example/x': { status: 302, headers: { location } } }, { 'internal.vendor.example': [{ address: '127.0.0.1', family: 4 }] })
      const r = await safeFetch('https://vendor.example/x', h.opts())
      expect([location, fail(r)]).toEqual([location, code])
      expect(h.calls).toHaveLength(1)
    }
  })
})

describe('safeFetch: response handling', () => {
  it('stops reading a chunked body at the byte cap (no Content-Length)', async () => {
    const chunk = new Uint8Array(64 * 1024)
    let yielded = 0
    const h = harness({})
    const r = await safeFetch('https://vendor.example/x', {
      ...h.opts({ maxBytes: 100_000 }),
      transport: async () => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: (async function* () {
          for (let i = 0; i < 1000; i++) {
            yielded++
            yield chunk
          }
        })(),
        destroy: () => {},
      }),
    })
    expect(fail(r)).toBe('TOO_LARGE')
    expect(yielded).toBeLessThanOrEqual(2)
  })

  it('refuses compressed bodies (no decompression bomb surface) and content-type confusion', async () => {
    const gz = harness({ 'https://vendor.example/x': { headers: { 'content-encoding': 'gzip' } } })
    expect(fail(await safeFetch('https://vendor.example/x', gz.opts()))).toBe('CONTENT_ENCODING')
    for (const type of ['text/html', 'application/json, text/html', 'application/jsonx', '']) {
      const h = harness({ 'https://vendor.example/x': { headers: { 'content-type': type } } })
      expect([type, fail(await safeFetch('https://vendor.example/x', h.opts()))]).toEqual([type, 'CONTENT_TYPE'])
    }
  })

  it('a slowloris body that trickles bytes hits the total deadline', async () => {
    const h = harness({})
    const r = await safeFetch('https://vendor.example/x', {
      ...h.opts({ timeoutMs: 150 }),
      transport: async () => ({
        status: 200,
        headers: { 'content-type': 'application/json' },
        body: (async function* () {
          for (;;) {
            await new Promise((res) => setTimeout(res, 20))
            yield new Uint8Array(1)
          }
        })(),
        destroy: () => {},
      }),
    })
    expect(fail(r)).toBe('TIMEOUT')
  })

  it('sends no cookies, credentials or referrer', async () => {
    const h = harness({ 'https://vendor.example/x': {} })
    await safeFetch('https://vendor.example/x', h.opts())
    const names = Object.keys(h.calls[0]!.headers).map((k) => k.toLowerCase())
    expect(names).not.toContain('cookie')
    expect(names).not.toContain('authorization')
    expect(names).not.toContain('referer')
  })
})

describe('policy URL selection: the allowlist comes from the registry, never from fetched data', () => {
  const vendor: Vendor = {
    id: 'acme',
    canonicalName: 'Acme',
    aliases: [],
    signatoryStatus: 'UNKNOWN',
    category: 'OTHER',
    domains: ['acme.example'],
    claims: [],
    synthetic: false,
  }
  const stxt = (policyUrls: string[]) => ({ present: true, url: '', contacts: [], policyUrls, canonical: [], warnings: [], signed: false })

  it('ignores Policy: URLs on internal hosts or other vendors’ domains', () => {
    for (const u of ['https://169.254.169.254/', 'https://localhost/', 'https://other-vendor.example/vdp', 'https://acme.example.evil.example/', 'javascript:alert(1)', 'http://acme.example/vdp']) {
      expect([u, choosePolicyUrl(vendor, stxt([u]))]).toEqual([u, undefined])
    }
    expect(choosePolicyUrl(vendor, stxt(['https://psirt.acme.example/vdp']))).toBe('https://psirt.acme.example/vdp')
    expect(policyAllowHosts(vendor)).not.toContain('*')
  })

  it('CSAF provider metadata pointing at another host is never fetched', async () => {
    const fetched: string[] = []
    const fetcher: Fetcher = async (url, opts) => {
      fetched.push(url)
      const meta = { distributions: [{ rolie: { feeds: [{ url: 'https://evil.example/feed.json' }] }, directory_url: 'https://169.254.169.254/' }] }
      if (url === 'https://acme.example/.well-known/csaf/provider-metadata.json') {
        const body = new TextEncoder().encode(JSON.stringify(meta))
        return { ok: true, url, finalUrl: url, status: 200, contentType: 'application/json', body, sha256: '0'.repeat(64), bytes: body.length, redirects: [], address: PUBLIC4, fetchedAt: '2026-10-06T00:00:00Z' }
      }
      // Delegate to the real validator so the allowlist decision is the production one.
      return safeFetch(url, { ...opts, resolver: async () => [{ address: PUBLIC4, family: 4 }], transport: async () => { throw new Error('must not connect') } })
    }
    const ctx: CollectContext = { store: new SnapshotStore(tmp()), fetchDefaults: {}, fetcher, parserVersion: 'test' }
    const r = await collectCsaf(ctx, { ...vendor, csafProviderUrl: 'https://acme.example/.well-known/csaf/provider-metadata.json' })
    expect(r.errors.some((e) => e.includes('HOST_NOT_ALLOWED'))).toBe(true)
    expect(r.errors.some((e) => e.includes('IP_LITERAL'))).toBe(true)
  })
})

describe('snapshot store: names come from hashes, never from fetched data', () => {
  it('rejects non-hash and non-id lookups (no traversal)', () => {
    const s = new SnapshotStore(tmp())
    expect(() => s.get('../../../etc/passwd')).toThrow(/not a sha256/)
    expect(() => s.putExtract('../x', 'y')).toThrow(/not a snapshot id/)
    expect(s.getExtract('..\\..\\x')).toBeNull()
  })
})

describe('address classification corner cases', () => {
  it.each(['::', '::1', '::ffff:0:0', '100::1', '2001:db8::1', '3fff::1', 'fec0::1', 'ff02::1', '0.0.0.0', '255.255.255.255', '192.88.99.1'])('refuses %s', (a) => {
    expect(classifyAddress(a).ok).toBe(false)
  })
  it.each(['8.8.8.8', '2606:4700::1111'])('accepts public %s', (a) => {
    expect(classifyAddress(a).ok).toBe(true)
  })
})

/* ------------------------------------------------------------------ findings */

const okJson = (url: string, value: unknown | string): SafeFetchResult => {
  const body = new TextEncoder().encode(typeof value === 'string' ? value : JSON.stringify(value))
  return { ok: true, url, finalUrl: url, status: 200, contentType: 'application/json', body, sha256: '0'.repeat(64), bytes: body.length, redirects: [], address: PUBLIC4, fetchedAt: '2026-10-06T00:00:00Z' }
}

describe('FINDING: one vendor-controlled document can abort collection', () => {
  const vendor: Vendor = {
    id: 'acme',
    canonicalName: 'Acme',
    aliases: [],
    signatoryStatus: 'UNKNOWN',
    category: 'OTHER',
    domains: ['acme.example'],
    csafProviderUrl: 'https://acme.example/.well-known/csaf/provider-metadata.json',
    claims: [],
    synthetic: false,
  }

  it('FINDING collectCsaf: a ROLIE entry with an unparseable URL rejects instead of being recorded as an error', async () => {
    const fetcher: Fetcher = async (url) => {
      if (url.endsWith('provider-metadata.json')) return okJson(url, { distributions: [{ rolie: { feeds: [{ url: 'https://acme.example/feed.json' }] } }] })
      if (url.endsWith('feed.json')) return okJson(url, { feed: { entry: [{ content: { src: 'https://[' } }] } })
      return { ok: false, url, code: 'HTTP_STATUS', status: 404, error: 'HTTP 404', redirects: [], fetchedAt: '2026-10-06T00:00:00Z' }
    }
    const ctx: CollectContext = { store: new SnapshotStore(tmp()), fetchDefaults: {}, fetcher, parserVersion: 'test' }
    // Expected: resolves, with the bad entry listed in errors.
    await expect(collectCsaf(ctx, vendor)).resolves.toMatchObject({ advisories: [] })
  })

  it('FINDING collectCveRecord: a deeply nested CVE record (x_ fields are schema-legal) throws RangeError instead of returning an error', async () => {
    let deep = '1'
    for (let i = 0; i < 20_000; i++) deep = `[${deep}]`
    const raw = `{"dataType":"CVE_RECORD","dataVersion":"5.1","cveMetadata":{"cveId":"CVE-2024-0001","state":"PUBLISHED","assignerOrgId":"x"},"containers":{"cna":{"x_generator":${deep},"affected":[],"problemTypes":[],"descriptions":[]}}}`
    const fetcher: Fetcher = async (url) => okJson(url, raw)
    const ctx: CollectContext = { store: new SnapshotStore(tmp()), fetchDefaults: {}, fetcher, parserVersion: 'test' }
    let outcome: unknown
    try {
      outcome = await collectCveRecord(ctx, 'CVE-2024-0001')
    } catch (e) {
      outcome = `threw ${(e as Error).name}`
    }
    expect(outcome).not.toBe('threw RangeError')
  })

  it('FINDING collectLive: the failure of one vendor’s feed aborts collection for every vendor in the run', async () => {
    const out = tmp()
    const registryPath = join(out, 'vendors.json')
    const other: Vendor = { ...vendor, id: 'other', domains: ['other.example'], csafProviderUrl: undefined } as Vendor
    delete (other as { csafProviderUrl?: string }).csafProviderUrl
    writeFileSync(registryPath, JSON.stringify([vendor, other]))
    const fetcher: Fetcher = async (url) => {
      if (url.endsWith('provider-metadata.json')) return okJson(url, { distributions: [{ rolie: { feeds: [{ url: 'https://acme.example/feed.json' }] } }] })
      if (url.endsWith('feed.json')) return okJson(url, { feed: { entry: [{ content: { src: 'https://[' } }] } })
      return { ok: false, url, code: 'HTTP_STATUS', status: 404, error: 'HTTP 404', redirects: [], fetchedAt: '2026-10-06T00:00:00Z' }
    }
    let result: Awaited<ReturnType<typeof collectLive>> | string
    try {
      result = await collectLive({ vendorIds: ['acme', 'other'], registryPath, outDir: out, asOf: '2026-10-06T12:00:00Z', fetcher })
    } catch (e) {
      result = `rejected: ${(e as Error).message}`
    }
    expect(typeof result).not.toBe('string')
    expect((result as { vdp: { vendorId: string }[] }).vdp.map((v) => v.vendorId).sort()).toEqual(['acme', 'other'])
  })
})

describe('FINDING: robots.txt matching cost is robots bytes x path length', () => {
  it('FINDING a 512 KB robots.txt and a 2 KB Policy path (both vendor-controlled, both within caps) evaluate in well under a second', () => {
    // 5000 rules (the parser's line cap) of "/*aaaa...ab": each rule restarts the star match at every path offset.
    const rule = `Disallow: /*${'a'.repeat(90)}b`
    const robots = `User-agent: *\n${Array.from({ length: 5000 }, () => rule).join('\n')}`
    expect(robots.length).toBeLessThan(512 * 1024)
    const path = `/${'a'.repeat(2040)}` // security.txt lines are read up to 2048 chars
    const t0 = performance.now()
    robotsAllows(robots, path, 'TOUCHSTONE')
    const ms = performance.now() - t0
    expect(ms).toBeLessThan(1000)
  })
})
