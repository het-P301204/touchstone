import { describe, expect, it } from 'vitest'
import { classifyAddress, parseIPv6 } from '../src/ip.ts'
import { HostRateLimiter, hostAllowed, pinnedLookup, safeFetch } from '../src/safe-fetch.ts'
import type { ResolvedAddress, SafeFetchOptions, TransportRequest, TransportResponse } from '../src/safe-fetch.ts'

const PUBLIC4 = '93.184.215.14'
const PUBLIC6 = '2606:2800:21f:cb07:6820:80da:af6b:8b2c'

type Reply = { status?: number; headers?: Record<string, string>; body?: string | Uint8Array[]; hang?: boolean }

function harness(replies: Record<string, Reply>, dns: Record<string, ResolvedAddress[] | ((n: number) => ResolvedAddress[])> = {}) {
  const calls: TransportRequest[] = []
  const lookups: string[] = []
  let destroyed = 0
  const resolver = async (host: string) => {
    lookups.push(host)
    const d = dns[host]
    if (typeof d === 'function') return d(lookups.filter((h) => h === host).length)
    return d ?? [{ address: PUBLIC4, family: 4 as const }]
  }
  const transport = async (req: TransportRequest): Promise<TransportResponse> => {
    calls.push(req)
    const r = replies[req.url.toString()]
    if (!r) throw new Error(`no reply for ${req.url}`)
    if (r.hang) return new Promise<TransportResponse>(() => {})
    const chunks = typeof r.body === 'string' ? [new TextEncoder().encode(r.body)] : (r.body ?? [])
    return {
      status: r.status ?? 200,
      headers: { 'content-type': 'application/json', ...r.headers },
      body: (async function* () {
        for (const c of chunks) yield c
      })(),
      destroy: () => {
        destroyed++
      },
    }
  }
  const opts = (over: Partial<SafeFetchOptions> = {}): SafeFetchOptions => ({
    allowHosts: ['vendor.example', '*.vendor.example', 'cdn.example'],
    allowedContentTypes: ['application/json', 'text/plain'],
    resolver,
    transport,
    ...over,
  })
  return { calls, lookups, opts, destroyed: () => destroyed }
}

describe('classifyAddress', () => {
  it.each([
    ['127.0.0.1', 'loopback'],
    ['10.1.2.3', 'private 10/8'],
    ['172.16.0.1', 'private 172.16/12'],
    ['192.168.1.1', 'private 192.168/16'],
    ['169.254.169.254', 'link-local / cloud metadata'],
    ['100.64.0.1', 'CGNAT 100.64/10'],
    ['100.127.255.254', 'CGNAT upper bound'],
    ['0.0.0.0', 'this network'],
    ['224.0.0.1', 'multicast'],
    ['255.255.255.255', 'broadcast'],
    ['198.18.0.1', 'benchmarking'],
    ['192.0.2.1', 'documentation'],
    ['::1', 'IPv6 loopback'],
    ['::', 'unspecified'],
    ['fc00::1', 'ULA fc00::/7'],
    ['fd12:3456::1', 'ULA fd00::/8'],
    ['fe80::1', 'link-local'],
    ['ff02::1', 'multicast'],
    ['::ffff:127.0.0.1', 'IPv4-mapped loopback'],
    ['::ffff:8.8.8.8', 'IPv4-mapped (any)'],
    ['::ffff:7f00:1', 'IPv4-mapped, hex form'],
    ['64:ff9b::7f00:1', 'NAT64 well-known prefix'],
    ['64:ff9b:1::a00:1', 'NAT64 local-use prefix'],
    ['2001:db8::1', 'documentation'],
    ['2002:7f00:1::1', '6to4'],
    ['2001::1', 'Teredo'],
    ['fe80::1%eth0', 'zone id'],
    ['0177.0.0.1', 'octal form'],
    ['127.1', 'shorthand form'],
    ['not-an-ip', 'garbage'],
  ])('rejects %s (%s)', (ip) => {
    expect(classifyAddress(ip).ok).toBe(false)
  })
  it('accepts global unicast addresses', () => {
    expect(classifyAddress(PUBLIC4)).toEqual({ ok: true, family: 4 })
    expect(classifyAddress('100.128.0.1').ok).toBe(true) // just outside CGNAT
    expect(classifyAddress(PUBLIC6)).toEqual({ ok: true, family: 6 })
  })
  it('parses IPv6 forms consistently', () => {
    expect(parseIPv6('::ffff:127.0.0.1')).toEqual(parseIPv6('::ffff:7f00:1'))
    expect(parseIPv6('[::1]')).toEqual([...new Array(15).fill(0), 1])
    expect(parseIPv6('1::2::3')).toBeNull()
  })
})

describe('safeFetch: URL rules', () => {
  it.each([
    ['http://vendor.example/a', 'SCHEME'],
    ['ftp://vendor.example/a', 'SCHEME'],
    ['https://vendor.example:8443/a', 'PORT'],
    ['https://user:pw@vendor.example/a', 'CREDENTIALS'],
    ['https://127.0.0.1/a', 'IP_LITERAL'],
    ['https://[::1]/a', 'IP_LITERAL'],
    ['https://2130706433/a', 'IP_LITERAL'],
    ['https://evil.example/a', 'HOST_NOT_ALLOWED'],
    ['https://vendor.example.evil.example/a', 'HOST_NOT_ALLOWED'],
    ['https://xvendor.example/a', 'HOST_NOT_ALLOWED'],
    ['not a url', 'BAD_URL'],
  ])('refuses %s with %s before any network activity', async (url, code) => {
    const h = harness({})
    const r = await safeFetch(url, h.opts())
    expect(r).toMatchObject({ ok: false, code })
    expect(h.lookups).toEqual([])
    expect(h.calls).toEqual([])
  })

  it('accepts explicit port 443 and allowlisted subdomains', async () => {
    const h = harness({ 'https://api.vendor.example/x': { body: '{}' } })
    expect((await safeFetch('https://api.vendor.example:443/x', h.opts())).ok).toBe(true)
    expect(hostAllowed('vendor.example', ['*.vendor.example'])).toBe(false)
    expect(hostAllowed('VENDOR.example.', ['vendor.example'])).toBe(true)
  })
})

describe('safeFetch: DNS checks', () => {
  it.each([['127.0.0.1'], ['10.0.0.8'], ['169.254.169.254'], ['100.64.12.1'], ['::1'], ['fc00::5'], ['::ffff:127.0.0.1'], ['64:ff9b::a9fe:a9fe']])(
    'refuses a host that resolves to %s',
    async (addr) => {
      const h = harness({ 'https://vendor.example/x': { body: '{}' } }, { 'vendor.example': [{ address: addr, family: addr.includes(':') ? 6 : 4 }] })
      const r = await safeFetch('https://vendor.example/x', h.opts())
      expect(r).toMatchObject({ ok: false, code: 'BLOCKED_ADDRESS' })
      expect(h.calls).toEqual([])
    },
  )

  it('refuses when ANY resolved address is private, even if the first is public', async () => {
    const h = harness({ 'https://vendor.example/x': { body: '{}' } }, { 'vendor.example': [{ address: PUBLIC4, family: 4 }, { address: '10.0.0.1', family: 4 }] })
    expect(await safeFetch('https://vendor.example/x', h.opts())).toMatchObject({ ok: false, code: 'BLOCKED_ADDRESS' })
  })

  it('pins the validated address: a DNS answer that changes after validation is never used (rebinding)', async () => {
    // First lookup public, any later lookup private. The connection must use the first answer and DNS must not be re-queried.
    const h = harness(
      { 'https://vendor.example/x': { body: '{"ok":true}' } },
      { 'vendor.example': (n) => (n === 1 ? [{ address: PUBLIC4, family: 4 }] : [{ address: '127.0.0.1', family: 4 }]) },
    )
    const r = await safeFetch('https://vendor.example/x', h.opts())
    expect(r.ok).toBe(true)
    expect(h.lookups).toEqual(['vendor.example'])
    expect(h.calls[0]!.address).toBe(PUBLIC4)
    if (r.ok) expect(r.address).toBe(PUBLIC4)
  })

  it('the socket lookup ignores the hostname and answers with the pinned address', () => {
    const lookup = pinnedLookup(PUBLIC4, 4)
    const single: unknown[] = []
    lookup('attacker-rebound.example', {}, (...args: unknown[]) => single.push(...args))
    expect(single).toEqual([null, PUBLIC4, 4])
    const all: unknown[] = []
    lookup('attacker-rebound.example', { all: true }, (...args: unknown[]) => all.push(...args))
    expect(all).toEqual([null, [{ address: PUBLIC4, family: 4 }]])
  })

  it('reports DNS failures', async () => {
    const h = harness({}, { 'vendor.example': [] })
    expect(await safeFetch('https://vendor.example/x', h.opts())).toMatchObject({ ok: false, code: 'DNS' })
  })
})

describe('safeFetch: redirects', () => {
  it('follows up to 3 redirects, re-validating each hop', async () => {
    const h = harness({
      'https://vendor.example/a': { status: 301, headers: { location: '/b' } },
      'https://vendor.example/b': { status: 302, headers: { location: 'https://cdn.example/c' } },
      'https://cdn.example/c': { status: 307, headers: { location: 'https://cdn.example/d' } },
      'https://cdn.example/d': { body: '{}' },
    })
    const r = await safeFetch('https://vendor.example/a', h.opts())
    expect(r).toMatchObject({ ok: true, finalUrl: 'https://cdn.example/d', redirects: ['https://vendor.example/b', 'https://cdn.example/c', 'https://cdn.example/d'] })
    expect(h.lookups).toEqual(['vendor.example', 'vendor.example', 'cdn.example', 'cdn.example'])
  })

  it('refuses a fourth redirect', async () => {
    const h = harness({
      'https://vendor.example/1': { status: 301, headers: { location: '/2' } },
      'https://vendor.example/2': { status: 301, headers: { location: '/3' } },
      'https://vendor.example/3': { status: 301, headers: { location: '/4' } },
      'https://vendor.example/4': { status: 301, headers: { location: '/5' } },
    })
    expect(await safeFetch('https://vendor.example/1', h.opts())).toMatchObject({ ok: false, code: 'TOO_MANY_REDIRECTS' })
  })

  it('refuses a redirect to a host that resolves privately', async () => {
    const h = harness(
      { 'https://vendor.example/a': { status: 302, headers: { location: 'https://internal.vendor.example/admin' } } },
      { 'internal.vendor.example': [{ address: '10.0.0.5', family: 4 }] },
    )
    const r = await safeFetch('https://vendor.example/a', h.opts())
    expect(r).toMatchObject({ ok: false, code: 'BLOCKED_ADDRESS' })
    expect(h.calls.map((c) => c.url.toString())).toEqual(['https://vendor.example/a'])
  })

  it('refuses redirects to http, to other ports, to IP literals and to unlisted hosts', async () => {
    for (const [location, code] of [
      ['http://vendor.example/x', 'SCHEME'],
      ['https://vendor.example:8080/x', 'PORT'],
      ['https://169.254.169.254/latest/meta-data/', 'IP_LITERAL'],
      ['https://evil.example/', 'HOST_NOT_ALLOWED'],
    ] as const) {
      const h = harness({ 'https://vendor.example/a': { status: 301, headers: { location } } })
      expect(await safeFetch('https://vendor.example/a', h.opts()), location).toMatchObject({ ok: false, code })
    }
  })

  it('a redirect without Location is an error', async () => {
    const h = harness({ 'https://vendor.example/a': { status: 302 } })
    expect(await safeFetch('https://vendor.example/a', h.opts())).toMatchObject({ ok: false, code: 'BAD_REDIRECT' })
  })
})

describe('safeFetch: response limits', () => {
  it('refuses a declared Content-Length over the cap without reading the body', async () => {
    const h = harness({ 'https://vendor.example/x': { headers: { 'content-length': '999999' }, body: '{}' } })
    expect(await safeFetch('https://vendor.example/x', h.opts({ maxBytes: 1000 }))).toMatchObject({ ok: false, code: 'TOO_LARGE' })
    expect(h.destroyed()).toBe(1)
  })

  it('refuses a streamed body that exceeds the cap (no or false Content-Length)', async () => {
    const chunk = new Uint8Array(600)
    const h = harness({ 'https://vendor.example/x': { headers: { 'content-length': '10' }, body: [chunk, chunk] } })
    expect(await safeFetch('https://vendor.example/x', h.opts({ maxBytes: 1000 }))).toMatchObject({ ok: false, code: 'TOO_LARGE' })
  })

  it('refuses a content type outside the allowlist', async () => {
    const h = harness({ 'https://vendor.example/x': { headers: { 'content-type': 'text/html; charset=utf-8' }, body: '<html>' } })
    expect(await safeFetch('https://vendor.example/x', h.opts())).toMatchObject({ ok: false, code: 'CONTENT_TYPE' })
    const missing = harness({ 'https://vendor.example/x': { headers: { 'content-type': '' }, body: '{}' } })
    expect(await safeFetch('https://vendor.example/x', missing.opts())).toMatchObject({ ok: false, code: 'CONTENT_TYPE' })
  })

  it('refuses compressed bodies (identity was requested)', async () => {
    const h = harness({ 'https://vendor.example/x': { headers: { 'content-encoding': 'gzip' }, body: '{}' } })
    expect(await safeFetch('https://vendor.example/x', h.opts())).toMatchObject({ ok: false, code: 'CONTENT_ENCODING' })
  })

  it('reports non-2xx statuses with the status code', async () => {
    const h = harness({ 'https://vendor.example/x': { status: 404 } })
    expect(await safeFetch('https://vendor.example/x', h.opts())).toMatchObject({ ok: false, code: 'HTTP_STATUS', status: 404 })
  })

  it('times out a request that never answers', async () => {
    const h = harness({ 'https://vendor.example/x': { hang: true } })
    expect(await safeFetch('https://vendor.example/x', h.opts({ timeoutMs: 50 }))).toMatchObject({ ok: false, code: 'TIMEOUT' })
  })

  it('returns the body, its sha256 and sends only identifying, credential-free headers', async () => {
    const h = harness({ 'https://vendor.example/x': { body: 'hello', headers: { 'content-type': 'text/plain; charset=utf-8', 'set-cookie': 'a=b' } } })
    const r = await safeFetch('https://vendor.example/x', h.opts({ now: () => new Date('2026-10-06T00:00:00Z') }))
    expect(r).toMatchObject({ ok: true, status: 200, bytes: 5, sha256: '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', fetchedAt: '2026-10-06T00:00:00.000Z' })
    const headers = Object.fromEntries(Object.entries(h.calls[0]!.headers).map(([k, v]) => [k.toLowerCase(), v]))
    expect(headers['user-agent']).toMatch(/^TOUCHSTONE\//)
    expect(headers['accept-encoding']).toBe('identity')
    expect(headers).not.toHaveProperty('cookie')
    expect(headers).not.toHaveProperty('authorization')
    expect(headers).not.toHaveProperty('referer')
  })
})

describe('HostRateLimiter', () => {
  it('spaces requests to the same host and not across hosts', async () => {
    let now = 1_000
    const sleeps: number[] = []
    const rl = new HostRateLimiter(500, () => now, async (ms) => {
      sleeps.push(ms)
      now += ms
    })
    await rl.wait('a.example')
    await rl.wait('a.example')
    await rl.wait('b.example')
    await rl.wait('a.example')
    expect(sleeps).toEqual([500, 500])
  })
})
