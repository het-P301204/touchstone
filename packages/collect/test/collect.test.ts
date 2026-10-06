import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, describe, expect, it } from 'vitest'
import type { Vendor } from '../../core/src/model/index.ts'
import { robotsAllows, robotsPatternMatches } from '../src/robots.ts'
import { SnapshotStore } from '../src/store.ts'
import { collectLive } from '../src/live.ts'
import { nvdWindows, nvdUrl } from '../src/collectors/nvd-enumerate.ts'
import { advisoryPathsFromChangesCsv, advisoryUrlsFromRolie, feedUrlsFromProviderMetadata } from '../src/collectors/csaf.ts'
import { choosePolicyUrl, selectPolicyUrl } from '../src/collectors/vdp-policy.ts'
import { cveRecordUrl } from '../src/collectors/cve-records.ts'
import type { Fetcher } from '../src/collectors/common.ts'
import type { SafeFetchResult } from '../src/safe-fetch.ts'

const realFixture = (name: string) => readFileSync(new URL(`../../../fixtures/real/${name}`, import.meta.url))
const dirs: string[] = []
const tmp = () => {
  const d = mkdtempSync(join(tmpdir(), 'touchstone-collect-'))
  dirs.push(d)
  return d
}
afterEach(() => {
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
})

describe('robots.txt', () => {
  const robots = ['User-agent: *', 'Disallow: /private', 'Allow: /private/vdp', '', 'User-agent: BadBot', 'Disallow: /', '', 'User-agent: touchstone', 'Disallow: /security/*.pdf$'].join('\n')
  it('uses our group when present, else *, with longest-match and Allow on ties', () => {
    expect(robotsAllows(robots, '/security/vdp', 'TOUCHSTONE')).toBe(true)
    expect(robotsAllows(robots, '/security/policy.pdf', 'TOUCHSTONE')).toBe(false)
    expect(robotsAllows(robots, '/private/x', 'OtherBot')).toBe(false)
    expect(robotsAllows(robots, '/private/vdp', 'OtherBot')).toBe(true)
    expect(robotsAllows('User-agent: *\nDisallow: /\n', '/anything', 'TOUCHSTONE')).toBe(false)
    expect(robotsAllows('User-agent: *\nDisallow:\n', '/anything', 'TOUCHSTONE')).toBe(true)
    expect(robotsAllows('', '/x', 'TOUCHSTONE')).toBe(true)
  })
  it('glob matching is safe on hostile patterns', () => {
    const t = performance.now()
    expect(robotsPatternMatches('*a*a*a*a*a*a*a*a*b', 'a'.repeat(3000))).toBe(false)
    expect(performance.now() - t).toBeLessThan(2000)
  })
})

describe('SnapshotStore', () => {
  it('stores content by hash, verifies on read, records failures with an explicit substitute', () => {
    const store = new SnapshotStore(tmp())
    const body = new TextEncoder().encode('hello')
    const ok = store.record({ sourceId: 's', url: 'https://x.example/a', fetchedAt: '2026-10-01T00:00:00Z', body, retention: 'RAW', parserVersion: '1.0.0', httpStatus: 200 })
    expect(ok.sha256).toBe('2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824')
    expect(ok.rawPath).toBe(`snapshots/${ok.sha256}`)
    expect(new TextDecoder().decode(store.get(ok.sha256!)!)).toBe('hello')
    const failed = store.recordFailure({ sourceId: 's', url: 'https://x.example/a', fetchedAt: '2026-10-06T00:00:00Z', error: 'TIMEOUT', parserVersion: '1.0.0', substitutedBy: ok.id })
    expect(failed).toMatchObject({ status: 'FAILED', substitutedBy: ok.id })
    expect(store.latestOk('s', 'https://x.example/a')!.id).toBe(ok.id)
    expect(store.list().map((s) => s.status)).toEqual(['OK', 'FAILED'])
    // tampering is detected
    writeFileSync(join(store.dir, ok.sha256!), 'tampered')
    expect(() => store.get(ok.sha256!)).toThrow(/corrupt/)
  })
  it('EXTRACT_ONLY keeps a hash, not the raw bytes', () => {
    const store = new SnapshotStore(tmp())
    const s = store.record({ sourceId: 'p', url: 'https://x.example/p', fetchedAt: '2026-10-01T00:00:00Z', body: new TextEncoder().encode('<p>policy</p>'), retention: 'EXTRACT_ONLY', parserVersion: '1.0.0' })
    expect(s.rawPath).toBeUndefined()
    expect(store.get(s.sha256!)).toBeNull()
  })
})

describe('collector helpers', () => {
  it('splits NVD enumeration into windows of at most 120 days', () => {
    const w = nvdWindows('2024-10-06T00:00:00.000Z', '2026-10-06T00:00:00.000Z')
    expect(w.length).toBe(7)
    for (const x of w) expect(Date.parse(x.end) - Date.parse(x.start)).toBeLessThan(120 * 86_400_000)
    expect(w[0]!.start).toBe('2024-10-06T00:00:00.000Z')
    expect(w[w.length - 1]!.end).toBe('2026-10-06T00:00:00.000Z')
    expect(nvdUrl('f38d906d-7342-40ea-92c1-6c4a2c6478c8', w[0]!, 0)).toMatch(/^https:\/\/services\.nvd\.nist\.gov\/rest\/json\/cves\/2\.0\?sourceIdentifier=f38d906d/)
  })
  it('builds CVE record URLs only for real CVE ids', () => {
    expect(cveRecordUrl('CVE-2024-3094')).toBe('https://cveawg.mitre.org/api/cve/CVE-2024-3094')
    expect(() => cveRecordUrl('CVE-2024-3094/../../x')).toThrow()
    expect(() => cveRecordUrl('DEMO-2026-1001')).toThrow()
  })
  it('reads CSAF provider metadata, ROLIE feeds and changes.csv', () => {
    expect(feedUrlsFromProviderMetadata({ distributions: [{ rolie: { feeds: [{ url: 'https://v.example/feed.json' }] } }, { directory_url: 'https://v.example/csaf/' }] })).toEqual({ rolie: ['https://v.example/feed.json'], directories: ['https://v.example/csaf/'] })
    expect(advisoryUrlsFromRolie({ feed: { entry: [{ content: { src: 'https://v.example/a.json' } }, { link: [{ rel: 'self', href: 'https://v.example/b.json' }] }] } })).toEqual(['https://v.example/a.json', 'https://v.example/b.json'])
    expect(advisoryPathsFromChangesCsv('"2025/a.json","2025-01-01T00:00:00Z"\n"2026/b.json","2026-01-01T00:00:00Z"\nbad line')).toEqual(['2026/b.json', '2025/a.json'])
  })
  it('chooses a policy URL only on vendor domains or known platforms', () => {
    const v = { id: 'v', domains: ['vendor.example'], vdpPolicyUrl: 'https://vendor.example/vdp' } as Vendor
    const stxt = (urls: string[]) => ({ present: true, contacts: [], policyUrls: urls, canonical: [], warnings: [], signed: false })
    expect(choosePolicyUrl(v, stxt(['https://evil.example/vdp']))).toBe('https://vendor.example/vdp')
    expect(choosePolicyUrl(v, stxt(['http://www.vendor.example/vdp']))).toBe('https://vendor.example/vdp')
    expect(choosePolicyUrl(v, stxt(['https://www.vendor.example/policy']))).toBe('https://www.vendor.example/policy')
  })
  it('credits a shared-platform program only when the registry ties it to the vendor', () => {
    const stxt = (urls: string[]) => ({ present: true, contacts: [], policyUrls: urls, canonical: [], warnings: [], signed: false })
    const unconfirmed = { id: 'v', domains: ['vendor.example'], vdpPolicyUrl: 'https://vendor.example/vdp' } as Vendor
    expect(selectPolicyUrl(unconfirmed, stxt(['https://hackerone.com/vendor']))).toEqual({ url: 'https://vendor.example/vdp', skipped: ['https://hackerone.com/vendor'] })
    const none = { id: 'v', domains: ['vendor.example'] } as Vendor
    expect(selectPolicyUrl(none, stxt(['https://hackerone.com/vendor']))).toEqual({ skipped: ['https://hackerone.com/vendor'] })
    const confirmed = { id: 'v', domains: ['vendor.example'], vdpPolicyUrl: 'https://hackerone.com/vendor' } as Vendor
    expect(choosePolicyUrl(confirmed, stxt(['https://hackerone.com/vendor/policy_scopes']))).toBe('https://hackerone.com/vendor/policy_scopes')
    expect(choosePolicyUrl(confirmed, stxt(['https://hackerone.com/vendor-impostor']))).toBe('https://hackerone.com/vendor')
  })
  it('robots.txt: only an exact product token or * applies', () => {
    expect(robotsAllows('User-agent:\nDisallow: /\n', '/vdp', 'TOUCHSTONE')).toBe(true)
    expect(robotsAllows('User-agent: touch\nDisallow: /\n', '/vdp', 'TOUCHSTONE')).toBe(true)
    expect(robotsAllows('User-agent: TouchStone\nDisallow: /\n', '/vdp', 'TOUCHSTONE')).toBe(false)
    expect(robotsAllows('User-agent: *\nAllow: /\n', `/${'a'.repeat(600)}`, 'TOUCHSTONE')).toBe(false) // over-long path fails closed
  })
})

describe('collectLive (offline, injected fetcher)', () => {
  const vendor: Vendor = {
    id: 'acme',
    canonicalName: 'Acme',
    aliases: [
      { kind: 'SIGNATORY_LISTING', value: 'Akamai', confidence: 'HIGH', evidence: [{ statement: 'test' }] },
      { kind: 'CNA_SHORT_NAME', value: 'redhat', confidence: 'HIGH', evidence: [{ statement: 'test' }] },
    ],
    signatoryStatus: 'UNKNOWN',
    category: 'OTHER',
    domains: ['acme.example'],
    claims: [],
    synthetic: false,
  }
  const policyHtml = '<h1>VDP</h1><p>This policy applies to all Acme products.</p><p>We authorize security testing of systems in scope.</p><p>Report vulnerabilities by email to security@acme.example.</p><p>We will not pursue legal action against good-faith researchers.</p><p>You may publicly disclose findings 90 days after your report.</p>'

  function fetcherFor(table: Record<string, { body?: string | Uint8Array; type?: string; status?: number; fail?: string }>): { fetcher: Fetcher; urls: string[] } {
    const urls: string[] = []
    const fetcher: Fetcher = async (url): Promise<SafeFetchResult> => {
      urls.push(url)
      const r = table[url]
      const fetchedAt = '2026-10-06T01:00:00.000Z'
      if (!r) return { ok: false, url, code: 'HTTP_STATUS', status: 404, error: 'HTTP 404', redirects: [], fetchedAt }
      if (r.fail) return { ok: false, url, code: 'TIMEOUT', error: r.fail, redirects: [], fetchedAt }
      const body = typeof r.body === 'string' ? new TextEncoder().encode(r.body) : (r.body ?? new Uint8Array())
      return { ok: true, url, finalUrl: url, status: 200, contentType: r.type ?? 'text/plain', body, sha256: 'x'.repeat(64), bytes: body.byteLength, redirects: [], address: '93.184.215.14', fetchedAt }
    }
    return { fetcher, urls }
  }

  it('produces RunInputs from real-format documents, with FAILED snapshots substituted explicitly', async () => {
    const out = tmp()
    const registryPath = join(out, 'vendors.json')
    writeFileSync(registryPath, JSON.stringify([vendor]))
    const table: Record<string, { body?: string | Uint8Array; type?: string; fail?: string }> = {
      'https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers': { body: realFixture('cisa-signers-2026-10-06.html'), type: 'text/html' },
      'https://acme.example/.well-known/security.txt': { body: 'Contact: mailto:security@acme.example\nExpires: 2027-06-01T00:00:00Z\nPolicy: https://acme.example/vdp\n' },
      'https://acme.example/robots.txt': { body: 'User-agent: *\nDisallow: /internal\n' },
      'https://acme.example/vdp': { body: policyHtml, type: 'text/html' },
      'https://cveawg.mitre.org/api/cve/CVE-2024-3094': { body: realFixture('CVE-2024-3094.json'), type: 'application/json' },
    }
    const first = fetcherFor(table)
    const run1 = await collectLive({ vendorIds: ['acme'], registryPath, outDir: out, asOf: '2026-10-06T12:00:00Z', cveIds: { acme: ['CVE-2024-3094'] }, fetcher: first.fetcher })
    expect(run1.mode).toBe('LIVE')
    expect(run1.signatoryList).toMatchObject({ declaredCount: 387, parsedCount: 387 })
    expect(run1.vendors[0]!.signatoryStatus).toBe('LISTED')
    expect(run1.cves.map((c) => c.id)).toEqual(['CVE-2024-3094'])
    expect(run1.vdp[0]!.criteria.filter((c) => c.state === 'MET').length).toBe(8)
    expect(run1.snapshots.every((s) => s.status === 'OK')).toBe(true)

    // Second run: the policy fetch fails. The previous snapshot is carried, labelled, never silently.
    const second = fetcherFor({ ...table, 'https://acme.example/vdp': { fail: 'deadline exceeded' } })
    const run2 = await collectLive({ vendorIds: ['acme'], registryPath, outDir: out, asOf: '2026-10-07T12:00:00Z', cveIds: { acme: ['CVE-2024-3094'] }, fetcher: second.fetcher })
    const failed = run2.snapshots.find((s) => s.status === 'FAILED')!
    const policySnap = run1.snapshots.find((s) => s.url === 'https://acme.example/vdp')!
    expect(failed).toMatchObject({ sourceId: 'vendor.acme.vdp', substitutedBy: policySnap.id })
    expect(run2.snapshots.some((s) => s.id === policySnap.id)).toBe(true)
    expect(run2.vdp[0]!.carriedFromSnapshotId).toBe(policySnap.id)
    expect(run2.vdp[0]!.criteria.filter((c) => c.state === 'MET').length).toBe(8)
  })

  it('does not fetch a policy that robots.txt disallows, and reports it as UNKNOWN, not NOT_MET', async () => {
    const out = tmp()
    const registryPath = join(out, 'vendors.json')
    writeFileSync(registryPath, JSON.stringify([vendor]))
    const f = fetcherFor({
      'https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers': { fail: 'down' },
      'https://acme.example/.well-known/security.txt': { body: 'Contact: mailto:security@acme.example\nExpires: 2027-06-01T00:00:00Z\nPolicy: https://acme.example/vdp\n' },
      'https://acme.example/robots.txt': { body: 'User-agent: *\nDisallow: /\n' },
      'https://acme.example/vdp': { body: policyHtml, type: 'text/html' },
    })
    const r = await collectLive({ vendorIds: ['acme'], registryPath, outDir: out, asOf: '2026-10-06T12:00:00Z', fetcher: f.fetcher })
    expect(f.urls).not.toContain('https://acme.example/vdp')
    expect(r.vdp[0]!.criteria.find((c) => c.criterion === 'TESTING_AUTHORIZED')!.state).toBe('UNKNOWN')
    expect(r.vendors[0]!.signatoryStatus).toBe('UNKNOWN')
    expect(r.snapshots.some((s) => s.sourceId === 'cisa.signers' && s.status === 'FAILED')).toBe(true)
  })

  it('refuses unknown vendor ids', async () => {
    const out = tmp()
    const registryPath = join(out, 'vendors.json')
    writeFileSync(registryPath, JSON.stringify([vendor]))
    await expect(collectLive({ vendorIds: ['nope'], registryPath, outDir: out })).rejects.toThrow(/Unknown vendor/)
  })
})
