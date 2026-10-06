/**
 * Smoke test against a running TOUCHSTONE server.
 *
 *   node scripts/smoke.ts [baseUrl]          default http://127.0.0.1:8787
 *
 * Checks /api/health, /api/runs, /api/signatories, one vendor (summary and
 * goals), a dispute POST + GET round trip, the security headers, and (unless
 * TOUCHSTONE_SMOKE_API_ONLY=true) that the single-page app HTML is served with
 * its SPA fallback. TOUCHSTONE_SMOKE_NO_WRITE=true skips the dispute POST
 * (use it against a server whose dispute log should stay untouched).
 *
 * Only the given base URL is contacted. Exit code 0 when every check passes, 1 otherwise.
 */

const base = (process.argv[2] ?? 'http://127.0.0.1:8787').replace(/\/+$/, '')
const apiOnly = process.env['TOUCHSTONE_SMOKE_API_ONLY'] === 'true'
const noWrite = process.env['TOUCHSTONE_SMOKE_NO_WRITE'] === 'true'

let parsed: URL
try {
  parsed = new URL(base)
} catch {
  console.error(`smoke: "${base}" is not a URL`)
  process.exit(1)
}
if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
  console.error('smoke: the base URL must be http:// or https://')
  process.exit(1)
}

type Json = Record<string, any>
const results: { name: string; ok: boolean; detail: string }[] = []

async function request(path: string, init: RequestInit = {}): Promise<Response> {
  return fetch(`${base}${path}`, { ...init, redirect: 'manual', signal: AbortSignal.timeout(30_000) })
}

async function json(path: string, init?: RequestInit): Promise<{ res: Response; body: Json }> {
  const res = await request(path, { ...init, headers: { accept: 'application/json', ...(init?.headers ?? {}) } })
  const type = res.headers.get('content-type') ?? ''
  if (!type.includes('json')) throw new Error(`${path}: expected JSON, got ${type || 'no content type'} (HTTP ${res.status})`)
  return { res, body: (await res.json()) as Json }
}

async function check(name: string, fn: () => Promise<string>): Promise<void> {
  try {
    const detail = await fn()
    results.push({ name, ok: true, detail })
  } catch (e) {
    results.push({ name, ok: false, detail: e instanceof Error ? e.message : String(e) })
  }
}

function assert(cond: unknown, message: string): asserts cond {
  if (!cond) throw new Error(message)
}

let latestRunId = ''
let vendorId = ''

await check('GET /api/health', async () => {
  const { res, body } = await json('/api/health')
  assert(res.status === 200, `HTTP ${res.status} (${body['status']})`)
  assert(body['ok'] === true, 'health is not ok')
  for (const h of ['content-security-policy', 'x-content-type-options', 'referrer-policy']) assert(res.headers.get(h), `missing ${h} header`)
  assert((res.headers.get('content-security-policy') ?? '').includes("frame-ancestors 'none'"), "CSP lacks frame-ancestors 'none'")
  return `${body['dataMode']} data, latest ${body['latestRunId']}, refresh ${body['refreshMode']}, admin ${body['adminEnabled'] ? 'enabled' : 'disabled'}`
})

await check('GET /api/runs', async () => {
  const { res, body } = await json('/api/runs')
  assert(res.status === 200, `HTTP ${res.status}`)
  assert(Array.isArray(body['runs']) && body['runs'].length > 0, 'no runs published')
  latestRunId = String(body['latestRunId'])
  assert(body['runs'].some((r: Json) => r['runId'] === latestRunId), 'latestRunId is not among the runs')
  return `${body['runs'].length} run(s), latest ${latestRunId}`
})

await check('GET /api/signatories', async () => {
  const { res, body } = await json('/api/signatories?sort=coverage&limit=5')
  assert(res.status === 200, `HTTP ${res.status}`)
  assert(Array.isArray(body['rows']) && body['rows'].length > 0, 'no signatories')
  vendorId = String(body['rows'][0]['id'])
  return `${body['total']} vendor(s) in ${body['runId']}`
})

await check('GET /api/vendors/:id and /goals', async () => {
  assert(vendorId, 'no vendor id from the directory')
  const v = await json(`/api/vendors/${encodeURIComponent(vendorId)}`)
  assert(v.res.status === 200, `vendor HTTP ${v.res.status}`)
  assert(v.body['summary']?.['vendor']?.['id'] === vendorId, 'vendor summary does not match')
  const g = await json(`/api/vendors/${encodeURIComponent(vendorId)}/goals`)
  assert(g.res.status === 200, `goals HTTP ${g.res.status}`)
  assert(Array.isArray(g.body['goals']) && g.body['goals'].length === 7, 'expected seven goals')
  const ev = await json(`/api/vendors/${encodeURIComponent(vendorId)}/evidence`)
  assert(ev.res.status === 200 && Array.isArray(ev.body['evidence']), 'evidence not served')
  return `${vendorId}: ${ev.body['evidence'].length} evidence item(s)`
})

if (!noWrite) {
  await check('POST /api/disputes round trip', async () => {
    const statement = `Smoke test dispute created by scripts/smoke.ts at ${new Date().toISOString()}. Safe to dismiss.`
    const created = await json('/api/disputes', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        vendorId,
        runId: latestRunId,
        target: { kind: 'GOAL', id: 'G5' },
        reason: 'METHODOLOGY_ERROR',
        submitterRole: 'OTHER',
        statement,
        evidenceUrls: ['https://example.org/touchstone-smoke'],
      }),
    })
    assert(created.res.status === 201, `HTTP ${created.res.status}: ${JSON.stringify(created.body['error'] ?? created.body).slice(0, 200)}`)
    const id = String(created.body['id'])
    assert(created.body['status'] === 'OPEN', 'new dispute is not OPEN')
    const back = await json(`/api/disputes/${encodeURIComponent(id)}`)
    assert(back.res.status === 200, `GET HTTP ${back.res.status}`)
    assert(back.body['statement'] === statement, 'statement did not round-trip')
    assert(Array.isArray(back.body['history']) && back.body['history'].length === 1, 'history should have one event')
    return `${id} created and read back`
  })
}

await check('error envelope', async () => {
  const { res, body } = await json('/api/does-not-exist')
  assert(res.status === 404, `HTTP ${res.status}`)
  assert(typeof body['error']?.['code'] === 'string', 'no error.code')
  return body['error']['code']
})

if (!apiOnly) {
  await check('GET / serves the app', async () => {
    const res = await request('/')
    assert(res.status === 200, `HTTP ${res.status}`)
    assert((res.headers.get('content-type') ?? '').includes('text/html'), 'not HTML')
    const html = await res.text()
    assert(html.includes('id="root"'), 'no app root element')
    assert(res.headers.get('content-security-policy'), 'no CSP on the app shell')
    return `${html.length} bytes`
  })
  await check('SPA fallback', async () => {
    const res = await request(`/vendors/${encodeURIComponent(vendorId || 'x')}`)
    assert(res.status === 200 && (res.headers.get('content-type') ?? '').includes('text/html'), `HTTP ${res.status}`)
    return 'client route answered with the app shell'
  })
}

let failed = 0
for (const r of results) {
  if (!r.ok) failed++
  console.log(`${r.ok ? 'ok  ' : 'FAIL'}  ${r.name}${r.detail ? `  ${r.detail}` : ''}`)
}
console.log(`\n${results.length - failed}/${results.length} checks passed against ${base}${apiOnly ? ' (API only)' : ''}`)
process.exit(failed ? 1 : 0)
