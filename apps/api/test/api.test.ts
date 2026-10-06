import { afterAll, describe, expect, it } from 'vitest'
import { BRIGHTWATER, HALCYON, NORTHWIND, RUN_1, RUN_2 } from './fixtures/bundle.ts'
import { makeApp } from './helpers.ts'

type Json = Record<string, any>
const get = async (t: ReturnType<typeof makeApp>, path: string) => {
  const r = await t.app.request(path)
  return { status: r.status, headers: r.headers, body: (r.headers.get('content-type') ?? '').includes('json') ? ((await r.json()) as any) : await r.text() }
}

describe('read endpoints over the published bundle', () => {
  const t = makeApp()
  afterAll(() => t.close())

  it('GET /api/health reports data, mode and admin state', async () => {
    const r = await get(t, '/api/health')
    expect(r.status).toBe(200)
    expect(r.body).toMatchObject({ ok: true, status: 'ok', latestRunId: RUN_2, runs: 2, refreshMode: 'DEMO', adminEnabled: false, dataMode: 'DEMO' })
    expect(r.body.networkCollection).toContain('no network calls')
    expect(r.body.db.ok).toBe(true)
  })

  it('GET /api/runs returns the RunIndex and /api/runs/:id the RunSummary', async () => {
    const idx = await get(t, '/api/runs')
    expect(idx.body.latestRunId).toBe(RUN_2)
    expect(idx.body.runs).toHaveLength(2)
    const s = await get(t, `/api/runs/${RUN_1}`)
    expect(s.status).toBe(200)
    expect(s.body.manifest.runId).toBe(RUN_1)
    expect(s.body.vendors).toHaveLength(2)
    expect((await get(t, '/api/runs/TS-1999-01-01-ffff')).status).toBe(404)
    expect((await get(t, '/api/runs/..%2F..%2Fetc')).status).toBe(404)
  })

  it('GET /api/runs/:id/inputs returns the run inputs', async () => {
    const r = await get(t, `/api/runs/${RUN_2}/inputs`)
    expect(r.status).toBe(200)
    expect(r.body).toMatchObject({ mode: 'DEMO', datasetVersion: '2026-10-06', methodologyVersion: '1.1.0' })
  })

  it('GET /api/signatories lists directory rows with filters, search, sort and pagination', async () => {
    const all = await get(t, '/api/signatories')
    expect(all.status).toBe(200)
    expect(all.body.runId).toBe(RUN_2)
    expect(all.body.total).toBe(3)
    expect(all.body.rows.map((r: Json) => r.id)).toEqual([BRIGHTWATER, HALCYON, NORTHWIND])
    const row = all.body.rows.find((r: Json) => r.id === NORTHWIND)
    expect(row).toMatchObject({ name: 'Northwind Systems', category: 'ENTERPRISE_SOFTWARE', synthetic: true, cveCount: 2, activeDisputes: 1 })
    expect(row.dimensions.VDP).toEqual({ value: 75, status: 'VERIFIED' })

    const cloud = await get(t, '/api/signatories?category=cloud')
    expect(cloud.body.rows.map((r: Json) => r.id)).toEqual([HALCYON])
    const multi = await get(t, '/api/signatories?category=CLOUD,NETWORKING')
    expect(multi.body.total).toBe(2)
    const cov = await get(t, '/api/signatories?coverageMin=20&coverageMax=50')
    expect(cov.body.rows.map((r: Json) => r.id)).toEqual([HALCYON])
    const search = await get(t, '/api/signatories?q=northwind')
    expect(search.body.rows.map((r: Json) => r.id)).toEqual([NORTHWIND])
    const byCoverage = await get(t, '/api/signatories?sort=coverage')
    expect(byCoverage.body.order).toBe('desc')
    expect(byCoverage.body.rows.map((r: Json) => r.id)).toEqual([NORTHWIND, HALCYON, BRIGHTWATER])
    const page = await get(t, '/api/signatories?sort=coverage&limit=1&offset=1')
    expect(page.body.rows.map((r: Json) => r.id)).toEqual([HALCYON])
    expect(page.body.total).toBe(3)
    const oldRun = await get(t, `/api/signatories?run=${RUN_1}`)
    expect(oldRun.body.total).toBe(2)
    // DSP-0001 was filed against RUN_2: it does not overlay the earlier run.
    expect(oldRun.body.rows.find((r: Json) => r.id === NORTHWIND).activeDisputes).toBe(0)
  })

  it('never ranks an unmeasured vendor as 0: nulls sort last in both directions', async () => {
    for (const order of ['asc', 'desc']) {
      const r = await get(t, `/api/signatories?sort=vdp&order=${order}`)
      expect(r.body.rows[r.body.rows.length - 1].id).toBe(HALCYON)
      expect(r.body.rows[r.body.rows.length - 1].dimensions.VDP.value).toBeNull()
    }
    const asc = await get(t, '/api/signatories?sort=vdp&order=asc')
    expect(asc.body.rows.map((r: Json) => r.id)).toEqual([BRIGHTWATER, NORTHWIND, HALCYON])
  })

  it('rejects invalid directory filters with the error envelope', async () => {
    for (const q of ['category=ROCKETS', 'coverageMin=-1', 'coverageMin=80&coverageMax=10', 'sort=score', 'limit=0', 'limit=100000']) {
      const r = await get(t, `/api/signatories?${q}`)
      expect(r.status, q).toBe(400)
      expect(r.body.error.code).toBe('VALIDATION_FAILED')
    }
  })

  it('GET /api/vendors/:id returns the summary, active disputes and run presence', async () => {
    const r = await get(t, `/api/vendors/${NORTHWIND}`)
    expect(r.status).toBe(200)
    expect(r.body.runId).toBe(RUN_2)
    expect(r.body.summary.vendor.id).toBe(NORTHWIND)
    expect(r.body.activeDisputes.map((d: Json) => d.id)).toEqual(['DSP-0001'])
    expect(r.body.presentInRuns.map((x: Json) => x.runId)).toEqual([RUN_1, RUN_2])
    expect((await get(t, '/api/vendors/acme-unknown')).status).toBe(404)
    expect((await get(t, '/api/vendors/BAD%20ID')).status).toBe(404)
    const notInRun = await get(t, `/api/vendors/${BRIGHTWATER}?run=${RUN_1}`)
    expect(notInRun.status).toBe(404)
    expect(notInRun.body.error.message).toContain('not part of run')
  })

  it('GET /api/vendors/:id/goals overlays DISPUTED without changing the original status', async () => {
    const r = await get(t, `/api/vendors/${NORTHWIND}/goals`)
    expect(r.status).toBe(200)
    expect(r.body.goals).toHaveLength(7)
    const g5 = r.body.goals.find((g: Json) => g.goal.id === 'G5')
    expect(g5.originalStatus).toBe('VERIFIED')
    expect(g5.assessment.status).toBe('VERIFIED')
    expect(g5.displayState).toBe('DISPUTED')
    expect(g5.activeDisputeIds).toEqual(['DSP-0001'])
    const g1 = r.body.goals.find((g: Json) => g.goal.id === 'G1')
    expect(g1.displayState).toBe('NOT_EXTERNALLY_VERIFIABLE')
    // The dispute was filed against RUN_2; the earlier run is shown without it.
    const old = await get(t, `/api/vendors/${NORTHWIND}/goals?run=${RUN_1}`)
    expect(old.body.goals.find((g: Json) => g.goal.id === 'G5').displayState).toBe('VERIFIED')
  })

  it('GET /api/vendors/:id/evidence returns the VendorDetail, optionally filtered', async () => {
    const r = await get(t, `/api/vendors/${NORTHWIND}/evidence?run=${RUN_1}`)
    expect(r.status).toBe(200)
    expect(r.body.runId).toBe(RUN_1)
    expect(r.body.vendorId).toBe(NORTHWIND)
    expect(r.body.evidence.length).toBe(2)
    expect(r.body.cves.length).toBe(2)
    const f = await get(t, `/api/vendors/${NORTHWIND}/evidence?metric=vdp.criteria_met`)
    expect(f.body.evidence).toEqual([])
  })

  it('GET /api/vendors/:id/history returns that vendor’s series only', async () => {
    const r = await get(t, `/api/vendors/${NORTHWIND}/history`)
    expect(r.status).toBe(200)
    expect(r.body).toHaveLength(1)
    expect(r.body[0].points.map((p: Json) => p.value)).toEqual([40, 50])
    const h = await get(t, `/api/vendors/${HALCYON}/history`)
    expect(h.body[0].points.map((p: Json) => p.value)).toEqual([null, null])
  })

  it('GET /api/cves lists attributed records with filters and CNA-only classification', async () => {
    const r = await get(t, '/api/cves')
    expect(r.status).toBe(200)
    expect(r.body.total).toBe(3)
    const byId = Object.fromEntries(r.body.rows.map((x: Json) => [x.id, x]))
    expect(byId['DEMO-2026-0001']).toMatchObject({ cnaFieldStatus: 'COMPLETE', enrichedOnly: false, severity: 'HIGH', severitySource: 'CNA', year: 2026 })
    // Ownership is the engine's attribution; the issuing CNA is reported separately and never treated as the owner.
    expect(byId['DEMO-2025-0003']).toMatchObject({ vendorIds: [HALCYON], assignerCna: 'northwind', exclusions: [] })
    // CWE came only from CISA-ADP: not credited, reported as enrichment.
    expect(byId['DEMO-2026-0002']).toMatchObject({ cnaFieldStatus: 'MISSING_CWE', enrichedOnly: true, severity: 'CRITICAL', severitySource: 'ADP' })
    // Methodology 1.1.0: a placeholder CWE is not a populated CWE.
    expect(byId['DEMO-2025-0003']).toMatchObject({ cnaFieldStatus: 'MISSING_BOTH', severity: 'UNKNOWN', severitySource: null })

    const q = async (s: string) => (await get(t, `/api/cves?${s}`)).body.rows.map((x: Json) => x.id)
    expect(await q(`vendor=${HALCYON}`)).toEqual(['DEMO-2025-0003'])
    expect(await q('year=2025')).toEqual(['DEMO-2025-0003'])
    expect(await q('severity=critical')).toEqual(['DEMO-2026-0002'])
    expect(await q('cwe=79')).toEqual(['DEMO-2026-0001'])
    expect(await q('cwe=CWE-787')).toEqual([])
    expect(await q('product=CONSOLE')).toEqual(['DEMO-2026-0002'])
    expect(await q('completeness=enriched_only')).toEqual(['DEMO-2026-0002'])
    expect(await q('completeness=complete,missing_both')).toEqual(['DEMO-2026-0001', 'DEMO-2025-0003'])
    expect(await q('limit=1')).toHaveLength(1)
    expect((await get(t, '/api/cves?severity=apocalyptic')).status).toBe(400)
    expect((await get(t, '/api/cves?cwe=79%27%20OR%201%3D1')).status).toBe(400)
  })

  it('GET /api/cves/:id returns the record, attributions and exclusions', async () => {
    const r = await get(t, '/api/cves/demo-2026-0001')
    expect(r.status).toBe(200)
    expect(r.body.record.id).toBe('DEMO-2026-0001')
    expect(r.body.attributions[0]).toMatchObject({ vendorId: NORTHWIND, rule: 'ASSIGNER_IS_VENDOR_CNA' })
    const excluded = await get(t, '/api/cves/DEMO-2026-0009')
    expect(excluded.status).toBe(200)
    expect(excluded.body.record).toBeNull()
    expect(excluded.body.exclusions[0].reason).toBe('AMBIGUOUS_VENDOR')
    expect((await get(t, '/api/cves/CVE-2099-99999')).status).toBe(404)
    expect((await get(t, '/api/cves/not-a-cve')).status).toBe(400)
  })

  it('GET /api/goals and /api/methodology', async () => {
    const g = await get(t, '/api/goals')
    expect(g.body.goals).toHaveLength(7)
    expect(g.body.goals.filter((x: Json) => x.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE').map((x: Json) => x.id)).toEqual(['G1', 'G2', 'G4', 'G7'])
    expect(g.body.metricDefinitions.length).toBeGreaterThan(0)
    const m = await get(t, '/api/methodology')
    expect(m.body.current).toBe('1.1.0')
    expect(m.body.versions.map((v: Json) => v.version)).toEqual(['1.0.0', '1.1.0'])
    expect(m.body.versions[1].runs).toEqual([RUN_1, RUN_2])
    expect(m.body.versions[1].parameters.placeholderCweCountsAsPopulated).toBe(false)
  })

  it('GET /api/freshness reports per-source freshness and substitutions', async () => {
    const r = await get(t, '/api/freshness')
    expect(r.status).toBe(200)
    expect(r.body.freshness[0].state).toBe('CURRENT')
    expect(r.body.snapshotStatus).toEqual({ OK: 1, FAILED: 1 })
    expect(r.body.substitutions[0]).toMatchObject({ sourceId: 'vendor.halcyon.vdp', substitutedBy: 'SN-000000000003' })
  })

  it('GET /api/reports/:vendorId renders each format as an attachment', async () => {
    const cases: [string, string, string][] = [
      ['json', 'application/json', '.json'],
      ['markdown', 'text/markdown', '.md'],
      ['md', 'text/markdown', '.md'],
      ['csv', 'text/csv', '.csv'],
      ['pdf', 'application/pdf', '.pdf'],
    ]
    for (const [format, type, ext] of cases) {
      const r = await t.app.request(`/api/reports/${NORTHWIND}?format=${format}`)
      expect(r.status, format).toBe(200)
      expect(r.headers.get('content-type')).toContain(type)
      expect(r.headers.get('content-disposition')).toBe(`attachment; filename="touchstone-${NORTHWIND}-${RUN_2}${ext}"`)
      if (format === 'pdf') expect(new TextDecoder().decode(new Uint8Array(await r.arrayBuffer())).startsWith('%PDF-')).toBe(true)
    }
    expect(t.calls).toContain('vendorReport:markdown')
    expect((await t.app.request(`/api/reports/${NORTHWIND}?format=docx`)).status).toBe(400)
    expect((await t.app.request('/api/reports/nobody?format=json')).status).toBe(404)
  })

  it('POST /api/runs/:id/reproduce re-executes from the run inputs and compares outputsHash', async () => {
    const r = await t.app.request(`/api/runs/${RUN_1}/reproduce`, { method: 'POST' })
    expect(r.status).toBe(200)
    const body = (await r.json()) as Json
    expect(body).toMatchObject({ runId: RUN_1, reproduced: true, mismatches: [], methodologyVersion: '1.1.0' })
    expect(body.actual.outputsHash).toBe(body.expected.outputsHash)
    expect(body.statement).toContain('Nothing was fetched')
    expect(t.calls).toContain('reproduceRun')
  })

  it('unknown /api paths get the JSON error envelope', async () => {
    const r = await get(t, '/api/nope')
    expect(r.status).toBe(404)
    expect(r.body).toEqual({ error: { code: 'NOT_FOUND', message: 'No such endpoint.' } })
  })
})

describe('reproduce mismatch and missing inputs', () => {
  it('reports reproduced=false when the published outputsHash does not match', async () => {
    const t = makeApp({}, { bundle: { outputsHash: { '2026-10-06': 'f'.repeat(64) } } })
    const r = await t.app.request(`/api/runs/${RUN_2}/reproduce`, { method: 'POST' })
    const body = (await r.json()) as Json
    expect(r.status).toBe(200)
    expect(body.reproduced).toBe(false)
    expect(body.mismatches).toEqual(['outputsHash'])
    expect(body.expected.outputsHash).toBe('f'.repeat(64))
    await t.close()
  })

  it('answers 404 INPUTS_NOT_PUBLISHED when the inputs are not in the bundle', async () => {
    const t = makeApp({}, { bundle: { withoutInputs: true } })
    const r = await t.app.request(`/api/runs/${RUN_2}/reproduce`, { method: 'POST' })
    expect(r.status).toBe(404)
    expect(((await r.json()) as Json).error.code).toBe('INPUTS_NOT_PUBLISHED')
    expect((await t.app.request(`/api/runs/${RUN_2}/inputs`)).status).toBe(404)
    await t.close()
  })
})

describe('without a published bundle', () => {
  const t = makeApp({}, { bundle: false })
  afterAll(() => t.close())

  it('health is degraded (503) and data endpoints answer 503 DATA_NOT_PUBLISHED', async () => {
    const h = await t.app.request('/api/health')
    expect(h.status).toBe(503)
    expect(((await h.json()) as Json).ok).toBe(false)
    for (const p of ['/api/runs', '/api/signatories', `/api/vendors/${NORTHWIND}`, '/api/cves', '/api/freshness']) {
      const r = await t.app.request(p)
      expect(r.status, p).toBe(503)
      expect(((await r.json()) as Json).error.code).toBe('DATA_NOT_PUBLISHED')
    }
    expect((await t.app.request('/api/goals')).status).toBe(200)
    expect((await t.app.request('/api/methodology')).status).toBe(200)
  })
})
