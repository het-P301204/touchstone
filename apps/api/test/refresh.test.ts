import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, expect, it } from 'vitest'
import { NORTHWIND, RUN_2, VENDORS } from './fixtures/bundle.ts'
import { ADMIN, makeApp, stubEngine } from './helpers.ts'

type Json = Record<string, any>

const poll = async (t: ReturnType<typeof makeApp>, jobId: string) => {
  await t.refresh.idle()
  return (await (await t.app.request(`/api/refresh/${jobId}`)).json()) as Json
}

describe('DEMO refresh', () => {
  it('replays the bundled snapshot stage by stage with no network calls', async () => {
    const t = makeApp({ adminToken: ADMIN })
    const r = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    expect(r.status).toBe(202)
    const started = (await r.json()) as Json
    expect(started.jobId).toMatch(/^rf_[0-9a-f]{24}$/)
    expect(started.mode).toBe('DEMO')
    expect(started.statement).toContain('makes no network calls')
    expect(started.stages.map((s: Json) => s.stage)).toEqual(['FETCH', 'NORMALIZE', 'VALIDATE', 'SCORE', 'PUBLISH'])

    const job = await poll(t, started.jobId)
    expect(job.status).toBe('DONE')
    expect(job.networkCalls).toBe(0)
    expect(job.stages.map((s: Json) => s.status)).toEqual(['OK', 'OK', 'OK', 'OK', 'OK'])
    expect(job.stages[0].detail).toContain('No network calls were made')
    expect(job.stages[0].detail).toContain('1 snapshot file')
    expect(job.stages[0].detail).toContain('1 source(s) are recorded in the snapshot manifest as FAILED')
    expect(job.stages[4].detail).toContain('identical to published run')
    expect(job.runId).toBe(RUN_2)
    expect(job.result).toMatchObject({ matchesPublished: true, datasetVersion: '2026-10-06', networkCalls: 0 })
    expect(t.calls).toEqual(['loadDemoInputs:2026-10-06', 'executeRun'])
    expect(t.calls).not.toContain('collectLive')

    const list = (await (await t.app.request('/api/refresh')).json()) as Json
    expect(list.current).toBeNull()
    expect(list.jobs[0].jobId).toBe(started.jobId)
    await t.close()
  })

  it('replays an earlier dataset on request and rejects an unknown one', async () => {
    const t = makeApp({ adminToken: ADMIN })
    const r = await t.json('POST', '/api/refresh', { datasetVersion: '2026-07-06' }, t.adminHeaders)
    const job = await poll(t, ((await r.json()) as Json).jobId)
    expect(job.datasetVersion).toBe('2026-07-06')
    expect(job.status).toBe('DONE')
    expect((await t.json('POST', '/api/refresh', { datasetVersion: '1999-01-01' }, t.adminHeaders)).status).toBe(404)
    expect((await t.json('POST', '/api/refresh', { datasetVersion: '../../x' }, t.adminHeaders)).status).toBe(400)
    await t.close()
  })

  it('accepts a POST with no body at all', async () => {
    const t = makeApp({ adminToken: ADMIN })
    const r = await t.app.request('/api/refresh', { method: 'POST', headers: t.adminHeaders })
    expect(r.status).toBe(202)
    await t.refresh.idle()
    await t.close()
  })

  it('runs one job at a time', async () => {
    const t = makeApp({ adminToken: ADMIN })
    const first = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    expect(first.status).toBe(202)
    const second = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    expect(second.status).toBe(409)
    const e = ((await second.json()) as Json).error
    expect(e.code).toBe('REFRESH_IN_PROGRESS')
    expect(e.details.jobId).toBe(((await first.json()) as Json).jobId)
    await t.refresh.idle()
    expect((await t.json('POST', '/api/refresh', {}, t.adminHeaders)).status).toBe(202)
    await t.close()
  })

  it('records a FETCH failure explicitly and skips the later stages', async () => {
    const t = makeApp({ adminToken: ADMIN }, { corruptFixtures: true })
    const r = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    const job = await poll(t, ((await r.json()) as Json).jobId)
    expect(job.status).toBe('FAILED')
    expect(job.error).toContain('FETCH failed')
    expect(job.error).toContain('sha256 mismatch')
    expect(job.stages.map((s: Json) => s.status)).toEqual(['FAILED', 'SKIPPED', 'SKIPPED', 'SKIPPED', 'SKIPPED'])
    expect(t.calls).toEqual([])
    await t.close()
  })

  it('records an engine failure in the stage that failed', async () => {
    const engine = stubEngine()
    engine.executeRun = () => {
      throw new Error('quality gate exploded')
    }
    const t = makeApp({ adminToken: ADMIN }, { engine })
    const r = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    const job = await poll(t, ((await r.json()) as Json).jobId)
    expect(job.status).toBe('FAILED')
    expect(job.stages.map((s: Json) => s.status)).toEqual(['OK', 'OK', 'OK', 'FAILED', 'SKIPPED'])
    expect(job.stages[3].detail).toContain('quality gate exploded')
    await t.close()
  })

  it('warns when the replay differs from the published run, without overwriting it', async () => {
    const t = makeApp({ adminToken: ADMIN }, { bundle: { outputsHash: { '2026-10-06': 'e'.repeat(64) } } })
    const r = await t.json('POST', '/api/refresh', {}, t.adminHeaders)
    const job = await poll(t, ((await r.json()) as Json).jobId)
    expect(job.status).toBe('DONE')
    expect(job.stages[4].status).toBe('WARN')
    expect(job.stages[4].detail).toContain('does not overwrite published data')
    expect(job.result.matchesPublished).toBe(false)
    const summary = (await (await t.app.request(`/api/runs/${RUN_2}`)).json()) as Json
    expect(summary.manifest.outputsHash).toBe('e'.repeat(64))
    await t.close()
  })

  it('GET /api/refresh/:jobId validates the id', async () => {
    const t = makeApp({ adminToken: ADMIN })
    expect((await t.app.request('/api/refresh/rf_000000000000000000000000')).status).toBe(404)
    expect((await t.app.request('/api/refresh/..%2F..%2Fetc')).status).toBe(404)
    await t.close()
  })

  it('marks jobs left running by a previous process as failed', async () => {
    const t = makeApp({ adminToken: ADMIN })
    t.store.saveJob({
      id: 'rf_aaaaaaaaaaaaaaaaaaaaaaaa',
      mode: 'DEMO',
      status: 'RUNNING',
      datasetVersion: '2026-10-06',
      requestedAt: '2026-10-06T00:00:00Z',
      startedAt: '2026-10-06T00:00:01Z',
      finishedAt: null,
      statement: 's',
      stages: [
        { stage: 'FETCH', status: 'OK', detail: '' },
        { stage: 'NORMALIZE', status: 'RUNNING', detail: '' },
        { stage: 'VALIDATE', status: 'PENDING', detail: '' },
      ],
      result: null,
      error: null,
    })
    expect(t.store.failInterruptedJobs('2026-10-06T01:00:00Z')).toBe(1)
    const j = (await (await t.app.request('/api/refresh/rf_aaaaaaaaaaaaaaaaaaaaaaaa')).json()) as Json
    expect(j.status).toBe('FAILED')
    expect(j.error).toContain('Interrupted')
    expect(j.stages.map((s: Json) => s.status)).toEqual(['OK', 'FAILED', 'SKIPPED'])
    await t.close()
  })
})

describe('LIVE refresh', () => {
  const registry = (dir: string) => {
    const path = join(dir, 'registry.json')
    writeFileSync(path, JSON.stringify(Object.values(VENDORS)))
    return path
  }

  it('calls the live collector only in live mode, scores the result and holds it for review', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'touchstone-live-'))
    const t = makeApp({ adminToken: ADMIN, mode: 'live', liveRegistry: registry(dir), liveOutDir: join(dir, 'out') })
    const r = await t.json('POST', '/api/refresh', { vendorIds: [NORTHWIND] }, t.adminHeaders)
    const started = (await r.json()) as Json
    expect(r.status).toBe(202)
    expect(started.mode).toBe('LIVE')
    expect(started.networkCalls).toBeNull()
    const job = await poll(t, started.jobId)
    expect(job.status).toBe('DONE')
    expect(t.calls).toEqual([`collectLive:${NORTHWIND}`, 'executeRun'])
    expect(job.stages.map((s: Json) => s.status)).toEqual(['WARN', 'OK', 'WARN', 'OK', 'SKIPPED'])
    expect(job.stages[2].detail).toContain('1 collection error(s)')
    expect(job.stages[4].detail).toContain('not published')
    expect(job.result.published).toBe(false)
    expect(existsSync(join(dir, 'out', 'runs', job.result.runId, 'manifest.json'))).toBe(true)
    await t.close()
    rmSync(dir, { recursive: true, force: true })
  })

  it('collects every registry vendor by default and refuses unknown ids or a datasetVersion', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'touchstone-live-'))
    const t = makeApp({ adminToken: ADMIN, mode: 'live', liveRegistry: registry(dir), liveOutDir: join(dir, 'out') })
    await poll(t, ((await (await t.json('POST', '/api/refresh', {}, t.adminHeaders)).json()) as Json).jobId)
    expect(t.calls[0]).toBe(`collectLive:${Object.keys(VENDORS).join(',')}`)
    expect((await t.json('POST', '/api/refresh', { datasetVersion: '2026-10-06' }, t.adminHeaders)).status).toBe(400)
    const unknown = await t.json('POST', '/api/refresh', { vendorIds: ['acme-unknown'] }, t.adminHeaders)
    const job = await poll(t, ((await unknown.json()) as Json).jobId)
    expect(job.status).toBe('FAILED')
    expect(job.error).toContain('Not in the live registry')
    await t.close()
    rmSync(dir, { recursive: true, force: true })
  })

  it('DEMO mode refuses vendorIds (no collection possible)', async () => {
    const t = makeApp({ adminToken: ADMIN })
    expect((await t.json('POST', '/api/refresh', { vendorIds: [NORTHWIND] }, t.adminHeaders)).status).toBe(400)
    await t.close()
  })
})
