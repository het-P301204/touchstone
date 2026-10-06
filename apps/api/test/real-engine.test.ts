/**
 * End to end with the real engine: a bundle produced by executeRun and
 * splitForPublication (not hand-written), served by the API, reproduced and
 * reported through the real modules. Also exercises the published demo
 * bundle when it has been built.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { afterAll, describe, expect, it } from 'vitest'
import type { RunIndex } from '../../../packages/core/src/model/index.ts'
import { createApp } from '../src/app.ts'
import { Bundle } from '../src/bundle.ts'
import { REPO_ROOT, testConfig } from '../src/config.ts'
import { loadEngine } from '../src/engine.ts'
import { Store } from '../src/store.ts'
import { buildRun } from './fixtures/bundle.ts'

type Json = Record<string, any>

const ENGINE_READY = ['packages/core/src/run/run.ts', 'packages/core/src/publish/split.ts', 'packages/core/src/report/vendor-report.ts', 'packages/collect/src/demo.ts'].every((p) =>
  existsSync(resolve(REPO_ROOT, p)),
)
const PUBLISHED = resolve(REPO_ROOT, 'apps', 'web', 'public', 'data')

describe.skipIf(!ENGINE_READY)('real engine over an engine-built bundle', () => {
  const dir = mkdtempSync(join(tmpdir(), 'touchstone-real-'))
  afterAll(() => rmSync(dir, { recursive: true, force: true }))

  const build = async () => {
    const engine = await loadEngine()
    const inputs = buildRun(1).inputs
    const out = engine.executeRun(inputs)
    const { summary, vendors } = engine.splitForPublication(out, engine.methodologyVersion(inputs.methodologyVersion))
    const m = out.manifest
    mkdirSync(join(dir, 'runs', m.runId, 'vendors'), { recursive: true })
    mkdirSync(join(dir, 'inputs'), { recursive: true })
    writeFileSync(join(dir, 'runs', m.runId, 'summary.json'), JSON.stringify(summary))
    for (const [id, d] of Object.entries(vendors)) writeFileSync(join(dir, 'runs', m.runId, 'vendors', `${id}.json`), JSON.stringify(d))
    writeFileSync(join(dir, 'inputs', `${m.datasetVersion}.json`), JSON.stringify(inputs))
    const index: RunIndex = {
      mode: 'DEMO',
      latestRunId: m.runId,
      builtFrom: 'real-engine test',
      runs: [{ runId: m.runId, datasetVersion: m.datasetVersion, asOf: m.asOf, methodologyVersion: m.methodologyVersion, mode: 'DEMO', outputsHash: m.outputsHash, inputsHash: m.inputsHash }],
    }
    writeFileSync(join(dir, 'index.json'), JSON.stringify(index))
    const store = new Store(':memory:')
    const t = createApp({ store, config: testConfig({ dataDir: dir }), bundle: Bundle.load(dir) })
    return { ...t, store, runId: m.runId, vendorIds: Object.keys(vendors) }
  }

  it('serves, reproduces and reports a real run', async () => {
    const t = await build()
    const sig = (await (await t.app.request('/api/signatories')).json()) as Json
    expect(sig.total).toBe(t.vendorIds.length)
    const rep = await t.app.request(`/api/runs/${t.runId}/reproduce`, { method: 'POST' })
    const body = (await rep.json()) as Json
    expect(body.mismatches).toEqual([])
    expect(body.reproduced).toBe(true)
    const vendorId = t.vendorIds[0]!
    for (const format of ['json', 'markdown', 'csv', 'pdf']) {
      const r = await t.app.request(`/api/reports/${vendorId}?format=${format}`)
      expect(r.status, format).toBe(200)
      const bytes = new Uint8Array(await r.arrayBuffer())
      expect(bytes.length).toBeGreaterThan(20)
      if (format === 'pdf') expect(new TextDecoder().decode(bytes.subarray(0, 5))).toBe('%PDF-')
    }
    const goals = (await (await t.app.request(`/api/vendors/${vendorId}/goals`)).json()) as Json
    expect(goals.goals).toHaveLength(7)
    t.store.close()
  })
})

describe.skipIf(!ENGINE_READY || !existsSync(join(PUBLISHED, 'index.json')))('the published demo bundle', () => {
  it('loads, serves every list endpoint and reproduces the latest run', async () => {
    const store = new Store(':memory:')
    const t = createApp({ store, config: testConfig({ dataDir: PUBLISHED }), bundle: Bundle.load(PUBLISHED) })
    const seeded = t.seed()
    expect(seeded.disputes.skipped.filter((s) => s.reason !== 'already present')).toEqual([])
    const index = JSON.parse(readFileSync(join(PUBLISHED, 'index.json'), 'utf8')) as RunIndex
    for (const p of ['/api/health', '/api/runs', '/api/signatories', '/api/cves', '/api/goals', '/api/methodology', '/api/freshness', '/api/disputes', '/api/notebook']) {
      expect((await t.app.request(p)).status, p).toBe(200)
    }
    const r = (await (await t.app.request(`/api/runs/${index.latestRunId}/reproduce`, { method: 'POST' })).json()) as Json
    expect(r.mismatches).toEqual([])
    expect(r.reproduced).toBe(true)
    store.close()
  })
})
