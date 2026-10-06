import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { methodologyVersion } from '../../../packages/core/src/methodology/versions.ts'
import type { RunInputs, RunOutput } from '../../../packages/core/src/model/index.ts'
import { createApp } from '../src/app.ts'
import { Bundle } from '../src/bundle.ts'
import { testConfig } from '../src/config.ts'
import type { Config } from '../src/config.ts'
import type { Engine } from '../src/engine.ts'
import { Store } from '../src/store.ts'
import { OUTPUTS_HASH, INPUTS_HASH, buildRun, writeBundle, writeDemoFixtures } from './fixtures/bundle.ts'
import type { BundleOptions } from './fixtures/bundle.ts'

export const ADMIN = 'admin-token-0123456789abcdef-xyz'

const sortKeys = (v: unknown): unknown =>
  Array.isArray(v) ? v.map(sortKeys) : v && typeof v === 'object' ? Object.fromEntries(Object.entries(v).sort(([a], [b]) => (a < b ? -1 : 1)).map(([k, x]) => [k, sortKeys(x)])) : v

/**
 * A deterministic stand-in for the engine: it "computes" the hashes the
 * fixture bundle publishes, so reproduce and refresh can be tested without
 * depending on the scoring code. Calls are recorded.
 */
export function stubEngine(calls: string[] = []): Engine {
  const outputFor = (inputs: RunInputs): RunOutput => {
    const i = inputs.datasetVersion === '2026-07-06' ? 0 : 1
    const run = buildRun(i)
    return {
      manifest: { ...run.summary.manifest, outputsHash: OUTPUTS_HASH[inputs.datasetVersion]!, inputsHash: INPUTS_HASH[inputs.datasetVersion]! },
      goals: run.summary.goals,
      metricDefinitions: run.summary.metricDefinitions,
      vendors: [],
      evidence: [],
      cves: inputs.cves,
      attributions: [],
      exclusions: [],
      identityConflicts: [],
      advisories: [],
      freshness: [],
      cohort: [],
      sources: [],
      snapshots: [],
    }
  }
  return {
    executeRun: (inputs) => {
      calls.push('executeRun')
      return outputFor(inputs)
    },
    reproduceRun: (inputs, expected) => {
      calls.push('reproduceRun')
      const out = outputFor(inputs)
      const reproduced = out.manifest.outputsHash === expected.outputsHash
      return { reproduced, outputsHash: out.manifest.outputsHash, inputsHash: out.manifest.inputsHash, mismatches: reproduced ? [] : ['outputsHash'] }
    },
    canonicalJson: (v) => JSON.stringify(sortKeys(v)),
    splitForPublication: () => {
      throw new Error('not used')
    },
    vendorReport: (_summary, detail, disputes, _history, format) => {
      calls.push(`vendorReport:${format}`)
      if (format === 'pdf') return new TextEncoder().encode('%PDF-1.4 stub')
      if (format === 'json') return JSON.stringify({ vendorId: detail.vendorId, disputes: disputes.length })
      if (format === 'csv') return `vendor,disputes\n${detail.vendorId},${disputes.length}\n`
      return `# ${detail.vendorId}\n\nDisputes: ${disputes.length}\n`
    },
    loadDemoInputs: (opts) => {
      calls.push(`loadDemoInputs:${opts.datasetVersion}`)
      return buildRun(opts.datasetVersion === '2026-07-06' ? 0 : 1).inputs
    },
    methodologyVersion,
    collectLive: async (opts) => {
      calls.push(`collectLive:${opts.vendorIds.join(',')}`)
      const inputs = buildRun(1).inputs
      return {
        ...inputs,
        mode: 'LIVE',
        vendors: inputs.vendors.filter((v) => opts.vendorIds.includes(v.id)),
        snapshots: [
          { id: 'SN-live00000001', sourceId: 'cisa.signers', url: 'https://www.cisa.gov/x', fetchedAt: '2026-10-06T00:00:00Z', status: 'OK', parserVersion: '1.0.0' },
          { id: 'SN-live00000002', sourceId: 'vendor.x.vdp', url: 'https://x.example/vdp', fetchedAt: '2026-10-06T00:00:00Z', status: 'FAILED', error: 'timeout', parserVersion: '1.0.0' },
        ],
        errors: ['vendor.x.vdp: timeout'],
      }
    },
  }
}

export type TestApp = ReturnType<typeof makeApp>

export function makeApp(overrides: Partial<Config> = {}, opts: { bundle?: BundleOptions | false; engine?: Engine; corruptFixtures?: boolean } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'touchstone-api-'))
  const dataDir = join(dir, 'data')
  const fixturesDir = join(dir, 'fixtures')
  if (opts.bundle !== false) writeBundle(dataDir, opts.bundle ?? {})
  writeDemoFixtures(fixturesDir, { corrupt: opts.corruptFixtures })
  const config = testConfig({ dataDir, demoFixturesDir: fixturesDir, ...overrides })
  const store = new Store(':memory:')
  const calls: string[] = []
  const engine = opts.engine ?? stubEngine(calls)
  const bundle = opts.bundle === false ? null : Bundle.load(dataDir)
  let clock = Date.parse('2026-10-06T12:00:00Z')
  const now = () => new Date((clock += 1000)).toISOString()
  const t = createApp({ store, config, bundle, engine: async () => engine, now })
  const seeded = t.seed()
  const json = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
    t.app.request(path, {
      method,
      headers: body === undefined ? headers : { 'content-type': 'application/json', ...headers },
      body: body === undefined ? undefined : JSON.stringify(body),
    })
  const adminHeaders = { authorization: `Bearer ${ADMIN}` }
  const close = async () => {
    await t.refresh.idle()
    store.close()
    rmSync(dir, { recursive: true, force: true })
  }
  return { ...t, store, config, calls, seeded, dataDir, fixturesDir, json, adminHeaders, close }
}
