/**
 * Refresh jobs. One at a time; every job and every stage outcome is recorded
 * in the store, failures included.
 *
 * DEMO mode replays the bundled demo snapshot through the real pipeline, stage
 * by stage, and makes no network calls:
 *   FETCH      read the snapshot files listed in fixtures/demo/<version>/manifest.json and verify each sha256
 *   NORMALIZE  loadDemoInputs: the raw files through the real normalizers
 *   VALIDATE   compare the inputs with the published inputs for that dataset
 *   SCORE      executeRun
 *   PUBLISH    compare outputsHash with the published run; the published bundle is never overwritten
 *
 * LIVE mode (TOUCHSTONE_MODE=live, never the default) hands FETCH to the live
 * collector, which writes snapshots under TOUCHSTONE_LIVE_OUT. Live snapshots
 * are not published by the API: a LIVE run is built and reviewed offline.
 */
import { createHash, randomBytes } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { isAbsolute, join, relative, resolve } from 'node:path'
import type { RunInputs } from '../../../packages/core/src/model/index.ts'
import type { Bundle } from './bundle.ts'
import { BundleError } from './bundle.ts'
import type { Config } from './config.ts'
import type { Engine, EngineLoader } from './engine.ts'
import { HttpError } from './security.ts'
import type { Log } from './security.ts'
import type { RefreshJob, RefreshStage, RefreshStageName, Store } from './store.ts'

export const JOB_ID_RE = /^rf_[0-9a-f]{24}$/

const STAGES: RefreshStageName[] = ['FETCH', 'NORMALIZE', 'VALIDATE', 'SCORE', 'PUBLISH']

export const DEMO_STATEMENT =
  'Replays the bundled demo snapshot (fixtures/demo) through the pipeline: fetch from fixture files, normalize, validate, score, publish check. It makes no network calls and does not modify the published bundle.'
export const LIVE_STATEMENT =
  'Collects public sources for the vendors in the configured registry through the SSRF-safe fetcher and stores content-addressed snapshots. The published bundle is not modified; a LIVE run is built and reviewed offline.'

type Deps = {
  store: Store
  config: Config
  engine: EngineLoader
  bundle: () => Bundle | null
  log: Log
  now?: () => string
}

/** Yield to the event loop so status polls are answered between stages. */
const tick = () => new Promise<void>((r) => setImmediate(r))

export class RefreshRunner {
  private readonly deps: Deps
  private running: string | null = null
  private finished: Promise<void> = Promise.resolve()

  constructor(deps: Deps) {
    this.deps = deps
  }

  private now(): string {
    return this.deps.now ? this.deps.now() : new Date().toISOString()
  }

  get currentJobId(): string | null {
    return this.running
  }

  /** Resolves when the current job (if any) has finished. For tests and shutdown. */
  idle(): Promise<void> {
    return this.finished
  }

  start(opts: { datasetVersion?: string; vendorIds?: string[] }): RefreshJob {
    if (this.running) throw new HttpError(409, 'REFRESH_IN_PROGRESS', 'A refresh is already running. One job runs at a time.', { jobId: this.running })
    const live = this.deps.config.mode === 'live'
    const bundle = this.deps.bundle()
    let datasetVersion: string | null = null
    if (live && opts.datasetVersion) throw new HttpError(400, 'VALIDATION_FAILED', 'datasetVersion applies to DEMO refreshes only.')
    if (!live && opts.vendorIds?.length) throw new HttpError(400, 'VALIDATION_FAILED', 'vendorIds applies to LIVE refreshes only.')
    if (!live) {
      if (!bundle) throw new HttpError(503, 'DATA_NOT_PUBLISHED', 'No published bundle is loaded, so there is no demo dataset to replay.')
      datasetVersion = opts.datasetVersion ?? bundle.index.runs.find((r) => r.runId === bundle.latestRunId)!.datasetVersion
      if (!bundle.index.runs.some((r) => r.datasetVersion === datasetVersion)) {
        throw new HttpError(404, 'DATASET_NOT_FOUND', `No published run for dataset ${datasetVersion}.`, { available: bundle.index.runs.map((r) => r.datasetVersion) })
      }
    }
    const job: RefreshJob = {
      id: `rf_${randomBytes(12).toString('hex')}`,
      mode: live ? 'LIVE' : 'DEMO',
      status: 'QUEUED',
      datasetVersion,
      requestedAt: this.now(),
      startedAt: null,
      finishedAt: null,
      statement: live ? LIVE_STATEMENT : DEMO_STATEMENT,
      stages: STAGES.map((stage) => ({ stage, status: 'PENDING', detail: '' })),
      result: null,
      error: null,
    }
    this.deps.store.saveJob(job)
    this.running = job.id
    this.finished = (async () => {
      await tick()
      try {
        if (live) await this.runLive(job, opts.vendorIds)
        else await this.runDemo(job, bundle!)
      } catch (e) {
        // runDemo/runLive record their own stage failures; this is the backstop.
        job.status = 'FAILED'
        job.error ??= e instanceof Error ? e.message : String(e)
        job.finishedAt = this.now()
        this.deps.store.saveJob(job)
        this.deps.log('error', { operation: 'refresh', jobId: job.id, error: job.error })
      } finally {
        this.running = null
      }
    })()
    return job
  }

  private async stage<T>(job: RefreshJob, name: RefreshStageName, fn: (set: (detail: string, status?: RefreshStage['status']) => void) => Promise<T> | T): Promise<T> {
    const s = job.stages.find((x) => x.stage === name)!
    s.status = 'RUNNING'
    s.startedAt = this.now()
    this.deps.store.saveJob(job)
    await tick()
    let outcome: RefreshStage['status'] = 'OK'
    const set = (detail: string, status?: RefreshStage['status']) => {
      s.detail = detail
      if (status) outcome = status
    }
    try {
      const out = await fn(set)
      s.status = outcome
      s.finishedAt = this.now()
      this.deps.store.saveJob(job)
      return out
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e)
      s.status = 'FAILED'
      s.detail = s.detail ? `${s.detail} ${message}` : message
      s.finishedAt = this.now()
      for (const later of job.stages) if (later.status === 'PENDING') later.status = 'SKIPPED'
      job.status = 'FAILED'
      job.error = `${name} failed: ${message}`
      job.finishedAt = this.now()
      this.deps.store.saveJob(job)
      throw e
    }
  }

  private async runDemo(job: RefreshJob, bundle: Bundle): Promise<void> {
    job.status = 'RUNNING'
    job.startedAt = this.now()
    this.deps.store.saveJob(job)
    const version = job.datasetVersion!
    const entry = bundle.index.runs.find((r) => r.datasetVersion === version)!
    const published = bundle.inputs(entry.runId)
    let engine: Engine | undefined

    await this.stage(job, 'FETCH', (set) => {
      const r = readFixtureSnapshots(this.deps.config.demoFixturesDir, version)
      set(
        `Read ${r.files} snapshot file(s) for dataset ${version} from the bundled fixtures; every sha256 matched. ` +
          `${r.failed} source(s) are recorded in the snapshot manifest as FAILED, as they were at collection time. No network calls were made.`,
      )
    })

    const inputs: RunInputs = await this.stage(job, 'NORMALIZE', async (set) => {
      engine = await this.deps.engine()
      const history = published?.history ?? []
      const inputs = engine.loadDemoInputs({ root: this.deps.config.demoFixturesDir, datasetVersion: version, methodologyVersion: entry.methodologyVersion, history })
      set(
        `Normalized ${inputs.vendors.length} vendors, ${inputs.cves.length} CVE records, ${inputs.advisories.length} advisories and ${inputs.vdp.length} VDP observations ` +
          `with the real parsers (methodology ${entry.methodologyVersion}; history from ${history.length} earlier vendor-run points).`,
      )
      return inputs
    })

    await this.stage(job, 'VALIDATE', (set) => {
      if (inputs.mode !== 'DEMO') throw new Error(`Replayed inputs are ${inputs.mode}, expected DEMO.`)
      if (!published) {
        set(`No published inputs for ${version} to compare against.`, 'WARN')
        return
      }
      const same = engine!.canonicalJson(inputs) === engine!.canonicalJson(published)
      if (same) set(`Inputs are identical to the published inputs for ${version}.`)
      else set(`Inputs differ from the published inputs for ${version}: the fixtures or the normalizers changed since the bundle was built.`, 'WARN')
    })

    const out = await this.stage(job, 'SCORE', (set) => {
      const out = engine!.executeRun(inputs)
      const failedChecks = out.manifest.qualityChecks.filter((q) => !q.passed)
      set(
        `Run ${out.manifest.runId}: ${out.vendors.length} vendors scored, ${out.evidence.length} evidence items, ` +
          `${out.manifest.qualityChecks.length - failedChecks.length}/${out.manifest.qualityChecks.length} quality checks passed. outputsHash ${out.manifest.outputsHash.slice(0, 16)}.`,
        failedChecks.length ? 'WARN' : 'OK',
      )
      return out
    })

    await this.stage(job, 'PUBLISH', (set) => {
      const matches = out.manifest.outputsHash === entry.outputsHash
      if (matches) set(`Output is identical to published run ${entry.runId} (same outputsHash). The published bundle is unchanged.`)
      else
        set(
          `Output differs from published run ${entry.runId} (published ${entry.outputsHash.slice(0, 16)}, replay ${out.manifest.outputsHash.slice(0, 16)}). ` +
            'The API does not overwrite published data; rebuild the bundle with npm run demo:build after review.',
          'WARN',
        )
      job.result = {
        runId: out.manifest.runId,
        datasetVersion: version,
        methodologyVersion: out.manifest.methodologyVersion,
        outputsHash: out.manifest.outputsHash,
        inputsHash: out.manifest.inputsHash,
        publishedRunId: entry.runId,
        publishedOutputsHash: entry.outputsHash,
        matchesPublished: matches,
        networkCalls: 0,
      }
    })

    job.status = 'DONE'
    job.finishedAt = this.now()
    this.deps.store.saveJob(job)
  }

  private async runLive(job: RefreshJob, vendorIds?: string[]): Promise<void> {
    job.status = 'RUNNING'
    job.startedAt = this.now()
    this.deps.store.saveJob(job)
    const { config } = this.deps
    let engine: Engine | undefined
    const collected = await this.stage(job, 'FETCH', async (set) => {
      const registryPath = config.liveRegistry!
      const registry = JSON.parse(readFileSync(registryPath, 'utf8')) as unknown
      if (!Array.isArray(registry)) throw new Error('The live registry must be a JSON array of vendors.')
      const all = registry.map((v) => (v && typeof v === 'object' ? String((v as { id?: unknown }).id ?? '') : '')).filter(Boolean)
      const ids = vendorIds?.length ? vendorIds : all
      const unknown = ids.filter((id) => !all.includes(id))
      if (unknown.length) throw new Error(`Not in the live registry: ${unknown.slice(0, 5).join(', ')}.`)
      engine = await this.deps.engine()
      const result = await engine.collectLive({ vendorIds: ids, registryPath, outDir: config.liveOutDir })
      const failed = result.snapshots.filter((s) => s.status !== 'OK').length
      set(
        `Collected ${result.snapshots.length} snapshot(s) for ${ids.length} vendor(s) from public sources through the SSRF-safe fetcher; ${failed} not OK. ` +
          `Snapshots stored under ${config.liveOutDir}.`,
        failed ? 'WARN' : 'OK',
      )
      return result
    })
    const { errors, ...inputs } = collected
    await this.stage(job, 'NORMALIZE', (set) => {
      set(`Normalized during collection: ${inputs.cves.length} CVE records, ${inputs.advisories.length} advisories, ${inputs.vdp.length} VDP observations.`)
    })
    await this.stage(job, 'VALIDATE', (set) => {
      if (inputs.mode !== 'LIVE') throw new Error(`Collected inputs are ${inputs.mode}, expected LIVE.`)
      if (errors.length) set(`${errors.length} collection error(s) recorded, e.g. ${errors.slice(0, 3).join(' | ').slice(0, 400)}`, 'WARN')
      else set('No collection errors recorded.')
    })
    const out = await this.stage(job, 'SCORE', (set) => {
      const out = engine!.executeRun(inputs)
      const failedChecks = out.manifest.qualityChecks.filter((q) => !q.passed).length
      set(`Run ${out.manifest.runId}: ${out.vendors.length} vendors scored. outputsHash ${out.manifest.outputsHash.slice(0, 16)}.`, failedChecks ? 'WARN' : 'OK')
      return out
    })
    await this.stage(job, 'PUBLISH', (set) => {
      const dir = join(config.liveOutDir, 'runs', out.manifest.runId)
      mkdirSync(dir, { recursive: true })
      writeFileSync(join(dir, 'manifest.json'), JSON.stringify(out.manifest, null, 2) + '\n')
      writeFileSync(join(dir, 'inputs.json'), JSON.stringify(inputs) + '\n')
      set(`Held for review, not published to the served bundle. Manifest and inputs written to ${dir}.`, 'SKIPPED')
      job.result = { runId: out.manifest.runId, outputsHash: out.manifest.outputsHash, inputsHash: out.manifest.inputsHash, published: false, collectionErrors: errors.length }
    })
    job.status = 'DONE'
    job.finishedAt = this.now()
    this.deps.store.saveJob(job)
  }
}

/**
 * The FETCH stage of a DEMO replay: read every snapshot file the dataset's
 * manifest lists, from disk only, and verify its sha256. Paths in the
 * manifest are relative to the demo fixtures root and must stay inside it.
 */
export function readFixtureSnapshots(fixturesRoot: string, datasetVersion: string): { files: number; failed: number } {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(datasetVersion)) throw new Error(`Invalid dataset version ${datasetVersion}.`)
  const root = resolve(fixturesRoot)
  const versionDir = join(root, datasetVersion)
  const manifestPath = join(versionDir, 'manifest.json')
  if (!existsSync(manifestPath)) throw new BundleError(`The demo fixtures for ${datasetVersion} are missing (${manifestPath}).`)
  const raw = JSON.parse(readFileSync(manifestPath, 'utf8')) as unknown
  const list = Array.isArray(raw) ? raw : raw && typeof raw === 'object' && Array.isArray((raw as { snapshots?: unknown }).snapshots) ? (raw as { snapshots: unknown[] }).snapshots : null
  if (!list) throw new Error('The snapshot manifest has no snapshot list.')
  let files = 0
  let failed = 0
  for (const item of list) {
    if (!item || typeof item !== 'object') throw new Error('The snapshot manifest contains a non-object entry.')
    const s = item as { status?: unknown; file?: unknown; sha256?: unknown; sourceId?: unknown }
    if (s.status !== 'OK') {
      failed++
      continue
    }
    if (typeof s.file !== 'string' || typeof s.sha256 !== 'string') continue
    // Paths are relative to the fixtures root (records shared across versions live in fixtures/demo/records).
    const target = resolve(root, s.file)
    const rel = relative(root, target)
    if (rel.startsWith('..') || isAbsolute(rel)) throw new Error(`Snapshot path ${JSON.stringify(s.file).slice(0, 120)} escapes the fixtures directory.`)
    const bytes = readFileSync(target)
    const digest = createHash('sha256').update(bytes).digest('hex')
    if (digest !== s.sha256.toLowerCase()) throw new Error(`sha256 mismatch for ${s.file}: the fixture file changed after its manifest was written.`)
    files++
  }
  return { files, failed }
}

/** The shape the web app reads from GET /api/refresh/:jobId. */
export function jobView(job: RefreshJob): Record<string, unknown> {
  const result = job.result as { runId?: string } | null
  return {
    jobId: job.id,
    mode: job.mode,
    status: job.status,
    datasetVersion: job.datasetVersion,
    statement: job.statement,
    networkCalls: job.mode === 'DEMO' ? 0 : null,
    requestedAt: job.requestedAt,
    startedAt: job.startedAt,
    finishedAt: job.finishedAt,
    stages: job.stages,
    ...(result?.runId ? { runId: result.runId } : {}),
    result: job.result,
    ...(job.error ? { error: job.error } : {}),
  }
}
