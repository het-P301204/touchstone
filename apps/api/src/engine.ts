/**
 * The seam between the API and the measurement engine.
 *
 * Engine modules are imported lazily: serving published data needs none of
 * them, so the API starts (and keeps answering reads) even while an engine
 * module fails to load, and the live collector (which can make network
 * requests) is only ever imported when TOUCHSTONE_MODE=live and an admin
 * starts a live refresh. Tests inject a stub engine through createApp.
 */
import type {
  Dispute,
  HistorySeries,
  MethodologyVersion,
  RunInputs,
  RunManifest,
  RunOutput,
  RunSummary,
  VendorDetail,
  HistoricalPoint,
} from '../../../packages/core/src/model/index.ts'

export type ReportFormat = 'json' | 'markdown' | 'csv' | 'pdf'

export type ReproduceResult = { reproduced: boolean; outputsHash: string; inputsHash: string; mismatches: string[] }

/** Options passed to the live collector. Mirrors the CLI's `collect --live` flags. */
export type LiveCollectOptions = { vendorIds: string[]; registryPath: string; outDir: string }
/** The live collector returns the run inputs it assembled plus the per-source errors it recorded. */
export type LiveCollectResult = RunInputs & { errors: string[] }

export type Engine = {
  executeRun(inputs: RunInputs): RunOutput
  reproduceRun(inputs: RunInputs, expected: RunManifest): ReproduceResult
  canonicalJson(v: unknown): string
  splitForPublication(out: RunOutput, methodology: MethodologyVersion): { summary: RunSummary; vendors: Record<string, VendorDetail> }
  vendorReport(summary: RunSummary, detail: VendorDetail, disputes: Dispute[], history: HistorySeries[], format: ReportFormat): string | Uint8Array
  loadDemoInputs(opts: { root: string; datasetVersion: string; methodologyVersion: string; history: HistoricalPoint[] }): RunInputs
  methodologyVersion(version: string): MethodologyVersion
  /** Only resolved in LIVE mode. Never called in DEMO mode. */
  collectLive(opts: LiveCollectOptions): Promise<LiveCollectResult>
}

export type EngineLoader = () => Promise<Engine>

let cached: Promise<Engine> | null = null

/** Load the real engine modules once. */
export const loadEngine: EngineLoader = () => {
  cached ??= (async () => {
    const [run, split, versions, report, demo] = await Promise.all([
      import('../../../packages/core/src/run/run.ts'),
      import('../../../packages/core/src/publish/split.ts'),
      import('../../../packages/core/src/methodology/versions.ts'),
      import('../../../packages/core/src/report/vendor-report.ts'),
      import('../../../packages/collect/src/demo.ts'),
    ])
    const engine: Engine = {
      executeRun: run.executeRun,
      reproduceRun: run.reproduceRun,
      canonicalJson: run.canonicalJson,
      splitForPublication: split.splitForPublication,
      vendorReport: report.vendorReport,
      loadDemoInputs: demo.loadDemoInputs,
      methodologyVersion: versions.methodologyVersion,
      // The collector package is imported here, at call time, and nowhere else.
      collectLive: async (opts) => {
        const collect = await import('@touchstone/collect')
        return collect.collectLive(opts)
      },
    }
    return engine
  })()
  cached.catch(() => {
    cached = null
  })
  return cached
}
