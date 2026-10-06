/**
 * The published bundle: the run data the API serves. Loaded once at start
 * (and swapped atomically after a refresh); the API never recomputes a run to
 * answer a read.
 *
 * Layout (see packages/core/src/model/publish.ts):
 *   index.json                            RunIndex
 *   runs/<runId>/summary.json             RunSummary
 *   runs/<runId>/vendors/<vendorId>.json  VendorDetail   (read on demand, cached)
 *   history.json                          HistorySeries[]
 *   inputs/<datasetVersion>.json          RunInputs      (read on demand for reproduce)
 *   disputes.json                         Dispute[]      (synthetic seeds)
 *   notebook.json                         NotebookEntry[] (synthetic seeds)
 *
 * Path safety: no request value is ever joined into a path. Run ids, vendor
 * ids and dataset versions are validated against strict patterns when the
 * bundle is loaded, and a request id is used only after it is found among
 * those loaded ids.
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { z } from 'zod'
import type {
  Attribution,
  AttributionExclusion,
  CveRecord,
  Dispute,
  HistorySeries,
  NotebookEntry,
  RunIndex,
  RunInputs,
  RunSummary,
  Severity,
  VendorDetail,
  VendorSummary,
} from '../../../packages/core/src/model/index.ts'

export class BundleError extends Error {}

export const RUN_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/
export const VENDOR_ID_RE = /^[a-z0-9][a-z0-9-]{0,99}$/
export const DATASET_VERSION_RE = /^\d{4}-\d{2}-\d{2}$/

const RunIndexSchema = z
  .object({
    mode: z.enum(['DEMO', 'LIVE']),
    latestRunId: z.string(),
    builtFrom: z.string(),
    runs: z
      .array(
        z
          .object({
            runId: z.string().regex(RUN_ID_RE),
            datasetVersion: z.string().regex(DATASET_VERSION_RE),
            asOf: z.string(),
            methodologyVersion: z.string(),
            mode: z.enum(['DEMO', 'LIVE']),
            outputsHash: z.string(),
            inputsHash: z.string(),
          })
          .loose(),
      )
      .min(1),
  })
  .loose()

const SummaryShape = z
  .object({
    manifest: z.object({ runId: z.string(), outputsHash: z.string(), datasetVersion: z.string() }).loose(),
    methodology: z.object({ version: z.string(), parameters: z.object({}).loose() }).loose(),
    goals: z.array(z.unknown()),
    vendors: z.array(z.object({ vendor: z.object({ id: z.string() }).loose() }).loose()),
  })
  .loose()

const SEVERITY_RANK: Record<Severity, number> = { CRITICAL: 5, HIGH: 4, MEDIUM: 3, LOW: 2, NONE: 1, UNKNOWN: 0 }

/** How the CNA container's own fields look under the run's methodology. Eligibility windows are NOT applied here. */
export type CnaFieldStatus = 'COMPLETE' | 'MISSING_CWE' | 'MISSING_CPE' | 'MISSING_BOTH'

export type CveRow = {
  id: string
  state: CveRecord['state']
  /**
   * The vendor(s) the engine attributed this record to. Ownership comes only
   * from the run's published attributions; the API never derives it (not from
   * the assigner, the affected-vendor strings or the CPEs).
   */
  vendorIds: string[]
  attribution: { vendorId: string; rule: Attribution['rule']; confidence: Attribution['confidence'] }[]
  /** Why the engine left the record unattributed, when it did (e.g. AMBIGUOUS_VENDOR with its candidates). */
  exclusions: { reason: AttributionExclusion['reason']; candidateVendorIds: string[] }[]
  /** The CNA that issued the record (cveMetadata.assignerShortName). Not an owner: see vendorIds. */
  assignerCna: string
  title: string | null
  datePublished: string | null
  year: number | null
  severity: Severity
  /** Which container the severity came from: the CNA's own score first, then third-party (ADP). */
  severitySource: 'CNA' | 'ADP' | null
  cnaCwes: string[]
  products: string[]
  cnaFieldStatus: CnaFieldStatus
  /** A CWE or CPE the CNA did not supply was supplied by a third party (ADP). Not credited. */
  enrichedOnly: boolean
  synthetic: boolean
}

export type CveIndex = {
  rows: CveRow[]
  byId: Map<string, { record: CveRecord; attributions: Attribution[] }>
  exclusions: AttributionExclusion[]
}

function readJson(path: string, what: string): unknown {
  let text: string
  try {
    text = readFileSync(path, 'utf8')
  } catch (e) {
    throw new BundleError(`${what}: cannot read ${path} (${(e as NodeJS.ErrnoException).code ?? 'error'}).`)
  }
  try {
    return JSON.parse(text) as unknown
  } catch {
    throw new BundleError(`${what}: ${path} is not valid JSON.`)
  }
}

function readOptionalArray<T>(path: string, what: string): T[] {
  if (!existsSync(path)) return []
  const v = readJson(path, what)
  if (!Array.isArray(v)) throw new BundleError(`${what}: ${path} must contain a JSON array.`)
  return v as T[]
}

/** Severity of a CVE row: highest CNA CVSS severity, else highest third-party, else UNKNOWN. */
export function rowSeverity(r: CveRecord): { severity: Severity; source: 'CNA' | 'ADP' | null } {
  const max = (xs: { severity: Severity }[]) => xs.reduce<Severity | null>((m, x) => (m === null || SEVERITY_RANK[x.severity] > SEVERITY_RANK[m] ? x.severity : m), null)
  const cna = max(r.cna.cvss)
  if (cna) return { severity: cna, source: 'CNA' }
  const adp = max(r.adp.flatMap((a) => a.cvss))
  if (adp) return { severity: adp, source: 'ADP' }
  return { severity: 'UNKNOWN', source: null }
}

export function cnaFieldStatus(r: CveRecord, placeholderCounts: boolean): { status: CnaFieldStatus; enrichedOnly: boolean } {
  const cweOk = (cwes: CveRecord['cna']['cwes']) => cwes.some((c) => c.id !== null && (!c.placeholder || placeholderCounts))
  const cpeOk = (cpes: CveRecord['cna']['cpes']) => cpes.some((c) => c.wellFormed)
  const cwe = cweOk(r.cna.cwes)
  const cpe = cpeOk(r.cna.cpes)
  const status: CnaFieldStatus = cwe && cpe ? 'COMPLETE' : !cwe && !cpe ? 'MISSING_BOTH' : !cwe ? 'MISSING_CWE' : 'MISSING_CPE'
  const enrichedOnly = (!cwe && r.adp.some((a) => cweOk(a.cwes))) || (!cpe && r.adp.some((a) => cpeOk(a.cpes)))
  return { status, enrichedOnly }
}

const yearOf = (r: CveRecord): number | null => {
  const d = r.datePublished ?? r.datePublic
  const fromDate = d && /^\d{4}/.test(d) ? Number(d.slice(0, 4)) : null
  if (fromDate !== null) return fromDate
  const m = /^[A-Z]+-(\d{4})-/.exec(r.id)
  return m ? Number(m[1]) : null
}

export class Bundle {
  readonly dir: string
  readonly index: RunIndex
  readonly history: HistorySeries[]
  readonly seedDisputes: Dispute[]
  readonly seedNotebook: NotebookEntry[]
  readonly loadedAt: string
  readonly warnings: string[]
  private readonly summaries: Map<string, RunSummary>
  private readonly vendorIds: Map<string, Set<string>>
  private readonly details = new Map<string, VendorDetail>()
  private readonly cveIndexes = new Map<string, CveIndex>()
  private readonly inputsCache = new Map<string, RunInputs>()

  private constructor(init: {
    dir: string
    index: RunIndex
    summaries: Map<string, RunSummary>
    vendorIds: Map<string, Set<string>>
    history: HistorySeries[]
    seedDisputes: Dispute[]
    seedNotebook: NotebookEntry[]
    warnings: string[]
  }) {
    this.dir = init.dir
    this.index = init.index
    this.summaries = init.summaries
    this.vendorIds = init.vendorIds
    this.history = init.history
    this.seedDisputes = init.seedDisputes
    this.seedNotebook = init.seedNotebook
    this.warnings = init.warnings
    this.loadedAt = new Date().toISOString()
  }

  static load(dir: string): Bundle {
    const indexPath = join(dir, 'index.json')
    if (!existsSync(indexPath)) {
      throw new BundleError(`No published data at ${dir} (index.json is missing). Run "npm run demo:build", or set TOUCHSTONE_DATA_DIR.`)
    }
    const parsed = RunIndexSchema.safeParse(readJson(indexPath, 'Run index'))
    if (!parsed.success) {
      throw new BundleError(`Run index ${indexPath} is not a valid RunIndex: ${parsed.error.issues.slice(0, 3).map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`)
    }
    const index = parsed.data as unknown as RunIndex
    if (!index.runs.some((r) => r.runId === index.latestRunId)) throw new BundleError(`Run index: latestRunId ${index.latestRunId} is not among its runs.`)
    const ids = new Set<string>()
    for (const r of index.runs) {
      if (ids.has(r.runId)) throw new BundleError(`Run index lists ${r.runId} twice.`)
      ids.add(r.runId)
    }

    const warnings: string[] = []
    const summaries = new Map<string, RunSummary>()
    const vendorIds = new Map<string, Set<string>>()
    for (const entry of index.runs) {
      const path = join(dir, 'runs', entry.runId, 'summary.json')
      const raw = readJson(path, `Run ${entry.runId} summary`)
      const shape = SummaryShape.safeParse(raw)
      if (!shape.success) throw new BundleError(`Run ${entry.runId}: summary.json is not a valid RunSummary (${shape.error.issues[0]?.path.join('.')}: ${shape.error.issues[0]?.message}).`)
      const summary = raw as RunSummary
      if (summary.manifest.runId !== entry.runId) throw new BundleError(`Run ${entry.runId}: summary.json belongs to run ${summary.manifest.runId}.`)
      if (summary.manifest.outputsHash !== entry.outputsHash) throw new BundleError(`Run ${entry.runId}: outputsHash in summary.json differs from index.json.`)
      const vids = new Set<string>()
      for (const v of summary.vendors) {
        if (VENDOR_ID_RE.test(v.vendor.id)) vids.add(v.vendor.id)
        else warnings.push(`Run ${entry.runId}: vendor id ${JSON.stringify(v.vendor.id).slice(0, 80)} is not a valid slug; its detail file is not served.`)
      }
      summaries.set(entry.runId, summary)
      vendorIds.set(entry.runId, vids)
    }
    return new Bundle({
      dir,
      index,
      summaries,
      vendorIds,
      history: readOptionalArray<HistorySeries>(join(dir, 'history.json'), 'History'),
      seedDisputes: readOptionalArray<Dispute>(join(dir, 'disputes.json'), 'Seed disputes'),
      seedNotebook: readOptionalArray<NotebookEntry>(join(dir, 'notebook.json'), 'Seed notebook'),
      warnings,
    })
  }

  get latestRunId(): string {
    return this.index.latestRunId
  }

  hasRun(runId: string): boolean {
    return this.summaries.has(runId)
  }

  /** Position of a run in publication order (index.json order), or -1. */
  runOrder(runId: string): number {
    return this.index.runs.findIndex((r) => r.runId === runId)
  }

  summary(runId: string): RunSummary | null {
    return this.summaries.get(runId) ?? null
  }

  vendorSummary(runId: string, vendorId: string): VendorSummary | null {
    return this.summaries.get(runId)?.vendors.find((v) => v.vendor.id === vendorId) ?? null
  }

  hasVendor(vendorId: string): boolean {
    for (const ids of this.vendorIds.values()) if (ids.has(vendorId)) return true
    return false
  }

  vendorDetail(runId: string, vendorId: string): VendorDetail | null {
    if (!this.vendorIds.get(runId)?.has(vendorId)) return null
    const key = `${runId}/${vendorId}`
    const cached = this.details.get(key)
    if (cached) return cached
    const path = join(this.dir, 'runs', runId, 'vendors', `${vendorId}.json`)
    if (!existsSync(path)) return null
    const detail = readJson(path, `Vendor ${vendorId} detail`) as VendorDetail
    if (detail.vendorId !== vendorId || detail.runId !== runId) throw new BundleError(`${path} does not belong to ${runId}/${vendorId}.`)
    // Bounded cache: details are a few hundred KB each at most.
    if (this.details.size >= 500) this.details.delete(this.details.keys().next().value!)
    this.details.set(key, detail)
    return detail
  }

  /** The exact inputs a run was computed from. */
  inputs(runId: string): RunInputs | null {
    const entry = this.index.runs.find((r) => r.runId === runId)
    if (!entry) return null
    const cached = this.inputsCache.get(entry.datasetVersion)
    if (cached) return cached
    const path = join(this.dir, 'inputs', `${entry.datasetVersion}.json`)
    if (!existsSync(path)) return null
    const inputs = readJson(path, `Inputs ${entry.datasetVersion}`) as RunInputs
    if (this.inputsCache.size >= 2) this.inputsCache.delete(this.inputsCache.keys().next().value!)
    this.inputsCache.set(entry.datasetVersion, inputs)
    return inputs
  }

  /** Every attributed CVE record in a run, with list-view classification. */
  cves(runId: string): CveIndex {
    const cached = this.cveIndexes.get(runId)
    if (cached) return cached
    const summary = this.summaries.get(runId)
    const index: CveIndex = { rows: [], byId: new Map(), exclusions: [] }
    if (!summary) return index
    const placeholderCounts = summary.methodology.parameters.placeholderCweCountsAsPopulated
    const seenExclusion = new Set<string>()
    for (const vendorId of this.vendorIds.get(runId) ?? []) {
      const d = this.vendorDetail(runId, vendorId)
      if (!d) continue
      for (const rec of d.cves) {
        const atts = d.attributions.filter((a) => a.cveId === rec.id)
        const prev = index.byId.get(rec.id)
        if (prev) {
          for (const a of atts) if (!prev.attributions.some((p) => p.vendorId === a.vendorId)) prev.attributions.push(a)
        } else index.byId.set(rec.id, { record: rec, attributions: [...atts] })
      }
      for (const x of d.exclusions) {
        const k = `${x.cveId}|${x.reason}`
        if (seenExclusion.has(k)) continue
        seenExclusion.add(k)
        index.exclusions.push(x)
      }
    }
    for (const { record: r, attributions } of index.byId.values()) {
      const excl = index.exclusions.filter((x) => x.cveId === r.id)
      const sev = rowSeverity(r)
      const f = cnaFieldStatus(r, placeholderCounts)
      index.rows.push({
        id: r.id,
        state: r.state,
        vendorIds: [...new Set(attributions.map((a) => a.vendorId))].sort(),
        attribution: attributions.map((a) => ({ vendorId: a.vendorId, rule: a.rule, confidence: a.confidence })),
        exclusions: excl.map((x) => ({ reason: x.reason, candidateVendorIds: [...x.candidateVendorIds] })),
        assignerCna: r.assigner.shortName,
        title: r.title ?? null,
        datePublished: r.datePublished ?? null,
        year: yearOf(r),
        severity: sev.severity,
        severitySource: sev.source,
        cnaCwes: r.cna.cwes.map((c) => c.id ?? c.raw),
        products: [...new Set(r.affected.map((a) => a.product))],
        cnaFieldStatus: f.status,
        enrichedOnly: f.enrichedOnly,
        synthetic: r.synthetic,
      })
    }
    index.rows.sort((a, b) => (b.datePublished ?? '').localeCompare(a.datePublished ?? '') || a.id.localeCompare(b.id))
    this.cveIndexes.set(runId, index)
    return index
  }
}
