/**
 * TOUCHSTONE REST API.
 *
 * Serves published run data (loaded once from the bundle, never recomputed per
 * request), the dispute workflow (SQLite, append-only history), the research
 * notebook, reproducibility checks and refresh jobs.
 *
 * Errors always use one envelope: { error: { code, message, details? } }.
 * No stack trace ever leaves the process.
 */
import { Hono } from 'hono'
import type { Context } from 'hono'
import { z } from 'zod'
import { GOALS, PLEDGE_SOURCE_URL } from '../../../packages/core/src/methodology/goals.ts'
import { CURRENT_METHODOLOGY_VERSION, METHODOLOGY_VERSIONS } from '../../../packages/core/src/methodology/versions.ts'
import { DISPUTE_TRANSITIONS } from '../../../packages/core/src/model/run.ts'
import { cleanText } from '../../../packages/core/src/util/sanitize.ts'
import type { Dispute, DisputeStatus, RunSummary, VendorDetail } from '../../../packages/core/src/model/index.ts'
import { Bundle, BundleError, RUN_ID_RE, VENDOR_ID_RE } from './bundle.ts'
import { API_VERSION } from './config.ts'
import type { Config } from './config.ts'
import { loadEngine } from './engine.ts'
import type { Engine, EngineLoader, ReportFormat } from './engine.ts'
import { ACTIVE_DISPUTE, SIGNATORY_SORTS, VENDOR_CATEGORIES, disputedGoalIds, queryCves, querySignatories } from './queries.ts'
import { JOB_ID_RE, RefreshRunner, jobView } from './refresh.ts'
import { HttpError, adminAuth, cors, hostCheck, logger, rateLimit, requestContext, secureHeaders, streamingBodyLimit } from './security.ts'
import type { Env, Log } from './security.ts'
import { serveStatic } from './static.ts'
import { StoreConflict } from './store.ts'
import type { Store } from './store.ts'

export type AppDeps = {
  store: Store
  config: Config
  /** The published bundle; null when none is available (reads answer 503). */
  bundle: Bundle | null
  /** Engine loader; tests inject a stub. */
  engine?: EngineLoader
  log?: Log
  startedAt?: number
  /** Clock for timestamps written by the API (dispute events, jobs). */
  now?: () => string
}

export type TouchstoneApp = {
  app: Hono<Env>
  refresh: RefreshRunner
  /** Replace the served bundle (after an operator rebuilds it). */
  setBundle(b: Bundle | null): void
  /** Seed synthetic disputes and notebook entries from the bundle, once. */
  seed(): { disputes: { inserted: string[]; skipped: { id: string; reason: string }[] }; notebook: number }
}

const DISPUTE_STATUSES = ['OPEN', 'UNDER_REVIEW', 'CONFIRMED', 'CORRECTED', 'DISMISSED'] as const
const DISPUTE_REASONS = [
  'INCORRECT_PRODUCT_MAPPING',
  'INCORRECT_VENDOR_ATTRIBUTION',
  'INCORRECT_CVE_MAPPING',
  'OUTDATED_SOURCE',
  'MISSING_SOURCE',
  'METHODOLOGY_ERROR',
] as const
const TARGET_KINDS = ['GOAL', 'METRIC', 'EVIDENCE', 'CVE', 'IDENTITY'] as const
const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NONE', 'UNKNOWN'] as const
const COMPLETENESS = ['COMPLETE', 'MISSING_CWE', 'MISSING_CPE', 'MISSING_BOTH', 'ENRICHED_ONLY'] as const
const REPORT_FORMATS: Record<string, ReportFormat> = { json: 'json', markdown: 'markdown', md: 'markdown', csv: 'csv', pdf: 'pdf' }
export const CVE_ID_RE = /^(CVE|DEMO)-\d{4}-\d{4,19}$/
const DISPUTE_ID_RE = /^DSP-\d{1,9}$/

export const MAX_STATEMENT_CHARS = 2000
export const MAX_EVIDENCE_URLS = 5
export const MAX_URL_CHARS = 500

/** Remove invisible/bidi characters and every control character except LF and TAB. */
export function sanitizeText(s: string): string {
  let out = ''
  for (const ch of cleanText(s.replace(/\r\n?/g, '\n'))) {
    const cp = ch.codePointAt(0)!
    if ((cp < 0x20 && cp !== 0x0a && cp !== 0x09) || (cp >= 0x7f && cp <= 0x9f)) continue
    out += ch
  }
  return out.trim()
}

const cleaned = (min: number, max: number) =>
  z
    .string()
    .max(max * 4)
    .transform(sanitizeText)
    .pipe(z.string().min(min, `must be at least ${min} character(s)`).max(max, `must be at most ${max} characters`))

/** A single-line label: sanitized, then any remaining whitespace run collapsed to one space. */
const label = (min: number, max: number) =>
  z
    .string()
    .max(max * 4)
    .transform((s) => sanitizeText(s).replace(/\s+/g, ' '))
    .pipe(z.string().min(min).max(max))

/**
 * An evidence URL supplied with a dispute. It must be an absolute https URL
 * without credentials. It is stored and shown; the server never fetches it.
 */
export const evidenceUrl = z
  .string()
  .max(MAX_URL_CHARS * 2)
  .transform((s) => cleanText(s).trim())
  .transform((s, ctx) => {
    let u: URL
    try {
      u = new URL(s)
    } catch {
      ctx.addIssue({ code: 'custom', message: 'must be an absolute https:// URL' })
      return z.NEVER
    }
    if (u.protocol !== 'https:') ctx.addIssue({ code: 'custom', message: 'must use https://' })
    else if (u.username || u.password) ctx.addIssue({ code: 'custom', message: 'must not contain credentials' })
    else if (!u.hostname || /\s/.test(s)) ctx.addIssue({ code: 'custom', message: 'must be an absolute https:// URL' })
    else if (u.href.length > MAX_URL_CHARS) ctx.addIssue({ code: 'custom', message: `must be at most ${MAX_URL_CHARS} characters` })
    else return u.href
    return z.NEVER
  })

const CreateDispute = z.strictObject({
  vendorId: z.string().regex(VENDOR_ID_RE, 'must be a vendor id'),
  runId: z.string().regex(RUN_ID_RE, 'must be a run id').optional(),
  target: z.strictObject({ kind: z.enum(TARGET_KINDS), id: label(1, 200) }),
  reason: z.enum(DISPUTE_REASONS),
  submitterRole: z.enum(['VENDOR', 'RESEARCHER', 'OTHER']),
  statement: cleaned(1, MAX_STATEMENT_CHARS),
  evidenceUrls: z.array(evidenceUrl).max(MAX_EVIDENCE_URLS).default([]),
})

const TransitionDispute = z.strictObject({
  to: z.enum(DISPUTE_STATUSES),
  note: cleaned(1, MAX_STATEMENT_CHARS),
  actor: label(1, 80).optional(),
  correctedInRunId: z.string().regex(RUN_ID_RE).optional(),
})

const CreateNotebookEntry = z.strictObject({
  title: label(1, 200),
  observation: cleaned(1, 4000),
  resolution: cleaned(1, 4000).optional(),
  vendorId: z.string().regex(VENDOR_ID_RE).optional(),
  tags: z.array(z.string().regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'tags are lower-case words joined by hyphens')).max(10).default([]),
})

const StartRefresh = z.strictObject({
  datasetVersion: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  /** LIVE mode only: collect these registry vendors (default: every vendor in the registry). */
  vendorIds: z.array(z.string().regex(VENDOR_ID_RE)).max(500).optional(),
})

const csv = <T extends string>(values: readonly T[], upper = true) =>
  z
    .string()
    .max(500)
    .transform((s) =>
      s
        .split(',')
        .map((x) => (upper ? x.trim().toUpperCase() : x.trim()))
        .filter(Boolean),
    )
    .pipe(z.array(z.enum(values as unknown as [T, ...T[]])).max(20))
    .optional()

const pageQuery = (maxLimit: number, defaultLimit: number) => ({
  limit: z.coerce.number().int().min(1).max(maxLimit).default(defaultLimit),
  offset: z.coerce.number().int().min(0).max(1_000_000).default(0),
})

const SignatoryQuery = z.object({
  run: z.string().regex(RUN_ID_RE).optional(),
  category: csv(VENDOR_CATEGORIES),
  status: csv(['LISTED', 'NOT_LISTED', 'UNKNOWN'] as const),
  coverageMin: z.coerce.number().min(0).max(100).optional(),
  coverageMax: z.coerce.number().min(0).max(100).optional(),
  q: z.string().max(200).optional(),
  search: z.string().max(200).optional(),
  synthetic: z.enum(['true', 'false']).optional(),
  sort: z.enum(SIGNATORY_SORTS).default('name'),
  order: z.enum(['asc', 'desc']).optional(),
  ...pageQuery(500, 100),
})

const CveQuery = z.object({
  run: z.string().regex(RUN_ID_RE).optional(),
  vendor: z.string().regex(VENDOR_ID_RE).optional(),
  year: z.coerce.number().int().min(1999).max(2100).optional(),
  severity: csv(SEVERITIES),
  cwe: z
    .string()
    .max(40)
    .regex(/^[A-Za-z0-9-]+$/)
    .optional(),
  product: z.string().max(200).optional(),
  completeness: csv(COMPLETENESS),
  ...pageQuery(500, 100),
})

export function safeFileName(s: string): string {
  const out = s.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^[._]+/, '').slice(0, 120)
  return out || 'report'
}

export function createApp(deps: AppDeps): TouchstoneApp {
  const { store, config } = deps
  const log = deps.log ?? logger(config.logLevel)
  const startedAt = deps.startedAt ?? Date.now()
  const now = deps.now ?? (() => new Date().toISOString())
  const engineLoader: EngineLoader = deps.engine ?? loadEngine
  let bundle = deps.bundle
  const app = new Hono<Env>()

  const refresh = new RefreshRunner({ store, config, engine: engineLoader, bundle: () => bundle, log, now })

  app.use('*', requestContext(log))
  app.use('*', secureHeaders(config))
  app.use('*', hostCheck(config))
  app.use('/api/*', cors(config))
  app.use('/api/*', rateLimit('api', config.rateLimitPerMinute, 60_000, config.trustProxy))
  // Body cap: a declared Content-Length over the cap is refused here, before
  // any handler runs; a chunked body is cut off at the first chunk past it.
  app.use('/api/*', streamingBodyLimit(config.maxBodyBytes))
  // JSON only: a POST that declares a body must declare it as application/json.
  // Checked before anything is read, so a form or text body is never buffered.
  app.use('/api/*', async (c, next) => {
    if (c.req.method === 'POST' && declaresBody(c)) requireJson(c)
    await next()
  })

  const admin = adminAuth(config)
  const disputeLimiter = rateLimit('disputes', config.disputeRateLimitPerHour, 3_600_000, config.trustProxy)
  const reproduceLimiter = rateLimit('reproduce', config.reproduceRateLimitPerHour, 3_600_000, config.trustProxy)

  app.onError((err, c) => {
    if (err instanceof HttpError) {
      const body: { error: { code: string; message: string; details?: unknown } } = { error: { code: err.code, message: err.message } }
      if (err.details !== undefined) body.error.details = err.details
      return c.json(body, err.status as 400)
    }
    if (err instanceof z.ZodError) {
      return c.json(
        {
          error: {
            code: 'VALIDATION_FAILED',
            message: 'The request did not match the expected shape.',
            details: err.issues.slice(0, 20).map((i) => ({ path: i.path.join('.'), message: i.message })),
          },
        },
        400,
      )
    }
    log('error', {
      requestId: c.get('requestId'),
      route: c.req.routePath,
      error: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack?.split('\n').slice(0, 6).join(' | ') : undefined,
    })
    return c.json({ error: { code: 'INTERNAL', message: 'TOUCHSTONE could not complete the request. The error has been logged.', details: { requestId: c.get('requestId') } } }, 500)
  })

  /* ---------------------------------------------------------------- helpers */

  const data = (): Bundle => {
    if (!bundle) throw new HttpError(503, 'DATA_NOT_PUBLISHED', 'No published run data is loaded. Build it with npm run demo:build, or set TOUCHSTONE_DATA_DIR.')
    return bundle
  }

  const runOf = (c: Context<Env>, explicit?: string): { b: Bundle; runId: string; summary: RunSummary } => {
    const b = data()
    const requested = explicit ?? c.req.query('run')
    const runId = requested === undefined || requested === '' || requested === 'latest' ? b.latestRunId : requested
    const summary = RUN_ID_RE.test(runId) ? b.summary(runId) : null
    if (!summary) throw new HttpError(404, 'RUN_NOT_FOUND', 'No published run with that id.', { runId: runId.slice(0, 80) })
    return { b, runId, summary }
  }

  const vendorIn = (c: Context<Env>) => {
    const vendorId = c.req.param('id') ?? c.req.param('vendorId') ?? ''
    const r = runOf(c)
    const v = VENDOR_ID_RE.test(vendorId) ? r.summary.vendors.find((x) => x.vendor.id === vendorId) : undefined
    if (!v) {
      const known = VENDOR_ID_RE.test(vendorId) && r.b.hasVendor(vendorId)
      throw new HttpError(404, 'VENDOR_NOT_FOUND', known ? `Vendor ${vendorId} is not part of run ${r.runId}.` : 'No vendor with that id.')
    }
    return { ...r, vendorId, vendor: v }
  }

  const detailOf = (b: Bundle, runId: string, vendorId: string): VendorDetail => {
    const d = b.vendorDetail(runId, vendorId)
    if (!d) throw new HttpError(404, 'EVIDENCE_NOT_PUBLISHED', `No published evidence file for ${vendorId} in run ${runId}.`)
    return d
  }

  /** Reject a POST body that is not declared as JSON, before reading it. */
  const requireJson = (c: Context<Env>) => {
    const type = (c.req.header('content-type') ?? '').split(';')[0]!.trim().toLowerCase()
    if (type !== 'application/json') throw new HttpError(415, 'UNSUPPORTED_MEDIA_TYPE', 'Send the request body as application/json.')
  }

  /** True when the request declares a body (Content-Length > 0 or chunked). */
  const declaresBody = (c: Context<Env>) => {
    const cl = c.req.header('content-length')
    return c.req.header('transfer-encoding') !== undefined || (cl !== undefined && cl.trim() !== '0')
  }

  /**
   * Read and validate a JSON body. The content type is checked before any byte
   * is read; the size cap is enforced while reading (streamingBodyLimit). An
   * optional body may be absent or empty, but a body that is present must be JSON.
   */
  const jsonBody = async <T extends z.ZodType>(c: Context<Env>, schema: T, optional = false): Promise<z.infer<T>> => {
    if (!optional || declaresBody(c)) requireJson(c)
    let text = ''
    if (c.req.raw.body !== null) {
      try {
        text = await c.req.text()
      } catch (e) {
        if (e instanceof HttpError) throw e
        if (e instanceof Error && e.cause instanceof HttpError) throw e.cause
        throw new HttpError(400, 'INVALID_BODY', 'The request body could not be read.')
      }
    }
    if (text.trim() === '') {
      if (optional) return schema.parse({})
      throw new HttpError(400, 'INVALID_JSON', 'The request body is empty; send a JSON object.')
    }
    if (optional) requireJson(c)
    let raw: unknown
    try {
      raw = JSON.parse(text) as unknown
    } catch {
      throw new HttpError(400, 'INVALID_JSON', 'The request body is not valid JSON.')
    }
    return schema.parse(raw)
  }

  /** Active disputes apply to the run they were filed against and every later run. */
  const overlayFor = (b: Bundle, runId: string, vendorId: string): Dispute[] => {
    const order = b.runOrder(runId)
    return store.disputesForVendor(vendorId).filter((d) => ACTIVE_DISPUTE.includes(d.status) && b.runOrder(d.runId) <= order && b.runOrder(d.runId) >= 0)
  }

  /* ----------------------------------------------------------------- health */

  app.get('/api/health', (c) => {
    const dbOk = store.ping()
    const ok = dbOk && bundle !== null
    return c.json(
      {
        ok,
        status: ok ? 'ok' : 'degraded',
        service: 'touchstone-api',
        version: API_VERSION,
        dataMode: bundle?.index.mode ?? null,
        refreshMode: config.mode.toUpperCase(),
        networkCollection: config.mode === 'live' ? 'enabled (TOUCHSTONE_MODE=live)' : 'disabled: demo mode makes no network calls',
        latestRunId: bundle?.latestRunId ?? null,
        runs: bundle?.index.runs.length ?? 0,
        dataLoadedAt: bundle?.loadedAt ?? null,
        db: { ok: dbOk, mode: store.mode, schemaVersion: dbOk ? store.schemaVersion() : null },
        adminEnabled: config.adminToken !== null,
        uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
      },
      ok ? 200 : 503,
    )
  })

  /* ------------------------------------------------------------- signatories */

  app.get('/api/signatories', (c) => {
    const q = SignatoryQuery.parse(c.req.query())
    const { b, runId, summary } = runOf(c, q.run)
    if (q.coverageMin !== undefined && q.coverageMax !== undefined && q.coverageMin > q.coverageMax) {
      throw new HttpError(400, 'VALIDATION_FAILED', 'coverageMin must not exceed coverageMax.')
    }
    const direction = q.order ?? (q.sort === 'name' ? 'asc' : 'desc')
    // Same overlay rule as a vendor profile: active disputes filed against this run or an earlier one.
    const order = b.runOrder(runId)
    const counts = new Map<string, number>()
    for (const d of store.listDisputes({ status: ACTIVE_DISPUTE }, { limit: 100_000, offset: 0 }).rows) {
      const o = b.runOrder(d.runId)
      if (o >= 0 && o <= order) counts.set(d.vendorId, (counts.get(d.vendorId) ?? 0) + 1)
    }
    const rows = querySignatories(summary, counts, {
      category: q.category,
      status: q.status,
      coverageMin: q.coverageMin,
      coverageMax: q.coverageMax,
      q: q.q ?? q.search,
      synthetic: q.synthetic === undefined ? undefined : q.synthetic === 'true',
      sort: q.sort,
      order: direction,
    })
    return c.json({
      runId,
      datasetVersion: summary.manifest.datasetVersion,
      methodologyVersion: summary.manifest.methodologyVersion,
      total: rows.length,
      limit: q.limit,
      offset: q.offset,
      sort: q.sort,
      order: direction,
      ordering: 'Vendors without a measurable value for the sort key are listed last in either order; they are never ranked as 0. Evidence coverage is how much could be observed, not a security score.',
      signatoryList: summary.signatoryList,
      rows: rows.slice(q.offset, q.offset + q.limit),
    })
  })

  /* ----------------------------------------------------------------- vendors */

  app.get('/api/vendors/:id', (c) => {
    const { b, runId, vendorId, vendor } = vendorIn(c)
    return c.json({
      runId,
      summary: vendor,
      activeDisputes: overlayFor(b, runId, vendorId),
      presentInRuns: b.index.runs.filter((r) => b.vendorSummary(r.runId, vendorId) !== null).map((r) => ({ runId: r.runId, datasetVersion: r.datasetVersion })),
    })
  })

  app.get('/api/vendors/:id/goals', (c) => {
    const { b, runId, vendorId, vendor, summary } = vendorIn(c)
    const detail = b.vendorDetail(runId, vendorId)
    const evidenceSubjects = new Map((detail?.evidence ?? []).map((e) => [e.id, e.subject]))
    const assessments = vendor.goals.map((g) => ({
      goalId: g.goalId,
      metrics: g.metrics,
      evidenceIds: detail?.goals.find((x) => x.goalId === g.goalId)?.evidenceIds ?? [],
    }))
    const active = overlayFor(b, runId, vendorId)
    const disputedBy = new Map<string, string[]>()
    for (const d of active) for (const gid of disputedGoalIds(d, assessments, evidenceSubjects)) disputedBy.set(gid, [...(disputedBy.get(gid) ?? []), d.id])
    const definitions = summary.goals.length ? summary.goals : GOALS
    return c.json({
      runId,
      vendorId,
      goals: definitions.map((def) => {
        const a = vendor.goals.find((g) => g.goalId === def.id) ?? null
        const ids = disputedBy.get(def.id) ?? []
        return {
          goal: def,
          assessment: a,
          originalStatus: a?.status ?? null,
          displayState: ids.length ? 'DISPUTED' : (a?.status ?? null),
          activeDisputeIds: ids,
        }
      }),
    })
  })

  app.get('/api/vendors/:id/evidence', (c) => {
    const { b, runId, vendorId } = vendorIn(c)
    const detail = detailOf(b, runId, vendorId)
    const metric = c.req.query('metric')
    const interpretation = c.req.query('interpretation')?.toUpperCase()
    if (!metric && !interpretation) return c.json(detail)
    return c.json({ ...detail, evidence: detail.evidence.filter((e) => (!metric || e.metricId === metric) && (!interpretation || e.interpretation === interpretation)) })
  })

  app.get('/api/vendors/:id/history', (c) => {
    const vendorId = c.req.param('id')
    const b = data()
    if (!VENDOR_ID_RE.test(vendorId) || !b.hasVendor(vendorId)) throw new HttpError(404, 'VENDOR_NOT_FOUND', 'No vendor with that id.')
    const metric = c.req.query('metric')
    return c.json(b.history.filter((s) => s.vendorId === vendorId && (!metric || s.metricId === metric)))
  })

  /* -------------------------------------------------------------------- CVEs */

  app.get('/api/cves', (c) => {
    const q = CveQuery.parse(c.req.query())
    const { b, runId, summary } = runOf(c, q.run)
    const index = b.cves(runId)
    const rows = queryCves(index.rows, q)
    return c.json({
      runId,
      methodologyVersion: summary.manifest.methodologyVersion,
      total: rows.length,
      limit: q.limit,
      offset: q.offset,
      note:
        "cnaFieldStatus classifies the CNA container's own CWE and CPE fields under this run's methodology. Third-party (ADP) enrichment is shown as enrichedOnly and is never credited. The pledge metrics also apply the eligibility window; see a vendor's evidence for the metric itself.",
      rows: rows.slice(q.offset, q.offset + q.limit),
    })
  })

  app.get('/api/cves/:id', (c) => {
    const id = c.req.param('id').toUpperCase()
    if (!CVE_ID_RE.test(id)) throw new HttpError(400, 'INVALID_CVE_ID', 'A CVE id looks like CVE-2024-21412 (or DEMO-2026-0001 in the synthetic demo).')
    const { b, runId } = runOf(c)
    const index = b.cves(runId)
    const hit = index.byId.get(id)
    const exclusions = index.exclusions.filter((x) => x.cveId === id)
    if (!hit && exclusions.length === 0) throw new HttpError(404, 'CVE_NOT_FOUND', `${id} is not in run ${runId}.`)
    return c.json({
      runId,
      record: hit?.record ?? null,
      attributions: hit?.attributions ?? [],
      exclusions,
      row: index.rows.find((r) => r.id === id) ?? null,
    })
  })

  /* ------------------------------------------------- goals and methodology */

  app.get('/api/goals', (c) => {
    const summary = bundle?.summary(bundle.latestRunId) ?? null
    return c.json({ pledgeSource: PLEDGE_SOURCE_URL, goals: GOALS, metricDefinitions: summary?.metricDefinitions ?? [] })
  })

  app.get('/api/methodology', (c) => {
    return c.json({
      current: CURRENT_METHODOLOGY_VERSION,
      versions: METHODOLOGY_VERSIONS.map((m) => ({
        ...m,
        runs: (bundle?.index.runs ?? []).filter((r) => r.methodologyVersion === m.version).map((r) => r.runId),
      })),
      note: 'A published figure never changes without the methodology version changing. Each run is reproduced with the methodology version it was computed with.',
    })
  })

  /* -------------------------------------------------------------------- runs */

  app.get('/api/runs', (c) => c.json(data().index))

  app.get('/api/runs/:id', (c) => c.json(runOf(c, c.req.param('id')).summary))

  app.get('/api/runs/:id/inputs', (c) => {
    const { b, runId } = runOf(c, c.req.param('id'))
    const inputs = b.inputs(runId)
    if (!inputs) throw new HttpError(404, 'INPUTS_NOT_PUBLISHED', `The inputs of run ${runId} are not published, so it cannot be reproduced from this server.`)
    return c.json(inputs)
  })

  let reproducing = false
  app.post('/api/runs/:id/reproduce', reproduceLimiter, async (c) => {
    const { b, runId, summary } = runOf(c, c.req.param('id'))
    const inputs = b.inputs(runId)
    if (!inputs) throw new HttpError(404, 'INPUTS_NOT_PUBLISHED', `The inputs of run ${runId} are not published, so it cannot be reproduced.`)
    if (reproducing) {
      c.header('Retry-After', '5')
      throw new HttpError(503, 'REPRODUCE_BUSY', 'Another reproduction is running. Try again shortly.')
    }
    reproducing = true
    try {
      let engine: Engine
      try {
        engine = await engineLoader()
      } catch (e) {
        log('error', { operation: 'engine.load', error: e instanceof Error ? e.message : String(e) })
        throw new HttpError(503, 'ENGINE_UNAVAILABLE', 'The measurement engine could not be loaded. The error has been logged.')
      }
      const t0 = performance.now()
      const r = engine.reproduceRun(inputs, summary.manifest)
      const durationMs = Math.round(performance.now() - t0)
      return c.json({
        runId,
        datasetVersion: summary.manifest.datasetVersion,
        methodologyVersion: inputs.methodologyVersion,
        reproduced: r.reproduced,
        expected: { outputsHash: summary.manifest.outputsHash, inputsHash: summary.manifest.inputsHash },
        actual: { outputsHash: r.outputsHash, inputsHash: r.inputsHash },
        mismatches: r.mismatches,
        durationMs,
        statement: `Re-executed run ${runId} from its published inputs with methodology ${inputs.methodologyVersion}. Nothing was fetched.`,
      })
    } finally {
      reproducing = false
    }
  })

  /* --------------------------------------------------------------- freshness */

  app.get('/api/freshness', (c) => {
    const { runId, summary } = runOf(c)
    const snapshotStatus: Record<string, number> = {}
    for (const s of summary.snapshots) snapshotStatus[s.status] = (snapshotStatus[s.status] ?? 0) + 1
    return c.json({
      runId,
      asOf: summary.manifest.asOf,
      freshness: summary.freshness,
      snapshotStatus,
      substitutions: summary.snapshots.filter((s) => s.substitutedBy).map((s) => ({ snapshotId: s.id, sourceId: s.sourceId, substitutedBy: s.substitutedBy, error: s.error ?? null })),
      note: 'Freshness is computed from the last successful fetch, never from the last attempt. A failed refresh that fell back to an earlier snapshot is listed under substitutions.',
    })
  })

  /* ----------------------------------------------------------------- reports */

  app.get('/api/reports/:vendorId', async (c) => {
    const { b, runId, summary, vendorId } = vendorIn(c)
    const formatRaw = (c.req.query('format') ?? 'json').toLowerCase()
    const format = REPORT_FORMATS[formatRaw]
    if (!format) throw new HttpError(400, 'VALIDATION_FAILED', 'format must be json, markdown, csv or pdf.')
    const detail = detailOf(b, runId, vendorId)
    let engine: Engine
    try {
      engine = await engineLoader()
    } catch (e) {
      log('error', { operation: 'engine.load', error: e instanceof Error ? e.message : String(e) })
      throw new HttpError(503, 'ENGINE_UNAVAILABLE', 'The report generator could not be loaded. The error has been logged.')
    }
    const body = engine.vendorReport(summary, detail, store.disputesForVendor(vendorId), b.history.filter((s) => s.vendorId === vendorId), format)
    const ext = { json: 'json', markdown: 'md', csv: 'csv', pdf: 'pdf' }[format]
    const type = { json: 'application/json; charset=utf-8', markdown: 'text/markdown; charset=utf-8', csv: 'text/csv; charset=utf-8', pdf: 'application/pdf' }[format]
    c.header('Content-Type', type)
    c.header('Content-Disposition', `attachment; filename="${safeFileName(`touchstone-${vendorId}-${runId}.${ext}`)}"`)
    return c.body(typeof body === 'string' ? body : new Uint8Array(body))
  })

  /* ---------------------------------------------------------------- disputes */

  app.get('/api/disputes', (c) => {
    const q = z
      .object({
        vendor: z.string().regex(VENDOR_ID_RE).optional(),
        run: z.string().regex(RUN_ID_RE).optional(),
        status: csv(DISPUTE_STATUSES),
        ...pageQuery(1000, 500),
      })
      .parse(c.req.query())
    const { rows, total } = store.listDisputes({ vendorId: q.vendor, runId: q.run, status: q.status as DisputeStatus[] | undefined }, { limit: q.limit, offset: q.offset })
    c.header('X-Total-Count', String(total))
    return c.json(rows)
  })

  app.post('/api/disputes', disputeLimiter, async (c) => {
    const input = await jsonBody(c, CreateDispute)
    const { runId, summary } = runOf(c, input.runId)
    if (!summary.vendors.some((v) => v.vendor.id === input.vendorId)) {
      throw new HttpError(422, 'VENDOR_NOT_IN_RUN', `Vendor ${input.vendorId} is not part of run ${runId}.`)
    }
    const t = input.target
    const targetOk =
      t.kind === 'GOAL'
        ? GOALS.some((g) => g.id === t.id)
        : t.kind === 'METRIC'
          ? summary.metricDefinitions.some((m) => m.id === t.id)
          : t.kind === 'CVE'
            ? CVE_ID_RE.test(t.id)
            : t.kind === 'EVIDENCE'
              ? /^EV-[0-9a-f]{6,64}$/.test(t.id)
              : true
    if (!targetOk) throw new HttpError(422, 'UNKNOWN_TARGET', `No ${t.kind.toLowerCase()} "${t.id.slice(0, 80)}" in this run to dispute.`)
    const created = store.createDispute({
      vendorId: input.vendorId,
      target: t,
      runId,
      reason: input.reason,
      submitterRole: input.submitterRole,
      statement: input.statement,
      evidenceUrls: input.evidenceUrls,
      at: now(),
      actor: `submitter (${input.submitterRole.toLowerCase()})`,
    })
    log('info', { operation: 'dispute.create', disputeId: created.id, vendorId: created.vendorId })
    return c.json(created, 201)
  })

  app.get('/api/disputes/:id', (c) => {
    const id = c.req.param('id').toUpperCase()
    const d = DISPUTE_ID_RE.test(id) ? store.getDispute(id) : null
    if (!d) throw new HttpError(404, 'DISPUTE_NOT_FOUND', 'No dispute with that id.')
    return c.json({ ...d, allowedTransitions: DISPUTE_TRANSITIONS[d.status] })
  })

  app.post('/api/disputes/:id/transition', admin, async (c) => {
    const id = c.req.param('id').toUpperCase()
    const existing = DISPUTE_ID_RE.test(id) ? store.getDispute(id) : null
    if (!existing) throw new HttpError(404, 'DISPUTE_NOT_FOUND', 'No dispute with that id.')
    const input = await jsonBody(c, TransitionDispute)
    const allowed = DISPUTE_TRANSITIONS[existing.status]
    if (!allowed.includes(input.to)) {
      throw new HttpError(409, 'ILLEGAL_TRANSITION', `A dispute in ${existing.status} cannot move to ${input.to}.`, { from: existing.status, to: input.to, allowed })
    }
    if (input.to === 'CORRECTED') {
      const b = data()
      if (!input.correctedInRunId) throw new HttpError(422, 'CORRECTED_RUN_REQUIRED', 'CORRECTED needs correctedInRunId: the later run that carries the corrected result.')
      if (!b.hasRun(input.correctedInRunId)) throw new HttpError(422, 'RUN_NOT_FOUND', 'correctedInRunId is not a published run.')
      if (b.runOrder(input.correctedInRunId) <= b.runOrder(existing.runId)) {
        throw new HttpError(422, 'CORRECTED_RUN_NOT_LATER', 'A correction appears in a later run; the disputed run itself is never changed.')
      }
    } else if (input.correctedInRunId) {
      throw new HttpError(422, 'VALIDATION_FAILED', 'correctedInRunId applies only to CORRECTED.')
    }
    try {
      const d = store.transitionDispute(id, { to: input.to, note: input.note, actor: input.actor ?? 'reviewer', at: now(), correctedInRunId: input.correctedInRunId })
      log('info', { operation: 'dispute.transition', disputeId: id, to: input.to })
      return c.json({ ...d, allowedTransitions: DISPUTE_TRANSITIONS[d.status] })
    } catch (e) {
      if (e instanceof StoreConflict && e.code === 'ILLEGAL_TRANSITION') throw new HttpError(409, e.code, e.message, e.details)
      throw e
    }
  })

  /* ---------------------------------------------------------------- notebook */

  app.get('/api/notebook', (c) => {
    const vendor = c.req.query('vendor')
    const tag = c.req.query('tag')
    return c.json(store.listNotebook({ vendorId: vendor, tag }))
  })

  app.post('/api/notebook', admin, async (c) => {
    const input = await jsonBody(c, CreateNotebookEntry)
    if (input.vendorId && !data().hasVendor(input.vendorId)) throw new HttpError(422, 'VENDOR_NOT_FOUND', 'No vendor with that id.')
    const entry = store.addNotebook({ ...input, createdAt: now() })
    return c.json(entry, 201)
  })

  /* ----------------------------------------------------------------- refresh */

  app.post('/api/refresh', admin, async (c) => {
    const input = await jsonBody(c, StartRefresh, true)
    const job = refresh.start({ datasetVersion: input.datasetVersion, vendorIds: input.vendorIds })
    log('info', { operation: 'refresh.start', jobId: job.id, mode: job.mode })
    return c.json(jobView(job), 202)
  })

  app.get('/api/refresh', (c) => c.json({ current: refresh.currentJobId, jobs: store.listJobs(10).map(jobView) }))

  app.get('/api/refresh/:jobId', (c) => {
    const id = c.req.param('jobId')
    const job = JOB_ID_RE.test(id) ? store.getJob(id) : null
    if (!job) throw new HttpError(404, 'JOB_NOT_FOUND', 'No refresh job with that id.')
    return c.json(jobView(job))
  })

  app.all('/api/*', () => {
    throw new HttpError(404, 'NOT_FOUND', 'No such endpoint.')
  })

  if (config.production) serveStatic(app, config.webDist)

  app.notFound((c) => c.json({ error: { code: 'NOT_FOUND', message: 'Not found.' } }, 404))

  const seed = () => {
    const disputes = bundle ? store.seedDisputes(bundle.seedDisputes) : { inserted: [], skipped: [] }
    const notebook = bundle ? store.seedNotebook(bundle.seedNotebook) : 0
    return { disputes, notebook }
  }

  return {
    app,
    refresh,
    setBundle: (b) => {
      bundle = b
    },
    seed,
  }
}

/** Load the bundle, or null with the reason logged; the API still serves health and the notebook. */
export function tryLoadBundle(dir: string, log: Log): Bundle | null {
  try {
    const b = Bundle.load(dir)
    for (const w of b.warnings) log('warn', { operation: 'bundle.load', warning: w })
    return b
  } catch (e) {
    if (e instanceof BundleError) {
      log('warn', { operation: 'bundle.load', error: e.message })
      return null
    }
    throw e
  }
}
