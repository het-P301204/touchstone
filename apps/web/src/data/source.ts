/**
 * The single data-access interface of the web app.
 *
 * Two adapters return the same published shapes (packages/core/src/model/publish.ts):
 *   StaticSource  reads the bundled files under `${BASE_URL}data/`
 *   ApiSource     calls the TOUCHSTONE REST API under /api
 *
 * `getSource()` probes GET /api/health once; when it answers, the API is used,
 * otherwise the static bundle. Nothing else in the app calls fetch().
 */
import { cleanText } from '../../../../packages/core/src/util/sanitize.ts'
import type {
  Dispute,
  DisputeReason,
  DisputeStatus,
  HistorySeries,
  NotebookEntry,
  RunIndex,
  RunInputs,
  RunSummary,
  VendorDetail,
} from '@touchstone/core/model'

export type SourceKind = 'static' | 'api'

export type NewDispute = {
  vendorId: string
  target: Dispute['target']
  runId: string
  reason: DisputeReason
  submitterRole: Dispute['submitterRole']
  statement: string
  evidenceUrls: string[]
}

/** A dispute as displayed: `localOnly` marks one saved in this browser by the static demo. */
export type DisputeView = Dispute & { localOnly?: boolean }

export type RefreshStage = { stage: string; status: 'PENDING' | 'RUNNING' | 'OK' | 'WARN' | 'FAILED' | 'SKIPPED'; detail?: string }
export type RefreshJob = {
  jobId: string
  mode?: 'DEMO' | 'LIVE'
  status: 'QUEUED' | 'RUNNING' | 'DONE' | 'FAILED'
  stages: RefreshStage[]
  statement?: string
  runId?: string
  error?: string
}

export type DisputeTransition = { to: DisputeStatus; note: string; actor?: string; correctedInRunId?: string }

export type ReportFormat = 'pdf' | 'markdown' | 'csv' | 'json'

export interface DataSource {
  readonly kind: SourceKind
  /** True only when the API reports an enabled administration surface. */
  readonly adminEnabled: boolean
  runIndex(): Promise<RunIndex>
  summary(runId: string): Promise<RunSummary>
  vendorDetail(vendorId: string, runId: string): Promise<VendorDetail>
  /** History for one vendor, or for every vendor when vendorIds is omitted (static) / given (API). */
  history(vendorIds?: string[]): Promise<HistorySeries[]>
  inputs(runId: string, datasetVersion: string): Promise<RunInputs>
  disputes(): Promise<DisputeView[]>
  submitDispute(d: NewDispute): Promise<DisputeView>
  notebook(): Promise<NotebookEntry[]>
  /** API: starts a pipeline refresh (administrative: needs the admin bearer token). Static: not available (the UI replays the stage log instead). */
  refresh?(adminToken: string): Promise<RefreshJob>
  refreshStatus?(jobId: string): Promise<RefreshJob>
  /** API only: one dispute with the transitions its current status allows. */
  disputeDetail?(id: string): Promise<DisputeView & { allowedTransitions: DisputeStatus[] }>
  /** API only (administrative): move a dispute to its next status. */
  transitionDispute?(id: string, body: DisputeTransition, adminToken: string): Promise<DisputeView>
  /** API: the server renders the report. Static: undefined (rendered in the browser from core). */
  reportUrl?(vendorId: string, runId: string, format: ReportFormat): string
}

export class DataError extends Error {
  readonly status: number | undefined
  readonly url: string
  constructor(message: string, url: string, status?: number) {
    super(message)
    this.name = 'DataError'
    this.url = url
    this.status = status
  }
}

async function getJson<T>(url: string, init?: RequestInit): Promise<T> {
  let res: Response
  try {
    res = await fetch(url, { ...init, headers: { Accept: 'application/json', ...(init?.headers ?? {}) }, credentials: 'same-origin' })
  } catch {
    throw new DataError(`Network request failed: ${url}`, url)
  }
  if (!res.ok) {
    let detail = ''
    try {
      const body = (await res.json()) as { error?: { message?: string } }
      if (body?.error?.message) detail = `: ${body.error.message}`
    } catch {
      /* not JSON */
    }
    throw new DataError(`${res.status} ${res.statusText || 'error'} for ${url}${detail}`, url, res.status)
  }
  const type = res.headers.get('content-type') ?? ''
  if (!type.includes('json')) throw new DataError(`Expected JSON from ${url}, got ${type || 'no content type'}`, url, res.status)
  return (await res.json()) as T
}

const enc = encodeURIComponent

// ---------------------------------------------------------------- disputes saved in this browser (static demo)

const LOCAL_DISPUTES_KEY = 'touchstone.disputes.local'
const MAX_STATEMENT = 2000

function readLocalDisputes(): DisputeView[] {
  try {
    const raw = window.localStorage.getItem(LOCAL_DISPUTES_KEY)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((d): d is DisputeView => !!d && typeof d === 'object' && typeof (d as Dispute).id === 'string').map((d) => ({ ...d, localOnly: true }))
  } catch {
    return []
  }
}

function writeLocalDisputes(list: DisputeView[]): void {
  try {
    window.localStorage.setItem(LOCAL_DISPUTES_KEY, JSON.stringify(list))
  } catch {
    /* storage full or unavailable: the dispute stays in memory for this session */
  }
}

/** Sanitize and bound what a person typed before it is stored or displayed. */
export function sanitizeDispute(d: NewDispute): NewDispute {
  const urls = d.evidenceUrls
    .map((u) => cleanText(u).trim())
    .filter((u) => /^https:\/\/[^\s]+$/i.test(u) && u.length <= 500)
    .slice(0, 5)
  return { ...d, statement: cleanText(d.statement).trim().slice(0, MAX_STATEMENT), evidenceUrls: urls }
}

// ---------------------------------------------------------------- adapters

class StaticSource implements DataSource {
  readonly kind = 'static' as const
  readonly adminEnabled = false
  private readonly base = `${import.meta.env.BASE_URL}data/`

  runIndex() {
    return getJson<RunIndex>(`${this.base}index.json`)
  }
  summary(runId: string) {
    return getJson<RunSummary>(`${this.base}runs/${enc(runId)}/summary.json`)
  }
  vendorDetail(vendorId: string, runId: string) {
    return getJson<VendorDetail>(`${this.base}runs/${enc(runId)}/vendors/${enc(vendorId)}.json`)
  }
  async history(vendorIds?: string[]) {
    const all = await getJson<HistorySeries[]>(`${this.base}history.json`)
    return vendorIds ? all.filter((s) => vendorIds.includes(s.vendorId)) : all
  }
  inputs(_runId: string, datasetVersion: string) {
    return getJson<RunInputs>(`${this.base}inputs/${enc(datasetVersion)}.json`)
  }
  async disputes() {
    let published: DisputeView[] = []
    try {
      published = await getJson<Dispute[]>(`${this.base}disputes.json`)
    } catch (e) {
      if (!(e instanceof DataError && e.status === 404)) throw e
    }
    return [...published, ...readLocalDisputes()]
  }
  async submitDispute(input: NewDispute) {
    const d = sanitizeDispute(input)
    const local = readLocalDisputes()
    const now = new Date().toISOString()
    const n = local.length + 1
    const dispute: DisputeView = {
      id: `LOCAL-${String(n).padStart(4, '0')}`,
      ...d,
      status: 'OPEN',
      createdAt: now,
      history: [{ at: now, from: null, to: 'OPEN', actor: 'you (this browser)', note: 'Submitted in the static demo. Saved in this browser only.' }],
      synthetic: true,
      localOnly: true,
    }
    writeLocalDisputes([...local, dispute])
    return dispute
  }
  async notebook() {
    try {
      return await getJson<NotebookEntry[]>(`${this.base}notebook.json`)
    } catch (e) {
      if (e instanceof DataError && e.status === 404) return []
      throw e
    }
  }
}

class ApiSource implements DataSource {
  readonly kind = 'api' as const
  readonly adminEnabled: boolean
  constructor(adminEnabled: boolean) {
    this.adminEnabled = adminEnabled
  }
  runIndex() {
    return getJson<RunIndex>('/api/runs')
  }
  summary(runId: string) {
    return getJson<RunSummary>(`/api/runs/${enc(runId)}`)
  }
  vendorDetail(vendorId: string, runId: string) {
    return getJson<VendorDetail>(`/api/vendors/${enc(vendorId)}/evidence?run=${enc(runId)}`)
  }
  async history(vendorIds?: string[]) {
    let ids = vendorIds
    if (!ids) {
      const index = await this.runIndex()
      const summary = await this.summary(index.latestRunId)
      ids = summary.vendors.map((v) => v.vendor.id)
    }
    const lists = await Promise.all(ids.map((id) => getJson<HistorySeries[]>(`/api/vendors/${enc(id)}/history`)))
    return lists.flat()
  }
  inputs(runId: string) {
    return getJson<RunInputs>(`/api/runs/${enc(runId)}/inputs`)
  }
  disputes() {
    return getJson<Dispute[]>('/api/disputes')
  }
  submitDispute(input: NewDispute) {
    return getJson<Dispute>('/api/disputes', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(sanitizeDispute(input)),
    })
  }
  async notebook() {
    try {
      return await getJson<NotebookEntry[]>('/api/notebook')
    } catch (e) {
      if (e instanceof DataError && e.status === 404) return []
      throw e
    }
  }
  refresh(adminToken: string) {
    return getJson<RefreshJob>('/api/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: '{}',
    })
  }
  refreshStatus(jobId: string) {
    return getJson<RefreshJob>(`/api/refresh/${enc(jobId)}`)
  }
  disputeDetail(id: string) {
    return getJson<DisputeView & { allowedTransitions: DisputeStatus[] }>(`/api/disputes/${enc(id)}`)
  }
  transitionDispute(id: string, body: DisputeTransition, adminToken: string) {
    return getJson<DisputeView>(`/api/disputes/${enc(id)}/transition`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${adminToken}` },
      body: JSON.stringify({ ...body, note: cleanText(body.note).trim().slice(0, MAX_STATEMENT) }),
    })
  }
  reportUrl(vendorId: string, runId: string, format: ReportFormat) {
    return `/api/reports/${enc(vendorId)}?format=${enc(format)}&run=${enc(runId)}`
  }
}

// ---------------------------------------------------------------- detection

let sourcePromise: Promise<DataSource> | null = null

async function detect(): Promise<DataSource> {
  const forced = new URLSearchParams(window.location.search).get('source')
  if (forced === 'static') return new StaticSource()
  const ctrl = new AbortController()
  const timer = window.setTimeout(() => ctrl.abort(), 1500)
  try {
    const res = await fetch('/api/health', { signal: ctrl.signal, headers: { Accept: 'application/json' } })
    if (res.ok && (res.headers.get('content-type') ?? '').includes('json')) {
      const body = (await res.json()) as { ok?: boolean; status?: string; admin?: boolean; adminEnabled?: boolean }
      if (body && (body.ok === true || body.status === 'ok')) return new ApiSource(body.admin === true || body.adminEnabled === true)
    }
  } catch {
    /* no API: fall through to the static bundle */
  } finally {
    window.clearTimeout(timer)
  }
  return new StaticSource()
}

export function getSource(): Promise<DataSource> {
  sourcePromise ??= detect()
  return sourcePromise
}
