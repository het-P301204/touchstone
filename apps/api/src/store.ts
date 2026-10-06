/**
 * Persistence for the parts of TOUCHSTONE that change between runs: disputes,
 * the research notebook and refresh jobs. Published run data is NOT stored
 * here; it is read from the published bundle (see bundle.ts).
 *
 * SQLite through Node's built-in node:sqlite (no native module to compile).
 *
 * Integrity is enforced inside the database, not only in route code:
 *  - dispute_events is append-only: UPDATE and DELETE abort.
 *  - disputes are never deleted, and only their `status` column may change.
 *  - an event may only be appended when it starts from the dispute's current
 *    status and the step is in DISPUTE_TRANSITIONS (mirrored into the
 *    dispute_transitions table at start).
 *  - disputes.status may only be set to the latest event's to_status, so the
 *    status can never drift from its audit history.
 *  - notebook entries are append-only.
 * A dispute overlays an observation; nothing here can modify a published run.
 */
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { DISPUTE_TRANSITIONS } from '../../../packages/core/src/model/run.ts'
import type { Dispute, DisputeEvent, DisputeReason, DisputeStatus, NotebookEntry } from '../../../packages/core/src/model/index.ts'

export type Page = { limit: number; offset: number }

export type RefreshStageName = 'FETCH' | 'NORMALIZE' | 'VALIDATE' | 'SCORE' | 'PUBLISH'
export type RefreshStage = {
  stage: RefreshStageName
  status: 'PENDING' | 'RUNNING' | 'OK' | 'WARN' | 'FAILED' | 'SKIPPED'
  detail: string
  startedAt?: string
  finishedAt?: string
}
export type RefreshJob = {
  id: string
  mode: 'DEMO' | 'LIVE'
  status: 'QUEUED' | 'RUNNING' | 'DONE' | 'FAILED'
  datasetVersion: string | null
  requestedAt: string
  startedAt: string | null
  finishedAt: string | null
  /** Plain statement of what this job does and does not do (e.g. no network calls in DEMO). */
  statement: string
  stages: RefreshStage[]
  /** Result summary when finished (run id, hashes, whether output matched the published run). */
  result: Record<string, unknown> | null
  error: string | null
}

export type NewDispute = Omit<Dispute, 'id' | 'status' | 'history' | 'createdAt' | 'synthetic'> & { at: string; actor: string }

export class StoreConflict extends Error {
  readonly code: string
  readonly details: unknown
  constructor(code: string, message: string, details?: unknown) {
    super(message)
    this.code = code
    this.details = details
  }
}

type Row = Record<string, unknown>
const str = (v: unknown): string => (typeof v === 'string' ? v : String(v ?? ''))
const strOrNull = (v: unknown): string | null => (v === null || v === undefined ? null : str(v))
const num = (v: unknown): number => (typeof v === 'number' ? v : typeof v === 'bigint' ? Number(v) : Number(v ?? 0))

const STATUSES: DisputeStatus[] = ['OPEN', 'UNDER_REVIEW', 'CONFIRMED', 'CORRECTED', 'DISMISSED']

/** Migrations run in order, each once, recorded in schema_version. Append only. */
export const MIGRATIONS: { version: number; sql: string }[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE disputes (
        id                 TEXT PRIMARY KEY,
        seq                INTEGER NOT NULL UNIQUE,
        vendor_id          TEXT NOT NULL,
        target_kind        TEXT NOT NULL,
        target_id          TEXT NOT NULL,
        run_id             TEXT NOT NULL,
        reason             TEXT NOT NULL,
        submitter_role     TEXT NOT NULL,
        statement          TEXT NOT NULL,
        evidence_urls_json TEXT NOT NULL,
        status             TEXT NOT NULL CHECK (status IN ('OPEN','UNDER_REVIEW','CONFIRMED','CORRECTED','DISMISSED')),
        created_at         TEXT NOT NULL,
        synthetic          INTEGER NOT NULL CHECK (synthetic IN (0,1))
      );
      CREATE INDEX disputes_vendor ON disputes(vendor_id, seq);
      CREATE TABLE dispute_events (
        seq                 INTEGER PRIMARY KEY AUTOINCREMENT,
        dispute_id          TEXT NOT NULL REFERENCES disputes(id),
        at                  TEXT NOT NULL,
        from_status         TEXT,
        to_status           TEXT NOT NULL,
        actor               TEXT NOT NULL,
        note                TEXT NOT NULL,
        corrected_in_run_id TEXT
      );
      CREATE INDEX dispute_events_dispute ON dispute_events(dispute_id, seq);
      CREATE TABLE dispute_transitions (
        from_status TEXT NOT NULL,
        to_status   TEXT NOT NULL,
        PRIMARY KEY (from_status, to_status)
      );

      CREATE TRIGGER dispute_events_no_update BEFORE UPDATE ON dispute_events
      BEGIN SELECT RAISE(ABORT, 'dispute_events is append-only'); END;
      CREATE TRIGGER dispute_events_no_delete BEFORE DELETE ON dispute_events
      BEGIN SELECT RAISE(ABORT, 'dispute_events is append-only'); END;
      CREATE TRIGGER disputes_no_delete BEFORE DELETE ON disputes
      BEGIN SELECT RAISE(ABORT, 'disputes are never deleted'); END;
      CREATE TRIGGER disputes_fields_immutable BEFORE UPDATE ON disputes
      WHEN NEW.id IS NOT OLD.id OR NEW.seq IS NOT OLD.seq OR NEW.vendor_id IS NOT OLD.vendor_id
        OR NEW.target_kind IS NOT OLD.target_kind OR NEW.target_id IS NOT OLD.target_id
        OR NEW.run_id IS NOT OLD.run_id OR NEW.reason IS NOT OLD.reason
        OR NEW.submitter_role IS NOT OLD.submitter_role OR NEW.statement IS NOT OLD.statement
        OR NEW.evidence_urls_json IS NOT OLD.evidence_urls_json OR NEW.created_at IS NOT OLD.created_at
        OR NEW.synthetic IS NOT OLD.synthetic
      BEGIN SELECT RAISE(ABORT, 'only a dispute''s status may change'); END;
      CREATE TRIGGER disputes_status_follows_history BEFORE UPDATE OF status ON disputes
      WHEN NEW.status IS NOT (SELECT to_status FROM dispute_events WHERE dispute_id = NEW.id ORDER BY seq DESC LIMIT 1)
      BEGIN SELECT RAISE(ABORT, 'a dispute''s status must equal its latest event'); END;
      CREATE TRIGGER dispute_events_legal BEFORE INSERT ON dispute_events
      WHEN (NEW.from_status IS NULL AND (NEW.to_status <> 'OPEN' OR EXISTS (SELECT 1 FROM dispute_events WHERE dispute_id = NEW.dispute_id)))
        OR (NEW.from_status IS NOT NULL AND (
              NEW.from_status IS NOT (SELECT to_status FROM dispute_events WHERE dispute_id = NEW.dispute_id ORDER BY seq DESC LIMIT 1)
              OR NOT EXISTS (SELECT 1 FROM dispute_transitions t WHERE t.from_status = NEW.from_status AND t.to_status = NEW.to_status)))
      BEGIN SELECT RAISE(ABORT, 'illegal dispute transition'); END;

      CREATE TABLE notebook_entries (
        id           TEXT PRIMARY KEY,
        seq          INTEGER NOT NULL UNIQUE,
        vendor_id    TEXT,
        title        TEXT NOT NULL,
        observation  TEXT NOT NULL,
        resolution   TEXT,
        created_at   TEXT NOT NULL,
        tags_json    TEXT NOT NULL,
        synthetic    INTEGER NOT NULL CHECK (synthetic IN (0,1))
      );
      CREATE TRIGGER notebook_no_update BEFORE UPDATE ON notebook_entries
      BEGIN SELECT RAISE(ABORT, 'notebook entries are append-only'); END;
      CREATE TRIGGER notebook_no_delete BEFORE DELETE ON notebook_entries
      BEGIN SELECT RAISE(ABORT, 'notebook entries are append-only'); END;

      CREATE TABLE refresh_jobs (
        id              TEXT PRIMARY KEY,
        mode            TEXT NOT NULL,
        status          TEXT NOT NULL,
        dataset_version TEXT,
        requested_at    TEXT NOT NULL,
        started_at      TEXT,
        finished_at     TEXT,
        statement       TEXT NOT NULL,
        stages_json     TEXT NOT NULL,
        result_json     TEXT,
        error           TEXT
      );
      CREATE INDEX refresh_jobs_requested ON refresh_jobs(requested_at);
    `,
  },
]

export class Store {
  readonly mode: 'memory' | 'file'
  private readonly db: DatabaseSync
  /** Highest id number used by the bundle's seeds, stored or refused, so a new id never reuses a published one. */
  private readonly reserved = new Map<string, number>()

  constructor(path: string) {
    if (path === ':memory:') {
      this.mode = 'memory'
      this.db = new DatabaseSync(':memory:')
    } else {
      this.mode = 'file'
      mkdirSync(dirname(path), { recursive: true })
      this.db = new DatabaseSync(path)
      this.db.exec('PRAGMA journal_mode = WAL')
    }
    this.db.exec('PRAGMA foreign_keys = ON')
    this.db.exec('PRAGMA busy_timeout = 5000')
    this.migrate()
    const ins = this.db.prepare('INSERT OR IGNORE INTO dispute_transitions (from_status, to_status) VALUES (?, ?)')
    for (const [from, tos] of Object.entries(DISPUTE_TRANSITIONS)) for (const to of tos) ins.run(from, to)
  }

  private migrate(): void {
    this.db.exec('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)')
    const current = this.schemaVersion()
    for (const m of MIGRATIONS) {
      if (m.version <= current) continue
      this.tx(() => {
        this.db.exec(m.sql)
        this.db.prepare('INSERT INTO schema_version (version, applied_at) VALUES (?, ?)').run(m.version, new Date().toISOString())
      })
    }
  }

  private tx<T>(fn: () => T): T {
    this.db.exec('BEGIN IMMEDIATE')
    try {
      const out = fn()
      this.db.exec('COMMIT')
      return out
    } catch (e) {
      this.db.exec('ROLLBACK')
      throw e
    }
  }

  schemaVersion(): number {
    const row = this.db.prepare('SELECT MAX(version) AS v FROM schema_version').get() as Row | undefined
    return row?.['v'] === null || row?.['v'] === undefined ? 0 : num(row['v'])
  }

  ping(): boolean {
    try {
      this.db.prepare('SELECT 1').get()
      return true
    } catch {
      return false
    }
  }

  /** Raw access for integrity tests only. */
  unsafeExec(sql: string): void {
    this.db.exec(sql)
  }

  /* ---------------------------------------------------------------- disputes */

  private eventsFor(id: string): DisputeEvent[] {
    const rows = this.db.prepare('SELECT at, from_status, to_status, actor, note, corrected_in_run_id FROM dispute_events WHERE dispute_id = ? ORDER BY seq').all(id) as Row[]
    return rows.map((r) => {
      const e: DisputeEvent = {
        at: str(r['at']),
        from: strOrNull(r['from_status']) as DisputeStatus | null,
        to: str(r['to_status']) as DisputeStatus,
        actor: str(r['actor']),
        note: str(r['note']),
      }
      const corrected = strOrNull(r['corrected_in_run_id'])
      if (corrected) e.correctedInRunId = corrected
      return e
    })
  }

  private disputeFrom(r: Row): Dispute {
    const id = str(r['id'])
    return {
      id,
      vendorId: str(r['vendor_id']),
      target: { kind: str(r['target_kind']) as Dispute['target']['kind'], id: str(r['target_id']) },
      runId: str(r['run_id']),
      reason: str(r['reason']) as DisputeReason,
      submitterRole: str(r['submitter_role']) as Dispute['submitterRole'],
      statement: str(r['statement']),
      evidenceUrls: JSON.parse(str(r['evidence_urls_json'])) as string[],
      status: str(r['status']) as DisputeStatus,
      createdAt: str(r['created_at']),
      history: this.eventsFor(id),
      synthetic: num(r['synthetic']) === 1,
    }
  }

  listDisputes(filter: { vendorId?: string; status?: DisputeStatus[]; runId?: string }, page: Page): { rows: Dispute[]; total: number } {
    const where: string[] = []
    const params: (string | number)[] = []
    if (filter.vendorId) {
      where.push('vendor_id = ?')
      params.push(filter.vendorId)
    }
    if (filter.runId) {
      where.push('run_id = ?')
      params.push(filter.runId)
    }
    if (filter.status?.length) {
      const valid = filter.status.filter((s) => STATUSES.includes(s))
      where.push(`status IN (${valid.map(() => '?').join(',') || "''"})`)
      params.push(...valid)
    }
    const clause = where.length ? ` WHERE ${where.join(' AND ')}` : ''
    const rows = this.db.prepare(`SELECT * FROM disputes${clause} ORDER BY seq LIMIT ? OFFSET ?`).all(...params, page.limit, page.offset) as Row[]
    const total = num((this.db.prepare(`SELECT COUNT(*) AS n FROM disputes${clause}`).get(...params) as Row)['n'])
    return { rows: rows.map((r) => this.disputeFrom(r)), total }
  }

  /** Every dispute for a vendor (small; used for the goal overlay and reports). */
  disputesForVendor(vendorId: string): Dispute[] {
    return (this.db.prepare('SELECT * FROM disputes WHERE vendor_id = ? ORDER BY seq').all(vendorId) as Row[]).map((r) => this.disputeFrom(r))
  }

  getDispute(id: string): Dispute | null {
    const r = this.db.prepare('SELECT * FROM disputes WHERE id = ?').get(id) as Row | undefined
    return r ? this.disputeFrom(r) : null
  }

  private nextSeq(table: 'disputes' | 'notebook_entries'): number {
    const r = this.db.prepare(`SELECT COALESCE(MAX(seq), 0) AS n FROM ${table}`).get() as Row
    return num(r['n']) + 1
  }

  /** Highest numeric suffix among ids like PREFIX-0007, so new ids never collide with seeded ones. */
  private nextNumber(table: 'disputes' | 'notebook_entries', prefix: string): number {
    const rows = this.db.prepare(`SELECT id FROM ${table}`).all() as Row[]
    let max = this.reserved.get(prefix) ?? 0
    for (const r of rows) {
      const m = new RegExp(`^${prefix}-(\\d{1,9})$`).exec(str(r['id']))
      if (m) max = Math.max(max, Number(m[1]))
    }
    return max + 1
  }

  private insertDispute(d: Omit<Dispute, 'history' | 'status'>): void {
    this.db
      .prepare(
        `INSERT INTO disputes (id, seq, vendor_id, target_kind, target_id, run_id, reason, submitter_role, statement, evidence_urls_json, status, created_at, synthetic)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'OPEN', ?, ?)`,
      )
      .run(d.id, this.nextSeq('disputes'), d.vendorId, d.target.kind, d.target.id, d.runId, d.reason, d.submitterRole, d.statement, JSON.stringify(d.evidenceUrls), d.createdAt, d.synthetic ? 1 : 0)
  }

  private appendEvent(disputeId: string, e: DisputeEvent): void {
    this.db
      .prepare('INSERT INTO dispute_events (dispute_id, at, from_status, to_status, actor, note, corrected_in_run_id) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(disputeId, e.at, e.from, e.to, e.actor, e.note, e.correctedInRunId ?? null)
    this.db.prepare('UPDATE disputes SET status = ? WHERE id = ?').run(e.to, disputeId)
  }

  createDispute(input: NewDispute): Dispute {
    const id = this.tx(() => {
      const id = `DSP-${String(this.nextNumber('disputes', 'DSP')).padStart(4, '0')}`
      this.insertDispute({
        id,
        vendorId: input.vendorId,
        target: input.target,
        runId: input.runId,
        reason: input.reason,
        submitterRole: input.submitterRole,
        statement: input.statement,
        evidenceUrls: input.evidenceUrls,
        createdAt: input.at,
        synthetic: false,
      })
      this.appendEvent(id, { at: input.at, from: null, to: 'OPEN', actor: input.actor, note: 'Submitted.' })
      return id
    })
    return this.getDispute(id)!
  }

  /**
   * Append a status change. Throws StoreConflict ILLEGAL_TRANSITION when the
   * step is not allowed from the current status (checked here for a clear
   * message, and again by the database trigger).
   */
  transitionDispute(id: string, step: { to: DisputeStatus; actor: string; note: string; at: string; correctedInRunId?: string }): Dispute {
    this.tx(() => {
      const current = this.db.prepare('SELECT status FROM disputes WHERE id = ?').get(id) as Row | undefined
      if (!current) throw new StoreConflict('DISPUTE_NOT_FOUND', `No dispute ${id}.`)
      const from = str(current['status']) as DisputeStatus
      const allowed = DISPUTE_TRANSITIONS[from] ?? []
      if (!allowed.includes(step.to)) {
        throw new StoreConflict('ILLEGAL_TRANSITION', `A dispute in ${from} cannot move to ${step.to}.`, { from, to: step.to, allowed })
      }
      const e: DisputeEvent = { at: step.at, from, to: step.to, actor: step.actor, note: step.note }
      if (step.correctedInRunId) e.correctedInRunId = step.correctedInRunId
      this.appendEvent(id, e)
    })
    return this.getDispute(id)!
  }

  /**
   * Seed synthetic demo disputes (from the bundle's disputes.json) once. Each
   * is replayed event by event through the same triggers, so a seed with an
   * illegal history is refused, not stored. Existing ids are left untouched.
   */
  seedDisputes(seeds: Dispute[]): { inserted: string[]; skipped: { id: string; reason: string }[] } {
    const inserted: string[] = []
    const skipped: { id: string; reason: string }[] = []
    for (const d of seeds) {
      const m = /^DSP-(\d{1,9})$/.exec(String(d.id))
      if (m) this.reserved.set('DSP', Math.max(this.reserved.get('DSP') ?? 0, Number(m[1])))
      if (this.getDispute(d.id)) {
        skipped.push({ id: d.id, reason: 'already present' })
        continue
      }
      try {
        const last = d.history[d.history.length - 1]
        if (!last) throw new Error('seed has no history')
        if (last.to !== d.status) throw new Error(`seed status ${d.status} does not match its history (${last.to})`)
        this.tx(() => {
          this.insertDispute({ ...d, synthetic: true })
          for (const e of d.history) this.appendEvent(d.id, e)
        })
        inserted.push(d.id)
      } catch (e) {
        skipped.push({ id: d.id, reason: e instanceof Error ? e.message : String(e) })
      }
    }
    return { inserted, skipped }
  }

  /* ---------------------------------------------------------------- notebook */

  private notebookFrom(r: Row): NotebookEntry {
    const e: NotebookEntry = {
      id: str(r['id']),
      title: str(r['title']),
      observation: str(r['observation']),
      createdAt: str(r['created_at']),
      tags: JSON.parse(str(r['tags_json'])) as string[],
      synthetic: num(r['synthetic']) === 1,
    }
    const vendorId = strOrNull(r['vendor_id'])
    if (vendorId) e.vendorId = vendorId
    const resolution = strOrNull(r['resolution'])
    if (resolution) e.resolution = resolution
    return e
  }

  listNotebook(filter: { vendorId?: string; tag?: string }): NotebookEntry[] {
    const rows = (this.db.prepare('SELECT * FROM notebook_entries ORDER BY seq').all() as Row[]).map((r) => this.notebookFrom(r))
    return rows.filter((e) => (!filter.vendorId || e.vendorId === filter.vendorId) && (!filter.tag || e.tags.includes(filter.tag)))
  }

  private insertNotebook(e: NotebookEntry): void {
    this.db
      .prepare('INSERT INTO notebook_entries (id, seq, vendor_id, title, observation, resolution, created_at, tags_json, synthetic) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
      .run(e.id, this.nextSeq('notebook_entries'), e.vendorId ?? null, e.title, e.observation, e.resolution ?? null, e.createdAt, JSON.stringify(e.tags), e.synthetic ? 1 : 0)
  }

  addNotebook(input: Omit<NotebookEntry, 'id' | 'synthetic'>): NotebookEntry {
    const id = this.tx(() => {
      const id = `NB-${String(this.nextNumber('notebook_entries', 'NB')).padStart(4, '0')}`
      this.insertNotebook({ ...input, id, synthetic: false })
      return id
    })
    return this.listNotebook({}).find((e) => e.id === id)!
  }

  seedNotebook(entries: NotebookEntry[]): number {
    let n = 0
    for (const e of entries) {
      const m = /^NB-(\d{1,9})$/.exec(String(e.id))
      if (m) this.reserved.set('NB', Math.max(this.reserved.get('NB') ?? 0, Number(m[1])))
      const exists = this.db.prepare('SELECT 1 FROM notebook_entries WHERE id = ?').get(e.id)
      if (exists) continue
      this.tx(() => this.insertNotebook({ ...e, synthetic: true }))
      n++
    }
    return n
  }

  /* ------------------------------------------------------------ refresh jobs */

  private jobFrom(r: Row): RefreshJob {
    return {
      id: str(r['id']),
      mode: str(r['mode']) as RefreshJob['mode'],
      status: str(r['status']) as RefreshJob['status'],
      datasetVersion: strOrNull(r['dataset_version']),
      requestedAt: str(r['requested_at']),
      startedAt: strOrNull(r['started_at']),
      finishedAt: strOrNull(r['finished_at']),
      statement: str(r['statement']),
      stages: JSON.parse(str(r['stages_json'])) as RefreshStage[],
      result: r['result_json'] ? (JSON.parse(str(r['result_json'])) as Record<string, unknown>) : null,
      error: strOrNull(r['error']),
    }
  }

  saveJob(job: RefreshJob): void {
    this.db
      .prepare(
        `INSERT INTO refresh_jobs (id, mode, status, dataset_version, requested_at, started_at, finished_at, statement, stages_json, result_json, error)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET status = excluded.status, dataset_version = excluded.dataset_version, started_at = excluded.started_at,
           finished_at = excluded.finished_at, stages_json = excluded.stages_json, result_json = excluded.result_json, error = excluded.error`,
      )
      .run(
        job.id,
        job.mode,
        job.status,
        job.datasetVersion,
        job.requestedAt,
        job.startedAt,
        job.finishedAt,
        job.statement,
        JSON.stringify(job.stages),
        job.result ? JSON.stringify(job.result) : null,
        job.error,
      )
  }

  getJob(id: string): RefreshJob | null {
    const r = this.db.prepare('SELECT * FROM refresh_jobs WHERE id = ?').get(id) as Row | undefined
    return r ? this.jobFrom(r) : null
  }

  listJobs(limit: number): RefreshJob[] {
    return (this.db.prepare('SELECT * FROM refresh_jobs ORDER BY requested_at DESC, id DESC LIMIT ?').all(limit) as Row[]).map((r) => this.jobFrom(r))
  }

  /** Jobs left RUNNING by a previous process are recorded as FAILED, never silently forgotten. */
  failInterruptedJobs(at: string): number {
    const rows = this.db.prepare("SELECT * FROM refresh_jobs WHERE status IN ('QUEUED','RUNNING')").all() as Row[]
    for (const r of rows) {
      const j = this.jobFrom(r)
      j.status = 'FAILED'
      j.finishedAt = at
      j.error = 'Interrupted: the server stopped before the job finished.'
      j.stages = j.stages.map((s) => (s.status === 'RUNNING' || s.status === 'PENDING' ? { ...s, status: s.status === 'RUNNING' ? 'FAILED' : 'SKIPPED' } : s))
      this.saveJob(j)
    }
    return rows.length
  }

  close(): void {
    if (this.db.isOpen) this.db.close()
  }
}
