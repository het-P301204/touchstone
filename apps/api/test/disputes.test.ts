import { afterAll, describe, expect, it } from 'vitest'
import { Store } from '../src/store.ts'
import { HALCYON, NORTHWIND, RUN_1, RUN_2 } from './fixtures/bundle.ts'
import { ADMIN, makeApp } from './helpers.ts'

type Json = Record<string, any>
const cp = (n: number) => String.fromCodePoint(n)

const valid = (over: Json = {}) => ({
  vendorId: NORTHWIND,
  runId: RUN_2,
  target: { kind: 'METRIC', id: 'cve.complete_records' },
  reason: 'INCORRECT_CVE_MAPPING',
  submitterRole: 'VENDOR',
  statement: 'Record DEMO-2026-0002 belongs to a different product line.',
  evidenceUrls: ['https://psirt.northwind-systems.example/notes/1'],
  ...over,
})

describe('dispute seeding', () => {
  const t = makeApp()
  afterAll(() => t.close())

  it('seeds synthetic disputes from disputes.json, replaying each history through the transition rules', async () => {
    expect(t.seeded.disputes.inserted).toEqual(['DSP-0001', 'DSP-0002'])
    // DSP-0003's history jumps OPEN -> CONFIRMED: refused, not stored.
    expect(t.seeded.disputes.skipped.map((s) => s.id)).toEqual(['DSP-0003'])
    expect(t.seeded.notebook).toBe(1)
    const list = (await (await t.app.request('/api/disputes')).json()) as Json[]
    expect(list.map((d) => d.id)).toEqual(['DSP-0001', 'DSP-0002'])
    expect(list.every((d) => d.synthetic === true)).toBe(true)
    const corrected = list.find((d) => d.id === 'DSP-0002')!
    expect(corrected.status).toBe('CORRECTED')
    expect(corrected.history.map((e: Json) => e.to)).toEqual(['OPEN', 'UNDER_REVIEW', 'CORRECTED'])
    expect(corrected.history[2].correctedInRunId).toBe(RUN_2)
    // Seeding again changes nothing.
    expect(t.seed().disputes.inserted).toEqual([])
  })
})

describe('dispute lifecycle', () => {
  const t = makeApp({ adminToken: ADMIN, disputeRateLimitPerHour: 1000 })
  afterAll(() => t.close())

  it('creates an OPEN dispute with sanitized text and validated URLs', async () => {
    const statement = `Wrong product${cp(0x202e)} mapping${cp(0x200b)}.${cp(0x1b)}[2J  `
    const r = await t.json('POST', '/api/disputes', valid({ statement }))
    expect(r.status).toBe(201)
    const d = (await r.json()) as Json
    expect(d.id).toBe('DSP-0004') // continues after the highest seeded id
    expect(d.status).toBe('OPEN')
    expect(d.synthetic).toBe(false)
    expect(d.statement).toBe('Wrong product mapping.[2J')
    expect(d.evidenceUrls).toEqual(['https://psirt.northwind-systems.example/notes/1'])
    expect(d.history).toEqual([{ at: d.createdAt, from: null, to: 'OPEN', actor: 'submitter (vendor)', note: 'Submitted.' }])
    const fetched = (await (await t.app.request('/api/disputes/dsp-0004')).json()) as Json
    expect(fetched.allowedTransitions).toEqual(['UNDER_REVIEW', 'DISMISSED'])
  })

  it('defaults runId to the latest run', async () => {
    const body = valid()
    delete (body as Json)['runId']
    const r = await t.json('POST', '/api/disputes', body)
    expect(r.status).toBe(201)
    expect(((await r.json()) as Json).runId).toBe(RUN_2)
  })

  it('validates the body: fields, targets, URLs and length', async () => {
    const bad: [Json, number][] = [
      [valid({ reason: 'I_DISAGREE' }), 400],
      [valid({ submitterRole: 'CEO' }), 400],
      [valid({ statement: '   ' }), 400],
      [valid({ statement: 'x'.repeat(2001) }), 400],
      [valid({ evidenceUrls: ['http://insecure.example/x'] }), 400],
      [valid({ evidenceUrls: ['javascript:alert(1)'] }), 400],
      [valid({ evidenceUrls: ['https://user:pass@evil.example/'] }), 400],
      [valid({ evidenceUrls: ['/relative/path'] }), 400],
      [valid({ evidenceUrls: [`https://x.example/${'a'.repeat(600)}`] }), 400],
      [valid({ evidenceUrls: Array.from({ length: 6 }, (_, i) => `https://x.example/${i}`) }), 400],
      [valid({ extra: true }), 400],
      [valid({ vendorId: '../../etc' }), 400],
      [valid({ vendorId: 'acme-unknown' }), 422],
      [valid({ runId: 'TS-1999-01-01-0000' }), 404],
      [valid({ target: { kind: 'GOAL', id: 'G9' } }), 422],
      [valid({ target: { kind: 'METRIC', id: 'made.up' } }), 422],
      [valid({ target: { kind: 'CVE', id: 'not-a-cve' } }), 422],
      [valid({ target: { kind: 'PERSON', id: 'x' } }), 400],
    ]
    for (const [body, status] of bad) {
      const r = await t.json('POST', '/api/disputes', body)
      expect(r.status, JSON.stringify(body).slice(0, 120)).toBe(status)
      expect(((await r.json()) as Json).error.code).toBeTypeOf('string')
    }
    const notJson = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: JSON.stringify(valid()) })
    expect(notJson.status).toBe(415)
    const form = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: 'vendorId=x' })
    expect(form.status).toBe(415)
    const broken = await t.app.request('/api/disputes', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{"vendorId":' })
    expect(broken.status).toBe(400)
    expect(((await broken.json()) as Json).error.code).toBe('INVALID_JSON')
  })

  it('checks every target kind against the run and vendor named in the dispute', async () => {
    const ev = ((await (await t.app.request(`/api/vendors/${NORTHWIND}/evidence?run=${RUN_2}`)).json()) as Json).evidence[0].id as string
    const cases: [Json, number][] = [
      [{ kind: 'GOAL', id: 'G3' }, 201],
      [{ kind: 'GOAL', id: 'G8' }, 422],
      [{ kind: 'METRIC', id: 'cve.timely_issuance' }, 201],
      [{ kind: 'METRIC', id: 'cve.made_up' }, 422],
      [{ kind: 'EVIDENCE', id: ev }, 201],
      [{ kind: 'EVIDENCE', id: 'EV-0000000000' }, 422],
      // Attributed to Northwind by the engine.
      [{ kind: 'CVE', id: 'demo-2026-0001' }, 201],
      // Excluded (ambiguous) with Northwind among the candidates.
      [{ kind: 'CVE', id: 'DEMO-2026-0009' }, 201],
      // Attributed to Halcyon, not to Northwind.
      [{ kind: 'CVE', id: 'DEMO-2025-0003' }, 422],
      [{ kind: 'CVE', id: 'CVE-2024-21412' }, 422],
      [{ kind: 'IDENTITY', id: 'northwind' }, 201],
      [{ kind: 'IDENTITY', id: 'Northwind Systems' }, 201],
      [{ kind: 'IDENTITY', id: 'Halcyon Cloud' }, 422],
      [{ kind: 'IDENTITY', id: 'IC-unknown' }, 422],
    ]
    for (const [target, status] of cases) {
      const r = await t.json('POST', '/api/disputes', valid({ target }))
      const body = (await r.json()) as Json
      expect([target.id, r.status]).toEqual([target.id, status])
      if (status === 422) {
        expect(body.error.code).toBe('UNKNOWN_TARGET')
        expect(body.error.message.length).toBeGreaterThan(10)
      }
    }
    const stored = (await (await t.json('POST', '/api/disputes', valid({ target: { kind: 'CVE', id: 'demo-2026-0002' } }))).json()) as Json
    expect(stored.target).toEqual({ kind: 'CVE', id: 'DEMO-2026-0002' })
    // The same CVE is valid for Halcyon only where the engine says so.
    expect((await t.json('POST', '/api/disputes', valid({ vendorId: HALCYON, target: { kind: 'CVE', id: 'DEMO-2025-0003' } }))).status).toBe(201)
    expect((await t.json('POST', '/api/disputes', valid({ vendorId: HALCYON, target: { kind: 'CVE', id: 'DEMO-2026-0001' } }))).status).toBe(422)
  })

  it('walks OPEN -> UNDER_REVIEW -> CONFIRMED with an append-only history', async () => {
    const id = ((await (await t.json('POST', '/api/disputes', valid())).json()) as Json).id as string
    const step = (to: string, extra: Json = {}) => t.json('POST', `/api/disputes/${id}/transition`, { to, note: `to ${to}`, ...extra }, t.adminHeaders)
    const r1 = await step('UNDER_REVIEW', { actor: 'Reviewer A' })
    expect(r1.status).toBe(200)
    expect(((await r1.json()) as Json).status).toBe('UNDER_REVIEW')
    const r2 = await step('CONFIRMED')
    const d = (await r2.json()) as Json
    expect(d.status).toBe('CONFIRMED')
    expect(d.history.map((e: Json) => [e.from, e.to, e.actor])).toEqual([
      [null, 'OPEN', 'submitter (vendor)'],
      ['OPEN', 'UNDER_REVIEW', 'Reviewer A'],
      ['UNDER_REVIEW', 'CONFIRMED', 'reviewer'],
    ])
    expect(d.allowedTransitions).toEqual([])
    // Terminal: every further step is illegal.
    for (const to of ['OPEN', 'UNDER_REVIEW', 'CORRECTED', 'DISMISSED']) {
      const r = await step(to)
      expect(r.status).toBe(409)
      expect(((await r.json()) as Json).error.code).toBe('ILLEGAL_TRANSITION')
    }
  })

  it('refuses illegal transitions with 409 and the allowed list', async () => {
    const id = ((await (await t.json('POST', '/api/disputes', valid())).json()) as Json).id as string
    const r = await t.json('POST', `/api/disputes/${id}/transition`, { to: 'CONFIRMED', note: 'skip review' }, t.adminHeaders)
    expect(r.status).toBe(409)
    const e = ((await r.json()) as Json).error
    expect(e.code).toBe('ILLEGAL_TRANSITION')
    expect(e.details).toEqual({ from: 'OPEN', to: 'CONFIRMED', allowed: ['UNDER_REVIEW', 'DISMISSED'] })
    const self = await t.json('POST', `/api/disputes/${id}/transition`, { to: 'OPEN', note: 'again' }, t.adminHeaders)
    expect(self.status).toBe(409)
    const d = (await (await t.app.request(`/api/disputes/${id}`)).json()) as Json
    expect(d.status).toBe('OPEN')
    expect(d.history).toHaveLength(1)
  })

  it('CORRECTED requires a later published run; the disputed run itself is never changed', async () => {
    const created = await t.json('POST', '/api/disputes', valid({ runId: RUN_1, vendorId: HALCYON, target: { kind: 'GOAL', id: 'G6' } }))
    const id = ((await created.json()) as Json).id as string
    await t.json('POST', `/api/disputes/${id}/transition`, { to: 'UNDER_REVIEW', note: 'review' }, t.adminHeaders)
    const before = (await (await t.app.request(`/api/runs/${RUN_1}`)).json()) as Json
    const noRun = await t.json('POST', `/api/disputes/${id}/transition`, { to: 'CORRECTED', note: 'fixed' }, t.adminHeaders)
    expect(noRun.status).toBe(422)
    const sameRun = await t.json('POST', `/api/disputes/${id}/transition`, { to: 'CORRECTED', note: 'fixed', correctedInRunId: RUN_1 }, t.adminHeaders)
    expect(((await sameRun.json()) as Json).error.code).toBe('CORRECTED_RUN_NOT_LATER')
    const ok = await t.json('POST', `/api/disputes/${id}/transition`, { to: 'CORRECTED', note: 'fixed', correctedInRunId: RUN_2 }, t.adminHeaders)
    expect(ok.status).toBe(200)
    expect(((await ok.json()) as Json).history.at(-1).correctedInRunId).toBe(RUN_2)
    const after = (await (await t.app.request(`/api/runs/${RUN_1}`)).json()) as Json
    expect(after).toEqual(before)
    const stray = await t.json('POST', `/api/disputes/DSP-0001/transition`, { to: 'DISMISSED', note: 'n', correctedInRunId: RUN_2 }, t.adminHeaders)
    expect(stray.status).toBe(422)
  })

  it('transitions are admin only', async () => {
    const none = await t.json('POST', '/api/disputes/DSP-0001/transition', { to: 'UNDER_REVIEW', note: 'x' })
    expect(none.status).toBe(401)
    const wrong = await t.json('POST', '/api/disputes/DSP-0001/transition', { to: 'UNDER_REVIEW', note: 'x' }, { authorization: `Bearer ${ADMIN}x` })
    expect(wrong.status).toBe(401)
    expect((await t.json('POST', '/api/disputes/DSP-9999/transition', { to: 'UNDER_REVIEW', note: 'x' }, t.adminHeaders)).status).toBe(404)
  })

  it('lists and filters disputes; the active overlay follows status', async () => {
    const open = (await (await t.app.request(`/api/disputes?vendor=${NORTHWIND}&status=open`)).json()) as Json[]
    expect(open.every((d) => d.vendorId === NORTHWIND && d.status === 'OPEN')).toBe(true)
    const all = await t.app.request('/api/disputes?limit=2')
    expect(((await all.json()) as Json[]).length).toBe(2)
    expect(Number(all.headers.get('x-total-count'))).toBeGreaterThan(2)
    expect((await t.app.request('/api/disputes?status=MAYBE')).status).toBe(400)
    expect((await t.app.request('/api/disputes/DSP-0404')).status).toBe(404)
    expect((await t.app.request('/api/disputes/..%2Fx')).status).toBe(404)
  })
})

describe('the database enforces append-only history', () => {
  it('refuses UPDATE/DELETE of events, DELETE of disputes, edits of dispute fields and status drift', () => {
    const store = new Store(':memory:')
    const d = store.createDispute({
      vendorId: NORTHWIND,
      target: { kind: 'GOAL', id: 'G5' },
      runId: RUN_2,
      reason: 'OUTDATED_SOURCE',
      submitterRole: 'VENDOR',
      statement: 's',
      evidenceUrls: [],
      at: '2026-10-06T00:00:00Z',
      actor: 'submitter',
    })
    expect(() => store.unsafeExec("UPDATE dispute_events SET note = 'rewritten'")).toThrow(/append-only/)
    expect(() => store.unsafeExec('DELETE FROM dispute_events')).toThrow(/append-only/)
    expect(() => store.unsafeExec('DELETE FROM disputes')).toThrow(/never deleted/)
    expect(() => store.unsafeExec("UPDATE disputes SET statement = 'edited'")).toThrow(/only a dispute's status/)
    expect(() => store.unsafeExec("UPDATE disputes SET status = 'CONFIRMED'")).toThrow(/latest event/)
    expect(() =>
      store.unsafeExec(`INSERT INTO dispute_events (dispute_id, at, from_status, to_status, actor, note) VALUES ('${d.id}', 'x', 'OPEN', 'CORRECTED', 'a', 'n')`),
    ).toThrow(/illegal dispute transition/)
    expect(() => store.unsafeExec(`INSERT INTO dispute_events (dispute_id, at, from_status, to_status, actor, note) VALUES ('${d.id}', 'x', NULL, 'OPEN', 'a', 'n')`)).toThrow(
      /illegal dispute transition/,
    )
    expect(() => store.unsafeExec("DELETE FROM notebook_entries")).not.toThrow() // empty table: nothing to delete
    store.addNotebook({ title: 't', observation: 'o', createdAt: 'x', tags: [] })
    expect(() => store.unsafeExec('DELETE FROM notebook_entries')).toThrow(/append-only/)
    expect(store.getDispute(d.id)!.history).toHaveLength(1)
    store.close()
  })
})

describe('notebook', () => {
  const t = makeApp({ adminToken: ADMIN })
  afterAll(() => t.close())

  it('GET lists seeded entries; POST is admin only and validated', async () => {
    const list = (await (await t.app.request('/api/notebook')).json()) as Json[]
    expect(list.map((e) => e.id)).toEqual(['NB-0001'])
    expect((await t.json('POST', '/api/notebook', { title: 't', observation: 'o' })).status).toBe(401)
    const bad = await t.json('POST', '/api/notebook', { title: 't', observation: 'o', tags: ['Not A Tag'] }, t.adminHeaders)
    expect(bad.status).toBe(400)
    const r = await t.json('POST', '/api/notebook', { title: 'Shared CPE namespace', observation: `Two vendors use one namespace${cp(0x202e)}.`, vendorId: NORTHWIND, tags: ['identity'] }, t.adminHeaders)
    expect(r.status).toBe(201)
    const e = (await r.json()) as Json
    expect(e).toMatchObject({ id: 'NB-0002', observation: 'Two vendors use one namespace.', synthetic: false, vendorId: NORTHWIND })
    const byTag = (await (await t.app.request('/api/notebook?tag=identity')).json()) as Json[]
    expect(byTag.map((x) => x.id)).toEqual(['NB-0002'])
  })
})
