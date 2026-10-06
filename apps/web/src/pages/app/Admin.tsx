/**
 * Administration. Shown in navigation only when the API reports an enabled
 * admin surface. Refresh the dataset and review disputes: each transition is
 * one the API allows for the dispute's current status, carries a note, and is
 * appended to the dispute's audit history.
 */
import { useId, useState } from 'react'
import type { FormEvent } from 'react'
import { Link } from 'react-router'
import type { DisputeStatus, RunIndex } from '@touchstone/core/model'
import { invalidate, useActiveSummary, useDisputes, useRunIndex, useSourceInfo } from '../../data/hooks.ts'
import { getSource } from '../../data/source.ts'
import type { DisputeView } from '../../data/source.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { Button } from '../../ui/Button.tsx'
import { Disclosure, Field } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { RefreshPipeline } from '../../features/RefreshPipeline.tsx'
import { DISPUTE_STATUS, TONE_CLASSES } from '../../lib/status.ts'
import { DISPUTE_REASON_LABEL } from '../../lib/vocab.ts'
import { getAdminToken } from '../../lib/admin.ts'
import { dateTime } from '../../lib/format.ts'
import { cx } from '../../lib/cx.ts'

const ACTION_LABEL: Record<DisputeStatus, string> = {
  OPEN: 'Reopen',
  UNDER_REVIEW: 'Start review',
  CONFIRMED: 'Confirm',
  CORRECTED: 'Correct',
  DISMISSED: 'Dismiss',
}

const ACTION_HELP: Record<DisputeStatus, string> = {
  OPEN: '',
  UNDER_REVIEW: 'A reviewer is checking the evidence.',
  CONFIRMED: 'The original finding stands.',
  CORRECTED: 'A later run carries the corrected result. The disputed run is never changed.',
  DISMISSED: 'Closed without change.',
}

function Review({ d, index, onDone }: { d: DisputeView; index: RunIndex; onDone: (msg: string) => void }) {
  const ids = useId()
  const [allowed, setAllowed] = useState<DisputeStatus[] | null>(null)
  const [to, setTo] = useState<DisputeStatus | null>(null)
  const [note, setNote] = useState('')
  const [runId, setRunId] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [done, setDone] = useState<string | null>(null)
  const order = index.runs.map((r) => r.runId)
  const laterRuns = index.runs.filter((r) => order.indexOf(r.runId) > order.indexOf(d.runId))

  const load = async () => {
    if (allowed) return
    try {
      const src = await getSource()
      if (!src.disputeDetail) return
      const detail = await src.disputeDetail(d.id)
      setAllowed(detail.allowedTransitions)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!to) return
    if (note.trim().length < 5) {
      setError('A note is required: say what was checked and why.')
      return
    }
    if (to === 'CORRECTED' && !runId) {
      setError('Choose the later run that carries the corrected result.')
      return
    }
    const token = getAdminToken()
    if (!token) {
      setError('No admin token for this tab. Add it under Settings.')
      return
    }
    setBusy(true)
    try {
      const src = await getSource()
      if (!src.transitionDispute) throw new Error('This data source cannot review disputes.')
      const updated = await src.transitionDispute(d.id, { to, note, ...(to === 'CORRECTED' ? { correctedInRunId: runId } : {}) }, token)
      const msg = `${d.id} is now ${DISPUTE_STATUS[updated.status].label.toLowerCase()}. The step is recorded in its audit history.`
      setDone(msg)
      onDone(msg)
      setAllowed(null)
      setTo(null)
      setNote('')
      invalidate('disputes')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  const st = DISPUTE_STATUS[d.status]
  return (
    <li className="ts-card p-4">
      <div onClickCapture={() => void load()} onFocusCapture={() => void load()}>
        <Disclosure
          summary={
            <span className="flex min-w-0 flex-wrap items-center gap-x-3 gap-y-1">
              <span className="font-mono text-[0.8rem] font-semibold text-ink">{d.id}</span>
              <span className={cx('rounded-chip px-2 py-0.5 text-[0.74rem] font-semibold ring-1 ring-inset', TONE_CLASSES[st.tone].chip)}>{st.label}</span>
              <span className="ts-ident min-w-0 text-[0.82rem] text-ink-2">
                {DISPUTE_REASON_LABEL[d.reason]} · {d.vendorId} · {d.target.kind.toLowerCase()} <span className="font-mono">{d.target.id}</span>
              </span>
            </span>
          }
        >
          <div className="mt-4 space-y-4 border-t border-line pt-4">
            <blockquote className="ts-ident border-l-2 border-line-strong pl-3 text-[0.86rem] text-ink">{d.statement}</blockquote>
            <ol className="space-y-1 text-[0.78rem] text-ink-2">
              {d.history.map((h, i) => (
                <li key={i}>
                  <span className="font-mono text-ink-3">{dateTime(h.at)}</span> · {DISPUTE_STATUS[h.to].label} · {h.actor} · {h.note}
                </li>
              ))}
            </ol>
            {allowed === null && !error ? (
              <p className="text-[0.8rem] text-ink-3">Loading the allowed transitions…</p>
            ) : allowed && allowed.length === 0 ? (
              <p className="text-[0.84rem] text-ink-2">This dispute is closed. Its history is kept; nothing further can change it.</p>
            ) : allowed ? (
              <form onSubmit={submit} className="space-y-3" noValidate>
                <fieldset>
                  <legend className="mb-2 text-[0.82rem] font-semibold text-ink">Next step</legend>
                  <div className="flex flex-wrap gap-2">
                    {allowed.map((a) => (
                      <Button key={a} size="sm" variant={to === a ? 'primary' : 'secondary'} aria-pressed={to === a} onClick={() => setTo(a)}>
                        {ACTION_LABEL[a]}
                      </Button>
                    ))}
                  </div>
                  {to && <p className="mt-2 text-[0.78rem] text-ink-3">{ACTION_HELP[to]}</p>}
                </fieldset>
                {to === 'CORRECTED' && (
                  <Field label="Corrected in run" htmlFor={`${ids}-run`} hint="Only runs published after the disputed run are offered.">
                    <select id={`${ids}-run`} className="ts-select w-full" value={runId} onChange={(e) => setRunId(e.target.value)}>
                      <option value="">Choose a run…</option>
                      {laterRuns.map((r) => (
                        <option key={r.runId} value={r.runId}>
                          {r.runId}
                        </option>
                      ))}
                    </select>
                  </Field>
                )}
                {to && (
                  <Field label="Note (required)" htmlFor={`${ids}-note`} hint="Recorded in the audit history.">
                    <textarea id={`${ids}-note`} className="ts-input h-24 py-2" maxLength={2000} value={note} onChange={(e) => setNote(e.target.value)} />
                  </Field>
                )}
                {to && (
                  <Button type="submit" variant="primary" size="sm" disabled={busy}>
                    {busy ? 'Recording' : `${ACTION_LABEL[to]} ${d.id}`}
                  </Button>
                )}
              </form>
            ) : null}
            {error && (
              <p role="alert" className="text-[0.84rem] text-vermilion-ink">
                {error}
              </p>
            )}
            {done && (
              <p role="status" className="text-[0.84rem] text-sage-ink">
                {done}
              </p>
            )}
          </div>
        </Disclosure>
      </div>
    </li>
  )
}

export function Admin() {
  const info = useSourceInfo()
  const active = useActiveSummary()
  const disputes = useDisputes()
  const index = useRunIndex()
  const [last, setLast] = useState<string | null>(null)
  if (info.status !== 'ready') return null
  if (info.data.kind !== 'api' || !info.data.adminEnabled) {
    return (
      <>
        <PageHeader eyebrow="Administration" title="Administration" />
        <EmptyState title={info.data.kind === 'api' ? 'Administration is disabled on this server' : 'Review happens on the API deployment'}>
          {info.data.kind === 'api' ? (
            <p>Set TOUCHSTONE_ADMIN_TOKEN on the server to enable refresh and dispute review.</p>
          ) : (
            <p>
              This static demo has no server, so disputes cannot be reviewed here. On an API deployment with TOUCHSTONE_ADMIN_TOKEN set, a reviewer moves each dispute through
              Open → Under review → Confirmed, Corrected or Dismissed from this page, and every step is recorded. Challenges you submit in this browser stay in the{' '}
              <Link to="/app/disputes" className="ts-link">
                dispute log
              </Link>
              .
            </p>
          )}
        </EmptyState>
      </>
    )
  }
  return (
    <>
      <PageHeader eyebrow="Administration" title="Administration" lede="Refresh the dataset and review disputes. Every action is recorded by the API." />
      {!getAdminToken() && (
        <p className="mb-5 text-[0.86rem] text-marigold-ink">
          No admin token for this tab. <Link to="/app/settings" className="ts-link">Add it in Settings</Link>.
        </p>
      )}
      <div className="grid gap-6">
        <Load value={active} what="the run">
          {({ summary }) => (
            <Panel title="Refresh" eyebrow="Pipeline">
              <RefreshPipeline manifest={summary.manifest} />
            </Panel>
          )}
        </Load>
        <Load value={disputes} what="disputes">
          {(list) => {
            const activeList = list.filter((d) => d.status === 'OPEN' || d.status === 'UNDER_REVIEW')
            const closed = list.filter((d) => !(d.status === 'OPEN' || d.status === 'UNDER_REVIEW'))
            return (
              <Panel title="Dispute review" eyebrow={`${activeList.length} active · ${closed.length} closed`} description="Only the transitions the dispute’s current status allows are offered. A note is required for each.">
                {last && (
                  <p role="status" className="mb-4 rounded-[12px] border border-sage/40 bg-sage/10 px-4 py-2.5 text-[0.84rem] text-sage-ink">
                    {last}
                  </p>
                )}
                {index.status === 'ready' && (
                  <>
                    {activeList.length === 0 && <p className="text-[0.84rem] text-ink-3">No dispute is waiting for review.</p>}
                    <ul className="space-y-2">
                      {activeList.map((d) => (
                        <Review key={`${d.id}-${d.status}`} d={d} index={index.data} onDone={setLast} />
                      ))}
                    </ul>
                    {closed.length > 0 && (
                      <>
                        <p className="ts-eyebrow mb-2 mt-6">Closed</p>
                        <ul className="space-y-2">
                          {closed.map((d) => (
                            <Review key={`${d.id}-${d.status}`} d={d} index={index.data} onDone={setLast} />
                          ))}
                        </ul>
                      </>
                    )}
                  </>
                )}
              </Panel>
            )
          }}
        </Load>
      </div>
    </>
  )
}
