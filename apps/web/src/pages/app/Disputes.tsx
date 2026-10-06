/**
 * Disputes: challenge a finding, and the audit log of every challenge. The
 * original result and the dispute status are always shown separately.
 */
import { useId, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useSearchParams } from 'react-router'
import { ArrowRight, MessageSquareWarning } from 'lucide-react'
import type { Dispute, DisputeReason, RunSummary } from '@touchstone/core/model'
import { invalidate, useActiveSummary, useDisputes, useSourceInfo } from '../../data/hooks.ts'
import { getSource } from '../../data/source.ts'
import type { DisputeView, NewDispute } from '../../data/source.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { Button } from '../../ui/Button.tsx'
import { DemoLabel, Field } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { StatusBadge } from '../../ui/StatusBadge.tsx'
import { DISPUTE_STATUS, TONE_CLASSES } from '../../lib/status.ts'
import { DISPUTE_REASON_LABEL, defOf, formatMetric, metricOf, vendorName } from '../../lib/vocab.ts'
import { dateTime } from '../../lib/format.ts'
import { cx } from '../../lib/cx.ts'

const KINDS: Dispute['target']['kind'][] = ['GOAL', 'METRIC', 'EVIDENCE', 'CVE', 'IDENTITY']
const MAX = 2000

function OriginalResult({ d, summary }: { d: DisputeView; summary: RunSummary }) {
  const v = summary.vendors.find((x) => x.vendor.id === d.vendorId)
  if (!v) return <span className="text-ink-3">Vendor not in the active run.</span>
  if (d.target.kind === 'GOAL') {
    const g = v.goals.find((x) => x.goalId === d.target.id)
    return g ? <StatusBadge status={g.status} size="sm" /> : <span className="text-ink-3">—</span>
  }
  if (d.target.kind === 'METRIC') {
    const m = metricOf(v, d.target.id)
    return m ? (
      <span className="ts-num text-[0.84rem] text-ink">
        {formatMetric(m.metric.value, defOf(summary, d.target.id))} <span className="font-sans text-[0.75rem] text-ink-3">{m.metric.calculation}</span>
      </span>
    ) : (
      <span className="text-ink-3">—</span>
    )
  }
  return (
    <span className="text-[0.8rem] text-ink-2">
      {d.target.kind.toLowerCase()} <span className="font-mono">{d.target.id}</span> as published in run {d.runId}
    </span>
  )
}

function DisputeCard({ d, summary }: { d: DisputeView; summary: RunSummary }) {
  const st = DISPUTE_STATUS[d.status]
  return (
    <article className="ts-panel p-5 sm:p-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-mono text-[0.78rem] text-ink-3">
            {d.id} · {dateTime(d.createdAt)}
          </p>
          <h3 className="mt-1 text-title-3 text-ink">
            {DISPUTE_REASON_LABEL[d.reason]} ·{' '}
            <Link to={`/app/vendors/${d.vendorId}`} className="ts-ident hover:underline">
              {vendorName(summary, d.vendorId)}
            </Link>
          </h3>
          <p className="mt-0.5 text-[0.8rem] text-ink-2">
            Challenges {d.target.kind.toLowerCase()} <span className="font-mono">{d.target.id}</span> · submitted by {d.submitterRole.toLowerCase()} · run {d.runId}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {d.localOnly && <span className="rounded-chip border border-dashed border-marigold-ink/50 bg-marigold/10 px-2 py-0.5 text-[0.72rem] font-semibold text-marigold-ink">Saved in this browser only (static demo)</span>}
          {d.synthetic && !d.localOnly && <DemoLabel />}
        </div>
      </header>
      <div className="mt-4 grid gap-3 sm:grid-cols-2">
        <div className="min-w-0 rounded-[12px] border border-line bg-surface-raised p-3.5">
          <p className="ts-eyebrow mb-1.5">Original result</p>
          <OriginalResult d={d} summary={summary} />
          <p className="mt-1.5 text-[0.72rem] text-ink-3">Unchanged by the dispute.</p>
        </div>
        <div className="min-w-0 rounded-[12px] border border-line bg-surface-raised p-3.5">
          <p className="ts-eyebrow mb-1.5">Dispute status</p>
          <span className={cx('inline-flex rounded-chip px-2 py-0.5 text-[0.78rem] font-semibold ring-1 ring-inset', TONE_CLASSES[st.tone].chip)}>{st.label}</span>
          <p className="mt-1.5 text-[0.72rem] text-ink-3">{st.description}</p>
        </div>
      </div>
      <blockquote className="ts-ident mt-4 border-l-2 border-line-strong pl-4 text-[0.88rem] leading-relaxed text-ink">{d.statement}</blockquote>
      {d.evidenceUrls.length > 0 && (
        <ul className="mt-2 space-y-0.5 pl-4 text-[0.78rem]">
          {d.evidenceUrls.map((u) => (
            <li key={u} className="ts-ident font-mono text-ink-2">
              {u}
            </li>
          ))}
        </ul>
      )}
      <div className="mt-4">
        <p className="ts-eyebrow mb-2">Audit history</p>
        <ol className="space-y-1.5 border-l border-line pl-4">
          {d.history.map((h, i) => (
            <li key={i} className="text-[0.8rem] text-ink-2">
              <span className="font-mono text-[0.72rem] text-ink-3">{dateTime(h.at)}</span> · {h.from ? `${DISPUTE_STATUS[h.from].label} → ` : ''}
              <span className="font-semibold text-ink">{DISPUTE_STATUS[h.to].label}</span> · {h.actor} · {h.note}
              {h.correctedInRunId && <span> · corrected in run {h.correctedInRunId}</span>}
            </li>
          ))}
        </ol>
      </div>
    </article>
  )
}

function NewDisputeForm({ summary, runId }: { summary: RunSummary; runId: string }) {
  const [params] = useSearchParams()
  const info = useSourceInfo()
  const ids = useId()
  const [vendorId, setVendorId] = useState(params.get('vendor') ?? summary.vendors[0]?.vendor.id ?? '')
  const [kind, setKind] = useState<Dispute['target']['kind']>((params.get('kind') as Dispute['target']['kind']) ?? 'GOAL')
  const [targetId, setTargetId] = useState(params.get('target') ?? 'G6')
  const [reason, setReason] = useState<DisputeReason>('INCORRECT_VENDOR_ATTRIBUTION')
  const [role, setRole] = useState<Dispute['submitterRole']>('RESEARCHER')
  const [statement, setStatement] = useState('')
  const [urls, setUrls] = useState('')
  const [busy, setBusy] = useState(false)
  const [done, setDone] = useState<DisputeView | null>(null)
  const [error, setError] = useState<string | null>(null)
  const isStatic = info.status === 'ready' && info.data.kind === 'static'
  const v = summary.vendors.find((x) => x.vendor.id === vendorId)
  const metricIds = v ? v.goals.flatMap((g) => g.metrics.map((m) => m.metricId)) : []

  const submit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)
    if (statement.trim().length < 20) {
      setError('Describe the problem in at least 20 characters, so a reviewer can check it.')
      return
    }
    if (!targetId.trim()) {
      setError('Name what is being challenged.')
      return
    }
    setBusy(true)
    try {
      const src = await getSource()
      const input: NewDispute = {
        vendorId,
        target: { kind, id: targetId.trim() },
        runId,
        reason,
        submitterRole: role,
        statement,
        evidenceUrls: urls.split(/\s+/).filter(Boolean),
      }
      const created = await src.submitDispute(input)
      setDone(created)
      setStatement('')
      setUrls('')
      invalidate('disputes')
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <Panel id="new" className="scroll-mt-24" eyebrow="Contestability" title="Challenge This Finding" description="Name what is wrong and why. The original result stays published; your challenge is shown beside it with its own status.">
      <form onSubmit={submit} className="grid gap-4 md:grid-cols-2" noValidate>
        <Field label="Vendor" htmlFor={`${ids}-v`}>
          <select id={`${ids}-v`} className="ts-select w-full" value={vendorId} onChange={(e) => setVendorId(e.target.value)}>
            {summary.vendors.map((x) => (
              <option key={x.vendor.id} value={x.vendor.id}>
                {x.vendor.canonicalName}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Reason" htmlFor={`${ids}-r`}>
          <select id={`${ids}-r`} className="ts-select w-full" value={reason} onChange={(e) => setReason(e.target.value as DisputeReason)}>
            {(Object.keys(DISPUTE_REASON_LABEL) as DisputeReason[]).map((r) => (
              <option key={r} value={r}>
                {DISPUTE_REASON_LABEL[r]}
              </option>
            ))}
          </select>
        </Field>
        <Field label="What is challenged" htmlFor={`${ids}-k`}>
          <select
            id={`${ids}-k`}
            className="ts-select w-full"
            value={kind}
            onChange={(e) => {
              const k = e.target.value as Dispute['target']['kind']
              setKind(k)
              setTargetId(k === 'GOAL' ? 'G6' : k === 'METRIC' ? (metricIds[0] ?? '') : '')
            }}
          >
            {KINDS.map((k) => (
              <option key={k} value={k}>
                {k.charAt(0) + k.slice(1).toLowerCase()}
              </option>
            ))}
          </select>
        </Field>
        <Field label="Which one" htmlFor={`${ids}-t`} hint={kind === 'CVE' ? 'A CVE id, e.g. DEMO-2026-1135' : kind === 'EVIDENCE' ? 'An evidence id, e.g. EV-0364262463' : undefined}>
          {kind === 'GOAL' ? (
            <select id={`${ids}-t`} className="ts-select w-full" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              {summary.goals.map((g) => (
                <option key={g.id} value={g.id}>
                  {g.id} {g.name}
                </option>
              ))}
            </select>
          ) : kind === 'METRIC' ? (
            <select id={`${ids}-t`} className="ts-select w-full" value={targetId} onChange={(e) => setTargetId(e.target.value)}>
              {metricIds.map((m) => (
                <option key={m} value={m}>
                  {defOf(summary, m)?.name ?? m}
                </option>
              ))}
            </select>
          ) : (
            <input id={`${ids}-t`} className="ts-input" maxLength={200} value={targetId} onChange={(e) => setTargetId(e.target.value)} />
          )}
        </Field>
        <Field label="You are" htmlFor={`${ids}-role`}>
          <select id={`${ids}-role`} className="ts-select w-full" value={role} onChange={(e) => setRole(e.target.value as Dispute['submitterRole'])}>
            <option value="VENDOR">The vendor</option>
            <option value="RESEARCHER">A researcher</option>
            <option value="OTHER">Someone else</option>
          </select>
        </Field>
        <Field label="Supporting links (optional)" htmlFor={`${ids}-u`} hint="https links only, separated by spaces or new lines; up to 5.">
          <input id={`${ids}-u`} className="ts-input" value={urls} onChange={(e) => setUrls(e.target.value)} placeholder="https://" />
        </Field>
        <div className="md:col-span-2">
          <Field label="Statement" htmlFor={`${ids}-s`} hint={`${statement.length} / ${MAX} characters. Invisible and bidirectional control characters are removed.`}>
            <textarea id={`${ids}-s`} className="ts-input h-32 py-2.5" maxLength={MAX} value={statement} onChange={(e) => setStatement(e.target.value)} />
          </Field>
        </div>
        <div className="flex flex-wrap items-center gap-3 md:col-span-2">
          <Button type="submit" variant="primary" icon={<MessageSquareWarning />} disabled={busy}>
            {busy ? 'Submitting' : 'Submit challenge'}
          </Button>
          {isStatic && <span className="text-[0.8rem] text-marigold-ink">Static demo: a challenge is saved in this browser only.</span>}
          {error && (
            <p role="alert" className="w-full text-[0.84rem] text-vermilion-ink">
              {error}
            </p>
          )}
          {done && (
            <p role="status" className="w-full text-[0.84rem] text-sage-ink">
              Challenge {done.id} recorded with status Open{done.localOnly ? ' — saved in this browser only (static demo)' : ''}. It appears in the log below.
            </p>
          )}
        </div>
      </form>
    </Panel>
  )
}

export function Disputes() {
  const active = useActiveSummary()
  const disputes = useDisputes()
  return (
    <Load value={active} what="the run">
      {({ summary, runId, index }) => (
        <>
          <PageHeader
            eyebrow="Disputes"
            title="Every finding can be challenged"
            lede="A dispute never overwrites an observation. The original result and the dispute status are shown separately, and every transition is kept."
            actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
          />
          <ol aria-label="Dispute workflow" className="mb-6 flex flex-wrap items-center gap-2 text-[0.8rem]">
            {(['OPEN', 'UNDER_REVIEW'] as const).map((s) => (
              <li key={s} className="flex items-center gap-2">
                <span className={cx('rounded-chip px-2.5 py-1 font-semibold ring-1 ring-inset', TONE_CLASSES[DISPUTE_STATUS[s].tone].chip)}>{DISPUTE_STATUS[s].label}</span>
                <ArrowRight aria-hidden="true" className="size-4 text-ink-3" />
              </li>
            ))}
            {(['CONFIRMED', 'CORRECTED', 'DISMISSED'] as const).map((s) => (
              <li key={s}>
                <span className={cx('rounded-chip px-2.5 py-1 font-semibold ring-1 ring-inset', TONE_CLASSES[DISPUTE_STATUS[s].tone].chip)} title={DISPUTE_STATUS[s].description}>
                  {DISPUTE_STATUS[s].label}
                </span>
              </li>
            ))}
          </ol>
          <div className="space-y-6">
            <NewDisputeForm summary={summary} runId={runId} />
            <Load value={disputes} what="disputes">
              {(list) =>
                list.length === 0 ? (
                  <EmptyState title="No disputes yet">Use the form above to challenge a finding.</EmptyState>
                ) : (
                  <section aria-label="Dispute log" className="space-y-4">
                    <h2 className="text-title-2 text-ink">Log ({list.length})</h2>
                    {[...list].reverse().map((d) => (
                      <DisputeCard key={d.id} d={d} summary={summary} />
                    ))}
                  </section>
                )
              }
            </Load>
          </div>
        </>
      )}
    </Load>
  )
}
