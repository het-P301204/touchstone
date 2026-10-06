import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router'
import { Search } from 'lucide-react'
import type { EvidenceInterpretation, RunSummary, VendorDetail } from '@touchstone/core/model'
import { useActiveSummary, useAllDetails } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import { PageHeader } from '../../ui/Panel.tsx'
import { Button } from '../../ui/Button.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { StateChip } from '../../ui/StatusBadge.tsx'
import { StackBar } from '../../ui/charts.tsx'
import { INTERPRETATION } from '../../lib/status.ts'
import { date } from '../../lib/format.ts'
import { defOf, vendorName } from '../../lib/vocab.ts'

const PAGE = 50

function Ledger({ summary, details, runId }: { summary: RunSummary; details: VendorDetail[]; runId: string }) {
  const openEvidence = useUi((s) => s.openEvidence)
  const [params, setParams] = useSearchParams()
  const [q, setQ] = useState('')
  const [page, setPage] = useState(0)
  const vendor = params.get('vendor') ?? 'all'
  const metric = params.get('metric') ?? 'all'
  const source = params.get('source') ?? 'all'
  const interp = params.get('interpretation') ?? 'all'
  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params)
    if (v === 'all') next.delete(k)
    else next.set(k, v)
    setParams(next, { replace: true })
    setPage(0)
  }
  const all = useMemo(() => details.flatMap((d) => d.evidence), [details])
  const metrics = useMemo(() => [...new Set(all.map((e) => e.metricId))].sort(), [all])
  const sources = useMemo(() => [...new Set(all.map((e) => e.sourceId.replace(/^vendor\.[^.]+\./, 'vendor.*.')))].sort(), [all])
  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return all.filter((e) => {
      if (vendor !== 'all' && e.vendorId !== vendor) return false
      if (metric !== 'all' && e.metricId !== metric) return false
      if (source !== 'all' && e.sourceId.replace(/^vendor\.[^.]+\./, 'vendor.*.') !== source) return false
      if (interp !== 'all' && e.interpretation !== interp) return false
      if (needle && !`${e.id} ${e.subject} ${e.reading}`.toLowerCase().includes(needle)) return false
      return true
    })
  }, [all, q, vendor, metric, source, interp])
  const counts = (Object.keys(INTERPRETATION) as EvidenceInterpretation[]).map((k) => ({ k, n: filtered.filter((e) => e.interpretation === k).length }))
  const shown = filtered.slice(page * PAGE, page * PAGE + PAGE)
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE))
  return (
    <>
      <div className="mb-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-5">
        <label className="relative min-w-0 sm:col-span-2 xl:col-span-1">
          <span className="sr-only">Search evidence id, subject or reading</span>
          <Search aria-hidden="true" className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-ink-3" />
          <input className="ts-input pl-9" placeholder="Evidence id, subject, reading" value={q} onChange={(e) => (setQ(e.target.value), setPage(0))} />
        </label>
        <select className="ts-select w-full" aria-label="Vendor" value={vendor} onChange={(e) => set('vendor', e.target.value)}>
          <option value="all">All vendors</option>
          {summary.vendors.map((v) => (
            <option key={v.vendor.id} value={v.vendor.id}>
              {v.vendor.canonicalName}
            </option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Metric" value={metric} onChange={(e) => set('metric', e.target.value)}>
          <option value="all">All metrics</option>
          {metrics.map((m) => (
            <option key={m} value={m}>
              {defOf(summary, m)?.name ?? m}
            </option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Source" value={source} onChange={(e) => set('source', e.target.value)}>
          <option value="all">All sources</option>
          {sources.map((s) => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <select className="ts-select w-full" aria-label="Interpretation" value={interp} onChange={(e) => set('interpretation', e.target.value)}>
          <option value="all">Any interpretation</option>
          {(Object.keys(INTERPRETATION) as EvidenceInterpretation[]).map((k) => (
            <option key={k} value={k}>
              {INTERPRETATION[k].label}
            </option>
          ))}
        </select>
      </div>
      <div className="ts-panel mb-4 p-5">
        <p className="mb-2 text-[0.8rem] text-ink-3" aria-live="polite">
          {filtered.length.toLocaleString('en-US')} of {all.length.toLocaleString('en-US')} evidence items
        </p>
        <StackBar
          parts={counts.map(({ k, n }) => ({ key: k, label: INTERPRETATION[k].label, value: n, tone: INTERPRETATION[k].tone, dashed: k === 'EXCLUDED', hatch: k === 'CONTEXT' }))}
        />
      </div>
      {filtered.length === 0 ? (
        <EmptyState title="No evidence matches these filters">Clear a filter to see more.</EmptyState>
      ) : (
        <ul className="divide-y divide-line overflow-hidden rounded-panel border border-line bg-surface shadow-soft">
          {shown.map((e) => (
            <li key={`${e.vendorId}-${e.id}`}>
              <button
                type="button"
                onClick={() => openEvidence({ vendorId: e.vendorId, runId, evidenceId: e.id })}
                className="grid w-full min-w-0 gap-2 px-4 py-3 text-left transition-colors hover:bg-paper-2/60 md:grid-cols-[8rem_minmax(0,1.1fr)_minmax(0,1.6fr)_9rem] md:items-center md:gap-4 sm:px-5"
              >
                <StateChip meta={INTERPRETATION[e.interpretation]} size="sm" className="w-fit" />
                <span className="min-w-0">
                  <span className="ts-ident block font-mono text-[0.8rem] font-semibold text-ink">{e.subject}</span>
                  <span className="ts-ident block text-[0.76rem] text-ink-3">
                    {vendorName(summary, e.vendorId)} · {defOf(summary, e.metricId)?.name ?? e.metricId}
                  </span>
                </span>
                <span className="min-w-0 text-[0.82rem] text-ink-2">{e.reading}</span>
                <span className="min-w-0 text-[0.72rem] text-ink-3 md:text-right">
                  <span className="block font-mono">{e.id}</span>
                  <span className="block">{date(e.collectedAt)}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-4 flex items-center justify-between gap-3 text-[0.82rem] text-ink-2">
        <span>
          Page {page + 1} of {pages}
        </span>
        <div className="flex gap-2">
          <Button size="sm" disabled={page === 0} onClick={() => setPage((p) => p - 1)}>
            Previous
          </Button>
          <Button size="sm" disabled={page >= pages - 1} onClick={() => setPage((p) => p + 1)}>
            Next
          </Button>
        </div>
      </div>
    </>
  )
}

export function EvidenceLedger() {
  const active = useActiveSummary()
  const runId = active.status === 'ready' ? active.data.runId : null
  const ids = active.status === 'ready' ? active.data.summary.vendors.map((v) => v.vendor.id) : null
  const details = useAllDetails(runId, ids)
  return (
    <Load value={active} what="the run">
      {({ summary, index, runId: rid }) => (
        <>
          <PageHeader
            eyebrow="Evidence ledger"
            title="Evidence"
            lede={`Every record and document that fed a figure in run ${summary.manifest.runId}, with the snapshot it was read from and how it was interpreted.`}
            actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
          />
          <Load value={details} what="evidence">
            {(d) => <Ledger summary={summary} details={d} runId={rid} />}
          </Load>
        </>
      )}
    </Load>
  )
}
