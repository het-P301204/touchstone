/**
 * "How was this calculated?" — for any metric of any vendor in any run:
 * metric, dataset, date range, query, records evaluated, numerator, formula
 * with numbers, sources, dataset/methodology versions, run id, confidence,
 * the evidence list, and a way to reproduce the run.
 */
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import { FlaskConical, MessageSquareWarning } from 'lucide-react'
import type { EvidenceItem, GoalAssessment, MetricValue, RunSummary, VendorDetail } from '@touchstone/core/model'
import { all, useSummary, useVendorDetail } from '../data/hooks.ts'
import { useUi } from '../state/ui.ts'
import type { MetricTarget } from '../state/ui.ts'
import { Drawer } from '../ui/Drawer.tsx'
import { Button } from '../ui/Button.tsx'
import { CopyText, KV } from '../ui/controls.tsx'
import { Load } from '../ui/States.tsx'
import { StateChip, StatusBadge } from '../ui/StatusBadge.tsx'
import { breakdownLabel, defOf, notMeasured, formatMetric, vendorName } from '../lib/vocab.ts'
import { INTERPRETATION } from '../lib/status.ts'
import { date, dateTime, minusDays, num, shortHash } from '../lib/format.ts'
import { cx } from '../lib/cx.ts'

/** Analysis window for a metric, derived from the methodology parameters (never guessed). */
export function dateRangeFor(metricId: string, summary: RunSummary): string {
  const asOf = summary.manifest.asOf
  const p = summary.methodology.parameters
  if (metricId.startsWith('cve.')) return `${date(minusDays(asOf, p.cveWindowDays))} → ${date(asOf)} (${p.cveWindowDays}-day window)`
  if (metricId.startsWith('g3.')) return `prior: ${date(minusDays(asOf, 730))} → ${date(minusDays(asOf, 365))} · latest: ${date(minusDays(asOf, 365))} → ${date(asOf)}`
  if (metricId.startsWith('vdp.')) return `policy as observed on or before ${date(asOf)}`
  return `as of ${date(asOf)}`
}

export function sourcesFor(evidence: EvidenceItem[], summary: RunSummary) {
  const ids = [...new Set(evidence.map((e) => e.sourceId))]
  return ids.map((id) => summary.sources.find((s) => s.id === id) ?? { id, title: id, url: '', publisher: '', attribution: '', family: 'CVE_PROGRAM' as const, retention: 'RAW' as const })
}

function Block({ label, children, mono = false }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p className="ts-eyebrow mb-1.5">{label}</p>
      <div className={cx('ts-ident rounded-[12px] border border-line bg-paper-2/60 px-3.5 py-3 text-[0.84rem] leading-relaxed text-ink', mono && 'font-mono text-[0.78rem]')}>{children}</div>
    </div>
  )
}

function MetricBody({ target, summary, detail }: { target: MetricTarget; summary: RunSummary; detail: VendorDetail }) {
  const navigate = useNavigate()
  const openEvidence = useUi((s) => s.openEvidence)
  const openMetric = useUi((s) => s.openMetric)
  const [showAll, setShowAll] = useState(false)
  const goal: GoalAssessment | undefined = detail.goals.find((g) => g.goalId === target.goalId) ?? detail.goals.find((g) => g.metrics.some((m) => m.metricId === target.metricId))
  const metric: MetricValue | undefined = goal?.metrics.find((m) => m.metricId === target.metricId)
  const def = defOf(summary, target.metricId)
  const evidence = useMemo(() => {
    if (!metric) return []
    const ids = new Set(metric.evidenceIds)
    return detail.evidence.filter((e) => ids.has(e.id) || (e.metricId === target.metricId && e.vendorId === target.vendorId))
  }, [detail, metric, target])
  if (!metric || !goal) {
    return <p className="text-sm text-ink-2">This run has no value for {target.metricId} for this vendor.</p>
  }
  const m = summary.manifest
  const counts = evidence.reduce<Record<string, number>>((acc, e) => ({ ...acc, [e.interpretation]: (acc[e.interpretation] ?? 0) + 1 }), {})
  const shown = showAll ? evidence : evidence.slice(0, 30)
  const sources = sourcesFor(evidence, summary)

  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          {metric.value === null ? (
            <p className="text-title-2 text-ink-2">{notMeasured(metric)}</p>
          ) : (
            <p className="ts-num text-[2.6rem] font-medium leading-none tracking-tight text-ink">{formatMetric(metric.value, def)}</p>
          )}
          {metric.value === null && <p className="mt-2 text-sm text-ink-3">A missing value is never shown as zero{metric.gap ? ` (gap code ${metric.gap})` : ''}.</p>}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge status={goal.status} size="sm" />
          <span className="rounded-chip bg-paper-2 px-2 py-1 font-mono text-[0.72rem] text-ink-2 ring-1 ring-inset ring-line">confidence {metric.confidence.toLowerCase()}</span>
        </div>
      </div>

      <Block label="Formula with numbers" mono>
        {metric.calculation || '—'}
      </Block>

      <KV
        rows={[
          ['Metric', <span className="font-mono text-[0.8rem]">{target.metricId}</span>],
          ['Vendor', vendorName(summary, target.vendorId)],
          ['Dataset', <span className="font-mono text-[0.8rem]">{m.datasetVersion} · {m.mode === 'DEMO' ? 'demo (synthetic)' : 'live'}</span>],
          ['Date range', dateRangeFor(target.metricId, summary)],
          ['Records evaluated', metric.denominator !== undefined ? <span className="ts-num">{num(metric.denominator)}{def?.denominatorLabel ? ` · ${def.denominatorLabel}` : ''}</span> : '—'],
          ['Numerator', metric.numerator !== undefined ? <span className="ts-num">{num(metric.numerator)}{def?.numeratorLabel ? ` · ${def.numeratorLabel}` : ''}</span> : '—'],
          ['Methodology', <span className="font-mono text-[0.8rem]">{m.methodologyVersion} (scoring {m.scoringVersion}, parser {m.parserVersion})</span>],
          ['Run', <span className="inline-flex items-center gap-1 font-mono text-[0.8rem]">{m.runId}<CopyText text={m.runId} label="Copy run id" /></span>],
          ['Outputs hash', <span className="inline-flex items-center gap-1 font-mono text-[0.8rem]">{shortHash(m.outputsHash, 20)}<CopyText text={m.outputsHash} label="Copy outputs hash" /></span>],
        ]}
      />

      <Block label="Query over the snapshot" mono>
        {metric.query || '—'}
      </Block>

      {def && (
        <div className="grid gap-4">
          <Block label="Formula">{def.formula}</Block>
          <Block label="Eligibility">{def.eligibility}</Block>
        </div>
      )}

      {metric.distribution && (
        <div>
          <p className="ts-eyebrow mb-2">Distribution</p>
          <div className="grid grid-cols-4 gap-2 text-center">
            {(
              [
                ['median', metric.distribution.median],
                ['p75', metric.distribution.p75],
                ['p95', metric.distribution.p95],
                ['n', metric.distribution.n],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="rounded-[12px] border border-line bg-surface-raised px-2 py-3">
                <p className="ts-num text-lg text-ink">{num(v, k === 'n' ? 0 : 1)}</p>
                <p className="ts-eyebrow mt-1">{k}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {metric.breakdown && Object.keys(metric.breakdown).length > 0 && (
        <div>
          <p className="ts-eyebrow mb-2">Breakdown</p>
          <table className="ts-tbl rounded-[12px] border border-line">
            <tbody>
              {Object.entries(metric.breakdown).map(([k, v]) => (
                <tr key={k}>
                  <td className="ts-ident font-mono text-[0.78rem] text-ink-2">{breakdownLabel(k)}</td>
                  <td className="ts-num text-right">{num(v, Number.isInteger(v) ? 0 : 1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {metric.confidenceReasons.length > 0 && (
        <div>
          <p className="ts-eyebrow mb-2">Why the confidence is {metric.confidence.toLowerCase()}</p>
          <ul className="list-disc space-y-1 pl-5 text-[0.84rem] text-ink-2">
            {metric.confidenceReasons.map((r) => (
              <li key={r}>{r}</li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <p className="ts-eyebrow mb-2">Sources</p>
        {sources.length ? (
          <ul className="space-y-2 text-[0.84rem]">
            {sources.map((s) => (
              <li key={s.id} className="min-w-0">
                <span className="font-semibold text-ink">{s.title}</span> <span className="font-mono text-[0.74rem] text-ink-3">{s.id}</span>
                {s.attribution && <span className="block text-[0.78rem] text-ink-3">{s.attribution}</span>}
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-[0.84rem] text-ink-3">No evidence items reference a source for this metric.</p>
        )}
      </div>

      <div>
        <div className="mb-2 flex flex-wrap items-baseline justify-between gap-2">
          <p className="ts-eyebrow">Evidence ({evidence.length})</p>
          <p className="flex flex-wrap gap-3 text-[0.75rem] text-ink-3">
            {Object.entries(counts).map(([k, v]) => (
              <span key={k}>
                {INTERPRETATION[k as keyof typeof INTERPRETATION]?.label ?? k} <span className="ts-num text-ink">{v}</span>
              </span>
            ))}
          </p>
        </div>
        {evidence.length === 0 ? (
          <p className="text-[0.84rem] text-ink-3">No evidence items. A metric without evidence has no value.</p>
        ) : (
          <ul className="divide-y divide-line overflow-hidden rounded-[12px] border border-line">
            {shown.map((e) => (
              <li key={e.id}>
                <button
                  type="button"
                  onClick={() => {
                    openMetric(null)
                    openEvidence({ vendorId: e.vendorId, runId: target.runId, evidenceId: e.id })
                  }}
                  className="flex w-full min-w-0 items-start gap-3 bg-surface-raised px-3.5 py-2.5 text-left transition-colors hover:bg-paper-2"
                >
                  <StateChip meta={INTERPRETATION[e.interpretation]} size="sm" className="mt-0.5 w-[7.6rem] shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="ts-ident block font-mono text-[0.78rem] text-ink">{e.subject}</span>
                    <span className="block text-[0.8rem] text-ink-2">{e.reading}</span>
                  </span>
                  <span className="hidden shrink-0 font-mono text-[0.7rem] text-ink-3 sm:block">{e.id}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
        {evidence.length > 30 && (
          <Button size="sm" variant="ghost" className="mt-2" onClick={() => setShowAll((s) => !s)}>
            {showAll ? 'Show the first 30' : `Show all ${evidence.length}`}
          </Button>
        )}
      </div>

      <div className="flex flex-wrap gap-2 border-t border-line pt-5">
        <Button
          variant="primary"
          icon={<FlaskConical />}
          onClick={() => {
            openMetric(null)
            navigate(`/app/runs?reproduce=${encodeURIComponent(target.runId)}`)
          }}
        >
          Reproduce this run
        </Button>
        <Button
          icon={<MessageSquareWarning />}
          onClick={() => {
            openMetric(null)
            navigate(`/app/disputes?vendor=${encodeURIComponent(target.vendorId)}&kind=METRIC&target=${encodeURIComponent(target.metricId)}&run=${encodeURIComponent(target.runId)}#new`)
          }}
        >
          Challenge this finding
        </Button>
      </div>
      <p className="text-[0.75rem] text-ink-3">Snapshots evaluated by this run: {m.snapshotIds.length}. Collected {dateTime(m.asOf)} or earlier.</p>
    </div>
  )
}

export function MetricDrawer({ target }: { target: MetricTarget | null }) {
  const openMetric = useUi((s) => s.openMetric)
  const [last, setLast] = useState<MetricTarget | null>(target)
  if (target && target !== last) setLast(target)
  const t = target ?? last
  const summary = useSummary(t?.runId ?? null)
  const detail = useVendorDetail(t?.vendorId ?? null, t?.runId ?? null)
  const both = all<[RunSummary, VendorDetail]>(summary, detail)
  const def = t && summary.status === 'ready' ? defOf(summary.data, t.metricId) : undefined
  return (
    <Drawer open={!!target} onClose={() => openMetric(null)} eyebrow="How was this calculated?" title={def?.name ?? t?.metricId ?? 'Metric'} width="lg">
      {t && (
        <Load value={both} what="the calculation">
          {([s, d]) => <MetricBody target={t} summary={s} detail={d} />}
        </Load>
      )}
    </Drawer>
  )
}
