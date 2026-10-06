import { useMemo, useState } from 'react'
import { Link } from 'react-router'
import type { HistorySeries, RunIndex, RunSummary } from '@touchstone/core/model'
import { all, useActiveSummary, useHistory } from '../../data/hooks.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { TrendChart } from '../../ui/charts.tsx'
import type { TrendSeries } from '../../ui/charts.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { Load } from '../../ui/States.tsx'
import { median } from '../../lib/history.ts'
import { METRIC_CHANGES_BY_VERSION } from '../../lib/core.ts'
import { defOf, formatMetric } from '../../lib/vocab.ts'
import { cx } from '../../lib/cx.ts'

const METRICS = ['cve.complete_records', 'cve.cwe_coverage', 'cve.cpe_coverage', 'vdp.criteria_met', 'cve.timely_issuance', 'cve.high_impact_with_cve', 'cve.enriched_only', 'cve.publication_latency']
const TONES: TrendSeries['tone'][] = ['sage', 'iris', 'marigold']

function Sparkline({ s, yMax }: { s: HistorySeries; yMax: number }) {
  const W = 120
  const H = 34
  const n = s.points.length
  const x = (i: number) => (n === 1 ? W / 2 : (i / (n - 1)) * (W - 6) + 3)
  const y = (v: number) => H - 3 - (Math.max(0, Math.min(yMax, v)) / yMax) * (H - 6)
  const segs: string[] = []
  let cur = ''
  s.points.forEach((p, i) => {
    if (p.value === null) {
      if (cur) segs.push(cur)
      cur = ''
    } else cur += `${cur ? 'L' : 'M'}${x(i)},${y(p.value)} `
  })
  if (cur) segs.push(cur)
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-9 w-full" aria-hidden="true">
      {segs.map((d, i) => (
        <path key={i} d={d} fill="none" stroke="rgb(var(--ink-2))" strokeWidth={1.6} strokeLinejoin="round" />
      ))}
      {s.points.map((p, i) => (p.value === null ? <circle key={i} cx={x(i)} cy={H - 3} r={2} fill="none" stroke="rgb(var(--ink-3))" strokeDasharray="1.5 1.5" /> : null))}
    </svg>
  )
}

function View({ summary, index, history }: { summary: RunSummary; index: RunIndex; history: HistorySeries[] }) {
  const [metricId, setMetricId] = useState(METRICS[0]!)
  const [picked, setPicked] = useState<string[]>([])
  const def = defOf(summary, metricId)
  const isDays = def?.unit === 'DAYS'
  const series = useMemo(() => history.filter((h) => h.metricId === metricId), [history, metricId])
  const runs = index.runs
  const medianSeries: TrendSeries = {
    key: 'median',
    label: 'Median across vendors with a value',
    tone: 'stone',
    dashed: true,
    points: runs.map((r) => ({
      label: r.datasetVersion.slice(0, 7),
      methodologyVersion: r.methodologyVersion,
      value: median(series.map((s) => s.points.find((p) => p.runId === r.runId)?.value).filter((v): v is number => v !== null && v !== undefined)),
    })),
  }
  const yMax = isDays ? Math.max(10, ...series.flatMap((s) => s.points.map((p) => p.value ?? 0))) : 100
  const vendorSeries: TrendSeries[] = picked.map((id, i) => {
    const s = series.find((x) => x.vendorId === id)
    return {
      key: id,
      label: summary.vendors.find((v) => v.vendor.id === id)?.vendor.canonicalName ?? id,
      tone: TONES[i % TONES.length]!,
      points: runs.map((r) => ({ label: r.datasetVersion.slice(0, 7), methodologyVersion: r.methodologyVersion, value: s?.points.find((p) => p.runId === r.runId)?.value ?? null })),
    }
  })
  const changedIn = Object.entries(METRIC_CHANGES_BY_VERSION)
    .filter(([, ids]) => ids.includes(metricId))
    .map(([v]) => v)
  return (
    <>
      <PageHeader
        eyebrow="Trends"
        title="Across the published runs"
        lede="Each point is the figure that run published under its own methodology version. Where a version changed the metric’s formula, values either side of the line are not comparable."
        actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined}
      />
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <label className="flex min-w-0 max-w-full items-center gap-2 text-[0.84rem] text-ink-2">
          Metric
          <select className="ts-select min-w-0 flex-1" value={metricId} onChange={(e) => setMetricId(e.target.value)}>
            {METRICS.map((m) => (
              <option key={m} value={m}>
                {defOf(summary, m)?.name ?? m}
              </option>
            ))}
          </select>
        </label>
      </div>
      <Panel
        title={def?.name ?? metricId}
        eyebrow={metricId}
        description={changedIn.length ? `The formula changed in methodology ${changedIn.join(', ')}: compare within a version only.` : 'The formula has not changed across the published versions.'}
      >
        <TrendChart series={[medianSeries, ...vendorSeries]} yMax={yMax} yLabel={isDays ? 'days' : '%'} ariaLabel={`${def?.name ?? metricId} across runs`} />
        <p className="mt-3 text-[0.78rem] text-ink-3">Select up to three vendors below to draw them against the median.</p>
      </Panel>
      <ul className="mt-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
        {summary.vendors.map((v) => {
          const s = series.find((x) => x.vendorId === v.vendor.id)
          const last = s?.points.at(-1)?.value ?? null
          const on = picked.includes(v.vendor.id)
          return (
            <li key={v.vendor.id} className={cx('ts-card p-3.5 transition-colors', on && 'border-ink/60')}>
              <div className="flex items-start justify-between gap-2">
                <Link to={`/app/vendors/${v.vendor.id}`} className="ts-ident min-w-0 text-[0.84rem] font-semibold text-ink hover:underline">
                  {v.vendor.canonicalName}
                </Link>
                <span className="ts-num shrink-0 text-[0.8rem] text-ink-2">{last === null ? <span className="font-sans text-[0.74rem] text-ink-3">not measured</span> : formatMetric(last, def)}</span>
              </div>
              {s ? <Sparkline s={s} yMax={yMax} /> : <p className="py-2 text-[0.78rem] text-ink-3">No history for this metric.</p>}
              <label className="mt-1 flex items-center gap-2 text-[0.75rem] text-ink-2">
                <input
                  type="checkbox"
                  checked={on}
                  disabled={!on && picked.length >= 3}
                  onChange={() => setPicked((p) => (on ? p.filter((x) => x !== v.vendor.id) : [...p, v.vendor.id]))}
                  className="size-3.5 accent-[rgb(var(--ink))]"
                />
                Draw on chart
              </label>
            </li>
          )
        })}
      </ul>
    </>
  )
}

export function Trends() {
  const active = useActiveSummary()
  const history = useHistory()
  const both = all<[{ summary: RunSummary; index: RunIndex }, HistorySeries[]]>(active, history)
  return <Load value={both} what="history">{([a, h]) => <View summary={a.summary} index={a.index} history={h} />}</Load>
}
