/**
 * Goal 6: CVE record quality (CNA-supplied fields only), gap breakdown,
 * CNA vs third-party enrichment, issuance timeliness and latency
 * distribution, and the vendor's CVE records.
 */
import { Link } from 'react-router'
import type { Advisory, CveRecord, MetricValue, VendorDetail, VendorSummary } from '@touchstone/core/model'
import { Panel } from '../../ui/Panel.tsx'
import { HBar, StackBar } from '../../ui/charts.tsx'
import type { StackPart } from '../../ui/charts.tsx'
import { breakdownLabel, metricOf, notMeasured } from '../../lib/vocab.ts'
import { date, days, num, pct } from '../../lib/format.ts'
import { GAP_LABEL } from '../../lib/vocab.ts'
import { HowCalculated } from '../figures.tsx'
import type { Tone } from '../../lib/status.ts'

const GAP_TONE: Record<string, Tone> = { NOT_PROVIDED: 'stone', PLACEHOLDER: 'marigold', MALFORMED: 'vermilion', NOT_FOUND: 'plum', PARSER_FAILURE: 'vermilion', NOT_APPLICABLE: 'stone' }

function gapParts(m: MetricValue | undefined, presentLabel: string): StackPart[] {
  if (!m || m.denominator === undefined) return []
  const parts: StackPart[] = [{ key: 'present', label: presentLabel, value: m.numerator ?? 0, tone: 'sage' }]
  for (const [k, v] of Object.entries(m.breakdown ?? {})) {
    if (!k.startsWith('gap.') || v <= 0) continue
    const gap = k.slice(4)
    parts.push({ key: k, label: GAP_LABEL[gap] ?? gap, value: v, tone: GAP_TONE[gap] ?? 'stone', dashed: gap === 'NOT_PROVIDED' })
  }
  return parts
}

/** Per-advisory latency (days) for high-impact advisories, from the vendor's own records. */
export function advisoryLatencies(detail: VendorDetail, highImpact: string[]): { advisory: Advisory; days: number | null }[] {
  const byId = new Map(detail.cves.map((c) => [c.id, c]))
  return detail.advisories
    .filter((a) => highImpact.includes(a.severity))
    .map((a) => {
      const published = a.cveIds.map((id) => byId.get(id)?.datePublished).filter((d): d is string => !!d)
      if (!published.length) return { advisory: a, days: null }
      const latest = published.sort().at(-1)!
      return { advisory: a, days: Math.round((Date.parse(latest) - Date.parse(a.publishedAt)) / 86_400_000) }
    })
}

function LatencyStrip({ points, tolerance }: { points: number[]; tolerance: number }) {
  if (!points.length) return null
  const min = Math.min(-5, ...points)
  const max = Math.max(tolerance + 5, ...points)
  const x = (d: number) => ((d - min) / (max - min)) * 100
  // Beeswarm: equal values stack upward, then into a second column.
  const seen = new Map<number, number>()
  const stacked = [...points].sort((a, b) => a - b).map((p) => {
    const k = seen.get(p) ?? 0
    seen.set(p, k + 1)
    return { p, k }
  })
  return (
    <figure className="min-w-0">
      <div className="relative h-14 rounded-[12px] bg-paper-2/70 ring-1 ring-inset ring-line" role="img" aria-label={`Publication latency per high-impact advisory: ${points.join(', ')} days`}>
        <span aria-hidden="true" className="absolute inset-y-0 bg-sage/15" style={{ left: `${x(min)}%`, width: `${x(tolerance) - x(min)}%` }} />
        <span aria-hidden="true" className="absolute inset-y-2 w-px bg-ink-3" style={{ left: `${x(0)}%` }} />
        {stacked.map(({ p, k }, i) => (
          <span
            key={i}
            aria-hidden="true"
            className="absolute size-2 -translate-x-1/2 rounded-full bg-ink"
            style={{ left: `${x(p)}%`, bottom: `${6 + (k % 5) * 9}px`, marginLeft: `${Math.floor(k / 5) * 9}px` }}
            title={`${p} days`}
          />
        ))}
      </div>
      <figcaption className="mt-1.5 flex justify-between font-mono text-[0.7rem] text-ink-3">
        <span>{min} d</span>
        <span>0 = advisory date · shaded ≤ {tolerance} d tolerance</span>
        <span>{max} d</span>
      </figcaption>
    </figure>
  )
}

export function CveQuality({ v, detail, runId, highImpact, tolerance }: { v: VendorSummary; detail: VendorDetail | null; runId: string; highImpact: string[]; tolerance: number }) {
  const get = (id: string) => metricOf(v, id)?.metric
  const bench = (id: string) => v.benchmarks.find((b) => b.metricId === id && b.peerGroup === 'ALL_SIGNATORIES')
  const bars = [
    { id: 'cve.complete_records', label: 'Complete records (CWE + CPE in namespace)' },
    { id: 'cve.cwe_coverage', label: 'CNA-supplied CWE' },
    { id: 'cve.cpe_coverage', label: 'CNA-supplied CPE' },
    { id: 'cve.cpe_namespace_consistency', label: 'CPE in the vendor’s namespace' },
  ]
  const cwe = get('cve.cwe_coverage')
  const cpe = get('cve.cpe_coverage')
  const enriched = get('cve.enriched_only')
  const timely = get('cve.timely_issuance')
  const latency = get('cve.publication_latency')
  const goalId = metricOf(v, 'cve.cwe_coverage')?.goal.goalId ?? 'G6'
  const cweFromAdp = enriched?.breakdown?.['cwe_from_adp'] ?? 0
  const cpeFromAdp = enriched?.breakdown?.['cpe_from_adp'] ?? 0
  const den = cwe?.denominator ?? 0
  const lat = detail ? advisoryLatencies(detail, highImpact) : []
  const timelyParts: StackPart[] = timely?.breakdown
    ? (['timely', 'late', 'no_cve_listed', 'cve_not_in_snapshot'] as const)
        .filter((k) => (timely.breakdown?.[k] ?? 0) > 0)
        .map((k) => ({ key: k, label: breakdownLabel(k), value: timely.breakdown![k]!, tone: k === 'timely' ? 'sage' : k === 'late' ? 'marigold' : 'stone', dashed: k !== 'timely' && k !== 'late' }))
    : []
  const cves = detail ? [...detail.cves].sort((a, b) => (b.datePublished ?? '').localeCompare(a.datePublished ?? '')) : []

  return (
    <Panel
      id="cve"
      className="scroll-mt-24"
      eyebrow="Goal 6"
      title="CVE record quality and issuance"
      description="Only data in the manufacturer’s own CNA container counts. Third-party enrichment (CISA-ADP, NVD) is reported beside it and never credited."
    >
      <div className="grid gap-8 lg:grid-cols-2">
        <div className="min-w-0 space-y-5">
          <p className="ts-eyebrow">Record quality · {cwe?.denominator !== undefined ? `${num(cwe.denominator)} eligible records` : 'eligible records'}</p>
          {bars.map((b) => {
            const m = get(b.id)
            const bm = bench(b.id)
            return (
              <div key={b.id} className="flex min-w-0 items-end gap-2">
                <HBar
                  className="flex-1"
                  value={m?.value ?? null}
                  label={b.label}
                  valueLabel={m?.value === null || !m ? <span className="text-ink-3">{notMeasured(m)}</span> : pct(m.value)}
                  marker={bm?.peerMedian ?? null}
                  markerLabel={bm ? `Peer median ${pct(bm.peerMedian)}` : undefined}
                  tone="sage"
                />
                <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={goalId} metricId={b.id} iconOnly />
              </div>
            )
          })}
          <p className="flex items-center gap-2 text-[0.75rem] text-ink-3">
            <span aria-hidden="true" className="inline-block h-3 w-0.5 rounded-full bg-ink" /> peer median (all signatories in the run)
          </p>
        </div>

        <div className="min-w-0 space-y-6">
          <div>
            <p className="ts-eyebrow mb-2">Why records are incomplete · CWE</p>
            {gapParts(cwe, 'Usable CNA CWE').length ? <StackBar parts={gapParts(cwe, 'Usable CNA CWE')} /> : <p className="text-[0.84rem] text-ink-3">Not measured.</p>}
          </div>
          <div>
            <p className="ts-eyebrow mb-2">Why records are incomplete · CPE</p>
            {gapParts(cpe, 'Well-formed CNA CPE').length ? <StackBar parts={gapParts(cpe, 'Well-formed CNA CPE')} /> : <p className="text-[0.84rem] text-ink-3">Not measured.</p>}
          </div>
          <div className="rounded-card border border-iris/35 bg-iris/5 p-4">
            <div className="flex items-start justify-between gap-2">
              <p className="text-[0.86rem] font-semibold text-ink">CNA vs third-party enrichment</p>
              {enriched && <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={goalId} metricId="cve.enriched_only" iconOnly />}
            </div>
            {den > 0 && cwe ? (
              <div className="mt-3 space-y-3">
                <HBar value={cwe.value} label="CWE from the vendor (CNA)" valueLabel={pct(cwe.value)} tone="sage" height="h-2" />
                <HBar value={((cwe.numerator ?? 0) + cweFromAdp) / den * 100} label="CWE if third-party data were counted" valueLabel={pct(((cwe.numerator ?? 0) + cweFromAdp) / den * 100)} tone="iris" height="h-2" />
                <p className="text-[0.8rem] leading-relaxed text-ink-2">
                  {enriched?.value !== null && enriched?.value !== undefined ? `${pct(enriched.value)} of eligible records` : 'Some records'} look complete only because a third party
                  supplied the missing field ({num(cweFromAdp)} CWE, {num(cpeFromAdp)} CPE). That data is context: the pledge asks the manufacturer to include it.
                </p>
              </div>
            ) : (
              <p className="mt-2 text-[0.84rem] text-ink-3">No eligible records to compare.</p>
            )}
          </div>
        </div>
      </div>

      <div className="mt-8 grid gap-8 border-t border-line pt-6 lg:grid-cols-2">
        <div className="min-w-0 space-y-4">
          <div className="flex items-start justify-between gap-2">
            <p className="ts-eyebrow">Issuance timeliness · high-impact advisories</p>
            {timely && <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={goalId} metricId="cve.timely_issuance" iconOnly />}
          </div>
          <p className="ts-num text-[1.8rem] font-medium leading-none text-ink">
            {timely?.value === null || !timely ? <span className="font-sans text-[1.05rem] font-semibold text-ink-2">{notMeasured(timely)}</span> : pct(timely.value)}
          </p>
          {timely?.calculation && <p className="font-mono text-[0.75rem] text-ink-3">{timely.calculation}</p>}
          {timelyParts.length > 0 && <StackBar parts={timelyParts} />}
          <p className="text-[0.78rem] text-ink-3">Tolerance: a CVE published within {tolerance} day{tolerance === 1 ? '' : 's'} after the advisory. A TOUCHSTONE methodology parameter, not a CISA threshold.</p>
        </div>
        <div className="min-w-0 space-y-4">
          <div className="flex items-start justify-between gap-2">
            <p className="ts-eyebrow">Latency distribution</p>
            {latency && <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={goalId} metricId="cve.publication_latency" iconOnly />}
          </div>
          {latency?.distribution ? (
            <div className="grid grid-cols-3 gap-2">
              {(['median', 'p75', 'p95'] as const).map((k) => (
                <div key={k} className="rounded-[12px] border border-line bg-surface-raised px-3 py-2.5">
                  <p className="ts-eyebrow">{k}</p>
                  <p className="ts-num mt-1 text-lg text-ink">{days(latency.distribution![k])}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[0.84rem] text-ink-3">{notMeasured(latency)}</p>
          )}
          {latency?.value !== null && latency !== undefined && <LatencyStrip points={lat.map((l) => l.days).filter((d): d is number => d !== null)} tolerance={tolerance} />}
        </div>
      </div>

      <div className="mt-8 border-t border-line pt-6">
        <div className="mb-3 flex flex-wrap items-baseline justify-between gap-2">
          <p className="ts-eyebrow">Related CVE records ({detail ? detail.cves.length : '…'})</p>
          <Link to={`/app/cves?vendor=${encodeURIComponent(v.vendor.id)}`} className="ts-link text-[0.82rem]">
            Open in the CVE explorer
          </Link>
        </div>
        {detail && <CveMiniTable cves={cves.slice(0, 8)} />}
      </div>
    </Panel>
  )
}

export function CveMiniTable({ cves }: { cves: CveRecord[] }) {
  return (
    <div className="ts-scroll-thin overflow-x-auto rounded-card border border-line">
      <table className="ts-tbl min-w-[36rem]">
        <thead>
          <tr>
            <th scope="col">CVE</th>
            <th scope="col">Published</th>
            <th scope="col">CNA CWE</th>
            <th scope="col">CNA CPE</th>
            <th scope="col">ADP adds</th>
          </tr>
        </thead>
        <tbody>
          {cves.map((c) => {
            const cwe = c.cna.cwes.find((w) => w.id && !w.placeholder) ?? c.cna.cwes[0]
            const cpeOk = c.cna.cpes.some((p) => p.wellFormed)
            const adpAdds = c.adp.some((a) => a.cwes.length || a.cpes.length)
            return (
              <tr key={c.id}>
                <td>
                  <Link to={`/app/cves/${encodeURIComponent(c.id)}`} className="ts-ident font-mono text-[0.8rem] font-semibold text-ink hover:underline">
                    {c.id}
                  </Link>
                </td>
                <td className="ts-num text-[0.8rem] text-ink-2">{date(c.datePublished)}</td>
                <td className="font-mono text-[0.78rem]">{cwe ? <span className={cwe.placeholder ? 'text-marigold-ink' : 'text-ink'}>{cwe.raw}</span> : <span className="text-ink-3">not provided</span>}</td>
                <td className="text-[0.8rem]">{c.cna.cpes.length === 0 ? <span className="text-ink-3">not provided</span> : cpeOk ? 'well-formed' : <span className="text-vermilion-ink">malformed</span>}</td>
                <td className="text-[0.8rem] text-ink-2">{adpAdds ? c.adp.map((a) => a.provider).join(', ') : '—'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}
