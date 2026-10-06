/**
 * Vendor context panels: benchmarks, observed deviations, history, vendor
 * claims, identity, data freshness, disputes, the CISO brief and the
 * researcher view.
 */
import { Link } from 'react-router'
import { AlertTriangle, MessageSquareWarning } from 'lucide-react'
import type { HistorySeries, RunSummary, SourceFreshness, VendorDetail, VendorSummary } from '@touchstone/core/model'
import { Panel } from '../../ui/Panel.tsx'
import { TrendChart } from '../../ui/charts.tsx'
import type { TrendSeries } from '../../ui/charts.tsx'
import { ExtLink, KV } from '../../ui/controls.tsx'
import { EmptyState } from '../../ui/States.tsx'
import { FreshnessBadge, StateChip } from '../../ui/StatusBadge.tsx'
import { DISPUTE_STATUS, GOAL_STATUS, POSITION, TONE_CLASSES } from '../../lib/status.ts'
import { ALIAS_KIND_LABEL, CATEGORY_LABEL, DISPUTE_REASON_LABEL, defOf, formatMetric, metricOf } from '../../lib/vocab.ts'
import { ageLabel, date, dateTime } from '../../lib/format.ts'
import { cx } from '../../lib/cx.ts'
import { HowCalculated, isVendorSource } from '../figures.tsx'
import type { DisputeView } from '../../data/source.ts'
import { ButtonLink } from '../../ui/Button.tsx'
import { GOALS } from '../../lib/core.ts'

export function Benchmarks({ summary, v }: { summary: RunSummary; v: VendorSummary }) {
  return (
    <Panel
      id="benchmarks"
      className="scroll-mt-24"
      eyebrow="Benchmarks"
      title="Against its own history and its peers"
      description="Positions describe one observable metric at a time. A position is stated only when enough peers have a value."
      flush
    >
      <div className="ts-scroll-thin overflow-x-auto">
        <table className="ts-tbl min-w-[40rem]">
          <thead>
            <tr>
              <th scope="col">Metric</th>
              <th scope="col" className="text-right">
                Current
              </th>
              <th scope="col" className="text-right">
                Own historical median
              </th>
              <th scope="col">Peer group</th>
              <th scope="col" className="text-right">
                Peer median
              </th>
              <th scope="col">Reading</th>
            </tr>
          </thead>
          <tbody>
            {v.benchmarks.map((b) => {
              const def = defOf(summary, b.metricId)
              const pos = POSITION[b.position]
              return (
                <tr key={`${b.metricId}-${b.peerGroup}`}>
                  <td className="min-w-[12rem] text-[0.84rem] font-semibold text-ink">{def?.name ?? b.metricId}</td>
                  <td className="ts-num text-right text-[0.84rem]">{formatMetric(b.current, def)}</td>
                  <td className="ts-num text-right text-[0.84rem] text-ink-2">{formatMetric(b.vendorHistoricalMedian, def)}</td>
                  <td className="text-[0.78rem] text-ink-2">{b.peerGroup === 'ALL_SIGNATORIES' ? 'All signatories' : (CATEGORY_LABEL as Record<string, string>)[b.peerGroup] ?? b.peerGroup}</td>
                  <td className="ts-num text-right text-[0.84rem] text-ink-2">
                    {formatMetric(b.peerMedian, def)} <span className="text-[0.7rem] text-ink-3">n={b.peerCount}</span>
                  </td>
                  <td className="min-w-[14rem] text-[0.8rem]">
                    <span className={cx('inline-flex items-center gap-1.5', TONE_CLASSES[pos.tone].text)}>
                      <span aria-hidden="true" className={cx('size-1.5 rounded-full', TONE_CLASSES[pos.tone].dot)} />
                      {b.wording || pos.label}
                    </span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </Panel>
  )
}

export function Anomalies({ v, runId }: { v: VendorSummary; runId: string }) {
  if (v.anomalies.length === 0) return null
  return (
    <Panel id="deviations" className="scroll-mt-24" eyebrow="Observed deviation" title={`${v.anomalies.length} observed deviation${v.anomalies.length === 1 ? '' : 's'}`} description="A rule fired. Each deviation names the rule and threshold; it is a prompt to look, not a judgement.">
      <ul className="space-y-3">
        {v.anomalies.map((a) => {
          const goalId = a.metricId ? metricOf(v, a.metricId)?.goal.goalId : undefined
          return (
            <li key={a.id} className="rounded-card border border-line bg-surface-raised p-4">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <p className="flex min-w-0 items-start gap-2 font-semibold text-ink">
                  <AlertTriangle aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-vermilion-ink" />
                  <span className="min-w-0">{a.headline}</span>
                </p>
                <span className="rounded-chip bg-paper-2 px-2 py-0.5 font-mono text-[0.68rem] text-ink-2 ring-1 ring-inset ring-line">{a.kind}</span>
              </div>
              <p className="mt-2 text-[0.84rem] leading-relaxed text-ink-2">{a.detail}</p>
              <p className="mt-2 font-mono text-[0.72rem] text-ink-3">Rule: {a.rule}</p>
              {a.metricId && goalId && <HowCalculated className="mt-2" vendorId={v.vendor.id} runId={runId} goalId={goalId} metricId={a.metricId} />}
            </li>
          )
        })}
      </ul>
    </Panel>
  )
}

const HISTORY_METRICS: { id: string; label: string; tone: TrendSeries['tone'] }[] = [
  { id: 'cve.complete_records', label: 'Complete CVE records', tone: 'sage' },
  { id: 'vdp.criteria_met', label: 'VDP criteria met', tone: 'iris' },
  { id: 'cve.timely_issuance', label: 'Timely issuance', tone: 'marigold' },
]

export function seriesFor(history: HistorySeries[], vendorId: string, metricId: string): HistorySeries | undefined {
  return history.find((h) => h.vendorId === vendorId && h.metricId === metricId)
}

export function HistoryPanel({ history, v }: { history: HistorySeries[]; v: VendorSummary }) {
  const series: TrendSeries[] = HISTORY_METRICS.map((m) => {
    const s = seriesFor(history, v.vendor.id, m.id)
    return {
      key: m.id,
      label: m.label,
      tone: m.tone,
      points: (s?.points ?? []).map((p) => ({ label: p.datasetVersion.slice(0, 7), value: p.value, methodologyVersion: p.methodologyVersion, runId: p.runId })),
    }
  }).filter((s) => s.points.length > 0)
  return (
    <Panel id="history" className="scroll-mt-24" eyebrow="History" title="Across the published runs" description="Each point is the figure that run published under its own methodology version. A version change is marked; values either side of it may not be comparable.">
      {series.length ? <TrendChart series={series} ariaLabel={`History of ${series.map((s) => s.label).join(', ')} for ${v.vendor.canonicalName}`} /> : <EmptyState title="No history yet">This vendor appears in only one run.</EmptyState>}
    </Panel>
  )
}

export function Claims({ v }: { v: VendorSummary }) {
  const claims = v.vendor.claims
  return (
    <Panel eyebrow="Vendor claims" title="Self-reported — not independently verifiable" description="The vendor’s own statements about pledge progress. Shown for context; never counted as evidence.">
      {claims.length === 0 ? (
        <p className="text-[0.84rem] text-ink-3">No self-reported progress statements are on record.</p>
      ) : (
        <ul className="space-y-3">
          {claims.map((c, i) => (
            <li key={i} className="ts-hatch-soft rounded-card border border-dashed border-iris/40 p-4">
              <p className="font-mono text-[0.72rem] text-ink-3">
                {c.goalId} · {GOALS.find((g) => g.id === c.goalId)?.name}
                {c.publishedOn ? ` · ${date(c.publishedOn)}` : ''}
              </p>
              <p className="mt-1.5 text-[0.88rem] text-ink">“{c.summary}”</p>
              {c.url && <ExtLink href={c.url} className="mt-1.5 text-[0.78rem]" />}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

export function Identity({ summary, v }: { summary: RunSummary; v: VendorSummary }) {
  const conflicts = summary.identityConflicts.filter((c) => c.vendorIds.includes(v.vendor.id))
  return (
    <Panel id="identity" className="scroll-mt-24" eyebrow="Identity" title="Who this vendor is in each source" description="Every name that links a record to this vendor is an explicit, evidenced mapping. Two identities are never merged silently." flush>
      <div className="px-5 pb-4 sm:px-6">
        <KV
          rows={[
            ['Canonical name', v.vendor.canonicalName],
            ['Vendor id', <span className="font-mono text-[0.8rem]">{v.vendor.id}</span>],
            ['Domains', v.vendor.domains.length ? <span className="font-mono text-[0.8rem]">{v.vendor.domains.join(', ')}</span> : '—'],
          ]}
        />
      </div>
      <div className="ts-scroll-thin overflow-x-auto border-t border-line">
        <table className="ts-tbl min-w-[40rem]">
          <thead>
            <tr>
              <th scope="col">Kind</th>
              <th scope="col">Alias</th>
              <th scope="col">Confidence</th>
              <th scope="col">Evidence</th>
            </tr>
          </thead>
          <tbody>
            {v.vendor.aliases.map((a, i) => (
              <tr key={i}>
                <td className="whitespace-nowrap text-[0.8rem] text-ink-2">{ALIAS_KIND_LABEL[a.kind]}</td>
                <td className="ts-ident max-w-[16rem] font-mono text-[0.78rem] text-ink">{a.value}</td>
                <td className="text-[0.78rem]">{a.confidence.toLowerCase()}</td>
                <td className="max-w-[22rem] text-[0.78rem] text-ink-2">
                  {a.evidence.map((e, j) => (
                    <span key={j} className="block">
                      {e.statement} {e.url && <ExtLink href={e.url}>source</ExtLink>}
                    </span>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {conflicts.length > 0 && (
        <div className="space-y-2 border-t border-line px-5 py-4 sm:px-6">
          <p className="ts-eyebrow">Identity conflicts</p>
          {conflicts.map((c) => (
            <p key={c.id} className="text-[0.84rem] text-ink-2">
              <span className="font-semibold text-vermilion-ink">{c.kind.replace(/_/g, ' ').toLowerCase()}</span> on “<span className="font-mono text-[0.78rem]">{c.value}</span>” with{' '}
              {c.vendorIds.filter((id) => id !== v.vendor.id).join(', ')}. {c.affectedRecordIds.length} records excluded until resolved. {c.note}
            </p>
          ))}
        </div>
      )}
    </Panel>
  )
}

export function freshnessNote(f: SourceFreshness, summary: RunSummary): string | null {
  if (f.lastStatus === 'FAILED' && f.usedSnapshotId) {
    const snap = summary.snapshots.find((s) => s.id === f.usedSnapshotId)
    return `Refresh failed — using previous verified snapshot ${date(snap?.fetchedAt ?? f.lastSuccessAt)}`
  }
  if (f.lastStatus === 'FAILED') return 'Refresh failed — no earlier snapshot available'
  return f.note ?? null
}

export function Freshness({ summary, v }: { summary: RunSummary; v: VendorSummary }) {
  const own = summary.freshness.filter((f) => isVendorSource(f.sourceId, v.vendor.id))
  const shared = summary.freshness.filter((f) => !f.sourceId.startsWith('vendor.') && (f.family === 'CVE_PROGRAM' || f.family === 'CISA_PLEDGE' || f.family === 'NVD'))
  const rows = [...own, ...shared]
  return (
    <Panel id="freshness" className="scroll-mt-24" eyebrow="Data freshness" title="How current each source is" description="Freshness is computed from the last successful fetch, never from the last attempt." flush>
      <ul className="divide-y divide-line border-t border-line">
        {rows.map((f) => {
          const note = freshnessNote(f, summary)
          return (
            <li key={f.sourceId} className="grid gap-2 px-5 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center sm:px-6">
              <div className="min-w-0">
                <p className="text-[0.86rem] font-semibold text-ink">{f.title}</p>
                <p className="ts-ident font-mono text-[0.72rem] text-ink-3">
                  {f.sourceId} · last success {dateTime(f.lastSuccessAt)}
                  {f.ageHours !== undefined ? ` · age ${ageLabel(f.ageHours)}` : ''}
                </p>
                {note && <p className={cx('mt-1 text-[0.8rem]', f.lastStatus === 'FAILED' ? 'text-marigold-ink' : 'text-ink-2')}>{note}</p>}
              </div>
              <FreshnessBadge state={f.state} />
            </li>
          )
        })}
      </ul>
    </Panel>
  )
}

export function VendorDisputes({ disputes, v, runId }: { disputes: DisputeView[]; v: VendorSummary; runId: string }) {
  const mine = disputes.filter((d) => d.vendorId === v.vendor.id)
  return (
    <Panel
      id="disputes"
      className="scroll-mt-24"
      eyebrow="Disputes"
      title="Challenges to these findings"
      actions={
        <ButtonLink to={`/app/disputes?vendor=${encodeURIComponent(v.vendor.id)}&run=${encodeURIComponent(runId)}#new`} size="sm" icon={<MessageSquareWarning />}>
          Challenge This Finding
        </ButtonLink>
      }
    >
      {mine.length === 0 ? (
        <p className="text-[0.84rem] text-ink-3">No disputes on record for this vendor.</p>
      ) : (
        <ul className="space-y-2">
          {mine.map((d) => (
            <li key={d.id} className="flex flex-wrap items-center justify-between gap-2 rounded-[12px] border border-line bg-surface-raised px-4 py-3">
              <span className="min-w-0">
                <span className="font-mono text-[0.78rem] text-ink">{d.id}</span>{' '}
                <span className="text-[0.84rem] text-ink-2">
                  {DISPUTE_REASON_LABEL[d.reason]} · {d.target.kind.toLowerCase()} <span className="font-mono text-[0.76rem]">{d.target.id}</span>
                </span>
                {d.localOnly && <span className="ml-2 text-[0.72rem] text-marigold-ink">Saved in this browser only (static demo)</span>}
              </span>
              <span className={cx('rounded-chip px-2 py-0.5 text-[0.74rem] font-semibold ring-1 ring-inset', TONE_CLASSES[DISPUTE_STATUS[d.status].tone].chip)}>{DISPUTE_STATUS[d.status].label}</span>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

/** CISO brief: what was measured, what is unverified, which way it moved, and what to ask. */
export function CisoBrief({ summary, v, history }: { summary: RunSummary; v: VendorSummary; history: HistorySeries[] | null }) {
  const measured = v.goals.filter((g) => g.status !== 'NOT_EXTERNALLY_VERIFIABLE')
  const unverified = v.goals.filter((g) => g.status === 'NOT_EXTERNALLY_VERIFIABLE' || g.status === 'NOT_VERIFIED')
  const trend = (metricId: string) => {
    const s = history ? seriesFor(history, v.vendor.id, metricId) : undefined
    const pts = (s?.points ?? []).filter((p) => p.value !== null)
    if (pts.length < 2) return 'not enough history'
    const a = pts[pts.length - 2]!
    const b = pts[pts.length - 1]!
    if (a.methodologyVersion !== b.methodologyVersion) return `methodology changed (${a.methodologyVersion} → ${b.methodologyVersion}); not compared`
    const d = (b.value ?? 0) - (a.value ?? 0)
    return d === 0 ? 'unchanged since the previous run' : `${d > 0 ? 'up' : 'down'} ${Math.abs(d).toFixed(1)} points since the previous run`
  }
  const questions: string[] = []
  const vdp = v.vdp
  if (!vdp?.policy.found) questions.push('Where is your vulnerability disclosure policy published, and does it authorize good-faith testing?')
  if (vdp?.prohibitive.length) questions.push('Your policy contains language that discourages disclosure or threatens legal action. Is that intended?')
  const enriched = metricOf(v, 'cve.enriched_only')?.metric
  if (enriched?.value) questions.push('Some of your CVE records rely on third-party enrichment for CWE or CPE. Will your CNA records carry these fields directly?')
  const timely = metricOf(v, 'cve.timely_issuance')?.metric
  if (timely?.value === null) questions.push('Do you publish machine-readable advisories (CSAF) so issuance timeliness can be measured?')
  else if (timely && timely.value < 100) questions.push('Some critical or high advisories had no CVE within the tolerance. What is your CVE issuance process?')
  questions.push('What evidence can you share for MFA adoption, default-password reduction, patch uptake and customer logging (Goals 1, 2, 4, 7)?')
  return (
    <section aria-labelledby="ciso-title" className="ts-panel overflow-hidden">
      <div className="border-b border-line bg-paper-2/60 px-6 py-4">
        <p className="ts-eyebrow">CISO view</p>
        <h2 id="ciso-title" className="text-title-3 text-ink">
          Brief: {v.vendor.canonicalName}
        </h2>
      </div>
      <div className="grid gap-6 p-6 lg:grid-cols-3">
        <div className="min-w-0">
          <p className="ts-eyebrow mb-2">Measured evidence</p>
          <ul className="space-y-1.5 text-[0.84rem]">
            {measured.map((g) => (
              <li key={g.goalId} className="flex items-center justify-between gap-2">
                <span className="min-w-0 truncate text-ink-2">
                  {g.goalId} {summary.goals.find((x) => x.id === g.goalId)?.shortName}
                </span>
                <StateChip meta={GOAL_STATUS[g.status]} size="sm" />
              </li>
            ))}
          </ul>
          <p className="mt-3 text-[0.78rem] text-ink-3">Trend, complete CVE records: {trend('cve.complete_records')}. VDP: {trend('vdp.criteria_met')}.</p>
        </div>
        <div className="min-w-0">
          <p className="ts-eyebrow mb-2">Unverified areas</p>
          <ul className="space-y-1.5 text-[0.84rem] text-ink-2">
            {unverified.map((g) => (
              <li key={g.goalId}>
                {g.goalId} {summary.goals.find((x) => x.id === g.goalId)?.name} — {GOAL_STATUS[g.status].label.toLowerCase()}
              </li>
            ))}
          </ul>
        </div>
        <div className="min-w-0">
          <p className="ts-eyebrow mb-2">Questions to ask the vendor</p>
          <ol className="list-decimal space-y-1.5 pl-5 text-[0.84rem] text-ink">
            {questions.map((q) => (
              <li key={q}>{q}</li>
            ))}
          </ol>
        </div>
      </div>
    </section>
  )
}

/** Researcher view: queries, mappings, snapshots, exclusions and evidence ids for this vendor. */
export function ResearcherPanel({ summary, v, detail, runId }: { summary: RunSummary; v: VendorSummary; detail: VendorDetail | null; runId: string }) {
  const metrics = v.goals.flatMap((g) => g.metrics.map((m) => ({ g, m })))
  return (
    <Panel id="research" className="scroll-mt-24" eyebrow="Researcher view" title="Queries, mappings and snapshots" description="Everything needed to re-derive this profile by hand.">
      <div className="space-y-6">
        <div>
          <p className="ts-eyebrow mb-2">Queries ({metrics.length})</p>
          <ul className="divide-y divide-line overflow-hidden rounded-card border border-line">
            {metrics.map(({ g, m }) => (
              <li key={m.metricId} className="grid gap-1 bg-surface-raised px-4 py-2.5 md:grid-cols-[13rem_minmax(0,1fr)_auto] md:items-center md:gap-3">
                <span className="font-mono text-[0.74rem] text-ink">{m.metricId}</span>
                <span className="ts-ident font-mono text-[0.72rem] text-ink-2">{m.query}</span>
                <HowCalculated vendorId={v.vendor.id} runId={runId} goalId={g.goalId} metricId={m.metricId} iconOnly />
              </li>
            ))}
          </ul>
        </div>
        {detail && (
          <div className="grid gap-6 lg:grid-cols-2">
            <div className="min-w-0">
              <p className="ts-eyebrow mb-2">Attributions ({detail.attributions.length})</p>
              <ul className="ts-scroll-thin max-h-64 space-y-1 overflow-y-auto rounded-card border border-line bg-surface-raised p-3 font-mono text-[0.72rem] text-ink-2">
                {detail.attributions.map((a) => (
                  <li key={a.cveId} className="ts-ident">
                    {a.cveId} · {a.rule} · {a.confidence} · {a.matched.map((x) => `${x.kind}=${x.value}`).join(', ')}
                  </li>
                ))}
              </ul>
            </div>
            <div className="min-w-0">
              <p className="ts-eyebrow mb-2">Exclusions ({detail.exclusions.length})</p>
              <ul className="ts-scroll-thin max-h-64 space-y-1 overflow-y-auto rounded-card border border-line bg-surface-raised p-3 font-mono text-[0.72rem] text-ink-2">
                {detail.exclusions.length === 0 && <li>none</li>}
                {detail.exclusions.map((x, i) => (
                  <li key={`${x.cveId}-${i}`} className="ts-ident">
                    {x.cveId} · {x.reason} · candidates {x.candidateVendorIds.join(', ')} · {x.note}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        )}
        <div>
          <p className="ts-eyebrow mb-2">Snapshots for this vendor</p>
          <ul className="ts-scroll-thin max-h-56 space-y-1 overflow-y-auto rounded-card border border-line bg-surface-raised p-3 font-mono text-[0.72rem] text-ink-2">
            {[...summary.snapshots.filter((s) => isVendorSource(s.sourceId, v.vendor.id)), ...(detail?.snapshots ?? [])]
              .map((s) => (
                <li key={s.id} className="ts-ident">
                  {s.id} · {s.status} · {s.fetchedAt} · {s.sha256 ?? 'no hash'} · {s.url}
                </li>
              ))}
          </ul>
        </div>
        {detail && (
          <p className="text-[0.78rem] text-ink-3">
            {detail.evidence.length} evidence items in this run for this vendor. <Link to={`/app/evidence?vendor=${encodeURIComponent(v.vendor.id)}`} className="ts-link">Open them in the ledger</Link>.
          </p>
        )}
      </div>
    </Panel>
  )
}
