/**
 * Vendor profile. /app/vendors/:id inside the app and /vendors/:id as a
 * shareable public page (same content, no app chrome).
 */
import { useEffect } from 'react'
import { useLocation, useParams } from 'react-router'
import { Info } from 'lucide-react'
import type { HistorySeries } from '@touchstone/core/model'
import { useActiveSummary, useDisputes, useHistory, useVendorDetail } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import { useInApp } from '../../lib/paths.ts'
import { cx } from '../../lib/cx.ts'
import { EmptyState, Load } from '../../ui/States.tsx'
import { VendorHeader } from '../../features/vendor/Header.tsx'
import { EvidenceOverview, GoalCards } from '../../features/vendor/Overview.tsx'
import { VdpExplorer } from '../../features/vendor/Vdp.tsx'
import { CveQuality } from '../../features/vendor/CveQuality.tsx'
import { Anomalies, Benchmarks, CisoBrief, Claims, Freshness, HistoryPanel, Identity, ResearcherPanel, VendorDisputes } from '../../features/vendor/Context.tsx'

const SECTIONS = [
  ['goals', 'Goals'],
  ['vdp', 'VDP'],
  ['cve', 'CVE records'],
  ['benchmarks', 'Benchmarks'],
  ['history', 'History'],
  ['identity', 'Identity'],
  ['freshness', 'Freshness'],
  ['disputes', 'Disputes'],
] as const

export function ProcurementNote() {
  return (
    <p role="note" className="flex items-start gap-3 rounded-card border border-line bg-surface px-4 py-3 text-[0.86rem] leading-relaxed text-ink-2">
      <Info aria-hidden="true" className="mt-0.5 size-4 shrink-0 text-ink-3" />
      These figures describe publicly observable evidence. They do not constitute a complete security assessment of the vendor.
    </p>
  )
}

export function VendorProfile() {
  const { vendorId = '' } = useParams()
  const inApp = useInApp()
  const { hash } = useLocation()
  const mode = useUi((s) => s.mode)
  const active = useActiveSummary()
  const runId = active.status === 'ready' ? active.data.runId : null
  const detail = useVendorDetail(vendorId, runId)
  const disputes = useDisputes()
  const history = useHistory()

  useEffect(() => {
    if (hash && active.status === 'ready') document.getElementById(hash.slice(1))?.scrollIntoView({ block: 'start' })
  }, [hash, active.status])

  return (
    <div className={cx(!inApp && 'mx-auto max-w-page px-4 py-10 sm:px-6 lg:px-10')}>
      <Load value={active} what="the run">
        {({ summary, index }) => {
          const v = summary.vendors.find((x) => x.vendor.id === vendorId)
          if (!v) return <EmptyState title="Vendor not in this run">No vendor with id “{vendorId}” is part of run {summary.manifest.runId}.</EmptyState>
          const rid = summary.manifest.runId
          const d = detail.status === 'ready' ? detail.data : null
          const disputeList = disputes.status === 'ready' ? disputes.data : []
          const open = disputeList.filter((x) => x.vendorId === v.vendor.id && (x.status === 'OPEN' || x.status === 'UNDER_REVIEW'))
          const disputedGoals = new Set(
            open.map((x) => (x.target.kind === 'GOAL' ? x.target.id : x.target.kind === 'METRIC' ? (summary.metricDefinitions.find((m) => m.id === x.target.id)?.goalId ?? '') : 'G6')),
          )
          const hist: HistorySeries[] | null = history.status === 'ready' ? history.data : null
          return (
            <>
              <VendorHeader summary={summary} v={v} detail={d} isDemo={index.mode === 'DEMO'} />
              <div className="xl:grid xl:grid-cols-[minmax(0,1fr)_11rem] xl:gap-10">
                <div className="min-w-0 space-y-6">
                  {mode === 'procurement' && <ProcurementNote />}
                  {mode === 'ciso' && <CisoBrief summary={summary} v={v} history={hist} />}
                  <EvidenceOverview summary={summary} v={v} runId={rid} />
                  <GoalCards summary={summary} v={v} runId={rid} disputedGoals={disputedGoals} />
                  <Anomalies v={v} runId={rid} />
                  <VdpExplorer v={v} runId={rid} minWords={(summary.methodology.parameters as { vdpMinimumPolicyWords?: number }).vdpMinimumPolicyWords} />
                  <CveQuality v={v} detail={d} runId={rid} highImpact={summary.methodology.parameters.highImpactSeverities} tolerance={summary.methodology.parameters.timelinessToleranceDays} />
                  {detail.status === 'error' && <p className="text-sm text-vermilion-ink">Evidence for this vendor could not be loaded: {detail.error.message}</p>}
                  <Benchmarks summary={summary} v={v} />
                  {hist && <HistoryPanel history={hist} v={v} />}
                  <div className="grid gap-6 2xl:grid-cols-2">
                    <Claims v={v} />
                    <Freshness summary={summary} v={v} />
                  </div>
                  <Identity summary={summary} v={v} />
                  {mode === 'researcher' && <ResearcherPanel summary={summary} v={v} detail={d} runId={rid} />}
                  <VendorDisputes disputes={disputeList} v={v} runId={rid} />
                </div>
                <nav aria-label="On this page" className="hidden xl:block">
                  <div className="sticky top-24">
                    <p className="ts-eyebrow mb-3">On this page</p>
                    <ul className="space-y-1.5 border-l border-line text-[0.82rem]">
                      {SECTIONS.map(([id, label]) => (
                        <li key={id}>
                          <a href={`#${id}`} className="-ml-px block border-l border-transparent pl-3 text-ink-2 hover:border-ink hover:text-ink">
                            {label}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                </nav>
              </div>
            </>
          )
        }}
      </Load>
    </div>
  )
}
