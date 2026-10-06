/**
 * Source viewer for one evidence item: the source page, the exact fields
 * extracted, the query of the metric it supports, the snapshot id and
 * sha256, and when it was collected.
 */
import { useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import type { RunSummary, Snapshot, VendorDetail } from '@touchstone/core/model'
import { all, useSummary, useVendorDetail } from '../data/hooks.ts'
import { useUi } from '../state/ui.ts'
import type { EvidenceTarget } from '../state/ui.ts'
import { Drawer } from '../ui/Drawer.tsx'
import { CopyText, ExtLink, KV } from '../ui/controls.tsx'
import { Load } from '../ui/States.tsx'
import { StateChip } from '../ui/StatusBadge.tsx'
import { INTERPRETATION } from '../lib/status.ts'
import { dateTime } from '../lib/format.ts'
import { defOf, vendorName } from '../lib/vocab.ts'

const CVE_ID = /^(CVE|DEMO)-\d{4}-\d{4,}$/

function renderValue(v: string | number | boolean | null | string[]): ReactNode {
  if (v === null) return <span className="text-ink-3">null</span>
  if (Array.isArray(v)) return v.length ? v.join(', ') : <span className="text-ink-3">[]</span>
  return String(v)
}

function Body({ target, summary, detail }: { target: EvidenceTarget; summary: RunSummary; detail: VendorDetail }) {
  const openMetric = useUi((s) => s.openMetric)
  const openEvidence = useUi((s) => s.openEvidence)
  const e = detail.evidence.find((x) => x.id === target.evidenceId)
  if (!e) return <p className="text-sm text-ink-2">Evidence item {target.evidenceId} is not part of run {target.runId}.</p>
  const source = summary.sources.find((s) => s.id === e.sourceId)
  // Per-record snapshots may live on the vendor detail rather than the run summary.
  const detailSnapshots: Snapshot[] = detail.snapshots ?? []
  const snapshot = summary.snapshots.find((s) => s.id === e.snapshotId) ?? detailSnapshots.find((s) => s.id === e.snapshotId)
  const metric = detail.goals.flatMap((g) => g.metrics.map((m) => ({ g, m }))).find((x) => x.m.metricId === e.metricId)
  const def = defOf(summary, e.metricId)
  const sourceUrl = snapshot?.url ?? source?.url ?? ''
  return (
    <div className="space-y-7">
      <div className="flex flex-wrap items-center gap-2">
        <StateChip meta={INTERPRETATION[e.interpretation]} />
        <span className="rounded-chip bg-paper-2 px-2 py-1 font-mono text-[0.72rem] text-ink-2 ring-1 ring-inset ring-line">confidence {e.confidence.toLowerCase()}</span>
      </div>
      <p className="text-lede text-ink">{e.reading}</p>

      <KV
        rows={[
          ['Evidence id', <span className="inline-flex items-center gap-1 font-mono text-[0.8rem]">{e.id}<CopyText text={e.id} label="Copy evidence id" /></span>],
          ['Vendor', vendorName(summary, e.vendorId)],
          [
            'Subject',
            CVE_ID.test(e.subject) ? (
              <Link to={`/app/cves/${encodeURIComponent(e.subject)}`} onClick={() => openEvidence(null)} className="ts-link font-mono text-[0.8rem]">
                {e.subject}
              </Link>
            ) : (
              <span className="font-mono text-[0.8rem]">{e.subject}</span>
            ),
          ],
          [
            'Metric',
            metric ? (
              <button
                type="button"
                className="ts-link text-left"
                onClick={() => {
                  openEvidence(null)
                  openMetric({ vendorId: e.vendorId, runId: target.runId, goalId: metric.g.goalId, metricId: e.metricId })
                }}
              >
                {def?.name ?? e.metricId}
              </button>
            ) : (
              <span className="font-mono text-[0.8rem]">{e.metricId}</span>
            ),
          ],
          ['Source', source ? `${source.title} · ${source.publisher}` : e.sourceId],
          ['Source page', sourceUrl ? <ExtLink href={sourceUrl} /> : '—'],
          ['Collected', dateTime(e.collectedAt)],
          ['Methodology', <span className="font-mono text-[0.8rem]">{e.methodologyVersion}</span>],
        ]}
      />

      <div>
        <p className="ts-eyebrow mb-2">Extracted fields</p>
        <table className="ts-tbl overflow-hidden rounded-[12px] border border-line">
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Value as read</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(e.extracted).map(([k, v]) => (
              <tr key={k}>
                <td className="ts-ident w-[40%] font-mono text-[0.76rem] text-ink-2">{k}</td>
                <td className="ts-ident font-mono text-[0.78rem] text-ink">{renderValue(v)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {metric && (
        <div>
          <p className="ts-eyebrow mb-1.5">Query</p>
          <p className="ts-ident rounded-[12px] border border-line bg-paper-2/60 px-3.5 py-3 font-mono text-[0.78rem] leading-relaxed text-ink">{metric.m.query}</p>
        </div>
      )}

      <div>
        <p className="ts-eyebrow mb-2">Snapshot</p>
        {snapshot ? (
          <KV
            rows={[
              ['Snapshot id', <span className="inline-flex items-center gap-1 font-mono text-[0.8rem]">{snapshot.id}<CopyText text={snapshot.id} label="Copy snapshot id" /></span>],
              ['sha256', snapshot.sha256 ? <span className="inline-flex items-start gap-1 font-mono text-[0.74rem]"><span className="ts-ident">{snapshot.sha256}</span><CopyText text={snapshot.sha256} label="Copy sha256" /></span> : '—'],
              ['Fetched', dateTime(snapshot.fetchedAt)],
              ['Status', <span className="font-mono text-[0.8rem]">{snapshot.status}{snapshot.httpStatus ? ` · HTTP ${snapshot.httpStatus}` : ''}{snapshot.contentType ? ` · ${snapshot.contentType}` : ''}</span>],
              ['Retention', source?.retention === 'EXTRACT_ONLY' ? 'Hash and extracted fields only (third-party page)' : 'Raw bytes retained'],
              ...(snapshot.substitutedBy ? ([['Substitution', <span className="text-marigold-ink">Refresh failed; snapshot {snapshot.substitutedBy} used instead</span>]] as [ReactNode, ReactNode][]) : []),
            ]}
          />
        ) : (
          <p className="font-mono text-[0.8rem] text-ink-2">{e.snapshotId}</p>
        )}
      </div>
      {source?.attribution && <p className="text-[0.75rem] text-ink-3">{source.attribution}</p>}
    </div>
  )
}

export function EvidenceViewer({ target }: { target: EvidenceTarget | null }) {
  const openEvidence = useUi((s) => s.openEvidence)
  const [last, setLast] = useState<EvidenceTarget | null>(target)
  if (target && target !== last) setLast(target)
  const t = target ?? last
  const summary = useSummary(t?.runId ?? null)
  const detail = useVendorDetail(t?.vendorId ?? null, t?.runId ?? null)
  const both = all<[RunSummary, VendorDetail]>(summary, detail)
  return (
    <Drawer open={!!target} onClose={() => openEvidence(null)} eyebrow="Source viewer" title={t?.evidenceId ?? 'Evidence'} width="lg">
      {t && <Load value={both} what="the evidence item">{([s, d]) => <Body target={t} summary={s} detail={d} />}</Load>}
    </Drawer>
  )
}
