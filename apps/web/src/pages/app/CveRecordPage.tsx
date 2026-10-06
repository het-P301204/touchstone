/**
 * One CVE record: the CNA container (the manufacturer's data, the only data
 * credited) beside each ADP container (third-party enrichment, context).
 */
import { Link, useParams } from 'react-router'
import type { ContainerData, CveRecord, RunSummary, VendorDetail } from '@touchstone/core/model'
import { useActiveSummary, useAllDetails } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { DemoLabel, KV } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { StateChip } from '../../ui/StatusBadge.tsx'
import { INTERPRETATION } from '../../lib/status.ts'
import { COMPLETENESS_LABEL, completenessOf, severityOf } from '../../lib/cve.ts'
import { date, shortHash } from '../../lib/format.ts'
import { defOf, vendorName } from '../../lib/vocab.ts'
import { cx } from '../../lib/cx.ts'

function Container({ c, credited }: { c: ContainerData; credited: boolean }) {
  return (
    <section
      aria-label={`${c.provider} container`}
      className={cx('min-w-0 rounded-panel border p-5', credited ? 'border-sage/50 bg-surface' : 'ts-hatch-soft border-dashed border-iris/45 bg-surface/60')}
    >
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 className="text-title-3 text-ink">{credited ? 'CNA container' : `ADP: ${c.provider}`}</h2>
        <span className={cx('text-[0.75rem] font-semibold', credited ? 'text-sage-ink' : 'text-iris-ink')}>{credited ? 'Manufacturer’s data · credited' : 'Third-party enrichment · context only'}</span>
      </div>
      <div className="mt-4 space-y-4 text-[0.84rem]">
        <div>
          <p className="ts-eyebrow mb-1.5">CWE ({c.cwes.length})</p>
          {c.cwes.length ? (
            <ul className="space-y-1 font-mono text-[0.78rem]">
              {c.cwes.map((w, i) => (
                <li key={i} className={w.placeholder ? 'text-marigold-ink' : w.id ? 'text-ink' : 'text-vermilion-ink'}>
                  {w.raw}
                  {w.placeholder && <span className="ml-2 font-sans text-[0.72rem]">placeholder</span>}
                  {!w.id && !w.placeholder && <span className="ml-2 font-sans text-[0.72rem]">not a CWE identifier</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-ink-3">Not provided</p>
          )}
        </div>
        <div>
          <p className="ts-eyebrow mb-1.5">CPE ({c.cpes.length})</p>
          {c.cpes.length ? (
            <ul className="space-y-1 font-mono text-[0.74rem]">
              {c.cpes.map((p, i) => (
                <li key={i} className={cx('ts-ident', p.wellFormed ? 'text-ink' : 'text-vermilion-ink')}>
                  {p.raw}
                  {!p.wellFormed && <span className="ml-2 font-sans text-[0.72rem]">malformed</span>}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-ink-3">Not provided</p>
          )}
        </div>
        <div>
          <p className="ts-eyebrow mb-1.5">CVSS ({c.cvss.length})</p>
          {c.cvss.length ? (
            <ul className="space-y-1 font-mono text-[0.76rem] text-ink">
              {c.cvss.map((s, i) => (
                <li key={i}>
                  {s.version} · {s.baseScore} · {s.severity.toLowerCase()}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-ink-3">Not provided</p>
          )}
        </div>
      </div>
    </section>
  )
}

function Record({ summary, rec, details, runId }: { summary: RunSummary; rec: { record: CveRecord; vendorId: string }; details: VendorDetail[]; runId: string }) {
  const openEvidence = useUi((s) => s.openEvidence)
  const c = rec.record
  const detail = details.find((d) => d.vendorId === rec.vendorId)!
  const attribution = detail.attributions.find((a) => a.cveId === c.id)
  const evidence = detail.evidence.filter((e) => e.subject === c.id)
  const advisories = detail.advisories.filter((a) => a.cveIds.includes(c.id))
  const exclusions = details.flatMap((d) => d.exclusions).filter((x) => x.cveId === c.id)
  const comp = completenessOf(c)
  return (
    <div className="space-y-6">
      <Panel>
        <KV
          rows={[
            ['Vendor', <Link to={`/app/vendors/${rec.vendorId}`} className="ts-link">{vendorName(summary, rec.vendorId)}</Link>],
            ['State', c.state],
            ['Assigner (CNA)', <span className="font-mono text-[0.8rem]">{c.assigner.shortName}</span>],
            ['Affected', c.affected.map((a) => `${a.vendor} · ${a.product}`).join('; ') || '—'],
            ['Published', date(c.datePublished)],
            ['Updated', date(c.dateUpdated)],
            ['Severity', `${severityOf(c).severity.toLowerCase()}${severityOf(c).from === 'ADP' ? ' (stated only by ADP)' : ''}`],
            ['Completeness', COMPLETENESS_LABEL[comp]],
            ['Attribution', attribution ? <span className="font-mono text-[0.78rem]">{attribution.rule} · {attribution.confidence.toLowerCase()} · {attribution.matched.map((m) => `${m.kind}=${m.value}`).join(', ')}</span> : 'not attributed'],
            ['Record', <span className="font-mono text-[0.78rem]">JSON {c.dataVersion} · snapshot {c.snapshotId} · source hash {shortHash(c.sourceHash, 16)}</span>],
          ]}
        />
        {exclusions.length > 0 && (
          <p className="mt-4 rounded-[12px] border border-marigold/40 bg-marigold/10 px-4 py-2.5 text-[0.84rem] text-marigold-ink">
            Excluded for {exclusions.map((x) => `${x.reason.replace(/_/g, ' ').toLowerCase()} (${x.note})`).join('; ')}.
          </p>
        )}
      </Panel>

      <div>
        <p className="ts-eyebrow mb-3">Containers, side by side</p>
        <div className={cx('grid gap-4', c.adp.length ? 'lg:grid-cols-2' : '')}>
          <Container c={c.cna} credited />
          {c.adp.map((a, i) => (
            <Container key={`${a.provider}-${i}`} c={a} credited={false} />
          ))}
          {c.adp.length === 0 && <p className="text-[0.84rem] text-ink-3">No ADP container on this record: nothing was added by a third party.</p>}
        </div>
      </div>

      <Panel title="Evidence items for this record" eyebrow={`${evidence.length} items`}>
        {evidence.length === 0 ? (
          <p className="text-[0.84rem] text-ink-3">This record fed no metric in this run (outside the eligibility window or excluded).</p>
        ) : (
          <ul className="divide-y divide-line overflow-hidden rounded-[12px] border border-line">
            {evidence.map((e) => (
              <li key={e.id}>
                <button type="button" onClick={() => openEvidence({ vendorId: e.vendorId, runId, evidenceId: e.id })} className="flex w-full min-w-0 items-start gap-3 bg-surface-raised px-3.5 py-2.5 text-left hover:bg-paper-2">
                  <StateChip meta={INTERPRETATION[e.interpretation]} size="sm" className="mt-0.5 w-[7.6rem] shrink-0" />
                  <span className="min-w-0 flex-1">
                    <span className="block text-[0.82rem] font-semibold text-ink">{defOf(summary, e.metricId)?.name ?? e.metricId}</span>
                    <span className="block text-[0.8rem] text-ink-2">{e.reading}</span>
                  </span>
                  <span className="hidden font-mono text-[0.7rem] text-ink-3 sm:block">{e.id}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {advisories.length > 0 && (
        <Panel title="Advisories listing this CVE" eyebrow="Vendor CSAF">
          <ul className="space-y-2 text-[0.84rem]">
            {advisories.map((a) => (
              <li key={a.id} className="flex flex-wrap items-baseline justify-between gap-2">
                <span className="min-w-0">
                  <span className="font-mono text-[0.78rem] text-ink">{a.id}</span> <span className="text-ink-2">{a.title}</span>
                </span>
                <span className="ts-num text-[0.78rem] text-ink-3">
                  {a.severity.toLowerCase()} · {date(a.publishedAt)}
                </span>
              </li>
            ))}
          </ul>
        </Panel>
      )}
    </div>
  )
}

export function CveRecordPage() {
  const { cveId = '' } = useParams()
  const active = useActiveSummary()
  const runId = active.status === 'ready' ? active.data.runId : null
  const ids = active.status === 'ready' ? active.data.summary.vendors.map((v) => v.vendor.id) : null
  const details = useAllDetails(runId, ids)
  return (
    <Load value={active} what="the run">
      {({ summary, index, runId: rid }) => (
        <Load value={details} what="the record">
          {(d) => {
            const found = d.flatMap((x) => x.cves.filter((c) => c.id === cveId).map((c) => ({ record: c, vendorId: x.vendorId })))
            return (
              <>
                <nav aria-label="Breadcrumb" className="mb-4 text-[0.8rem] text-ink-3">
                  <Link to="/app/cves" className="hover:text-ink">
                    CVE records
                  </Link>{' '}
                  / <span className="font-mono text-ink-2">{cveId}</span>
                </nav>
                <PageHeader eyebrow="CVE record" title={<span className="font-mono">{cveId}</span>} lede={found[0]?.record.title} actions={index.mode === 'DEMO' ? <DemoLabel /> : undefined} />
                {found.length === 0 ? (
                  <EmptyState title="Not attributed in this run">No vendor in run {summary.manifest.runId} carries {cveId}. It may be outside every vendor’s attribution, excluded, or absent from the snapshot.</EmptyState>
                ) : (
                  <div className="space-y-10">
                    {found.length > 1 && <p className="text-[0.84rem] text-marigold-ink">This id appears {found.length} times (duplicate content or more than one vendor). Each copy is shown.</p>}
                    {found.map((f) => (
                      <Record key={`${f.vendorId}-${f.record.sourceHash}`} summary={summary} rec={f} details={d} runId={rid} />
                    ))}
                  </div>
                )}
              </>
            )
          }}
        </Load>
      )}
    </Load>
  )
}
