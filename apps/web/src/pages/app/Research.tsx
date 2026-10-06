/**
 * Researcher view: the raw material of a run in one place — queries,
 * identity mappings and conflicts, snapshots, formulas, run history and
 * evidence ids.
 */
import { useState } from 'react'
import { Link } from 'react-router'
import { useActiveSummary } from '../../data/hooks.ts'
import { useUi } from '../../state/ui.ts'
import { PageHeader, Panel } from '../../ui/Panel.tsx'
import { DemoLabel, Segmented } from '../../ui/controls.tsx'
import { Load } from '../../ui/States.tsx'
import { HowCalculated } from '../../features/figures.tsx'
import { dateTime, num } from '../../lib/format.ts'
import { ALIAS_KIND_LABEL, notMeasured } from '../../lib/vocab.ts'

type Tab = 'queries' | 'identity' | 'snapshots' | 'formulas'

export function Research() {
  const value = useActiveSummary()
  const mode = useUi((s) => s.mode)
  const setMode = useUi((s) => s.setMode)
  const [tab, setTab] = useState<Tab>('queries')
  const [vendorId, setVendorId] = useState<string | null>(null)
  return (
    <Load value={value} what="the run">
      {({ summary, index, runId }) => {
        const vid = vendorId ?? summary.vendors[0]?.vendor.id ?? ''
        const v = summary.vendors.find((x) => x.vendor.id === vid)
        return (
          <>
            <PageHeader
              eyebrow="Research view"
              title="The raw material of the run"
              lede="Queries, identity mappings, snapshots and formulas, exactly as the engine used them."
              actions={
                <>
                  {index.mode === 'DEMO' && <DemoLabel />}
                  {mode !== 'researcher' && (
                    <button type="button" className="ts-link text-[0.84rem]" onClick={() => setMode('researcher')}>
                      Switch vendor profiles to Researcher mode
                    </button>
                  )}
                </>
              }
            />
            <Segmented
              label="Section"
              value={tab}
              onChange={setTab}
              className="mb-5"
              options={[
                { value: 'queries', label: 'Queries' },
                { value: 'identity', label: 'Identity mappings' },
                { value: 'snapshots', label: 'Snapshots' },
                { value: 'formulas', label: 'Formulas' },
              ]}
            />
            {tab === 'queries' && (
              <Panel
                title="Metric queries"
                description="The exact, re-runnable description of each query over the snapshot."
                actions={
                  <select className="ts-select h-9" aria-label="Vendor" value={vid} onChange={(e) => setVendorId(e.target.value)}>
                    {summary.vendors.map((x) => (
                      <option key={x.vendor.id} value={x.vendor.id}>
                        {x.vendor.canonicalName}
                      </option>
                    ))}
                  </select>
                }
              >
                <ul className="divide-y divide-line overflow-hidden rounded-card border border-line">
                  {v?.goals.flatMap((g) =>
                    g.metrics.map((m) => (
                      <li key={m.metricId} className="grid gap-1.5 bg-surface-raised px-4 py-3 lg:grid-cols-[14rem_minmax(0,1fr)_auto] lg:items-start lg:gap-4">
                        <span className="min-w-0">
                          <span className="block font-mono text-[0.76rem] font-semibold text-ink">{m.metricId}</span>
                          <span className="block font-mono text-[0.72rem] text-ink-3">{m.value === null ? notMeasured(m) : m.calculation}</span>
                        </span>
                        <span className="ts-ident font-mono text-[0.72rem] leading-relaxed text-ink-2">{m.query}</span>
                        <span className="flex items-center gap-2 text-[0.72rem] text-ink-3">
                          {m.evidenceIds.length} evidence
                          <HowCalculated vendorId={vid} runId={runId} goalId={g.goalId} metricId={m.metricId} iconOnly />
                        </span>
                      </li>
                    )),
                  )}
                </ul>
              </Panel>
            )}
            {tab === 'identity' && (
              <div className="space-y-6">
                <Panel title="Identity conflicts" eyebrow={`${summary.identityConflicts.length} conflicts`} description="Records involved are excluded until the registry resolves the conflict explicitly.">
                  {summary.identityConflicts.length === 0 ? (
                    <p className="text-[0.84rem] text-ink-3">None in this run.</p>
                  ) : (
                    <ul className="space-y-2 text-[0.84rem]">
                      {summary.identityConflicts.map((c) => (
                        <li key={c.id} className="rounded-[12px] border border-line bg-surface-raised p-3.5">
                          <p className="font-mono text-[0.78rem] text-ink">
                            {c.id} · {c.kind} · {ALIAS_KIND_LABEL[c.aliasKind]} “{c.value}”
                          </p>
                          <p className="mt-1 text-ink-2">
                            Vendors: {c.vendorIds.join(', ')} · {c.affectedRecordIds.length} records excluded. {c.note}
                          </p>
                        </li>
                      ))}
                    </ul>
                  )}
                  <p className="mt-3 text-[0.8rem] text-ink-3">{num(summary.exclusionCount)} records excluded from attribution in total.</p>
                </Panel>
                <Panel title="Alias mappings" eyebrow="All vendors" flush>
                  <div className="ts-scroll-thin max-h-[36rem] overflow-auto">
                    <table className="ts-tbl min-w-[46rem]">
                      <thead>
                        <tr>
                          <th scope="col">Vendor</th>
                          <th scope="col">Kind</th>
                          <th scope="col">Alias</th>
                          <th scope="col">Confidence</th>
                          <th scope="col">Evidence</th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.vendors.flatMap((x) =>
                          x.vendor.aliases.map((a, i) => (
                            <tr key={`${x.vendor.id}-${i}`}>
                              <td className="text-[0.8rem]">
                                <Link to={`/app/vendors/${x.vendor.id}#identity`} className="ts-ident hover:underline">
                                  {x.vendor.canonicalName}
                                </Link>
                              </td>
                              <td className="text-[0.78rem] text-ink-2">{ALIAS_KIND_LABEL[a.kind]}</td>
                              <td className="ts-ident font-mono text-[0.76rem]">{a.value}</td>
                              <td className="text-[0.78rem]">{a.confidence.toLowerCase()}</td>
                              <td className="text-[0.76rem] text-ink-2">{a.evidence.map((e) => e.statement).join(' ')}</td>
                            </tr>
                          )),
                        )}
                      </tbody>
                    </table>
                  </div>
                </Panel>
              </div>
            )}
            {tab === 'snapshots' && (
              <Panel
                title="Source-level snapshots"
                eyebrow={`${summary.snapshots.length} listed`}
                description="Signer list, policies, security.txt files, advisory feeds and every snapshot that was not OK. Per-record CVE snapshots are listed on each vendor’s detail."
                flush
              >
                <div className="ts-scroll-thin max-h-[40rem] overflow-auto">
                  <table className="ts-tbl min-w-[60rem]">
                    <thead>
                      <tr>
                        <th scope="col">Snapshot</th>
                        <th scope="col">Source</th>
                        <th scope="col">Status</th>
                        <th scope="col">Fetched</th>
                        <th scope="col">sha256</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.snapshots.map((s) => (
                        <tr key={s.id}>
                          <td className="font-mono text-[0.74rem]">{s.id}</td>
                          <td className="ts-ident max-w-[16rem] font-mono text-[0.72rem] text-ink-2">{s.sourceId}</td>
                          <td className={s.status === 'OK' ? 'text-[0.76rem] text-ink-2' : 'text-[0.76rem] font-semibold text-vermilion-ink'}>
                            {s.status}
                            {s.substitutedBy ? ` → ${s.substitutedBy}` : ''}
                          </td>
                          <td className="whitespace-nowrap text-[0.74rem] text-ink-2">{dateTime(s.fetchedAt)}</td>
                          <td className="ts-ident max-w-[18rem] font-mono text-[0.68rem] text-ink-3">{s.sha256 ?? s.error ?? '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Panel>
            )}
            {tab === 'formulas' && (
              <Panel title="Formulas in this run" eyebrow={`methodology ${summary.manifest.methodologyVersion}`}>
                <ul className="space-y-3">
                  {summary.metricDefinitions.map((m) => (
                    <li key={m.id} className="rounded-[12px] border border-line bg-surface-raised p-3.5">
                      <p className="font-mono text-[0.76rem] font-semibold text-ink">
                        {m.id} <span className="font-normal text-ink-3">· {m.unit.toLowerCase()}</span>
                      </p>
                      <p className="mt-1 text-[0.82rem] leading-relaxed text-ink-2">{m.formula}</p>
                    </li>
                  ))}
                </ul>
              </Panel>
            )}
            <p className="mt-6 text-[0.8rem] text-ink-3">
              Run history and reproduction are on the <Link to="/app/runs" className="ts-link">Runs</Link> page; every evidence id is in the{' '}
              <Link to="/app/evidence" className="ts-link">
                evidence ledger
              </Link>
              .
            </p>
          </>
        )
      }}
    </Load>
  )
}
