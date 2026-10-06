/**
 * VDP explorer: the eight criteria with their states, the quoted sentences,
 * rule ids, the policy source and when it was last updated, prohibitive
 * language, and before/after when the policy changed between snapshots.
 */
import type { VdpChange, VdpObservation, VendorSummary } from '@touchstone/core/model'
import { ArrowRight, Quote } from 'lucide-react'
import { Panel } from '../../ui/Panel.tsx'
import { CriterionBadge } from '../../ui/StatusBadge.tsx'
import { ExtLink, KV } from '../../ui/controls.tsx'
import { EmptyState } from '../../ui/States.tsx'
import { criterionLabel } from '../../lib/vocab.ts'
import { PLEDGE_VDP_CRITERIA } from '../../lib/core.ts'
import { date } from '../../lib/format.ts'
import { HowCalculated } from '../figures.tsx'
import type { CriterionState } from '@touchstone/core/model'

type Retrieval = VdpObservation['policy']['retrieval']

/** How the policy text was obtained. Older runs predate the field: infer only "found" vs "not found". */
export function retrievalOf(vdp: VdpObservation): Retrieval | undefined {
  return vdp.policy.retrieval ?? (vdp.policy.found ? undefined : 'NOT_FOUND')
}

const RETRIEVAL_NOTE: Record<Retrieval, { tone: 'sage' | 'marigold' | 'vermilion' | 'stone'; text: (words?: number, min?: number) => string }> = {
  READ: { tone: 'sage', text: (w) => `Policy text read${w !== undefined ? ` (${w} words)` : ''}. Each criterion below quotes the sentence it rests on.` },
  TOO_SHORT: {
    tone: 'marigold',
    text: (w, min) => `Policy text is shorter than the plausibility floor (${w ?? '?'} words${min ? `, minimum ${min}` : ''}): assessed, but Goal 5 is at most partial.`,
  },
  UNREADABLE: { tone: 'vermilion', text: () => 'Policy could not be read (script-only, interstitial or empty page): criteria undetermined. This is not a finding about the policy’s content.' },
  FETCH_FAILED: { tone: 'vermilion', text: () => 'Policy could not be fetched: criteria undetermined. A retrieval problem is never reported as a missing element.' },
  NOT_FOUND: { tone: 'stone', text: () => 'No policy document was found on the vendor’s domain, in security.txt or in the registry: pledge elements are reported as not found.' },
}

const RETRIEVAL_LABEL: Record<Retrieval, string> = {
  READ: 'Read',
  TOO_SHORT: 'Read, below the plausibility floor',
  UNREADABLE: 'Not readable',
  FETCH_FAILED: 'Fetch failed',
  NOT_FOUND: 'No policy found',
}

const NOTE_TONE = {
  sage: 'border-sage/40 bg-sage/10 text-sage-ink',
  marigold: 'border-marigold/40 bg-marigold/10 text-marigold-ink',
  vermilion: 'border-vermilion/40 bg-vermilion/10 text-vermilion-ink',
  stone: 'border-line-strong bg-paper-2 text-ink-2',
}

function RetrievalNote({ vdp, minWords }: { vdp: VdpObservation; minWords?: number }) {
  const r = retrievalOf(vdp)
  if (!r) return null
  const note = RETRIEVAL_NOTE[r]
  return (
    <p role="note" className={`rounded-[12px] border px-4 py-2.5 text-[0.84rem] ${NOTE_TONE[note.tone]}`}>
      {note.text(vdp.policy.wordCount, minWords)}
    </p>
  )
}

function unknownText(r: Retrieval | undefined): string {
  if (r === 'UNREADABLE') return 'Undetermined: the policy page could not be read.'
  if (r === 'FETCH_FAILED') return 'Undetermined: the policy could not be fetched.'
  return 'Undetermined: no readable policy text.'
}

function Criteria({ vdp }: { vdp: VdpObservation }) {
  const r = retrievalOf(vdp)
  return (
    <ul className="divide-y divide-line overflow-hidden rounded-card border border-line">
      {vdp.criteria.map((c) => {
        const pledge = (PLEDGE_VDP_CRITERIA as string[]).includes(c.criterion)
        return (
          <li key={c.criterion} className="grid gap-3 bg-surface-raised px-4 py-3.5 md:grid-cols-[minmax(11rem,0.8fr)_minmax(0,2fr)]">
            <div className="min-w-0">
              <p className="font-semibold text-ink">
                {criterionLabel(c.criterion)}
                {pledge && <span className="ml-2 rounded-[6px] bg-paper-2 px-1.5 py-0.5 align-middle font-mono text-[0.62rem] uppercase tracking-[0.08em] text-ink-3 ring-1 ring-inset ring-line">pledge</span>}
              </p>
              <div className="mt-2">
                <CriterionBadge state={c.state} />
              </div>
              <p className="mt-2 font-mono text-[0.7rem] text-ink-3">{c.ruleId}</p>
            </div>
            <div className="min-w-0 space-y-2">
              {c.quotes.length > 0 ? (
                c.quotes.map((q, i) => (
                  <blockquote key={i} className="ts-ident flex gap-2 text-[0.86rem] leading-relaxed text-ink">
                    <Quote aria-hidden="true" className="mt-1 size-3.5 shrink-0 text-ink-3" />
                    <span>{q}</span>
                  </blockquote>
                ))
              ) : (
                <p className="text-[0.84rem] text-ink-3">{c.state === 'UNKNOWN' ? unknownText(r) : r === 'NOT_FOUND' ? 'Not found: there is no policy document to contain it.' : 'No sentence in the policy supports this element.'}</p>
              )}
              {c.note && <p className="text-[0.8rem] text-ink-2">{c.note}</p>}
            </div>
          </li>
        )
      })}
    </ul>
  )
}

function Change({ change }: { change: VdpChange }) {
  const changed = change.criteria.filter((c) => c.before !== c.after)
  return (
    <div className="rounded-card border border-plum/30 bg-plum/5 p-4">
      <p className="text-[0.86rem] font-semibold text-ink">
        Policy changed between {date(change.fromObservedAt)} and {date(change.toObservedAt)}
        {change.reviewRecommended && <span className="ml-2 font-normal text-plum-ink">· review recommended (a pledge element changed state)</span>}
      </p>
      <p className="mt-1 font-mono text-[0.72rem] text-ink-3">
        {change.fromSnapshotId} → {change.toSnapshotId} · text {change.textChanged ? 'changed' : 'unchanged'}
      </p>
      {changed.length > 0 && (
        <ul className="mt-3 space-y-2">
          {changed.map((c) => (
            <li key={c.criterion} className="flex flex-wrap items-center gap-2 text-[0.84rem]">
              <span className="min-w-[10rem] font-semibold text-ink">{criterionLabel(c.criterion)}</span>
              <CriterionBadge state={c.before as CriterionState} />
              <ArrowRight aria-hidden="true" className="size-4 text-ink-3" />
              <CriterionBadge state={c.after as CriterionState} />
            </li>
          ))}
        </ul>
      )}
    </div>
  )
}

export function VdpExplorer({ v, runId, minWords }: { v: VendorSummary; runId: string; minWords?: number }) {
  const vdp = v.vdp
  return (
    <Panel
      id="vdp"
      className="scroll-mt-24"
      eyebrow="Goal 5"
      title="Vulnerability disclosure policy"
      actions={<HowCalculated vendorId={v.vendor.id} runId={runId} goalId="G5" metricId="vdp.criteria_met" />}
      description="Eight criteria, four of them named by the pledge. Each determination quotes the sentence it rests on. A security.txt file alone is not counted as a policy."
    >
      {!vdp ? (
        <EmptyState title="No VDP observation in this run">No security.txt or policy page was observed for this vendor. This is reported as not found, not as a score of zero.</EmptyState>
      ) : (
        <div className="space-y-5">
          {vdp.carriedFromSnapshotId && (
            <p role="note" className="rounded-[12px] border border-marigold/40 bg-marigold/10 px-4 py-2.5 text-[0.84rem] text-marigold-ink">
              Refresh failed — using previous verified snapshot {vdp.carriedFromSnapshotId} (observed {date(vdp.observedAt)}).
            </p>
          )}
          <RetrievalNote vdp={vdp} minWords={minWords} />
          <KV
            rows={[
              ['Policy', vdp.policy.found && vdp.policy.url ? <ExtLink href={vdp.policy.url} /> : 'No policy document found'],
              ['Hosted on', vdp.policy.host ?? 'Not stated'],
              ['Stated last update', vdp.policy.statedLastUpdated ? date(vdp.policy.statedLastUpdated) : 'Not stated'],
              ['Observed', date(vdp.observedAt)],
              ['security.txt', vdp.securityTxt.present ? <span>{vdp.securityTxt.url ? <ExtLink href={vdp.securityTxt.url} /> : 'present'}{vdp.securityTxt.expires ? ` · expires ${date(vdp.securityTxt.expires)}` : ' · no Expires field'}</span> : 'Not found'],
              ['Contacts', vdp.securityTxt.contacts.length ? <span className="font-mono text-[0.78rem]">{vdp.securityTxt.contacts.join(', ')}</span> : 'None listed'],
              ['Policy words', vdp.policy.wordCount !== undefined ? String(vdp.policy.wordCount) : 'Not extracted'],
              ['Policy text', retrievalOf(vdp) ? RETRIEVAL_LABEL[retrievalOf(vdp)!] : 'Not recorded in this run'],
            ]}
          />
          {vdp.prohibitive.length > 0 && (
            <div className="rounded-card border border-vermilion/35 bg-vermilion/5 p-4">
              <p className="text-[0.86rem] font-semibold text-vermilion-ink">Observed deviation: prohibitive language</p>
              <ul className="mt-2 space-y-2">
                {vdp.prohibitive.map((p, i) => (
                  <li key={i} className="text-[0.84rem] text-ink">
                    “{p.quote}” <span className="font-mono text-[0.7rem] text-ink-3">({p.ruleId}, against {criterionLabel(p.againstCriterion)})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          <Criteria vdp={vdp} />
          {vdp.securityTxt.warnings.length > 0 && (
            <p className="text-[0.78rem] text-ink-3">security.txt parse notes: {vdp.securityTxt.warnings.join('; ')}</p>
          )}
        </div>
      )}
      {v.vdpChanges.length > 0 && (
        <div className="mt-6 space-y-3">
          <p className="ts-eyebrow">VDP change, before and after</p>
          {v.vdpChanges.map((c) => (
            <Change key={`${c.fromSnapshotId}-${c.toSnapshotId}`} change={c} />
          ))}
        </div>
      )}
    </Panel>
  )
}
