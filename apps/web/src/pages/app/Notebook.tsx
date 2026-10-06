import { useState } from 'react'
import { Link } from 'react-router'
import type { NotebookEntry, RunSummary } from '@touchstone/core/model'
import { all, useActiveSummary, useNotebook } from '../../data/hooks.ts'
import { PageHeader } from '../../ui/Panel.tsx'
import { DemoLabel } from '../../ui/controls.tsx'
import { EmptyState, Load } from '../../ui/States.tsx'
import { Tag } from '../../ui/StatusBadge.tsx'
import { date } from '../../lib/format.ts'
import { vendorName } from '../../lib/vocab.ts'
import { cx } from '../../lib/cx.ts'

function Entries({ entries, summary }: { entries: NotebookEntry[]; summary: RunSummary }) {
  const [tag, setTag] = useState<string | null>(null)
  const tags = [...new Set(entries.flatMap((e) => e.tags))].sort()
  const shown = tag ? entries.filter((e) => e.tags.includes(tag)) : entries
  if (entries.length === 0) return <EmptyState title="The notebook is empty">Observations made while building the methodology are recorded here.</EmptyState>
  return (
    <>
      <div className="mb-5 flex flex-wrap gap-1.5" role="group" aria-label="Filter by tag">
        {[null, ...tags].map((t) => (
          <button
            key={t ?? 'all'}
            type="button"
            aria-pressed={tag === t}
            onClick={() => setTag(t)}
            className={cx('h-8 rounded-[10px] px-3 font-mono text-[0.72rem] ring-1 ring-inset transition-colors', tag === t ? 'bg-ink text-paper ring-ink' : 'text-ink-2 ring-line hover:ring-line-strong')}
          >
            {t ?? 'all'}
          </button>
        ))}
      </div>
      <ol className="space-y-4">
        {shown.map((e) => (
          <li key={e.id} className="ts-panel p-6">
            <div className="flex flex-wrap items-baseline justify-between gap-2">
              <p className="font-mono text-[0.75rem] text-ink-3">
                {e.id} · {date(e.createdAt)}
                {e.vendorId && (
                  <>
                    {' '}
                    ·{' '}
                    <Link to={`/app/vendors/${e.vendorId}`} className="ts-link font-sans">
                      {vendorName(summary, e.vendorId)}
                    </Link>
                  </>
                )}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {e.tags.map((t) => (
                  <Tag key={t}>{t}</Tag>
                ))}
              </div>
            </div>
            <h2 className="mt-2 text-title-3 text-ink">{e.title}</h2>
            <p className="mt-2 max-w-prose text-[0.9rem] leading-relaxed text-ink-2">{e.observation}</p>
            {e.resolution && (
              <p className="mt-3 max-w-prose border-l-2 border-sage pl-3 text-[0.88rem] leading-relaxed text-ink">
                <span className="ts-eyebrow mr-2">Resolution</span>
                {e.resolution}
              </p>
            )}
          </li>
        ))}
      </ol>
    </>
  )
}

export function Notebook() {
  const active = useActiveSummary()
  const notebook = useNotebook()
  const both = all<[{ summary: RunSummary; index: { mode: string } }, NotebookEntry[]]>(active, notebook)
  return (
    <Load value={both} what="the notebook">
      {([a, entries]) => (
        <>
          <PageHeader
            eyebrow="Research notebook"
            title="What the data taught the method"
            lede="Observations made while building and running the methodology, and what each one changed."
            actions={a.index.mode === 'DEMO' ? <DemoLabel /> : undefined}
          />
          <Entries entries={entries} summary={a.summary} />
        </>
      )}
    </Load>
  )
}
