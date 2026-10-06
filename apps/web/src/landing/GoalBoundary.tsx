/**
 * Observable vs unobservable: the seven goals against the public evidence
 * boundary. Select a goal to read what public evidence can and cannot show.
 * Reads GOALS from the engine; no goal text lives here.
 */
import { useState } from 'react'
import { Link } from 'react-router'
import { AnimatePresence, motion } from 'motion/react'
import { ArrowRight } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { GOALS } from '../lib/core.ts'
import { VERIFICATION_MODE } from '../lib/status.ts'
import type { VerificationMode } from '@touchstone/core/model'

export function ModeSwatch({ mode, className }: { mode: VerificationMode; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={cx(
        'inline-block shrink-0 rounded-[5px]',
        mode === 'PUBLICLY_MEASURABLE' && 'bg-sage',
        mode === 'PARTIALLY_MEASURABLE' && 'bg-[linear-gradient(90deg,rgb(var(--marigold))_50%,transparent_50%)] ring-1 ring-inset ring-marigold',
        mode === 'NOT_EXTERNALLY_VERIFIABLE' && 'ts-hatch ring-1 ring-inset ring-iris/60',
        className,
      )}
    />
  )
}

export function GoalBoundary({ goalHref = (id: string) => `/goals/${id}` }: { goalHref?: (id: string) => string }) {
  const [selected, setSelected] = useState('G6')
  const goal = GOALS.find((g) => g.id === selected)!
  const mode = VERIFICATION_MODE[goal.verificationMode]
  const canShow = goal.evidenceRequirements.filter((r) => r.publiclyAvailable)

  return (
    <div className="grid min-w-0 gap-5 lg:grid-cols-[minmax(0,0.95fr)_minmax(0,1.05fr)]">
      <div role="tablist" aria-label="Pledge goals" aria-orientation="vertical" className="min-w-0 space-y-1.5">
        {GOALS.map((g) => {
          const on = g.id === selected
          return (
            <button
              key={g.id}
              role="tab"
              type="button"
              aria-selected={on}
              aria-controls="goal-boundary-panel"
              onClick={() => setSelected(g.id)}
              onKeyDown={(e) => {
                const i = GOALS.findIndex((x) => x.id === g.id)
                if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                  e.preventDefault()
                  const next = GOALS[(i + (e.key === 'ArrowDown' ? 1 : GOALS.length - 1)) % GOALS.length]!
                  setSelected(next.id)
                  ;(e.currentTarget.parentElement?.querySelector(`[data-goal="${next.id}"]`) as HTMLElement | null)?.focus()
                }
              }}
              data-goal={g.id}
              tabIndex={on ? 0 : -1}
              className={cx(
                'flex w-full min-w-0 items-center gap-3 rounded-card border px-4 py-3 text-left transition-[background-color,border-color,box-shadow] duration-200',
                on ? 'border-ink/70 bg-surface-raised shadow-soft' : 'border-line bg-surface/60 hover:border-line-strong hover:bg-surface',
              )}
            >
              <span className="ts-num w-7 shrink-0 text-[0.78rem] text-ink-3">{g.id}</span>
              <span className="min-w-0 flex-1">
                <span className="block truncate font-semibold text-ink">{g.name}</span>
                <span className="block truncate text-[0.78rem] text-ink-3">{VERIFICATION_MODE[g.verificationMode].label}</span>
              </span>
              <ModeSwatch mode={g.verificationMode} className="h-6 w-12 sm:w-20" />
            </button>
          )
        })}
      </div>

      <div id="goal-boundary-panel" role="tabpanel" aria-label={goal.name} className="ts-panel relative min-h-[26rem] overflow-hidden">
        <AnimatePresence mode="wait">
          <motion.div
            key={goal.id}
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
            className="p-6 sm:p-7"
          >
            <div className="flex flex-wrap items-center gap-2">
              <span className="ts-num text-[0.8rem] text-ink-3">Goal {goal.number}</span>
              <span className="text-ink-3" aria-hidden="true">
                ·
              </span>
              <span className={cx('inline-flex items-center gap-2 text-[0.8rem] font-semibold', mode.tone === 'iris' ? 'text-iris-ink' : mode.tone === 'sage' ? 'text-sage-ink' : 'text-marigold-ink')}>
                <ModeSwatch mode={goal.verificationMode} className="h-3 w-5" />
                {mode.label}
              </span>
            </div>
            <h3 className="mt-3 text-title-2 text-ink">{goal.name}</h3>
            <blockquote className="mt-4 border-l-2 border-line-strong pl-4 text-[0.92rem] leading-relaxed text-ink-2">“{goal.pledgeText}”</blockquote>
            <p className="mt-5 text-[0.92rem] leading-relaxed text-ink">{goal.methodology.summary}</p>

            <div className="mt-6 grid gap-5 sm:grid-cols-2">
              <div className="min-w-0">
                <p className="ts-eyebrow mb-2">Public evidence can show</p>
                {canShow.length ? (
                  <ul className="space-y-1.5 text-[0.86rem] text-ink-2">
                    {canShow.map((r) => (
                      <li key={r.id} className="flex gap-2">
                        <span aria-hidden="true" className="mt-[0.45rem] size-1.5 shrink-0 rounded-full bg-sage" />
                        {r.description}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-[0.86rem] text-ink-3">Nothing that answers this goal.</p>
                )}
              </div>
              <div className="min-w-0">
                <p className="ts-eyebrow mb-2">{goal.methodology.evidenceNeeded.length ? 'Verification would need' : 'Limits of the evidence'}</p>
                <ul className="space-y-1.5 text-[0.86rem] text-ink-2">
                  {(goal.methodology.evidenceNeeded.length ? goal.methodology.evidenceNeeded : goal.methodology.limitations).map((t) => (
                    <li key={t} className="flex gap-2">
                      <span aria-hidden="true" className="ts-hatch mt-[0.3rem] size-2.5 shrink-0 rounded-[3px] ring-1 ring-inset ring-iris/50" />
                      {t}
                    </li>
                  ))}
                </ul>
              </div>
            </div>
            <Link to={goalHref(goal.id)} className="ts-link mt-6 inline-flex items-center gap-1.5 text-sm">
              Read the full method for {goal.id} <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  )
}
