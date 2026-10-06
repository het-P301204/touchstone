/**
 * Evidence We Cannot See. The goals outside the public evidence boundary,
 * Goal 3's partial boundary, and what verification would actually need.
 */
import { Link } from 'react-router'
import { motion } from 'motion/react'
import { ArrowRight } from 'lucide-react'
import { GOALS } from '../lib/core.ts'
import { cx } from '../lib/cx.ts'
import { useInApp, usePaths } from '../lib/paths.ts'

export function CannotSee() {
  const inApp = useInApp()
  const paths = usePaths()
  const hidden = GOALS.filter((g) => g.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE')
  const partial = GOALS.filter((g) => g.verificationMode === 'PARTIALLY_MEASURABLE')
  return (
    <div className={cx(!inApp && 'mx-auto max-w-page px-4 py-12 sm:px-6 lg:px-10')}>
      <header className="grid gap-8 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,1fr)] lg:items-end">
        <div className="min-w-0">
          <p className="ts-eyebrow mb-3">The evidence boundary</p>
          <h1 className="text-display text-ink">Evidence we cannot see.</h1>
          <p className="mt-5 max-w-prose text-lede text-ink-2">
            Some security commitments cannot be reliably verified from public evidence. TOUCHSTONE does not invent a score.
          </p>
        </div>
        <div className="ts-hatch-soft min-w-0 rounded-hero border border-iris/40 p-6">
          <p className="text-title-3 text-ink">No score is not a failing score.</p>
          <p className="mt-2 text-[0.9rem] leading-relaxed text-ink-2">
            “Not externally verifiable” describes the goal and the public record, identically for every vendor. It is never counted against anyone. The evidence boundary is
            real.
          </p>
        </div>
      </header>

      <section aria-label="Goals outside the public evidence boundary" className="mt-14 grid gap-5 md:grid-cols-2">
        {hidden.map((g, i) => (
          <motion.article
            key={g.id}
            initial={{ opacity: 0, y: 12 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: i * 0.05, ease: [0.16, 1, 0.3, 1] }}
            className="ts-panel relative overflow-hidden"
          >
            <div aria-hidden="true" className="ts-hatch absolute inset-y-0 left-0 w-2" />
            <div className="p-6 pl-8">
              <p className="ts-num text-[0.8rem] text-ink-3">Goal {g.number} · not externally verifiable</p>
              <h2 className="mt-1 text-title-2 text-ink">{g.name}</h2>
              <p className="mt-3 text-[0.86rem] leading-relaxed text-ink-2">“{g.pledgeText}”</p>
              <p className="mt-4 text-[0.92rem] leading-relaxed text-ink">{g.methodology.summary}</p>
              <div className="mt-5 grid gap-5 sm:grid-cols-2">
                <div className="min-w-0">
                  <p className="ts-eyebrow mb-2">Evidence needed</p>
                  <ul className="space-y-1.5 text-[0.86rem] text-ink-2">
                    {g.methodology.evidenceNeeded.map((e) => (
                      <li key={e} className="flex gap-2">
                        <span aria-hidden="true" className="ts-hatch mt-[0.3rem] size-2.5 shrink-0 rounded-[3px] ring-1 ring-inset ring-iris/50" />
                        {e}
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="min-w-0">
                  <p className="ts-eyebrow mb-2">Why public data is not enough</p>
                  <ul className="space-y-1.5 text-[0.86rem] text-ink-2">
                    {g.methodology.limitations.map((l) => (
                      <li key={l}>{l}</li>
                    ))}
                  </ul>
                </div>
              </div>
              <Link to={paths.goal(g.id)} className="ts-link mt-5 inline-flex items-center gap-1.5 text-sm">
                Goal {g.number} in full <ArrowRight aria-hidden="true" className="size-4" />
              </Link>
            </div>
          </motion.article>
        ))}
      </section>

      {partial.map((g) => {
        const visible = g.evidenceRequirements.filter((r) => r.publiclyAvailable)
        const invisible = g.evidenceRequirements.filter((r) => !r.publiclyAvailable)
        return (
          <section key={g.id} aria-labelledby={`partial-${g.id}`} className="mt-14">
            <p className="ts-eyebrow mb-2">A partial boundary</p>
            <h2 id={`partial-${g.id}`} className="text-title-1 text-ink">
              Goal {g.number}: {g.name}
            </h2>
            <p className="mt-3 max-w-prose text-[0.95rem] leading-relaxed text-ink-2">{g.methodology.summary}</p>
            <div className="mt-6 grid overflow-hidden rounded-panel border border-line md:grid-cols-2">
              <div className="min-w-0 bg-surface p-6">
                <p className="inline-flex items-center gap-2 text-[0.84rem] font-semibold text-sage-ink">
                  <span aria-hidden="true" className="h-3 w-6 rounded-[4px] bg-sage" /> Visible: a signal
                </p>
                <ul className="mt-3 space-y-1.5 text-[0.9rem] text-ink">
                  {visible.map((r) => (
                    <li key={r.id}>{r.description}</li>
                  ))}
                </ul>
                <p className="mt-3 text-[0.82rem] text-ink-3">{g.methodology.statusRule}</p>
              </div>
              <div className="ts-hatch-soft min-w-0 border-t border-line p-6 md:border-l md:border-t-0">
                <p className="inline-flex items-center gap-2 text-[0.84rem] font-semibold text-iris-ink">
                  <span aria-hidden="true" className="ts-hatch h-3 w-6 rounded-[4px] ring-1 ring-inset ring-iris/60" /> Not visible: the outcome
                </p>
                <ul className="mt-3 space-y-1.5 text-[0.9rem] text-ink">
                  {invisible.map((r) => (
                    <li key={r.id}>{r.description}</li>
                  ))}
                  {g.methodology.evidenceNeeded.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              </div>
            </div>
          </section>
        )
      })}

      <section className="mt-14 max-w-3xl border-t border-line pt-8">
        <h2 className="text-title-2 text-ink">What would change this</h2>
        <p className="mt-3 text-[0.95rem] leading-relaxed text-ink-2">
          If a vendor publishes independently audited, scoped, time-bounded figures for one of these goals, that becomes a public source and a candidate for measurement in a
          future methodology version. Until then, a vendor’s own statement is shown on its profile as a self-reported claim, never as evidence.
        </p>
        <Link to={paths.methodology} className="ts-link mt-4 inline-flex items-center gap-1.5 text-sm">
          Read the methodology <ArrowRight aria-hidden="true" className="size-4" />
        </Link>
      </section>
    </div>
  )
}
