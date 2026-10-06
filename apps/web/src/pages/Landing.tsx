/**
 * Landing page. The thesis first (a pledge needs a test), then the test
 * itself, then the evidence boundary, a live excerpt of the published run,
 * and how every figure can be checked or challenged.
 */
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { motion } from 'motion/react'
import { ArrowDown, ArrowRight, ArrowUpRight } from 'lucide-react'
import { ButtonLink, buttonClass } from '../ui/Button.tsx'
import { TestSurface } from '../landing/TestSurface.tsx'
import { GoalBoundary } from '../landing/GoalBoundary.tsx'
import { DemoBoard } from '../landing/DemoBoard.tsx'
import { METRIC_DEFINITIONS, PLEDGE_SOURCE_URL } from '../lib/core.ts'
import { DISPUTE_STATUS, TONE_CLASSES } from '../lib/status.ts'
import { cx } from '../lib/cx.ts'

const reveal = {
  initial: { opacity: 0, y: 14 },
  whileInView: { opacity: 1, y: 0 },
  viewport: { once: true, margin: '-80px' },
  transition: { duration: 0.6, ease: [0.16, 1, 0.3, 1] as const },
}

function Section({ id, eyebrow, title, lede, children, className }: { id?: string; eyebrow: string; title: ReactNode; lede?: ReactNode; children?: ReactNode; className?: string }) {
  return (
    <section id={id} aria-labelledby={id ? `${id}-title` : undefined} className={cx('mx-auto max-w-page px-4 py-20 sm:px-6 sm:py-28 lg:px-10', className)}>
      <motion.div {...reveal} className="max-w-3xl">
        <p className="ts-eyebrow mb-3">{eyebrow}</p>
        <h2 id={id ? `${id}-title` : undefined} className="text-display text-ink">
          {title}
        </h2>
        {lede && <p className="mt-5 max-w-prose text-lede text-ink-2">{lede}</p>}
      </motion.div>
      {children && <div className="mt-12 sm:mt-14">{children}</div>}
    </section>
  )
}

const PIPELINE = [
  {
    step: 'Public data',
    body: 'The signer list, CVE JSON 5.x records, vendor CSAF advisories, security.txt and disclosure policies. Each fetch is stored as a snapshot with its sha256.',
    artifact: 'SN-3f9a0c27e1b4 · sha256 9e1f…c07a',
  },
  {
    step: 'Normalization',
    body: 'Records are parsed into one model. The manufacturer’s CNA container is kept apart from third-party enrichment, and every vendor name is mapped through evidenced aliases.',
    artifact: 'containers.cna ≠ containers.adp[]',
  },
  {
    step: 'Measurement',
    body: 'Each metric is a published formula over a fixed query: an eligibility rule, a numerator and a denominator. Missing data is a state, never a zero.',
    artifact: '414 / 428 = 96.73%',
  },
  {
    step: 'Evidence',
    body: 'Every record that fed a figure becomes an evidence item: the snapshot it came from, the exact fields read, and how it was interpreted.',
    artifact: 'EV-7c21d0e9aa · SUPPORTS',
  },
  {
    step: 'Reproducible result',
    body: 'A run hashes its inputs and its outputs. Re-running the same snapshots under the same methodology version gives the same outputs hash, in the CLI or in your browser.',
    artifact: 'outputsHash 4b8e…19d2 ✓ match',
  },
]

export function Landing() {
  const quality = METRIC_DEFINITIONS.find((m) => m.id === 'cve.complete_records')
  return (
    <>
      {/* ------------------------------------------------------------ hero */}
      <section className="relative overflow-hidden">
        <div aria-hidden="true" className="ts-dotgrid pointer-events-none absolute inset-0 [mask-image:linear-gradient(to_bottom,black,transparent_70%)]" />
        <div className="relative mx-auto max-w-page px-4 pb-16 pt-12 sm:px-6 sm:pb-24 sm:pt-20 lg:px-10">
          <motion.p {...reveal} className="ts-eyebrow">
            CISA Secure by Design Pledge · public evidence research
          </motion.p>
          <motion.h1
            initial={{ opacity: 0, y: 18 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
            className="mt-5 max-w-[15ch] text-hero text-ink"
          >
            A security pledge means nothing without a way to test it.
          </motion.h1>
          <div className="mt-8 grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,22rem)] lg:items-end">
            <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.12, ease: [0.16, 1, 0.3, 1] }} className="min-w-0">
              <p className="max-w-[40rem] text-lede text-ink-2">TOUCHSTONE turns public security commitments into independently reproducible evidence.</p>
              <div className="mt-8 flex flex-wrap items-center gap-3">
                <ButtonLink to="/app" variant="primary" size="lg" trailing={<ArrowRight />}>
                  Explore the Scorecard
                </ButtonLink>
                <ButtonLink to="/methodology" variant="secondary" size="lg">
                  View Methodology
                </ButtonLink>
                <a href="#how" className={buttonClass('ghost', 'lg')}>
                  How It Works <ArrowDown aria-hidden="true" />
                </a>
              </div>
            </motion.div>
            <motion.p
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.8, delay: 0.3 }}
              className="border-l-2 border-marigold pl-4 font-mono text-[0.8rem] leading-relaxed text-ink-2"
            >
              Measure the commitment. Not the claim.
              <br />
              Every figure: a source, a query, a formula, the records behind it, and a run you can repeat.
            </motion.p>
          </div>
          <motion.div initial={{ opacity: 0, y: 24 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.9, delay: 0.25, ease: [0.16, 1, 0.3, 1] }} className="mt-14 sm:mt-16">
            <TestSurface />
          </motion.div>
        </div>
      </section>

      {/* ------------------------------------------------------------ the problem */}
      <section aria-labelledby="problem-title" className="border-y border-line bg-surface/70">
        <div className="mx-auto grid max-w-page gap-12 px-4 py-20 sm:px-6 sm:py-28 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)] lg:px-10">
          <motion.div {...reveal} className="min-w-0">
            <p className="ts-eyebrow mb-4">The problem</p>
            <h2 id="problem-title" className="text-display text-ink">
              <span className="block">Signature</span>
              <span className="block text-vermilion" aria-label="is not">
                ≠
              </span>
              <span className="block">verification.</span>
            </h2>
          </motion.div>
          <motion.div {...reveal} className="min-w-0 space-y-8">
            <p className="text-lede text-ink">
              CISA’s signer page lists <span className="ts-num font-semibold">387</span> companies (fetched 6 Oct 2026). A listing records that a company made seven
              commitments. It does not record what the company did next.
            </p>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="ts-card p-5">
                <p className="ts-eyebrow mb-3">A signature shows</p>
                <ul className="space-y-2 text-[0.9rem] text-ink-2">
                  <li>A company name on a list.</li>
                  <li>An intention, in the pledge’s own words.</li>
                </ul>
              </div>
              <div className="ts-card border-ink/40 p-5">
                <p className="ts-eyebrow mb-3">Verification needs</p>
                <ul className="space-y-2 text-[0.9rem] text-ink-2">
                  <li>A public source anyone can fetch.</li>
                  <li>A fixed query and a published formula.</li>
                  <li>The records behind the number.</li>
                  <li>A run that gives the same answer twice.</li>
                </ul>
              </div>
            </div>
            <p className="text-[0.95rem] leading-relaxed text-ink-2">
              Some of what the pledge asks leaves a public trace: a disclosure policy anyone can read, CVE records anyone can download. Most of it does not. TOUCHSTONE
              measures the first and says plainly where the second begins.{' '}
              <a href={PLEDGE_SOURCE_URL} target="_blank" rel="noopener noreferrer" className="ts-link inline-flex items-center gap-1">
                Read the pledge <ArrowUpRight aria-hidden="true" className="size-3.5" />
              </a>
            </p>
          </motion.div>
        </div>
      </section>

      {/* ------------------------------------------------------------ how it works */}
      <Section
        id="how"
        eyebrow="How it works"
        title="From a public page to a figure you can re-run."
        lede="Five stages, in order. Each leaves an artifact you can inspect: the snapshot, the normalized record, the formula, the evidence item, the run hash."
      >
        <ol className="relative grid gap-6 sm:grid-cols-2 lg:grid-cols-5 lg:gap-3">
          <span aria-hidden="true" className="absolute left-0 right-0 top-[1.1rem] hidden h-px bg-line-strong lg:block" />
          {PIPELINE.map((p, i) => (
            <motion.li key={p.step} {...reveal} transition={{ ...reveal.transition, delay: i * 0.07 }} className="relative min-w-0">
              <span className="relative z-[1] inline-flex h-9 items-center rounded-full bg-ink px-3.5 font-mono text-[0.72rem] text-paper">{String(i + 1).padStart(2, '0')}</span>
              <h3 className="mt-4 text-title-3 text-ink">{p.step}</h3>
              <p className="mt-2 text-[0.88rem] leading-relaxed text-ink-2">{p.body}</p>
              <p className="ts-ident mt-4 rounded-[10px] border border-line bg-paper-2/70 px-3 py-2 font-mono text-[0.72rem] text-ink-2">{p.artifact}</p>
            </motion.li>
          ))}
        </ol>
      </Section>

      {/* ------------------------------------------------------------ evidence boundary */}
      <section aria-labelledby="boundary-title" className="border-y border-line bg-paper-2/50">
        <div className="mx-auto max-w-page px-4 py-20 sm:px-6 sm:py-28 lg:px-10">
          <motion.div {...reveal} className="grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.9fr)] lg:items-end">
            <div className="min-w-0">
              <p className="ts-eyebrow mb-3">Observable vs unobservable</p>
              <h2 id="boundary-title" className="text-display text-ink">
                Three goals leave public evidence. Four do not.
              </h2>
            </div>
            <div className="min-w-0 space-y-3 text-[0.95rem] leading-relaxed text-ink-2">
              <p>Some security commitments cannot be reliably verified from public evidence. TOUCHSTONE does not invent a score.</p>
              <p className="flex flex-wrap gap-x-5 gap-y-2 text-[0.8rem]">
                <span className="inline-flex items-center gap-2">
                  <span aria-hidden="true" className="h-3 w-6 rounded-[4px] bg-sage" /> Publicly measurable
                </span>
                <span className="inline-flex items-center gap-2">
                  <span aria-hidden="true" className="h-3 w-6 rounded-[4px] bg-[linear-gradient(90deg,rgb(var(--marigold))_50%,transparent_50%)] ring-1 ring-inset ring-marigold" />{' '}
                  Partially measurable
                </span>
                <span className="inline-flex items-center gap-2">
                  <span aria-hidden="true" className="ts-hatch h-3 w-6 rounded-[4px] ring-1 ring-inset ring-iris/60" /> Not externally verifiable
                </span>
              </p>
            </div>
          </motion.div>
          <div className="mt-12">
            <GoalBoundary />
          </div>
          <p className="mt-8 text-sm text-ink-2">
            No score is not a low score. The evidence boundary is real.{' '}
            <Link to="/cannot-see" className="ts-link">
              Read what it would take to verify the other four
            </Link>
            .
          </p>
        </div>
      </section>

      {/* ------------------------------------------------------------ live demo */}
      <Section
        id="demo"
        eyebrow="The published run"
        title="Evidence, vendor by vendor."
        lede="Coverage counts how many of fourteen evidence slots could be determined from public sources. It describes how much can be seen, not how strong a vendor’s security is."
      >
        <DemoBoard />
      </Section>

      {/* ------------------------------------------------------------ method, evidence, contestability */}
      <section aria-label="Method, evidence and contestability" className="border-t border-line">
        <div className="mx-auto grid max-w-page gap-5 px-4 py-20 sm:px-6 sm:py-24 lg:grid-cols-3 lg:px-10">
          <motion.article {...reveal} className="ts-panel flex flex-col p-6 sm:p-7">
            <p className="ts-eyebrow">Methodology</p>
            <h3 className="mt-2 text-title-2 text-ink">Every figure has a formula.</h3>
            <p className="mt-3 text-[0.9rem] leading-relaxed text-ink-2">Formulas, eligibility rules and parameters are published and versioned. A figure never changes without the version changing.</p>
            {quality && (
              <div className="mt-5 rounded-card bg-paper-2/80 p-4">
                <p className="font-mono text-[0.72rem] text-ink-3">{quality.id}</p>
                <p className="mt-1.5 line-clamp-4 font-mono text-[0.76rem] leading-relaxed text-ink">{quality.formula}</p>
              </div>
            )}
            <Link to="/methodology" className="ts-link mt-auto inline-flex items-center gap-1.5 pt-6 text-sm">
              Read the methodology <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          </motion.article>
          <motion.article {...reveal} transition={{ ...reveal.transition, delay: 0.06 }} className="ts-panel flex flex-col p-6 sm:p-7">
            <p className="ts-eyebrow">Evidence</p>
            <h3 className="mt-2 text-title-2 text-ink">Every figure has its records.</h3>
            <p className="mt-3 text-[0.9rem] leading-relaxed text-ink-2">
              Open any number to see the query, the numerator and denominator, and each record that fed it, down to the snapshot hash.
            </p>
            <dl className="mt-5 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1.5 rounded-card bg-paper-2/80 p-4 font-mono text-[0.74rem]">
              <dt className="text-ink-3">subject</dt>
              <dd className="text-ink">DEMO-2026-0142</dd>
              <dt className="text-ink-3">read</dt>
              <dd className="text-ink">cna.problemTypes → CWE-787</dd>
              <dt className="text-ink-3">reading</dt>
              <dd className="text-sage-ink">supports</dd>
              <dt className="text-ink-3">snapshot</dt>
              <dd className="ts-ident text-ink">SN-3f9a0c27e1b4</dd>
            </dl>
            <Link to="/app/evidence" className="ts-link mt-auto inline-flex items-center gap-1.5 pt-6 text-sm">
              Browse the evidence ledger <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          </motion.article>
          <motion.article {...reveal} transition={{ ...reveal.transition, delay: 0.12 }} className="ts-panel flex flex-col p-6 sm:p-7">
            <p className="ts-eyebrow">Contestability</p>
            <h3 className="mt-2 text-title-2 text-ink">Every finding can be challenged.</h3>
            <p className="mt-3 text-[0.9rem] leading-relaxed text-ink-2">
              A vendor or researcher can dispute a mapping, a source or a method. The original result stays visible beside the dispute; nothing is silently overwritten.
            </p>
            <ol className="mt-5 flex flex-wrap items-center gap-1.5 rounded-card bg-paper-2/80 p-4 text-[0.74rem] font-semibold" aria-label="Dispute workflow">
              {(['OPEN', 'UNDER_REVIEW'] as const).map((s) => (
                <li key={s} className="flex items-center gap-1.5">
                  <span className={cx('rounded-chip px-2 py-1 ring-1 ring-inset', TONE_CLASSES[DISPUTE_STATUS[s].tone].chip)}>{DISPUTE_STATUS[s].label}</span>
                  <ArrowRight aria-hidden="true" className="size-3.5 text-ink-3" />
                </li>
              ))}
              <li className="flex flex-wrap gap-1.5">
                {(['CONFIRMED', 'CORRECTED', 'DISMISSED'] as const).map((s) => (
                  <span key={s} className={cx('rounded-chip px-2 py-1 ring-1 ring-inset', TONE_CLASSES[DISPUTE_STATUS[s].tone].chip)}>
                    {DISPUTE_STATUS[s].label}
                  </span>
                ))}
              </li>
            </ol>
            <Link to="/app/disputes" className="ts-link mt-auto inline-flex items-center gap-1.5 pt-6 text-sm">
              How disputes work <ArrowRight aria-hidden="true" className="size-4" />
            </Link>
          </motion.article>
        </div>
      </section>

      {/* ------------------------------------------------------------ CTA */}
      <section aria-labelledby="cta-title" className="mx-auto max-w-page px-4 pb-20 sm:px-6 lg:px-10">
        <div className="relative overflow-hidden rounded-hero bg-slab px-6 py-16 text-slab-ink sm:px-12 sm:py-20">
          <div aria-hidden="true" className="absolute inset-x-12 bottom-10 hidden h-[5px] rounded-full bg-[linear-gradient(90deg,transparent,rgb(var(--marigold)/0.85)_60%,#E9C46F)] sm:block" />
          <motion.h2 {...reveal} id="cta-title" className="text-display">
            Test the claim.
          </motion.h2>
          <div className="mt-6 grid gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
            <div className="min-w-0 space-y-3 text-[0.95rem] leading-relaxed text-slab-dim">
              <p>TOUCHSTONE evaluates publicly available evidence. It does not conduct intrusive testing of vendor infrastructure.</p>
              <p>A measurement describes observable evidence and should not be interpreted as a complete security assessment.</p>
            </div>
            <div className="flex flex-wrap items-start gap-3 lg:justify-end">
              <Link to="/app" className={buttonClass('on-slab', 'lg')}>
                Explore Demo <ArrowRight aria-hidden="true" />
              </Link>
              <Link to="/methodology" className={buttonClass('on-slab-outline', 'lg')}>
                View Methodology
              </Link>
            </div>
          </div>
        </div>
      </section>
    </>
  )
}
