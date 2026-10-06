/**
 * Methodology. Every formula, rule and parameter is rendered from the
 * engine's own definitions, so this page cannot drift from what runs.
 */
import type { ReactNode } from 'react'
import { Link } from 'react-router'
import { useInApp, usePaths } from '../lib/paths.ts'
import { cx } from '../lib/cx.ts'
import { CONFIDENCE_RULES, CURRENT_METHODOLOGY_VERSION, GOALS, METHODOLOGY_VERSIONS, METRIC_DEFINITIONS, MIN_PEERS_FOR_POSITION, TRACKED_CWE_CLASSES, VDP_CRITERIA } from '../lib/core.ts'
import { VERIFICATION_MODE } from '../lib/status.ts'
import { DISPUTE_REASON_LABEL, GAP_LABEL, criterionLabel } from '../lib/vocab.ts'
import { date } from '../lib/format.ts'
import { ModeSwatch } from '../landing/GoalBoundary.tsx'
import { MethodTrace } from '../features/MethodTrace.tsx'
import { DISPUTE_STATUS } from '../lib/status.ts'
import { Disclosure } from '../ui/controls.tsx'

const TOC = [
  ['measured', 'What is measured'],
  ['sources', 'Sources'],
  ['formulas', 'Formulas'],
  ['identity', 'Identity resolution'],
  ['attribution', 'CVE attribution'],
  ['missing', 'Missing data'],
  ['freshness', 'Freshness'],
  ['confidence', 'Confidence'],
  ['disputes', 'Dispute process'],
  ['limitations', 'Limitations'],
  ['versions', 'Version history'],
  ['trace', 'Worked example'],
] as const

function Sec({ id, title, children, lede }: { id: string; title: string; lede?: ReactNode; children: ReactNode }) {
  return (
    <section id={id} aria-labelledby={`${id}-h`} className="scroll-mt-24 border-t border-line py-10 first:border-t-0 first:pt-0">
      <h2 id={`${id}-h`} className="text-title-2 text-ink">
        {title}
      </h2>
      {lede && <p className="mt-2 max-w-prose text-[0.95rem] leading-relaxed text-ink-2">{lede}</p>}
      <div className="mt-6">{children}</div>
    </section>
  )
}

const SOURCES: [string, string, string][] = [
  ['CISA Secure by Design Pledge', 'Signer list and pledge text', 'Who is listed; the seven goals verbatim. A listing is never treated as evidence of progress.'],
  ['CVE Program (CVE JSON 5.x)', 'One record per CVE id, with the CNA container and ADP containers', 'The record-quality metrics. Only the CNA container counts toward the pledge figure.'],
  ['NVD CVE API 2.0', 'Enumeration of candidate CVE ids by source identifier', 'Used only to find candidate ids. NVD’s own analysis is never credited to a vendor.'],
  ['Vendor advisories (CSAF 2.0)', 'Machine-readable advisories with severity, CVE ids and release dates', 'Issuance timeliness and the high-impact CVE share. No feed means not measured, not zero.'],
  ['Vendor disclosure policy', 'The policy page, read as text', 'The eight VDP criteria, each with its quoted sentence. Stored as hash plus extracted fields.'],
  ['security.txt (RFC 9116)', '/.well-known/security.txt', 'Contact, Expires and Policy fields. Not counted as a policy on its own.'],
]

export function MethodologyPage() {
  const inApp = useInApp()
  const paths = usePaths()
  const current = METHODOLOGY_VERSIONS.find((m) => m.version === CURRENT_METHODOLOGY_VERSION)!
  const p = current.parameters
  return (
    <div className={cx(!inApp && 'mx-auto max-w-page px-4 py-12 sm:px-6 lg:px-10')}>
      <header className="mb-10 max-w-3xl">
        <p className="ts-eyebrow mb-3">Methodology {CURRENT_METHODOLOGY_VERSION}</p>
        <h1 className="text-display text-ink">How every figure is made.</h1>
        <p className="mt-5 text-lede text-ink-2">
          Every formula, eligibility rule and parameter below is rendered from the engine’s own definitions. A figure never changes without the methodology version changing,
          and every run records the version it used.
        </p>
      </header>
      <div className="lg:grid lg:grid-cols-[12rem_minmax(0,1fr)] lg:gap-12">
        <nav aria-label="Methodology sections" className="mb-8 hidden lg:block">
          <ul className="sticky top-24 space-y-1.5 border-l border-line text-[0.84rem]">
            {TOC.map(([id, label]) => (
              <li key={id}>
                <a href={`#${id}`} className="-ml-px block border-l border-transparent pl-3 text-ink-2 hover:border-ink hover:text-ink">
                  {label}
                </a>
              </li>
            ))}
          </ul>
        </nav>
        <div className="min-w-0 max-w-4xl">
          <Sec id="measured" title="What is measured, and what is not" lede="The verification mode is a property of the public evidence boundary, not of any vendor.">
            <ul className="divide-y divide-line overflow-hidden rounded-card border border-line">
              {GOALS.map((g) => (
                <li key={g.id} className="grid gap-2 bg-surface px-4 py-3.5 sm:grid-cols-[3rem_minmax(0,1fr)_12rem] sm:items-center">
                  <span className="ts-num text-[0.8rem] text-ink-3">{g.id}</span>
                  <span className="min-w-0">
                    <Link to={paths.goal(g.id)} className="font-semibold text-ink hover:underline">
                      {g.name}
                    </Link>
                    <span className="block text-[0.8rem] text-ink-2">{g.methodology.metricIds.length ? g.methodology.metricIds.join(', ') : 'No metric: not externally verifiable'}</span>
                  </span>
                  <span className="inline-flex items-center gap-2 text-[0.8rem] text-ink-2">
                    <ModeSwatch mode={g.verificationMode} className="h-3 w-6" />
                    {VERIFICATION_MODE[g.verificationMode].label}
                  </span>
                </li>
              ))}
            </ul>
            <p className="mt-4 text-[0.88rem] text-ink-2">
              There is no composite security score. Three dimensions carry a figure (VDP, CVE record quality, CVE timeliness); each stands alone with its own numerator and
              denominator. <Link to={paths.cannotSee} className="ts-link">What it would take to verify the other goals</Link>.
            </p>
          </Sec>

          <Sec id="sources" title="Sources" lede="Public sources only. TOUCHSTONE does not test, scan or log in to any vendor system.">
            <div className="ts-scroll-thin overflow-x-auto rounded-card border border-line">
              <table className="ts-tbl min-w-[40rem]">
                <thead>
                  <tr>
                    <th scope="col">Source</th>
                    <th scope="col">What is read</th>
                    <th scope="col">Used for</th>
                  </tr>
                </thead>
                <tbody>
                  {SOURCES.map(([a, b, c]) => (
                    <tr key={a}>
                      <td className="font-semibold text-ink">{a}</td>
                      <td className="text-[0.84rem] text-ink-2">{b}</td>
                      <td className="text-[0.84rem] text-ink-2">{c}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Sec>

          <Sec id="formulas" title="Formulas" lede="Rendered verbatim in every “How was this calculated?” panel. Metrics marked as coverage slots count toward evidence coverage.">
            <ul className="space-y-3">
              {METRIC_DEFINITIONS.map((m) => (
                <li key={m.id} className="ts-card p-4">
                  <Disclosure
                    summary={
                      <span className="flex min-w-0 flex-wrap items-baseline gap-x-3 gap-y-1">
                        <span className="font-semibold text-ink">{m.name}</span>
                        <span className="font-mono text-[0.74rem] text-ink-3">{m.id}</span>
                        <span className="font-mono text-[0.7rem] text-ink-3">
                          {m.goalId} · {m.unit.toLowerCase()}
                          {m.dimension ? ` · ${m.dimension} figure` : ''}
                          {m.coverageSlot ? ' · coverage slot' : ''}
                        </span>
                      </span>
                    }
                  >
                    <div className="mt-3 space-y-3 text-[0.86rem] leading-relaxed">
                      <p className="rounded-[12px] bg-paper-2/70 px-3 py-2.5 font-mono text-[0.78rem] text-ink">{m.formula}</p>
                      {(m.numeratorLabel || m.denominatorLabel) && (
                        <p className="text-ink-2">
                          <span className="ts-eyebrow mr-2">Numerator</span>
                          {m.numeratorLabel ?? '—'} <span className="ts-eyebrow mx-2">Denominator</span>
                          {m.denominatorLabel ?? '—'}
                        </p>
                      )}
                      <p className="text-ink-2">
                        <span className="ts-eyebrow mr-2">Eligibility</span>
                        {m.eligibility}
                      </p>
                    </div>
                  </Disclosure>
                </li>
              ))}
            </ul>
            <div className="mt-6 grid gap-4 md:grid-cols-2">
              <div className="ts-card p-4">
                <p className="ts-eyebrow mb-2">VDP criteria</p>
                <ol className="list-decimal space-y-1 pl-5 text-[0.86rem] text-ink-2">
                  {VDP_CRITERIA.map((c) => (
                    <li key={c}>{criterionLabel(c)}</li>
                  ))}
                </ol>
                <p className="mt-2 text-[0.78rem] text-ink-3">MET counts 1, PARTIAL 0.5; NOT_MET, CONTRADICTED and UNKNOWN count 0, and every UNKNOWN is listed.</p>
              </div>
              <div className="ts-card p-4">
                <p className="ts-eyebrow mb-2">Goal 3 tracked weakness classes</p>
                <ul className="space-y-2 text-[0.84rem] text-ink-2">
                  {TRACKED_CWE_CLASSES.map((c) => (
                    <li key={c.id}>
                      <span className="font-semibold text-ink">{c.label}</span>
                      <span className="ts-ident block font-mono text-[0.7rem] text-ink-3">{c.cwes.join(' ')}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          </Sec>

          <Sec id="identity" title="Identity resolution" lede="A vendor appears under many names. Each link from a name to a vendor is an explicit, evidenced alias with a kind and a confidence.">
            <ul className="space-y-2 text-[0.9rem] leading-relaxed text-ink-2">
              <li>Name matching is exact after normalization: case-folded, trimmed, spaces collapsed, corporate suffixes (Inc, LLC, Ltd, Corp, Corporation, GmbH, AG) removed.</li>
              <li>Free text (descriptions, titles) is never used to attribute a record.</li>
              <li>When one name resolves to more than one vendor, an identity conflict is recorded and the affected records are excluded until the registry resolves it explicitly.</li>
              <li>Signatories are matched to vendors through their exact signer-list string (a SIGNATORY_LISTING alias).</li>
            </ul>
          </Sec>

          <Sec id="attribution" title="CVE attribution" lede="Rules are applied in order; the first that matches attributes the record.">
            <ol className="space-y-3">
              {[
                ['ASSIGNER_IS_VENDOR_CNA', 'High', 'The record’s assigner (CNA short name or org id) is an alias of the vendor.'],
                ['AFFECTED_VENDOR_AND_CPE', 'High', 'The CNA’s affected-vendor string is an alias AND a CNA CPE falls in the vendor’s CPE namespace.'],
                ['AFFECTED_VENDOR_ONLY', 'Medium', 'The affected-vendor string matches without a corroborating CPE. Confidence of dependent metrics is capped at medium.'],
              ].map(([rule, conf, text]) => (
                <li key={rule} className="ts-card flex flex-wrap items-baseline gap-x-4 gap-y-1 p-4">
                  <span className="font-mono text-[0.78rem] font-semibold text-ink">{rule}</span>
                  <span className="text-[0.75rem] text-ink-3">{conf} confidence</span>
                  <span className="w-full text-[0.86rem] text-ink-2">{text}</span>
                </li>
              ))}
            </ol>
            <p className="mt-4 max-w-prose text-[0.9rem] leading-relaxed text-ink-2">
              In CVE JSON 5.x the manufacturer’s own data lives in <code className="font-mono text-[0.82rem]">containers.cna</code>; third parties such as CISA-ADP
              (“Vulnrichment”) add data in <code className="font-mono text-[0.82rem]">containers.adp[]</code>. A record can look complete because someone else enriched it.
              Only CNA-supplied CWE and CPE count toward the pledge metric; enrichment is reported separately as <code className="font-mono text-[0.82rem]">cve.enriched_only</code>.
            </p>
          </Sec>

          <Sec id="missing" title="Missing data" lede="Missing data is a first-class state. UNKNOWN is never PASS, and a missing value is never shown as zero.">
            <dl className="grid gap-2 sm:grid-cols-2">
              {Object.entries(GAP_LABEL).map(([k, v]) => (
                <div key={k} className="rounded-[12px] border border-line bg-surface px-3.5 py-2.5">
                  <dt className="font-mono text-[0.74rem] text-ink-3">{k}</dt>
                  <dd className="text-[0.86rem] text-ink">{v}</dd>
                </div>
              ))}
            </dl>
          </Sec>

          <Sec id="freshness" title="Freshness" lede="Computed from the last successful fetch, never from the last attempt. A failed refresh keeps the previous verified snapshot and says so.">
            <div className="ts-scroll-thin overflow-x-auto rounded-card border border-line">
              <table className="ts-tbl min-w-[30rem]">
                <thead>
                  <tr>
                    <th scope="col">Source family</th>
                    <th scope="col" className="text-right">
                      Current up to
                    </th>
                    <th scope="col" className="text-right">
                      Aging up to
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {Object.entries(p.freshnessHours).map(([fam, [cur, aging]]) => (
                    <tr key={fam}>
                      <td className="font-mono text-[0.78rem]">{fam}</td>
                      <td className="ts-num text-right">{cur >= 48 ? `${cur / 24} days` : `${cur} h`}</td>
                      <td className="ts-num text-right">{aging >= 48 ? `${aging / 24} days` : `${aging} h`}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Sec>

          <Sec id="confidence" title="Confidence" lede="Each metric starts at high confidence. Every rule that fires caps it and adds its reason; the lowest cap wins. No weighting, no arithmetic.">
            <ul className="space-y-2">
              {CONFIDENCE_RULES.map((r) => (
                <li key={r.id} className="flex flex-wrap items-baseline gap-x-3 rounded-[12px] border border-line bg-surface px-3.5 py-2.5 text-[0.86rem]">
                  <span className="font-mono text-[0.74rem] text-ink">{r.id}</span>
                  <span className="font-mono text-[0.72rem] text-ink-3">cap {r.cap.toLowerCase()}</span>
                  <span className="w-full text-ink-2">{r.rule}</span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-[0.84rem] text-ink-2">A cohort position is stated only when at least {MIN_PEERS_FOR_POSITION} peers have a value.</p>
          </Sec>

          <Sec id="disputes" title="Dispute process" lede="Anyone can challenge a finding. The original result is never overwritten: dispute state is shown alongside it, and a correction appears in a later run.">
            <p className="mb-3 text-[0.86rem] text-ink-2">Reasons: {Object.values(DISPUTE_REASON_LABEL).join(' · ')}.</p>
            <ol className="flex flex-wrap items-center gap-2 text-[0.8rem]">
              {(Object.keys(DISPUTE_STATUS) as (keyof typeof DISPUTE_STATUS)[]).map((s) => (
                <li key={s} className="rounded-chip border border-line bg-surface px-2.5 py-1.5">
                  <span className="font-semibold text-ink">{DISPUTE_STATUS[s].label}</span> <span className="text-ink-3">· {DISPUTE_STATUS[s].description}</span>
                </li>
              ))}
            </ol>
            <p className="mt-3 text-[0.84rem] text-ink-2">
              Open → Under review → Confirmed, Corrected or Dismissed. Every transition is appended to an audit history; nothing is deleted.{' '}
              <Link to="/app/disputes" className="ts-link">
                Open the dispute log
              </Link>
              .
            </p>
          </Sec>

          <Sec id="limitations" title="Limitations" lede="What these measurements cannot tell you.">
            <ul className="space-y-2 text-[0.88rem] leading-relaxed text-ink-2">
              <li>A measurement describes observable evidence and should not be interpreted as a complete security assessment.</li>
              {GOALS.flatMap((g) => g.methodology.limitations.map((l) => ({ g, l }))).map(({ g, l }) => (
                <li key={`${g.id}-${l}`}>
                  <span className="font-mono text-[0.74rem] text-ink-3">{g.id}</span> {l}
                </li>
              ))}
            </ul>
          </Sec>

          <Sec id="versions" title="Version history" lede="Runs made under an earlier version keep that version’s figures. Values either side of a version change may not be comparable.">
            <ol className="space-y-4">
              {[...METHODOLOGY_VERSIONS].reverse().map((v) => (
                <li key={v.version} className="ts-card p-5">
                  <div className="flex flex-wrap items-baseline justify-between gap-2">
                    <p className="text-title-3 text-ink">
                      {v.version}
                      {v.version === CURRENT_METHODOLOGY_VERSION && <span className="ml-2 rounded-chip bg-sage/15 px-2 py-0.5 align-middle text-[0.72rem] font-semibold text-sage-ink">current</span>}
                    </p>
                    <p className="font-mono text-[0.78rem] text-ink-3">
                      released {date(v.releasedOn)} · scoring {v.scoringVersion} · parser {v.parserVersion}
                    </p>
                  </div>
                  <ul className="mt-3 list-disc space-y-1.5 pl-5 text-[0.88rem] leading-relaxed text-ink-2">
                    {v.changes.map((c) => (
                      <li key={c}>{c}</li>
                    ))}
                  </ul>
                </li>
              ))}
            </ol>
            <div className="mt-6">
              <p className="ts-eyebrow mb-2">Parameters ({CURRENT_METHODOLOGY_VERSION})</p>
              <dl className="grid gap-2 sm:grid-cols-2">
                {(
                  [
                    ['CVE window', `${p.cveWindowDays} days`],
                    ['Placeholder CWE counts as populated', String(p.placeholderCweCountsAsPopulated)],
                    ['Timeliness tolerance', `${p.timelinessToleranceDays} day (a methodology choice, not a CISA threshold)`],
                    ['High-impact severities', p.highImpactSeverities.join(', ')],
                    ['Minimum eligible records', String(p.minimumEligibleRecords)],
                    ['Minimum records per trend period', String(p.minimumRecordsPerTrendPeriod)],
                    ['VDP current within', `${p.vdpCurrentWithinDays} days`],
                    ['Unusual below percentile', String(p.unusualBelowPercentile)],
                    ['Latency outlier', `× ${p.latencyOutlierFactor} and ≥ ${p.latencyOutlierMinDays} days`],
                    ...(p.vdpMinimumPolicyWords !== undefined ? ([['Minimum policy words (plausibility floor)', String(p.vdpMinimumPolicyWords)]] as const) : []),
                    ...(p.minimumHighImpactAdvisories !== undefined ? ([['Minimum high-impact advisories for timeliness', String(p.minimumHighImpactAdvisories)]] as const) : []),
                  ] as const
                ).map(([k, v]) => (
                  <div key={k} className="rounded-[12px] border border-line bg-surface px-3.5 py-2.5">
                    <dt className="text-[0.78rem] text-ink-3">{k}</dt>
                    <dd className="font-mono text-[0.8rem] text-ink">{v}</dd>
                  </div>
                ))}
              </dl>
            </div>
          </Sec>

          <Sec id="trace" title="Worked example: one figure, step by step" lede="Trace a vendor’s CNA CWE coverage through the published run, from the dataset to the outputs hash.">
            <div className="ts-panel p-5 sm:p-6">
              <MethodTrace />
            </div>
          </Sec>
        </div>
      </div>
    </div>
  )
}
