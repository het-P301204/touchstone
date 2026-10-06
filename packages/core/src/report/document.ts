/**
 * The vendor report as one structured model. JSON serializes the model;
 * Markdown and PDF render the same model through one block list, so the
 * formats cannot disagree. Every sentence is assembled from the published
 * run data; nothing about the vendor is written freehand.
 */

import type { Dispute, HistorySeries, RunSummary, VendorDetail } from '../model/index.ts'
import { cleanText } from '../util/sanitize.ts'
import { METRIC_DEFINITIONS } from '../measure/definitions.ts'
import { fmt } from '../measure/stats.ts'

export const POSITIONING = [
  'TOUCHSTONE evaluates publicly available evidence. It does not conduct intrusive testing of vendor infrastructure.',
  'A measurement describes observable evidence and should not be interpreted as a complete security assessment.',
]

export const REPORT_SECTIONS = [
  'Vendor',
  'Scope',
  'Methodology version',
  'Data sources',
  'Measured goals',
  'Unverifiable goals',
  'Metrics',
  'Evidence',
  'Historical comparison',
  'Data quality',
  'Disputes',
  'Limitations',
] as const

export type Block =
  | { t: 'h1' | 'h2' | 'h3'; text: string }
  | { t: 'p'; text: string }
  | { t: 'kv'; rows: Array<[string, string]> }
  | { t: 'table'; head: string[]; rows: string[][] }
  | { t: 'list'; items: string[] }
  | { t: 'rule' }

const s = (x: unknown): string => cleanText(x === null || x === undefined ? '' : String(x))
const val = (v: number | null | undefined, unit?: string): string =>
  v === null || v === undefined ? 'not measured' : unit === 'PERCENT' ? `${fmt(v)}%` : unit === 'DAYS' ? `${fmt(v)} days` : fmt(v)

export type ReportModel = {
  title: string
  positioning: string[]
  vendor: Record<string, string>
  scope: Record<string, string>
  methodology: { version: string; releasedOn: string; parserVersion: string; scoringVersion: string; changes: string[]; parameters: Record<string, string> }
  dataSources: { sourceId: string; title: string; family: string; state: string; lastSuccessAt: string; usedSnapshotId: string; note: string }[]
  measuredGoals: { goalId: string; name: string; status: string; statusReason: string; evidenceCount: number }[]
  dimensions: { dimension: string; value: string; status: string; metricId: string }[]
  unverifiableGoals: { goalId: string; name: string; status: string; statusReason: string; evidenceNeeded: string[]; claims: string[] }[]
  metrics: {
    metricId: string
    name: string
    goalId: string
    value: string
    numerator: string
    denominator: string
    gap: string
    confidence: string
    calculation: string
    formula: string
    confidenceReasons: string[]
  }[]
  evidence: { id: string; metricId: string; subject: string; interpretation: string; reading: string; snapshotId: string; sourceId: string; collectedAt: string; confidence: string }[]
  history: { metricId: string; points: { runId: string; datasetVersion: string; methodologyVersion: string; value: string }[] }[]
  benchmarks: { metricId: string; peerGroup: string; current: string; peerMedian: string; peerCount: number; vendorHistoricalMedian: string; wording: string }[]
  dataQuality: { anomalies: { kind: string; headline: string; detail: string; rule: string }[]; exclusions: { cveId: string; reason: string; note: string }[]; qualityChecks: { id: string; question: string; passed: boolean; detail: string }[] }
  disputes: { id: string; target: string; reason: string; status: string; submitterRole: string; createdAt: string; statement: string; events: number }[]
  limitations: string[]
}

export function buildReportModel(summary: RunSummary, detail: VendorDetail, disputes: Dispute[], history: HistorySeries[]): ReportModel {
  const vs = summary.vendors.find((v) => v.vendor.id === detail.vendorId)
  if (!vs) throw new Error(`Vendor ${detail.vendorId} is not in run ${summary.manifest.runId}`)
  const v = vs.vendor
  const m = summary.manifest
  const goalsById = new Map(summary.goals.map((g) => [g.id, g]))
  const defs = new Map(METRIC_DEFINITIONS.map((d) => [d.id, d]))
  const unit = (id: string) => defs.get(id)?.unit

  const usedSourceIds = new Set(detail.evidence.map((e) => e.sourceId))
  const measured = detail.goals.filter((g) => goalsById.get(g.goalId)?.verificationMode !== 'NOT_EXTERNALLY_VERIFIABLE')
  const unverifiable = detail.goals.filter((g) => goalsById.get(g.goalId)?.verificationMode === 'NOT_EXTERNALLY_VERIFIABLE')
  const p = summary.methodology.parameters

  return {
    title: `TOUCHSTONE vendor report: ${s(v.canonicalName)}`,
    positioning: POSITIONING,
    vendor: {
      Name: s(v.canonicalName),
      'Vendor id': s(v.id),
      'Signatory status': v.signatoryStatus,
      'Signed on': s(v.signedOn ?? 'not stated by a source'),
      Category: v.category,
      'Data kind': v.synthetic ? 'SYNTHETIC demo vendor (fictional)' : 'Real vendor (public sources)',
      'Registered aliases': String(v.aliases.length),
    },
    scope: {
      'Run id': m.runId,
      'Dataset version': s(m.datasetVersion),
      'Analysis date (asOf)': s(m.asOf),
      Mode: m.mode,
      'Measured goals': 'G3 (partial signal), G5 VDP, G6 CVE record quality and issuance timeliness',
      'Not externally verifiable': 'G1 MFA, G2 default passwords, G4 patch installation, G7 intrusion evidence',
      'Inputs hash': m.inputsHash,
      'Outputs hash': m.outputsHash,
      'Composite score': 'None. Each dimension stands alone.',
    },
    methodology: {
      version: summary.methodology.version,
      releasedOn: summary.methodology.releasedOn,
      parserVersion: summary.methodology.parserVersion,
      scoringVersion: summary.methodology.scoringVersion,
      changes: summary.methodology.changes.map(s),
      parameters: {
        cveWindowDays: String(p.cveWindowDays),
        placeholderCweCountsAsPopulated: String(p.placeholderCweCountsAsPopulated),
        timelinessToleranceDays: `${p.timelinessToleranceDays} (TOUCHSTONE methodology parameter, not a CISA threshold)`,
        highImpactSeverities: p.highImpactSeverities.join(', '),
        minimumEligibleRecords: String(p.minimumEligibleRecords),
        minimumRecordsPerTrendPeriod: String(p.minimumRecordsPerTrendPeriod),
        vdpCurrentWithinDays: String(p.vdpCurrentWithinDays),
      },
    },
    dataSources: summary.freshness
      .filter((f) => usedSourceIds.has(f.sourceId) || f.family === 'CISA_PLEDGE' || f.family === 'CVE_PROGRAM')
      .map((f) => ({
        sourceId: s(f.sourceId),
        title: s(f.title),
        family: f.family,
        state: f.state,
        lastSuccessAt: s(f.lastSuccessAt ?? 'none'),
        usedSnapshotId: s(f.usedSnapshotId ?? 'none'),
        note: s(f.note ?? ''),
      })),
    measuredGoals: measured.map((g) => ({
      goalId: g.goalId,
      name: s(goalsById.get(g.goalId)?.name ?? g.goalId),
      status: g.status,
      statusReason: s(g.statusReason),
      evidenceCount: g.evidenceIds.length,
    })),
    dimensions: vs.dimensions.map((d) => ({ dimension: d.dimension, value: val(d.value, 'PERCENT'), status: d.status, metricId: d.metricId })),
    unverifiableGoals: unverifiable.map((g) => ({
      goalId: g.goalId,
      name: s(goalsById.get(g.goalId)?.name ?? g.goalId),
      status: g.status,
      statusReason: s(g.statusReason),
      evidenceNeeded: (goalsById.get(g.goalId)?.methodology.evidenceNeeded ?? []).map(s),
      claims: v.claims.filter((c) => c.goalId === g.goalId).map((c) => `Unverified claim: ${s(c.summary)}${c.url ? ` (${s(c.url)})` : ''}`),
    })),
    metrics: measured.flatMap((g) =>
      g.metrics.map((x) => ({
        metricId: x.metricId,
        name: s(defs.get(x.metricId)?.name ?? x.metricId),
        goalId: g.goalId,
        value: val(x.value, unit(x.metricId)),
        numerator: x.numerator === undefined ? '' : fmt(x.numerator),
        denominator: x.denominator === undefined ? '' : fmt(x.denominator),
        gap: x.gap ?? '',
        confidence: x.confidence,
        calculation: s(x.calculation),
        formula: s(defs.get(x.metricId)?.formula ?? ''),
        confidenceReasons: x.confidenceReasons.map(s),
      })),
    ),
    evidence: detail.evidence.map((e) => ({
      id: e.id,
      metricId: e.metricId,
      subject: s(e.subject),
      interpretation: e.interpretation,
      reading: s(e.reading),
      snapshotId: s(e.snapshotId),
      sourceId: s(e.sourceId),
      collectedAt: s(e.collectedAt),
      confidence: e.confidence,
    })),
    history: history
      .filter((h) => h.vendorId === v.id)
      .map((h) => ({
        metricId: h.metricId,
        points: h.points.map((pt) => ({ runId: pt.runId, datasetVersion: s(pt.datasetVersion), methodologyVersion: pt.methodologyVersion, value: val(pt.value, unit(h.metricId)) })),
      })),
    benchmarks: vs.benchmarks.map((b) => ({
      metricId: b.metricId,
      peerGroup: b.peerGroup,
      current: val(b.current, unit(b.metricId)),
      peerMedian: val(b.peerMedian, unit(b.metricId)),
      peerCount: b.peerCount,
      vendorHistoricalMedian: val(b.vendorHistoricalMedian, unit(b.metricId)),
      wording: s(b.wording),
    })),
    dataQuality: {
      anomalies: vs.anomalies.map((a) => ({ kind: a.kind, headline: s(a.headline), detail: s(a.detail), rule: s(a.rule) })),
      exclusions: detail.exclusions.map((x) => ({ cveId: s(x.cveId), reason: x.reason, note: s(x.note) })),
      qualityChecks: m.qualityChecks.map((q) => ({ id: q.id, question: q.question, passed: q.passed, detail: s(q.detail) })),
    },
    disputes: disputes
      .filter((d) => d.vendorId === v.id)
      .map((d) => ({
        id: s(d.id),
        target: `${d.target.kind} ${s(d.target.id)}`,
        reason: d.reason,
        status: d.status,
        submitterRole: d.submitterRole,
        createdAt: s(d.createdAt),
        statement: s(d.statement),
        events: d.history.length,
      })),
    limitations: [
      ...measured.flatMap((g) => (goalsById.get(g.goalId)?.methodology.limitations ?? []).map((l) => `${g.goalId}: ${s(l)}`)),
      'Only CNA-supplied CWE and CPE fields are credited; third-party enrichment is shown as context.',
      'UNKNOWN is never counted as met, and a value that could not be measured is reported as not measured, never as zero.',
      'A dispute never overwrites an observation: the original result and the dispute are shown side by side.',
    ],
  }
}

/** Render the model as document blocks (Markdown and PDF share this). */
export function reportBlocks(r: ReportModel): Block[] {
  const b: Block[] = []
  b.push({ t: 'h1', text: r.title })
  for (const x of r.positioning) b.push({ t: 'p', text: x })

  b.push({ t: 'h2', text: '1. Vendor' })
  b.push({ t: 'kv', rows: Object.entries(r.vendor) })

  b.push({ t: 'h2', text: '2. Scope' })
  b.push({ t: 'kv', rows: Object.entries(r.scope) })

  b.push({ t: 'h2', text: '3. Methodology version' })
  b.push({
    t: 'kv',
    rows: [
      ['Version', r.methodology.version],
      ['Released', r.methodology.releasedOn],
      ['Parser / scoring', `${r.methodology.parserVersion} / ${r.methodology.scoringVersion}`],
      ...Object.entries(r.methodology.parameters),
    ],
  })
  if (r.methodology.changes.length) b.push({ t: 'list', items: r.methodology.changes })

  b.push({ t: 'h2', text: '4. Data sources' })
  b.push({
    t: 'table',
    head: ['Source', 'Family', 'Freshness', 'Last success', 'Snapshot used', 'Note'],
    rows: r.dataSources.map((x) => [x.sourceId, x.family, x.state, x.lastSuccessAt, x.usedSnapshotId, x.note]),
  })

  b.push({ t: 'h2', text: '5. Measured goals' })
  b.push({ t: 'table', head: ['Dimension', 'Figure', 'Status', 'Metric'], rows: r.dimensions.map((d) => [d.dimension, d.value, d.status, d.metricId]) })
  b.push({ t: 'p', text: 'There is no composite score: each dimension figure stands alone with its own formula, numerator and denominator.' })
  for (const g of r.measuredGoals) {
    b.push({ t: 'h3', text: `${g.goalId} ${g.name}: ${g.status}` })
    b.push({ t: 'p', text: `${g.statusReason} (${g.evidenceCount} evidence items.)` })
  }

  b.push({ t: 'h2', text: '6. Unverifiable goals' })
  for (const g of r.unverifiableGoals) {
    b.push({ t: 'h3', text: `${g.goalId} ${g.name}: ${g.status.replace(/_/g, ' ')}` })
    b.push({ t: 'p', text: g.statusReason })
    b.push({ t: 'list', items: [...g.evidenceNeeded.map((e) => `Evidence needed: ${e}`), ...g.claims] })
  }

  b.push({ t: 'h2', text: '7. Metrics' })
  b.push({
    t: 'table',
    head: ['Metric', 'Goal', 'Value', 'Numerator', 'Denominator', 'Gap', 'Confidence', 'Calculation'],
    rows: r.metrics.map((x) => [x.metricId, x.goalId, x.value, x.numerator, x.denominator, x.gap, x.confidence, x.calculation]),
  })
  b.push({ t: 'h3', text: 'Formulas' })
  b.push({ t: 'list', items: r.metrics.map((x) => `${x.metricId}: ${x.formula}`) })
  const reasons = r.metrics.filter((x) => x.confidenceReasons.length)
  if (reasons.length) {
    b.push({ t: 'h3', text: 'Confidence reasons' })
    b.push({ t: 'list', items: reasons.map((x) => `${x.metricId} (${x.confidence}): ${x.confidenceReasons.join(' ')}`) })
  }

  b.push({ t: 'h2', text: '8. Evidence' })
  b.push({ t: 'p', text: `${r.evidence.length} evidence items. Each names the snapshot it was read from and how the methodology interpreted it.` })
  b.push({
    t: 'table',
    head: ['Evidence', 'Metric', 'Subject', 'Interpretation', 'Reading', 'Snapshot'],
    rows: r.evidence.map((e) => [e.id, e.metricId, e.subject, e.interpretation, e.reading, e.snapshotId]),
  })

  b.push({ t: 'h2', text: '9. Historical comparison' })
  const dimHistory = r.history.filter((h) => ['vdp.criteria_met', 'cve.complete_records', 'cve.timely_issuance', 'cve.cwe_coverage'].includes(h.metricId))
  if (dimHistory.length === 0) b.push({ t: 'p', text: 'No earlier runs are available for this vendor.' })
  for (const h of dimHistory) {
    b.push({ t: 'h3', text: h.metricId })
    b.push({ t: 'table', head: ['Run', 'Dataset', 'Methodology', 'Value'], rows: h.points.map((pt) => [pt.runId, pt.datasetVersion, pt.methodologyVersion, pt.value]) })
  }
  b.push({ t: 'p', text: 'Values computed under different methodology versions are labelled with their version; a methodology change can move a figure without any change in the vendor’s records.' })
  b.push({
    t: 'table',
    head: ['Metric', 'Peer group', 'Current', 'Peer median', 'Peers', 'Own historical median', 'Position'],
    rows: r.benchmarks.map((x) => [x.metricId, x.peerGroup, x.current, x.peerMedian, String(x.peerCount), x.vendorHistoricalMedian, x.wording]),
  })

  b.push({ t: 'h2', text: '10. Data quality' })
  if (r.dataQuality.anomalies.length) b.push({ t: 'list', items: r.dataQuality.anomalies.map((a) => `${a.kind}: ${a.headline} ${a.detail} Rule: ${a.rule}`) })
  else b.push({ t: 'p', text: 'No observed deviations or data quality notes for this vendor.' })
  if (r.dataQuality.exclusions.length)
    b.push({ t: 'table', head: ['Record', 'Exclusion', 'Note'], rows: r.dataQuality.exclusions.map((x) => [x.cveId, x.reason, x.note]) })
  b.push({ t: 'h3', text: 'Run quality checks' })
  b.push({ t: 'table', head: ['Check', 'Question', 'Result'], rows: r.dataQuality.qualityChecks.map((q) => [q.id, q.question, q.detail]) })

  b.push({ t: 'h2', text: '11. Disputes' })
  if (r.disputes.length === 0) b.push({ t: 'p', text: 'No disputes recorded for this vendor.' })
  else
    b.push({
      t: 'table',
      head: ['Dispute', 'Target', 'Reason', 'Status', 'Submitted by', 'Created', 'Statement'],
      rows: r.disputes.map((d) => [d.id, d.target, d.reason, d.status, d.submitterRole, d.createdAt, d.statement]),
    })
  b.push({ t: 'p', text: 'A dispute never overwrites an observation; the original result stands until a later run corrects it.' })

  b.push({ t: 'h2', text: '12. Limitations' })
  b.push({ t: 'list', items: r.limitations })
  b.push({ t: 'rule' })
  for (const x of r.positioning) b.push({ t: 'p', text: x })
  return b
}
