/**
 * CSV export of a vendor report: one row per metric, one per evidence item,
 * one per benchmark, one per dispute, plus the positioning notes. A
 * `record_type` column says which kind each row is. Every cell is
 * formula-guarded and stripped of invisible characters (escape.ts).
 */

import type { ReportModel } from './document.ts'
import { csvRow } from './escape.ts'

export const CSV_HEAD = [
  'record_type',
  'vendor_id',
  'run_id',
  'methodology_version',
  'goal_id',
  'metric_id',
  'value',
  'numerator',
  'denominator',
  'gap',
  'confidence',
  'subject',
  'interpretation',
  'reading',
  'evidence_id',
  'snapshot_id',
  'source_id',
  'detail',
]

export function renderCsv(r: ReportModel): string {
  const vendorId = r.vendor['Vendor id'] ?? ''
  const runId = r.scope['Run id'] ?? ''
  const mv = r.methodology.version
  const rows: unknown[][] = [CSV_HEAD]
  const row = (o: Partial<Record<(typeof CSV_HEAD)[number], unknown>>): unknown[] =>
    CSV_HEAD.map((h) => (h === 'vendor_id' ? vendorId : h === 'run_id' ? runId : h === 'methodology_version' ? mv : (o[h] ?? '')))

  for (const p of r.positioning) rows.push(row({ record_type: 'note', detail: p }))
  rows.push(row({ record_type: 'vendor', subject: r.vendor['Name'] ?? '', detail: `${r.vendor['Category'] ?? ''} ${r.vendor['Data kind'] ?? ''}`.trim() }))
  for (const g of [...r.measuredGoals, ...r.unverifiableGoals]) rows.push(row({ record_type: 'goal', goal_id: g.goalId, value: g.status, detail: g.statusReason }))
  for (const d of r.dimensions) rows.push(row({ record_type: 'dimension', metric_id: d.metricId, value: d.value, detail: `${d.dimension} ${d.status}` }))
  for (const m of r.metrics)
    rows.push(
      row({
        record_type: 'metric',
        goal_id: m.goalId,
        metric_id: m.metricId,
        value: m.value,
        numerator: m.numerator,
        denominator: m.denominator,
        gap: m.gap,
        confidence: m.confidence,
        detail: m.calculation,
      }),
    )
  for (const e of r.evidence)
    rows.push(
      row({
        record_type: 'evidence',
        metric_id: e.metricId,
        confidence: e.confidence,
        subject: e.subject,
        interpretation: e.interpretation,
        reading: e.reading,
        evidence_id: e.id,
        snapshot_id: e.snapshotId,
        source_id: e.sourceId,
        detail: e.collectedAt,
      }),
    )
  for (const b of r.benchmarks)
    rows.push(row({ record_type: 'benchmark', metric_id: b.metricId, value: b.current, detail: `${b.peerGroup}: peer median ${b.peerMedian} (${b.peerCount} peers). ${b.wording}` }))
  for (const d of r.disputes) rows.push(row({ record_type: 'dispute', subject: d.target, value: d.status, reading: d.statement, detail: `${d.id} ${d.reason}` }))
  return `${rows.map(csvRow).join('\r\n')}\r\n`
}
