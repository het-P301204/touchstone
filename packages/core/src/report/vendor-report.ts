/**
 * vendorReport: one vendor's published run as JSON, Markdown, CSV or PDF.
 * All four formats are built from the same ReportModel.
 */

import type { Dispute, HistorySeries, RunSummary, VendorDetail } from '../model/index.ts'
import { buildReportModel, reportBlocks } from './document.ts'
import { renderMarkdown } from './markdown.ts'
import { renderCsv } from './csv.ts'
import { renderPdf } from './pdf.ts'

export type ReportFormat = 'json' | 'markdown' | 'csv' | 'pdf'

export function vendorReport(summary: RunSummary, detail: VendorDetail, disputes: Dispute[], history: HistorySeries[], format: ReportFormat): string | Uint8Array {
  const model = buildReportModel(summary, detail, disputes, history)
  switch (format) {
    case 'json':
      return `${JSON.stringify(model, null, 2)}\n`
    case 'markdown':
      return renderMarkdown(reportBlocks(model))
    case 'csv':
      return renderCsv(model)
    case 'pdf':
      return renderPdf(reportBlocks(model), {
        title: model.title,
        footer: `TOUCHSTONE · ${summary.manifest.runId} · methodology ${summary.manifest.methodologyVersion} · public evidence only, not a complete security assessment`,
        created: summary.manifest.asOf,
      })
    default: {
      const never: never = format
      throw new Error(`Unknown report format ${String(never)}`)
    }
  }
}
