/**
 * Report and evidence downloads. With the API the server renders the report;
 * the static demo renders the same report in the browser with the engine's
 * own report module, so both paths produce the same document.
 */
import type { RunSummary, VendorDetail } from '@touchstone/core/model'
import { getSource } from '../data/source.ts'
import type { ReportFormat } from '../data/source.ts'

const MIME: Record<ReportFormat, string> = {
  pdf: 'application/pdf',
  markdown: 'text/markdown;charset=utf-8',
  csv: 'text/csv;charset=utf-8',
  json: 'application/json;charset=utf-8',
}
const EXT: Record<ReportFormat, string> = { pdf: 'pdf', markdown: 'md', csv: 'csv', json: 'json' }

export function saveBlob(data: BlobPart, filename: string, type: string): void {
  const url = URL.createObjectURL(new Blob([data], { type }))
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  a.remove()
  window.setTimeout(() => URL.revokeObjectURL(url), 4000)
}

export async function exportReport(summary: RunSummary, detail: VendorDetail, format: ReportFormat): Promise<void> {
  const src = await getSource()
  const filename = `touchstone-${detail.vendorId}-${summary.manifest.runId}.${EXT[format]}`
  if (src.reportUrl) {
    const res = await fetch(src.reportUrl(detail.vendorId, summary.manifest.runId, format))
    if (!res.ok) throw new Error(`Report request failed: ${res.status}`)
    saveBlob(await res.blob(), filename, MIME[format])
    return
  }
  const [{ vendorReport }, disputes, history] = await Promise.all([
    import('../../../../packages/core/src/report/vendor-report.ts'),
    src.disputes(),
    src.history([detail.vendorId]),
  ])
  const vendorDisputes = disputes.filter((d) => d.vendorId === detail.vendorId)
  const out = vendorReport(summary, detail, vendorDisputes, history, format)
  saveBlob(typeof out === 'string' ? out : new Uint8Array(out), filename, MIME[format])
}

export function downloadEvidence(summary: RunSummary, detail: VendorDetail): void {
  const payload = {
    note: 'TOUCHSTONE evidence export. Each item names the snapshot it was read from; re-run the run id to reproduce every figure.',
    manifest: summary.manifest,
    vendorId: detail.vendorId,
    evidence: detail.evidence,
    attributions: detail.attributions,
    exclusions: detail.exclusions,
  }
  saveBlob(JSON.stringify(payload, null, 2), `touchstone-evidence-${detail.vendorId}-${summary.manifest.runId}.json`, MIME.json)
}

export async function copyLink(path: string): Promise<boolean> {
  const url = new URL(`${import.meta.env.BASE_URL.replace(/\/$/, '')}${path}`, window.location.origin).toString()
  try {
    await navigator.clipboard.writeText(url)
    return true
  } catch {
    return false
  }
}
