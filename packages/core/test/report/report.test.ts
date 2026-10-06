import { describe, expect, it } from 'vitest'
import { executeRun } from '../../src/run/run.ts'
import { historySeries, splitForPublication } from '../../src/publish/split.ts'
import { methodologyVersion } from '../../src/methodology/versions.ts'
import { vendorReport } from '../../src/report/vendor-report.ts'
import { POSITIONING, REPORT_SECTIONS } from '../../src/report/document.ts'
import { csvCell, mdCell, mdInline } from '../../src/report/escape.ts'
import { encodeWinAnsi } from '../../src/report/pdf.ts'
import { cohortInputs } from '../fixtures/run-fixture.ts'
import type { Dispute } from '../../src/model/index.ts'

const RLO = String.fromCodePoint(0x202e)
const ZWSP = String.fromCodePoint(0x200b)

function setup() {
  const inputs = cohortInputs()
  // A hostile vendor name and claim: formula prefix, pipe, bidi override, zero-width space.
  const nw = inputs.vendors.find((v) => v.id === 'northwind')!
  nw.canonicalName = `=HYPERLINK("http://evil.example")|Northwind${RLO}cod.exe${ZWSP}`
  const out = executeRun(inputs)
  const { summary, vendors } = splitForPublication(out, methodologyVersion('1.1.0'))
  const disputes: Dispute[] = [
    {
      id: 'DSP-0001',
      vendorId: 'northwind',
      target: { kind: 'CVE', id: 'DEMO-2026-0100' },
      runId: out.manifest.runId,
      reason: 'INCORRECT_CVE_MAPPING',
      submitterRole: 'VENDOR',
      statement: `@SUM(A1:A9) | injected ${RLO}text`,
      evidenceUrls: [],
      status: 'OPEN',
      createdAt: '2026-10-06T09:00:00Z',
      history: [{ at: '2026-10-06T09:00:00Z', from: null, to: 'OPEN', actor: 'fixture', note: 'opened' }],
      synthetic: true,
    },
  ]
  return { summary, detail: vendors['northwind']!, disputes, history: historySeries([out]) }
}

describe('vendorReport', () => {
  const { summary, detail, disputes, history } = setup()

  it('markdown has every section and both positioning sentences', () => {
    const md = vendorReport(summary, detail, disputes, history, 'markdown') as string
    REPORT_SECTIONS.forEach((s, i) => expect(md).toContain(`## ${i + 1}. ${s}`))
    for (const p of POSITIONING) expect(md).toContain(mdInline(p))
    expect(md).toContain('no composite score')
  })

  it('markdown escapes pipes and strips bidi/invisible characters', () => {
    const md = vendorReport(summary, detail, disputes, history, 'markdown') as string
    expect(md).not.toContain(RLO)
    expect(md).not.toContain(ZWSP)
    expect(md).toContain('\\|Northwind')
    expect(md).toContain('\\| injected')
    // no unescaped pipe from the vendor name can open a table cell
    const nameRow = md.split('\n').find((l) => l.startsWith('| Name |'))!
    // "| Name | <value> |": exactly three structural pipes; the vendor's pipe is escaped
    expect(nameRow.replace(/\\\|/g, '').split('|').length - 1).toBe(3)
    expect(nameRow).toContain('\\(')
  })

  it('csv neutralises formula injection and strips invisible characters', () => {
    const csv = vendorReport(summary, detail, disputes, history, 'csv') as string
    expect(csv).not.toContain(RLO)
    const lines = csv.split('\r\n')
    expect(lines[0]!.startsWith('record_type,vendor_id')).toBe(true)
    // the dispute statement and the vendor name start with formula triggers and must be prefixed
    expect(lines.find((l) => l.startsWith('dispute,'))!).toContain(",'@SUM(A1:A9) | injected text,")
    expect(lines.find((l) => l.startsWith('vendor,'))!).toContain(`"'=HYPERLINK(""http://evil.example"")|Northwindcod.exe"`)
    // positioning notes are rows
    expect(lines.filter((l) => l.startsWith('note,'))).toHaveLength(2)
    // no cell begins with a formula trigger
    for (const line of lines.slice(1)) {
      for (const cell of line.match(/("([^"]|"")*"|[^,]*)(,|$)/g) ?? []) {
        const c = cell.replace(/,$/, '').replace(/^"/, '')
        expect(/^[=+@\t\r]/.test(c) || /^-[^0-9]/.test(c), `cell ${c}`).toBe(false)
      }
    }
  })

  it('csvCell guards every trigger, including after whitespace and full-width forms', () => {
    for (const x of ['=1+1', '+1', '-1+2', '@SUM(A1)', '\tx', '\rx', '  =cmd', String.fromCodePoint(0xff1d) + '1']) {
      expect(csvCell(x).replace(/^"/, '').startsWith("'")).toBe(true)
    }
    expect(csvCell(-3.5)).toBe('-3.5')
    expect(csvCell('a,b')).toBe('"a,b"')
    expect(csvCell('say "hi"')).toBe('"say ""hi"""')
    expect(csvCell(`${RLO}=x`)).toBe("'=x")
    expect(mdCell('a|b\nc')).toBe('a\\|b c')
  })

  it('json parses and contains the sections and positioning', () => {
    const j = JSON.parse(vendorReport(summary, detail, disputes, history, 'json') as string)
    for (const k of ['vendor', 'scope', 'methodology', 'dataSources', 'measuredGoals', 'unverifiableGoals', 'metrics', 'evidence', 'history', 'dataQuality', 'disputes', 'limitations']) expect(j).toHaveProperty(k)
    expect(j.positioning).toEqual(POSITIONING)
    expect(j.unverifiableGoals.map((g: { goalId: string }) => g.goalId)).toEqual(['G1', 'G2', 'G4', 'G7'])
    expect(j.unverifiableGoals[0].claims[0]).toMatch(/^Unverified claim:/)
    expect(j.disputes).toHaveLength(1)
  })

  it('pdf is a well-formed, deterministic PDF 1.4 file', () => {
    const a = vendorReport(summary, detail, disputes, history, 'pdf') as Uint8Array
    const b = vendorReport(summary, detail, disputes, history, 'pdf') as Uint8Array
    expect(a).toBeInstanceOf(Uint8Array)
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(true)
    const text = Buffer.from(a).toString('latin1')
    expect(text.startsWith('%PDF-1.4')).toBe(true)
    expect(text.trimEnd().endsWith('%%EOF')).toBe(true)
    // startxref points at the xref table
    const xref = Number(/startxref\n(\d+)/.exec(text)![1])
    expect(text.slice(xref, xref + 4)).toBe('xref')
    // each object offset in the xref table points at "<n> 0 obj"
    const entries = text.slice(xref).split('\n').slice(3).filter((l) => / 00000 n $/.test(l))
    entries.forEach((l, i) => expect(text.slice(Number(l.slice(0, 10)), Number(l.slice(0, 10)) + 12)).toContain(`${i + 1} 0 obj`))
    expect(text).toContain('Not externally verifiable')
    expect(text).not.toContain(RLO)
  })

  it('winansi encoding transliterates and never emits raw control bytes', () => {
    expect(encodeWinAnsi('a → b')).toEqual([97, 32, 45, 62, 32, 98])
    expect(encodeWinAnsi(`x${RLO}y`).includes(0x202e)).toBe(false)
  })
})
