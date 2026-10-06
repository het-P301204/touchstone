/**
 * Command palette (Ctrl/Cmd+K). A combobox over navigation commands and the
 * vendors of the active run. Arrow keys move, Enter runs, Esc closes.
 */
import { useId, useMemo, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from 'react-router'
import { motion } from 'motion/react'
import {
  ArrowRight,
  Building2,
  Bug,
  Columns3,
  Download,
  ListChecks,
  MessageSquareWarning,
  Microscope,
  RotateCw,
  Ruler,
  Search,
  Target,
  Users,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { GOALS } from '../lib/core.ts'
import { useUi } from '../state/ui.ts'
import { useActiveSummary } from '../data/hooks.ts'
import { useFocusTrap } from '../ui/useFocusTrap.ts'
import { Kbd } from '../ui/controls.tsx'

type Command = { id: string; group: string; label: string; hint?: string; icon: LucideIcon; keywords?: string; run: () => void }

const CVE_ID = /^(CVE|DEMO)-\d{4}-\d{4,}$/i

export function CommandPalette() {
  const setOpen = useUi((s) => s.setCommandOpen)
  const setMode = useUi((s) => s.setMode)
  const navigate = useNavigate()
  const summary = useActiveSummary()
  const [query, setQuery] = useState('')
  const [active, setActive] = useState(0)
  const ref = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLInputElement>(null)
  const listId = useId()
  const close = () => setOpen(false)
  useFocusTrap(ref, true, { onEscape: close, initialFocus: inputRef })

  const go = (to: string) => () => {
    close()
    navigate(to)
  }

  const commands = useMemo<Command[]>(() => {
    const base: Command[] = [
      { id: 'signatories', group: 'Go to', label: 'Open Signatories', icon: Users, run: go('/app/signatories') },
      { id: 'compare', group: 'Go to', label: 'Compare Vendors', icon: Columns3, run: go('/app/compare') },
      { id: 'evidence', group: 'Go to', label: 'View Evidence', hint: 'Evidence ledger', icon: ListChecks, run: go('/app/evidence') },
      { id: 'cves', group: 'Go to', label: 'Open CVE', hint: 'CVE explorer', icon: Bug, keywords: 'cve record', run: go('/app/cves') },
      { id: 'methodology', group: 'Go to', label: 'View Methodology', icon: Ruler, run: go('/app/methodology') },
      { id: 'refresh', group: 'Actions', label: 'Refresh Dataset', hint: 'Overview → pipeline', icon: RotateCw, run: go('/app?refresh=1#pipeline') },
      { id: 'disputes', group: 'Go to', label: 'View Disputes', icon: MessageSquareWarning, run: go('/app/disputes') },
      {
        id: 'research',
        group: 'Actions',
        label: 'Open Research Mode',
        hint: 'Switches the audience mode',
        icon: Microscope,
        run: () => {
          setMode('researcher')
          go('/app/research')()
        },
      },
      ...GOALS.map<Command>((g) => ({
        id: `goal-${g.id}`,
        group: 'Goals',
        label: `Open Goal ${g.number}: ${g.name}`,
        icon: Target,
        keywords: `${g.id} ${g.shortName}`,
        run: go(`/app/goals/${g.id}`),
      })),
    ]
    if (summary.status === 'ready') {
      for (const v of summary.data.summary.vendors) {
        base.push({
          id: `vendor-${v.vendor.id}`,
          group: 'Search Vendor',
          label: v.vendor.canonicalName,
          hint: v.vendor.id,
          icon: Building2,
          keywords: v.vendor.aliases.map((a) => a.value).join(' '),
          run: go(`/app/vendors/${v.vendor.id}`),
        })
        base.push({
          id: `export-${v.vendor.id}`,
          group: 'Export Report',
          label: `Export Report: ${v.vendor.canonicalName}`,
          icon: Download,
          keywords: 'export pdf markdown csv json',
          run: go(`/app/vendors/${v.vendor.id}#export`),
        })
      }
    }
    return base
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [summary.status])

  const q = query.trim().toLowerCase()
  const results = useMemo(() => {
    const out: Command[] = []
    if (CVE_ID.test(query.trim())) {
      const id = query.trim().toUpperCase()
      out.push({ id: `cve-${id}`, group: 'Open CVE', label: `Open ${id}`, icon: Bug, run: go(`/app/cves/${encodeURIComponent(id)}`) })
    }
    const matches = commands.filter((c) => {
      if (!q) return c.group !== 'Export Report' && c.group !== 'Search Vendor'
      return `${c.label} ${c.hint ?? ''} ${c.keywords ?? ''} ${c.group}`.toLowerCase().includes(q)
    })
    return [...out, ...matches].slice(0, 40)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [commands, q, query])

  const clamped = Math.min(active, Math.max(0, results.length - 1))

  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActive((a) => Math.min(a + 1, results.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActive((a) => Math.max(a - 1, 0))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      results[clamped]?.run()
    }
  }

  let lastGroup = ''
  return createPortal(
    <div className="fixed inset-0 z-[80] flex items-start justify-center px-3 pt-[10vh]">
      <motion.div aria-hidden="true" className="absolute inset-0 bg-[rgb(var(--graphite-fixed)/0.4)]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} onClick={close} />
      <motion.div
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-label="Command palette"
        className="relative w-full max-w-xl overflow-hidden rounded-panel bg-surface shadow-overlay ring-1 ring-line"
        initial={{ opacity: 0, y: -8, scale: 0.98 }}
        animate={{ opacity: 1, y: 0, scale: 1 }}
        transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
      >
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search aria-hidden="true" className="size-5 shrink-0 text-ink-3" />
          <input
            ref={inputRef}
            role="combobox"
            aria-expanded="true"
            aria-controls={listId}
            aria-activedescendant={results[clamped] ? `${listId}-${results[clamped].id}` : undefined}
            aria-label="Search vendors, goals and commands"
            placeholder="Search vendors, goals, CVE ids, commands…"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setActive(0)
            }}
            onKeyDown={onKeyDown}
            className="h-14 min-w-0 flex-1 bg-transparent text-[0.975rem] text-ink placeholder:text-ink-3 focus:outline-none"
          />
          <Kbd>Esc</Kbd>
        </div>
        <ul id={listId} role="listbox" aria-label="Results" className="ts-scroll-thin max-h-[min(60vh,28rem)] overflow-y-auto p-2">
          {results.length === 0 && <li className="px-3 py-6 text-center text-sm text-ink-3">No command or vendor matches “{query}”.</li>}
          {results.map((c, i) => {
            const header = c.group !== lastGroup ? c.group : null
            lastGroup = c.group
            const Icon = c.icon
            return (
              <li key={c.id} role="presentation">
                {header && <p className="ts-eyebrow px-3 pb-1 pt-3">{header}</p>}
                <div
                  id={`${listId}-${c.id}`}
                  role="option"
                  aria-selected={i === clamped}
                  onMouseMove={() => setActive(i)}
                  onClick={() => c.run()}
                  className={cx('flex cursor-pointer items-center gap-3 rounded-[12px] px-3 py-2.5 text-sm', i === clamped ? 'bg-paper-2 text-ink' : 'text-ink-2')}
                >
                  <Icon aria-hidden="true" className="size-4 shrink-0 text-ink-3" />
                  <span className="ts-ident min-w-0 flex-1 font-semibold">{c.label}</span>
                  {c.hint && <span className="ts-ident hidden max-w-[40%] truncate font-mono text-[0.72rem] text-ink-3 sm:block">{c.hint}</span>}
                  {i === clamped && <ArrowRight aria-hidden="true" className="size-4 shrink-0 text-ink-3" />}
                </div>
              </li>
            )
          })}
        </ul>
      </motion.div>
    </div>,
    document.body,
  )
}
