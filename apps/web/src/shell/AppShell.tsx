/**
 * App shell for /app/*: top bar, left navigation (a drawer below lg), the
 * historical-run banner, and the global overlays.
 */
import { useEffect, useRef } from 'react'
import { Link, NavLink, Outlet, useLocation } from 'react-router'
import { AnimatePresence, motion } from 'motion/react'
import { History, Menu, Search, X } from 'lucide-react'
import { cx } from '../lib/cx.ts'
import { useUi } from '../state/ui.ts'
import type { AudienceMode } from '../state/ui.ts'
import { useActiveSummary, useRunIndex, useSourceInfo } from '../data/hooks.ts'
import { Wordmark } from '../ui/Mark.tsx'
import { IconButton } from '../ui/Button.tsx'
import { DemoLabel, Kbd, Segmented } from '../ui/controls.tsx'
import { useFocusTrap } from '../ui/useFocusTrap.ts'
import { PRIMARY_NAV, SECONDARY_NAV } from './nav.ts'
import type { NavItem } from './nav.ts'
import { ThemeToggle } from './ThemeToggle.tsx'
import { GlobalOverlays, useCommandShortcut } from './GlobalOverlays.tsx'
import { SkipLink } from './SkipLink.tsx'
import { date } from '../lib/format.ts'

const MODES: { value: AudienceMode; label: string; title: string }[] = [
  { value: 'procurement', label: 'Procurement', title: 'Scorecard emphasis, with the assessment-scope note' },
  { value: 'researcher', label: 'Researcher', title: 'Queries, raw records, mappings, snapshots and evidence ids' },
  { value: 'ciso', label: 'CISO', title: 'Measured evidence, unverified areas and questions to ask' },
]

function ModeSwitch({ className }: { className?: string }) {
  const mode = useUi((s) => s.mode)
  const setMode = useUi((s) => s.setMode)
  return <Segmented label="Audience mode" size="sm" value={mode} onChange={setMode} options={MODES} className={className} />
}

function TopBar() {
  const setCommandOpen = useUi((s) => s.setCommandOpen)
  const setNavOpen = useUi((s) => s.setNavOpen)
  const index = useRunIndex()
  const isDemo = index.status === 'ready' && index.data.mode === 'DEMO'
  return (
    <header className="sticky top-0 z-40 border-b border-line bg-paper/90 backdrop-blur supports-[backdrop-filter]:bg-paper/80">
      <div className="flex h-16 items-center gap-2 px-3 sm:px-5">
        <IconButton label="Open navigation" className="lg:hidden" onClick={() => setNavOpen(true)}>
          <Menu />
        </IconButton>
        <Link to="/" className="mr-1 flex min-w-0 items-center rounded-control px-1 py-1" aria-label="TOUCHSTONE home">
          <Wordmark compact />
        </Link>
        {isDemo && <DemoLabel className="hidden xs:inline-flex" />}
        <nav aria-label="Sections" className="ml-3 hidden items-center gap-1 xl:flex">
          {[
            { to: '/app/research', label: 'Research' },
            { to: '/app/methodology', label: 'Method' },
            { to: '/app/settings', label: 'Settings' },
          ].map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              className={({ isActive }) => cx('rounded-control px-3 py-2 text-sm font-semibold transition-colors', isActive ? 'text-ink' : 'text-ink-2 hover:text-ink')}
            >
              {l.label}
            </NavLink>
          ))}
        </nav>
        <div className="ml-auto flex items-center gap-1.5">
          <ModeSwitch className="hidden lg:block" />
          <button
            type="button"
            onClick={() => setCommandOpen(true)}
            className="ml-1 hidden h-10 items-center gap-2 rounded-control border border-line bg-surface-raised pl-3 pr-2 text-sm text-ink-3 transition-colors hover:border-line-strong hover:text-ink-2 sm:inline-flex"
          >
            <Search aria-hidden="true" className="size-4" />
            <span>Search</span>
            <span className="ml-3 flex gap-0.5">
              <Kbd>Ctrl</Kbd>
              <Kbd>K</Kbd>
            </span>
          </button>
          <IconButton label="Search and commands" className="sm:hidden" onClick={() => setCommandOpen(true)}>
            <Search />
          </IconButton>
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}

function NavList({ items, adminEnabled, onNavigate }: { items: NavItem[]; adminEnabled: boolean; onNavigate?: () => void }) {
  return (
    <ul className="space-y-0.5">
      {items
        .filter((i) => !i.adminOnly || adminEnabled)
        .map(({ to, label, icon: Icon, end }) => (
          <li key={to}>
            <NavLink
              to={to}
              end={end}
              onClick={onNavigate}
              className={({ isActive }) =>
                cx(
                  'group relative flex h-9 items-center gap-3 rounded-[12px] px-3 text-[0.875rem] font-semibold transition-colors',
                  isActive ? 'bg-surface-raised text-ink shadow-soft ring-1 ring-line' : 'text-ink-2 hover:bg-paper-2 hover:text-ink',
                )
              }
            >
              {({ isActive }) => (
                <>
                  <Icon aria-hidden="true" className={cx('size-[17px] shrink-0', isActive ? 'text-ink' : 'text-ink-3 group-hover:text-ink-2')} />
                  <span className="truncate">{label}</span>
                  {isActive && <span aria-hidden="true" className="absolute -left-3 top-2 h-5 w-[3px] rounded-r-full bg-marigold" />}
                </>
              )}
            </NavLink>
          </li>
        ))}
    </ul>
  )
}

function SidebarContent({ onNavigate }: { onNavigate?: () => void }) {
  const info = useSourceInfo()
  const summary = useActiveSummary()
  const adminEnabled = info.status === 'ready' && info.data.adminEnabled
  return (
    <div className="flex h-full flex-col">
      <nav aria-label="Application" className="px-4 pt-5">
        <NavList items={PRIMARY_NAV} adminEnabled={adminEnabled} onNavigate={onNavigate} />
        <p className="ts-eyebrow mb-2 mt-6 px-3">Research</p>
        <NavList items={SECONDARY_NAV} adminEnabled={adminEnabled} onNavigate={onNavigate} />
      </nav>
      <div className="mt-auto space-y-1.5 border-t border-line px-7 py-4 text-[0.72rem] text-ink-3">
        {summary.status === 'ready' ? (
          <>
            <p className="ts-num ts-ident">Run {summary.data.runId}</p>
            <p className="ts-num">Methodology {summary.data.summary.manifest.methodologyVersion}</p>
            <p className="ts-num">As of {date(summary.data.summary.manifest.asOf)}</p>
          </>
        ) : (
          <p>No run loaded</p>
        )}
        <p className="ts-num">{info.status === 'ready' ? (info.data.kind === 'api' ? 'Source: API' : 'Source: static bundle') : 'Source: detecting'}</p>
      </div>
    </div>
  )
}

function MobileNav() {
  const open = useUi((s) => s.navOpen)
  const setNavOpen = useUi((s) => s.setNavOpen)
  const ref = useRef<HTMLDivElement>(null)
  const close = () => setNavOpen(false)
  useFocusTrap(ref, open, { onEscape: close })
  return (
    <AnimatePresence>
      {open && (
        <div className="fixed inset-0 z-[60] lg:hidden">
          <motion.div aria-hidden="true" className="absolute inset-0 bg-[rgb(var(--graphite-fixed)/0.36)]" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} onClick={close} />
          <motion.div
            ref={ref}
            role="dialog"
            aria-modal="true"
            aria-label="Navigation"
            tabIndex={-1}
            className="absolute inset-y-0 left-0 flex w-[min(20rem,86vw)] flex-col overflow-y-auto bg-paper shadow-overlay outline-none"
            initial={{ x: '-100%' }}
            animate={{ x: 0 }}
            exit={{ x: '-100%' }}
            transition={{ duration: 0.28, ease: [0.16, 1, 0.3, 1] }}
          >
            <div className="flex h-16 items-center justify-between border-b border-line px-4">
              <Wordmark compact />
              <IconButton label="Close navigation" onClick={close}>
                <X />
              </IconButton>
            </div>
            <div className="border-b border-line px-4 py-3 lg:hidden">
              <ModeSwitch />
            </div>
            <SidebarContent onNavigate={close} />
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  )
}

function HistoricalRunBanner() {
  const summary = useActiveSummary()
  const setSelectedRunId = useUi((s) => s.setSelectedRunId)
  if (summary.status !== 'ready' || summary.data.isLatest) return null
  const m = summary.data.summary.manifest
  return (
    <div role="status" className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b border-plum/30 bg-plum/10 px-4 py-2.5 text-[0.84rem] text-plum-ink sm:px-6">
      <History aria-hidden="true" className="size-4 shrink-0" />
      <span className="min-w-0 flex-1">
        Viewing historical run <span className="ts-num font-semibold">{m.runId}</span> (as of {date(m.asOf)}, methodology {m.methodologyVersion}). Its stored figures are shown
        unchanged.
      </span>
      <button type="button" className="ts-link text-plum-ink" onClick={() => setSelectedRunId(null)}>
        Return to the latest run
      </button>
    </div>
  )
}

export function AppShell() {
  useCommandShortcut()
  const { pathname } = useLocation()
  const mainRef = useRef<HTMLElement>(null)
  useEffect(() => {
    window.scrollTo({ top: 0 })
  }, [pathname])
  return (
    <div className="min-h-dvh bg-paper">
      <SkipLink />
      <TopBar />
      <div className="mx-auto flex w-full max-w-[1680px]">
        <aside className="sticky top-16 hidden h-[calc(100dvh-4rem)] w-[248px] shrink-0 overflow-y-auto border-r border-line lg:block ts-scroll-thin">
          <SidebarContent />
        </aside>
        <div className="min-w-0 flex-1">
          <HistoricalRunBanner />
          <main id="main" ref={mainRef} tabIndex={-1} className="min-w-0 px-4 pb-20 pt-6 outline-none sm:px-6 sm:pt-8 xl:px-10">
            <Outlet />
          </main>
        </div>
      </div>
      <MobileNav />
      <GlobalOverlays />
    </div>
  )
}
