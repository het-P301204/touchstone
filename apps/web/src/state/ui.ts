/**
 * UI state: theme, audience mode, the run being viewed, and the global
 * overlays (command palette, "How was this calculated?" drawer, source viewer).
 * The resolved theme is written to <html data-theme>; public/theme-init.js
 * applies the same rule before first paint.
 */
import { create } from 'zustand'

export type ThemePref = 'light' | 'dark' | 'system'
/** Audience mode changes emphasis, never the numbers. */
export type AudienceMode = 'procurement' | 'researcher' | 'ciso'

export type MetricTarget = { vendorId: string; runId: string; goalId: string; metricId: string }
export type EvidenceTarget = { vendorId: string; runId: string; evidenceId: string }

const THEME_KEY = 'touchstone.theme'
const MODE_KEY = 'touchstone.mode'

function lsGet(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null
  }
}
function lsSet(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    /* storage unavailable: preference lasts for this session */
  }
}

function readTheme(): ThemePref {
  const v = typeof window !== 'undefined' ? lsGet(THEME_KEY) : null
  return v === 'light' || v === 'dark' || v === 'system' ? v : 'system'
}
function readMode(): AudienceMode {
  const v = typeof window !== 'undefined' ? lsGet(MODE_KEY) : null
  return v === 'researcher' || v === 'ciso' || v === 'procurement' ? v : 'procurement'
}

function systemDark(): boolean {
  return typeof window !== 'undefined' && !!window.matchMedia?.('(prefers-color-scheme: dark)').matches
}

const PAPER_LIGHT = '#F6F2EA'
const PAPER_DARK = '#1B1A19'

export function applyTheme(pref: ThemePref): 'light' | 'dark' {
  const resolved = pref === 'system' ? (systemDark() ? 'dark' : 'light') : pref
  document.documentElement.setAttribute('data-theme', resolved)
  document.querySelectorAll<HTMLMetaElement>('meta[name="theme-color"]').forEach((m) => {
    const forMedia = m.media.includes('dark') ? PAPER_DARK : PAPER_LIGHT
    m.content = pref === 'system' ? forMedia : resolved === 'dark' ? PAPER_DARK : PAPER_LIGHT
  })
  return resolved
}

interface UiState {
  theme: ThemePref
  resolvedTheme: 'light' | 'dark'
  mode: AudienceMode
  selectedRunId: string | null
  commandOpen: boolean
  navOpen: boolean
  metric: MetricTarget | null
  evidence: EvidenceTarget | null
  setTheme: (t: ThemePref) => void
  setMode: (m: AudienceMode) => void
  setSelectedRunId: (id: string | null) => void
  setCommandOpen: (open: boolean) => void
  setNavOpen: (open: boolean) => void
  openMetric: (t: MetricTarget | null) => void
  openEvidence: (t: EvidenceTarget | null) => void
}

const initialTheme = readTheme()

export const useUi = create<UiState>((set) => ({
  theme: initialTheme,
  resolvedTheme: typeof document !== 'undefined' ? applyTheme(initialTheme) : 'light',
  mode: readMode(),
  selectedRunId: null,
  commandOpen: false,
  navOpen: false,
  metric: null,
  evidence: null,
  setTheme: (theme) => {
    lsSet(THEME_KEY, theme)
    set({ theme, resolvedTheme: applyTheme(theme) })
  },
  setMode: (mode) => {
    lsSet(MODE_KEY, mode)
    set({ mode })
  },
  setSelectedRunId: (selectedRunId) => set({ selectedRunId }),
  setCommandOpen: (commandOpen) => set({ commandOpen }),
  setNavOpen: (navOpen) => set({ navOpen }),
  openMetric: (metric) => set({ metric }),
  openEvidence: (evidence) => set({ evidence }),
}))

if (typeof window !== 'undefined' && window.matchMedia) {
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
    const { theme } = useUi.getState()
    if (theme === 'system') useUi.setState({ resolvedTheme: applyTheme('system') })
  })
}
