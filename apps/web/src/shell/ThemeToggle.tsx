import { Monitor, Moon, Sun } from 'lucide-react'
import { useUi } from '../state/ui.ts'
import type { ThemePref } from '../state/ui.ts'
import { IconButton } from '../ui/Button.tsx'
import { Segmented } from '../ui/controls.tsx'

const ORDER: ThemePref[] = ['system', 'light', 'dark']
const LABEL: Record<ThemePref, string> = { system: 'System theme', light: 'Light theme', dark: 'Dark theme' }

/** Compact cycling toggle for the top bar: system -> light -> dark. */
export function ThemeToggle() {
  const theme = useUi((s) => s.theme)
  const setTheme = useUi((s) => s.setTheme)
  const next = ORDER[(ORDER.indexOf(theme) + 1) % ORDER.length]!
  const Icon = theme === 'light' ? Sun : theme === 'dark' ? Moon : Monitor
  return (
    <IconButton label={`${LABEL[theme]} (switch to ${LABEL[next].toLowerCase()})`} onClick={() => setTheme(next)}>
      <Icon />
    </IconButton>
  )
}

/** Full three-way control for the settings page. */
export function ThemeSwitcher() {
  const theme = useUi((s) => s.theme)
  const setTheme = useUi((s) => s.setTheme)
  return (
    <Segmented
      label="Theme"
      value={theme}
      onChange={setTheme}
      options={[
        { value: 'light', label: 'Light', icon: <Sun /> },
        { value: 'dark', label: 'Dark', icon: <Moon /> },
        { value: 'system', label: 'System', icon: <Monitor /> },
      ]}
    />
  )
}
