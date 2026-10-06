import {
  Building2,
  ChartLine,
  ChartNoAxesColumn,
  Columns3,
  FileSearch,
  Gauge,
  History,
  ListChecks,
  MessageSquareWarning,
  NotebookPen,
  Ruler,
  Settings2,
  Target,
  Users,
  Waypoints,
  Bug,
  Microscope,
  Wrench,
} from 'lucide-react'
import type { LucideIcon } from 'lucide-react'

export type NavItem = { to: string; label: string; icon: LucideIcon; end?: boolean; adminOnly?: boolean }

export const PRIMARY_NAV: NavItem[] = [
  { to: '/app', label: 'Overview', icon: Gauge, end: true },
  { to: '/app/signatories', label: 'Signatories', icon: Users },
  { to: '/app/vendors', label: 'Vendors', icon: Building2 },
  { to: '/app/compare', label: 'Compare', icon: Columns3 },
  { to: '/app/goals', label: 'Goals', icon: Target },
  { to: '/app/evidence', label: 'Evidence', icon: ListChecks },
  { to: '/app/cves', label: 'CVEs', icon: Bug },
  { to: '/app/trends', label: 'Trends', icon: ChartLine },
  { to: '/app/cohort', label: 'Cohort', icon: ChartNoAxesColumn },
  { to: '/app/methodology', label: 'Methodology', icon: Ruler },
  { to: '/app/disputes', label: 'Disputes', icon: MessageSquareWarning },
  { to: '/app/notebook', label: 'Notebook', icon: NotebookPen },
]

export const SECONDARY_NAV: NavItem[] = [
  { to: '/app/runs', label: 'Runs', icon: History },
  { to: '/app/graph', label: 'Evidence graph', icon: Waypoints },
  { to: '/app/research', label: 'Research view', icon: Microscope },
  { to: '/app/cannot-see', label: 'Evidence we cannot see', icon: FileSearch },
  { to: '/app/settings', label: 'Settings', icon: Settings2 },
  { to: '/app/admin', label: 'Administration', icon: Wrench, adminOnly: true },
]
