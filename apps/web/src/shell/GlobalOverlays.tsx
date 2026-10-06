/**
 * Overlays shared by the public site and the app: the command palette and
 * the "How was this calculated?" / source viewer drawers. Each is loaded on
 * first use so the landing page stays light.
 */
import { Suspense, lazy, useEffect, useState } from 'react'
import { useUi } from '../state/ui.ts'

const CommandPalette = lazy(() => import('./CommandPalette.tsx').then((m) => ({ default: m.CommandPalette })))
const MetricDrawer = lazy(() => import('../features/MetricDrawer.tsx').then((m) => ({ default: m.MetricDrawer })))
const EvidenceViewer = lazy(() => import('../features/EvidenceViewer.tsx').then((m) => ({ default: m.EvidenceViewer })))

export function useCommandShortcut() {
  const setCommandOpen = useUi((s) => s.setCommandOpen)
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setCommandOpen(!useUi.getState().commandOpen)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [setCommandOpen])
}

export function GlobalOverlays() {
  const commandOpen = useUi((s) => s.commandOpen)
  const metric = useUi((s) => s.metric)
  const evidence = useUi((s) => s.evidence)
  // Mount a drawer on first use and keep it mounted so its exit animation runs.
  const [everMetric, setEverMetric] = useState(false)
  const [everEvidence, setEverEvidence] = useState(false)
  if (metric && !everMetric) setEverMetric(true)
  if (evidence && !everEvidence) setEverEvidence(true)
  return (
    <Suspense fallback={null}>
      {commandOpen && <CommandPalette />}
      {everMetric && <MetricDrawer target={metric} />}
      {everEvidence && <EvidenceViewer target={evidence} />}
    </Suspense>
  )
}
