import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { MotionConfig } from 'motion/react'
import { RouterProvider } from 'react-router/dom'
import './fonts.ts'
import './index.css'
import './state/ui.ts'
import { router } from './router.tsx'

const root = document.getElementById('root')
if (!root) throw new Error('TOUCHSTONE: #root element missing')

createRoot(root).render(
  <StrictMode>
    {/* "user": motion follows prefers-reduced-motion. */}
    <MotionConfig reducedMotion="user">
      <RouterProvider router={router} />
    </MotionConfig>
  </StrictMode>,
)
