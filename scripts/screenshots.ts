/**
 * Captures the README screenshots from the real production build: the API
 * serves apps/web/dist and the published demo bundle on one origin, exactly
 * as deployed (minus HTTPS). Every screenshot shows synthetic demo data.
 *
 *   npm run build && node scripts/screenshots.ts
 *
 * Writes docs/screenshots/*.png.
 */
import { spawn } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { chromium } from '@playwright/test'
import type { Browser, Page } from '@playwright/test'
import type { RunIndex, RunSummary, VendorDetail } from '../packages/core/src/model/index.ts'

const root = join(import.meta.dirname, '..')
const out = join(root, 'docs', 'screenshots')
mkdirSync(out, { recursive: true })
const PORT = 8798
const base = `http://127.0.0.1:${PORT}`

const data = join(root, 'apps', 'web', 'public', 'data')
const index = JSON.parse(readFileSync(join(data, 'index.json'), 'utf8')) as RunIndex
const summary = JSON.parse(readFileSync(join(data, 'runs', index.latestRunId, 'summary.json'), 'utf8')) as RunSummary

// The profile shown is the vendor whose goals span the most distinct states,
// so one screenshot shows verified, partial and not-externally-verifiable side by side.
const profile = [...summary.vendors].sort(
  (a, b) => new Set(b.goals.map((g) => g.status)).size - new Set(a.goals.map((g) => g.status)).size || b.anomalies.length - a.anomalies.length,
)[0]!.vendor.id
// A record whose CWE or CPE came only from a third-party (ADP) container: the CNA-vs-ADP view.
const enrichedCve = (() => {
  for (const v of summary.vendors) {
    const detail = JSON.parse(readFileSync(join(data, 'runs', index.latestRunId, 'vendors', `${v.vendor.id}.json`), 'utf8')) as VendorDetail
    const rec = detail.cves.find((c) => c.cna.cwes.length === 0 && c.adp.some((a) => a.cwes.length > 0))
    if (rec) return rec.id
  }
  return null
})()
const compareIds = summary.vendors
  .filter((v) => v.dimensions.every((d) => d.value !== null))
  .slice(0, 3)
  .map((v) => v.vendor.id)

const server = spawn(process.execPath, ['apps/api/src/index.ts', '--production'], {
  cwd: root,
  env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1', TOUCHSTONE_DB: ':memory:', TOUCHSTONE_LOG_LEVEL: 'warn', TOUCHSTONE_RATE_LIMIT_PER_MINUTE: '5000' },
  stdio: 'inherit',
})

async function waitForServer() {
  for (let i = 0; i < 60; i++) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 500))
  }
  throw new Error('server did not start')
}

async function settle(page: Page) {
  await page.mouse.move(4, 4)
  await page.waitForLoadState('networkidle').catch(() => {})
  await page.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running'), undefined, { timeout: 15_000 }).catch(() => {})
  await page.waitForTimeout(400)
}

async function shot(page: Page, name: string) {
  await settle(page)
  await page.screenshot({ path: join(out, `${name}.png`) })
  console.log('wrote', name)
}

async function context(browser: Browser, opts: { width: number; height: number; dark?: boolean; mobile?: boolean }) {
  const ctx = await browser.newContext({
    viewport: { width: opts.width, height: opts.height },
    deviceScaleFactor: opts.mobile ? 2 : 1,
    colorScheme: opts.dark ? 'dark' : 'light',
    reducedMotion: 'no-preference',
    ...(opts.mobile ? { isMobile: true, hasTouch: true } : {}),
  })
  return ctx.newPage()
}

let browser: Browser | null = null
try {
  await waitForServer()
  browser = await chromium.launch()

  const page = await context(browser, { width: 1440, height: 1000 })
  await page.goto(`${base}/`)
  await shot(page, '01-landing')

  await page.setViewportSize({ width: 1440, height: 1200 })
  await page.goto(`${base}/app`)
  await shot(page, '02-overview')

  await page.setViewportSize({ width: 1440, height: 1400 })
  await page.goto(`${base}/app/vendors/${profile}`)
  await shot(page, '03-vendor-profile')

  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.getByRole('button', { name: /How was this calculated\?/ }).first().click()
  await page.getByRole('dialog').waitFor()
  await shot(page, '04-how-calculated')
  await page.keyboard.press('Escape')

  await page.setViewportSize({ width: 1440, height: 1200 })
  await page.goto(`${base}/app/cannot-see`)
  await shot(page, '05-evidence-we-cannot-see')

  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.goto(`${base}/app/compare?v=${compareIds.join(',')}`)
  await shot(page, '06-compare')

  if (enrichedCve) {
    await page.goto(`${base}/app/cves/${enrichedCve}`)
    await shot(page, '07-cna-vs-adp')
  }

  await page.goto(`${base}/app/runs?reproduce=${index.latestRunId}`)
  await page.getByText(/identical|reproduced/i).first().waitFor({ timeout: 30_000 }).catch(() => {})
  await shot(page, '08-reproduce')

  await page.goto(`${base}/app/vendors`)
  await shot(page, '09-leaderboard')

  await page.goto(`${base}/app/disputes`)
  await shot(page, '10-disputes')

  await page.goto(`${base}/app/trends`)
  await shot(page, '11-trends')

  await page.goto(`${base}/app/graph`)
  await shot(page, '12-evidence-graph')

  const dark = await context(browser, { width: 1440, height: 1100, dark: true })
  await dark.goto(`${base}/app/vendors/${profile}`)
  await shot(dark, '13-vendor-dark')

  const phone = await context(browser, { width: 390, height: 844, mobile: true })
  await phone.goto(`${base}/app/vendors/${profile}`)
  await shot(phone, '14-vendor-mobile')
  const overflow = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
  if (overflow > 2) console.warn(`warning: mobile vendor profile overflows horizontally by ${overflow}px`)
} finally {
  await browser?.close()
  server.kill()
}
