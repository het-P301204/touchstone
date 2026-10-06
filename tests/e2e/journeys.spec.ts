/**
 * The signature journey and the integrity rules, checked in a real browser
 * against the production build: search vendor -> profile -> what can and
 * cannot be measured -> open a metric -> formula, records, source -> reproduce.
 */
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { AxeBuilder } from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import type { RunIndex, RunSummary } from '../../packages/core/src/model/index.ts'

const data = join(import.meta.dirname, '..', '..', 'apps', 'web', 'public', 'data')
const index = JSON.parse(readFileSync(join(data, 'index.json'), 'utf8')) as RunIndex
const summary = JSON.parse(readFileSync(join(data, 'runs', index.latestRunId, 'summary.json'), 'utf8')) as RunSummary
const vendor = summary.vendors[0]!.vendor

const BANNED = /\b(compliant|non-compliant|noncompliant|insecure|is secure|more secure)\b/i

test('landing page states the claim and labels illustrative figures', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { level: 1 })).toContainText('A security pledge means nothing without a way to test it.')
  await expect(page.getByText(/does not conduct intrusive testing/i).first()).toBeVisible()
})

test('signature journey: vendor profile to the exact calculation and its source', async ({ page }) => {
  await page.goto(`/app/vendors/${vendor.id}`)
  await expect(page.getByRole('heading', { name: vendor.canonicalName }).first()).toBeVisible()
  // Demo data is never presented as a live measurement.
  await expect(page.getByText(/demo data/i).first()).toBeVisible()
  // The unmeasurable goals are labelled as such, not scored.
  await expect(page.getByText(/not externally verifiable/i).first()).toBeVisible()
  await page.getByRole('button', { name: /How was this calculated\?/ }).first().click()
  const drawer = page.getByRole('dialog')
  await expect(drawer).toBeVisible()
  await expect(drawer).toContainText(index.latestRunId)
  await expect(drawer).toContainText(/formula/i)
  await expect(drawer).toContainText(/query/i)
})

test('a published run reproduces in the browser with the identical outputs hash', async ({ page }) => {
  await page.goto(`/app/runs?reproduce=${index.latestRunId}`)
  const latest = index.runs.find((r) => r.runId === index.latestRunId)!
  await expect(page.getByText(latest.outputsHash.slice(0, 12)).first()).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText(/reproduced|identical/i).first()).toBeVisible({ timeout: 30_000 })
})

test('no page calls a vendor compliant, secure or insecure', async ({ page }) => {
  for (const path of ['/', '/app', '/app/vendors', `/app/vendors/${vendor.id}`, '/app/compare', '/app/cannot-see', '/methodology']) {
    await page.goto(path)
    await page.waitForLoadState('networkidle')
    const text = await page.locator('main').innerText()
    // The methodology states the rule itself ("never says compliant"), so only flag affirmative uses.
    const hits = text.split('\n').filter((l) => BANNED.test(l) && !/never|does not|not .*(say|use|call)|no .*word/i.test(l))
    expect(hits, `${path}: ${hits.join(' | ')}`).toEqual([])
  }
})

test('submitting a dispute keeps the original finding and shows the dispute beside it', async ({ request }) => {
  const res = await request.post('/api/disputes', {
    data: {
      vendorId: vendor.id,
      target: { kind: 'GOAL', id: 'G5' },
      runId: index.latestRunId,
      reason: 'OUTDATED_SOURCE',
      submitterRole: 'RESEARCHER',
      statement: 'End-to-end test: the policy was revised after the snapshot.',
      evidenceUrls: [],
    },
  })
  expect(res.status()).toBe(201)
  const before = summary.vendors[0]!.goals.find((g) => g.goalId === 'G5')!.status
  const goals = (await (await request.get(`/api/vendors/${vendor.id}/goals`)).json()) as unknown
  expect(JSON.stringify(goals)).toContain(before)
  expect(JSON.stringify(goals)).toContain('DISPUTED')
})

test('core pages have no serious accessibility violations', async ({ page }) => {
  for (const path of ['/', '/app', `/app/vendors/${vendor.id}`, '/app/cannot-see']) {
    await page.goto(path)
    await page.waitForLoadState('networkidle')
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze()
    const serious = result.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
    expect(serious.map((v) => `${path}: ${v.id} (${v.nodes.length})`)).toEqual([])
  }
})

test('vendor profile fits a phone without horizontal scrolling @mobile', async ({ page }) => {
  for (const path of ['/', '/app', `/app/vendors/${vendor.id}`, '/app/compare', '/app/cves']) {
    await page.goto(path)
    await page.waitForLoadState('networkidle')
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    expect(overflow, path).toBeLessThanOrEqual(2)
  }
})
