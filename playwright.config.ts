import { defineConfig, devices } from '@playwright/test'

/**
 * End-to-end tests against the production build: the API serves apps/web/dist
 * and the published demo bundle on one origin with an in-memory database,
 * exactly as deployed (minus HTTPS). Run `npm run build` first.
 */
const PORT = 8797
export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: process.env['CI'] ? 1 : 0,
  reporter: process.env['CI'] ? [['github'], ['html', { open: 'never' }]] : 'list',
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 1000 } } },
    { name: 'mobile', use: { ...devices['Pixel 7'] }, grep: /@mobile/ },
  ],
  webServer: {
    command: 'node apps/api/src/index.ts --production',
    url: `http://127.0.0.1:${PORT}/api/health`,
    timeout: 60_000,
    reuseExistingServer: !process.env['CI'],
    env: {
      PORT: String(PORT),
      HOST: '127.0.0.1',
      TOUCHSTONE_DB: ':memory:',
      TOUCHSTONE_LOG_LEVEL: 'warn',
      TOUCHSTONE_RATE_LIMIT_PER_MINUTE: '5000',
    },
  },
})
