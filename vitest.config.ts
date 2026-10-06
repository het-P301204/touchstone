import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts', 'apps/api/test/**/*.test.ts', 'apps/cli/test/**/*.test.ts', 'tests/**/*.test.ts', 'apps/web/src/**/*.test.{ts,tsx}'],
    exclude: ['**/node_modules/**', 'tests/e2e/**'],
    environment: 'node',
    testTimeout: 30_000,
    pool: 'forks',
  },
})
