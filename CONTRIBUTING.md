# Contributing to TOUCHSTONE

Thank you for helping. TOUCHSTONE publishes statements about named organisations, so changes are held to two rules
above all: every figure must be reproducible, and every sentence about a vendor must be measurement language (see
[docs/methodology.md](docs/methodology.md#18-language-rules)).

## Setup

Requirements: **Node.js 24** or later (the code runs as TypeScript through Node's type stripping) and npm. No `make`,
no compiler toolchain, no database server: SQLite comes from Node's built-in `node:sqlite`. Works on Windows, macOS and
Linux.

```
git clone <repository url>
cd touchstone
npm ci
npm run demo:check     # the committed demo data matches the generator and the engine
npm test               # unit, integration, security and adversarial tests (Vitest)
```

Run the app:

```
npm run dev:api        # API on http://127.0.0.1:8787 (reloads on source changes)
npm run dev            # web app (Vite) in a second terminal; /api is proxied to the API
```

Or the production server, which serves the built web app and the API from one origin:

```
npm run build
npm start              # http://127.0.0.1:8787
```

Without the API the web app falls back to the static bundle in `apps/web/public/data`.

Configuration is environment-only; every variable is optional and documented in `.env.example`. Copy it to `.env`
(git-ignored) to change it.

## Scripts

| Script | What it does |
|---|---|
| `npm run dev` | Vite dev server for the web app |
| `npm run dev:api` | API with file watching |
| `npm run build` | type-check and build the web app into `apps/web/dist` |
| `npm run build:pages` | the same with base path `/touchstone/` for GitHub Pages |
| `npm start` | API in production mode, also serving `apps/web/dist` |
| `npm run lint` | ESLint over the whole repository |
| `npm run typecheck` | `tsc --noEmit` for the Node code and for the web app |
| `npm test` | Vitest, all test suites |
| `npm run test:e2e` | Playwright journeys (`tests/e2e`) against the production server; run `npm run build` first, and `npx playwright install chromium` once |
| `npm run demo:generate` | regenerate `fixtures/demo` from `scripts/demo/vendors.ts` |
| `npm run demo:build` | run the pipeline over every demo version; write `apps/web/public/data` and `fixtures/demo/expected` |
| `npm run demo:check` | regenerate both in memory; fail on any difference |
| `npm run touchstone -- <args>` | the CLI, for example `npm run touchstone -- reproduce TS-2026-10-06-3CC6` |
| `npm run verify` | lint, typecheck, demo:check, test and build, in that order (what CI's main job runs first) |

`node scripts/smoke.ts <baseUrl>` smoke-tests a running server; `node scripts/docs/vdp-rules-table.ts` prints the VDP
rule tables for the methodology document.

## Test layout

| Path | Covers |
|---|---|
| `packages/core/test/{normalize,identity,vdp,text}` | parsers and normalizers, attribution, VDP criteria, HTML-to-text |
| `packages/core/test/{measure,assess,evidence,run,publish,report}` | metrics, goal status, cohort and anomalies, evidence ledger, runs and reproducibility, publication split, reports |
| `packages/core/test/fixtures` | builders for small in-memory runs |
| `packages/collect/test` | safeFetch (injected resolver and transport, no network), collectors, demo loader |
| `apps/api/test` | routes, disputes and their database triggers, refresh jobs, security middleware, the real engine behind the API |
| `apps/cli/test` | CLI commands and exit codes |
| `apps/web/src/**/*.test.ts` | web app logic |
| `tests/security` | security review tests; a test named `FINDING ...` demonstrates a confirmed issue and fails while it exists |
| `tests/adversarial` | cross-module adversarial tests; a test named `DEFECT ...` documents a defect and fails while it is open |
| `tests/regression/methodology.test.ts` | pins each methodology version's fingerprint and re-executes every published demo run against `fixtures/demo/expected` |
| `tests/e2e` | Playwright journeys and an axe accessibility check (`playwright.config.ts`; not part of `npm test`) |

No Vitest test touches the network. Tests use the synthetic fixtures, small in-memory builders, or the real documents in
`fixtures/real/`.

## Engine purity rules

`packages/core/src` is the measurement engine. It runs in Node and in the browser and must be deterministic. ESLint
(`eslint.config.js`) enforces, inside that directory:

- no `Date.now()` (the caller passes `asOf`) and no `Math.random()`;
- no `fetch`, `XMLHttpRequest`, `document`, `window` or `DOMParser`;
- no Node built-ins (`node:*`, `fs`, `path`, `child_process`, `http`, `https`, `net`);
- no `eval` and no `new Function`.

Everywhere (Node runs TypeScript by type stripping, which cannot emit runtime code for these): no `enum`, no
`namespace`, no constructor parameter properties; type-only imports use `import type`; import specifiers carry the
real `.ts` extension. Also enforced: no `any`, `===` only.

Other expectations for engine code: sort anything whose order reaches an output; never coerce an unknown to 0; give
every null metric a `gap`; strip invisible characters (`util/sanitize.ts`) from any remote text you store or quote.

## Changing the methodology

A published figure never changes without the methodology version changing. To change a formula, a parameter or a rule
that can move a figure:

1. **Add a version** to `METHODOLOGY_VERSIONS` in `packages/core/src/methodology/versions.ts` with a new semver, its
   `releasedOn` date, a `changes` entry that says what changed **and its expected effect on outputs**, its full
   `parameters`, and bumped `scoringVersion` (or `parserVersion` for a normalizer change). Never edit the parameters of
   an existing version.
2. **Gate the behaviour on the version's parameters**, so a run under an older version still computes the old way.
3. **Record which metrics changed** in `METRIC_CHANGES_BY_VERSION` (`packages/core/src/measure/definitions.ts`), so
   historical values are not compared across the change. Update the metric's `formula` and `eligibility` strings, and
   the goal's `statusRule` in `methodology/goals.ts` if the status logic changed.
4. **Update `CURRENT_METHODOLOGY_VERSION`** and `docs/methodology.md` (re-run `node scripts/docs/vdp-rules-table.ts` if
   a VDP rule changed).
5. **Regenerate:** `npm run demo:build`. The demo build applies the latest version released on or before each dataset
   date.
6. **Review the expected-manifest diff** in `fixtures/demo/expected/*.manifest.json`. Runs dated before `releasedOn`
   must be unchanged; if one changed, the new behaviour is leaking into the old version. For the runs that did change,
   check the `outputsHash`, the stage details and the quality checks, and confirm in the published summaries that the
   figures moved the way the `changes` entry says.
7. **Update the pins** in `tests/regression/methodology.test.ts`: add the new version's fingerprint
   (`methodologyFingerprint`). Existing pins must not change; if one does, a parameter of an existing version was
   edited in place. The test also re-executes every published run against its expected manifest.
8. **Add tests** that pin the old and new behaviour (see the 1.0.0 to 1.1.0 placeholder-CWE test in
   `packages/core/test/measure/cve-quality.test.ts`), then run `npm run verify`.

A change that only fixes a bug in how an existing version is computed still changes published figures: treat it the
same way and say so in the `changes` entry.

## Changing the demo dataset

Edit `scripts/demo/vendors.ts` (or `scripts/demo/generate.ts`), then `npm run demo:generate` and `npm run demo:build`.
Never edit files under `fixtures/demo` by hand: the loader checks every sha256. Keep every vendor fictional and every
URL on `.example`.

## Pull requests

- Keep `npm run verify` passing, and run it before you push. CI also runs the CLI and API smoke tests, a container build
  with a Trivy scan, `npm audit`, CodeQL and gitleaks.
- Do not commit measurements of real vendors, `.env` files, databases (`.data/`) or snapshot stores (`.touchstone/`).
- Wording about vendors: never "compliant", "secure", "insecure" or "failed". Quality check Q8 scans generated text for
  these words.
- New dependencies need a reason; the API has three production dependencies and we would like to keep it small.

By contributing you agree that your contribution is licensed under the Apache License 2.0.
