# syntax=docker/dockerfile:1.7
#
# TOUCHSTONE production image: the API serves the built web app and the
# published run data from one origin. Node 24 runs the TypeScript sources
# directly (type stripping), so the server has no compile step.

# Pinned by digest (multi-arch index of node:24.21.0-alpine3.24); Dependabot updates it.
ARG NODE_IMAGE=node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

# ---- build: install everything, verify the demo data, build the web app -----
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/collect/package.json packages/collect/
COPY apps/api/package.json apps/api/
COPY apps/cli/package.json apps/cli/
COPY apps/web/package.json apps/web/
RUN npm ci --no-audit --no-fund
COPY tsconfig.base.json tsconfig.json ./
COPY packages packages
COPY apps apps
COPY scripts scripts
COPY fixtures fixtures
# The published bundle must match what the generator and engine produce.
RUN node scripts/build-demo.ts --check && npm run build -w @touchstone/web

# ---- runtime: production dependencies only, non-root -------------------------
FROM ${NODE_IMAGE} AS runtime
# HOST=0.0.0.0 lets the published port reach the server. The Host allowlist
# stays on so a page using DNS rebinding cannot reach a port published on the
# reviewer's machine; set TOUCHSTONE_ALLOWED_HOSTS to the public name behind a
# reverse proxy.
ENV NODE_ENV=production \
    PORT=8787 \
    HOST=0.0.0.0 \
    TOUCHSTONE_ALLOWED_HOSTS=127.0.0.1,localhost,[::1] \
    TOUCHSTONE_DB=/data/touchstone.db \
    TOUCHSTONE_DATA_DIR=/app/apps/web/dist/data \
    TOUCHSTONE_WEB_DIST=/app/apps/web/dist \
    TOUCHSTONE_DEMO_FIXTURES=/app/fixtures/demo \
    TOUCHSTONE_MODE=demo
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY packages/collect/package.json packages/collect/
COPY apps/api/package.json apps/api/
COPY apps/cli/package.json apps/cli/
COPY apps/web/package.json apps/web/
# Production dependencies, then remove the package managers: the server never
# runs npm, and the npm bundled in the base image carries its own dependencies
# that image scanners report. Patch OS packages.
RUN npm ci --omit=dev --no-audit --no-fund \
 && npm cache clean --force \
 && rm -rf /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/corepack \
           /usr/local/bin/npm /usr/local/bin/npx /usr/local/bin/corepack /opt/yarn* /usr/local/bin/yarn /usr/local/bin/yarnpkg \
 && apk upgrade --no-cache
COPY packages/core/src packages/core/src
COPY packages/collect/src packages/collect/src
COPY apps/api/src apps/api/src
COPY apps/cli/src apps/cli/src
# Raw demo snapshots, for the demo refresh replay (synthetic data only).
COPY fixtures/demo fixtures/demo
COPY --from=build /app/apps/web/dist apps/web/dist
RUN mkdir -p /data && chown -R node:node /data
USER node
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s --retries=5 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"]
CMD ["node", "apps/api/src/index.ts", "--production"]
