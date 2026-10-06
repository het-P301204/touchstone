# Security policy

## Reporting a vulnerability in TOUCHSTONE

Please report security issues in TOUCHSTONE itself privately, through GitHub's private vulnerability reporting
("Report a vulnerability" on the repository's Security tab). Do not open a public issue for a vulnerability.

Include what you found, the affected file or endpoint, the version or commit, and steps to reproduce. We aim to
acknowledge a report within 7 days and to agree a disclosure date with you. Coordinated public disclosure is welcome
once a fix is available or 90 days have passed, whichever comes first.

Good-faith research on your own local copy of TOUCHSTONE, within this policy, is welcome; we will not pursue or
recommend legal action against it. Please do not test against deployments you do not run, and do not use TOUCHSTONE's
collector against third-party systems in ways their owners have not allowed.

**Disagreeing with a finding about a vendor is not a security report.** Use the dispute workflow instead
([docs/disputes.md](docs/disputes.md)).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | yes |

## Security design in brief

The full threat model is in [docs/threat-model.md](docs/threat-model.md). The main controls:

- **Outbound requests** (live collection only) go through one SSRF-safe fetcher: https and port 443 only, a per-source
  host allowlist, every resolved address checked against private, loopback, link-local, CGNAT, ULA, multicast,
  IPv4-mapped and NAT64 ranges, the connection pinned to the validated address, at most 3 re-validated redirects,
  timeouts, size caps, content-type allowlists, no cookies or credentials, per-host rate limits, robots.txt respected
  for policy pages (`packages/collect/src/safe-fetch.ts`, `ip.ts`).
- **No network by default.** The demo dataset is replayed from local files. The CLI refuses `collect` without `--live`;
  the API collects only with `TOUCHSTONE_MODE=live` and an admin token.
- **Untrusted content is only parsed, never executed:** a linear HTML-to-text extractor, own-property JSON access,
  bounded arrays and strings, invisible and bidi characters stripped from all displayed text, CSV formula guarding and
  Markdown escaping in reports, terminal-safe CLI output.
- **The API** binds to loopback by default and refuses to start on another interface without a Host allowlist,
  checks the Host header (DNS-rebinding protection), sends a strict CSP and related headers, caps request bodies before
  reading them, accepts only JSON bodies, rate-limits per client (IPv4 by address, IPv6 by /64) with separate limits
  and server-wide hourly ceilings for dispute submissions and reproductions, runs reproductions one at a time behind a
  bounded queue, keeps server paths out of public refresh status, and returns one error envelope with no stack traces.
- **One secret,** `TOUCHSTONE_ADMIN_TOKEN` (at least 24 characters, never defaulted, never logged, compared in constant
  time). Without it the administrative endpoints answer 403.
- **Append-only audit data:** SQLite triggers stop dispute history and notebook entries from being edited or deleted.
- **Reproducible results:** every published run can be re-executed from its published inputs and compared by hash.
- **Supply chain:** three production dependencies (`hono`, `@hono/node-server`, `zod`); GitHub Actions pinned by
  commit SHA, the container base image pinned by digest, and the gitleaks binary checked against a pinned sha256; CI
  runs `npm audit`, CodeQL, gitleaks over the full history, an SPDX SBOM and a Trivy scan of the container image;
  Dependabot is enabled. The container runs as a non-root user with a read-only root filesystem and no capabilities.

## Deploying

- Keep `HOST=127.0.0.1` unless a TLS-terminating reverse proxy sits in front. With a non-loopback `HOST` the server
  refuses to start until `TOUCHSTONE_ALLOWED_HOSTS` lists the host names clients use. `*` accepts any Host and is
  logged as a warning; use it only behind a proxy that validates Host.
- Set `TOUCHSTONE_TRUST_PROXY=true` only when exactly one trusted proxy is in front; otherwise `X-Forwarded-For` is
  ignored.
- Generate the admin token with
  `node -e "console.log(require('node:crypto').randomBytes(32).toString('hex'))"` and keep it out of version control
  (`.env` is git-ignored).
- Dispute statements and evidence URLs are public. Tell submitters not to include personal data.
