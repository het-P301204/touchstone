# TOUCHSTONE threat model

Scope: the collectors (`packages/collect`), the engine (`packages/core`), the API (`apps/api`), the CLI (`apps/cli`),
the web app (`apps/web`), the published bundle and the build pipeline. Each threat lists what the code does today, with
file references, and the risk that remains.

## Assets

| Asset | Why it matters |
|---|---|
| Integrity of published figures and evidence | People make decisions about vendors from them. A wrong figure harms a named organisation. |
| Correct attribution of records to vendors | Misattribution moves another vendor's records into a figure. |
| The dispute record | It is the audit trail of challenges and decisions; it must not be rewritten. |
| The host that runs collection | An outbound fetcher can be turned against internal networks and cloud metadata endpoints. |
| Browsers and terminals of readers | Remote text is displayed to them. |
| The admin bearer token | It authorizes refresh jobs, dispute transitions and notebook entries. |
| Availability of the API | Reproduction and reports are CPU-bound. |
| Goodwill of public sources | TOUCHSTONE depends on CISA, the CVE Program, NVD and vendor sites tolerating its requests. |
| The build and its dependencies | A compromised action, image or tool would produce trusted-looking output. |

## Trust boundaries

```
[public internet sources] --(1)--> [collector: safeFetch] --(2)--> [snapshot store] --(3)--> [engine]
                                                                                              |
[operator: registry, fixtures, build] --------------------------------------------------(4)--+--> [published bundle]
                                                                                                      |
[reader's browser / terminal] <--(6)-- [web app / CLI] <--(5)-- [API] <-- [bundle + SQLite]  <-------+
[anyone on the network] --(7)--> [API public endpoints]      [admin] --(8)--> [API admin endpoints]
```

1. Remote servers return untrusted bytes, headers and redirects.
2. Raw bytes are stored content-addressed; reads re-hash them.
3. Every document entering the engine is untrusted: HTML, JSON, security.txt, CSV, robots.txt.
4. The vendor registry (`fixtures/demo/registry/vendors.json`, `fixtures/live/registry.example.json`) and the
   methodology are operator-controlled and trusted. Wrong registry entries are a data-quality risk, handled by disputes.
5. The bundle is produced by the operator's build and trusted by the API and the static site.
6. Everything shown to a reader derives from untrusted remote text.
7. Public API callers are anonymous and untrusted, including dispute submitters.
8. The admin is authenticated by one shared bearer token.

TOUCHSTONE is **single-tenant**: one deployment serves one dataset and one dispute log. All data it serves is public by
design. There are no user accounts.

## Threats

### T1. SSRF through source URLs

**Where URLs come from.** Hard-coded (CISA signer page, `cveawg.mitre.org`, `services.nvd.nist.gov`); the registry
(vendor `domains`, `csafProviderUrl`, `vdpPolicyUrl`); and remote content: the security.txt `Policy:` field, CSAF
provider metadata (ROLIE feed URLs, `directory_url`), ROLIE entries, `changes.csv` paths, and HTTP redirects.

**Mitigations as implemented** (`packages/collect/src/safe-fetch.ts`, `ip.ts`):

- Every collector request goes through `safeFetch` (`collectors/common.ts fetchToSnapshot`).
- `validateUrl`: `https:` only; port 443 only; no username or password in the URL; IP-literal hosts refused
  (`isIpLiteral` also refuses all-digit-and-dot names and `0x` forms); the host must match the caller's allowlist
  exactly or as `*.domain` (any subdomain, not the apex). The fragment is dropped.
- Per-collector allowlists: signer page `www.cisa.gov`; CVE records `cveawg.mitre.org`; NVD `services.nvd.nist.gov`;
  security.txt only the vendor's first registered domain; CSAF the vendor's domains and subdomains; policy pages the
  vendor's domains and subdomains, or a program page on a known disclosure platform (`hackerone.com`, `bugcrowd.com`,
  `app.intigriti.com`, `yeswehack.com`, `responsibledisclosure.com`) **only when the registry ties it to the vendor**
  (the URL equals the registered `vdpPolicyUrl` or lies under it as a program path; `collectors/vdp-policy.ts
  platformUrlConfirmed`). A feed-supplied URL that does not parse is recorded as a collection error, not fetched
  (`collectors/csaf.ts`).
- DNS: the host is resolved once (`dns.lookup` with `all: true`) and **every** returned address must be globally
  routable. `classifyAddress` refuses: `0.0.0.0/8`, `10/8`, `100.64/10` (CGNAT), `127/8`, `169.254/16` (link-local,
  cloud metadata), `172.16/12`, `192.0.0/24`, `192.0.2/24`, `192.31.196/24`, `192.52.193/24`, `192.88.99/24`,
  `192.168/16`, `192.175.48/24`, `198.18/15`, `198.51.100/24`, `203.0.113/24`, `224/4`, `240/4`; and for IPv6
  IPv4-mapped `::ffff:0:0/96`, NAT64 `64:ff9b::/96` and `64:ff9b:1::/48`, `::/96`, ULA `fc00::/7`, link-local and
  site-local `fe80::/10` and `fec0::/10`, multicast `ff00::/8`, anything outside `2000::/3`, and within it `2001::/23`
  (incl. Teredo), `2001:db8::/32`, `2002::/16` (6to4), `3fff::/20`. IPv4 is parsed strictly (no octal, hex or
  shorthand); IPv6 zone ids are refused.
- **Pinned connection.** The socket's `lookup` hook always answers with the validated address (`pinnedLookup`), so a DNS
  answer that changes between validation and connect cannot redirect the request. TLS SNI and certificate checks use
  the original host name. `agent: false`: no connection reuse, no proxy from the environment.
- Redirects are followed manually, at most 3, and each hop goes through `validateUrl` and the DNS check again.
- No cookies, no `Authorization`, no `Referer`; headers sent are `User-Agent`, `Accept`, `Accept-Encoding: identity`.
- URLs supplied with disputes are validated (https, no credentials, at most 500 characters) and stored, but the server
  **never fetches them** (`apps/api/src/app.ts evidenceUrl`).
- Live collection is off unless explicitly enabled: the CLI refuses `collect` without `--live`; the API runs it only with
  `TOUCHSTONE_MODE=live` and an admin token; the collector module is imported only then (`apps/api/src/engine.ts`).

**Residual risk.**
- The `*.domain` rule trusts every subdomain of a registered vendor domain. A dangling or taken-over subdomain that
  resolves to a public address can serve content. That is a data-poisoning risk (T3), not SSRF: it cannot reach private
  addresses.
- `dns.lookup` uses the system resolver; a compromised resolver can still return a public address of its choosing.

### T2. Malicious remote content

**Mitigations as implemented.**
- **Size caps** per request, enforced on `Content-Length` and while streaming (`safeFetch`): signer page 3 MB, CVE
  record 4 MB, NVD page 64 MB, CSAF documents and `changes.csv` 8 MB, security.txt 64 KB, policy page 2 MB, robots.txt
  512 KB (`collectors/*.ts`); 5 MB when a caller sets none.
- **Content-type allowlist** per source; `Accept-Encoding: identity` and any other `Content-Encoding` refused, so no
  decompression bombs.
- **Timeouts:** 20 s total and 5 s connect by default, enforced across DNS, rate-limit wait, connect and body read.
- **Nesting depth:** a CVE record nested deeper than 256 levels is rejected ("record nested too deeply"), and canonical
  hashing of source documents refuses deeper input instead of overflowing the stack (`normalize/json.ts jsonDepth`,
  `MAX_JSON_DEPTH`). A normalizer that throws on one record is caught and recorded as an error for that record
  (`collectors/cve-records.ts`).
- **Per-vendor isolation:** in live collection, each vendor runs in its own error boundary; one malformed feed or record
  becomes an error entry ("collection stopped for this vendor"), not an aborted run (`packages/collect/src/live.ts`).
- **HTML is reduced to text by a single forward scan** (`packages/core/src/text/html.ts`): no DOM, no regex over the
  document, no recursion; script, style, noscript, template, iframe, object, svg, math, head, textarea and select
  content is dropped; entities decoded with invalid code points replaced; nothing is executed or fetched. The signer
  heading regex is bounded (`[^>]{0,200}`, bounded whitespace) so it stays linear.
- **robots.txt evaluation is bounded** (`packages/collect/src/robots.ts`): at most 1000 rules, paths over 512 characters
  are treated as disallowed, and the matcher has a budget of 2 000 000 character comparisons per evaluation; exceeding
  it is treated as disallowed (fail closed). Only an exact (case-insensitive) `User-agent: TOUCHSTONE` group or `*`
  applies.
- **Untrusted JSON** is read through own-property accessors (`normalize/json.ts`), so `__proto__`, `constructor` or
  `toString` keys cannot resolve to inherited values; arrays are truncated to fixed maxima (for example 2000 affected
  entries, 5000 CPEs per container, 50 ADP containers); strings are capped (500 characters for titles and CWE text);
  impossible calendar dates are rejected rather than rolled over.
- **Invisible and bidi characters** are stripped from every human-readable string before it is stored or quoted
  (`util/sanitize.ts stripInvisible`, applied in normalizers and the evidence ledger): C0/C1 controls except tab, LF and
  CR; soft hyphen; combining grapheme joiner; Arabic letter mark; Hangul fillers; Mongolian free variation selectors and
  vowel separator; zero-width characters; line and paragraph separators; bidi embeddings, overrides and isolates; word
  joiner and invisible operators; variation selectors (including the supplement); BOM; tag characters; lone surrogates.
- **Quotes are bounded** to 300 characters, at most two per criterion (`vdp/assess.ts`).
- **Output encoding.** The web app renders through React (escaped text) under a CSP of `script-src 'self'`, no
  `unsafe-eval`, `object-src 'none'`, `base-uri 'none'` (in `apps/web/index.html` and sent by the API,
  `apps/api/src/security.ts`). Reports escape Markdown (links, images, HTML, emphasis, table pipes) and guard CSV cells
  against formula injection (leading `= + - @`, tab, CR, their full-width forms, or whitespace before them get a `'`
  prefix) (`packages/core/src/report/escape.ts`). The CLI removes control, escape and bidi characters from every
  data-derived string before it reaches the terminal (`apps/cli/src/terminal.ts`).

**Residual risk.** A 64 MB NVD page is parsed with `JSON.parse` in memory. A page that passes every check can still
contain misleading prose (T5).

### T3. Data poisoning

Anyone can get text onto the sources TOUCHSTONE reads: a CNA can publish a record naming any vendor; a third party can
enrich a record; a vendor controls its own policy page and advisory feed; anyone can open a program on a shared
disclosure platform.

**Mitigations as implemented.**
- Attribution uses structured fields only (assigner, `affected[].vendor`, CNA CPE vendor), never descriptions or titles.
  A title mention alone is reported as FREE_TEXT_ONLY and never attributed (`identity/index.ts`).
- The assigner rule does not override structured data that names a different registered vendor: such a record is
  excluded as AMBIGUOUS_VENDOR with both candidates, not given to the CNA's vendor.
- Attribution by affected-vendor name without a corroborating CNA CPE is MEDIUM confidence and caps metric confidence
  (rule C1).
- Records that fit more than one vendor are excluded (AMBIGUOUS_VENDOR); conflicting duplicates are excluded in every
  copy (DUPLICATE_CONFLICT), and an advisory that lists such a CVE is set aside rather than counted as "no CVE". Both
  are listed as data-quality anomalies.
- Third-party ADP data is never credited to the vendor, so enrichment cannot raise a figure.
- A disclosure-platform program page counts as the vendor's policy only when the registry confirms it (T1).
- A policy page of fewer than 80 words is TOO_SHORT: Goal 5 cannot be VERIFIED from it. Negated permissive sentences
  count as contradictions, not credit (methodology section 5).
- Every figure links to evidence items naming the snapshot, the extracted fields and the quote, so a poisoned input can
  be found and disputed.

**Residual risk.**
- A vendor can write a policy that matches the phrase rules without changing practice. TOUCHSTONE reads a policy; it
  does not test whether the vendor honours it.
- A vendor can omit or downgrade advisories in its CSAF feed and so shrink the timeliness denominator.

### T4. Vendor identity collision

**Mitigations as implemented.** Every name-to-vendor link is an explicit alias in the registry with evidence and a
confidence (`model/vendor.ts`). `detectIdentityConflicts` reports a name, CNA identity or CPE namespace registered for
two vendors; records whose attribution depends on it are excluded as IDENTITY_CONFLICT until a registry decision
resolves it. Signatories are matched by exact normalized SIGNATORY_LISTING alias; a listed name that matches two
vendors is reported as ambiguous, not matched. Quality check Q1 confirms no attributed record is conflicted and every
attribution names an evidenced alias.

**Residual risk.** The registry is maintained by hand. A wrong alias with plausible evidence attributes records
wrongly until disputed. Namespace consistency depends on which CPE_VENDOR aliases the registry lists (see
[methodology](methodology.md#field-rules)).

### T5. Misleading source metadata

Sources state their own dates and severities: security.txt `Expires`, a policy's "Last updated", CSAF
`initial_release_date` and severity, CVE `datePublished`, the signer page's declared count.

**Mitigations as implemented.**
- Values are used as the source states them and shown in the evidence with the snapshot.
- The security.txt parser records deviations as warnings (`NO_CONTACT`, `NO_EXPIRES`, `MULTIPLE_EXPIRES`,
  `CONTRADICTORY_EXPIRES`, `INVALID_EXPIRES`, `EXPIRED`, `EXPIRES_TOO_FAR`, `INSECURE_URI`, `BAD_CONTACT_URI`,
  `UNKNOWN_FIELD`, `MALFORMED_LINE`, `CANONICAL_MISMATCH`, `TRUNCATED`, `EMPTY`) (`normalize/security-txt.ts`).
  Contradictory `Expires` values are not used, and a non-URI `Contact` (for example "none") is not a contact.
- A policy "last updated" date after the analysis date is implausible and not counted (CURRENT UNKNOWN).
- A CVE published after the analysis date is not credited for timeliness. Impossible calendar dates are rejected.
- The signer page's declared count and parsed count are both published; a mismatch is a warning, never reconciled.
- Advisory severity comes from the advisory's own fields, never from prose.

**Residual risk.** TOUCHSTONE cannot verify a plausible self-stated date. A backdated advisory release date, or a
far-future but single `Expires`, is taken at face value (a warning is recorded where the parser can detect it).

### T6. Stale data

**Mitigations as implemented.** Freshness is computed per source from successful fetches, never the last attempt, with
bands per source family (`freshness/freshness.ts`). A source whose latest attempt did not succeed is never CURRENT. A
recorded substitute is honoured only when it exists, belongs to the same source, is OK and predates the analysis date.
Per-record sources (CVE records, NVD pages) use the age of the oldest successful record fetch, so fetch order cannot
make them look fresher. STALE caps confidence at MEDIUM and UNKNOWN at LOW (C3); a STALE or UNKNOWN vendor source
raises a DATA_QUALITY anomaly; quality check Q2 confirms every such source is labelled and no metric citing it stays
HIGH. A failed fetch is recorded as a FAILED snapshot; when an earlier good snapshot is used, the failure names it in
`substitutedBy` and the observation carries `carriedFromSnapshotId` (C4). Substitution is never silent
(`collectors/common.ts`).

**Residual risk.** Freshness is relative to the run's `asOf`, not to the time someone reads the page. A published run
looked at months later still shows the freshness it had on its analysis date; the run date is shown with it.

### T7. Scoring manipulation

**By the operator or a compromised build.**
- The engine is pure and deterministic (ESLint rules on `packages/core/src`: no clock, no randomness, no Node built-ins,
  no fetch, no DOM, no eval). Every run publishes `inputsHash`, `outputsHash` and its inputs; anyone can re-execute it
  in the browser, with `touchstone reproduce <runId>`, or with `POST /api/runs/:id/reproduce`, and compare.
- Both hashes include a **methodology fingerprint** over the version and every parameter, so a parameter edited in
  place changes the run id and the hashes. `tests/regression/methodology.test.ts` pins each version's fingerprint and
  every published run's manifest; `npm run demo:check` (run in CI) regenerates the dataset and every published file in
  memory and fails on any difference.
- A methodology change must come with a new version; old runs keep their version and figures.

**By API callers.** There is no write path to run data. Disputes overlay an observation and never change it. The bundle
is read-only to the API; a DEMO refresh compares its output with the published run and does not overwrite it, and a
LIVE refresh writes to a separate directory for offline review (`apps/api/src/refresh.ts`).

**Residual risk.** Reproduction proves the published outputs follow from the published inputs and code; it does not
prove the inputs are what the sources served. For live runs, the content-addressed snapshots (and the robots.txt
snapshots, now part of the run) support that check; for policy pages only the hash and the extracted text are kept
locally, so the raw page cannot be re-examined.

### T8. Privilege escalation and information disclosure

**Mitigations as implemented** (`apps/api/src/security.ts`, `config.ts`, `refresh.ts`).
- One secret: `TOUCHSTONE_ADMIN_TOKEN`, at least 24 characters, never defaulted, never logged. Without it every admin
  endpoint answers 403 "administration disabled".
- Admin endpoints: `POST /api/refresh`, `POST /api/disputes/:id/transition`, `POST /api/notebook`. The bearer token is
  checked before any body is read, with a constant-time comparison of sha256 digests; a missing or wrong token is 401.
- Logs record the matched route pattern, method, status and duration; never bodies, headers, query strings or tokens.
- Refresh job status is readable without a token, so server filesystem paths in stage details are replaced before they
  are returned: configured directories become their variable names (for example `TOUCHSTONE_LIVE_OUT`), any other
  absolute path becomes `<path>` (`pathScrubber`). The unscrubbed text stays in the database and the server log.
- The web app keeps the admin token in `sessionStorage` only (`apps/web/src/lib/admin.ts`).
- The container runs as the non-root `node` user, read-only root filesystem, all capabilities dropped,
  `no-new-privileges` (`Dockerfile`, `docker-compose.yml`).

**Residual risk.** A single shared token: no per-person identity (the `actor` on a transition is free text), no
rotation without a restart, no lockout beyond the general rate limit.

### T9. Cross-tenant leakage

Not applicable in the multi-tenant sense: TOUCHSTONE is single-tenant and serves only public data. What remains is
public exposure of what submitters type: dispute statements and evidence URLs are returned by `GET /api/disputes` to
anyone. TOUCHSTONE collects no names or e-mail addresses (only a submitter role), but nothing stops a submitter from
typing personal data into a statement.

### T10. Arbitrary code execution through parsers, and the supply chain

**Mitigations as implemented.**
- No `eval`, no `new Function`, no `DOMParser` in the engine (ESLint `no-eval`, `no-new-func`, restricted globals).
- Remote content is only ever parsed as JSON (`JSON.parse`), as plain text, or by the hand-written linear scanners
  above. There is no YAML, XML or HTML DOM parser, no template engine, and no deserialization into classes.
- Prototype-pollution-safe JSON access and a nesting-depth limit (T2).
- Path handling: demo manifest file paths with `..`, a leading `/` or `:` are refused (`collect/src/demo.ts`) and replay
  paths must stay inside the fixtures root (`apps/api/src/refresh.ts readFixtureSnapshots`); bundle run, vendor and
  dataset ids are validated against strict patterns and a request value is used only after it is found among loaded ids
  (`apps/api/src/bundle.ts`); static files are resolved inside `dist` with drive-letter, UNC, NUL and symlink-escape
  checks (`apps/api/src/static.ts`); snapshot ids are pattern-checked before a path is built (`collect/src/store.ts`);
  `Content-Disposition` file names are reduced to `[A-Za-z0-9._-]` (`safeFileName`).
- **Supply chain.** Production dependencies are few (`hono`, `@hono/node-server`, `zod`). GitHub Actions are pinned by
  commit SHA; the container base image is pinned by digest (`Dockerfile`); the gitleaks binary is downloaded at a fixed
  version and its sha256 is checked before it runs (`.github/workflows/ci.yml`). CI runs `npm audit` (high and above),
  `npm ci --ignore-scripts`, CodeQL, gitleaks over the full history, an SPDX SBOM and a Trivy image scan; Dependabot is
  configured.

**Residual risk.** Vulnerabilities in Node, V8 or a dependency; a pinned action or image that was malicious when pinned.

### T11. Dispute and reproduction abuse

**Mitigations as implemented** (`apps/api/src/app.ts`, `security.ts`, `store.ts`).
- **Per-client limits:** disputes 10 per hour, reproductions 30 per hour, all API requests 300 per minute. Clients are
  keyed by IPv4 address, or by IPv6 /64 prefix (one host normally controls a whole /64, so rotating through it buys no
  new buckets); IPv4-mapped IPv6 counts as the IPv4 address. Each limiter tracks at most 10 000 keys (expired windows
  swept first, then the oldest evicted), so an address flood cannot grow memory without bound.
- **Server-wide ceilings** per hour, whatever the address: 200 accepted disputes and 120 reproductions
  (`TOUCHSTONE_DISPUTE_GLOBAL_LIMIT_PER_HOUR`, `TOUCHSTONE_REPRODUCE_GLOBAL_LIMIT_PER_HOUR`); beyond them the API answers
  429 `RATE_LIMITED_GLOBAL`. The dispute ceiling is checked before the body is read and consumed only by accepted
  disputes, so invalid submissions do not use it up for everyone else.
- **Reproduction queue:** reproductions are CPU-bound and run strictly one at a time; at most 4 wait behind the one in
  flight (`TOUCHSTONE_REPRODUCE_QUEUE_LIMIT`), further requests get 429 `REPRODUCE_BUSY` at once, and the event loop is
  yielded between runs so other requests are served.
- **Dispute validation:** strict schema (unknown fields refused); the vendor must be in the run; the target must exist in
  that run for that vendor: a goal G1 to G7, a defined metric, an evidence item in the vendor's evidence, a CVE
  attributed to the vendor or excluded with it as a candidate, or one of the vendor's names, aliases or identity
  conflicts (`disputeTargetProblem`). Reason and role from fixed lists; statement 1 to 2000 characters after sanitizing;
  at most 5 https evidence URLs; body cap 32 KB enforced before and while reading; `application/json` required.
- State changes require the admin token and must follow `DISPUTE_TRANSITIONS`; the SQLite triggers refuse an illegal
  transition, an edited event, a deleted dispute, or a status that does not match the latest event, even for code that
  bypasses the route checks.
- A cross-origin state-changing request with an `Origin` header that is not the server's own and not in
  `TOUCHSTONE_CORS_ORIGINS` is refused (403); the JSON content-type requirement forces a CORS preflight.

**Residual risk.**
- An OPEN dispute immediately shows the affected goal as DISPUTED (next to its original status) until a reviewer acts.
  Within the limits above, filing disputes can put a DISPUTED label on a vendor's goals.
- Statements are displayed publicly without moderation.
- The limits key on the socket address. Behind a reverse proxy without `TOUCHSTONE_TRUST_PROXY=true`, all clients share
  the proxy's address and one bucket. Limits are in memory per process.

### T12. DNS rebinding of the local server

A page on another site can make its own name resolve to `127.0.0.1` and send requests to a TOUCHSTONE server running on
the reader's machine.

**Mitigations as implemented.** `hostCheck` (`apps/api/src/security.ts`) answers 421 to any `Host` not in
`allowedHosts`. When `HOST` is a loopback address and `TOUCHSTONE_ALLOWED_HOSTS` is unset, the list defaults to
`127.0.0.1`, `localhost` and `[::1]`. When `HOST` is not loopback, **the server refuses to start** unless
`TOUCHSTONE_ALLOWED_HOSTS` is set (`config.ts`); `*` accepts any Host only when set explicitly, and is logged as a
warning at start. The container sets the loopback list even though it binds `0.0.0.0`, and `docker-compose.yml`
publishes the port on loopback only. CORS is off by default, and cross-origin state-changing requests are refused
(T11). The server binds `127.0.0.1` by default.

**Residual risk.** An operator who sets `TOUCHSTONE_ALLOWED_HOSTS=*` without a proxy that validates Host turns the
protection off.

### T13. Load on public sources

**Mitigations as implemented.** A per-host rate limiter serializes requests (1 per second per host by default; 6.5 s
for NVD, which allows 5 requests per 30 s without a key); the NVD enumeration is capped at 200 pages; a policy page is
fetched only when the host's robots.txt allows it for the product token `TOUCHSTONE` (a robots.txt that cannot be
fetched, other than 404, means the page is not fetched); an identifying User-Agent is sent. TOUCHSTONE does no
scanning or testing of vendor systems.

## Security headers sent by the API

`Content-Security-Policy` (same-origin only, `frame-ancestors 'none'`), `X-Content-Type-Options: nosniff`,
`X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`,
`Cross-Origin-Resource-Policy: same-origin`, a restrictive `Permissions-Policy`,
`X-Permitted-Cross-Domain-Policies: none`, `Cache-Control: no-store` on `/api/*`, and `Strict-Transport-Security` in
production.
