# Changelog

All notable changes to TOUCHSTONE are recorded here. The project follows semantic versioning. Methodology versions are
versioned separately (see [docs/methodology.md](docs/methodology.md#16-methodology-versioning)); a release notes which
methodology version is current.

## 0.1.0 - 2026-10-06

First release. Current methodology: 1.1.0.

### Measurement

- The seven Secure by Design Pledge goals as data, with the pledge text quoted verbatim and a verification mode per
  goal: G5 (VDP) and G6 (CVEs) publicly measurable, G3 (vulnerability classes) partially measurable, G1, G2, G4 and G7
  not externally verifiable.
- Goal 5: eight VDP criteria assessed with documented phrase and structural rules, each determination quoted;
  prohibitive language reported as observed deviation; `vdp.criteria_met` and `vdp.pledge_elements_met`.
- Goal 6: CNA-supplied CWE and CPE coverage, CPE namespace consistency, complete records, third-party enrichment
  reported separately and never credited, duplicate and exclusion counts; issuance timeliness, high-impact advisories
  with a CVE, and publication latency from vendor CSAF advisories.
- Goal 3: tracked weakness-class share, latest 12 months against the prior 12, never VERIFIED.
- Evidence ledger with content-derived ids; evidence coverage over 14 slots; confidence rules; freshness bands;
  cohort benchmarks against peer medians (no composite score); anomaly and VDP change detection.
- Ten-question pre-publication quality gate on every run.
- Methodology 1.0.0 and 1.1.0 (placeholder CWEs no longer count as populated); historical runs keep their figures.
- The methodology parameters were finalized before this release. In response to an adversarial review,
  `vdpMinimumPolicyWords` (80) and `minimumHighImpactAdvisories` (5) were added to **both** versions, together with the
  rules that use them: policy retrieval states (READ, TOO_SHORT, UNREADABLE, FETCH_FAILED, NOT_FOUND) so a retrieval
  problem is never scored as missing content; a clause-level negation model for the VDP phrase rules; timeliness null
  (not zero) when the CVE source failed, and not VERIFIED below five high-impact advisories; contradictory security.txt
  `Expires` values and future "last updated" dates treated as undetermined; a CNA assigning for another registered
  vendor's product no longer attributed to the CNA's vendor; cohort peer groups limited to listed signatories;
  order-independent freshness for per-record sources; and a methodology fingerprint in both run hashes.

### Reproducibility

- Pure, deterministic engine; runs identified by `inputsHash` and `outputsHash`, both covering a methodology
  fingerprint; reproduction from published inputs in the CLI, the API and the browser; a regression suite pinning each
  methodology version and every published run.

### Collection

- SSRF-safe fetcher with host allowlists, address classification, pinned connections, re-validated redirects, size,
  type and time limits, and per-host rate limits.
- Collectors for the CISA signer list, CVE records, NVD id enumeration, CSAF 2.0 feeds, security.txt and VDP pages
  (robots.txt respected), writing a content-addressed snapshot store with explicit failure substitution.
- Live collection from the CLI (`collect --live`, with `--enumerate-nvd`, `--cve`, `--max-cves`) and from the API in
  live mode; a CVE cap is reported as a collection error.

### Applications

- REST API (Hono, SQLite) with the dispute workflow enforced by database triggers, research notebook, refresh jobs,
  reports in JSON, Markdown, CSV and PDF, and security middleware: Host allowlist required on non-loopback binds,
  per-client limits keyed by IPv4 address or IPv6 /64, server-wide hourly ceilings for disputes and reproductions, a
  bounded reproduction queue, dispute targets validated against the run, and server paths redacted from refresh status.
- CLI: `run`, `reproduce`, `export`, `methodology`, `goals`, `collect`.
- Web application working against the API or as a static site.

### Data

- Synthetic demo cohort of 22 fictional vendors over five quarterly dataset versions, generated deterministically and
  published as five runs.

### Operations

- Container image (non-root, read-only, base image pinned by digest), Docker Compose file, CI (lint, type check, data
  check, tests, build, CLI and API smoke tests, Playwright journeys, container scan, SBOM, dependency audit, secret
  scanning with a checksum-verified gitleaks), CodeQL and GitHub Pages workflows; actions pinned by commit SHA.
