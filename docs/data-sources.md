# TOUCHSTONE data sources

Every number TOUCHSTONE reports traces back to a **snapshot**: a recorded fetch of a public source at a specific time.
This page lists each source family, what is read from it, how much of it is kept, the terms it is used under, how fast
it is fetched, and how failures are recorded.

Source definitions live in `packages/collect/src/collectors/*.ts`; the snapshot store in
`packages/collect/src/store.ts`; the families and retention modes in `packages/core/src/model/source.ts`.

## Summary

| Family | Source id | URL | Retention | Used for |
|---|---|---|---|---|
| CISA_PLEDGE | `cisa.signers` | https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers | RAW | Signatory status; declared and parsed signer counts |
| CVE_PROGRAM | `cve.record` | `https://cveawg.mitre.org/api/cve/{id}` | RAW | Every CVE record metric and Goal 3 |
| NVD | `nvd.cves` | https://services.nvd.nist.gov/rest/json/cves/2.0 | RAW | Enumerating candidate CVE ids only |
| VENDOR_ADVISORY | `vendor.<id>.csaf` | the vendor's CSAF `provider-metadata.json` and the feeds it lists | RAW | Issuance timeliness |
| SECURITY_TXT | `vendor.<id>.security-txt` | `https://<vendor domain>/.well-known/security.txt`, then `/security.txt` | RAW | Security contact, Policy URL, Expires |
| VENDOR_VDP | `vendor.<id>.vdp` | the policy URL (security.txt `Policy:` or the registry's `vdpPolicyUrl`) | EXTRACT_ONLY | The eight VDP criteria |
| VENDOR_VDP | `robots.<host>` | `https://<policy host>/robots.txt` | EXTRACT_ONLY (hash only) | Permission to fetch a policy page; its snapshot and source are part of the run |

Retention, as implemented (`packages/collect/src/store.ts`):

- **RAW**: the response bytes are kept in the local snapshot store under `<store>/snapshots/<sha256>` and re-hashed on
  every read, so a modified file is detected rather than trusted.
- **EXTRACT_ONLY**: the raw bytes are hashed and **not kept**. For policy pages the extracted plain text is kept
  locally under `<store>/extracts/<snapshotId>.txt`, so the policy can be re-assessed later (for example after a rule
  change) and a later failed fetch can be carried forward explicitly. The raw policy HTML is never stored. For
  robots.txt only the hash is kept.
- **What is published:** for policy pages, only the quoted sentences (at most two per criterion, 300 characters each),
  the rule ids, the text hash, the word count and the stated last-updated date. The extracted text in
  `<store>/extracts/` stays on the collecting machine and is not part of the published bundle.

The default store is `.touchstone/` (git-ignored); live collection writes to the directory given by `--out` or
`TOUCHSTONE_LIVE_OUT`.

## CISA Secure by Design Pledge signers

- **URL:** https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers (allowlisted host `www.cisa.gov`).
- **Extracted** (`packages/core/src/normalize/signers.ts`): the count in the "N Companies" heading and the company names
  in the table cells, entity-decoded and trimmed. A difference between the declared and the parsed count is a warning
  (`COUNT_MISMATCH`), never reconciled; both counts are published.
- **Matching:** listed names are matched to registry vendors by exact normalized SIGNATORY_LISTING alias. Matched
  vendors are LISTED, the others NOT_LISTED, all UNKNOWN when no successful signer snapshot exists.
- **Terms:** a public U.S. government web page (cisa.gov). Works of the U.S. federal government are generally not
  subject to copyright in the United States. TOUCHSTONE does not use CISA's name or marks to suggest endorsement; it
  quotes the pledge text with its source URL (https://www.cisa.gov/securebydesign/pledge).
- **Limits:** 3 MB, `text/html`.

A real copy fetched on 2026-10-06 is kept in `fixtures/real/cisa-signers-2026-10-06.html` for parser tests (see
`fixtures/real/PROVENANCE.md`).

## CVE records (CVE Program)

- **URL:** `https://cveawg.mitre.org/api/cve/{id}`, one request per record (allowlisted host `cveawg.mitre.org`). The id
  must match `CVE-YYYY-NNNN+` before a URL is built.
- **Extracted** (`packages/core/src/normalize/cve.ts`, CVE JSON 5.0 to 5.2): id, state, assigner org id and short name,
  dates (reserved, published, updated, `datePublic`), title, distinct `affected[]` vendor/product pairs, and per
  container (the CNA and each ADP provider) the CWE references, CPE names (from `affected[].cpes` and
  `cpeApplicability[].nodes[].cpeMatch[].criteria`) and CVSS scores. A sha256 of the canonical record is kept to detect
  conflicting duplicates. Descriptions are not interpreted. Legacy CVE JSON 4.x, unknown states and malformed ids are
  rejected with an error.
- **Terms:** CVE records are published by the CVE Program under the CVE Program terms of use
  (https://www.cve.org/Legal/TermsOfUse), which permit reproduction and redistribution of CVE content with attribution.
  The attribution shown next to evidence is "CVE records are published by the CVE Program under its terms of use."
- **Limits:** 4 MB, `application/json`.

## NVD CVE API 2.0

- **URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0?sourceIdentifier=<CNA org id>&pubStartDate=...&pubEndDate=...`
  (allowlisted host `services.nvd.nist.gov`).
- **Used only to enumerate candidate CVE ids** for a vendor, by the vendor's CNA_ORG_ID aliases, over the eligibility
  window split into windows of at most 120 days (the API's limit), 2000 results per page, at most 200 pages. The records
  themselves are then fetched from the CVE Program, so NVD's own analysis never enters a metric.
- **Terms:** NVD data is a U.S. government work. The notice TOUCHSTONE carries: "This product uses data from the NVD API
  but is not endorsed or certified by the NVD."
- **Rate:** 6.5 s between requests (NVD allows 5 requests per rolling 30 seconds without an API key). TOUCHSTONE does not
  send an API key.
- **Limits:** 64 MB per page, `application/json`.

## Vendor CSAF 2.0 advisories

- **URL:** the vendor's `csafProviderUrl` from the registry (`provider-metadata.json`), then the ROLIE feeds and
  `directory_url` entries it lists (`changes.csv`, newest first), then the advisory documents. Only hosts on the vendor's
  registered domains and their subdomains are fetched. At most 100 advisories per vendor by default.
- **Extracted** (`packages/core/src/normalize/csaf.ts`): tracking id, title, initial release date, listed CVE ids, and the
  severity the advisory states (`aggregate_severity.text`, else the highest CVSS `baseSeverity`, else UNKNOWN).
- **Terms:** vendor-published documents. CSAF documents carry their own distribution terms in `document.distribution`
  (for example a TLP label) and notes; TOUCHSTONE keeps them RAW and quotes only identifiers, dates and severities.
  Operators publishing a live bundle should check each provider's stated terms.
- **No feed:** timeliness is not measured for that vendor (gap NO_SOURCE), never scored as zero.
- **Limits:** 8 MB, `application/json` (`text/csv` or `text/plain` for `changes.csv`).

## security.txt (RFC 9116)

- **URL:** `https://<first registered vendor domain>/.well-known/security.txt`, then the legacy `/security.txt`. Only that
  exact host is allowed.
- **Extracted** (`packages/core/src/normalize/security-txt.ts`): Contact, Expires, Policy, Canonical, whether the file is
  PGP-signed, and parse warnings. A security.txt file is a contact pointer, not a disclosure policy.
- **Terms:** vendor-published. Kept RAW (small files).
- **Limits:** 64 KB, `text/plain`. A 404 or 410 on both paths is recorded as an observation of absence, not a failure.

## Vendor vulnerability disclosure policy pages

- **URL:** the first https URL among the security.txt `Policy:` values and the registry's `vdpPolicyUrl` whose host is a
  vendor domain or subdomain. A program page on a known disclosure platform (`hackerone.com`, `bugcrowd.com`,
  `app.intigriti.com`, `yeswehack.com`, `responsibledisclosure.com`) is used only when it equals the registered
  `vdpPolicyUrl` or lies under it as a program path: anyone can open a program on such a platform, so the host alone
  proves nothing about ownership. An unconfirmed platform URL is skipped and the collection note says so. Nothing is
  crawled or guessed.
- **robots.txt is respected** for the product token `TOUCHSTONE` (an exact `User-agent: TOUCHSTONE` group, else `*`): a
  404 means no restriction; a disallowed path, or a robots.txt that cannot be fetched, means the policy is not fetched
  (retrieval FETCH_FAILED) and the criteria that depend on it are UNKNOWN. The robots.txt snapshot and its source
  (`robots.<host>`) are recorded in the run, so the decision is part of the provenance.
- **Extracted:** the page is reduced to plain text by the hardened extractor (`packages/core/src/text/html.ts`), given a
  retrieval state (READ, TOO_SHORT under 80 words, UNREADABLE for an empty page or a JavaScript shell or interstitial),
  and assessed against the eight criteria; each determination quotes at most two sentences of at most 300 characters.
- **Terms:** third-party pages. Kept EXTRACT_ONLY: the raw HTML is hashed and not kept; the extracted text is kept
  locally for re-assessment; only the quoted sentences are published.
- **Limits:** 2 MB, `text/html`, `application/xhtml+xml` or `text/plain`.

## Rate limits and identification

- One request per second per host by default (`HostRateLimiter`, `packages/collect/src/live.ts`); 6.5 s for NVD.
- Identifying User-Agent: `TOUCHSTONE/0.1 (public-evidence research collector; +https://github.com/touchstone-research/touchstone)`.
- 20 s total and 5 s connect timeouts per request; at most 3 redirects, each re-validated.
- No cookies, no credentials, no Referer.

## Failures and substitutions

One fetch produces one recorded snapshot (`collectors/common.ts fetchToSnapshot`):

| Outcome | Snapshot recorded | What the run uses |
|---|---|---|
| 2xx with an accepted content type | OK, with sha256, size, content type | the fresh content |
| 404 or 410 | OK with that `httpStatus` and no content | an observation that the document does not exist |
| anything else (DNS, blocked address, timeout, HTTP error, wrong type, too large) | FAILED with the error code and message | nothing, unless an earlier OK snapshot of the same source and URL exists |
| FAILED, earlier OK snapshot exists | FAILED with `substitutedBy: <earlier snapshot id>` | the earlier snapshot; the VDP observation carries `carriedFromSnapshotId` |
| fetched but rejected by a normalizer (for example legacy CVE JSON 4.0, or nesting deeper than 256 levels) | demo loader: the snapshot is marked REJECTED with the parser error; live collector: the snapshot stays OK and the parser error is recorded as a collection error | nothing |

Substitution is never silent. It appears in the run's SNAPSHOT stage, in `GET /api/freshness` under `substitutions`, as
a DATA_QUALITY anomaly, and as confidence rule C4.CARRIED on the affected metrics. Freshness is computed from the
snapshot actually used and is never CURRENT after a failed refresh.

Collection errors are returned with the inputs and shown by the CLI and the refresh job log. They include a reached CVE
cap: `--max-cves` shrinks every CVE denominator, so it is reported as an error saying the metrics describe a sample.
CVE ids listed by the vendor's own advisories are always fetched, even beyond the cap, so an uncollected CVE is never
read as an absent one. Each vendor is collected inside its own error boundary: a failure stops that vendor only
("collection stopped for this vendor") and the run continues.

## How live collection has been exercised

- The demo dataset never touches the network. Its synthetic raw files go through the same normalizers as live data.
- The collectors, `safeFetch` and the store are unit-tested with an injected resolver and an injected fake transport
  (`packages/collect/test/`), including private-address, rebinding, redirect, size, type and timeout cases.
- The normalizers are tested against unmodified real documents in `fixtures/real/` (a signer page, CVE records, a
  security.txt file and a CSAF advisory, each with its URL and sha256 in `PROVENANCE.md`).
- On 2026-10-06 live collection was run end to end against real public sources for the single vendor in
  `fixtures/live/registry.example.json`, with `--enumerate-nvd --max-cves 60`. It recorded 70 snapshots, all OK: the
  CISA signer list, 7 NVD enumeration pages, 60 CVE records, security.txt and the policy page, and the result was scored
  locally. Measurements of real vendors are not published in this repository. (That run predates the change that
  records robots.txt snapshots in the run; a run today also lists the robots.txt snapshot.)
- Not yet exercised against a live source: a vendor CSAF feed (the CSAF path is covered by the fake transport and by a
  real advisory document in `fixtures/real/`).
