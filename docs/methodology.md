# TOUCHSTONE methodology

Methodology version described: **1.1.0** (current), with the one difference from **1.0.0** called out where it applies.
Every rule below is taken from the code that computes it. Where a rule lives in code, the file is named so the
statement can be checked:

| What | Where |
|---|---|
| The seven goals, pledge text, verification modes, status rules in words | `packages/core/src/methodology/goals.ts` |
| Methodology versions and parameters | `packages/core/src/methodology/versions.ts` |
| Metric definitions, coverage slots, tracked weakness classes, confidence rules | `packages/core/src/measure/definitions.ts` |
| Metric computation | `packages/core/src/measure/{vdp,cve-quality,timeliness,class-share,metric,stats}.ts` |
| Goal status, dimension figures, coverage, cohort, anomalies, VDP change | `packages/core/src/assess/*.ts` |
| VDP criteria, phrase rules and the negation model | `packages/core/src/vdp/assess.ts` |
| CVE normalization (CWE, CPE parsing) | `packages/core/src/normalize/cve.ts` |
| Attribution of CVE records to vendors | `packages/core/src/identity/index.ts` |
| Freshness | `packages/core/src/freshness/freshness.ts` |
| Runs, hashing, reproduction | `packages/core/src/run/run.ts` |
| Pre-publication quality gate | `packages/core/src/run/quality-gate.ts` |

The UI's "How was this calculated?" panel, the API (`GET /api/goals`, `GET /api/methodology`) and the reports render
the same strings from those files, so this document and the product cannot quietly disagree on a formula.

## 1. What TOUCHSTONE does and does not claim

TOUCHSTONE measures **publicly observable evidence** behind the commitments in the CISA Secure by Design Pledge. For
each vendor and each goal it reports what could be measured, the evidence behind every number, what could not be
determined, and a reproducible run that produced it.

Rules that hold everywhere:

- **UNKNOWN is never MET.** A VDP criterion that could not be determined counts 0 and is listed by name. A metric that
  could not be measured has `value: null` and a `gap` reason. It is never shown as 0 or 100.
- **A retrieval problem is never a content finding.** A policy page that could not be fetched or read makes its
  criteria UNKNOWN and Goal 5 DATA_ERROR, never NOT_MET. An unreadable CVE source makes timeliness null, never 0.
- **NOT_EXTERNALLY_VERIFIABLE is a property of the goal**, not a finding about a vendor.
- **There is no composite score.** Three dimension figures (VDP, CVE record quality, CVE issuance timeliness) stand
  alone, each with its own numerator and denominator. Nothing is weighted or summed across goals.
- **Only the manufacturer's own data is credited.** In CVE JSON 5.x the CNA container (`containers.cna`) carries the
  data the CNA supplied. Third parties (CISA-ADP "Vulnrichment", others) add data in `containers.adp[]`. A record can
  look complete on an aggregator because someone else enriched it. Only CNA-supplied CWE and CPE count toward the
  pledge metric; enrichment is reported on its own as `cve.enriched_only`.
- **The engine is deterministic.** `executeRun` reads no clock (the analysis date `asOf` is an input), uses no
  randomness, does no I/O, and orders everything, including the registry's alias lists. ESLint enforces this inside
  `packages/core/src`.

## 2. Verification modes

| Goal | Name | Verification mode | Metrics |
|---|---|---|---|
| G1 | Multi-factor authentication | NOT_EXTERNALLY_VERIFIABLE | none |
| G2 | Default passwords | NOT_EXTERNALLY_VERIFIABLE | none |
| G3 | Reducing entire classes of vulnerability | PARTIALLY_MEASURABLE | `g3.class_share_trend` |
| G4 | Security patches | NOT_EXTERNALLY_VERIFIABLE | none |
| G5 | Vulnerability disclosure policy | PUBLICLY_MEASURABLE | `vdp.criteria_met`, `vdp.pledge_elements_met` |
| G6 | CVEs | PUBLICLY_MEASURABLE | `cve.cwe_coverage`, `cve.cpe_coverage`, `cve.cpe_namespace_consistency`, `cve.complete_records`, `cve.enriched_only`, `cve.timely_issuance`, `cve.high_impact_with_cve`, `cve.publication_latency` (plus the data-quality counts `cve.duplicate_conflicts`, `cve.excluded_records`) |
| G7 | Evidence of intrusions | NOT_EXTERNALLY_VERIFIABLE | none |

Goal statuses:

| Status | Meaning |
|---|---|
| VERIFIED | Evidence directly supports the measurement. |
| PARTIAL | Evidence supports only part of the measurement. |
| NOT_VERIFIED | Insufficient public evidence to establish it. |
| NOT_EXTERNALLY_VERIFIABLE | Public evidence cannot meaningfully answer the goal. |
| DATA_ERROR | A source or mapping problem prevents measurement. |

DATA_ERROR arises in these cases only:

- Goal 5: the policy could not be fetched (FETCH_FAILED) or read (UNREADABLE) and no earlier snapshot was carried
  forward.
- Goal 6: the CVE source failed (CVE_PROGRAM snapshots exist and none is OK); or neither part could be measured for a
  reason other than a small sample or a missing advisory feed, for example no CPE vendor namespace is registered so
  completeness cannot be checked.
- Goal 3: the CVE source failed and no value was measured.

A vendor's own statements about pledge progress (`Vendor.claims`) are shown as unverified claims and counted
(`claimCount`). They are never evidence.

## 3. Methodology parameters

Both versions share these parameters except `placeholderCweCountsAsPopulated`.

| Parameter | 1.0.0 | 1.1.0 | Used by |
|---|---|---|---|
| `cveWindowDays` | 730 | 730 | CVE record eligibility; advisory window |
| `placeholderCweCountsAsPopulated` | true | **false** | CWE usability |
| `timelinessToleranceDays` | 1 | 1 | `cve.timely_issuance` |
| `highImpactSeverities` | CRITICAL, HIGH | CRITICAL, HIGH | advisory eligibility |
| `minimumEligibleRecords` | 5 | 5 | CVE record metrics |
| `minimumHighImpactAdvisories` | 5 | 5 | timeliness confidence; caps Goal 6 and the timeliness figure at PARTIAL |
| `minimumRecordsPerTrendPeriod` | 10 | 10 | Goal 3 |
| `vdpCurrentWithinDays` | 730 | 730 | VDP criterion CURRENT |
| `vdpMinimumPolicyWords` | 80 | 80 | policy plausibility floor (TOO_SHORT) |
| `freshnessHours` | see section 12 | same | freshness bands |
| `unusualBelowPercentile` | 10 | 10 | UNUSUAL anomaly |
| `latencyOutlierFactor` | 2 | 2 | LATENCY_OUTLIER anomaly |
| `latencyOutlierMinDays` | 7 | 7 | LATENCY_OUTLIER anomaly |

`timelinessToleranceDays` is a TOUCHSTONE methodology choice. It is not a CISA threshold, and every reading that
uses it says so.

## 4. Statistics used

Only three: a share, a median and a nearest-rank percentile (`measure/stats.ts`).

- Percentages are `numerator / denominator x 100`, rounded to two decimals.
- Median: the middle value, or the mean of the two middle values (rounded to two decimals). Null for an empty list.
- Percentile (nearest rank): the value at rank `ceil(p/100 x n)` of the sorted list.
- Day differences are `(b - a) / 86 400 000 ms`, rounded to two decimals for display. Comparisons against a tolerance
  use the raw milliseconds, never the rounded value.

Nothing is weighted, smoothed or modelled.

---

## 5. The goals

### G1 Multi-factor authentication

> "Within one year of signing the pledge, demonstrate actions taken to measurably increase the use of multi-factor authentication across the manufacturer's products."

- **Verification mode:** NOT_EXTERNALLY_VERIFIABLE.
- **Why:** MFA adoption is measured inside the vendor's own telemetry. No public source reports it in a form a third
  party can check. Product documentation can show that MFA is available; it cannot show that it is used.
- **Status rule:** always NOT_EXTERNALLY_VERIFIABLE. A vendor statement is shown as a claim, never as evidence.
- **Evidence that would be needed:** an independently audited adoption rate; scoped customer and employee coverage;
  the measurement methodology; a time period and baseline.

### G2 Default passwords

> "Within one year of signing the pledge, demonstrate measurable progress towards reducing default passwords across the manufacturers' products."

- **Verification mode:** NOT_EXTERNALLY_VERIFIABLE.
- **Why:** verifying default credentials would require testing products or devices. TOUCHSTONE does no testing of
  vendor products or infrastructure. CVE records citing hard-coded credentials (CWE-798) show past defects, not current
  defaults.
- **Status rule:** always NOT_EXTERNALLY_VERIFIABLE.
- **Evidence that would be needed:** a product inventory with its credential provisioning model; independent product
  testing results; a time period and baseline.

### G3 Reducing entire classes of vulnerability

> "Within one year of signing the pledge, demonstrate actions taken towards enabling a significant measurable reduction in the prevalence of one or more vulnerability classes across the manufacturer's products."

- **Verification mode:** PARTIALLY_MEASURABLE.
- **What is measured:** the share of the vendor's disclosed CVE records (with a CNA-supplied CWE identifier) that fall
  in a tracked weakness class, in the latest 12 months against the prior 12 months. This is a signal about disclosed
  records only. Disclosure volume, product mix and CWE assignment practice all move the share without any change in
  prevalence.
- **Metric:** `g3.class_share_trend` (`measure/class-share.ts`).

**Eligibility.** A record contributes when it is attributed to the vendor (not excluded, not a conflicting duplicate),
in state PUBLISHED, has a parseable `datePublished` that is not after `asOf`, and its CNA container lists at least one
CWE identifier that names a weakness. Placeholders (`NVD-CWE-noinfo`, `NVD-CWE-Other`, `CWE-noinfo`, `CWE-Other`) and
malformed values name no class and never contribute, under either methodology version. Only CNA-supplied CWEs count.

**Periods.** Latest period: `(asOf - 365 days, asOf]`. Prior period: `(asOf - 730 days, asOf - 365 days]`.

**Tracked classes** (`TRACKED_CWE_CLASSES`). A record is in a class when any of its CNA CWE identifiers is in the
class set. These sets are a TOUCHSTONE methodology choice, published so they can be disputed.

| Class id | Label | CWE identifiers |
|---|---|---|
| MEMORY_SAFETY | Memory safety | 119, 120, 121, 122, 123, 124, 125, 126, 127, 131, 415, 416, 476, 562, 590, 761, 762, 763, 787, 788, 805, 822, 823, 824, 825, 843 |
| INJECTION | Injection | 74, 77, 78, 79, 80, 88, 89, 90, 91, 94, 95, 96, 643, 652, 917, 1336 |
| AUTH_CREDENTIALS | Authentication and credentials | 255, 259, 287, 288, 290, 294, 303, 304, 306, 307, 521, 522, 523, 620, 640, 798, 1390, 1391, 1392, 1393 |

**Formula.**

```
share(period)  = records in the period in any tracked class / records in the period with a CNA CWE identifier x 100
value          = share(latest) - share(prior)            in percentage points, two decimals
```

The breakdown carries the record counts and the per-class shares for each period (`prior_share_pct.<CLASS>`,
`latest_share_pct.<CLASS>`). A period with no records has no share: its per-class keys are omitted, never reported as
0%. A record can be in more than one class; for the headline share it counts once ("in any tracked class").

**Minimum sample.** Each period needs at least `minimumRecordsPerTrendPeriod` (10) records. Otherwise the value is null
with gap `BELOW_MINIMUM_SAMPLE`, or `NO_ELIGIBLE_RECORDS` (`SOURCE_FAILED` when the CVE source failed) when both
periods are empty. The evidence items for the records that were found are still attached.

**Status rule** (`assess/goals.ts assessG3`):

- DATA_ERROR when the CVE source failed and no value was measured;
- PARTIAL when the value is measured;
- NOT_VERIFIED otherwise.

G3 is **never VERIFIED**: the disclosed mix cannot establish a reduction in prevalence. The quality gate (Q8) checks
this on every run.

**Evidence that would be needed** to go further: defect data that includes vulnerabilities found and fixed before
release; class definitions mapped to code-level controls (for example memory-safe language adoption).

### G4 Security patches

> "Within one year of signing the pledge, demonstrate actions taken to measurably increase the installation of security patches by customers."

- **Verification mode:** NOT_EXTERNALLY_VERIFIABLE.
- **Why:** patch installation happens inside customer environments. Internet-wide scan data would require scanning
  third-party assets, which TOUCHSTONE does not do.
- **Status rule:** always NOT_EXTERNALLY_VERIFIABLE.
- **Evidence that would be needed:** installation telemetry with its methodology; independent attestation; a time
  period and baseline.

### G5 Vulnerability disclosure policy

> "Within one year of signing the pledge, publish a vulnerability disclosure policy (VDP) that authorizes testing by members of the public on products offered by the manufacturer, commits to not recommending or pursuing legal action against anyone engaging in good faith efforts to follow the VDP, provides a clear channel to report vulnerabilities, and allows for public disclosure of vulnerabilities in line with coordinated vulnerability disclosure best practices and international standards."

- **Verification mode:** PUBLICLY_MEASURABLE.
- **What is measured:** the vendor's public policy, found through the security.txt `Policy:` field or the vendor
  registry's `vdpPolicyUrl`, assessed against eight criteria. Each determination carries its rule id and the
  sentence(s) quoted from the policy (at most two quotes of at most 300 characters each).
- **Where a policy may come from** (live collection, `packages/collect/src/collectors/vdp-policy.ts`): the first
  https candidate on the vendor's own domains (or subdomains) is used. A program page on a shared disclosure platform
  (`hackerone.com`, `bugcrowd.com`, `app.intigriti.com`, `yeswehack.com`, `responsibledisclosure.com`) is used only when
  the registry ties it to the vendor: it equals the registered `vdpPolicyUrl` or lies under it as a program path.
  Anyone can open a program on such a platform, so the host alone proves nothing about ownership; a platform URL that
  is not confirmed is skipped and noted ("Policy hosted on a shared platform; program ownership not independently
  established.").
- **A security.txt file on its own is not a VDP.** It can supply the security contact, a policy URL, an `Expires` date
  for currency, and, when no policy exists, a PARTIAL reporting channel. It never makes a policy "found".

#### Retrieval states

Before any criterion is assessed, the policy text gets a retrieval state (`policyRetrieval`, recorded as
`VdpObservation.policy.retrieval`):

| State | When | Effect |
|---|---|---|
| READ | Text extracted with at least `vdpMinimumPolicyWords` (80) words. | Assessed normally. |
| TOO_SHORT | Text extracted, at least 3 words, fewer than 80, and no interstitial marker. | Assessed, but confidence rule C7 caps the VDP metrics at LOW and Goal 5 at PARTIAL. |
| UNREADABLE | Fetched, but fewer than 3 words, or under 80 words containing an interstitial marker (`VDP_INTERSTITIAL_MARKERS`, for example "enable javascript", "checking your browser", "captcha"). | Every text criterion UNKNOWN; Goal 5 DATA_ERROR unless an earlier snapshot is carried. |
| FETCH_FAILED | The fetch did not succeed (including a robots.txt that disallows the page or cannot be fetched). | As UNREADABLE. |
| NOT_FOUND | No policy URL is known, or the URL returned 404 or 410. | Text criteria NOT_MET: the sources were read and nothing exists. |

#### The eight criteria

| Criterion | Pledge element | Determined from |
|---|---|---|
| POLICY_DISCOVERABLE | | whether a policy was read, and from where |
| SECURITY_CONTACT | | a usable security.txt `Contact:`, else a security mailbox named in the policy |
| REPORTING_CHANNEL | yes | policy phrase rules; else PARTIAL from a security.txt contact when no policy exists or none matched |
| TESTING_AUTHORIZED | yes | policy phrase rules |
| GOOD_FAITH_SAFE_HARBOR | yes | policy phrase rules |
| PUBLIC_DISCLOSURE_ALLOWED | yes | policy phrase rules |
| SCOPE_DEFINED | | policy phrase rules |
| CURRENT | | security.txt `Expires:` and the policy's stated last-updated date |

Criterion states:

| State | Meaning | Credit in `vdp.criteria_met` |
|---|---|---|
| MET | A rule found supporting language (quoted). | 1 |
| PARTIAL | Supporting language that is limited (for example testing only on some assets). | 0.5 |
| NOT_MET | The policy was read and contains no supporting language, or no policy exists. | 0 |
| CONTRADICTED | Prohibitive language against the criterion (quoted, and listed as a `ProhibitiveFinding`). | 0 |
| UNKNOWN | Could not be determined (policy not fetched or not readable, no dates to judge, contradictory or implausible dates). | 0, and listed |

How the assessor decides each criterion (`vdp/assess.ts assessVdp`). "Readable" means READ or TOO_SHORT;
"unreadable" means UNREADABLE or FETCH_FAILED.

- **POLICY_DISCOVERABLE:** MET when readable (`VDP.DISCOVERABLE.STXT` when the policy URL is one of the security.txt
  `Policy:` URLs, else `VDP.DISCOVERABLE.KNOWN`; a TOO_SHORT page notes its word count); UNKNOWN when unreadable;
  NOT_MET when not found.
- **SECURITY_CONTACT:** MET when security.txt lists a usable contact: `mailto:` with an address, `https:`/`http:` with
  a value, or `tel:` with digits (`isCreditableContact`; a placeholder such as "Contact: none" is warned about by the
  parser and not used). Else MET when the policy is readable and a sentence matches `VDP.CONTACT.R2`. Else UNKNOWN when
  the policy is unreadable. Else NOT_MET.
- **Text criteria** (REPORTING_CHANNEL, TESTING_AUTHORIZED, GOOD_FAITH_SAFE_HARBOR, PUBLIC_DISCLOSURE_ALLOWED,
  SCOPE_DEFINED), in this order:
  1. readable and a rule fired: the effect of the highest-precedence finding (CONTRADICTED 100 > PARTIAL 60 > MET 50).
     If a contradiction wins while supporting language was also found, the note says so;
  2. unreadable: UNKNOWN (`VDP.POLICY_UNREADABLE`), whatever security.txt says;
  3. REPORTING_CHANNEL only, with a usable security.txt contact: PARTIAL (`VDP.REPORTING.STXT_ONLY`);
  4. readable: NOT_MET (`VDP.NO_MATCH`);
  5. otherwise (no policy exists): NOT_MET (`VDP.NO_POLICY`).
- **CURRENT,** with `E` the security.txt `Expires` and `D` the policy's stated last-updated date, first match wins:
  1. `E` has passed: PARTIAL if `D` is within `vdpCurrentWithinDays` (730) of `asOf`, else NOT_MET;
  2. `E` has not passed: MET;
  3. `D` within the window: MET (`VDP.CURRENT.POLICY_DATE`);
  4. security.txt states more than one different `Expires` value: UNKNOWN (`VDP.CURRENT.STXT_CONTRADICTORY`; the parser
     warns `CONTRADICTORY_EXPIRES` and uses none of them);
  5. `D` is after `asOf`: UNKNOWN (`VDP.CURRENT.FUTURE_DATE`; an implausible date is not counted);
  6. `D` older than the window: NOT_MET (`VDP.CURRENT.POLICY_OLD`);
  7. no security.txt, no policy (NOT_FOUND), and no failed security.txt fetch: NOT_MET (`VDP.CURRENT.NONE`);
  8. otherwise UNKNOWN (`VDP.CURRENT.UNDATED`).
  The stated date is parsed after a marker such as "Last updated", "Last modified", "Last revised", "Updated on",
  "Revised on", "Effective date", "Effective as of" or "Date of last revision", in ISO (`2026-03-14`), month-day-year
  or day-month-year form. The latest date found wins.

#### Phrase matching and the negation model

Each sentence is lower-cased, curly quotes are straightened and whitespace is collapsed. Sentences are split at line
breaks and after `.`, `!` or `?` followed by whitespace (not after "e.g", "i.e", "inc", "etc", "vs"); at most 5000
sentences are read.

1. **Match.** A phrase in `allOf` or `noneOf` that starts with a letter or digit must start at a word boundary and may
   be a word prefix (`disclos` matches "disclose" and "disclosure"). A rule matches a sentence when every `allOf` group
   has at least one phrase present and no `noneOf` phrase is present.
2. **Negation.** For a permissive rule (MET or PARTIAL) that lists negations, TOUCHSTONE takes the clause around the
   first group's match: the text between the nearest clause breaks (`,` `;` `:` `(` `)` and the words "but", "and",
   "or", "however", "whereas", "while", "although", "except"). Negation markers and qualifiers are matched as plain
   substrings of that clause, so `n't` catches "isn't" and `not ` catches "cannot ".
   - No negation in the clause: the rule's own effect (MET or PARTIAL).
   - A negation **and** a qualifier in the clause: the sentence is ignored for that rule. A qualifier makes it an
     ordinary scope or coordination limit ("testing of systems outside this scope is not authorized", "do not disclose
     until a fix is available"), neither credit nor contradiction.
   - A negation without a qualifier: a **CONTRADICTED** finding for the criterion with rule id `<rule id>.NEGATED`
     ("Testing is never permitted", "We don't offer safe harbor"). It is recorded as prohibitive language.
3. **Precedence.** Among all findings for a criterion, CONTRADICTED (100, including `.NEGATED` findings) beats a
   limiting PARTIAL (60), which beats MET (50).

The word lists (`VDP_NEGATIONS`, `VDP_SCOPE_QUALIFIERS`, `VDP_COORDINATION_QUALIFIERS`,
`VDP_LEGAL_CONDITION_EXCLUSIONS`, `VDP_INTERSTITIAL_MARKERS`) and every rule are in
[section 15](#15-vdp-phrase-rules). Legal action conditioned on not following the policy ("we may take legal action
against anyone who does not comply with this policy") is excluded from the safe-harbor contradiction rule by
`VDP_LEGAL_CONDITION_EXCLUSIONS`: it is compatible with the pledge commitment.

The policy text also yields `textHash` (sha256 of the normalized text, used for change detection), `wordCount` and the
stated last-updated date.

#### Metrics

**`vdp.criteria_met`** (the VDP dimension figure)

```
value = (criteria MET + 0.5 x criteria PARTIAL) / 8 x 100
```

NOT_MET, CONTRADICTED and UNKNOWN count 0, and every UNKNOWN criterion is named in the calculation string. The
denominator is always 8.

- Policy unreadable or not fetched, nothing carried: both VDP metrics are null with gap `SOURCE_FAILED`, whatever
  security.txt alone would allow.
- All eight criteria UNKNOWN for another reason: null with gap `NO_SOURCE`.
- No VDP observation at all: both VDP metrics null with gap `NO_SOURCE`.

A vendor with a security.txt file and no policy (NOT_FOUND) can have a non-zero `vdp.criteria_met` (security contact,
currency, and a PARTIAL reporting channel). Goal 5 does not count such a vendor as having a policy.

**`vdp.pledge_elements_met`**

```
value = count of {REPORTING_CHANNEL, TESTING_AUTHORIZED, GOOD_FAITH_SAFE_HARBOR, PUBLIC_DISCLOSURE_ALLOWED} in state MET
```

A count from 0 to 4. PARTIAL, NOT_MET, CONTRADICTED and UNKNOWN are not counted. Null when all four are UNKNOWN, or
with gap `SOURCE_FAILED` as above.

When more than one VDP observation is supplied for a vendor, the one with the latest `observedAt` (then the lowest
snapshot id) is used and a DATA_QUALITY anomaly says so.

#### Status rule (`assess/goals.ts assessG5`)

Evaluated in this order:

1. No VDP observation for the vendor: NOT_VERIFIED.
2. Retrieval FETCH_FAILED or UNREADABLE and no carried snapshot: DATA_ERROR ("a retrieval problem, not a finding about
   the policy's content").
3. All four pledge elements MET and none CONTRADICTED: VERIFIED, unless the policy is TOO_SHORT, in which case PARTIAL
   with a note naming the word count and the floor.
4. A policy was found and at least one pledge element is MET: PARTIAL.
5. No policy was found: NOT_VERIFIED (the reason notes when a security.txt file exists but is not counted as a policy).
6. Otherwise (a policy was found, no pledge element MET): NOT_VERIFIED.

The status reason lists elements with prohibitive language (as observed deviation), elements not found or only partly
found, and elements that could not be determined. A carried-forward observation says so in the reason.

#### Evidence requirements

| Id | Requirement | Publicly available |
|---|---|---|
| G5.R1 | A discoverable public policy document | yes |
| G5.R2 | Authorization of testing by the public | yes |
| G5.R3 | Good-faith legal safe harbor | yes |
| G5.R4 | A clear reporting channel | yes |
| G5.R5 | Public disclosure allowed in line with coordinated disclosure | yes |

One evidence item is written per criterion (metric id `vdp.criteria_met`), quoting the supporting sentence or the
prohibitive sentence. TOUCHSTONE reads a policy; it does not test whether the vendor honours it.

### G6 CVEs

> "Demonstrate transparency in vulnerability reporting by including accurate Common Weakness Enumeration (CWE) and Common Platform Enumeration (CPE) fields in every Common Vulnerabilities and Exposures (CVE) record for the manufacturer's products. Additionally, issue CVEs in a timely manner for, at minimum, all critical or high impact vulnerabilities (whether discovered internally or by a third party) that either require actions by a customer to patch or have evidence of active exploitation."

- **Verification mode:** PUBLICLY_MEASURABLE.
- **Two measured dimensions:** record quality (CNA-supplied CWE and CPE in every record) and issuance timeliness (for
  critical and high advisories, whether a CVE record exists and how long after the advisory it was published).

#### Attribution: which records belong to a vendor

Records are attributed by `identity/index.ts attributeCves`, using only structured fields and the aliases in the
vendor registry. Names are compared exactly after normalization: Unicode NFKC, case-fold, trim, collapse whitespace,
drop trailing periods and commas, and strip trailing corporate suffixes (Inc, LLC, Ltd, Corp, Corporation, GmbH, AG).
CNA short names, CNA org ids and CPE vendor strings are compared case-folded and whitespace-collapsed, without suffix
stripping.

Rules, in order:

| Rule | Confidence | Condition |
|---|---|---|
| ASSIGNER_IS_VENDOR_CNA | HIGH | `cveMetadata.assignerShortName` or `assignerOrgId` is one of the vendor's CNA_SHORT_NAME / CNA_ORG_ID aliases, **unless** the record's affected vendor or a well-formed CNA CPE names a different registered vendor and not this one (a CNA assigning for another vendor's product): then the record is excluded as AMBIGUOUS_VENDOR with both vendors as candidates. |
| AFFECTED_VENDOR_AND_CPE | HIGH | A `containers.cna.affected[].vendor` is one of the vendor's AFFECTED_VENDOR aliases, and a well-formed CNA CPE uses one of the vendor's CPE_VENDOR namespaces. |
| AFFECTED_VENDOR_ONLY | MEDIUM | The affected-vendor alias matches without a corroborating CNA CPE. |

Exclusions (the record is set aside from every metric and listed):

| Reason | When |
|---|---|
| DUPLICATE_CONFLICT | The same CVE id appears more than once with different content hashes. Every copy is excluded. Byte-identical copies are collapsed to one and not excluded. |
| REJECTED_RECORD | Record state is REJECTED. |
| IDENTITY_CONFLICT | A matched CNA name or id, or the CPE namespace that would corroborate rule 2, is registered for more than one vendor. |
| AMBIGUOUS_VENDOR | The matching aliases point at more than one vendor, or the assigner's vendor differs from the vendor the structured data names. The record is never split or given to the first match. |
| FREE_TEXT_ONLY | No structured field matches, but the record title mentions a registered vendor name. Reported, never attributed. |

Free text (descriptions, titles) is never used to attribute a record. Identity conflicts are detected from the
registry (`detectIdentityConflicts`): a legal name, brand, subsidiary or signatory listing shared by two vendors
(NAME_COLLISION), a CNA short name or org id shared by two vendors (CNA_SHARED), or a CPE vendor namespace shared by two
vendors, for example after an acquisition (CPE_NAMESPACE_SHARED). AFFECTED_VENDOR aliases are deliberately not
conflicts; a record that hits a shared affected-vendor name is excluded per record as AMBIGUOUS_VENDOR.

#### Eligibility for the record-quality metrics

A record is **eligible** when it is attributed to the vendor, not excluded, not a conflicting duplicate, in state
PUBLISHED, and its `datePublished` falls in `(asOf - cveWindowDays, asOf]`, that is the 730 days up to the analysis
date. Impossible calendar dates (for example `2026-02-30`) are rejected by the normalizer rather than rolled over, so
such a record has no `datePublished`. Ineligible attributed records get an evidence item with interpretation EXCLUDED
and one of: `REJECTED`, `NO_DATE_PUBLISHED`, `PUBLISHED_AFTER_AS_OF`, `OUTSIDE_WINDOW`, `DUPLICATE_CONFLICT`. Their
counts appear in the `cve.complete_records` breakdown as `not_eligible.<reason>`.

#### Field rules

**Usable CWE** (`assessCwe`). The CNA container's `problemTypes[].descriptions[]` are read. A description contributes
a CWE statement when it has a `cweId`, or when it is typed `CWE` or its text begins with `CWE-` or `NVD-CWE-`. A
free-text problem type (for example `type: "text"`, "information disclosure") is not a CWE statement.

| CNA CWE values | Result |
|---|---|
| none | not usable, gap NOT_PROVIDED |
| at least one `CWE-<n>` identifier (n > 0) | usable |
| only placeholders (`NVD-CWE-noinfo`, `NVD-CWE-Other`, `CWE-noinfo`, `CWE-Other`, matched case-insensitively, alone or followed by a space or colon) | **1.0.0: usable. 1.1.0: not usable, gap PLACEHOLDER** |
| only values that are neither | not usable, gap MALFORMED |

**Well-formed CPE** (`parseCpe23`, `assessCpe`). CNA CPEs are read from both places the schema allows:
`affected[].cpes[]` and `cpeApplicability[].nodes[].cpeMatch[].criteria`. A CPE is well-formed when it is a CPE 2.3
formatted string with 13 colon-separated components (backslash escapes honoured), `part` is `a`, `o` or `h`, and both
`vendor` and `product` are concrete (not empty, not `*` or `-`, no `*` or `?` inside). A CPE 2.2 URI (`cpe:/a:...`), a
wrong component count, an unknown part, control characters or a value over 1000 characters is MALFORMED. A container
with no CPE is NOT_PROVIDED; a container whose CPEs are all malformed is MALFORMED.

**In the vendor's CPE namespace.** A record is in namespace when at least one of its well-formed CNA CPEs has a
`vendor` field equal (case-folded, whitespace-collapsed) to one of the vendor's registered CPE_VENDOR aliases. When the
registry lists no CPE_VENDOR alias for the vendor, the namespace cannot be checked.

The namespace check depends on the registry, not on the official CPE dictionary. A vendor's CNA can write CPEs under
one vendor string (for example a legal-entity form such as `<name>_ab`) while the NVD CPE dictionary uses a shorter
one (`<name>`). Whether both count is a registry decision: each CPE_VENDOR alias is carried with its evidence and a
confidence level, and can be disputed (reason INCORRECT_PRODUCT_MAPPING). TOUCHSTONE does not validate CNA CPEs
against the official CPE dictionary; that is a roadmap item.

#### Record-quality metrics

All ratios below use the eligible records as the denominator `n` unless stated, and share one rule (`measure/metric.ts
ratioMetric`):

```
denominator = 0                         -> value null, gap NO_ELIGIBLE_RECORDS (SOURCE_FAILED if the CVE source failed)
0 < denominator < minimumEligibleRecords -> value null, gap BELOW_MINIMUM_SAMPLE  (numerator and denominator still published)
otherwise                                -> numerator / denominator x 100
```

The minimum sample (5) applies **per metric** to that metric's own denominator.

| Metric | Numerator | Denominator | Notes |
|---|---|---|---|
| `cve.cwe_coverage` | eligible records with a usable CNA CWE | eligible records | Breakdown: `gap.NOT_PROVIDED`, `gap.PLACEHOLDER`, `gap.MALFORMED`, and `placeholder_counted_as_populated` (records credited only through a placeholder, 1.0.0). |
| `cve.cpe_coverage` | eligible records with at least one well-formed CNA CPE | eligible records | Breakdown by gap. |
| `cve.cpe_namespace_consistency` | records with a well-formed CNA CPE in the vendor's namespace | eligible records **with a well-formed CNA CPE** | Minimum sample applies to this smaller denominator. Null with gap NOT_APPLICABLE when no CPE_VENDOR alias is registered; gap NOT_PROVIDED when there are eligible records but none has a well-formed CNA CPE. |
| `cve.complete_records` (CVE_QUALITY figure) | eligible records whose CNA container has a usable CWE **and** a well-formed CPE in the vendor's namespace | eligible records | The pledge says "every" record, so this is the record-quality figure. Null with gap NOT_APPLICABLE when no CPE_VENDOR alias is registered and there are eligible records. Breakdown: `missing_cwe`, `missing_cpe`, `cpe_outside_namespace`, `not_eligible.<reason>`. |
| `cve.enriched_only` | eligible records lacking a usable CNA CWE or a well-formed CNA CPE for which an ADP container supplies the missing field | eligible records | Context only, never credited. Direction NEUTRAL. Breakdown: `cwe_from_adp`, `cpe_from_adp`. ADP CWE usability uses the same placeholder parameter. |
| `cve.duplicate_conflicts` | CVE ids naming this vendor as a candidate that appear more than once with different content | (count) | Data quality, not a quality signal. |
| `cve.excluded_records` | distinct (CVE id, reason) exclusions naming this vendor as a candidate | (count) | Data quality. Breakdown `reason.<REASON>`. |

Each eligible record gets one evidence item per metric it feeds (CWE, CPE, namespace when it has a well-formed CPE,
complete, and enriched-only when applicable), stating the container (`CNA` or `ADP`), the raw values and the reading.

#### Issuance timeliness

Timeliness is measured against the vendor's own machine-readable advisories (CSAF 2.0). An advisory's severity is the
one the advisory states: `document.aggregate_severity.text` when it maps to a known word (critical; high or important;
medium or moderate; low; none or informational), otherwise the highest CVSS `baseSeverity` in
`vulnerabilities[].scores[]`, otherwise UNKNOWN. Nothing is inferred from prose.

Advisories are first de-duplicated by (vendor, advisory id); the run's NORMALIZE stage reports how many listings were
collapsed.

**Eligible advisories:** the vendor's advisories whose stated severity is CRITICAL or HIGH (`highImpactSeverities`) and
whose initial release date (`tracking.initial_release_date`) is in `(asOf - 730 days, asOf]`.

**When nothing can be measured:**

- No advisories at all (no CSAF feed, or a feed that yielded none): `cve.high_impact_with_cve`, `cve.timely_issuance`
  and `cve.publication_latency` are null with gap `NO_SOURCE`. Never zero.
- The CVE source failed (CVE snapshots exist, none OK): the three metrics are null with gap `SOURCE_FAILED`. An unread
  source says nothing about whether the CVEs exist.

Per advisory (`timeAdvisory`), each listed CVE id (de-duplicated) is classified:

- **undetermined:** the id is a conflicting duplicate in the snapshot;
- **missing:** absent from the run's records, REJECTED, or without a `datePublished`;
- **published after asOf:** its `datePublished` is after the analysis date, so it did not exist then;
- **found:** a PUBLISHED record with a `datePublished` on or before `asOf`. Any record in the snapshot counts, not only
  records attributed to the vendor.

**Latency** = the latest `datePublished` among the found records minus the advisory's release date (sign kept:
negative means a CVE was public before the advisory). When an advisory lists several CVEs, the latest one decides.
The tolerance comparison uses milliseconds: 1 day plus 7 minutes is LATE.

**Outcome**, first match wins:

| Outcome | When | Counted |
|---|---|---|
| NO_CVE_LISTED | the advisory lists no CVE id | in the denominators, not timely |
| CVE_UNDETERMINED | at least one listed id is a conflicting duplicate | **set aside**: outside every denominator, counted in the breakdown as `undetermined_set_aside` |
| CVE_NOT_IN_SNAPSHOT | an id is missing (or nothing found) | not timely |
| CVE_PUBLISHED_AFTER_AS_OF | nothing is missing, but an id was published after `asOf` | not timely, not "with CVE" |
| TIMELY | every listed id found and latency <= `timelinessToleranceDays` (1 day) | timely |
| LATE | every listed id found and latency above the tolerance | not timely |

| Metric | Formula | Notes |
|---|---|---|
| `cve.high_impact_with_cve` | high-impact advisories with at least one listed CVE found / high-impact advisories x 100 | Breakdown: `no_cve_listed`, `advisories_total`, `undetermined_set_aside`, `duplicate_advisories_collapsed`. |
| `cve.timely_issuance` (CVE_TIMELINESS figure) | advisories with outcome TIMELY / high-impact advisories x 100 | Breakdown: `timely`, `late`, `no_cve_listed`, `cve_not_in_snapshot`, `cve_published_after_as_of`, `tolerance_days`, `minimum_high_impact_advisories`, plus the two counts above. |
| `cve.publication_latency` | median of per-advisory latencies, with p75 and p95 (nearest rank) | Over advisories with a latency (at least one listed CVE found). Null with gap NO_ELIGIBLE_RECORDS when none. Breakdown: `cve_before_advisory`, `within_tolerance`. |

**Small advisory samples.** The advisory ratios are reported from one advisory upward; they are not withheld. Below
`minimumHighImpactAdvisories` (5) advisories, confidence rule C2 caps them at LOW, and the timeliness figure and Goal 6
cannot be VERIFIED (they are at most PARTIAL). When advisories exist but none is high-impact in the window, the
ratios are null with gap `NO_ELIGIBLE_RECORDS`.

#### Status rule (`assess/goals.ts assessG6`)

With `q` = `cve.complete_records` and `t` = `cve.timely_issuance`:

1. The CVE source failed: DATA_ERROR.
2. `q = 100`, `t = 100`, and `t` rests on at least `minimumHighImpactAdvisories` (5) advisories: VERIFIED.
3. `q` and `t` both null:
   - NOT_VERIFIED ("Evidence incomplete") when record quality is null for a sample reason (BELOW_MINIMUM_SAMPLE or
     NO_ELIGIBLE_RECORDS) **and** timeliness is null because there is nothing to measure (NO_SOURCE or
     NO_ELIGIBLE_RECORDS);
   - DATA_ERROR otherwise ("A source or mapping problem prevents measurement"), for example when no CPE vendor
     namespace is registered so completeness cannot be checked.
4. Otherwise: PARTIAL. The reason begins "Evidence supports part of the goal" when either measured value is above 0,
   and "Evidence does not support the goal on the parts that could be measured" when both measured values are 0. A
   note is added when timeliness rests on fewer than 5 advisories.

So a vendor with every eligible record complete but no CSAF feed is PARTIAL: the timeliness half has no evidence.

#### Evidence requirements

| Id | Requirement | Publicly available |
|---|---|---|
| G6.R1 | CVE records for the vendor's products, with the CNA container | yes |
| G6.R2 | Vendor advisories stating severity and CVE ids, with release dates | yes |

### G7 Evidence of intrusions

> "Within one year of signing the pledge, demonstrate a measurable increase in the ability for customers to gather evidence of cybersecurity intrusions affecting the manufacturer's products."

- **Verification mode:** NOT_EXTERNALLY_VERIFIABLE.
- **Why:** logging features are sometimes documented publicly, but documentation does not show availability by
  licence tier, default configuration, or change over time in a comparable way. Counting documentation pages would
  measure documentation, not capability.
- **Status rule:** always NOT_EXTERNALLY_VERIFIABLE.
- **Evidence that would be needed:** a per-product logging capability inventory with licence tier; default retention
  and enablement; a change log over the pledge year.

---

## 6. Dimension figures

Three figures, never combined (`assess/goals.ts dimensionFigures`):

| Dimension | Metric | Status |
|---|---|---|
| VDP | `vdp.criteria_met` | the Goal 5 status |
| CVE_QUALITY | `cve.complete_records` | DATA_ERROR if G6 is DATA_ERROR; NOT_VERIFIED if the value is null; VERIFIED at 100; PARTIAL otherwise |
| CVE_TIMELINESS | `cve.timely_issuance` | as CVE_QUALITY, except that VERIFIED also needs at least `minimumHighImpactAdvisories` (5) advisories in the denominator; below that a 100% figure is PARTIAL |

## 7. Missing data and unknown states

Missing data is a first-class state at two levels.

**Field level** (`FieldGap`, per record field):

| Gap | Meaning | Emitted by the current measures |
|---|---|---|
| NOT_PROVIDED | The field is absent or empty in the source. | yes (CWE, CPE) |
| PLACEHOLDER | Present but a placeholder such as `NVD-CWE-noinfo`. | yes (CWE, under 1.1.0) |
| MALFORMED | Present but unparseable, for example a CPE that is not CPE 2.3. | yes (CWE, CPE) |
| NOT_FOUND | The record itself was not found in the source. | defined in the model; a missing record shows up as a missing advisory CVE or a collection error instead |
| PARSER_FAILURE | The parser threw on the record. | defined in the model; a record the normalizer rejects is recorded as a REJECTED snapshot with the parser error |
| NOT_APPLICABLE | The methodology excludes the field. | used as a metric gap |

**Metric level** (`MetricValue.gap`, when `value` is null):

| Gap | Meaning |
|---|---|
| NO_SOURCE | No source exists for this vendor (no VDP observation, no advisory feed). |
| SOURCE_FAILED | The source exists but could not be retrieved or read, and no earlier snapshot was usable. |
| NO_ELIGIBLE_RECORDS | The source was read; nothing was eligible. |
| BELOW_MINIMUM_SAMPLE | Fewer eligible items than the minimum sample. Numerator and denominator are still published. |
| NOT_APPLICABLE | The metric cannot apply (no CPE_VENDOR alias registered for a namespace check). |
| NOT_PROVIDED | Eligible records exist but none carries the field the metric needs (namespace consistency). |

A null value is never coerced to 0. In the API's sorted signatory list, vendors without a value sort last in both
directions and are never ranked as 0.

## 8. Confidence

Each metric starts HIGH. Each rule that fires caps it and adds its reason; the lowest cap wins. No weighting, no
arithmetic (`CONFIDENCE_RULES`).

| Rule | Cap | Fires when |
|---|---|---|
| C1.ATTRIBUTION | MEDIUM | At least one contributing record was attributed by affected-vendor name only (MEDIUM attribution). |
| C2.SAMPLE | LOW | An advisory-based metric rests on fewer than `minimumHighImpactAdvisories` high-impact advisories (CVE record metrics are not reported below `minimumEligibleRecords`). |
| C3.STALE | MEDIUM | A source feeding the metric is STALE under the freshness bands. |
| C3.UNKNOWN_FRESHNESS | LOW | A source feeding the metric has no successful snapshot, so its age is unknown. |
| C4.CARRIED | MEDIUM | The observation was carried forward from an earlier snapshot after a refresh did not succeed. |
| C5.UNDETERMINED | MEDIUM | Part of the input could not be determined (UNKNOWN criteria are counted as 0). |
| C6.NOT_MEASURED | LOW | No value could be measured. |
| C7.TOO_SHORT | LOW | The policy text read is shorter than `vdpMinimumPolicyWords`; the goal is capped at PARTIAL. |

Which metrics read which rules: VDP metrics apply C3 (policy and security.txt sources), C4, C5 and C7; CVE record
metrics and G3 apply C1 and C3 (CVE_PROGRAM sources); advisory metrics apply C3 (advisory sources) and C2; every null
value gets C6. Individual evidence items also carry a confidence: the attribution confidence for record evidence; for
VDP criteria LOW when UNKNOWN, MEDIUM when carried, else HIGH.

## 9. Evidence coverage

Coverage says how much could be looked at, not how good the result was. It has 14 slots (`COVERAGE_SLOTS`):

- the 8 VDP criteria (`vdp.criterion.<CRITERION>`); a criterion slot is observed when its state is MET, NOT_MET,
  PARTIAL or CONTRADICTED;
- `cve.cwe_coverage`, `cve.cpe_coverage`, `cve.cpe_namespace_consistency`, `cve.high_impact_with_cve`,
  `cve.publication_latency`, `g3.class_share_trend`; a metric slot is observed when its value is not null and its
  denominator (or distribution `n`) is above 0.

```
coverage.percent = observed slots / 14 x 100, one decimal
```

Each unobserved slot is listed with its reason. The coverage object also reports the number of distinct sources the
vendor's evidence came from, the number of evidence-backed measurements, and the number of goals that are not
externally verifiable (4). An unreadable policy leaves its text criteria UNKNOWN, so they are not counted as observed.

## 10. Cohort benchmarking

(`assess/cohort.ts`)

- **Only rates, shares and medians are compared**, never raw counts. Benchmarked metrics (`BENCHMARK_METRIC_IDS`):
  `vdp.criteria_met`, `cve.cwe_coverage`, `cve.cpe_coverage`, `cve.cpe_namespace_consistency`, `cve.complete_records`,
  `cve.high_impact_with_cve`, `cve.timely_issuance`, `cve.publication_latency`.
- **Peer groups contain only LISTED vendors** (on the signer page of that run): `ALL_SIGNATORIES` is every listed
  vendor; a category group is the listed vendors of that `category`. A vendor that is not listed is still placed against
  the listed peers, but never shapes their medians. A listed vendor is included in its own peer group.
- **Peer median** uses only peers with a non-null value; the peer count is always reported.
- **Position** (ABOVE_PEER_MEDIAN, AT_PEER_MEDIAN, BELOW_PEER_MEDIAN) is stated only when at least
  `MIN_PEERS_FOR_POSITION` = **3** peers have a value; otherwise NOT_COMPARABLE. Wording is fixed: "Above peer median
  on this observable metric." and so on. The comparison is a plain `>`, `<` or `=` against the median, whatever the
  metric's direction.
- **Historical median:** the median of the vendor's own earlier values for the metric, from runs with an earlier `asOf`,
  using only values comparable under the current methodology (see section 16).
- **Cohort summary** per group (ALL_SIGNATORIES and each category present among listed vendors): vendor count, the
  median of each benchmarked metric and of coverage percent, a coverage histogram (0-24, 25-49, 50-74, 75-100), and
  Goal 5 status counts.
- **Ranking notes:** one sentence per dimension with the value, its numerator and denominator, and the
  ALL_SIGNATORIES position.

## 11. Anomalies

Anomalies are observed deviations, stated with the rule and threshold that fired. They are prompts for review, never
judgements (`assess/anomalies.ts`).

| Kind | Rule |
|---|---|
| UNUSUAL | For each benchmarked metric whose direction is HIGHER_IS_STRONGER_EVIDENCE: the vendor's value is strictly below the nearest-rank P`unusualBelowPercentile` (P10) of the values of LISTED vendors. Evaluated only when at least `MIN_PEERS_FOR_PERCENTILE` = **10** listed vendors have a value. |
| LATENCY_OUTLIER | Current median latency > max(historical median, 1 day) x `latencyOutlierFactor` (2) **and** current - historical >= `latencyOutlierMinDays` (7). Needs a historical median. |
| DATA_QUALITY | One per exclusion reason affecting the vendor; one per identity conflict involving the vendor; one when more than one VDP observation was supplied; one when the VDP observation is carried forward; one per vendor source (VENDOR_VDP, SECURITY_TXT, VENDOR_ADVISORY) whose freshness is STALE or UNKNOWN, including the policy, security.txt, carried and advisory snapshots the vendor's observations rely on. |
| CHANGE_DETECTED | The VDP text hash or a criterion state differs from the previous dataset's observation (section 13). |

Headlines start with "Observed deviation", "Observed change" or "Data quality"; the quality gate (Q9) checks this.
Anomaly ids are content-derived (`AN-` + 10 hex of sha256).

## 12. Freshness

Freshness is computed from successful fetches, never from the last attempt (`freshness/freshness.ts`). Snapshots
fetched after `asOf` are ignored. Bands are in hours: age <= first value is CURRENT, <= second is AGING, above is STALE.

| Source family | CURRENT up to | AGING up to | STALE after |
|---|---|---|---|
| CISA_PLEDGE | 168 h (7 days) | 720 h (30 days) | 30 days |
| CVE_PROGRAM | 24 h (1 day) | 168 h (7 days) | 7 days |
| NVD | 24 h (1 day) | 168 h (7 days) | 7 days |
| VENDOR_ADVISORY | 48 h (2 days) | 336 h (14 days) | 14 days |
| VENDOR_VDP | 168 h (7 days) | 1080 h (45 days) | 45 days |
| SECURITY_TXT | 168 h (7 days) | 1080 h (45 days) | 45 days |

**Document sources** (signer page, advisories, policy pages, security.txt, robots.txt):

- The snapshot used is the latest successful one, or the explicit `substitutedBy` of a failed latest attempt. A
  substitute is honoured only when it exists in the run, belongs to the same source, is OK and was fetched on or before
  `asOf`; otherwise it is ignored, the note says why, and the source's own last success is used (else UNKNOWN).
- The latest attempt did not succeed: the state is computed from the age of the snapshot actually used and is **never
  CURRENT** (CURRENT is lowered to AGING). The note names the failed attempt and the snapshot used.
- No attempt recorded, or no usable successful snapshot: UNKNOWN.

**Per-record sources** (CVE_PROGRAM, NVD) hold one snapshot per record fetched in one batch, so "the latest attempt"
would be whichever record happened to come last. Their freshness is order-independent: the age is that of the **oldest**
successful record fetch (no record used is older); the status is OK when at least one record was fetched successfully;
records that were not OK are counted in the note (a failed record is a record problem, not a stale source); no
successful record means UNKNOWN.

## 13. VDP change detection

The current observation is compared with the previous dataset's observation for the same vendor
(`assess/vdp-change.ts`). A retrieval problem is not a change:

- no change is reported when the current observation could not read the policy (FETCH_FAILED or UNREADABLE);
- criteria that are UNKNOWN on either side are skipped;
- the text is compared only when both observations carry a text hash.

Otherwise a change is reported when the text hash differs or a criterion's state differs. "Review recommended" is set
when a pledge criterion changed state. A change is an observation, not a judgement. Live runs started from the CLI or
API do not supply a previous observation, so change detection runs only where previous observations are provided (the
demo pipeline supplies them).

## 14. Pre-publication quality gate

Ten questions a reviewer would ask before a figure is published, each answered by a concrete check over the run
(`run/quality-gate.ts`). A check that does not pass is published with its detail; the gate reports, it does not edit
results. The PUBLISH stage of the run is WARN when any check needs review.

| Id | Question | Check |
|---|---|---|
| Q1 | Is the vendor identity correct? | No attributed record is involved in an identity conflict, and every attribution names at least one matched alias that the registry backs with evidence. |
| Q2 | Is the dataset current enough? | Every STALE or UNKNOWN source is labelled in the freshness table, and every metric that cites evidence from such a source carries confidence below HIGH. |
| Q3 | Is the source authoritative? | Every evidence item resolves to a declared source, and every credited CWE/CPE evidence item comes from the CNA container. |
| Q4 | Is the formula documented? | Every reported metric has a published definition with a formula, a query and a rendered calculation. |
| Q5 | Is the denominator correct? | Every percentage recomputes from its numerator and denominator, numerators never exceed denominators, and per-record metric denominators equal the count of their per-record evidence items. |
| Q6 | Are missing values explicit? | Every null value carries a gap reason; no value is reported over a zero denominator. |
| Q7 | Can the result be re-run? | The methodology version is published, every number is finite, and the outputs survive a canonical JSON round trip unchanged. |
| Q8 | Is the conclusion overstated? | Goal 3 is never VERIFIED, unverifiable goals are NOT_EXTERNALLY_VERIFIABLE, no VERIFIED goal has an unmeasured figure, and generated text contains no judgement words. |
| Q9 | Is measurement separated from interpretation? | Benchmark wording refers to an observable metric, anomaly headlines are worded as observations, and vendor claims never appear as supporting evidence. |
| Q10 | Could the mapping be disputed? | Every evidence item names a subject and a snapshot that exists in the run, and every determined VDP criterion carries its rule id. |

## 15. VDP phrase rules

The tables below are generated from `VDP_RULES`, the negation word lists and `VDP_STRUCTURAL_RULES` in
`packages/core/src/vdp/assess.ts` by `node scripts/docs/vdp-rules-table.ts`. Re-run the script and paste its output
here after changing a rule.

`VDP.NO_POLICY`, `VDP.POLICY_UNREADABLE`, `VDP.NO_MATCH` and `VDP.*.NEGATED` are listed under TESTING_AUTHORIZED but
apply to every text criterion.

### Phrase rules (`VDP_RULES`)

A rule matches a sentence when every "all of" group has at least one phrase present (word-start match) and no
"none of" phrase is present. Groups are separated by **AND**; phrases inside a group are alternatives. For a rule
with negations, the clause around the first group's match is then checked: a negation marker there turns the match
into a CONTRADICTED finding with rule id `<rule>.NEGATED`, unless a qualifier is also in that clause, in which case
the sentence is ignored for that rule.

| Rule id | Criterion | Effect | Precedence | What it means | All of (each group) | None of | Negations | Qualifiers |
|---|---|---|---|---|---|---|---|---|
| `VDP.REPORTING.R1` | REPORTING_CHANNEL | MET | 50 | The policy tells reporters how to report: a reporting verb together with a channel (address, form, portal, platform or URL). | (`report`, `submit`, `send`, `contact us`, `reach us`, `email us`, `e-mail us`, `notify us`, `let us know`) **AND** (`@`, `mailto:`, `form`, `portal`, `https://`, `email`, `e-mail`, `platform`, `hackerone`, `bugcrowd`, `intigriti`, `yeswehack`) | `do not report`, `not accept` | (none) | (none) |
| `VDP.TESTING.C1` | TESTING_AUTHORIZED | CONTRADICTED | 100 | Testing requires prior written or explicit permission: testing by the public is not authorized. | (`written permission`, `prior written`, `prior authorization`, `prior authorisation`, `prior approval`, `explicit permission`, `express permission`, `written consent`, `written authorization`) **AND** (`test`, `scan`, `research`, `assess`, `probe`) | (none) | (none) | (none) |
| `VDP.TESTING.C2` | TESTING_AUTHORIZED | CONTRADICTED | 100 | The policy prohibits testing outright. | (`do not test`, `must not test`, `may not test`, `not permitted to test`, `testing is prohibited`, `testing is not permitted`, `testing is not authorized`, `not authorized to test`, `prohibits testing`, `prohibit testing`, `prohibits any testing`, `no testing`, `testing is forbidden`, `forbids testing`) | (none) | (none) | (none) |
| `VDP.TESTING.P1` | TESTING_AUTHORIZED | PARTIAL | 60 | Testing is authorized, but only on a restricted subset of the vendor’s products or assets. | (`authoriz`, `authoris`, `permit`, `allowed`, `may test`, `may conduct`, `welcome`, `invite`, `encourage`) **AND** (`test`, `security research`, `vulnerability research`, `research activit`, `good faith research`, `good-faith research`) **AND** (`only`, `limited to`, `restricted to`, `solely`, `exclusively`) | `not limited to` | `VDP_NEGATIONS` | `VDP_SCOPE_QUALIFIERS` |
| `VDP.TESTING.R1` | TESTING_AUTHORIZED | MET | 50 | The policy authorizes, permits or invites security testing by the public. | (`authoriz`, `authoris`, `permit`, `allowed`, `may test`, `may conduct`, `welcome`, `invite`, `encourage`) **AND** (`test`, `security research`, `vulnerability research`, `research activit`, `good faith research`, `good-faith research`) | (none) | `VDP_NEGATIONS` | `VDP_SCOPE_QUALIFIERS` |
| `VDP.SAFE_HARBOR.C1` | GOOD_FAITH_SAFE_HARBOR | CONTRADICTED | 100 | The policy reserves or threatens legal action against researchers. Legal action conditioned on not following the policy is not a contradiction. | (`reserve the right to pursue legal`, `reserves the right to pursue legal`, `reserve the right to take legal`, `reserves the right to take legal`, `reserve the right to initiate legal`, `reserves the right to initiate legal`, `reserve all legal`, `reserves all legal`, `may pursue legal action`, `may take legal action`, `may initiate legal action`, `will pursue legal action`, `will take legal action`, `may result in legal action`, `will result in legal action`, `may be prosecuted`, `will be prosecuted`, `referred to law enforcement`, `criminal prosecution`, `hesitate to pursue legal`, `hesitate to take legal`) | `VDP_LEGAL_CONDITION_EXCLUSIONS` | (none) | (none) |
| `VDP.SAFE_HARBOR.R1` | GOOD_FAITH_SAFE_HARBOR | MET | 50 | The policy commits not to recommend or pursue legal action against good-faith research, or states the research is considered authorized. | (`will not pursue legal`, `will not take legal`, `will not initiate legal`, `will not bring legal`, `will not recommend or pursue legal`, `not recommend or pursue legal`, `won't pursue legal`, `won't take legal`, `will not file`, `will not sue`, `will not bring a lawsuit`, `not to pursue legal`, `will not seek prosecution`, `will not report you to law enforcement`, `consider your research to be authorized`, `consider your research authorized`, `consider such research authorized`, `deem your research authorized`, `considered authorized`) | (none) | `not considered`, `not be considered`, `n't considered`, `never considered`, `no longer considered`, `not deem` | `VDP_SCOPE_QUALIFIERS` |
| `VDP.SAFE_HARBOR.R2` | GOOD_FAITH_SAFE_HARBOR | MET | 50 | The policy offers a safe harbor in a sentence about good-faith research or legal action (a bare "Safe harbor" heading does not count). | (`safe harbor`, `safe harbour`) **AND** (`good faith`, `good-faith`, `legal`, `research`, `comply`, `complian`, `authoriz`) | (none) | `VDP_NEGATIONS` | `VDP_SCOPE_QUALIFIERS` |
| `VDP.DISCLOSURE.C1` | PUBLIC_DISCLOSURE_ALLOWED | CONTRADICTED | 100 | The policy forbids public disclosure without a path to coordinated disclosure (no "until", "after" or time frame). | (`must not disclose`, `may not disclose`, `shall not disclose`, `do not disclose`, `will not disclose`, `not to disclose`, `never disclose`, `must not publish`, `may not publish`, `shall not publish`, `do not publish`, `not publicly disclose`, `not permitted to disclose`, `not permitted to publish`, `prohibited from disclos`, `prohibited from publish`, `public disclosure is prohibited`, `public disclosure is not permitted`, `public disclosure is forbidden`, `keep confidential`, `remain confidential`, `confidential indefinitely`) | `until`, `unless`, `prior to`, `before`, `without coordinat`, `without first`, `within`, `after`, `once` | (none) | (none) |
| `VDP.DISCLOSURE.R1` | PUBLIC_DISCLOSURE_ALLOWED | MET | 50 | The policy allows public disclosure or describes coordinated disclosure. | (`coordinated disclosure`, `coordinated vulnerability disclosure`, `coordinate disclosure`, `coordinate public disclosure`, `public disclosure`, `publicly disclose`, `disclose publicly`, `publish your findings`, `publish the details`, `publish details`, `publish your research`, `may publish`, `may disclose`, `free to disclose`, `free to publish`) | (none) | `VDP_NEGATIONS` | `VDP_COORDINATION_QUALIFIERS` |
| `VDP.DISCLOSURE.R2` | PUBLIC_DISCLOSURE_ALLOWED | MET | 50 | The policy asks reporters to hold disclosure until a fix or a stated time: disclosure is allowed after coordination. | (`disclos`, `publish`) **AND** (`until`, `after`, `before`, `once`, `days`, `prior to`, `when a fix`, `coordinat`) | `never`, `indefinitely`, `without our written`, `without written`, `without prior written`, `not permitted`, `prohibit`, `forbid`, `aren't permitted`, `not allowed` | (none) | (none) |
| `VDP.SCOPE.P1` | SCOPE_DEFINED | PARTIAL | 60 | Scope is stated but restricted to a subset of the vendor’s products or assets. | (`applies only to`, `only applies to`, `applies solely to`, `limited to`, `restricted to`, `only the following`, `only covers`, `covers only`, `is limited`, `only in scope`, `only these`) **AND** (`scope`, `policy`, `applies`, `asset`, `system`, `propert`, `domain`, `product`, `service`, `website`, `web`) | `not limited to` | (none) | (none) |
| `VDP.SCOPE.R1` | SCOPE_DEFINED | MET | 50 | The policy states what is in or out of scope. | (`in scope`, `in-scope`, `out of scope`, `out-of-scope`, `scope of this policy`, `this policy applies to`, `policy applies to`, `the following products`, `the following systems`, `the following assets`, `applies to all`, `covers all`) | (none) | (none) | (none) |
| `VDP.CONTACT.R2` | SECURITY_CONTACT | MET | 50 | The policy names a security mailbox or security team contact. | (`security@`, `psirt@`, `secure@`, `vulnerability@`, `vulns@`, `disclosure@`, `cert@`, `product-security@`, `productsecurity@`, `security contact`, `security team at`, `psirt`) | (none) | (none) | (none) |

### Negation model word lists

Negations and qualifiers are matched as substrings of the clause (padded with a space at each end), so `n't` matches
"isn't" and `not·` matches "cannot ". A `·` marks a significant leading or trailing space.

| List | Role | Phrases |
|---|---|---|
| `VDP_NEGATIONS` | negation markers for the permissive rules | `not·`, `n't`, `never`, `cannot`, `can not`, `prohibit`, `forbid`, `no longer`, `unauthoriz`, `unauthoris`, `without our authoriz`, `without authoriz`, `without prior authoriz`, `without our permission`, `without permission`, `without prior permission`, `without written permission`, `without our written`, `without explicit`, `does not apply`, `no safe harbo`, `no legal safe harbo` |
| `VDP_SCOPE_QUALIFIERS` | a negated clause that limits scope is a scope statement, not a refusal | `outside`, `out of scope`, `out-of-scope`, `not listed`, `other than`, `beyond`, `not in accordance`, `not consistent with`, `inconsistent with`, `in violation`, `violat`, `do not follow`, `don't follow`, `not comply`, `fail to comply`, `not covered`, `excluded`, `third-party`, `third party`, `not owned` |
| `VDP_COORDINATION_QUALIFIERS` | a negated disclosure clause with a coordination window is coordinated disclosure, not a ban | `until`, `before`, `prior to`, `after`, `·once`, `within`, `·days`, `coordinat`, `unless` |
| `VDP_LEGAL_CONDITION_EXCLUSIONS` | legal action conditioned on not following the policy (or a "will not pursue" commitment) is not a contradiction | `will not pursue`, `will not take`, `will not initiate`, `won't pursue`, `won't take`, `not to pursue`, `do not follow`, `don't follow`, `not comply`, `fail to comply`, `failure to comply`, `violat`, `outside this policy`, `outside the scope`, `outside of this policy`, `not in accordance`, `not consistent with`, `inconsistent with`, `breach`, `not acting in good faith`, `bad faith` |
| `VDP_INTERSTITIAL_MARKERS` | a page under the word floor containing one of these is UNREADABLE, not TOO_SHORT | `enable javascript`, `javascript is required`, `javascript must be enabled`, `requires javascript`, `turn on javascript`, `javascript is disabled`, `loading...`, `loading…`, `please wait`, `checking your browser`, `just a moment`, `verify you are human`, `are you a robot`, `access denied`, `captcha` |

### Structural rules (`VDP_STRUCTURAL_RULES`)

These rules read security.txt fields, the outcome of the policy fetch, or dates. They do not match phrases.

| Rule id | Criterion | State | What it means |
|---|---|---|---|
| `VDP.DISCOVERABLE.STXT` | POLICY_DISCOVERABLE | MET | A policy was read from the URL in the security.txt Policy field. |
| `VDP.DISCOVERABLE.KNOWN` | POLICY_DISCOVERABLE | MET | A policy was read from the vendor’s registered policy URL (vendor domain or known disclosure platform). |
| `VDP.DISCOVERABLE.UNREADABLE` | POLICY_DISCOVERABLE | UNKNOWN | A policy URL is known but the fetch failed or the page had no readable text. |
| `VDP.DISCOVERABLE.NONE` | POLICY_DISCOVERABLE | NOT_MET | No policy was found in security.txt, the registry, or on the vendor domain. |
| `VDP.CONTACT.STXT` | SECURITY_CONTACT | MET | security.txt lists at least one Contact. |
| `VDP.CONTACT.NONE` | SECURITY_CONTACT | NOT_MET | No security.txt Contact and no security contact in the policy text. |
| `VDP.CONTACT.UNKNOWN` | SECURITY_CONTACT | UNKNOWN | No security.txt Contact, and the policy could not be read. |
| `VDP.REPORTING.STXT_ONLY` | REPORTING_CHANNEL | PARTIAL | The policy does not describe a channel, but security.txt lists a Contact. |
| `VDP.NO_POLICY` | TESTING_AUTHORIZED | NOT_MET | No policy exists: the pledge elements and scope are NOT_MET (applies to every text criterion). |
| `VDP.POLICY_UNREADABLE` | TESTING_AUTHORIZED | UNKNOWN | The policy could not be read: text criteria are UNKNOWN (applies to every text criterion). |
| `VDP.NO_MATCH` | TESTING_AUTHORIZED | NOT_MET | The policy was read and no rule for the criterion matched (applies to every text criterion). |
| `VDP.CURRENT.STXT` | CURRENT | MET | security.txt is present and its Expires date has not passed. |
| `VDP.CURRENT.POLICY_DATE` | CURRENT | MET | The policy states a last-updated date within the methodology window (vdpCurrentWithinDays). |
| `VDP.CURRENT.EXPIRED` | CURRENT | NOT_MET | security.txt Expires has passed and the policy states no recent update. |
| `VDP.CURRENT.EXPIRED_POLICY_RECENT` | CURRENT | PARTIAL | security.txt Expires has passed, but the policy states a recent update. |
| `VDP.CURRENT.POLICY_OLD` | CURRENT | NOT_MET | No valid security.txt, and the policy’s stated update is older than the window. |
| `VDP.CURRENT.STXT_CONTRADICTORY` | CURRENT | UNKNOWN | security.txt states several different Expires dates and the policy states no recent update. |
| `VDP.CURRENT.FUTURE_DATE` | CURRENT | UNKNOWN | The policy states a last-updated date after asOf: implausible, not counted. |
| `VDP.*.NEGATED` | TESTING_AUTHORIZED | CONTRADICTED | A permissive rule matched in a negated clause (e.g. "testing is never permitted"): recorded as prohibitive language (applies to every rule with negations). |
| `VDP.CURRENT.NONE` | CURRENT | NOT_MET | Neither security.txt nor a policy exists (both sources were read). |
| `VDP.CURRENT.UNDATED` | CURRENT | UNKNOWN | No security.txt Expires and no stated policy date: currency cannot be determined. |

14 phrase rules, 21 structural rules.

## 16. Methodology versioning

A published figure never changes without the methodology version changing. Every run records the methodology,
parser and scoring versions it used (`RunManifest`), and every evidence item carries the methodology version.

| Version | Released | Parser | Scoring | Change |
|---|---|---|---|---|
| 1.0.0 | 2025-09-15 | 1.0.0 | 1.0.0 | Initial methodology: VDP (8 criteria), CVE record quality (CNA-supplied CWE and CPE), CVE issuance timeliness, Goal 3 class-share signal. |
| 1.1.0 | 2026-06-15 | 1.0.0 | 1.1.0 | `NVD-CWE-noinfo` and `NVD-CWE-Other` (and the `CWE-noinfo` / `CWE-Other` forms) no longer count as a populated CWE. |

**Why 1.1.0.** A placeholder states that no weakness was identified, so it cannot satisfy "accurate CWE". Expected
effect: CWE coverage and complete-record figures fall for vendors that use placeholders.

**Why historical runs keep their figures.** A run is a methodology version applied to a fixed set of snapshots.
Changing the methodology does not reach back into earlier runs: a run made under 1.0.0 is reproduced with 1.0.0 from
its own published inputs (`touchstone reproduce <runId>`, `POST /api/runs/:id/reproduce`, or the browser's reproduce
action) and yields the same `outputsHash`. A figure that drops between a 1.0.0 run and a 1.1.0 run is a methodology
change, not a vendor change, and the history series carries the methodology version of every point.

**The methodology fingerprint.** `methodologyFingerprint` is the first 16 hex characters of a sha256 over the
version, every parameter, and the parser and scoring versions. It is part of both `inputsHash` and `outputsHash`. A
parameter edited in place without a version bump therefore changes the run id and both hashes, and the regression
suite (`tests/regression/methodology.test.ts`) pins each version's fingerprint and every published run's manifest, so
such an edit fails CI. The two parameters `vdpMinimumPolicyWords` and `minimumHighImpactAdvisories` were added to both
versions before the first release, in response to an adversarial review, and are pinned with them.

**Comparability.** `METRIC_CHANGES_BY_VERSION` lists the metrics whose formula a version changed (1.1.0:
`cve.cwe_coverage`, `cve.complete_records`). A historical value is compared with a current one (historical medians,
LATENCY_OUTLIER) only when no version between them changed that metric.

**Which version a dataset uses.** The demo build applies the latest methodology released on or before the dataset date
(`scripts/build-demo.ts`): 1.0.0 for 2025-10-06, 2026-01-06 and 2026-04-06; 1.1.0 for 2026-07-06 and 2026-10-06.

How to change the methodology is described in [CONTRIBUTING.md](../CONTRIBUTING.md#changing-the-methodology).

## 17. Disputes

Any finding can be challenged: a goal, a metric, an evidence item, a CVE attribution or an identity mapping. A
dispute overlays an observation; it never overwrites it. The full procedure is in [disputes.md](disputes.md). In short:

| From | Allowed next states (`DISPUTE_TRANSITIONS`) |
|---|---|
| OPEN | UNDER_REVIEW, DISMISSED |
| UNDER_REVIEW | CONFIRMED, CORRECTED, DISMISSED |
| CONFIRMED | (final: the original finding stands) |
| CORRECTED | (final: a later run carries the corrected result) |
| DISMISSED | (final) |

While a dispute is OPEN or UNDER_REVIEW, the affected goal is displayed as DISPUTED next to its original status.

## 18. Language rules

TOUCHSTONE writes about vendors in measurement language only.

- It never calls a vendor compliant, non-compliant, secure, insecure or failed, and never alleges a violation. The
  generated text (status reasons, anomaly headlines, benchmark wording, ranking notes) is scanned by quality check
  Q8 for the words in `BANNED_TERMS` (`assess/language.ts`): compliant, noncompliant, compliance, noncompliance,
  secure, insecure, insecurely, fail, fails, failed, failing, failure, violate, violates, violated, violation,
  violations. Matching is whole-word and case-insensitive, and hyphens separate words, so "non-compliant" is caught.
  "Secure by Design" as a proper name is allowed.
- It uses: "Evidence supports", "Evidence incomplete", "Not externally verifiable", "Observed deviation", "Observed
  change", "Above peer median on this observable metric", "Not comparable on this observable metric".
- It never produces a composite security score, a grade or a rank of vendors as more or less safe.
- Reports open with two positioning statements: TOUCHSTONE evaluates publicly available evidence and does not conduct
  intrusive testing of vendor infrastructure; a measurement describes observable evidence and should not be
  interpreted as a complete security assessment.

## 19. Limitations

See [limitations.md](limitations.md).
