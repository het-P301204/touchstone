# TOUCHSTONE limitations

TOUCHSTONE measures what public sources show. That boundary is the point of the project, and it is also its main
limitation. Read every figure with the following in mind.

## What public evidence cannot show

- **Four of the seven pledge goals cannot be measured from outside** (G1 MFA, G2 default passwords, G4 patch
  installation, G7 intrusion evidence). They are labelled NOT_EXTERNALLY_VERIFIABLE. That label says nothing about the
  vendor's progress; it says what a third party can check.
- **A policy is not a practice.** TOUCHSTONE reads a vulnerability disclosure policy. It does not test whether the vendor
  honours safe harbor, answers reports, or allows disclosure in practice.
- **Disclosed vulnerabilities only.** A vulnerability that was never disclosed, or fixed before release, cannot be
  counted. Goal 3's class-share signal describes the disclosed mix; disclosure volume, product mix and CWE assignment
  practice move it without any change in prevalence. Goal 3 is therefore never VERIFIED.
- **No testing.** TOUCHSTONE does no scanning, probing or testing of vendor products or infrastructure, so anything that
  would need it (default credentials, patch uptake, logging defaults) is out of reach.
- **Not a security assessment.** A figure describes observable evidence for one commitment. It is not a rating of a
  vendor's security, and there is deliberately no composite score.

## Measurement limits

- **Phrase rules can miss or misread wording.** VDP criteria are decided by documented phrase rules over sentences
  (methodology section 15). A clause-level negation model turns negated permissions into contradictions and leaves
  scope and coordination limits alone, but it works on word lists: unusual wording, negation far from the matched
  phrase, or a qualifier used in an unexpected sense can still be misread. Every determination carries its quote and
  rule id so it can be checked and disputed.
- **Pages that need a browser.** A policy rendered by JavaScript, or behind an interstitial or bot check, yields little
  or no readable text. Such a page is UNREADABLE when it is nearly empty or carries a known interstitial marker, and
  Goal 5 is then DATA_ERROR; a short page without a marker is TOO_SHORT and Goal 5 is at most PARTIAL. The 80-word floor
  is a plausibility heuristic, not a test of what a valid policy is.
- **Only CNA-supplied fields count.** A record completed by CISA-ADP or another enricher is not credited to the vendor.
  That is the intended reading of the pledge ("the manufacturer's" records), but it means aggregator views (for example
  NVD) can look more complete than TOUCHSTONE's figure. Enrichment is reported separately as `cve.enriched_only`.
- **"Accurate" is checked for form, not truth.** TOUCHSTONE checks that a CWE is a real identifier (not a placeholder)
  and that a CPE is well-formed and in the vendor's registered namespace. It does not check that the CWE is the right
  weakness or that the CPE names the right product.
- **CPE namespaces are a registry decision.** A vendor's CNA may write CPEs under one vendor string (for example a
  legal-entity form such as `<name>_ab`) while the NVD CPE dictionary uses another (`<name>`). Which strings count for
  `cve.cpe_namespace_consistency` and `cve.complete_records` depends on the CPE_VENDOR aliases the registry lists, each
  carried with evidence and a confidence and open to dispute. TOUCHSTONE does not validate CNA CPEs against the official
  CPE dictionary yet.
- **Timeliness needs a machine-readable advisory feed.** Without CSAF, timeliness is not measured (NOT_VERIFIED, never
  zero). Severity is what the advisory states; a vendor that under-rates an advisory removes it from the denominator.
  The 1-day tolerance is a TOUCHSTONE parameter, not a CISA threshold.
- **Dates are taken as the sources state them.** CVE `datePublished`, advisory release dates, a policy's "Last updated"
  and security.txt `Expires` cannot be verified independently.
- **Small samples.** CVE record metrics need at least 5 eligible records, Goal 3 at least 10 records per 12-month
  period. Below that the value is withheld (BELOW_MINIMUM_SAMPLE), so small vendors often have no figure. Timeliness
  is shown from a single advisory, but below 5 high-impact advisories it carries LOW confidence and cannot be VERIFIED.
- **Windows.** CVE records and advisories count when published in the 730 days before the analysis date; older
  practice is not reflected.

## Identity and attribution limits

- **Attribution depends on a hand-maintained registry.** Aliases (CNA names and ids, affected-vendor strings, CPE
  namespaces, signer listings) are curated with evidence. A missing alias leaves records unattributed; a wrong one
  attributes them to the wrong vendor until disputed.
- **Ambiguous and conflicting records are excluded, not resolved.** Records that fit more than one vendor, or depend on
  a name registered for two vendors, are set aside and listed, which can shrink a vendor's sample.
- **A CNA assigning for another vendor's product.** When a record's assigner is one vendor's CNA but its affected
  vendor or CPE names a different registered vendor, the record is excluded as ambiguous rather than given to either.
  This is safe but shrinks both vendors' samples until the registry or a dispute settles it.
- **Shared disclosure platforms.** A program page on a platform such as HackerOne or Bugcrowd counts as the vendor's
  policy only when the registry's `vdpPolicyUrl` points at it. A real program the registry does not list is skipped.
- **Signer matching is exact.** A signer page name that differs from every registered SIGNATORY_LISTING alias (after
  normalization) leaves the vendor NOT_LISTED.

## Operational limits

- **Live collection is young.** The collectors are tested with a fake transport and recorded real documents, and one end
  to end live collection against real sources has been run (see [data-sources.md](data-sources.md)). A vendor CSAF feed
  has not yet been collected live. Live runs are reviewed offline and not published automatically.
- **Live runs have no history.** The live collector does not supply previous VDP observations or earlier figures, so VDP
  change detection, historical medians and the latency-outlier rule only work where history is supplied (the demo
  pipeline).
- **Freshness is relative to the analysis date**, not to when someone reads a published run.
- **Policy pages cannot be re-examined in full.** The raw HTML is not kept; only its hash and the extracted text (on
  the collecting machine) remain, so a question about the original markup cannot be answered later.
- **Disputes are public and unmoderated**, and an open dispute marks the affected goals as DISPUTED until a reviewer
  acts. The admin surface uses a single shared token.
- **Single-tenant, single-process.** Rate limits are in memory per process; one refresh job runs at a time.

## Demo data

The bundled dataset is synthetic: fictional vendors, `.example` URLs, `DEMO-` record ids. Its figures illustrate the
method and its edge cases and say nothing about any real company. See [demo-data.md](demo-data.md).

## Known issues

Defects found in review are recorded as tests before they are fixed: `DEFECT ...` tests in `tests/adversarial/` and
`FINDING ...` tests in `tests/security/`. While such a test fails, the defect is open; once fixed it stays as a
regression test. Run `npm test` to see the current state.
