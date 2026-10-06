# Challenging a finding

Every TOUCHSTONE figure points at evidence: the snapshot it was read from, the fields extracted, the quote, and the
rule that interpreted it. If any of that is wrong, file a dispute. Vendors, researchers and anyone else can file one.

## What can be disputed

| Target kind | Target id | Example |
|---|---|---|
| GOAL | `G1` to `G7` | "The Goal 5 status ignores our updated policy." |
| METRIC | a metric id, for example `cve.cpe_namespace_consistency` | "Our second CPE namespace is not registered." |
| EVIDENCE | an evidence id, `EV-` followed by hex | "This quote is from a page that is not our policy." |
| CVE | a CVE id | "This record is not ours; it belongs to another vendor." |
| IDENTITY | free text naming the alias or mapping | "This brand name belongs to our subsidiary, not to vendor X." |

Reasons:

| Reason | Use it when |
|---|---|
| INCORRECT_PRODUCT_MAPPING | A product or CPE namespace is mapped to the wrong vendor or is missing from the registry. |
| INCORRECT_VENDOR_ATTRIBUTION | A CVE record is attributed to (or excluded from) the wrong vendor. |
| INCORRECT_CVE_MAPPING | An advisory and a CVE are linked wrongly. |
| OUTDATED_SOURCE | The snapshot used is older than the current public document. |
| MISSING_SOURCE | A public source exists that TOUCHSTONE did not read (for example a CSAF feed). |
| METHODOLOGY_ERROR | The rule applied does not do what the methodology says, or the methodology is wrong. |

## How to file

- **Web app:** the Disputes page (`/app/disputes`) has a form for any target kind. A metric's "How was this
  calculated?" drawer and the vendor profile link to it with the vendor, run and target filled in. In the static demo
  site the dispute is saved in your browser only and labelled as such; nothing is sent anywhere.
- **API:** `POST /api/disputes` with a JSON body:

```json
{
  "vendorId": "northwind-systems",
  "runId": "TS-2026-10-06-3CC6",
  "target": { "kind": "METRIC", "id": "cve.cpe_namespace_consistency" },
  "reason": "INCORRECT_PRODUCT_MAPPING",
  "submitterRole": "VENDOR",
  "statement": "Records since the acquisition use our second namespace, northwind_sys.",
  "evidenceUrls": ["https://northwind.example/psirt/cpe-namespaces"]
}
```

Rules enforced by the API (`apps/api/src/app.ts`):

- `runId` is optional (the latest run is used); the vendor must be part of that run.
- The target must exist in that run for that vendor: a goal G1 to G7; a defined metric; an evidence item in the
  vendor's evidence; a CVE attributed to the vendor, or excluded with the vendor as a candidate; or, for IDENTITY, one
  of the vendor's names or aliases or an identity conflict that involves it. Anything else is refused with 422
  `UNKNOWN_TARGET` and the reason.
- `submitterRole` is VENDOR, RESEARCHER or OTHER. No name or e-mail address is collected.
- `statement`: 1 to 2000 characters after invisible, bidi and control characters are removed.
- `evidenceUrls`: at most 5 absolute `https://` URLs without credentials, each at most 500 characters. TOUCHSTONE stores
  and shows them; **the server never fetches them**.
- The body must be `application/json` and at most 32 KB. Submissions are limited to 10 per client per hour (IPv6
  clients by /64) and 200 accepted disputes per hour for the whole server.
- Everything you submit is public: `GET /api/disputes` returns it to anyone. Do not include personal data.

## What happens next

```
OPEN ──> UNDER_REVIEW ──> CONFIRMED   the original finding stands
  │           │
  │           ├────────> CORRECTED   a later run carries the corrected result
  │           │
  └───────────┴────────> DISMISSED
```

| From | Allowed next states |
|---|---|
| OPEN | UNDER_REVIEW, DISMISSED |
| UNDER_REVIEW | CONFIRMED, CORRECTED, DISMISSED |
| CONFIRMED, CORRECTED, DISMISSED | none (final) |

- A reviewer with the admin token moves a dispute with `POST /api/disputes/:id/transition`
  (`{ "to": "...", "note": "...", "actor": "..." }`). Every step needs a note, which is recorded.
- **CORRECTED** requires `correctedInRunId`: a published run **later** than the disputed one. The API refuses the
  disputed run itself or an earlier one.
- While a dispute is OPEN or UNDER_REVIEW, the affected goals of that run and every later run are shown as **DISPUTED**,
  with the original status still visible next to it (`GET /api/vendors/:id/goals` returns both `originalStatus` and
  `displayState`). A dispute on a metric, evidence item or CVE marks the goals that use it; an IDENTITY dispute marks the
  goals with CVE or Goal 3 metrics.
- A correction is made the only way a figure can change: by fixing the registry, the source or the methodology and
  producing a new run. A methodology fix means a new methodology version (see [CONTRIBUTING.md](../CONTRIBUTING.md)).

## What never happens

- **An observation is never overwritten.** Published runs are files built from their inputs; the API has no write path
  to them. The disputed run keeps its figures forever and can still be reproduced byte for byte.
- **History is append-only.** Dispute events cannot be edited or deleted, disputes cannot be deleted, only the status
  column can change, and it must equal the latest event's target state. These rules are SQLite triggers
  (`apps/api/src/store.ts`), so they hold even for code that bypasses the API's checks.
- **No illegal jump.** An event must start from the dispute's current status, and the step must be one of the allowed
  transitions. The database refuses anything else.
- **A dispute is not a verdict.** DISPUTED is a display overlay, not a new status. A dismissed dispute leaves the finding
  as it was.
- **No silent fixes.** A corrected figure appears in a later run, linked from the dispute by `correctedInRunId`.

## The demo disputes

The demo bundle seeds four synthetic disputes (`apps/web/public/data/disputes.json`, written by
`scripts/build-demo.ts`), one per workflow outcome: an OPEN attribution dispute, an UNDER_REVIEW outdated-source
dispute, a CORRECTED product-mapping dispute whose correction appears in the following run, and a DISMISSED methodology
dispute asking for third-party enrichment to be credited. They are replayed through the same database triggers when the
API starts, and are marked synthetic.
