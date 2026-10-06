# Real-format fixtures: provenance

Small, unmodified public documents used to test the normalizers against real data. Each was fetched once, as a
single document, with an identifying User-Agent. Nothing was scanned or probed. The sha256 is of the file as
committed (byte-identical to the response body).

| File | Source URL | Fetched | sha256 | Why it is here |
|---|---|---|---|---|
| `cisa-signers-2026-10-06.html` | https://www.cisa.gov/securebydesign/pledge/secure-design-pledge-signers | 2026-10-06 | `c40746d85f0019f183c8e89050f185af1f1bb2547fd972a41727b787008f9ed5` | Signer list: "387 Companies" heading, 387 names in a 7-column table, `&nbsp;` padding cells and trailing `&nbsp;` in names |
| `CVE-2024-21412.json` | https://cveawg.mitre.org/api/cve/CVE-2024-21412 | 2026-10-06 | `e0c4facccad7a91b9473068ca1ce15d70d673c5df9b299d5c15d063b3a556a93` | CVE JSON 5.2, vendor CNA (microsoft), CNA CPEs via `cpeApplicability`, CNA CWE, CISA-ADP (SSVC/KEV, no CWE) and CVE Program containers |
| `CVE-2024-3094.json` | https://cveawg.mitre.org/api/cve/CVE-2024-3094 | 2026-10-06 | `f9a8e892f8d23a0289a6002fd1b6a5d6c2c60aeba536c6ee20a673751f902095` | CNA (redhat) CPEs in `affected[].cpes`, written as CPE 2.2 URIs (`cpe:/o:redhat:...`): present but not CPE 2.3, so MALFORMED for the pledge metric |
| `CVE-2024-23897.json` | https://cveawg.mitre.org/api/cve/CVE-2024-23897 | 2026-10-06 | `abac2e7624d0d655c99a4bcd244c9c074f2e025124ef17feb9e03641897b98b2` | CNA (jenkins) supplies no CWE and no CPE; CISA-ADP adds CWE-27 and CPE 2.3 names: the "enriched only" case |
| `CVE-2022-0001.json` | https://cveawg.mitre.org/api/cve/CVE-2022-0001 | 2026-10-06 | `ca835ca4331ce806df6378981153d68928e6f4a6e1abcd8344f20fc9134f8952` | CNA (intel) problem type is free text (`type: "text"`, "information disclosure"): no CWE statement, so NOT_PROVIDED. The CISA-ADP container states the placeholder "CWE-noinfo Not enough information" |
| `CVE-2022-0003.json` | https://cveawg.mitre.org/api/cve/CVE-2022-0003 | 2026-10-06 | `762ad6334d75d469b4ce41d3e1ec4a182181ea032d50efd1fa009c5e6b46882f` | REJECTED record (`rejectedReasons`, no affected) |
| `cisa-security-2026-10-06.txt` | https://www.cisa.gov/.well-known/security.txt (301 to https://www.cisa.gov/sites/default/files/security.txt) | 2026-10-06 | `df33aa200a68c7cbd6202c99f2dd660e9a24591cf89a231fca533c9866aef0b7` | Real RFC 9116 file: two Contacts, Expires, CSAF field, no Policy and no Canonical; served through a redirect |
| `siemens-csaf-ssa-823812.json` | https://cert-portal.siemens.com/productcert/csaf/ssa-823812.json | 2026-10-06 | `db923d3c474b1b2f354ca34fc4a5acc614de9ca2319cecee519f57ed50c266b8` | CSAF 2.0 advisory from a public provider feed; no `aggregate_severity`, so severity comes from the CVSS v3 score (MEDIUM) |

A real placeholder CWE appears in the CISA-ADP container of `CVE-2022-0001.json` ("CWE-noinfo Not enough
information"). A real CNA container stating `NVD-CWE-noinfo` was not found among the records fetched; that case is
covered by unit tests and by the synthetic `lanternfish-security` vendor in `fixtures/demo`.

Licensing: CVE records are used under the CVE Program terms of use; the CISA pages are U.S. government works;
the Siemens advisory is published under the terms stated in its `document.distribution` and `notes`. The files
are kept unmodified so the sha256 values can be re-checked against the source.
