# Pre-registration S4: does OSV.dev link the CVEs that GitHub's CVE lookup misses?

Written 2026-10-31 (UTC), before any data for this study was collected. Code: `osv_bridge.py`
(tests: `test_osv_bridge.py`). Licence: Apache-2.0 (code), CC BY 4.0 (text and results).
Made with AI agents working for MV2 of Munim, Inc.

## Background

- S3 ([study/late-cve-s3/RESULTS.md](../late-cve-s3/RESULTS.md)) found 648 pairs where a live reviewed
  GHSA has no CVE alias and its CVE sits only on an unreviewed twin that lists no package. GitHub's
  `GET /advisories?cve_id=` returns only the twin.
- S2 ([study/cve-lookup-s2/RESULTS.md](../cve-lookup-s2/RESULTS.md)) found 96 pairs where a live reviewed
  GHSA links to a CVE that another reviewed GHSA holds, so the lookup returns only the holder.
- **Known before the data (exploratory spot checks on 2026-10-31):** for two S3 pairs (Open WebUI
  GHSA-6xcp-7mpr-m7wm / CVE-2026-56400, and Kyverno GHSA-459x-q9hg-4gpq / CVE-2025-15613), OSV.dev's
  GHSA record lists the CVE in `aliases`. OSV's record for CVE-2026-56400 aliases GHSA-6xcp-7mpr-m7wm.
  No S2 pair was checked on OSV.dev.
- Prior art searched 2026-10-31: AppThreat vulnerability-db PRs #283/#285 (OSV.dev rewrites each
  record's aliases to the whole alias group; measured for GHSAs with 2+ CVE aliases); comparison blog
  posts on OSV, NVD and GHSA. None measures whether OSV.dev bridges the specific GitHub lookup gaps
  found in S2 and S3.

## Data

1. `study/late-cve-s3/pairs.csv` (must have exactly 648 rows) and `study/cve-lookup-s2/pairs.csv`
   (exactly 96 rows) from this repository's main branch. The SHA-256 of each is recorded.
2. `GET https://api.osv.dev/v1/vulns/{id}` for each GHSA and each CVE in those pairs, once per id.

No GitHub REST calls.

## Definitions

- **GHSA lists CVE (S3):** OSV's record of the reviewed GHSA has the CVE in `aliases`.
- **GHSA names CVE (S2):** OSV's record of the hidden GHSA has the CVE in `aliases`, `related` or `upstream`.
- **CVE links GHSA:** OSV's record fetched for the CVE ID has that GHSA as its `id` or in `aliases`,
  `related` or `upstream`.
- A pair whose GHSA or CVE lookup still fails after 3 tries (not a 404) is an **error** and is
  left out of the denominator. A 404 counts as "does not link".

## Predictions (frozen)

- **Q1.** For at least 90% of S3 pairs, OSV's GHSA record lists the CVE.
- **Q2.** For at least 90% of S3 pairs, the CVE links to the GHSA.
- **Q3.** For at most 20% of S2 pairs, OSV's GHSA record names the CVE.
- **Q4.** For at most 20% of S2 pairs, the CVE links to the GHSA.

Any prediction is INCONCLUSIVE_ERRORS if more than 5% of its pairs are errors, or if it has no
pairs. No prediction is graded by hand; the job prints only "done".

Reported without predictions: for each study, pairs linked in either or neither direction, GHSAs and
CVEs that OSV.dev doesn't have, and CVE records that name an ecosystem package.

## Known limits (stated before results)

- OSV.dev at one point in time; GitHub may have changed since the S2/S3 commits. The S3 and S2
  pairs are frozen at their own commits and are not re-checked against GitHub.
- "Links" means the IDs are connected. It doesn't check that OSV's package ranges are right.
- OSV.dev's alias grouping is not documented here, and this doesn't explain why a link exists.
