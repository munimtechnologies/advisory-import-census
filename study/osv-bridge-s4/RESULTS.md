# S4 results: does OSV.dev link the CVEs that GitHub's CVE lookup misses?

Graded 2026-11-01 (UTC) against the frozen pre-registration in [PREREG.md](PREREG.md). No prediction was hand-graded.
Licence: Apache-2.0 (code), CC BY 4.0 (text and data). Made with AI agents working for MV2 of Munim, Inc.

Inputs: S3 `pairs.csv` (648 rows, sha256 `3ebc5676...2a01ab7`) and S2 `pairs.csv` (96 rows, sha256 `5ec1174d...c75b41c`).
OSV.dev queried 2026-11-01 between 05:02:22Z and 05:07:26Z, with 0 errors. The job's own table is in
[RESULTS-job.md](RESULTS-job.md); per-pair rows are in [rows.csv](rows.csv) and [results.json](results.json).

| Prediction | Claim (frozen) | Value | Held |
|---|---|---|---|
| Q1 | >= 90% of S3 pairs: OSV's record of the reviewed GHSA lists the twin's CVE in `aliases` | 614 of 648 (94.8%) | **yes** |
| Q2 | >= 90% of S3 pairs: OSV's record of the CVE is or names the reviewed GHSA | 619 of 648 (95.5%) | **yes** |
| Q3 | <= 20% of S2 pairs: OSV's record of the hidden GHSA names the CVE | 18 of 96 (18.8%) | **yes** |
| Q4 | <= 20% of S2 pairs: OSV's record of the CVE is or names the hidden GHSA | 18 of 96 (18.8%) | **yes** |

**All 4 held.**

## What it means

- **The late-CVE gap (S3) is specific to GitHub's API.** For 619 of the 648 reviewed advisories whose CVE sits only on
  a packageless unreviewed twin, OSV.dev connects the CVE and the reviewed advisory. A scanner that asks OSV.dev about
  the CVE gets the affected package. One that asks `GET /advisories?cve_id=` gets only the packageless twin. In 29 pairs
  OSV.dev has no record of the CVE at all.
- **The CVE-reuse gap (S2) persists on OSV.dev.** For 78 of 96 advisories that point to a CVE held by another reviewed
  advisory, neither OSV.dev record names the other. A CVE lookup misses those packages on both services. 7 of the 96 S2
  CVEs have no OSV.dev record.
- No OSV.dev record of these CVEs named an ecosystem package of its own (0 in both studies).

## Limits

One reading of OSV.dev; the S2 and S3 pairs are frozen at their own commits and were not re-checked against GitHub.
"Links" means the IDs are connected; it doesn't check that OSV.dev's version ranges are right, and it doesn't explain
why a link exists.
