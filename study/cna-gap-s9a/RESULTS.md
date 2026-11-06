# S9a results: do late GitHub-CNA CVEs reach the reviewed advisory they cite?

Part of [advisory-import-census](../../README.md). Code Apache-2.0; data CC BY 4.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

Graded 2026-11-06 (UTC) against the frozen [PREREG.md](PREREG.md). Job output: [RESULTS-job.md](RESULTS-job.md),
[results.json](results.json), per-CVE table [rows.csv](rows.csv). Run 2026-11-06T13:11:07Z on the
github/advisory-database clone at commit 9f58b825 (2026-10-30T15:42:09Z) and S8's `cves.csv`
(sha256 4088acc7...481ae58).

## Gate

PASSED: 13,769 rows, 7,699 REVIEWED and 78 GLOBAL_WITHOUT_ALIAS (matching S8), and 65 eligible MISSING rows (the
allowed range was 62-68, matching S8-alias's 65).

## Predictions: 4 of 6 held

| ID | Prediction | Result | Held |
|---|---|---|---|
| P1 | At most 10% of eligible late CVEs are MISSING | 64 of 3,685 (1.74%) | yes |
| P2 | At least 30% of eligible late CVEs whose advisory was published 2026-06-18/19 are MISSING | 41 of 202 (20.3%) | no |
| P3 | At most 3% of eligible late CVEs whose advisory was published outside 2026-06-01..07-31 are MISSING | 6 of 2,545 (0.24%) | yes |
| P4 | MISSING rate for lag >= 30 days is higher than for lag 1-29 days | 3.75% (25/666) vs 1.29% (39/3,019) | yes |
| P5 | Late CVEs are 2-20% of eligible CVEs | 3,685 of 7,703 (47.84%) | no |
| P6 | At least 50% of eligible late LISTED CVEs sit in an advisory modified on or after the CVE's NVD date | 2,644 of 3,621 (73.02%) | yes |

## What the numbers show (descriptive)

- **Overall:** 65 of 7,703 eligible CVEs (0.84%) are missing from the reviewed advisory they cite. 64 of the 65 are
  late (CVE published in NVD at least a day after the advisory); for CVEs not late the rate is 1 of 4,018 (0.02%).
- **By when the advisory was published:** June 2026 advisories 47 of 717 late CVEs missing (6.6%), July 2026 11 of
  423 (2.6%), every other month together 6 of 2,545 (0.24%). For advisories published on 18-19 June it is 41 of 202
  (20.3%): high, but below the 30% predicted (P2).
- **By lag:** 1-6 days 0.61% (11/1,799), 7-29 days 2.3% (28/1,220), 30-89 days 3.62% (23/636), 90+ days 6.67% (2/30).
- **P5 was wrong by a wide margin:** almost half of eligible CVEs are published in NVD at least a day after the
  advisory. The prediction assumed CVE publication usually coincides with advisory publication. It does not.

## Hand checks (live, 2026-11-06 ~15:00 UTC)

Eight rows, read on api.github.com and cveawg.mitre.org. All eight match the job's labels.

| CVE | Advisory | Job label | Live advisory | Note |
|---|---|---|---|---|
| CVE-2026-48068 | GHSA-5375-pq7m-f5r2 (grpc-node) | LISTS_THIS, lag 33 | cve_id CVE-2026-48068 | updated_at 3 s after published |
| CVE-2026-48113 | GHSA-24fp-5v3p-rvpw (chisel) | LISTS_THIS, lag 52 | cve_id CVE-2026-48113 | updated_at = published; CVE reserved 2026-05-20, before review |
| CVE-2026-48170 | GHSA-9m6g-wc8r-q59c (scim-patch) | LISTS_THIS, lag 46 | cve_id CVE-2026-48170 | updated_at 1 s after published |
| CVE-2026-54898 | GHSA-q2gm-54r6-8fwm (oj) | LISTS_THIS, lag 12 | cve_id CVE-2026-54898 | updated_at 3 s after published |
| CVE-2026-54899 | GHSA-2cw7-v8ff-p88r (oj) | LISTS_THIS, lag 12 | cve_id CVE-2026-54899 | modified 2026-10-06; CVE reserved 2026-06-16, before review |
| CVE-2026-57204 | GHSA-jm82-fx9c-mx94 (pypdf) | LISTS_NONE | cve_id null | CVE reserved 2026-06-24, after the 06-18 review |
| CVE-2026-48019 | GHSA-5vg9-5847-vvmq (laravel/framework) | LISTS_NONE | cve_id null | CVE reserved 2026-05-20, before review; CNA source.advisory is GHSA-fpqx-6722-p65v |
| CVE-2025-55300 | GHSA-q355-h244-969h (komari) | LISTS_NONE | cve_id null | CVE reserved 2025-08-12 16:15, after the 00:13 review |

The five LISTED rows were taken from the first matches of a text search over rows.csv, not drawn at random.

## What this does and does not show

- **The PREREG's reading of P1 ("adding the alias after review usually works") is not supported by these data,
  even though P1's number held.** In 4 of the 5 checked listed advisories the file had not changed since review: the
  CVE ID was already written in at review time, while the CVE was still RESERVED. "Late but listed" therefore
  mostly measures IDs reserved before review, not aliases added afterwards. P6's 73% counts files touched after
  the CVE date for any reason.
- The question that matters to curators (when a CVE ID is reserved only after review, how often is the alias added?)
  is the subject of the pre-registered follow-up [S9c](../cna-gap-s9c-reserve-timing/PREREG.md), which reads each
  late CVE's `dateReserved`.
- One of the three checked missing CVEs (laravel's CVE-2026-48019) names a different repository advisory as its CNA
  source than the one it links. That is the pattern S9b counts
  ([PREREG](../cna-gap-s9b-split-source/PREREG.md)); S9c's Q6 tests how common it is among missing CVEs.
- One snapshot (clone of 2026-10-30). Fixes since then are not counted, including MV2's alias pull request
  [github/advisory-database#10920](https://github.com/github/advisory-database/pull/10920) (nokogiri,
  CVE-2026-57234), which was still open when this was graded.
- Descriptive only. Nothing here says why an alias is missing; GitHub's curation process is not visible from outside.
