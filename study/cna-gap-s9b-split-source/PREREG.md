# S9b (pre-registered): CVEs whose record names one GitHub advisory as its source but links another

Pre-registered 2026-11-06 UTC, before any of the data below was read in bulk. Code: `split_source.py`
(Apache-2.0), offline tests: `test_split_source.py`. Text CC BY 4.0. Made with AI agents working for MV2 of
Munim, Inc.

## Why

Every CVE record that GitHub's CNA (`GitHub_M`) publishes carries a `containers.cna.source.advisory` field naming
the repository advisory (GHSA) the CVE was requested from, and normally the same GHSA is the record's advisory
reference. S8's alias-gap list has ten CVEs that cite a global advisory holding a different CVE; nine of them sit
under two umbrella advisories. Reading four of those nine records by hand on 2026-11-06, we found that in each the
two fields differ:

| CVE | CVSS | `source.advisory` | Only advisory reference | Global advisory lists |
|---|---|---|---|---|
| CVE-2026-95842 .. CVE-2026-95848 (7 CVEs, Moquette) | 8.7 (95842), 9.3 (95848) | GHSA-pqwr-fmcp-mjq7 (95842), GHSA-h285-r7h3-gfjg (95848); the other five not yet read | GHSA-5f42-97gr-vfhq | CVE-2026-85724 only |
| CVE-2026-92284, CVE-2026-92700 (Caddy) | 6.9, 6.3 | GHSA-5wr5-c398-ph72, GHSA-xvgq-2cgx-86qq | GHSA-j8px-rmrx-76h9 | CVE-2026-77281 only |

The one source advisory we requested (GHSA-h285-r7h3-gfjg, at the Moquette repository) returns 404 to the public, and `GET /advisories?cve_id=` for
CVE-2026-95848 (CVSS 9.3) returns `[]`. So a CVE lookup in GitHub's Advisory Database, and in every scanner that
relies on it, finds nothing for these CVEs, even though the umbrella advisory describing them is in the database.

Prior art (searched 2026-11-06): github/advisory-database #10224 asks for one CVE to be linked to several GHSAs (the
reverse case); #8479, #10735 and our S8-alias note cover single missing aliases. We found no count of records whose
CNA source advisory differs from the advisory they link.

## Population and classes

Population: the 13,769 rows of S8's `cves.csv` (CVEs whose NVD source is GitHub's CNA, published in NVD
2025-01-01..2026-09-30, not rejected). For each CVE the job reads `https://cveawg.mitre.org/api/cve/<CVE>` once
(4 parallel readers, retries) and classifies it:

- **MATCH**: `source.advisory` is a GHSA that is also cited in a `github.com/<owner>/<repo>/security/advisories/`
  reference.
- **SPLIT**: `source.advisory` is a GHSA, the record cites at least one repository advisory, and none of them is it.
  The first cited repository advisory is the "umbrella".
- **NO_REF** (GHSA source, no repository-advisory reference), **NO_SOURCE** (no GHSA in `source.advisory`),
  **NOT_PUBLISHED**, **NO_RECORD** (404), **FETCH_ERROR**.

Global-database facts come from the same local github/advisory-database clone S8 used (github-reviewed plus
unreviewed 2025-2026, not pulled, HEAD as reported by the job). `split_bundle` = how many SPLIT CVEs share an
umbrella. A seeded sample (seed 20261106) of 10 distinct SPLIT source advisories is requested once at
`github.com/<umbrella owner>/<umbrella repo>/security/advisories/<source GHSA>` and its HTTP status recorded
(descriptive only).

## Gate (predictions are not graded unless all pass)

1. 13,769 population rows; 2. at least 98% of them read (anything but FETCH_ERROR); 3. known cases: CVE-2026-95842,
CVE-2026-95848, CVE-2026-92284 and CVE-2026-92700 are SPLIT and CVE-2026-57234 is MATCH (all checked by hand on
2026-11-06). If the gate fails, the code or the data path is wrong: fix it and re-run, never the predictions.

## Frozen predictions

- **P1**: SPLIT CVEs are between 0.2% and 3% of population CVEs whose record was read.
- **P2**: at least 95% of MATCH+SPLIT CVEs are MATCH.
- **P3**: at least 90% of SPLIT CVEs name a source advisory that is absent from the global database clone.
- **P4**: at least 70% of SPLIT CVEs had no live global advisory in S8 (coverage NONE or WITHDRAWN_ONLY).
- **P5**: at least 60% of SPLIT CVEs share their umbrella with at least one other SPLIT CVE.
- **P6**: at least 80% of SPLIT CVEs whose umbrella is a live global advisory are not in that advisory's aliases.

Reported but not predicted: class counts, umbrellas, bundle sizes, SPLIT CVEs by NVD month, top umbrella repos,
the umbrellas' own MATCH CVEs, the sample's HTTP statuses.

## Limits

CVE records are read live in November 2026, while the clone dates from 2026-11-05; a CNA may have edited a record
since S8. The class says nothing about why a record was split (a maintainer merging advisories, or the CNA editing
references); the sample only shows whether the source advisory is public. No one is contacted on the basis of these
numbers until RESULTS.md is written and hand-checked.
