# S8 follow-up: reviewed advisories that lack the CVE GitHub's own CNA issued for them

Part of [advisory-import-census](../../README.md). Code Apache-2.0; data CC BY 4.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

**Descriptive, not pre-registered.** Five rows were looked at by hand before the code was written, so nothing
here is a graded prediction.

## Question

Study S8 ([RESULTS.md](../cna-gap-s8/RESULTS.md)) found 6,064 of 13,769 CVEs published by GitHub's CNA
(`GitHub_M`, 2025-01..2026-09) with no live advisory in the global GitHub Advisory Database. 78 of them were of
kind `GLOBAL_WITHOUT_ALIAS`: the CVE record cites a repository advisory that *is* a global advisory, yet that
global advisory does not list the CVE. Why?

## Method

`alias_gap.py` reads each of the 78 rows (`gwa_rows.csv`, copied from S8's `uncovered.csv`), opens the cited
advisory's JSON in a clone of github/advisory-database (HEAD `9f58b825cb0cc6baa792ddb37e7c227a5d525395`) and the
CVE record from CVE Services (cveawg.mitre.org, read 2026-11-05T20:53Z), and sorts it:

| Kind | Meaning | Rows |
|---|---|---|
| MISSING_ALIAS | cited advisory is live and lists no CVE at all | **65** |
| HOLDS_OTHER_CVE | cited advisory lists a different CVE (bundled or related advisories: moquette x7, caddy x2, Git Credential Manager x1) | 10 |
| WITHDRAWN_ADVISORY | cited advisory is withdrawn (Emby, ImageMagick, diffusers) | 3 |
| ADVISORY_NOT_FOUND | cited advisory not in the clone | 0 |

A row is a **candidate for a one-line alias fix** when it is MISSING_ALIAS, the CVE record is PUBLISHED by
`GitHub_M`, the record cites exactly one repository advisory (this one), and no other uncovered CVE cites the
same advisory. **All 65 MISSING_ALIAS rows are candidates.** Per-row data: [alias_gap.csv](alias_gap.csv).

## Results

- **65 GitHub-reviewed advisories lack the CVE ID that GitHub's own CNA published for that same advisory**, so a
  lookup by CVE (`GET /advisories?cve_id=...`, Dependabot or scanners matching on CVE) finds nothing, even though
  the advisory is reviewed and has package data.
- **In 63 of 65 the CVE record was published at least a day after the global advisory** (median gap over all
  65: 19 days). The other two: minder GHSA-6xvf-4vh9-mw47 (CVE published just under 24 hours after the
  advisory) and quinn-proto GHSA-4w2j-m93h-cj5j (advisory published about 19 hours after the CVE, still
  without it).
- **41 of the 65 global advisories were published as reviewed on 2026-06-18 or 2026-06-19**, one more on
  06-17 and five on 06-26/27; 12 in July 2026; 6 elsewhere (the oldest, pycares GHSA-5qpg-rh4j-qp35, has
  lacked CVE-2025-48945 since June 2025).
- Ecosystems: npm 22, PyPI 16, RubyGems 12, Go 10, Packagist 2, GitHub Actions 1, Maven 1, crates.io 1.
- Projects include nokogiri (8 advisories), Network-AI (5), pnpm (3), hugo (3), crawl4ai (3), Budibase (3),
  parse-server (2), mcp-atlassian (2), nezha (2), mcp-searxng (2), pydantic-settings, pypdf, msgpack-python,
  langsmith-sdk, loofah, kin-openapi, laravel/framework, coder, python-zeep, anki, quinn-proto and others.
- The CVE title equals the advisory summary in 33 of 65; the rest differ only in wording.

**Live spot check, 2026-11-06 ~03:00Z:** `GET /advisories/<GHSA>` still shows `cve_id: null` for nokogiri
GHSA-8678-w3jw-xfc2 (CVE-2026-57234), pycares GHSA-5qpg-rh4j-qp35 (CVE-2025-48945), quinn-proto
GHSA-4w2j-m93h-cj5j (CVE-2026-25800) and pnpm GHSA-72r4-9c5j-mj57 (CVE-2026-59194): 4 of 4.

## What it suggests (not tested)

The timing fits a sync gap: a repository advisory is reviewed into the global database while its CVE request is
still pending, and the CVE published days later is not written back to the global record. The 18-19 June
cluster looks like one review batch. This is a hypothesis from the dates only; GitHub's process is not public.

Precedent that a fix is welcome: github/advisory-database #10735 / PR #10686 (one missing alias, applied by the
curators after a community PR in October 2026).

## Limits

- Only CVEs that S8 counted (GitHub-CNA CVEs in NVD, published 2025-01-01..2026-09-30) and only the 78
  `GLOBAL_WITHOUT_ALIAS` rows; the same gap may exist for CVEs published since, or for advisories whose CVE
  record does not cite the repository advisory.
- The clone was not re-synced for this job; the live check covers 4 of 65 rows.
- Nothing here says the advisories are wrong, only that their CVE alias is missing.

## Files

`alias_gap.py` (stdlib only), `test_alias_gap.py` (16 offline tests, passed in the job), `gwa_rows.csv` (input),
`alias_gap.csv`, `summary.json`, `ALIAS-GAP.md` (job outputs, job `s8-alias-v1`, 2026-11-05).

Run: `python alias_gap.py --rows gwa_rows.csv --db-root <advisory-database clone> --out-dir out`
