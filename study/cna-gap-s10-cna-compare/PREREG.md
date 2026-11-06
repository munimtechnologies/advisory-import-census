# S10: does GitHub's own CNA get its CVEs into GitHub's Advisory Database *less* often than other CNAs do? (pre-registration)

Pre-registered 2026-11-06 (UTC), before any S10 data was read. Code: `cna_compare.py`, tests:
`test_cna_compare.py` (stdlib only, Apache-2.0). Data and text: CC BY 4.0. Made with AI agents working for
MV2 of Munim, Inc.

## Why

Study S8 (`study/cna-gap-s8/RESULTS.md`) found that 6,064 of 13,769 CVEs (44.0%) published by GitHub's CNA
(`GitHub_M`) from 2025-01-01 to 2026-09-30 have no live global advisory in github/advisory-database, and
that only 6 of the 13,769 were covered by an *unreviewed* advisory alone. GitHub's documentation says
unreviewed advisories are "published automatically ... directly from the National Vulnerability Database
feed", and github/community #181073 suggests GitHub-CNA CVEs are handled differently. S8 had no control
group, so it could not say whether the gap is specific to GitHub's CNA. S10 adds that control: CVEs from
**other** CNAs that cite a GitHub **repository** advisory in the same way.

Prior art searched 2026-11-06: GitHub Docs (GitHub Advisory Database), the GitHub Blog "by the numbers"
post, the 2022 changelog "All historical NVD advisories are now listed on GitHub", community #181073, and
issues #10423, #8851, #8831. None compares coverage by issuing CNA.

## Population and arms

Every NVD CVE record published 2025-01-01..2026-09-30 (NVD `published`, UTC date), not `Rejected`, whose
references include at least one URL `github.com/<owner>/<repo>/security/advisories/GHSA-...`. The first such
URL is the *cited repository advisory*.

- **Arm G:** NVD `sourceIdentifier` is `security-advisories@github.com` (GitHub's CNA).
- **Arm O:** any other `sourceIdentifier` (MITRE, VulnCheck, vendors' CNAs, ...).

NVD is read month by month with `pubStartDate`/`pubEndDate` (21 queries, paged at 2,000, 7 s apart).

## Database side

The shared sparse checkout of github/advisory-database (github-reviewed + unreviewed 2025 and 2026), used
**as it is** (the job does not fetch: the queued job S9b reads the same checkout); its commit and date are
recorded. Labels are as in S8: coverage `REVIEWED` / `UNREVIEWED_ONLY` / `WITHDRAWN_ONLY` / `NONE`
(uncovered = `NONE` or `WITHDRAWN_ONLY`); `ref_global_state` of the cited advisory `NOT_GLOBAL` /
`REVIEWED` / `UNREVIEWED` / `*_WITHDRAWN`. `DUP` = the cited advisory is a live global record **and** a
different live global advisory also lists the CVE.

Known limit: unreviewed advisories are read only from the 2025 and 2026 folders (same as S8). A 2025-2026
NVD record cannot have an unreviewed GHSA created before it, so this should not miss any.

## Gate

NVD records fetched >= 95% of NVD's reported total, and each arm >= 100 CVEs. Otherwise Q1-Q4 and Q6 are
INCONCLUSIVE. Q3 and Q6 also need >= 30 CVEs in each arm's stratum.

## Predictions (frozen)

| # | Prediction |
|---|---|
| Q1 | Arm O: <= 10% of CVEs are uncovered (no live global advisory). |
| Q2 | Arm O's uncovered share is at least 25 percentage points lower than arm G's in the same run. |
| Q3 | Where the cited repository advisory is NOT_GLOBAL: arm O covered share >= 80% **and** arm G covered share <= 5%. |
| Q4 | Of covered CVEs, the share covered only by an unreviewed advisory: arm O >= 25% **and** arm G <= 3%. |
| Q5 | Live check, seeded (20261106): 10 arm-O CVEs from the NOT_GLOBAL + UNREVIEWED_ONLY cell and 10 arm-G CVEs from the NOT_GLOBAL + uncovered cell. >= 18 of 20 `GET /advisories?cve_id=` answers agree with the checkout (arm O non-empty, arm G `[]`); errors excluded, threshold scaled; PENDING if more than 4 errors. |
| Q6 | Where the cited repository advisory is a live global record: arm O has DUP in >= 5% of CVEs, and a higher DUP share than arm G. |

What would follow (stated now, judged only after grading):
- Q1-Q3 holding would mean the S8 gap is specific to GitHub's CNA: the same kind of CVE from another CNA
  reaches the database through the NVD feed, while a GitHub-CNA CVE whose repository advisory was never
  made global does not. That is the number #181073, #8851 and #10423 lack.
- Q1 failing with Q2 holding would mean other CNAs' CVEs also fall through, just less often.
- Q2 failing would mean the gap is not about who issued the CVE.
- Q6 is about duplicates (the #10359 kind): a CVE issued outside GitHub for a vulnerability that also has
  a repository advisory may get both a reviewed record and an NVD-fed one.

## Grading (next run, before reading the counts)

Hand-check 3 rows from each of: arm O NOT_GLOBAL + UNREVIEWED_ONLY, arm G NOT_GLOBAL + NONE, and arm O DUP
(cveawg record, `GET /advisories?cve_id=`, the cited repository advisory page). Labels in RESULTS.md exactly
as the job's. Descriptive output (not predicted): arm sizes, coverage by arm, the top 15 arm-O sources with
their uncovered counts, arm O by year, and the day lag from NVD publication to the unreviewed advisory's
`published` date (this may be 0 by construction if GitHub copies NVD's date; it will be read that way).
