# S12 results: a CVE stays out of GitHub's Advisory Database when its repository advisory already listed it on the day NVD published it (6 of 6 held)

Part of [advisory-import-census](../../README.md). Pre-registration: [PREREG.md](PREREG.md). Graded 2026-11-08 (UTC).
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). Code Apache-2.0, text and data CC BY 4.0.

Job: `s12-timing-v1`, run 2026-11-08 14:35-14:57 UTC. Job output, unchanged: [RESULTS-job.md](RESULTS-job.md),
[results.json](results.json), [rows.csv](rows.csv) (one row per repository advisory page read; 411 rows).

## Gate: passed (all eight checks)

Frame sha256 `819b43ea…e323` as served (no line-ending restore needed), 18,102 rows, S11's six stratum sizes exactly
(OV_COV 1,273, OV_UNC 122, OO_COV 287, OO_UNC 876, G_UNC 5,913, G_COV 16), S11's sample 266 rows and v2's 180, 0
`ERROR` pages, 0 `UNPARSED`, 0 listing pages without a date, and all six hand-read parser cases as expected.

One number differs from the pre-registration's wording, not from its rules: PREREG.md estimated the OO_COV pool at
"about 237". That estimate subtracted only S11's 50-page sample; the written rule also removes v2's fetched CVEs
and the eight hand-read advisories, which took out 26 more. The pool the rule defines is **211** (OO_UNC: **791**).
All 211 were read, as specified.

## Grades

Covered = the CVE is in GitHub's database (`REVIEWED` or `UNREVIEWED_ONLY` at S10's commit). Estimates are weighted
by pool size: `pool × pages in the cell / parsed pages`, with 175 parsed OO_COV pages (36 of 211 are gone, 404)
and 200 parsed OO_UNC pages.

| # | Prediction | Result | Held |
|---|---|---|---|
| T1 | Listing page published on or before NVD's day (EARLY): covered share <= 12% | **5.3%** (44.6 of 835.6; 237 pages) | yes |
| T2 | Listing page published after NVD's day (LATE): covered share >= 75% | **100%** (47.0 of 47.0; 39 pages) | yes |
| T3 | Page says "No known CVE": covered share >= 80% | 100% (89.2 of 89.2; 74 pages) | yes |
| T4 | OO_UNC: <= 5% of dated listing pages are LATE | 0 of 200 (0.0%) | yes |
| T5 | OO_COV: >= 40% of dated listing pages are LATE | 39 of 76 (51.3%) | yes |
| T6 | Rule right for >= 88% of CVEs, pool-weighted | **95.5%** (957.4 of 1,002) | yes |

Cells (pages): OO_COV `NO_CVE` 74, `LISTS_OTHER` 25, EARLY 37, LATE 39, `GONE` 36; OO_UNC EARLY 200, nothing else.
T1: OO_COV 211 × 37/175 = 44.6 covered; OO_UNC 791 × 200/200 = 791 uncovered. T6: OO_COV 211 × 138/175 = 166.4
plus OO_UNC 791 right, of 1,002.

## What this means

For CVEs from CNAs other than GitHub and VulnCheck that cite a GitHub repository advisory GitHub has not curated,
**the order of events predicts coverage.** If the repository advisory already listed the CVE on or before the day
NVD published it, the CVE is almost never in GitHub's database (about 5%, pool-weighted). If the advisory listed it
only later, said "No known CVE", or listed another CVE, the CVE was in the database every time in this sample,
nearly always as an NVD-fed unreviewed record.

This fits the gaps the earlier studies measured: GitHub's own CNA writes the CVE into the advisory before NVD
publishes it (S11 R1: 50 of 50 uncovered pages list it), and project CNAs such as Zephyr, Erlang/OTP (EEF) and
Eclipse publish advisory and CVE together. A plausible reading, **not tested here**, is that GitHub's NVD import
leaves a CVE to the repository-advisory route when an advisory already carries it, and that route only reaches the
global database through curation. S12 sees only the outside.

For anyone asking why such a CVE "cannot be found by CVE ID" (github/advisory-database#7268, #10224): look at the
CVE record's GitHub advisory reference. If it is a repository advisory that listed the CVE when NVD published it,
the gap is expected; the repository advisory is the record to use.

## Read with care (seen after grading; not tests)

- **T2 and T4 are nearly the same fact.** No uncovered CVE had a LATE page, so the LATE covered share is 100% by
  construction once T4 holds.
- **Eclipse dominates LATE.** 27 of the 39 LATE pages are Eclipse (`emo@eclipse.org`) CVEs. Without Eclipse, 12
  LATE pages remain, all covered. Within Eclipse alone, the split still shows: 27 LATE pages all covered, while 12
  of its 16 EARLY pages are uncovered.
- **MITRE-assigned CVEs are the main exception.** 15 of the 37 EARLY-but-covered pages are `cve@mitre.org` CVEs;
  weighted, about 40% of MITRE's EARLY CVEs are covered, against about 3% for EEF (5 covered EARLY pages vs 53
  uncovered). The rule is weak for CVEs MITRE assigns. A follow-up would need a fresh sample.
- 36 of 211 OO_COV pages (17%) are gone. If deleted advisories differ, the OO_COV cells are biased.

## Hand checks (live, 2026-11-08 UTC)

Made after reading the gate line and a few rows of `rows.csv`, before reading the graded verdicts.

| Stratum | Advisory (CVE) | Job | Live | Match |
|---|---|---|---|---|
| OO_COV | WhiteBeamSec/WhiteBeam GHSA-3f8r-9483-pfxj (CVE-2021-47688) | `NO_CVE`, published 2021-05-08 | "No known CVE", published May 8, 2021 | yes |
| OO_COV | tianocore/edk2 GHSA-p7wp-52j7-6r5x (CVE-2024-38805) | `LISTS_THIS`, 2025-08-13, LATE (NVD 2025-08-12) | CVE-2024-38805, Aug 13, 2025; `?cve_id=` returns unreviewed GHSA-w8rg-pqpr-83hp | yes |
| OO_UNC | erlang/otp GHSA-rf72-wp7h-jg3x (CVE-2026-47078) | `LISTS_THIS`, 2026-07-27, EARLY (same day) | CVE-2026-47078, Jul 27, 2026; `?cve_id=` returns `[]` | yes |
| OO_UNC | canonical/lxd GHSA-h85r-gjgx-g2rv (CVE-2026-85526) | `LISTS_THIS`, 2026-09-25, EARLY (NVD 2026-09-28) | CVE-2026-85526, Sep 25, 2026 | yes |

## Limits

- The page's "Published" time is the advisory's public date, not when the CVE was written into it; a CVE added later
  to an early advisory counts as EARLY. Day granularity; same day counts as EARLY.
- One coverage snapshot (S10's commit, 2026-11-02); pages read 2026-11-08.
- VulnCheck CVEs and GitHub's own CNA are outside this test (see PREREG.md).
- Correlation only; S12 cannot see GitHub's importer.

## Tool

The rule is packaged as an agent skill and a standard-library script in this repository:
[skills/github-advisory-cve-gap](../../skills/github-advisory-cve-gap/SKILL.md). Given a CVE ID, it checks GitHub's
database, the CVE record and the cited repository advisory, and says which known pattern (if any) explains a gap.
