# S13 results: live PyPA advisories that rest on a rejected CVE

Graded 2026-11-09 (UTC) against the frozen [PREREG.md](PREREG.md). **4 of 6 predictions held.**
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). No human has reviewed
these results. Code Apache-2.0; text and data CC BY 4.0.

## Inputs (pinned by the job)

- pypa/advisory-database commit `8e3fe64f4612dd6037f5381f8e0004d38bebc56b` (2026-11-05T19:48:55Z): 7,903 PYSEC files, 0 parse errors.
- github/advisory-database commit `0847e81e34d87d1b50efe58b86a780d05e6cd051` (2026-11-09T00:37:44Z): 37,571 reviewed advisories.
- CVE List release `cve_2026-11-09_0100Z` (`2026-11-09_all_CVEs_at_midnight.zip.zip`): 421,272 CVE records, read 2026-11-09T02:20:49Z.
- Script `pysec_rejected.py` 0.1.0, seed 20261108. Gate: PASSED (all four floors met).
- Job output as produced: [`job-v1/`](job-v1/) (results.json, RESULTS-job.md, rows.csv, pr_candidates.csv, missing.csv, grading_sample.csv).

## Grades

| | Prediction | Value | Held |
|---|---|---|---|
| P1 | >= 10 live PYSEC records hold a REJECTED CVE alias | **21** of 7,631 live records (0.28%) | **yes** |
| P2 | >= 50% of rows are `WITHDRAW_CANDIDATE` | 17 / 21 = 81.0% as run; **16 / 21 = 76.2%** after the correction below | **yes** (either way) |
| P3 | >= 40% of rows with a GHSA alias have a GHSA that GitHub withdrew | 3 / 19 = 15.8% | **no** |
| P4 | >= 70% of rows untouched since the rejection | 15 / 21 = 71.4% | **yes** (narrowly) |
| P5 | >= 80% of rows rejected after the PYSEC record was published | 16 / 21 = 76.2% | **no** |
| P6 | >= 75% of the seeded sample (8) still PR-ready when checked live | **8 / 8** by the pre-registered checks; 7 / 8 = 87.5% if the misclassified row is counted as not ready | **yes** (either way) |

P6 was checked by hand on 2026-11-09 (UTC), the same day as the run. For each of the 8 sampled records: the CVE
record at `cveawg.mitre.org/api/cve/<CVE>` showed `REJECTED`; the file on pypa `main` had no `withdrawn`
line; and a GitHub search of pypa/advisory-database for the PYSEC ID and the CVE found no pull request
(the only hit, issue #110 from 2022, is an issue about PYSEC-2021-126's version range). Per-row grades:
[`grading_sample-graded.csv`](grading_sample-graded.csv).

## Correction found while grading (disclosed, predictions unchanged)

The pre-registered definition says a row is `REPLACE_ALIAS` when "a rejection reason names another CVE
that is PUBLISHED". Script 0.1.0 searched only the first 300 characters of the reason (the copy it keeps
for display) and ignored the CVE record's `replacedBy` field. One row is affected: **PYSEC-2026-518
(ray)**. Its CVE-2025-34351 was rejected by VulnCheck at the CVE Program's request, and the rejection
says, after character 300, that it "conflicts with an existing CVE (CVE-2023-48022)". The record's
`replacedBy` also names CVE-2023-48022, which is PUBLISHED (tagged disputed). By the pre-registered
definition the row is `REPLACE_ALIAS`, not `WITHDRAW_CANDIDATE`. P2 moves from 17/21 to 16/21 and still
holds. P6 holds whether or not this row counts.

`pysec_rejected.py` 0.1.1 reads the full reason and `replacedBy`, and adds tests that reproduce the 0.1.0
mistake. The grades above come from the pinned v1 output plus this one hand correction.

### Re-run with the corrected script (job v2, 2026-11-09)

Job `pysec-rejected-s13-v2` ran script 0.1.1 on fresh inputs: the same pypa/advisory-database commit
`8e3fe64` (no newer commit existed), github/advisory-database commit `8fa5ec7` (2026-11-09T03:38:55Z) and
CVE List release `cve_2026-11-09_0300Z`. Its unit tests passed and its gate passed. It reproduces the
corrected grades exactly: the same 21 rows, **16 `WITHDRAW_CANDIDATE` and 5 `REPLACE_ALIAS`**, with
PYSEC-2026-518 (ray) now `REPLACE_ALIAS` to CVE-2023-48022 mechanically rather than by hand. P1, P3, P4
and P5 have the same values as v1. Its output is published as produced under [`job-v2/`](job-v2/); the
grades are not re-graded from it.

## What the census shows

1. **Mostly one project and one CNA.** 10 of the 21 rows are `open-webui`, all built on CVEs issued by
   huntr (`@huntr_ai`) and rejected on 2026-08-13 (9) or 2026-08-31 (1). 13 of 21 rows are huntr CVEs
   (open-webui 10, zenml, vllm, nltk). The other rejecting CNAs are MITRE (4), VulnCheck (2), GitHub (1)
   and Red Hat (1).
2. **There is a precedent for exactly this fix, and the second batch was missed.** In July 2026 the
   open-webui maintainer had five sibling records withdrawn after huntr rejected their CVEs
   ([#354](https://github.com/pypa/advisory-database/pull/354)-[#358](https://github.com/pypa/advisory-database/pull/358),
   each merged within an hour; a collaborator suggested auto-withdrawing when the upstream CVE is rejected).
   GitHub withdrew the matching advisory GHSA-3p9q-7w63-3f8q on 2026-09-02, six weeks after PyPA did.
   huntr rejected ten more open-webui CVEs in August. Nearly three months later, none of the ten
   PYSEC records has been withdrawn, and all ten matching GitHub advisories are still live.
3. **PyPA does not lag GitHub here; both keep serving these advisories (P3 failed).** GitHub had withdrawn
   only 3 of the 19 matching advisories (weblate and gerapy, both duplicates with a published replacement,
   and one nltk record). GitHub's live advisories still carry the rejected ID as their CVE (for example
   GHSA-54f4-v6v9-9q82 still lists `cve_id` CVE-2024-7037). That matches S6's count of 54 live reviewed
   GitHub advisories with rejected aliases.
4. **Five records were created after their CVE was already rejected (P5 failed).** All five are 2026
   records from PyPA's June-July 2026 batch: gradio PYSEC-2026-1407 (CVE rejected 2024-05), langchain
   PYSEC-2026-372 (2023-12), zenml PYSEC-2026-2068 (2024-07), vllm PYSEC-2026-568 (2025-04) and ray
   PYSEC-2026-518 (2025-12). Checking the CVE's state when a record is created would have kept them out.
   17 of the 21 rows are 2026 records.
5. **What the fix is.** 16 rows (after the correction) are withdrawal candidates. 5 are `REPLACE_ALIAS`:
   weblate, gerapy, gradio, langchain and ray each point to a published replacement CVE. These are
   reported here and not sent, until a maintainer says which fix they prefer. 13 CVE aliases on live
   records are not in the CVE List at all (RESERVED or never assigned); they are listed in
   `job-v1/missing.csv` and not graded.

## What happens next

As pre-registered: one pull request at a time, one file each, adding `withdrawn` and bumping `modified`
to the same timestamp in the format of #354. Each is checked live again just before it is sent. Each PR
body cites the CVE record, says the check was made with AI agents, and offers to stop. The first,
for PYSEC-2021-126 (ansible; Red Hat rejected CVE-2021-3533 on 2024-01-15 because it "does not meet the
criteria for a security vulnerability"), was opened on 2026-11-09 as
[pypa/advisory-database#424](https://github.com/pypa/advisory-database/pull/424). The next one waits
until a maintainer has looked at it.

A follow-up study, [S15](../osv-rejected-s15/PREREG.md), asks the same question of the other source
databases OSV serves (Go, RustSec, Haskell, R, Julia, Erlang/Elixir and others).

## Limits

- One snapshot of each source. The PyPA snapshot is from 2026-11-05; the others are from 2026-11-09.
- A rejected CVE does not prove there is no flaw. huntr's August rejections give no reason ("rejected or
  withdrawn by its CVE Numbering Authority"), while GitHub's matching advisories are still live. That is
  why every PR is checked by hand, and why maintainers may prefer to wait for GitHub.
- n = 21 is small; P4 passed by one row (15/21 against a 70% bar).
- `ghsa_state` uses only github-reviewed advisories.
- The reason classes are coarse keyword classes; they were not graded.

## Reproduce

```
pip install pyyaml==6.0.2
python -m unittest -v test_pysec_rejected
python pysec_rejected.py --data-dir data --out-dir out
```
Fresh runs read the latest commits and CVE List release, so counts can differ from the pinned run above.
