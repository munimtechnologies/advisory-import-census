# S13: live PyPA advisories that rest on a rejected CVE (pre-registration)

Frozen 2026-11-08 (UTC), before any data for this study was collected. Code: `pysec_rejected.py`
(v0.1.0), tests: `test_pysec_rejected.py`. Apache-2.0 code; the results data will be CC BY 4.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

## Question

The Python Packaging Authority's advisory database ([pypa/advisory-database](https://github.com/pypa/advisory-database))
holds the PYSEC advisories that pip-audit, PyPI's JSON API and OSV serve for Python packages. When
the CNA that issued a CVE later **rejects** it, the PYSEC advisory built on that CVE keeps flagging
the package unless someone withdraws it. Maintainers have done this one record at a time
([#354-#358](https://github.com/pypa/advisory-database/pulls?q=is%3Apr+rejected), July 2026, all merged within an hour;
[#189](https://github.com/pypa/advisory-database/pull/189), 2024; [#393](https://github.com/pypa/advisory-database/pull/393), a disputed CVE).
We found no count of how many live PYSEC records still rest on a rejected CVE (searched 2026-11-08).

1. How many live (not withdrawn) PYSEC records carry a CVE alias whose CVE record is REJECTED?
2. Does GitHub's Advisory Database already treat the same flaw as withdrawn (does PyPA lag GitHub)?

## Data (pinned and recorded by the job)

- pypa/advisory-database, shallow clone of `main`: every `vulns/**/PYSEC-*.yaml`. Commit SHA and date recorded.
- github/advisory-database, sparse shallow clone of `advisories/github-reviewed`. Commit SHA and date recorded.
- CVE List bulk release (CVEProject/cvelistV5, latest `*_all_CVEs_at_midnight.zip.zip`). Tag recorded.
  A CVE ID that is not in the list (RESERVED or never assigned) counts as MISSING and is reported separately.

## Definitions

- **Live PYSEC record:** no `withdrawn` field.
- **Row:** a live PYSEC record with at least one CVE alias whose CVE record has state REJECTED.
- **Action class of a row:** `DROP_ALIAS` if it also has a PUBLISHED CVE alias; else `REPLACE_ALIAS`
  if a rejection reason names another CVE that is PUBLISHED and is not already an alias; else
  `WITHDRAW_CANDIDATE`.
- **GHSA state of a row:** over its GHSA aliases, `withdrawn` if any is withdrawn in github-reviewed,
  else `live` if any is a live reviewed advisory, else `not_in_reviewed`; `none` if it lists no GHSA.
- **Untouched since rejection:** the record's `modified` is earlier than every rejected alias's `dateRejected`.
- **Rejected after publish:** every rejected alias's `dateRejected` is later than the record's `published`.

## Predictions (thresholds fixed now)

| | Prediction |
|---|---|
| P1 | At least 10 live PYSEC records hold a CVE alias whose CVE record is REJECTED. |
| P2 | At least 50% of those rows are `WITHDRAW_CANDIDATE`. |
| P3 | Of the rows that list a GHSA alias, at least 40% have a GHSA alias that GitHub has withdrawn. |
| P4 | At least 70% of rows are untouched since rejection. |
| P5 | At least 80% of rows were rejected after the PYSEC record was published (records went stale, rather than being imported already rejected). |
| P6 | Of a seeded sample (seed 20261108, up to 8) of `WITHDRAW_CANDIDATE` rows, at least 75% are still PR-ready when checked live by hand: cveawg.mitre.org shows REJECTED, the file on pypa `main` has no `withdrawn`, and no pull request in pypa/advisory-database names the PYSEC ID or the CVE. |

With fewer than 5 rows, P2-P5 are reported as INCONCLUSIVE_UNDERPOWERED. P1 is graded on the count alone.

## Sanity gate (floors, not expected values)

At least 2,000 PYSEC files, at most 1% of them failing to parse, at least 200,000 CVE records and at
least 15,000 reviewed GitHub advisories. If any floor fails, the job writes no verdicts and the study
is fixed in the open and re-run with the predictions unchanged.

## What happens with the result

The job writes `pr_candidates.csv`. Each candidate is checked live by hand before anything is sent,
and then sent as **one pull request per UTC day** that changes one file only: it adds `withdrawn` and
bumps `modified` to the same timestamp, the format the merged PRs above use. Every PR body cites the
CVE record, says plainly that the check was made with AI agents, and offers to stop if the maintainers
would rather handle these themselves. `REPLACE_ALIAS` and `DROP_ALIAS` rows are reported, not sent,
until a maintainer says which fix they prefer.

## Known limits

- One snapshot of each source; CVE states can change after the CVE List release we read.
- A rejected CVE does not prove there is no flaw (for example a duplicate that was replaced by another
  CVE). That is why duplicates with a published replacement are a separate class, and why every PR
  candidate is read by hand.
- GHSA state uses github-reviewed only; a PYSEC record whose GHSA alias is unreviewed counts as `not_in_reviewed`.
- Rows from this study's earlier sibling S6 (GitHub's reviewed advisories with rejected aliases,
  [results](https://github.com/munimtechnologies/advisory-import-census/tree/main/study)) were not
  looked at when setting these thresholds.
