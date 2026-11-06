# S9a: when GitHub's CNA publishes a CVE after the reviewed advisory it cites, does the advisory get the alias? (pre-registration)

Part of [advisory-import-census](../../README.md). Code Apache-2.0; data CC BY 4.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

Written 2026-11-06 (UTC) before any S9a output exists. The code (`backfill_rate.py`), its offline tests and these
predictions are committed together; the job runs afterwards and is graded in a later run, unchanged.

## Why

[S8-alias](../cna-gap-s8-alias/README.md) found 65 live GitHub-reviewed advisories with no CVE alias, although
GitHub's own CNA published a CVE whose only repository-advisory reference is that same advisory. In 63 of them the
CVE was published at least a day after the advisory, and 41 of the advisories were published as reviewed on
18-19 June 2026. That list has no denominator. Is 65 a small leak in a step that usually works, or is it the normal
result whenever a CVE arrives after review? Without that rate, the June cluster is only an observation, not a finding.

## Data (fixed before running)

- Population: S8's `study/cna-gap-s8/cves.csv` (13,769 GitHub-CNA CVEs published in NVD 2025-01-01..2026-09-30),
  read from this repository's main branch; its sha256 is recorded in the output.
- Advisories: the github/advisory-database clone already used by S8-alias (stored with the job data, not refreshed;
  HEAD recorded in the output). `published`, `modified`, `aliases` and `withdrawn` come from each reviewed file.
- No other network use, and no live API reads.

## Definitions

- Each CVE's cited advisory is the first repository-advisory URL in its NVD references (S8's `ref_ghsa`).
- Status: LISTS_THIS (the cited reviewed advisory lists exactly this CVE), LISTS_NONE (it lists no CVE and no live
  reviewed advisory holds the CVE), and the excluded LISTS_THIS_AND_OTHERS, LISTS_NONE_HELD_ELSEWHERE, LISTS_OTHER,
  REF_WITHDRAWN, REF_NOT_REVIEWED and NO_REF.
- Eligible: LISTS_THIS or LISTS_NONE, where no other population CVE cites the same advisory.
- MISSING: LISTS_NONE.
- lag_days: the CVE's NVD published date minus the advisory's `published` date, in UTC calendar days. Late means
  lag_days >= 1.

## Gate (checked before grading)

The input must have 13,769 rows, 7,699 with coverage REVIEWED and 78 GLOBAL_WITHOUT_ALIAS, matching S8. The number of
eligible MISSING rows must be between 62 and 68, matching S8-alias's 65. If the gate fails, the predictions are not
graded; the next run reports why and files a corrected v2 with these predictions unchanged.

## Predictions (frozen)

| ID | Prediction |
|---|---|
| P1 | At most 10% of eligible late CVEs are MISSING (adding the alias after review usually works). |
| P2 | At least 30% of eligible late CVEs whose advisory was published on 2026-06-18 or 2026-06-19 are MISSING. |
| P3 | At most 3% of eligible late CVEs whose advisory was published outside 2026-06-01..2026-07-31 are MISSING. |
| P4 | The MISSING rate for late CVEs with lag >= 30 days is higher than for lag 1-29 days. |
| P5 | Late CVEs are between 2% and 20% of eligible CVEs. |
| P6 | Of the eligible late CVEs that ARE listed, at least 50% sit in an advisory whose `modified` date is on or after the CVE's NVD published date. |

## Already known before writing (so not predictions)

The numerators of the MISSING side are partly known from S8-alias: 65 MISSING, of which 63 had a CVE published
(CVE Services date) at least a day after the advisory; 41 advisories were published 2026-06-18/19, 1 on 2026-06-17,
5 on 2026-06-26/27, 12 in July and 6 at other times. None of the denominators (listed late CVEs) has been counted or looked at.

## Limits

- The NVD published date can be a few hours later than the CVE Services publication time, so lag is in whole UTC days
  and can be off by one.
- An advisory can list a CVE ID that was still RESERVED when it was reviewed. A "listed" late CVE therefore does not
  show that GitHub added the alias afterwards; P6 only checks whether the file was touched on or after the CVE date.
- One snapshot (2026-11-05). Fixes made since then, including any from MV2's alias pull requests, are not counted here.
  The S8-alias re-check planned for around 2026-11-20 covers them.
- Descriptive only. Nothing here says why an alias is missing; GitHub's curation process is not visible from outside.
