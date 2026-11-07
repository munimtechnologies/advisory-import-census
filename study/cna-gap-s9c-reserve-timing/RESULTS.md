# S9c results: was the CVE ID already reserved when GitHub reviewed the advisory?

Part of [advisory-import-census](../../README.md). Pre-registration: [PREREG.md](PREREG.md); amendment:
[AMENDMENT.md](AMENDMENT.md). Code `reserve_timing.py` (Apache-2.0); text and data CC BY 4.0. Made with AI agents
working for MV2 of Munim, Inc. (mv2@munimtech.com). Graded 2026-11-07 UTC.

Job output: [RESULTS-job.md](RESULTS-job.md), [results.json](results.json), per-CVE table [rows.csv](rows.csv).
Job `s9c-timing-v2` ran 2026-11-07 00:43-00:46 UTC. It read S9a's published `rows.csv` (sha256 `897fb04c...`,
the same file v1 read) and live CVE Services records. Advisory times come from S9a's 2026-10-30 clone.

## Short answer

When a GitHub-reviewed advisory does not list the CVE that GitHub's own CNA later published for it, it is almost
always because **the CVE ID did not exist yet when the advisory was reviewed, and the advisory was never edited
afterwards**.

- Of the 64 late CVEs still missing from their advisory (S9a), **61 (95.3%) were reserved after the review**.
- In **all 61**, the advisory's last `modified` time is before the CVE was reserved. In all 349 reserved-after
  cases that *were* added, the advisory was modified on or after the reservation (median 8.2 days later).
- Reserved-after CVEs normally do get added: 349 of 410 (85.1%). The misses cluster in advisories published in
  June-July 2026 (57 of 173 missing, 32.9%) compared with every other month (4 of 237, 1.7%).

## Gate

Passed (amended row count 7,770; 3,685 eligible late rows, 64 MISSING; 3,685 of 3,685 records read; input sha256
matches v1; the five hand-checked CVEs from the pre-registration came out as checked).

## Predictions (frozen 2026-11-06, unchanged by the amendment)

| ID | Prediction | Value | Held |
|---|---|---|---|
| Q1 | >= 80% of late LISTED CVEs were reserved BEFORE review | 3,272 of 3,621 = 90.4% | yes |
| Q2 | >= 50% of late AFTER CVEs are LISTED | 349 of 410 = 85.1% | yes |
| Q3 | >= 60% of late MISSING CVEs are AFTER | 61 of 64 = 95.3% | yes |
| Q4 | Among AFTER CVEs, the MISSING rate is higher for advisories published 2026-06-01..07-31 than outside | 57/173 = 32.9% vs 4/237 = 1.7% | yes |
| Q5 | >= 95% of AFTER LISTED CVEs sit in an advisory modified on or after `dateReserved` | 349 of 349 = 100% | yes |
| Q6 | >= 30% of BEFORE MISSING CVEs name a different GHSA as CNA source | 1 of 3 = 33.3% | yes (see note) |

**6 of 6 held.** Two notes that weaken this:

- **Q6 says almost nothing.** Only 3 CVEs were BEFORE + MISSING, and the one with a different source
  (CVE-2026-48019, Laravel) was already one of the five hand-checked cases listed in the pre-registration. The
  pre-registration set no minimum count, so it is graded as written, but it should not be read as evidence.
- **Q3 includes known cases.** Two of the 61 AFTER + MISSING CVEs (pypdf CVE-2026-57204 and komari
  CVE-2025-55300) were hand-checked before the predictions were written. Without them Q3 is 59 of 62 (95.2%).
- v1's descriptive counts (not grades) were seen before the amendment was written (see AMENDMENT.md).

## Descriptive (not predicted)

- Timing by status: BEFORE + LISTED 3,272; AFTER + LISTED 349; BEFORE + MISSING 3; AFTER + MISSING 61; UNKNOWN 0.
- **AFTER + MISSING and "never modified after reservation" coincide exactly** in this data: every one of the 61
  has `modified_after_reserved = no`, and every one of the 349 AFTER + LISTED has `yes`. This was not predicted
  for the MISSING side and it is a description, not a cause: `modified` changes on any edit, so it shows that
  these advisories were not touched again, not why.
- Advisories published in 2026-06 alone hold 46 of the 61 AFTER + MISSING CVEs (of 95 AFTER CVEs that month).
- Days from reservation to the advisory's next edit, for AFTER + LISTED: median 8.2, min 0.1, max 200.6.

## Hand checks (2026-11-07 UTC, after the job's summary was seen, so not blind)

Read live: `cveawg.mitre.org/api/cve/<id>` (`dateReserved`, source) and `api.github.com/advisories/<ghsa>`
(`github_reviewed_at`, `cve_id`). All six agree with the job's labels.

| CVE | Advisory (package) | Job | Reserved | Reviewed | Live `cve_id` |
|---|---|---|---|---|---|
| CVE-2026-41056 | GHSA-ccq9-r5cw-5hwq (composer wwbn/avideo) | AFTER, LISTED | 2026-04-16 | 2026-04-14 | CVE-2026-41056 |
| CVE-2026-41129 | GHSA-3m9m-24vh-39wx (composer craftcms/cms) | AFTER, LISTED | 2026-04-17 | 2026-04-14 | CVE-2026-41129 |
| CVE-2026-57122 | GHSA-x92v-rpx6-p6cw (pip praisonai) | AFTER, LISTED | 2026-06-24 | 2026-06-18 | CVE-2026-57122 |
| CVE-2026-42088 | GHSA-2wvh-87g2-89hr (rubygems openc3) | AFTER, MISSING | 2026-04-23 19:17 | 2026-04-23 14:17 | null |
| CVE-2026-63464 | GHSA-7rx3-5wx3-5v76 (go nebula-mesh) | AFTER, MISSING | 2026-07-16 | 2026-07-14 | null |
| CVE-2026-79743 | GHSA-p3h2-2j4p-p83g (npm @samanhappy/mcphub) | AFTER, MISSING | 2026-08-25 | 2026-04-22 | null |

In all three LISTED cases the live `updated_at` (2026-04-24, 2026-04-24, 2026-07-20) is after the reservation;
in all three MISSING cases it is before it (2026-04-23, 2026-07-14, 2026-05-05). The OpenC3 CVE was reserved five
hours after review; the MCPHub CVE four months after.

## What this means for the 65 missing aliases (S8-alias)

The fix is a one-line alias edit, and the gap is closed whenever someone edits the advisory after the CVE exists.
The 61 AFTER + MISSING advisories were never edited again. This is consistent with the one-advisory alias pull
requests already sent (github/advisory-database #10920, #10936) and gives curators a test: an advisory whose
`modified` predates its CVE's `dateReserved` cannot list that CVE.

Limits: one advisory snapshot (2026-10-30), so later fixes are not counted; `dateReserved` is when GitHub's CNA
reserved the ID, not when a reviewer could have seen it; descriptive only.
