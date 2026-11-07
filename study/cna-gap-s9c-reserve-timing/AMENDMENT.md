# S9c amendment 1 (2026-11-07 UTC): the gate's row-count check was written wrong

Part of [advisory-import-census](../../README.md). Text CC BY 4.0, code Apache-2.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

## What happened

Job `s9c-timing-v1` ran on 2026-11-06 (23:11-23:14 UTC). Its tests passed and it read all 3,685 CVE records
(0 fetch errors), but the gate failed, so, as the [pre-registration](PREREG.md) says, **no prediction was graded**.

The gate's five checks came back:

| Check | Result |
|---|---|
| rows: S9a's file has 13,769 rows | **failed**: the file has 7,770 rows |
| late: 3,685 eligible late rows | passed |
| late_missing: 64 of them MISSING | passed |
| fetch: at least 98% of records read | passed (3,685 of 3,685) |
| known: the five hand-checked CVEs get the hand-found timing | passed |

## Why

13,769 is the size of S9a's population (every GitHub-CNA CVE published in NVD from 2025-01 to 2026-09). The
`rows.csv` that S9a published holds only the 7,770 CVEs whose cited repository advisory is a GitHub-reviewed global
advisory, because those are the only rows S9a could classify. The pre-registration mixed up the two counts. The
input itself was the right one: the population inside it (3,685 rows, 64 MISSING) matched exactly.

## What changes

- `EXPECTED_ROWS` goes from 13769 to 7770.
- The input's sha256 is now pinned to the file v1 read
  (`897fb04c44b650d991d61691eec5b70ed1bfef9ea36b5ef8069f2fc2d56f8117`), so v2 must read the same S9a file.
- Nothing else changes: population, definitions, the six predictions (Q1-Q6) and the other four gate checks are as
  pre-registered.

The corrected job `s9c-timing-v2` reads the CVE records again and is graded in a later run. v1's own output is kept
next to this file (`v1/RESULTS-job.md`, `v1/results.json`, `v1/rows.csv`).

## Honest note

v1 wrote its descriptive counts (but no grades) before this amendment was written, and they were read while
diagnosing the failure. The predictions could not be changed after that and were not. The only change is the
constant above, whose correct value can be checked against S9a's `rows.csv` without reading any S9c result.
