# S9c: was the CVE ID already reserved when GitHub reviewed the advisory? (pre-registration)

Part of [advisory-import-census](../../README.md). Code Apache-2.0; data CC BY 4.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

Written 2026-11-06 (UTC) before any S9c output exists. The code (`reserve_timing.py`), its offline tests and these
predictions are committed together; the job runs afterwards and is graded in a later run, unchanged.

## Why

[S9a](../cna-gap-s9a/RESULTS.md) found that 64 of 3,685 eligible "late" GitHub-CNA CVEs (published in NVD at least a
day after the reviewed advisory they cite) are missing from that advisory's aliases (1.74%), against 6.6% for
advisories published in June 2026. But hand checks during S9a's grading showed that a "late but listed" CVE is
usually not a CVE that was added later: in 4 of 5 checked listed advisories the file had not been modified since
review, so the CVE ID was already written in when the advisory was reviewed, while the CVE was still RESERVED.
So S9a's 1.74% says nothing yet about the step that matters to curators: when a CVE ID is reserved only after an
advisory has been reviewed, how often does the alias get added? This study splits S9a's late CVEs by whether
the CVE ID existed (was reserved) at review time.

## Data (fixed before running)

- Population: rows of S9a's `study/cna-gap-s9a/rows.csv` (this repository's main branch) with `eligible = yes` and
  `late = yes`: 3,685 CVEs, 64 of them MISSING. Its sha256 is recorded in the output.
- For each CVE, the CVE record from CVE Services (`cveawg.mitre.org/api/cve/<id>`): `dateReserved`, `datePublished`,
  `state`, `containers.cna.source.advisory` and the repository-advisory references.
- Advisory times (`github_reviewed_at`, `published`, `modified`) come from S9a's rows (the 2026-10-30 clone), not live.

## Definitions

- BEFORE: `dateReserved` <= the advisory's `github_reviewed_at` (the advisory's `published` time when that is empty).
  AFTER: later. UNKNOWN: no record, not PUBLISHED, or an unreadable time. Full timestamps in UTC, no rounding.
- LISTED: S9a status LISTS_THIS. MISSING: S9a status LISTS_NONE.
- source matches: the CNA `source.advisory` GHSA equals the advisory S9a cites (S9b's SPLIT pattern when it does not).
- In window: advisory published 2026-06-01..2026-07-31.

## Gate (checked before grading)

S9a's file has 13,769 rows; the population has 3,685 rows with 64 MISSING; at least 98% of records are read; and the
five hand-checked CVEs below get the timing found by hand. If the gate fails, predictions are not graded; the next run
reports why and files a corrected v2 with these predictions unchanged.

## Predictions (frozen)

| ID | Prediction |
|---|---|
| Q1 | At least 80% of eligible late LISTED CVEs were reserved BEFORE review. |
| Q2 | At least 50% of eligible late CVEs reserved AFTER review are LISTED (the alias was added afterwards). |
| Q3 | At least 60% of eligible late MISSING CVEs were reserved AFTER review. |
| Q4 | Among AFTER CVEs, the MISSING rate is higher for advisories published 2026-06-01..07-31 than outside. |
| Q5 | At least 95% of AFTER CVEs that are LISTED sit in an advisory whose `modified` is on or after `dateReserved`. |
| Q6 | At least 30% of BEFORE MISSING CVEs name a different GHSA as their CNA `source.advisory`. |

## Already known before writing (so not predictions)

Checked by hand on 2026-11-06 against cveawg and api.github.com:

| CVE | Advisory | S9a status | Reserved | Reviewed | Timing | CNA source |
|---|---|---|---|---|---|---|
| CVE-2026-57204 | GHSA-jm82-fx9c-mx94 (pypdf) | MISSING | 2026-06-24 | 2026-06-18 | AFTER | same |
| CVE-2025-55300 | GHSA-q355-h244-969h (komari) | MISSING | 2025-08-12 16:15 | 2025-08-12 00:13 | AFTER | same |
| CVE-2026-48019 | GHSA-5vg9-5847-vvmq (laravel/framework) | MISSING | 2026-05-20 | 2026-06-17 | BEFORE | GHSA-fpqx-6722-p65v |
| CVE-2026-48113 | GHSA-24fp-5v3p-rvpw (chisel) | LISTED | 2026-05-20 | 2026-06-12 | BEFORE | same |
| CVE-2026-54899 | GHSA-2cw7-v8ff-p88r (oj) | LISTED | 2026-06-16 | 2026-06-19 | BEFORE | same |

Five rows out of 3,685; no other dateReserved value has been looked at.

## Limits

- `dateReserved` is when GitHub's CNA reserved the ID, not when the advisory author saw it. A BEFORE CVE could still
  have been unknown to the reviewer.
- `modified` changes for any edit, so Q5 shows the file was touched after the ID existed, not that the edit added it.
- One advisory snapshot (2026-10-30 clone). Fixes made since then, including from MV2's alias pull requests, are not
  counted.
- Descriptive only. GitHub's curation process is not visible from outside; nothing here says why an alias is missing.
