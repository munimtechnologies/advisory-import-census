# S7 pre-registration: CVE aliases on GitHub-reviewed advisories that the CVE List does not have

Frozen 2026-11-02 (UTC), before the job runs and before the 143 population rows were read one by one.
Code: `reserved_alias.py` (tests: `test_reserved_alias.py`). Population file: `s6_missing.csv`.
Licence: Apache-2.0 (code), CC BY 4.0 (text and data). Made with AI agents working for MV2 of Munim, Inc.

## Why

Study S6 ([../rejected-alias-s6/RESULTS.md](../rejected-alias-s6/RESULTS.md)) looked up every CVE alias of the
live GitHub-reviewed advisories in the CVE Program's bulk CVE List (release `cve_2026-11-01_1700Z`). 143 aliases
were not in the list at all, and S6 set them aside as MISSING. The bulk list only holds CVE *records*. An ID that
was reserved and never published, an ID that was rejected *before* it ever got a record, and an ID that was never
allocated all look the same there: absent.

The public CVE Services endpoint `https://cveawg.mitre.org/api/cve-id/<CVE>` (no account needed) tells them apart:
it returns the ID's state (`RESERVED`, `PUBLISHED`, `REJECTED`) and its owning CNA, and 404 for an ID that does not
exist. Testing it on 2026-11-02 on one of the 143 rows, CVE-2024-10039 (on GHSA-93ww-43rr-79v3), returned
`state: REJECTED, owning_cna: redhat`, with no CVE record (`/api/cve/` is 404). So S6's count of 54 reviewed
advisories carrying a rejected CVE is a floor: rejected IDs with no record were invisible to it.

## Prior art (searched 2026-11-02)

- **RBP Tracker** (Jerry Gamblin / RogoLabs, rbptracker.org, announced 2026-09-14) lists *Reserved But Public* CVE
  IDs: IDs in state RESERVED that a public advisory already cites, read from 17-18 feeds including OSV and the GitHub
  Advisory Database, using the same `/api/cve-id/` endpoint. Empirical Security's write-up (about 2026-10-05) gives
  1,983 such IDs. **So counting RESERVED aliases is not new**, and S7 reports them only as context.
- RBP Tracker tracks RESERVED only. Neither source reports cited IDs that are **REJECTED without a record** or that
  **do not exist**, and neither gives a figure for GitHub-*reviewed* advisories specifically.
- github/advisory-database #8851 (four ComfyUI advisories with RESERVED CVEs), #8051 (CVE aliases with no record).
What S7 adds: on one frozen population (every reviewed-advisory alias absent from the CVE List on 2026-11-01), the
split into reserved / rejected-without-record / never-allocated, the owning CNAs, and a hand check of whether a
never-allocated alias is a typo for a real CVE that the advisory itself mentions.

## What was known before freezing

The count (143 alias rows, from S6's job output), the CSV's columns, its first three rows (CVE-2021-30492,
CVE-2024-10039, CVE-2015-3542 and their advisories) and the single API result above. No other state was looked up.

## Population and data

- **Population:** the alias rows in `s6_missing.csv`, an exact copy of S6's `missing.csv` (columns `reviewed`,
  `cve`, `reviewed_published`). The unit for P1-P5 is the **distinct CVE ID**.
- **State:** `GET /api/cve-id/<CVE>`: 200 gives `state` and `owning_cna`; 404 gives NOT_FOUND; anything else after
  three tries gives ERROR. For PUBLISHED and REJECTED IDs, `GET /api/cve/<CVE>` adds the record if one exists
  (publication date, rejection reason).
- **Advisories:** github/advisory-database at the commit the job reads (same cached sparse clone as S1-S6). For each
  population advisory: still live? does it still carry the alias? its publication date, summary, details,
  references, and every other CVE ID it mentions.
- **Typo candidate** (for NOT_FOUND aliases only): a CVE ID that the advisory itself mentions (another alias, its
  summary or details, or a reference URL), that differs from the alias by at most 2 characters (edit distance), and
  whose own state is PUBLISHED.

## Predictions (frozen)

Denominator for P1-P3: distinct population CVE IDs whose state was read (not ERROR).

| | Claim |
|---|---|
| P1 | >= 50% are RESERVED |
| P2 | >= 10% are REJECTED (rejected IDs that S6's CVE-List lookup could not see) |
| P3 | >= 3 distinct IDs are NOT_FOUND (never allocated) |
| P4 | >= 50% of the RESERVED IDs sit on a reviewed advisory published at least 180 days before the read date |
| P5 | GitHub's own CNA (`GitHub_M`) owns at most 10% of the RESERVED IDs |
| P6 | >= 50% of the NOT_FOUND IDs have a typo candidate graded SAME by hand (same component, same weakness) |

If more than 10% of the IDs come back ERROR, P1-P5 are INCONCLUSIVE. If fewer than 3 IDs are NOT_FOUND, P6 is
INCONCLUSIVE_UNDERPOWERED. P6 is graded from `grading_sample.csv` (the alias, the candidate, the advisory text and
the candidate's CVE text; no counts or other states) **before** any other output is opened. UNCLEAR counts as not
SAME. The job prints no counts.

## Reported but not predicted

Owning CNAs by state; IDs that were PUBLISHED after the 2026-11-01 snapshot; whether each REJECTED ID is its
advisory's only CVE alias; rejection reasons where a record exists; advisories withdrawn or edited since S6.

## Limits

- The population is what S6's CVE-List snapshot missed. Aliases that were published or rejected *with* a record are
  outside it (S6 covers rejected-with-record).
- `/api/cve-id/` reports the state today, not when the alias was added. An ID can move from RESERVED to PUBLISHED
  between S6's snapshot and this read (counted separately as PUBLISHED).
- A RESERVED ID on a public advisory may be under a legitimate embargo or simply waiting on its CNA; S7 makes no
  claim about why.
- A typo candidate is a lead, not a fix. Which CVE belongs on the advisory is the curators' and the CNA's call
  (lesson of github/advisory-database #10828).

## What happens with the results

No bulk outreach. RESULTS.md and the per-ID table go in this folder. At most one summary note goes to the
advisory-database curators, only for checked rows, and only if it reads as a data-lookup gap.
