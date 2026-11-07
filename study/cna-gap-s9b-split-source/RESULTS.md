# S9b results: CVEs whose record names one GitHub advisory as its source but links another

Part of [advisory-import-census](../../README.md). Pre-registration: [PREREG.md](PREREG.md). Code
`split_source.py` (Apache-2.0); text and data CC BY 4.0. Made with AI agents working for MV2 of Munim, Inc.
(mv2@munimtech.com). Graded 2026-11-07 UTC.

Job output: [RESULTS-job.md](RESULTS-job.md), [results.json](results.json), per-CVE table [rows.csv](rows.csv),
source-advisory HTTP sample [sample.csv](sample.csv). Job `s9b-split-v1` ran 2026-11-06 19:59-20:11 UTC against
advisory-database commit `9f58b825` (2026-10-30) and live CVE Services records.

## Short answer

Splits are rare but every one is invisible to a CVE lookup. Of the 13,769 CVEs GitHub's CNA (`GitHub_M`)
published in NVD from 2025-01 to 2026-09, **13 (0.09%)** have a record whose `source.advisory` names one
repository advisory (GHSA) while its references link a different one (the "umbrella"). The source advisory of
all 13 is absent from GitHub's global database, none of the 13 CVEs had a live global advisory in S8, and none
is in the umbrella's aliases. So `GET /advisories?cve_id=` returns `[]` for all 13, even though in 11 cases the
umbrella advisory describing the bug is a live GitHub-reviewed advisory.

## Gate

Passed: 13,769 population rows, 100% of records read (0 fetch errors), and the five known cases came out as
checked by hand (CVE-2026-95842, -95848, -92284, -92700 SPLIT; CVE-2026-57234 MATCH).

## Predictions (frozen 2026-11-06)

| ID | Prediction | Value | Held |
|---|---|---|---|
| P1 | SPLIT CVEs are 0.2% to 3% of CVEs whose record was read | 13 of 13,769 = 0.09% | **no** (rarer than predicted) |
| P2 | >= 95% of MATCH+SPLIT CVEs are MATCH | 13,677 of 13,690 = 99.91% | yes |
| P3 | >= 90% of SPLIT CVEs name a source advisory absent from the global clone | 13 of 13 | yes |
| P4 | >= 70% of SPLIT CVEs had no live global advisory in S8 | 13 of 13 | yes |
| P5 | >= 60% of SPLIT CVEs share their umbrella with another SPLIT CVE | 9 of 13 = 69.2% | yes |
| P6 | >= 80% of SPLIT CVEs whose umbrella is live are not in its aliases | 11 of 11 | yes |

**5 of 6 held.** P1 failed on the low side: the pattern is real but smaller than the hand-found cases suggested.

## Descriptive (not predicted)

- Classes: MATCH 13,677; SPLIT 13; NO_REF 72 (GHSA source but no repository-advisory link); NO_SOURCE 7;
  NOT_PUBLISHED, NO_RECORD, FETCH_ERROR 0.
- The 13 SPLIT CVEs sit under 6 umbrellas: Moquette GHSA-5f42-97gr-vfhq (7 CVEs), Caddy GHSA-j8px-rmrx-76h9
  (2), and one each under Laravel GHSA-5vg9-5847-vvmq, Quinn GHSA-4w2j-m93h-cj5j and two Outline advisories
  (GHSA-c8xf-3j86-7686, GHSA-mx2c-3g2x-5m9m).
- Umbrella in the global database: 11 GitHub-reviewed, 2 not there at all (both Outline). Two umbrellas carry a
  CVE of their own (Moquette CVE-2026-85724, Caddy CVE-2026-77281); Laravel's and Quinn's have none.
- By NVD month: 2026-02 2, 2026-07 1, 2026-09 10.
- Sample: all 10 sampled source advisories return HTTP 404 at the umbrella's repository (private, deleted or
  never published; the job cannot tell which).

## Hand checks (2026-11-07 UTC)

Read live on cveawg.mitre.org and api.github.com, after the job's summary had been seen (so not blind). Five of
the 13 SPLIT rows (none of them the gate's known cases) and three MATCH rows. All eight agree with the job's labels.

| CVE | Job | `source.advisory` | First advisory reference | Matches |
|---|---|---|---|---|
| CVE-2025-64487 (Outline) | SPLIT | GHSA-x4x3-6c29-946p | GHSA-c8xf-3j86-7686 | yes; `?cve_id=` returns `[]` |
| CVE-2025-68663 (Outline) | SPLIT | GHSA-9hv9-67q3-fjc6 | GHSA-mx2c-3g2x-5m9m | yes |
| CVE-2026-25800 (quinn-proto) | SPLIT | GHSA-p2f3-wfhq-fj93 | GHSA-4w2j-m93h-cj5j | yes; umbrella is reviewed, `cve_id` null |
| CVE-2026-95845 (Moquette) | SPLIT | GHSA-f9rr-rg42-xc8x | GHSA-5f42-97gr-vfhq | yes |
| CVE-2026-48019 (Laravel) | SPLIT | GHSA-fpqx-6722-p65v | GHSA-5vg9-5847-vvmq | yes |
| CVE-2022-31114 (Backpack CRUD) | MATCH | GHSA-m8xx-3x29-84h8 | same | yes |
| CVE-2026-62681 (orval) | MATCH | GHSA-fg9p-mrxr-hvq7 | same | yes |
| CVE-2026-62683 (filebrowser) | MATCH | GHSA-pp88-jhwj-5qh5 | same | yes |

Two cases read in more detail:

- **Moquette.** The reviewed umbrella GHSA-5f42-97gr-vfhq (Maven `io.moquette:moquette-broker` <= 0.18.0, CVSS
  9.6) describes six separate findings from one audit, and holds one CVE (CVE-2026-85724). GitHub's CNA published
  seven more CVEs on 2026-09-23 (CVE-2026-95842..95848), each requested through its own repository advisory but
  linking only the umbrella. A lookup by any of those seven, including CVSS 8.7 and 9.3 ones, finds nothing.
- **Quinn.** CVE-2026-25800 ("quinn-proto has remote memory exhaustion from unbounded out-of-order stream
  reassembly") was published 2026-07-23. The umbrella GHSA-4w2j-m93h-cj5j, reviewed one day later with nearly the
  same title, has `cve_id: null`. Here the CVE and the umbrella look like one vulnerability under two GHSA IDs.

## What this does and doesn't show

- It shows that a CVE record's `source.advisory` and its advisory reference can disagree, that this happened 13
  times in 21 months, and that none of those 13 CVEs can be found by CVE ID in GitHub's database.
- It does not show why. One reading that fits every case: maintainers merged several draft advisories into one
  before publishing, and the CVEs requested from the drafts kept the draft as their source. This was not tested.
- Whether a split CVE should become an alias of its umbrella is the curators' call. For Quinn the two look like
  the same bug. For Moquette, seven separate findings under one advisory are a one-advisory-many-CVEs question
  (the reverse of github/advisory-database#10224), and an alias may not be the right link.
- Limits: CVE records were read live on 2026-11-06 against a 2026-10-30 clone; one CNA only; 13 cases is too few
  for any rate by month or project.
