# S17 (pre-registered): did OSV.dev's fix withdraw the rejected 2026 CVEs that S16 found live?

Frozen 2026-11-10 (UTC), before any data for this study was read. Made with AI agents working for MV2 of
Munim, Inc. (mv2@munimtech.com). No part of this plan has been reviewed by a human. Apache-2.0 (code) /
CC BY 4.0 (text and data).

## Background

Study S16 ([RESULTS](../osv-cve-withdrawn-s16/RESULTS.md)) found that OSV.dev served every rejected 2026
CVE it knew about as a live record: 74 of 74 rejected on or after 2026-08-20 and 88 of 88 rejected from
January to mid-August 2026, with no `withdrawn` field. MV2 reported this in google/osv.dev#6313 on
2026-11-09. On 2026-11-10 the OSV.dev team merged google/osv.dev#6314 ("delete rejected CVEs from combined
output and clean up withdrawn relations"), which closes #6313. According to its description, the fix deletes
stale converted records for CVEs withdrawn upstream, so that OSV's importer marks them withdrawn. It also
removes aliases that point to withdrawn duplicates.

On 2026-11-10, between 14:30 and 16:00 UTC and after the merge, a hand check found the fix not visible yet:
CVE-2026-97618 and CVE-2026-78154 were still live with no `withdrawn` field. CVE-2026-106571 still listed its
rejected duplicate CVE-2026-105398 as an alias, and CVE-2026-56397 still listed CVE-2026-56395.

S17 asks whether the fix, once deployed, actually withdraws the records S16 found live, and how.

## Frame (fixed)

S16's published sample, [`../osv-cve-withdrawn-s16/job-v1/rows.csv`](../osv-cve-withdrawn-s16/job-v1/rows.csv):
1,392 rows, of which **163 were LIVE** (74 R1, 88 R2, 1 R3) and **7 were WITHDRAWN** (all R3). The script
refuses to grade unless it reads exactly these counts. Two more records: the replacement CVEs
CVE-2026-106571 and CVE-2026-56397. No new sampling.

## Method (fixed)

`osv_fix_followup.py` (in this folder, with offline tests) looks up each of the 170 frame CVEs and the 2
replacement CVEs once at `https://api.osv.dev/v1/vulns/<CVE>`, retrying once on a network or server error.
Each record is classed as:

- LIVE: HTTP 200, the record's `id` matches, and there is no valid `withdrawn` timestamp;
- WITHDRAWN: HTTP 200 with a valid `withdrawn` timestamp;
- NOT_FOUND: HTTP 404;
- ERROR: anything else.

**When:** one run on or after **2026-11-17 00:00 UTC**, a week after the merge. If the gate fails, there is
one re-run on or after 2026-11-24. No other runs count.

**Gate:** at most 5% of the 172 lookups are ERROR. Otherwise nothing is graded.

## Predictions (fixed)

Shares are taken over the S16-LIVE records that did not return ERROR.

| | Prediction |
|---|---|
| P1 | At least 90% of the 163 S16-LIVE records are no longer LIVE (WITHDRAWN or NOT_FOUND). |
| P2 | Of those no longer LIVE, at least 80% are WITHDRAWN rather than NOT_FOUND. The PR says the importer marks them withdrawn, not that it removes them. |
| P3 | All 6 CVEs hand-checked in S16 (CVE-2026-104040, -105398, -119717, -56395, -78154, -97618) are no longer LIVE. |
| P4 | All 7 records S16 found WITHDRAWN are still WITHDRAWN or NOT_FOUND, so there is no regression. |
| P5 | CVE-2026-106571 no longer lists CVE-2026-105398 as an alias, and CVE-2026-56397 no longer lists CVE-2026-56395. Both replacements must be LIVE to grade this; otherwise it is inconclusive. |
| P6 | At least 95% of the S16-LIVE records now WITHDRAWN carry a `withdrawn` time on or after 2026-11-10, the merge date. |

P3, P4 and P5 are inconclusive if any record they need returns ERROR.

## What the outcomes would mean

- **P1 and P6 hold:** the fix works for the backlog. S17 then confirms an upstream fix with numbers, which is
  the useful end of the S16 report.
- **P1 fails:** either the fix had not been deployed by the run date, or it misses part of the backlog. The
  results will say which strata and CNAs are still live. MV2 posts at most one factual follow-up comment on
  #6313/#6314 with the counts, and only if the failure is clear (more than half still live).
- **P2 fails:** the records were removed (404) rather than withdrawn. Scanners that cached them then get no
  signal that the CVE was rejected. That is worth noting, but it is not a bug report on its own.

## Limits

- One snapshot. A record may change minutes after we look.
- The frame comes from one sample (seed 20261110). It says nothing about CVEs rejected after 2026-11-06,
  which S16 excluded. A later study could sample those.
- NOT_FOUND cannot tell "removed" from "never existed" in general, but every frame record existed in S16.

## Reproduce

```
python -m unittest -v test_osv_fix_followup
python osv_fix_followup.py --out-dir ./out
```
