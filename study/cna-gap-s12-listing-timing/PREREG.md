# S12: is a CVE kept out of GitHub's Advisory Database when a repository advisory listing it already exists when NVD publishes it? (pre-registration)

Part of [advisory-import-census](../../README.md). Pre-registered 2026-11-08 (UTC), before any S12 page was fetched.
Code: `timing_rule.py`, tests: `test_timing_rule.py` (stdlib only, Apache-2.0). Text and data CC BY 4.0. Made with AI
agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

## Why

S11 ([RESULTS.md](../cna-gap-s11-repo-cve-field/RESULTS.md)) tested a simple rule: where a repository advisory's
"CVE ID" field lists the CVE, GitHub creates no NVD-fed record for it. The rule failed (R4): about 27% of other-CNA
CVEs whose advisory lists them are in GitHub's database anyway. After grading, the publish dates in S11's sample
suggested why. Among covered CVEs from CNAs other than GitHub and VulnCheck, 13 of the 22 listing advisories were
published **after** NVD published the CVE; among uncovered ones, 0 of 49 were. So the refined rule is:

> A CVE whose cited repository advisory is not curated into a global advisory is missing from GitHub's database
> when that repository advisory, listing the CVE, was already published on or before the day NVD published it.

That idea came from S11's data, so S12 tests it on **CVEs S11 did not sample**. If it holds, it gives one plain
explanation for the gaps S8, S10 and S11 measured (GitHub's own CNA, Zephyr, Erlang/OTP, CPANSec and others), and a
practical check for users who ask, as in github/advisory-database#7268, why such CVEs cannot be found by CVE ID.

Prior art, searched for S11 on 2026-11-07 and re-checked for the timing angle on 2026-11-08 (GitHub Docs "About the
GitHub Advisory Database", the 2022 changelog on NVD imports, github/advisory-database #7268, #10224, #10352, github
community #209436): none states or measures a rule linking NVD import to whether a repository advisory listing the
CVE already existed. This is an outside view: S12 cannot see GitHub's importer.

## Population, sample and what is read

- Frame: S11's published frame (`frame-part-1.csv` + `frame-part-2.csv` in the S11 folder, the S10 frame rebuilt
  at advisory-database commit `b072a703…`). The job joins the parts and requires sha256 `819b43ea…e323` (taken
  again after restoring CRLF line ends if the served copy has LF only; nothing else may differ), 18,102 rows and
  S11's six stratum sizes exactly.
- Population: arm O rows (CNA is not GitHub) whose CNA is **not VulnCheck** and whose cited repository advisory is
  `NOT_GLOBAL`. OO_COV = covered (`REVIEWED` or `UNREVIEWED_ONLY`), OO_UNC = uncovered (`NONE` or
  `WITHDRAWN_ONLY`). Removed first: every CVE in S11's sample (`rows.csv`, 266 rows), every CVE whose page S11's
  failed v2 run fetched (`v2-gate-failed/rows.csv`, 180 rows), and the eight S11 hand-read advisories. What is left
  are the **pools**.
- Sample: **all** of the OO_COV pool (about 237) and **200** from the OO_UNC pool (`random.Random(20261108)`, pool
  sorted by CVE ID).
- Each cited repository advisory page is fetched once, 2.5 s apart. Read: the "CVE ID" field (`LISTS_THIS`,
  `LISTS_OTHER`, `NO_CVE`, `UNPARSED`; `GONE` for 404, `ERROR` otherwise), with S11's parser, and the page's first
  `relative-time` (its "Published" time; S11's job read the same field). For a `LISTS_THIS` page: **EARLY** if that
  UTC day is on or before NVD's published day in the frame, **LATE** if after, `NODATE` if missing.
- Estimates are weighted by pool size: for a cell, `pool size × pages in the cell / parsed pages` per stratum,
  where parsed = `NO_CVE` + `LISTS_OTHER` + `LISTS_THIS`. Covered share = OO_COV estimate / (OO_COV + OO_UNC).

## Gate (all must hold, or nothing is graded)

Frame sha256, 18,102 rows and S11's six stratum sizes as above; S11's sample has 266 rows and v2's 180; at most 5%
of fetched pages are `ERROR` (404s are allowed: S11 found 12 of 50 OO_COV pages gone); at most 5% of HTTP 200 pages
are `UNPARSED`; at most 5% of `LISTS_THIS` pages have no date; and six parser checks come out as hand-read
(Cap-go GHSA-6g74-8cpq-g2c8 `NO_CVE`; OneUptime GHSA-g9cp-35m2-fjv6 and Zephyr GHSA-hfww-j92m-x8fv `LISTS_THIS`;
Zammad GHSA-p97w-927q-8vxq published 2026-10-08, Chamilo GHSA-hvpp-6mp9-frx4 2026-03-02 and RabbitMQ
GHSA-9wm4-9m6g-w38x 2026-07-09, each `LISTS_THIS`). If either stratum has fewer than 30 parsed pages, or a
prediction's cell has fewer than 10 pages, that prediction is INCONCLUSIVE.

## Predictions (frozen)

| # | Prediction |
|---|---|
| T1 | Pages that list this CVE and were published on or before NVD's day (EARLY): covered share **<= 12%**. |
| T2 | Pages that list this CVE and were published after NVD's day (LATE): covered share **>= 75%**. |
| T3 | Pages that say "No known CVE": covered share **>= 80%**. |
| T4 | OO_UNC: **<= 5%** of dated listing pages are LATE. |
| T5 | OO_COV: **>= 40%** of dated listing pages are LATE. |
| T6 | The rule (uncovered exactly when the page lists this CVE and is EARLY) is right for **>= 88%** of CVEs, pool-weighted, over parsed dated pages. |

T1 and T2 are the test of the rule. T3 repeats S11's held half of R4 on fresh CVEs. T4-T5 check each stratum; T6
says how much of the gap the rule explains.

What would follow (judged only after grading):
- T1 and T2 holding would mean the order of events, not the CVE field alone, predicts whether a non-curated CVE can
  be found in GitHub's database. It would fit GitHub's own CNA (which writes the CVE into the advisory before NVD
  publishes it) and project CNAs that publish the advisory and the CVE together.
- T1 failing would mean early listing does not keep CVEs out, and S11's dates were chance. T2 failing would mean
  late listing does not let them in either, so something else decides.

## Limits (stated now)

- The page's published time is the advisory's public date, not the moment the CVE was written into it. A CVE added
  later to an early advisory is counted EARLY.
- Day granularity: same-day publication counts as EARLY.
- One coverage snapshot (2026-11-02, S10's commit); pages are read days later. Advisories deleted since then are
  `GONE` and are not graded.
- VulnCheck CVEs are left out on purpose: VulnCheck usually assigns CVEs to advisories that are already public, so
  the advisory's date says little about when the CVE was listed.
- Correlation only.
