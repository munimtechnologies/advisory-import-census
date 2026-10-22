# Pre-registration O1: do the same advisories change over time? A panel re-check of A4

**Status: frozen 2026-10-22 (UTC), before any second snapshot exists.** No OSV record
was re-queried for this study and no transition table has been computed. The only
numbers used below are the A4 / L1 figures already published on `main`. Apache-2.0
(code) / CC BY 4.0 (text & data). Made with AI agents working for MV2 of Munim, Inc.;
no human has reviewed this plan.

## Why

L1 found that the no_registry blind spot is partly import lag (+22.4 pts old vs young)
but that a +74.1 pt registry gap survives among advisories at least a year old, and
that package-less no_registry advisories stay blind at every age. L1's own first limit:
it is **cross-sectional**. "Old vs young" mixes elapsed time with a cohort effect
(older advisories were written under older practices), and it cannot show any single
advisory moving from blind to visible.

O1 removes that limit the direct way: it re-checks **the same advisories** (same GHSA
ids) at a second snapshot at least 28 days after A4, with the same classification code,
and counts which ones changed state.

## Prior art and what is new

- *Characterizing and Modeling the GitHub Security Advisories Review Pipeline*
  (arXiv 2602.06009; ACM DL 10.1145/3793302.3793360) models review timing for about
  288k GHSAs from 2019 to 2025, using `github_reviewed_at`. It does not follow
  repository advisories that never enter the reviewed database, and it does not split
  by whether the project publishes to a registry.
- Safeguard.sh (Oct 2026) measured missing rates for 2,486 2026 repository advisories,
  month by month (under 8% missing for January to June against about 90% for October),
  across 45 projects sampled **from OSV's Go/npm/PyPI dumps**. That sample only includes
  projects with registry packages, so Docker-only apps cannot appear in it. It is also
  cross-sectional by publication month.
- github/advisory-database#10425 documents review times longer than 72 h in 2026.

As far as we found, none of these follows the **same** advisories across two snapshots
split by registry channel and by package-typed vs package-less. O1 does. If it turns
out someone already has, we will cite them in RESULTS.md.

## Frame (fixed now)

Exactly the 1,429 advisories L1 analysed. These are the rows of
`study/registry-channel-a4/real_package_census.csv` (git blob
`4617c2df697f36eeb4c4d4fe8483bbae7119bcfd`) whose repository has a registry /
no_registry label in `study/registry-channel-a4/registry_classification.json` (blob
`260a9c04dedaa108437c84082346ff72ed7ad635`, nested format), all at least 14 days old at
the A4 snapshot. If a blob sha does not match, the job halts. The A4 snapshot time is
recovered per row as `published_at + age_days` (about 2026-10-19 UTC). Its state at A4
is the row's `scanner_class`. "Package-typed" is A4's product-type field, cut exactly as
L1 cuts it (`registry-channel-l1/age_lag_analysis.py`, blob
`c55542938cd354013fb654c07c583ac3256b8d2c`). Age bins are L1's: young 14–89 d, mid
90–364 d, old ≥ 365 d, taken from the A4 `age_days`.

## Second snapshot (T2)

- **Not before 2026-11-16 00:00 UTC** (at least 28 days after A4). It runs once, as a
  network-enabled compute job, and the T2 time is recorded in the output.
- **Measure:** A4's `classify` function, copied verbatim from
  `registry-channel-a4/real_package_census.py` (blob
  `def387a9a6cc4b93cfe1fd61df3d509e299bb4c1`), with the same OSV endpoint
  (`https://api.osv.dev/v1/vulns/<id>`): first the advisory's own GHSA id, then its
  **A4-stored** `cve_id` if the GHSA record names no package. Pacing is 0.2 s, and the A4
  canary `GHSA-39mp-8hj3-5c49` must resolve or the run is void. Every OSV response is
  archived in the output.
- The **transition** for an advisory is its A4 state → its T2 state.
  `blind→visible` = caught up. `visible→blind` = reversal.

## Predictions (frozen)

| ID | Set | Claim | Threshold | Role |
|---|---|---|---|---|
| **P1** | no_registry advisories, **package-less** (not package-typed), blind at A4 (617 at A4) | Package-less no-registry advisories stay blind over time | share blind→visible **≤ 3.0%** | **Primary** |
| **P2** | registry advisories, **young** at A4, blind at A4 (157 at A4) | Registry advisories catch up within weeks | share blind→visible **≥ 30.0%** | Secondary |
| **P3** | advisories **young** at A4 and blind at A4, both groups | Catching up depends on the registry channel, age-matched | registry − no_registry blind→visible **≥ +25.0 pts** and repo-level permutation **p < 0.05** | **Mechanism** |
| P4 | all 1,429 | Reversals (visible→blind) are rare | none: count, list and explain | Descriptive |
| P5 | advisories in the same 25 repos **published after A4's snapshot** and at least 14 days old at T2 | Out-of-time registry gap on new advisories | none: registry vs no_registry visible rate, Wilson 95% CI | Descriptive |

Why these thresholds:
- **P1, 3.0%:** at A4, package-less no_registry advisories were 30 visible out of 647
  across *all* ages, accumulated over years. A 4-week window should move almost none of
  them. Go-module rescue (A6) is the one known route, which is why the bar is above 0.
- **P2, 30.0%:** this could go either way, and the two pieces of evidence point in
  opposite directions. Cross-sectionally, registry visibility jumps from 31.4% (young)
  to 98.4% (mid), which suggests strong catch-up. Against that, the 2026 review backlog
  (Safeguard.sh, #10425) suggests recent advisories may wait longer than four weeks.
- **P3:** the same +25 pt bar and p < 0.05 as A2/A1/E2/L1.

**Statistics.** For P3, the repo-level permutation of group labels uses repositories
with at least one young-and-blind-at-A4 advisory, with seed 20261017, 10,000
permutations, two-sided. Shares come with Wilson 95% CIs.

**Power floor.** P1 is underpowered if it has fewer than 100 advisories or fewer than
3 repos. P2 is underpowered if it has fewer than 30 advisories or fewer than 3 repos.
P3 is underpowered if either group has fewer than 3 repos.

## Verdict logic

1. If P1 or P3 is underpowered: **INCONCLUSIVE_UNDERPOWERED**.
2. If P1 holds and P3 holds: **PERSISTS_LONGITUDINALLY**. The same package-less
   advisories stay blind while registry ones catch up, which supports L1's corrected
   headline in a within-advisory design.
3. If P1 fails: **PACKAGELESS_CATCHUP**. This falsifies "package-less Docker-only apps
   stay blind at every age" for this window. We say so on every page that claims it
   (study/README.md, docs/maintainer-checklist.md, the DEV posts' follow-up).
4. If P1 holds and P3 fails: **NO_DIFFERENTIAL_MOVEMENT**. Little moves in either group
   within the window, for example because of the 2026 review backlog. This does not
   refute the arc. It means four weeks is too short to see catch-up.

P2 is reported, and stated as held or failed, but it does not enter the verdict.

## Robustness (pre-specified, reported whichever way they fall)

- **R1, new CVEs:** re-fetch each advisory page and use any CVE id assigned after A4.
  This reports how many transitions depend on new CVE ids.
- **R2, withdrawn:** exclude OSV records with a `withdrawn` field (A4 did not check
  this) and re-state P1–P3.
- **R3, per repo:** a per-repository transition table. If one repository causes P1 to
  fail on its own, we say so, but the verdict stands as frozen.
- **R4, advisories gone from GitHub** (the page 404s, or the advisory is withdrawn at
  T2): count them and exclude them from the primary sets.

## Stated limits

- One window of at least 28 days. A hold of P1 says "not within this window", not
  "never".
- The frame is A4's 25 self-hosted apps. The 2026 review backlog means the window's
  catch-up rate may not represent other periods.
- This is observational. A transition shows *that* an advisory became visible, not
  *why*.
- No human review.

## Outputs (committed with RESULTS.md, whichever way it falls)

- `panel_transitions.csv`: one row per advisory, with its A4 state, T2 state, group,
  bin, package-typed flag and OSV packages at T2.
- `panel_summary.json`: P1–P5, R1–R4 and the verdict.
- `panel_per_repo.csv`
- `frozen_code_sha.json`
- the raw OSV archive

The collector, analysis and offline tests will be committed to this folder **before**
T2 and their blob shas recorded. Code written after this file can only implement the
plan above. It cannot change a threshold.
