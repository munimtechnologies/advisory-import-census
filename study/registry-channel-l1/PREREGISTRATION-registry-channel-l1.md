# Pre-registration — registry-channel L1: is the no-registry blind spot an import *lag* that closes with age, or a *permanent* gap?

**Status:** frozen and published **before** any advisory-age × visibility table is
computed or read. L1 is a **re-analysis of A4's already-published census**; no new
advisory or visibility data is collected. Only the distribution of `age_days` alone was
looked at to check that the bins below are populated (268 of 1,429 rows are over 1,000
days old); visibility was not split by age. Made with AI agents working for MV2 of
Munim, Inc. Apache-2.0 (code) / CC BY 4.0 (text & data).

Frozen UTC: 2026-10-19.

## Background and why this is new

Across A1/A2/A6/A7 this arc found that a self-hosted app's own advisories reach
OSV-backed scanners when the app publishes to an OSV-indexed registry (or is a Go module
at its repo path), and that apps shipping only Docker images or install scripts are
almost entirely blind. A natural objection is that this is **review lag**: GitHub's
reviewers import repository advisories into the global database over time, so the gap
might be mostly recent advisories that simply have not been reached yet. A6 checked one
cut (advisories settled ≥ 90 days) inside the Go/non-Go contrast only. Nobody in this
arc has asked whether the **registry vs no-registry** gap **closes with advisory age
within the same repositories**. Safeguard.sh's Oct 2026 work (cited in A6) reports that
recent advisories are missed more often; to our knowledge no one has tested the age
effect separately inside the no-registry channel. L1 does, using within-repo
comparisons so that project-level differences cannot masquerade as age effects.

## Data (frozen)

- `study/registry-channel-a4/real_package_census.csv` (git blob
  `4617c2df697f36eeb4c4d4fe8483bbae7119bcfd`), 1,429 advisories, with A4's `age_days`
  (days from `published_at` to the census snapshot) and `scanner_class`.
- `study/registry-channel-a4/registry_classification.json` (git blob
  `260a9c04dedaa108437c84082346ff72ed7ad635`) → each repo's `registry` / `no_registry`
  group, read exactly as A4's `load_classification` does.
- Visibility: `scanner_class == "scanner_visible"`, verbatim from A4 (an OSV record by
  GHSA id or CVE alias names a package). Rows with `age_days < 14` are dropped (A4's
  eligibility rule; expected to be a no-op).

Both files are fetched from `main` at run time and their blob shas checked; any
mismatch stops the job.

## Age bins (frozen)

```
young : 14  <= age_days < 90
mid   : 90  <= age_days < 365
old   :        age_days >= 365
```

## Statistics (frozen)

- **Primary P1 (lag within no-registry apps).** Among `no_registry` repos, pooled
  `visible(old) − visible(young)`. Test: **within-repository** permutation — for each
  repo, shuffle the young/old labels among that repo's own young+old advisories
  (10,000 permutations, seed 20261017, two-sided), so only within-repo age contrasts
  count. Repos with advisories in only one of the two bins contribute nothing to the
  null spread but are kept in the pooled rates.
- **P2 (gap among settled advisories).** Among `old` advisories only,
  `visible(registry) − visible(no_registry)` with the arc's **repository-level**
  permutation test (shuffle group labels across repos; 10,000, seed 20261017).
- **P3 (descriptive).** Visible rate with Wilson 95% CI for every bin × group cell, for
  all advisories and for package-typed (`advisory_product_type == "package"`)
  advisories separately; per-repo young/old table.

## Pre-registered predictions and thresholds

| id | prediction | threshold | role |
|----|------------|-----------|------|
| **P1** | the no-registry blind spot is **not** an import lag: old no-registry advisories are not much more visible than young ones | `visible(old) − visible(young) < +15.0 pts` within no_registry | primary |
| **P2** | the registry gap is still large among settled (≥ 1 year) advisories | `diff ≥ +25.0 pts` AND repo-level permutation `p < 0.05` | mechanism |
| **P3** | — | descriptive, no threshold | descriptive |

**Power floor.** P1 is **INCONCLUSIVE_UNDERPOWERED** if, within `no_registry`, the
young or the old bin holds fewer than **20** advisories, or fewer than **3** repos have
advisories in **both** bins. P2 is underpowered if either group has fewer than 3 repos
with old advisories.

## Verdict rule (frozen)

```
if underpowered(P1):                                   INCONCLUSIVE_UNDERPOWERED
elif d1 >= 15.0 and p1 < 0.05:                         LAG    (gap closes with age)
elif d1 <  15.0 and P2 holds:                          PERMANENT
else:                                                  MIXED  (report d1, p1, P2 as found)
```

`LAG` falsifies the arc's "structural blind spot" reading for no-registry apps;
`PERMANENT` supports it. `MIXED` covers, e.g., d1 < 15 but the old-bin registry gap
below +25 pts or not significant.

## Limits stated in advance

Age is not pure lag: older advisories were also written under older reviewer and
tooling practices (a cohort effect), and an advisory's age is fixed at the snapshot, so
L1 is cross-sectional. Within-repo comparison removes project-level confounding but not
cohort effects. A4's frame is 25 self-hosted apps; the result speaks to that frame.

## Outputs

`age_lag_summary.json` (all cells with Wilson CIs, P1 d1 + within-repo permutation p,
P2 diff + p, verdict), `age_lag_per_repo.csv`, `frozen_code_sha.json`. The analysis
code and offline tests will be committed **before** the job runs; `RESULTS.md` will be
written against the thresholds above whichever way they fall.
