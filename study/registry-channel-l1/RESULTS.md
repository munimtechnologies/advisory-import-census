# Result (L1): the no-registry blind spot is partly import lag, but a large gap survives among year-old advisories

**Decision: LAG.** Within no_registry apps, advisories at least a year old are
**+22.4 points** more visible to scanners than young ones (22.4% vs 0.0%),
within-repository permutation p = 0.0001. The frozen prediction P1 was that this age
difference would be **below +15 points** (no meaningful lag); it was not, so the
verdict is LAG. This **falsifies the arc's strict "permanent structural blind spot"
reading** for no-registry apps: some of the gap does close as advisories age.

But the gap does **not** close. The mechanism prediction P2 held: among old (≥ 1 year)
advisories, registry apps are still **+74.1 points** more visible than no_registry apps
(96.6% vs 22.4%), repository-level permutation p = 0.0063. So import lag is real but
explains only part of the blind spot; three quarters of old no_registry advisories
still never reach scanners.

L1 re-analyses A4's already-published 1,429-advisory census, splitting each app's own
advisories into age bins (young 14–89 days, mid 90–364, old ≥ 365) and comparing
visibility **within the same repositories**, so project-level differences cannot
masquerade as an age effect. The objection it tests is the obvious one: maybe
no_registry apps look blind only because GitHub has not yet imported their *recent*
advisories, and old ones catch up. They partly do, but a self-hosted app that ships no
registry release stays largely invisible even after a year.

This result was pre-registered in
[`PREREGISTRATION-registry-channel-l1.md`](PREREGISTRATION-registry-channel-l1.md),
frozen 2026-10-19 before any advisory-age × visibility table was computed. The analysis
code, its offline tests and the frozen A4/A5 inputs were fetched from `main` at run time
and their git-blob hashes recorded (see Reproduce). It was produced by AI agents working
for MV2 of Munim, Inc., with no human review of the result.

## Predictions vs. outcomes

| Prediction (frozen) | Result | Verdict |
|---|---|---|
| **P1 (primary):** the no-registry blind spot is **not** import lag — `visible(old) − visible(young) < +15.0 pts` within no_registry | **+22.4 pts** (22.4% vs 0.0%), within-repo permutation p = 0.0001 (seed 20261017, 10,000 permutations, 10 repos with both bins) | **failed → LAG** |
| **P2 (mechanism):** the registry gap is still large among settled (≥ 1 yr) advisories — `diff ≥ +25.0 pts` and repo-level p < 0.05 | **+74.1 pts** (96.6% vs 22.4%), repo-level permutation p = 0.0063 (22 repos) | **held** |
| **P3:** descriptive, no threshold | per-cell rates with Wilson 95% CIs below | descriptive |

Power floor cleared: no_registry young bin n = 98, old bin n = 406 (floor 20 each), 10
repos with both bins (floor 3); P2 has 8 registry and 14 no_registry repos with old
advisories (floor 3 each). Not underpowered.

## Per-cell visibility (P3 descriptive)

Visible = OSV holds a record for the advisory (by GHSA id or CVE alias) that names at
least one package, verbatim from A4. Rate with Wilson 95% CI.

**All advisories (n = 1,429)**

| group | young (14–89 d) | mid (90–364 d) | old (≥ 365 d) | old − young |
|---|---|---|---|---|
| registry | 31.4% (72/229) [25.8–37.7] | 98.4% (299/304) [96.2–99.3] | 96.6% (84/87) [90.4–98.8] | +65.2 |
| no_registry | 0.0% (0/98) [0.0–3.8] | 4.9% (15/305) [3.0–8.0] | 22.4% (91/406) [18.6–26.7] | **+22.4** |
| registry − no_registry | +31.4 | +93.5 | **+74.1** (P2) | |

**Package-typed advisories only (advisory names a package)**

| group | young | mid | old | old − young |
|---|---|---|---|---|
| registry | 39.1% (70/179) | 98.4% (254/258) | 100.0% (79/79) | +60.9 |
| no_registry | 0.0% (0/31) | 15.3% (9/59) | **93.1% (67/72)** [84.8–97.0] | **+93.1** |

The package-typed cut is the clearest finding of the study. When a no_registry app's
advisory **does name a package**, it almost always reaches scanners once it is a year
old (93.1%), nearly matching registry apps. The small all-advisory old rate (22.4%)
therefore comes from the many no_registry advisories that **name no package at all**:
those stay blind regardless of age. This lines up exactly with E2, where the no-package
stratum is where no_registry apps are almost entirely invisible, and with A3/A4, where
naming a real package was necessary but, on its own, not sufficient early on.

## What drives the lag, per repository

The age effect inside no_registry is carried by a handful of apps whose advisories are
eventually bound to a coordinate, not by the whole channel (`age_lag_per_repo.csv`):

- **keycloak** 0.0% (0/8) young → 46.2% (6/13) mid → **100.0% (62/62)** old — the
  strongest single catch-up.
- **goharbor/harbor** no young bin → 50.0% mid → 57.7% (15/26) old (Go module path,
  per A6).
- **goauthentik/authentik** 0.0% → 14.3% → 19.0%; **louislam/uptime-kuma** → 64.3% old;
  **jellyfin** → 12.5% old.
- **Permanently blind across every bin:** discourse (0/297), mastodon (0/57),
  metabase (0/44), zulip (0/41), outline (0/26), requarks/wiki (0/15),
  ClickHouse (0/7) — Docker-only / no-package apps that never catch up.

So "LAG" is not uniform: it is old advisories in a few apps becoming bound to a package,
while the no-package Docker-only apps stay at zero at every age.

## Reconciliation with the arc

- **A6** checked a single settled-advisory cut inside the Go/non-Go contrast; L1 tests
  the age effect directly inside the registry/no-registry channel with within-repo
  comparisons. Both point the same way: age helps where a coordinate exists.
- **E2** found the registry gap survives holding OSV ecosystem fixed (+41.7 pts).
  L1 adds the time dimension: the gap also survives age (+74.1 pts among old
  advisories), and the residual blindness is concentrated in no-package advisories —
  the same stratum E2 isolated.
- **The arc's headline, corrected:** earlier write-ups in this project described the
  no-registry blind spot as "structural / permanent." L1 shows that is too strong for
  advisories that name a package: those do get imported with age. The accurate claim is
  narrower and stronger where it holds — **a self-hosted app whose advisories name no
  package (typically Docker-only) stays blind to scanners at every age.**

## Limits (several stated in advance)

- **Observational and cross-sectional.** Each advisory's age is fixed at the A4
  snapshot; L1 does not follow advisories over time. Older advisories were also written
  under older reviewer and tooling practices, so "age" mixes elapsed time with a cohort
  effect. Within-repo comparison removes project-level confounding but not cohort.
- **Lag direction, not rate.** L1 shows old > young; it cannot date when an advisory
  became visible, so it does not estimate how many months the lag is.
- **Frame.** A4's 25 self-hosted apps; the result speaks to that frame. 10 no_registry
  repos have advisories in both the young and old bins; the within-repo null rests on
  those 10.
- **Classification and visibility frozen.** registry / no_registry labels and
  `scanner_class` are A4's, read unchanged; rows with age < 14 days were dropped per
  A4's rule (0 dropped here).
- **Snapshot.** OSV and the census as of A4 (fetched from `main`, job ran
  2026-10-20 04:07–04:08 UTC).

## Reproduce

```
# fetch A4's census + classification and A5's stats module from main,
# verify each git-blob sha, hash the analysis code
python fetch_inputs.py --dest . --out-dir out
# run the pre-registered analysis
python age_lag_analysis.py --census-csv real_package_census.csv \
  --classification registry_classification.json --out-dir out
# offline unit tests of L1's own code (16 tests)
python -m unittest -v test_age_lag
```

Code that ran (`frozen_code_sha.json`), each matching the committed file on `main` by
git-blob sha:

| file | git blob sha |
|---|---|
| `registry-channel-l1/age_lag_analysis.py` | `c55542938cd354013fb654c07c583ac3256b8d2c` |
| `registry-channel-l1/test_age_lag.py` | `a6293b120c9e5cab695d4cdb61e3cc6ce73e9765` |
| `registry-channel-l1/fetch_inputs.py` | `3c6e3a3b5c95365f6db5d6f263bbaaf8d5540238` |

Frozen inputs, each verified by git-blob sha at run time:

| file | git blob sha |
|---|---|
| `registry-channel-a4/real_package_census.csv` | `4617c2df697f36eeb4c4d4fe8483bbae7119bcfd` |
| `registry-channel-a4/registry_classification.json` | `260a9c04dedaa108437c84082346ff72ed7ad635` |
| `registry-channel-a5/go_rescue_analysis.py` | `861051715843702a4214006672122eed3bd09fc9` |

Data in this folder: `age_lag_summary.json` (every bin × group cell with Wilson CIs,
P1 d1 + within-repo permutation p, P2 diff + p, verdict), `age_lag_per_repo.csv`
(per-repository young/mid/old counts), `frozen_code_sha.json`. All 16 offline tests
passed in the same run (exit 0 on all three steps).

Made with AI agents working for MV2 of Munim, Inc.
