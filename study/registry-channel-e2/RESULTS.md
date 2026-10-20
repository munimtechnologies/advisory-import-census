# Result (E2): the registry gap survives holding the OSV ecosystem fixed — pooled 52-app test

**Decision: SURVIVES.** Ecosystem-adjusted difference **+41.7 points**, permutation
p < 0.0001 (0 of 10,000 within-stratum permutations as extreme), across **6 usable
ecosystem strata** and **52 repositories**. The frozen bar was ≥ +25 points and
p < 0.05 with at least 3 usable strata.

E2 asked the question E1 could not answer: is the registry → scanner-visibility gap
just OSV indexing some ecosystems (npm, PyPI) better than others? E1 ran on the
32-app A4 frame, found only 2 usable strata (floor 3) and was reported
INCONCLUSIVE. E2 pooled the A1/A4 and A2 frames (59 apps, disjoint, frozen before any
pooled data was read), re-collected the whole frame with one frozen collector, and ran
E1's **unchanged** analysis. With the ecosystem held fixed, apps that publish to an
OSV-indexed registry are still far more often visible to scanners, and the difference
is positive in **every one** of the six strata.

This result was pre-registered in
[`PREREGISTRATION-registry-channel-e2.md`](PREREGISTRATION-registry-channel-e2.md).
The collector (`registry-channel-a4/real_package_census.py`) and the analysis
(`registry-channel-e1/ecosystem_adjusted_analysis.py`) were fetched from `main` at run
time and their hashes recorded (see Reproduce). It was produced by AI agents working
for MV2 of Munim, Inc., with no human review of the result.

## Predictions vs. outcomes

| Prediction (frozen) | Result | Verdict |
|---|---|---|
| **1. Power:** ≥ 3 usable strata (≥ 2 repos on each side), including at least one of Go, PyPI, Packagist | **6** usable: Go, Packagist, PyPI, none, npm, other; all three named ones qualify; 52 distinct repos (floor 6) | **met** |
| **2. Primary (P1):** adjusted difference ≥ +25 pts and p < 0.05 | **+41.71 pts**, p < 0.0001 (seed 20261017, 10,000 within-stratum permutations) | **SURVIVES** |
| **3. P2:** registry apps' advisories sit more often in well-indexed ecosystems | mean well-indexed share 63.4% (22 registry apps) vs 13.6% (30 no_registry apps), +49.9 pts, p < 0.0001 | **met** |
| **4. P3:** Packagist and `none` low; PyPI / npm / Go high; coolify's Packagist artefact diluted, not reversed | Packagist 12.0%, none 12.0%; PyPI 79.4%, npm 71.2%, Go 69.5%. Within Packagist, registry apps 37.5% (6 / 16) vs no_registry 0.0% (0 / 34); the 0% side is coolify's 33 advisories naming a package absent from Packagist, plus one siyuan advisory naming `composer:siyuan` | **met** |

## Per-stratum table (P1 inputs)

Visible = OSV holds a record for the advisory (by GHSA id or CVE alias) that names at
least one package. Weight = Mantel–Haenszel `n1·n0/(n1+n0)` in advisories.

| stratum | registry repos | registry visible | no_registry repos | no_registry visible | diff (pts) | weight |
|---|---|---|---|---|---|---|
| none (advisory names no package) | 16 | 73 / 146 (50.0%) | 29 | 55 / 924 (6.0%) | **+44.0** | 126.1 |
| Go | 3 | 134 / 166 (80.7%) | 2 | 89 / 155 (57.4%) | +23.3 | 80.2 |
| npm | 10 | 386 / 497 (77.7%) | 12 | 4 / 51 (7.8%) | **+69.8** | 46.3 |
| Packagist | 2 | 6 / 16 (37.5%) | 2 | 0 / 34 (0.0%) | +37.5 | 10.9 |
| PyPI | 4 | 164 / 204 (80.4%) | 3 | 2 / 5 (40.0%) | +40.4 | 4.9 |
| other | 3 | 2 / 4 (50.0%) | 4 | 5 / 17 (29.4%) | +20.6 | 3.2 |
| **adjusted (MH)** | | | | | **+41.7** | |

Not usable (no registry app on one side): **Maven** — 3 no_registry apps, 65 / 101
visible (64.4%); **crates.io** — 1 no_registry app, 3 / 18 (16.7%).

Two things stand out:

- **The largest stratum is the one where no package is named at all** (1,070 of 2,338
  advisories). There, registry apps' advisories are 50.0% visible and no_registry apps'
  6.0%. This is the same pattern E1 saw (50.0% vs 4.6%) on a frame almost twice the
  size: the registry advantage is not carried by the package named on the advisory
  page, which fits A3 and A4.
- **Go has the smallest gap (+23.3)**, as A6 predicts: no_registry Go apps are rescued
  through their module path, so they sit at 57.4% rather than near zero. Most of that
  side is one app (siyuan, 147 of 155 Go-stratum advisories; harbor has the other 8).

## How much of the raw gap does ecosystem explain? (descriptive, not pre-registered)

Without stratifying, registry apps' included advisories are 74.1% visible (765 / 1,033)
and no_registry apps' 17.1% (223 / 1,305), a crude gap of **+57.0 points**. Holding the
ecosystem fixed leaves **+41.7**. So ecosystem composition accounts for roughly a
quarter (about 27%) of the crude gap, and about three quarters remain within
ecosystems. This split was not a frozen prediction; it is reported for context only.

## Reconciliation with the arc

- **E1 → E2:** E1's descriptive +49.9 was underpowered; on the pooled frame the
  adjusted effect is +41.7 with a real p-value. The ecosystem-coverage confound is now
  tested and does not explain the gap.
- **A1 / A2:** on this pooled frame the crude gap (+57.0) is the same size as A1/A2's
  (−58.2 and −51.5 points blind), and about three quarters of it survives ecosystem
  adjustment.
- **A3 / A4 / A7:** naming a package, the named package being real, and release cadence
  each explained little of the effect. E2 adds ecosystem coverage to that list.
  What remains is a property of the app (does it ship a registry release?) rather than
  of any single advisory field the studies have measured.
- **Documented mechanism:** GitHub's reviewed advisories are mapped only to packages in
  its twelve supported ecosystems (see
  [`docs/maintainer-checklist.md`](../../docs/maintainer-checklist.md)). E2 is
  consistent with that: the no-package stratum is where no_registry apps are almost
  entirely blind.

## Limits

- **Observational.** E2 compares apps; it does not change one app and watch.
- **One app was not collected.** `grafana/grafana` (no_registry, Go) was skipped
  because one advisory names a package containing spaces (`!grafana snapshot
  service`), which the frozen collector put into a URL unescaped; the run logged it as
  `UNREADABLE (not counted as zero)`. Grafana's repository advisories page lists
  three pages of advisories (well under 100, checked 2026-10-20). Arithmetic on the table above shows
  that even if every Grafana advisory were visible and all fell in the Go stratum (or
  all in `none`), more than 540 of them would be needed to pull the adjusted point
  estimate below +25. So the omission cannot change the decision, but the bug is
  real and is recorded here; the frozen collector was not edited.
- **Six more frame apps contributed no rows** (apache/superset, appwrite/appwrite,
  janhq/jan, mattermost/mattermost, nextcloud/server, jenkinsci/jenkins): the collector
  found no eligible advisories in their repositories' advisory listings. 52 of 59 apps
  enter the test.
- **Classification is frozen, not re-judged.** The registry / no_registry labels come
  from A1/A4 and A2 unchanged. The Maven stratum (only no_registry apps, 64.4% visible)
  shows some no_registry apps' advisories do get bound to Maven coordinates; it is
  excluded from P1 by the frozen usability rule, not by choice.
- **Small strata.** Packagist, PyPI and `other` meet the 2-repos-per-side floor but
  are thin (PyPI has 5 no_registry advisories, `other` 4 registry ones, Packagist 16
  registry ones); their weights are correspondingly small (together about 7% of the
  total). The decision rests mainly on `none`, Go and npm.
- **Inherited label.** `ecosystem_adjusted_meta.json` says "E1" and "no new
  collection" because that text is hard-coded in the frozen E1 analysis code. E2 did
  collect: it re-ran the A4 collector on the 59-app frame (2,341 eligible advisories;
  the 3 rows of the placeholder library `pallets/flask` are dropped as off-frame).
- **Snapshot.** OSV and GitHub as of 2026-10-19/20 (job ran 23:32–02:13 UTC).

## Reproduce

```
# fetch the frozen A4 collector and E1 analysis from main, recording their hashes
python fetch_frozen.py --dest . --out-dir out
# re-collect the pooled 59-app frame (about 2.7 hours, paced, unauthenticated)
python real_package_census.py --frame-dir frame --out-dir out
# run E1's unchanged analysis on the pooled census
python ecosystem_adjusted_analysis.py --census-csv out/real_package_census.csv \
  --classification frame/registry_classification.json --out-dir out
python -m unittest -v test_ecosystem_adjusted_analysis
```

`frame/` holds this folder's `frame_apps.json`, `frame_libs.json` and
`registry_classification.json`. Code that ran (`frozen_code_sha.json`), each
matching the committed file on `main` by git-blob sha:

| file | git blob sha |
|---|---|
| `registry-channel-a4/real_package_census.py` | `def387a9a6cc4b93cfe1fd61df3d509e299bb4c1` |
| `registry-channel-e1/ecosystem_adjusted_analysis.py` | `3c1ee283448fd5bbdd479cedfd432135e5d5ea1f` |
| `registry-channel-e1/test_ecosystem_adjusted_analysis.py` | `2784f015b38a0e0858d2f39b606f325e06148e07` |

Data in this folder: `real_package_census.csv` (pooled census, every eligible
advisory), `ecosystem_census.csv` (with the stratum each advisory was assigned),
`ecosystem_adjusted_summary.json` (P1/P2/P3), `ecosystem_adjusted_meta.json` (input
hashes, thresholds), `frozen_code_sha.json`. The archived advisory pages (2,653 HTML
files) were kept by the job and are not committed. All 17 offline tests passed in the
same run.

Made with AI agents working for MV2 of Munim, Inc.
