# Pre-registration — E2: pooled-frame ecosystem-adjusted test

**Study:** registry-channel-e2
**Status:** FROZEN. This file and the three frozen frame files in this directory
(`frame_apps.json`, `frame_libs.json`, `registry_classification.json`) are committed
to the public repository *before* the pooled census is collected or read. No pooled
data has been looked at when this plan is written.
**Made with AI agents** working for MV2 of Munim, Inc. No result here has been
reviewed by a human.

## Why E2 exists

E1 asked whether the registry → scanner-visibility effect survives holding each
advisory's OSV ecosystem fixed. On the 32-app A4 frame only **2** ecosystem strata
(`none`, `npm`) had ≥2 repositories on each side, below E1's own floor of 3 usable
strata, so E1's primary test P1 was reported **INCONCLUSIVE (underpowered)**. The
adjusted difference was descriptively **+49.9 points** and P2 (ecosystem composition
differs by group) held, but no permutation p-value could be computed.

E1 named the fix: pool a larger frame so the Go / PyPI / Packagist strata each reach
≥2 repositories per side. E2 is that pooled re-run of E1's *identical* frozen
analysis — nothing about the test changes except the frame it runs on.

## Pooled frame (frozen)

The pooled frame is the **union, deduplicated by repository**, of the application
sets of three earlier frozen frames:

- **A1 / A4** (`study/registry-channel-a1`, `study/registry-channel-a4`): the same
  32-app frame (11 registry, 21 no_registry). A1 and A4 use an identical
  `frame_apps.json` and `registry_classification.json`, verified 2026-10-19.
- **A2** (the base `study/registry-channel` study, same-sample channel): the 27
  classified apps of its `registry_classification.json` (12 registry, 15 no_registry),
  drawn from `study/app-vs-library/frame_apps.json`.

The two classified sets are **disjoint** (no repository appears in both), so the
union is 32 + 27 = **59 apps: 23 registry, 36 no_registry**. The exact list and
labels are frozen in `frame_apps.json` and `registry_classification.json` beside
this file. Deduplication rule, stated for completeness even though no collision
occurs: if a repository appeared in more than one source it would be kept once, and
if its labels disagreed the A4 label would win and the conflict would be reported;
neither case arises here.

`frame_libs.json` carries a single placeholder library (`pallets/flask`) only so the
censuser's library loop is non-empty; library rows are **not** in
`registry_classification.json` and are therefore dropped by the analysis, which is
application-only. They do not enter any E2 number.

## Census (frozen code, re-run uniformly)

The A1/A4 census and the A2 census were produced by different, older collectors with
different columns (A1's `app_library_census.csv` has no per-advisory package
coordinate). To pool cleanly, the **whole** 59-app frame is re-censused with one
frozen collector: `study/registry-channel-a4/real_package_census.py` (standard-library
only, unchanged). Its exact bytes are fetched from the repository at run time and the
sha256 + git-blob-sha of what ran are recorded to `frozen_code_sha.json`, so the code
that produced the numbers is auditable. The census yields, per advisory: product type,
listed OSV ecosystems, the named-package coordinates in the advisory HTML, whether the
named package resolves to a real registry package, and the scanner-visibility class.

## Analysis (frozen code, identical to E1)

The pooled census is handed to the **unchanged** E1 analysis,
`study/registry-channel-e1/ecosystem_adjusted_analysis.py`, with the pooled
`registry_classification.json`. Every rule is E1's:

- **Ecosystem stratum per advisory** (`derive_stratum`): `software` product →
  `none`; `package` product → canonical ecosystem of the **first** named-package
  coordinate in page order (`named_package_first`), else the first alphabetically
  sorted listed ecosystem (`ecosystem_fallback`), else `other`; `other` product →
  excluded. Canonicalization via E1's `ECO_CANON`.
- **P1 (primary):** stratum-weighted (Mantel–Haenszel, weight `n1*n0/(n1+n0)`) common
  risk difference in OSV-visible rate between registry and no_registry apps, over
  **usable** strata (≥2 repositories in **each** group). Within-stratum label
  permutation, **seed 20261017, 10000 permutations**. Power floor:
  **INCONCLUSIVE_UNDERPOWERED** if fewer than 3 usable strata or fewer than 6 distinct
  repositories; otherwise **SURVIVES** iff adjusted difference ≥ **+25 points** and
  permutation p < **0.05**; else **DOES_NOT_SURVIVE**.
- **P2:** per-app share of advisories in a well-indexed stratum
  (`npm, PyPI, Go, RubyGems, crates.io, Packagist`); repository-level permutation test
  on the registry − no_registry mean-share difference (> 0).
- **P3 (descriptive, no threshold):** pooled OSV-visible rate per ecosystem stratum
  with k/n and a Wilson 95% CI.

## Predictions (frozen)

1. **Primary:** with N roughly doubled, **≥3 usable strata** qualify — in particular
   at least one of Go, PyPI and Packagist reaches ≥2 repositories per side — so a real
   permutation p-value is computable and P1 is **no longer underpowered**.
2. **Direction:** P1 **SURVIVES** — adjusted difference ≥ +25 points, p < 0.05 —
   consistent with E1's descriptive +49.9 and with the whole arc (H1 +53.0; A1 −58.2
   blind; A2 −51.5 blind). The registry → visibility gap is **not** merely an
   artefact of OSV indexing some ecosystems better than others.
3. **P2** holds (registry apps' advisories sit in better-indexed ecosystems).
4. **P3:** Packagist stays low and `none` stays low; PyPI / npm / Go stay high. The
   one-app Packagist artefact seen in E1 (coolify naming a package absent from
   Packagist) is diluted but not reversed.

A result that contradicts any of these — too few usable strata again, or a
non-surviving / reversed adjusted difference — will be reported plainly as such.
A negative or inconclusive outcome is a real result and will be published unchanged.

## Outputs

`real_package_census.csv` (pooled), `ecosystem_census.csv`,
`ecosystem_adjusted_summary.json`, `ecosystem_adjusted_meta.json`,
`frozen_code_sha.json`. The RESULTS.md will lead with the P1 verdict
(SURVIVES / DOES_NOT_SURVIVE / INCONCLUSIVE_UNDERPOWERED), list usable vs unusable
strata with repos per side, and give P2 and P3.
