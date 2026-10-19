# Result (E1): the ecosystem-coverage confound — inconclusive (underpowered) as pre-registered; descriptively, the registry gap holds within each comparable stratum

**Decision, scored against the frozen plan in
[`PREREGISTRATION-registry-channel-e1.md`](PREREGISTRATION-registry-channel-e1.md):**

- **P1 (primary, ecosystem-adjusted registry effect) is INCONCLUSIVE (underpowered).**
  Only **2** ecosystem strata (`none`, `npm`) have ≥ 2 repositories in both groups. The
  frozen floor was 3, so the analysis code stopped at the verdict and computed **no
  permutation p-value**, as the plan requires. The stratum-weighted adjusted difference
  it reported is **+49.9 pts**. It is shown below as a description, not a test result.
- **P2 (the confound's premise) holds:** registry apps' advisories sit mostly in
  well-indexed ecosystems (mean share 72.5%), and no_registry apps' advisories mostly
  do not (10.5%). The difference is **+62.0 pts**, and none of 10,000 label permutations
  was as extreme.
- **P3 (OSV coverage by ecosystem):** PyPI 81.0%, npm 76.4%, Go 70.1%, Maven 69.1% are
  visible. **Packagist 12.2%** and **`none` (no package named) 10.9%** are mostly blind.
  The Packagist figure is driven by one app naming a package that does not exist (below).

Plain-language finding: the data do not yet license a formal ecosystem-adjusted test.
But the two strata where a fair comparison is possible both show the registry gap
**at full size**. Within advisories that name **no package at all**, where ecosystem
coverage cannot differ by construction, registry apps' advisories are **50.0% visible
vs 4.6%**. Within **npm**, they are **81.5% vs 5.9%**. Nothing here suggests the
registry effect is an OSV-coverage artefact.

E1 is a re-analysis of A4's public census (no new collection). Code frozen and
committed before A4's census existed. Run 2026-10-19 13:42 UTC in a sealed sandbox
(78 s). No human has reviewed this. It was made with AI agents working for MV2 of
Munim, Inc.

## Data

A4's `real_package_census.csv` (sha256 `cc680a3a…0d804`) and the frozen
`registry_classification.json` (sha256 `6f2f559b…59f03`, 32 apps). **25 apps** have
eligible advisories (10 registry, 15 no_registry). That gives **1,429 advisories**
(678 package-typed, 751 software-typed), with 0 excluded as `other`.

## P1: strata where a within-ecosystem comparison exists

| Stratum | Registry: repos, visible/adv (%) | No_registry: repos, visible/adv (%) | Difference | Weight |
|---|---|---|---|---|
| `none` (no package named) | 8 repos, 52/104 (**50.0%**) | 15 repos, 30/647 (**4.6%**) | **+45.4 pts** | 89.6 |
| `npm` | 5 repos, 190/233 (**81.5%**) | 5 repos, 1/17 (**5.9%**) | **+75.7 pts** | 15.8 |
| **Weighted (Mantel–Haenszel style)** | | | **+49.9 pts** | |

Strata **not usable** (fewer than 2 repos on one side): Go (1 vs 1 repo), PyPI (2 vs 1),
Packagist (2 vs 1), Maven (0 vs 2), other (1 vs 2). The 32-app frame simply does not
have registry and no_registry apps naming packages in the same ecosystem often
enough.

**Verdict as frozen: INCONCLUSIVE (underpowered).** The direction and size of both
usable strata match the crude effect (A1: −58.2 pts blind). That points toward "the
effect survives". It does not establish it, and no p-value is claimed.

## P2: ecosystem composition differs sharply by group

| Stratum | Registry apps (adv, repos) | No_registry apps (adv, repos) |
|---|---|---|
| npm | 233 (5) | 17 (5) |
| PyPI | 167 (2) | 1 (1) |
| Go | 99 (1) | 8 (1) |
| Packagist | 16 (2) | 33 (1) |
| Maven | 0 (0) | 94 (2) |
| other | 1 (1) | 9 (2) |
| none | 104 (8) | 647 (15) |

Mean per-app share of advisories in a well-indexed ecosystem (npm, PyPI, Go, RubyGems,
crates.io, Packagist): **72.5% vs 10.5%**. Repository-level permutation: no permutation
in 10,000 as extreme. P2 mostly restates the registry channel itself: no_registry apps'
advisories overwhelmingly name **no package** (647 of 809).

## P3: OSV visibility by ecosystem stratum (both groups pooled)

| Stratum | Visible / n | % | 95% CI |
|---|---|---|---|
| PyPI | 136 / 168 | 81.0 | 74.4–86.2 |
| npm | 191 / 250 | 76.4 | 70.8–81.2 |
| Go | 75 / 107 | 70.1 | 60.8–78.0 |
| Maven | 65 / 94 | 69.1 | 59.2–77.6 |
| other | 6 / 10 | 60.0 | 31.3–83.2 |
| **Packagist** | **6 / 49** | **12.2** | 5.7–24.2 |
| **none** | **82 / 751** | **10.9** | 8.9–13.4 |

**The Packagist row is not evidence that OSV under-indexes PHP.** 33 of its 49
advisories are `coollabsio/coolify`'s, and each one names `composer:coollabsio/coolify`,
a package that **does not exist on Packagist** (A4 resolution `absent`). All 33 are
scanner-blind. On **real** Packagist packages the rate is 6/16 (37.5%): firefly-iii
2/2, snipe-it 4/14. Even that is well below npm/PyPI. Many of snipe-it's blind
advisories have no CVE, which Safeguard's 2026 study also found predicts missing
advisories. This is a small sample of two apps.

A maintainer-actionable note follows. When a self-hosted app names a package
coordinate that was never published (here, a Composer name on an app installed by
script/Docker), the advisory page looks package-bound, but no scanner can match it.
In this frame, that pattern accounted for every Packagist-named advisory from a
no_registry app.

## What E1 does and doesn't settle

- **Settled (descriptively):** where a within-ecosystem comparison exists, the registry
  gap is as large as the crude one. Confound C ("registry apps just live in better-
  indexed ecosystems") cannot explain the `none` stratum, which holds 53% of all
  advisories, because there no ecosystem is named at all.
- **Not settled:** a formal ecosystem-adjusted test. The pre-registration names the
  next step, **E2**: the pooled frame (A1 ∪ A2 ∪ A4 apps, about 59 apps), frozen before
  pooling, so that Go/PyPI/Packagist strata reach two repos per side.

## Erratum to A5

A5's `RESULTS.md` has a parenthetical listing "registry apps with few software-typed
rows", and it includes `appsmithorg/appsmith`, `coollabsio/coolify` and
`ToolJet/ToolJet`. In the frozen classification all three are **no_registry**. A5's
computed tables use the frozen file (for example, goauthentik is shown as no_registry),
so only that prose list was wrong. A dated correction is in
[`../registry-channel-a5/ERRATUM.md`](../registry-channel-a5/ERRATUM.md).

## Reproduce

```
python -I fetch_inputs.py          # A4's census + the frozen E1 code from this repo
python -I ecosystem_adjusted_analysis.py --census-csv real_package_census.csv \
    --classification registry_classification.json --out-dir out
```

Data in this folder: `ecosystem_adjusted_summary.json`, `ecosystem_adjusted_meta.json`,
`ecosystem_census.csv` (A4's rows plus the derived `ecosystem_stratum`, for audit).

Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working for MV2 of
Munim, Inc.
