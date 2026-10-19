# Pre-registration — registry-channel A7: is the registry→visibility effect reducible to a repository-level maintainer-cadence covariate?

**Status:** frozen and published **before** the release-cadence covariate was collected
or analysed. The analysis code (`release_cadence_analysis.py`) and its unit tests
(`test_release_cadence.py`) are committed in the same change and are reused byte-for-byte
at run time. Made with AI agents working for MV2 of Munim, Inc. Apache-2.0 (code) /
CC BY 4.0 (text & data).

Frozen UTC: 2026-10-19.

## Background and why this is new

The advisory-import gap — a maintainer publishes a GitHub repository security advisory,
but it never reaches the global GitHub Advisory Database / OSV, so Dependabot, `pip-audit`,
`npm audit` and OSV scanners cannot flag it — is, for self-hosted applications, strongly
predicted by whether the application also ships through an OSV-indexed language registry
(the **registry channel**): H1 (+53.0 pts, p=0.0057), A2 (−51.5 pts blind, p=0.0077),
A1 out-of-sample (−58.2 pts blind, p=0.0017).

Three mechanism refinements have now *failed* to explain that effect away at the level of a
single advisory:

- **A3 (naming):** the advisory page naming a package mediates only 36% of the gap.
- **A4 (real-package):** the named package being a real, repo-matching registry release
  mediates only 12.8% — and advisories that name a package which exists but points
  elsewhere (`no_match`) are 76.0% visible, as visible as real ones (74.2%).
- **A5/A6 (Go-module rescue):** null.

A4's conclusion was that the effect is **mostly direct** — not reducible to any single
*advisory*-level covariate. The natural next question, and the one this study
pre-registers, is at the **repository** level: maybe "publishes to a registry" is just a
marker for a well-run, frequently-released project whose maintainers are diligent enough
that GitHub reviews and imports their advisories, and the registry channel per se does
nothing. The cleanest, non-circular repository-level proxy for maintainer diligence is
**release cadence**: how many releases the project publishes per year.

**Prior art.** Published measurements of the gap (advisory-import-census v0.9.x;
Safeguard.sh's Oct 2026 studies of 618 and 2,486 repository advisories) control for
maintainer activity only by *selecting* active projects and by matching on topic
(AI/ML vs not), CVE presence and advisory age. None models release cadence as a
repository-level covariate and asks whether the registry→visibility effect survives
holding it fixed. A7 is, to our knowledge, the first such test. A negative, positive or
inconclusive result all count, provided the frame and thresholds below are honoured.

## Sample (frozen)

Every repository that appears in the published A4 census
(`study/registry-channel-a4/real_package_census.csv`) — i.e. the advisories of the 32
out-of-sample self-hosted applications classified in
`study/registry-channel-a4/registry_classification.json` that have at least one eligible
advisory. Group (`registry` / `no_registry`) is taken verbatim from that frozen
classification. Visibility is taken verbatim from the census column `scanner_class`
(`scanner_visible` vs its complement `scanner_blind`), exactly as in A1–A4. No advisory
or visibility datum is re-collected; A7 only *adds* a repository-level covariate.

## Covariate (frozen definition)

For each repository `owner/name` in the sample:

```
releases_per_year = R / age_years
R          = number of published (draft == false) releases returned by the GitHub REST API
             GET /repos/{owner}/{name}/releases, counting pre-releases as releases,
             obtained via the per_page=1 Link rel="last" page number (one request/repo).
age_years  = max(0.5, (measured_utc - created_at) / 365.25 days),
             created_at from GET /repos/{owner}/{name}.
measured_utc = recorded at collection time (after this pre-registration is public).
```

A repository whose metadata or release count cannot be read (HTTP 403/404, or the
unauthenticated GitHub rate limit is exhausted) is recorded `cadence_status = unknown`
and **excluded** from the stratified test; the excluded count is reported.

**Cadence tertiles.** Rank the repositories-with-advisories-and-known-cadence ascending
by `(releases_per_year, repo_name)`; split the ranked list into three contiguous blocks
as equal as possible, the lower-cadence tertiles receiving any extra repositories. Label
`T1` (lowest cadence) … `T3` (highest). This rule is fully deterministic.

## Statistics (frozen)

Visibility is scored as `scanner_visible` (a *higher* rate = more visible = good), so the
registry effect is expected to be **positive** in these units.

- **Total (crude) effect** — reproduces A1 on this sample: pooled advisory-level
  visible-rate difference `registry − no_registry`, repository-level permutation
  (`permutation_test`, 10,000 perms, seed 20261017), copied verbatim from the A4 collector.
- **Adjusted (direct) effect — PRIMARY:** cadence-tertile-stratified, size-weighted
  visible-rate difference
  `direct = Σ_t (n_t / N) · [visible(registry ∩ t) − visible(no_registry ∩ t)]`,
  where `n_t` is the advisory count in tertile `t` and `N` the total; a tertile missing
  one group contributes 0 (disclosed, A4-identical convention). Also reported:
  `direct_defined_only`, re-normalised over tertiles where both groups are present.
- **Adjusted permutation p:** shuffle the repository→group labels **within each cadence
  tertile**, recompute `direct`, two-sided p over 10,000 perms (seed 20261017).
- **Mediated fraction:** `(total − direct) / total`.
- **Descriptive:** Spearman ρ between `releases_per_year` and per-repo visible rate; mean
  `releases_per_year` by group.

## Pre-registered predictions and thresholds

| id | prediction | threshold | role |
|----|------------|-----------|------|
| **P1** | the registry→visibility effect **survives** adjustment for release cadence | `direct ≥ +25.0 pts` AND adjusted `p < 0.05` → **SURVIVES** | primary |
| **P2** | cadence substantially **mediates** the registry effect | `mediated_fraction ≥ 0.50` → cadence explains the effect; report vs A3 (0.36) and A4 (0.128) | mediation |
| **P3** | cadence and visibility co-vary; registry repos release more | Spearman ρ and mean cadence by group | descriptive (no threshold) |

**Power floor.** The primary test is **INCONCLUSIVE_UNDERPOWERED** unless at least **2**
cadence tertiles each contain **both** a `registry` and a `no_registry` repository **and**
at least 4 advisories in each group within that tertile. If registry and no_registry
repositories occupy disjoint cadence tertiles (no within-stratum contrast anywhere), the
result is reported as **CONFOUNDED_INSEPARABLE** — honestly, cadence and registry status
cannot be separated on this sample.

**Falsification clause.** A7 does **not** support a cadence-irreducible registry channel if
`direct < +25 pts` **OR** adjusted `p ≥ 0.05` **OR** `mediated_fraction ≥ 0.50`. Given the
strong prior that registry-publishing projects also release more often, an underpowered or
confounded outcome is a plausible and fully reportable result.

## Verdict rule (frozen)

```
if power_good < 2:                      INCONCLUSIVE_UNDERPOWERED   (CONFOUNDED_INSEPARABLE if power_good == 0)
elif direct >= 25.0 and p < 0.05:       SURVIVES
else:                                   DOES_NOT_SURVIVE
```

## Outputs

`cadence_adjusted_summary.json` (all statistics above, plus per-tertile detail, excluded
repos, and the verdict) and `release_cadence.csv` (one row per repository: group,
releases, repo_age_years, releases_per_year, tertile, eligible advisories, visible,
visible_pct, cadence_status). A `RESULTS.md` will be written and shipped once the job
returns, scoring each prediction against the thresholds above and stating the verdict
plainly, whatever it is.
