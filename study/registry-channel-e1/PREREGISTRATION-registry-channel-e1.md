# Pre-registration — registry-channel E1: the ecosystem-coverage confound

**Study:** registry-channel **E1** — does the registry→scanner-visibility effect
(registry-publishing self-hosted apps' own advisories reach vulnerability scanners
far more often) **survive adjusting for the OSV ecosystem** each advisory's package
belongs to, or is it partly an artefact of OSV covering some ecosystems better than
others?

**Registered:** 2026-10-19, by AI agents working for MV2 of Munim, Inc., **before the
A4 collector result was read** (A4 was still queued in the shared compute queue at
registration time, after a sandbox restart). E1 is a **re-analysis**: it adds **no new
data collection and no new compute job** — it is computed entirely from the A4 study's
`real_package_census.csv`, whose columns are fixed by the already-public A4
pre-registration (committed 2026-10-19). The frame, classification, visibility measure,
permutation seed and eligibility are reused verbatim from A1/A4. The predictions below
are registered before A4's census is read.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## The alternative explanation E1 tests

The pre-registered chain establishes a strong registry covariate:

- **H1:** apps are +53.0 pts more scanner-blind than libraries (p=0.0057).
- **A2:** within apps, registry-publishing apps are −51.5 pts less blind (p=0.0077).
- **A1:** replicated out of sample, −58.2 pts (p=0.0017).
- **A3:** *naming* a package mediates only 36% of the effect (partial null).
- **A4 (pending):** whether the named package is a **real, repo-matching registry
  release** is the sharper candidate mechanism.

All of these treat "reaches OSV" as one outcome. But **OSV is not uniform across
ecosystems.** OSV ingests GitHub-reviewed advisories plus per-ecosystem feeds
(npm via GHSA, PyPI via PyPA, Go via the Go vuln DB, RubyGems, crates.io, Packagist),
and historically indexes some ecosystems more completely than others. This raises a
confound that none of H1/A2/A1/A3/A4 isolates:

> **Confound C:** registry apps may simply publish to **well-indexed** ecosystems
> (npm, PyPI, Go), while no_registry apps, on the rare advisory that names a package
> at all, name it in a **less-indexed** ecosystem — so the registry "effect" would be
> re-describable as an **ecosystem-coverage** effect, not a property of registry
> publishing per se.

A4's own robustness check R2 *splits `real` advisories by ecosystem descriptively*,
but it does **not** estimate the registry effect **holding ecosystem fixed**. E1 does
exactly that: a stratified (ecosystem-adjusted) estimate of the registry→visibility
difference, with a stratified permutation test. This is the standard way to tell a
real covariate from a confounded one, and it has not been done for self-hosted-app
advisory visibility before (prior art checked below).

## Frame, measure, data (all reused — no re-selection, no new fetch)

- **Frame:** the identical 32 self-hosted applications in A4's `frame_apps.json`,
  classified `registry` (11) vs `no_registry` (21) in `registry_classification.json`
  (frozen 2026-10-18). E1 adds **no** repositories and changes **no** labels.
- **Visibility measure:** the shared `classify` — an advisory is `scanner_visible`
  when OSV holds a record (by GHSA id or CVE alias) naming ≥1 package, else
  `scanner_blind`. Eligibility: published and ≥14 days old at the A4 snapshot. Scored
  by A4; E1 reuses A4's `scanner_class` column verbatim.
- **Input:** A4's `real_package_census.csv` (one row per eligible advisory, with
  `repo`, `group`, `product_type`, `named_packages` (ecosystem+name coordinates),
  `named_pkg_resolution`, `real_package`, `scanner_class`). **No network, no sandbox
  collection** — E1's analysis script reads this CSV and the frozen classification only.

## New derived variable: the ecosystem stratum

For each eligible advisory, E1 assigns exactly one **ecosystem stratum** from A4's
already-parsed `named_packages`, by a frozen rule:

- If `product_type == package` with ≥1 named package: the stratum is the **ecosystem
  of the named-package coordinate that appears first in the archived advisory HTML**
  (the order A4 already records in `named_packages`); ties within the same position
  are broken by case-insensitive alphabetical ecosystem name. Possible ecosystems:
  `npm`, `PyPI`, `Packagist`, `RubyGems`, `crates.io`, `Go`, `Maven`, `NuGet`, `other`.
- If `product_type == software` (no named package): stratum = **`none`**.
- If `product_type == other`: **excluded** (as A3/A4 exclude `other`).

The stratum is derived with **no network request and no visibility input** — it is a
pure re-labelling of A4's package column, so it cannot be circular with the outcome.
Every advisory's stratum is written to E1's output CSV for audit against A4's archive.

## Hypotheses and pre-registered predictions

Let **visible** = `scanner_class == scanner_visible`. "Usable stratum" = an ecosystem
stratum containing ≥1 `registry` **and** ≥1 `no_registry` repository that each have ≥1
eligible advisory in that stratum (both groups present, so a within-stratum contrast
exists).

**P1 — the registry effect survives ecosystem adjustment (primary).**
The **stratum-size-weighted** pooled registry−no_registry visible-rate difference
across all usable strata (a Mantel–Haenszel-style common difference) is **positive and
≥ +25 points**, and a **stratified label-permutation test** (the `registry` /
`no_registry` repository labels permuted **within each ecosystem stratum
independently**, 10,000 permutations, seed 20261017) gives **p < 0.05**.
*Rationale for +25, not the ~51–58 pt crude effect:* adjustment should attenuate the
estimate if any ecosystem confounding exists, but if registry publishing is a real
mechanism the adjusted effect must stay clearly positive and significant.

**P2 — the confound's premise: ecosystem composition differs by group (descriptive +
test).** The distribution of advisories over ecosystem strata differs between
`registry` and `no_registry` apps. Reported as a per-group stratum table plus a
repository-level permutation test on the share of each app's advisories that fall in a
**well-indexed** stratum (frozen set: `npm`, `PyPI`, `Go`, `RubyGems`, `crates.io`,
`Packagist`); difference **> 0** with its permutation p. (If P2 is null — groups do not
differ by ecosystem — then Confound C is empty and P1 is expected to equal the crude
effect; this is reported, not hidden.)

**P3 — OSV coverage varies by ecosystem (descriptive).** Visible-rate **by ecosystem
stratum**, pooled over both groups, with k/n per stratum. This quantifies *which*
ecosystems OSV indexes well and whether the `none` (software-typed) stratum is the
blindest. No threshold; purely the confound's mechanism, laid out.

## Power floor (pre-specified, to avoid mislabelling thin data as a null)

With only 32 apps the usable strata will be few and small. Therefore:

- A stratum with **<2 repositories in either group** is **not usable** and is excluded
  from P1 (reported in the stratum table as single-group).
- If **fewer than 3 usable strata** exist, **or** the usable strata together contain
  **fewer than 6 repositories**, P1 is reported **INCONCLUSIVE (underpowered)**, not as
  support or a null. In that case E1's contribution is P2+P3 (the confound's size and
  OSV's per-ecosystem coverage) plus an honest statement that the 32-app frame cannot
  adjust for ecosystem, and E1 names the larger frame (A1∪A2∪A4 pooled) that a future
  pre-registered E2 would need.

## What each outcome means (registered before the run)

- **P1 holds (adjusted effect ≥ +25 pts, p<0.05):** the registry→visibility effect is
  **not** merely OSV ecosystem coverage — registry publishing predicts visibility even
  comparing advisories *within the same ecosystem*. This strengthens A1/A2/A4.
- **P1 fails (adjusted effect < +25 pts or loses significance) while P2 holds:** the
  registry effect is **substantially a coverage confound** — registry apps look safer
  largely because they live in ecosystems OSV indexes. That is a genuine, important
  negative result: it bounds the earlier studies' causal reading and tells
  self-hosted maintainers in thinly-indexed ecosystems that *publishing to a registry
  will not, by itself, get their advisory to scanners*.
- **P1 INCONCLUSIVE (power floor):** honest; E1 reports the confound's size (P2) and
  OSV's per-ecosystem coverage (P3) and defers the adjusted estimate to a pre-registered
  larger-frame E2.

## What would falsify "the registry effect is a real, ecosystem-independent mechanism"

The adjusted effect (P1) dropping below +25 pts **or** losing significance (p ≥ 0.05)
while P2 confirms the groups differ by ecosystem. Either means the registry covariate
is, in substantial part, an OSV-coverage artefact, and E1 is written up as that result.

## Prior art (why this is new)

Searched GitHub, OSV documentation, and the advisory-ecosystem literature: OSV's own
docs describe per-ecosystem ingestion, and several studies measure CVE/advisory
coverage gaps, but **no public work estimates the registry-publishing effect on a
self-hosted application's *own* advisory reaching scanners while holding the package's
ecosystem fixed.** H1/A1/A2/A3/A4 (this repo) are the only pre-registered measurements
of the effect, and none adjusts for ecosystem. E1 is the first ecosystem-adjusted
estimate on this question; a confirmatory null would be equally novel.

## Outputs

`ecosystem_adjusted_summary.json` (P1 adjusted difference + permutation p + usable
strata, P2 per-group stratum table + test, P3 per-ecosystem visible-rate, power-floor
verdict), `ecosystem_census.csv` (A4's rows plus the derived `ecosystem_stratum`), and
`ecosystem_adjusted_meta.json` (input CSV sha, counts, excluded `other`). RESULTS.md is
written from these, honestly, whichever way the predictions fall.

## Sequencing (so this document provably precedes the result)

E1 is registered now, while A4 is still queued, so this frozen plan demonstrably
precedes A4's census. E1 launches **no compute job of its own**: once A4's
`real_package_census.csv` is produced, E1's analysis script is run against it (it needs
no network), or, if the sandbox is used, as a cheap `poc` re-analysis step. Registering
E1 before reading A4 fixes these predictions so the ecosystem-adjustment cannot be
tuned after seeing the data.

Made with AI agents working for MV2 of Munim, Inc. No result here has been reviewed by
a human.
