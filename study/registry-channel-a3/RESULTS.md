# Result (A3): on-page package attribution explains only about a third of the registry-channel gap — the attribution hypothesis is NOT supported as pre-registered

**Study:** registry-channel **A3** — does *naming an affected package on the GitHub
advisory page* mediate the registry-channel effect on scanner visibility?
Pre-registration: [`PREREGISTRATION-registry-channel-a3.md`](PREREGISTRATION-registry-channel-a3.md)
(frozen 2026-10-18, before any A3 data was collected). Collected 2026-10-19 (snapshot
`2026-10-19T02:12:20Z`) by AI agents working for MV2 of Munim, Inc. No human has
reviewed this result; it is reported against the frozen predictions, whichever way
they fell.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## What was tested

A1 and A2 showed *that* self-hosted applications which publish their own code to an
OSV-indexed package registry are far less "scanner-blind" than Docker-/binary-only
applications. A3 asked *why*, testing the simplest mechanism: a GitHub repository
advisory becomes visible to OSV-based scanners only when it names an affected package
in a supported ecosystem (rendered on the page as a **Package** box with an
`ecosystem:<name>` link, versus a generic **Software** box). If that is the whole
story, registry apps are less blind *because* their advisories name packages, and
conditioning on "names a package" should remove the registry gap.

## Coverage

- Frame: the identical 32 applications of A1 (`frame_apps.json`), 11 `registry` and
  21 `no_registry` (`registry_classification.json`, frozen 2026-10-18). No repository
  was added or relabelled.
- 26 repositories had ≥1 eligible (published, ≥14 days old) advisory: 10 registry
  (620 advisories) and 16 no_registry (837). Six had none (appwrite, jan, mattermost,
  nextcloud/server, jenkins, superset), exactly as in A1.
- Eligible advisories: **1,457**, all 1,457 detail pages fetched and archived
  (`raw/`), 0 detail failures, 0 unreadable repositories. OSV canary
  `GHSA-39mp-8hj3-5c49` resolved.
- Product type parsed from every page: **680 `package`**, **777 `software`**,
  **0 `other`** (the pre-registered >10% `other` parse-failure rule was not
  triggered).
- The fresh snapshot reproduced A1's visibility gap to the decimal: registry 73.4%
  visible (455/620) vs no_registry 15.2% (127/837), total effect **58.2 points**.

## Results against the pre-registered predictions

| Prediction | Pre-registered threshold | Observed | Met? |
|---|---|---|---|
| **P1** attribution → visibility, within apps (16 repos with both types; within-repo label permutation, 10,000 perms, seed 20261017) | ≥ +40 pts and p < 0.05 | package 69.6% (403/579) vs software 36.1% (101/280) = **+33.5 pts, p = 0.0107** | **No** — direction and significance hold, magnitude below the threshold |
| **P2** registry status → attribution (repo-level permutation, 26 repos) | > 0 and p < 0.05 | package-type rate 83.2% (516/620) vs 19.6% (164/837) = **+63.6 pts, p = 0.0053** | **Yes** |
| **P3** attribution mediates the registry → visibility effect | mediated fraction ≥ 0.50 and \|direct\| < \|total\| | total 58.2 pts, direct 37.2 pts, mediated 21.0 pts, **mediated fraction 0.36** | **No** — \|direct\| < \|total\| holds, but only 36% of the gap is mediated |
| **P4** residual slack (descriptive, no threshold) | package-type < 100% visible; software-type > 0% but small | package-type **70.6%** visible (480/680; CI 67.1–73.9%); software-type **13.1%** visible (102/777; CI 10.9–15.7%) | reported |

**Verdict: the on-page attribution hypothesis is not supported as pre-registered.**
Naming a package on the advisory page is strongly associated with visibility (P1) and
registry apps do name packages far more often (P2), but conditioning on it removes
only about a third of the registry gap (P3). Two of the four pre-registered thresholds
were missed, so A3 is reported as a **partial null**: attribution is *part* of the
mechanism, not the mechanism.

## The decisive split: within package-named advisories, registry apps stay far more visible

The pre-registration named this as the quantity that decides between "naming is all
that matters" and "what matters is whether the named package is a real registry
release":

| Stratum (product type on the page) | registry visible | no_registry visible | difference |
|---|---|---|---|
| `package` (names an ecosystem package) | **78.1%** (403/516) | **47.0%** (77/164) | **+31.1 pts** |
| `software` (generic product box) | 50.0% (52/104) | 7.4% (50/673) | +42.6 pts |

If naming were sufficient, the `package` row would show ≈0 difference. Instead a
no_registry app's advisory that names a package is visible less than half the time,
while a registry app's is visible more than three quarters of the time. That is the
pattern the coolify counter-example predicted: `coollabsio/coolify` (no_registry)
names a package on 39 of its 70 advisories (Packagist/npm `coolify`) and **0 of 70
are visible**; `appsmithorg/appsmith` (no_registry) names a package on 27 of 41 and
3 are visible; `ToolJet/ToolJet` names one on 5 of 12 and 0 are visible. Naming a
package that is not the project's real, GitHub-reviewable registry release does not
make an advisory visible. The refined mechanism — *the named package must be a real,
repo-matching registry release* — is exactly what the already pre-registered A4 study
measures directly from registry metadata
([`../registry-channel-a4/`](../registry-channel-a4/)).

## The residuals, and what they say about where the package comes from

**Software-type yet visible (102 of 777).** These advisories show no package on the
repository page, yet OSV holds a record that names one. Counted from
`attribution_census.csv` they are concentrated in a few repositories, and in every
case the OSV record names the project's own registry package:

| repo | group | software-type & visible | package OSV names |
|---|---|---|---|
| grokability/snipe-it | registry | 35 | Packagist `snipe/snipe-it` |
| grafana/grafana | no_registry | 20 | Go `github.com/grafana/grafana` |
| goharbor/harbor | no_registry | 11 | Go `github.com/goharbor/harbor` |
| goauthentik/authentik | no_registry | 7 | Go `goauthentik.io`, npm `@goauthentik/api` |
| open-webui/open-webui | registry | 6 | PyPI `open-webui` |
| keycloak/keycloak | no_registry | 6 | Maven `org.keycloak:*` |
| louislam/uptime-kuma | no_registry | 5 | npm `uptime-kuma` |
| nocodb, gitea, directus, firefly-iii, synapse, jellyfin | mixed | 1–3 each | the project's npm/Go/Packagist/PyPI/NuGet package |

So when a maintainer leaves the package box empty, GitHub's advisory curators
sometimes attach the package themselves during review — and they do so for Go
modules in particular (grafana, harbor, authentik), where the module path is the
repository path and needs no registry publication. This is an **honest limit of the
A3 measure**: the repository page shows what the *maintainer* entered, not what the
*reviewed global record* contains, and the two differ for 102 advisories here.

**Package-type yet blind (200 of 680).** By repository (package-typed minus
package-typed-and-visible, from the per-repo table and the rows above): coolify 39,
gitea 29, appsmith 24, Ghost 24, open-webui 20, Directus 19, synapse 11, keycloak 10,
snipe-it 10, ToolJet 5, harbor 3, uptime-kuma 2, requarks/wiki 2, grafana 1,
authentik 1. Two different things are mixed here: no_registry apps naming a package
that is not a real release of theirs (coolify, appsmith, ToolJet — the A4 question),
and registry apps whose named package *is* real but whose advisory has not been
reviewed into the global database (gitea, Ghost, open-webui, Directus — the
GitHub→OSV review-lag question, the vein planned after A4).

## Robustness (pre-specified)

- **R1** (drop the heaviest repo per group: discourse/discourse and
  open-webui/open-webui): P2 keeps sign and significance, +48.3 pts, p = 0.0214
  (24 repos). Holds.
- **R2** (ecosystem split of package-type advisories, visible %): npm 76.8% (195/254),
  pip 81.1% (137/169), Go 69.7% (76/109), Maven 68.4% (65/95), **Composer 12.2%
  (6/49)**, helm 0% (0/1), docker 82.1% (23/28). The Composer figure is almost
  entirely coolify's 39 blind Packagist-named advisories, so it is the coolify effect
  under another name, not a property of Packagist (snipe-it and firefly-iii, the real
  Packagist projects, are visible). The `docker` and `helm` coordinates are names the
  advisory form accepted; neither is an OSV-indexed ecosystem. The 28 `docker`-tagged
  advisories are open-webui 18 (all visible), uptime-kuma 7 (5 visible) and appsmith
  3 (none visible); the visible ones are visible through the project's pip or npm
  package in the OSV record, which the page also names in all but two cases
  (open-webui `GHSA-x3qm-p8hr-3c3h` and uptime-kuma `GHSA-g9v2-wqcj-j99g` name only
  `docker` on the page, so there the reviewers attached the package). An advisory
  counts once per ecosystem it names.
- **R3** (secondary measure `own_id_in_osv` instead of `scanner_visible`): identical
  to P1, +33.5 pts, p = 0.0107 — in this sample every advisory whose own GHSA id is
  in OSV also has an OSV package, and vice versa. Sign reproduced.

## Per-repository table

`attribution_per_repo.csv` (eligible, visible, visible %, package, software, other).
Extremes: nocodb and strapi 100% visible with every advisory package-typed;
discourse (297), mastodon (57), metabase (44), zulip (41), outline (26) and
ClickHouse (7) 0% visible with every advisory software-typed; coolify 0% visible
despite 39 package-typed advisories; keycloak (no_registry) 81.9% visible with 72
package-typed advisories naming Maven artifacts that GitHub does review (its Maven
Central channel was classified "not live" under the frozen rule because it lags
releases, which is a limit of the covariate, not of the measure).

## Limits

- Association, not causation; a convenience frame of 32 widely used self-hosted
  apps, reused from A1 (so this is the same sample as A1, re-measured with one new
  variable, not a new replication).
- The attribution variable is what the **repository page** shows; reviewed global
  records can differ (102 cases above). A3 could not see whether a named package is
  real — that is A4's measurement.
- The within-repo P1 test uses only the 16 repositories with both product types;
  the 10 all-package or all-software repositories contribute to P2–P4 only.
- Ecosystem mix differs between groups (registry apps skew npm/pip; no_registry apps
  skew Go/Maven/none), so R2 is a description, not a controlled comparison.
- Counts are a one-day snapshot (2026-10-19); advisories younger than 14 days are
  excluded, and visibility can change as GitHub reviews older advisories.

## Reproduce

```
python -m unittest -v test_attribution
python -I attribution_census.py --frame-dir . --out-dir out
python -I attribution_analysis.py --csv out/attribution_census.csv \
    --classification registry_classification.json --out-dir out
```

Outputs in this directory: `attribution_summary.json` (P1–P4, robustness, per-repo),
`attribution_per_repo.csv`, `attribution_census.csv` (one row per eligible advisory
with product type and named ecosystems). The archived HTML (`raw/`, 1,632 files) is
kept with the compute result and can be re-parsed with `attribution_census.py` to
audit any row.

Made with AI agents working for MV2 of Munim, Inc.
