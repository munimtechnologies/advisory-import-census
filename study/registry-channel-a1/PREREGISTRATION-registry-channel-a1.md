# Pre-registration (A1): out-of-sample replication of the registry-channel mechanism

**Project:** advisory-import-census (MV2 of Munim, Inc.)
**Frozen:** 2026-10-18, **before any advisory data was collected for this frame.**
The collector has **not** been run on these 32 repositories yet; this document and
`registry_classification.json` were committed first.
**Made with AI agents working for MV2 of Munim, Inc.** Apache-2.0 (code) / CC BY 4.0 (text & data).

## Background and what is new here

Two earlier results are live in this repo:

- **H1 (app-vs-library census, commit `141a3ade`):** self-hosted *applications* are
  far more *scanner-blind* than *libraries* — 53.0% of eligible application
  advisories have no package named in OSV, versus 0% for libraries (repository-level
  permutation test, **p = 0.0057**).
- **H2 (registry-channel A2, commit `310b6bb`):** *within* the same 27 application
  repositories, those that publish their own app code to a public registry OSV
  indexes are **less** scanner-blind than Docker-/binary-only apps
  (**p = 0.0077**, robust p = 0.0001). A2's own stated limitation is that it reuses
  the **same sample** that generated the observation, so it is confirmatory-of-
  mechanism, **not an independent replication.**

**A1 is that missing independent replication.** It applies the *identical* frozen
covariate rule to a **new, out-of-sample frame of 32 self-hosted applications that
share no repository with the earlier frames**, collects their advisories fresh, and
re-runs the *same* permutation test. We are not aware of any prior work that tests,
at the repository level and out-of-sample, whether *having a live app package on an
OSV-indexed registry* predicts whether a repo's own GitHub advisories carry a
machine-matchable package. A clean replication would strengthen a concrete,
low-cost lever for maintainers (publish/attach an official package → scanner
visibility). A null, honestly reported, would bound the A2 effect as sample-specific.

## Frozen frame (the 32 repositories)

Objective inclusion rule (frozen in `registry_classification.json` → `frame.rule`):
widely-used self-hosted **applications** (a runnable self-hosted server/app, not a
library/SDK/framework-only package, not a meta-list), that are (a) **not archived**,
(b) have their **canonical source home on GitHub** (not a read-only mirror of a
project hosted elsewhere, not a repo that has moved off GitHub), and (c) are **none
of the 67 repositories** used in the earlier same-sample frames (27 application
repos + 40 libraries). The candidate pool is the advisory-rich self-hosted apps
enumerated in the project playbook — named in a prior run for being advisory-rich
self-hosted apps, **not** chosen on registry status or blind rate — taking every
repo that passes the filters. Stars read from the GitHub REST API on 2026-10-18.

Excluded by the filters (recorded in advance): `minio/minio` (archived),
`BookStackApp/BookStack` (moved to Codeberg), `zabbix/zabbix` and `moodle/moodle`
(GitHub mirrors whose maintainers do not publish GHSAs there).

## Frozen covariate classification (verified 2026-10-18, before any advisory data)

Same rule as A2. A repo is **`registry`** iff an official, live package on an
OSV-indexed registry (npm, PyPI, crates.io, Go [tagged semver], RubyGems,
Packagist, Maven Central) ships the app's own runnable code; else `no_registry`.
Full per-repo basis and the registry evidence are in `registry_classification.json`.

**`registry` (11):** `open-webui/open-webui` (PyPI open-webui), `strapi/strapi`
(npm @strapi/strapi), `nocodb/nocodb` (npm nocodb), `go-gitea/gitea` (Go, v1.27.3),
`TryGhost/Ghost` (npm ghost), `apache/superset` (PyPI apache-superset),
`directus/directus` (npm directus), `firefly-iii/firefly-iii` (Packagist
grumpydictator/firefly-iii), `grokability/snipe-it` (Packagist snipe/snipe-it),
`element-hq/synapse` (PyPI matrix-synapse), `netbox-community/netbox` (PyPI netbox).

**`no_registry` (21):** `louislam/uptime-kuma`, `grafana/grafana`,
`coollabsio/coolify`, `jellyfin/jellyfin`, `appwrite/appwrite`,
`mastodon/mastodon`, `ClickHouse/ClickHouse`, `metabase/metabase`,
`discourse/discourse`, `janhq/jan`, `ToolJet/ToolJet`, `appsmithorg/appsmith`,
`outline/outline`, `mattermost/mattermost`, `keycloak/keycloak`,
`nextcloud/server`, `goharbor/harbor`, `requarks/wiki`, `jenkinsci/jenkins`,
`zulip/zulip`, `goauthentik/authentik`.

Boundary calls recorded in advance so they cannot be revised after the result:
`uptime-kuma`'s only npm release is a dev pre-release, not the stable channel →
`no_registry`; `outline`'s npm name is an unrelated Meta editor library →
`no_registry`; `zulip`'s PyPI package is the API client, not the server →
`no_registry`; `jenkins`'s WAR is not on Maven Central (it ships from
repo.jenkins-ci.org) → `no_registry`; `keycloak`'s Maven Central dist (26.2.5) lags
the current release (26.8.1), so it is not a live channel → `no_registry`;
`nextcloud/server` is not on Packagist (404) → `no_registry`.

## Analysis plan (frozen)

- **Collect (next step):** run the published census collector
  `app_library_census_html.py` (commit `eb532df`) on the 32 repos in
  `frame_apps.json`, all entered as `application`. It downloads each repo's GitHub
  repository security advisories and, for each eligible advisory, scores whether any
  OSV record (by GHSA id or CVE alias) names a package (`scanner_class`), exactly as
  in H1/H2. No advisory data is consulted for the classification above.
- **Relabel & test:** feed the resulting census CSV and this
  `registry_classification.json` to `registry_channel_analysis.py` (the A2 script,
  unchanged). It relabels each advisory to its repo's `registry`/`no_registry`
  class and runs the census's own repository-level permutation test
  (`permutation_test`, **seed 20261017, 10,000 permutations**, two-sided).
  Statistic = `blind%(registry) − blind%(no_registry)`.
- **Secondary:** the same test on `own_id_not_in_osv`.
- **Robustness (pre-specified):** repeat after dropping the most advisory-heavy repo
  in **each** group; also report each group's repository-median blind rate.
- The test runs on the subset of the 32 repos that have ≥1 eligible advisory; we
  will report how many repos per group that is (repos with 0 advisories drop out,
  exactly as in H1/H2).

## Pre-registered predictions

1. **P1 (primary):** the pooled difference `registry − no_registry` is **negative**
   (registry repos less blind). We claim replication only if the primary two-sided
   **p < 0.05** *and* the sign is negative.
2. **P2:** the repository-median blind rate is lower in `registry` than in
   `no_registry`.
3. **P3 (robustness):** the sign of the difference is unchanged after dropping the
   heaviest repo in each group.

## Honest limitations (stated before the result)

- **Convenience frame.** The candidate pool is the playbook's enumerated
  advisory-rich self-hosted apps, not a random draw from all self-hosted apps. It
  was specified independently of registry status and blind rate, but it is not a
  probability sample, so generalisation beyond "widely-used advisory-rich
  self-hosted apps" is not claimed.
- **Effective N depends on coverage.** Some repos may publish few or no GitHub
  *repository* security advisories (e.g. they may use CVEs via a CNA instead) and
  will drop out, reducing power. Frame balance is 11 vs 21; the tested balance may
  differ and will be reported.
- **Possible null.** As in A2, "ships a package" may be insufficient for scanner
  visibility; a clean, honestly reported null is a valid outcome and bounds A2 as
  sample-specific.
- **Single measure primary.** Two correlated measures (blind, own-id) are reported;
  the primary is `blind`.

## Reproduce (after collection)

The collector (`app_library_census_html.py`, commit `eb532df`) reads a `--frame-dir`
holding `frame_apps.json` **and** `frame_libs.json`; for A1 the libs file is empty
(`[]`), so only the 32 application repos are collected. It writes
`app_library_census.csv`.

```
python app_library_census_html.py --frame-dir .  --out-dir out
    # frame-dir holds frame_apps.json (32 apps) + frame_libs.json ([])
    # -> out/app_library_census.csv  (application rows only)
python registry_channel_analysis.py --csv out/app_library_census.csv \
  --classification registry_classification.json --out-dir out
    # -> out/registry_channel_summary.json, out/registry_channel_per_repo.csv
```
