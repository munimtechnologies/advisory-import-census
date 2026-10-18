# Pre-registration: is the advisory-import gap a *registry-channel* effect within applications?

**Project:** advisory-import-census (MV2 of Munim, Inc.)
**Frozen:** 2026-10-18, before the permutation test was run.
**Made with AI agents working for MV2 of Munim, Inc.** Apache-2.0 (code) / CC BY 4.0 (text & data).

## Background

The confirmed application-vs-library census
([`study/app-vs-library/RESULTS.md`](../app-vs-library/RESULTS.md), committed at
`141a3ade`) established **H1**: self-hosted **applications** are far more
*scanner-blind* than **libraries**. 53.0% of eligible application advisories have
no package named in OSV (so a dependency scanner reading OSV cannot match them),
versus 0% for libraries — a +53.0 point gap, repository-level permutation test
**p = 0.0057** (32 repositories, seed 20261017, 10,000 permutations).

That write-up also recorded an **exploratory observation** (obs #2): *within*
applications, the visible repos looked like the ones that also ship a package to
a public registry (gogs, payload, copyparty, lobehub, …), while the ~100%-blind
ones looked like the Docker-only apps (Immich, paperless-ngx, Plane, …). Obs #2
was a hypothesis *generated from* the data, never tested. This document turns it
into a falsifiable test with a crisp, objective, pre-registered covariate.

## Why this may be new

OSV/GHSA "package coverage" has been studied at the *ecosystem* level, but we are
not aware of prior work testing, at the **repository** level and within a single
application frame, whether *having a live package on a registry that OSV indexes*
predicts whether a repo's own GitHub advisories carry a machine-matchable package
at all. If it holds, it gives maintainers a concrete, low-cost lever (publish an
official package, or ask GitHub to attach one) to make their advisories visible
to scanners. If it does not, it rules out the simplest explanation and points the
cause elsewhere (e.g. GHSA reviewer policy for end-applications).

## Hypothesis

**H2 (registry channel):** Among application repositories that have eligible
advisories, those whose project publishes its own application code to a public
language registry OSV indexes have a **lower** repository-level blind rate than
those distributed only as Docker images / binaries / source.

## Frozen classification rule (the covariate)

A repository is **`registry`** iff there exists at least one public package, on a
language registry whose ecosystem OSV/GHSA indexes (npm, PyPI, crates.io, Go
[`proxy.golang.org`, **with a tagged semantic-version release**], RubyGems,
Packagist, Maven Central), that

- (a) is **official** to the project (published by the project; its registry
  metadata points back to the same GitHub repo), **and**
- (b) contains the application's **own source/build code** (a runnable server,
  CLI, desktop app, or the framework that *is* the product) as a **live channel**
  — the latest published version tracks a real/current release, not a placeholder,
  name reservation, abandoned stub, or (for Go) a pseudo-version with no tag.

Explicitly **not** `registry`: client SDKs / API wrappers that only talk to a
separately-hosted instance; helper CLIs that drive a remote instance; Docker/OCI
images; prebuilt OS binaries or installer assets attached to GitHub releases.
Everything else is **`no_registry`**.

The rule is a **distribution fact about the project**, assigned and verified
against the registry on 2026-10-18 **independently of the advisory data**. The
full per-repository basis is frozen in
[`registry_classification.json`](registry_classification.json).

## Frozen classification of the 27 application repositories with advisories

**`registry` (12):** `n8n-io/n8n` (npm n8n), `coder/code-server` (npm),
`9001/copyparty` (PyPI), `getsentry/sentry` (PyPI server), `payloadcms/payload`
(npm), `laurent22/joplin` (npm joplin CLI), `DIYgod/RSSHub` (npm rsshub),
`gogs/gogs` (Go, v0.11.91), `syncthing/syncthing` (Go, v1.30.0),
`usememos/memos` (Go, v0.31.0), `pocketbase/pocketbase` (Go framework, v0.40.5),
`lobehub/lobehub` (npm @lobehub/chat).

**`no_registry` (15):** `immich-app/immich`, `Stirling-Tools/Stirling-PDF`,
`hoppscotch/hoppscotch`, `dani-garcia/vaultwarden`, `pi-hole/pi-hole`,
`penpot/penpot`, `makeplane/plane`, `twentyhq/twenty`, `huginn/huginn`,
`calcom/cal.diy`, `siyuan-note/siyuan`, `paperless-ngx/paperless-ngx`,
`RocketChat/Rocket.Chat`, `LibreChat-AI/LibreChat`,
`reactive-resume/reactive-resume`.

Boundary calls recorded in advance so they cannot be revised after seeing the
result: `twenty`'s npm package is the *CLI client*, not the CRM → `no_registry`;
`immich`'s npm package is a *deprecated CLI client* → `no_registry`;
`vaultwarden`'s crate is an abandoned `0.0.1` placeholder while the app ships at
1.x → `no_registry`; `siyuan`'s Go kernel has only pseudo-versions (no tagged
release) → `no_registry`; `huginn`'s and `hoppscotch`'s only same-named registry
packages are third-party/unrelated → `no_registry`.

## Analysis plan (frozen)

- **Input:** the application rows of `app_library_census.csv` committed at
  `141a3ade` (909 eligible advisories across these 27 repos). No re-collection.
- **Relabel** each advisory's group from `application` to its repository's
  `registry` / `no_registry` class.
- **Primary test:** the census's **own** repository-level permutation test
  (`permutation_test`, copied verbatim; pooled blind rate per group, labels
  permuted across repositories, **seed 20261017, 10,000 permutations**), reported
  two-sided. Statistic = `blind%(registry) − blind%(no_registry)`.
- **Secondary:** the same test on `own_id_not_in_osv`.
- **Robustness (pre-specified):** repeat the primary test after dropping the most
  advisory-heavy repository in **each** group (so `n8n-io/n8n` and
  `siyuan-note/siyuan`-type heavy hitters cannot decide the result alone). Also
  report each group's **repository-median** blind rate (a per-repo, not
  advisory-weighted, view).
- **Code (frozen with this document):**
  [`registry_channel_analysis.py`](registry_channel_analysis.py), tested offline
  by [`test_registry_channel.py`](test_registry_channel.py). Executed in the
  sealed MV2-Compete sandbox, downloading the pinned CSV from
  `raw.githubusercontent.com/...141a3ade/...`.

## Pre-registered predictions

1. **P1 (primary):** the pooled difference `registry − no_registry` is **negative**
   (registry repos less blind). We claim H2 only if the primary two-sided
   **p < 0.05**.
2. **P2:** the repository-median blind rate is lower in `registry` than in
   `no_registry`.
3. **P3 (robustness):** the sign of the difference is unchanged after dropping the
   heaviest repo in each group.

## Honest limitations (stated before the result)

- **Same sample.** This reuses the exact 27 repositories that generated obs #2, so
  it is **confirmatory-of-mechanism on the generating sample, not an independent
  replication.** A strong test needs a *new* application frame; that is the planned
  next step.
- **Known counter-signal.** `n8n-io/n8n` (npm, `registry`) is itself largely blind
  in the data, and the overall application blind rate is high (repo-median 93.8%).
  The effect may therefore be small, or **null**. A clean null, honestly reported,
  is a real result: it would mean "ships a package" is **not** sufficient for
  scanner visibility, and the cause lies in how GitHub/OSV attach packages to
  end-application advisories.
- **Low power / imbalance.** 12 vs 15 repositories, unit = repository.
- **Multiplicity.** Two correlated measures (blind, own-id) are reported; the
  primary is `blind`.

## Reproduce

```
python registry_channel_analysis.py \
  --csv app_library_census.csv \
  --classification registry_classification.json \
  --out-dir out
```
(`app_library_census.csv` = the file committed at `141a3ade`.) Outputs
`registry_channel_summary.json` and `registry_channel_per_repo.csv`.
