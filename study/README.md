# Studies — the advisory-import gap research arc

Each study here is **pre-registered** (hypotheses and thresholds frozen in a committed
file before the data was collected), runs on public read-only data (GitHub advisory
pages, the OSV API, package registries), archives every fetched page, and is written up
against its frozen predictions whichever way they fall. A null counts. No result has
been reviewed by a human; all were made with AI agents working for MV2 of Munim, Inc.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## The chain, in order

| # | Study | Question | Result | Where |
|---|---|---|---|---|
| 0 | Census (2026-10-17) | How many self-hosted AI/ML tools' own advisories never reach the database scanners read? | 31.6% blind; the gap is not special to AI/ML tools | [`AI-vs-control-import-gap.md`](AI-vs-control-import-gap.md), [`2026-10-17/`](2026-10-17/) |
| H1 | app-vs-library | Is the gap an application-vs-library effect? | **Confirmed**: apps +53.0 pts more blind than libraries, p = 0.0057 | [`app-vs-library/RESULTS.md`](app-vs-library/RESULTS.md) |
| A2 | registry-channel (same sample) | Within apps, do those that publish to an OSV-indexed registry fare better? | **Supported**: registry apps −51.5 pts less blind, p = 0.0077, 27 repos | [`registry-channel/RESULTS.md`](registry-channel/RESULTS.md) |
| A1 | registry-channel (out of sample) | Does A2 replicate on 32 fresh apps sharing no repo with earlier frames? | **Replicated**: −58.2 pts, p = 0.0017, 26 repos with advisories | [`registry-channel-a1/RESULTS.md`](registry-channel-a1/RESULTS.md) |
| A3 | attribution mechanism | Is the registry effect explained by whether the advisory page *names a package*? | **Partial null**: naming mediates only 36% of the gap (threshold was ≥ 50%); within package-named advisories registry apps stay +31 pts more visible | [`registry-channel-a3/RESULTS.md`](registry-channel-a3/RESULTS.md) |
| A4 | real-package mechanism | Is it whether the named package is a *real, repo-matching registry release* (read from the registry's own metadata)? | **Null**: P1 +14.4 pts, p = 0.98; it mediates only 12.8% of the gap, *below* A3's 36%. Advisories naming a non-matching package are 76% visible — as visible as real ones — so real-package status does not separate visible from blind. The first stage holds (registry apps carry real packages, no_registry apps ~never) | [`registry-channel-a4/RESULTS.md`](registry-channel-a4/RESULTS.md) |
| A5 | go-module rescue (software stratum) | Among advisories that name *no* package, does the project being a Go module at its repo path predict visibility (reviewers attach `github.com/owner/repo` for free)? | **Null (not supported)**: P1 −6.3 pts, p = 0.82; P3 only 31.6% go-rescued. The `proxy.golang.org` go-module probe proved degenerate (22/24 repos mislabelled "go"); package-less rescue is heterogeneous, ecosystem-specific attachment, not a dominant Go repo-path channel ([erratum](registry-channel-a5/ERRATUM.md)) | [`registry-channel-a5/RESULTS.md`](registry-channel-a5/RESULTS.md) |
| A6 | go-module rescue (out of sample) | Does it hold on 30 fresh no-registry apps, with a valid language-based cross-check and age/CVE controls? | **Primary inconclusive** (frozen proxy covariate left 2 "not_go" repos, below the floor of 4). **Pre-specified language check R2 holds strongly**: Go apps' package-less advisories 74.8% visible (83/111) vs 0.2% (1/638), +74.6 pts, p = 0.0001, 24 repos; 98.8% rescued as the repo-path Go module, all via GitHub's own reviewed records | [`registry-channel-a6/RESULTS.md`](registry-channel-a6/RESULTS.md) |
| E1 | ecosystem-coverage confound | Does the registry→visibility effect survive holding OSV ecosystem fixed, or is it partly OSV indexing some ecosystems better than others? | **Inconclusive (underpowered)**: only 2 usable strata (floor 3), no p-value computed. Descriptively the gap holds at full size within both: no package named 50.0% vs 4.6%; npm 81.5% vs 5.9%. OSV coverage by stratum: PyPI 81%, npm 76%, Go 70%, Maven 69%, Packagist 12% (mostly one app naming a package that doesn't exist) | [`registry-channel-e1/RESULTS.md`](registry-channel-e1/RESULTS.md) |
| A7 | release-cadence confound | Is the registry effect reducible to a repository-level covariate, release cadence (GitHub releases per year)? | **Survives**: cadence-adjusted direct effect +59.6 pts, p = 0.0017; cadence mediates only 1.1% (below A3's 36% and A4's 12.8%). The confound's premise fails — registry repos release *less* often (40.3/yr vs 44.5/yr), Spearman ρ = −0.068. The registry advantage is large in all 3 cadence tertiles (+50.6 / +58.4 / +75.1 pts) | [`registry-channel-a7/RESULTS.md`](registry-channel-a7/RESULTS.md) |
| E2 | ecosystem confound (pooled) | Does E1's ecosystem test reach ≥ 3 usable strata when the A1∪A2∪A4 frames are pooled (59 apps)? | pre-registered 2026-10-19 with the frame frozen before any pooled data was read; job queued; result pending | [`registry-channel-e2/PREREGISTRATION-registry-channel-e2.md`](registry-channel-e2/PREREGISTRATION-registry-channel-e2.md) |
| A8 | Go module-path class | Within Go apps, is A6's repo-path rescue confined to modules whose `go.mod` path *is* the repo root, and does it fail for vanity / non-root paths (e.g. `filippo.io/...`)? | pre-registered 2026-10-19 as a re-analysis of A6's published census; analysis code and offline tests committed before the class × visibility table was read; job queued; result pending | [`registry-channel-a8/`](registry-channel-a8/) |
| L1 | review lag vs permanent gap | Within the same no-registry repos, do older advisories become visible (an import lag that closes with age), or does the blind spot stay (a permanent gap)? | pre-registered 2026-10-19 as a re-analysis of A4's published census (within-repo permutation); result pending | [`registry-channel-l1/PREREGISTRATION-registry-channel-l1.md`](registry-channel-l1/PREREGISTRATION-registry-channel-l1.md) |

## What the chain says so far

An advisory reaches OSV-backed scanners when it can be bound to a package. For a
self-hosted app that means a real release on an OSV-indexed registry (A1/A2), or, for a
Go project, the module at the repository path, which exists without any extra
publishing (A6). Merely *naming* a package on the advisory page is not enough (A3/A4,
and the coolify and frappe cases in E1/A6), nor is the project simply being
well-run: release cadence does not explain the effect (A7). Apps in PHP, Ruby, Python
or JavaScript that ship only as Docker images or install scripts stay almost entirely
blind.

## How to read a study folder

- `PREREGISTRATION-*.md` — the frozen plan: frame, measure, predictions with numeric
  thresholds, robustness checks, and what would falsify the hypothesis.
- `*_census*.py` — the collector (stdlib only; paced, unauthenticated, archives HTML).
- `*_analysis.py` — the pre-registered tests (repository-level permutation tests,
  seed 20261017, 10,000 permutations).
- `test_*.py` — offline unit tests for the parser and the statistics.
- `RESULTS.md` — the write-up against the predictions, with coverage, robustness,
  per-repository table, limits and reproduce commands.
- `*summary.json`, `*per_repo.csv`, `*census.csv` — the data the write-up is computed
  from.

## Shared measure

An advisory is **scanner-visible** when OSV holds a record (by its GHSA id or a CVE
alias) that names at least one package; otherwise it is **scanner-blind**: a tool that
matches installed packages against OSV cannot find it. Eligibility is "published and
at least 14 days old" at the snapshot. The same `classify` code is copied verbatim
between studies so every study scores an advisory identically.

Made with AI agents working for MV2 of Munim, Inc.
