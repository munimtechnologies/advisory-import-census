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
| E2 | ecosystem confound (pooled) | Does E1's ecosystem test reach ≥ 3 usable strata when the A1∪A2∪A4 frames are pooled (59 apps)? | **Survives**: 6 usable strata, 52 repos; ecosystem-adjusted difference +41.7 pts, p < 0.0001 (bar was ≥ +25, p < 0.05). Positive in every stratum: no package named 50.0% vs 6.0%, npm 77.7% vs 7.8%, Go 80.7% vs 57.4% (the Go rescue), Packagist 37.5% vs 0%, PyPI 80.4% vs 40.0%. Crude gap +57.0, so ecosystem composition accounts for about a quarter of it (descriptive) | [`registry-channel-e2/RESULTS.md`](registry-channel-e2/RESULTS.md) |
| A8 | Go module-path class | Within Go apps, is A6's repo-path rescue confined to modules whose `go.mod` path *is* the repo root, and does it fail for vanity / non-root paths (e.g. `filippo.io/...`)? | **Confounded / inseparable**: non-root module paths barely exist among real self-hosted Go apps — 12 of 13 Go-module repos declare `github.com/owner/repo` at the root; the one vanity case (woodpecker, `go.woodpecker-ci.org/...`) has 2 package-less advisories, both visible. Root-match 73.0% (73/100) vs non-root 100% (2/2), −27.0 pts, p = 0.298. The no-`go.mod` class's 1.4% comes entirely from one mis-probed Go app (1Panel); every non-Go app there is 0% | [`registry-channel-a8/RESULTS.md`](registry-channel-a8/RESULTS.md) |
| L1 | review lag vs permanent gap | Within the same no-registry repos, do older advisories become visible (an import lag that closes with age), or does the blind spot stay (a permanent gap)? | **LAG, but the gap survives**: within no-registry apps, old (≥ 1 yr) advisories are +22.4 pts more visible than young (22.4% vs 0.0%), within-repo permutation p = 0.0001 — so part of the blind spot *is* import lag, falsifying a strict "permanent" reading. The gap does not close, though: among old advisories registry apps are still +74.1 pts more visible (96.6% vs 22.4%), p = 0.0063. The catch-up is concentrated in advisories that name a package (old no-registry package-typed 93.1% visible); no-package / Docker-only apps stay blind at every age | [`registry-channel-l1/RESULTS.md`](registry-channel-l1/RESULTS.md) |

## What the chain says so far

An advisory reaches OSV-backed scanners when it can be bound to a package. For a
self-hosted app that means a real release on an OSV-indexed registry (A1/A2), or, for a
Go project, the module at the repository path, which exists without any extra
publishing (A6). In practice that Go path is almost always the GitHub repository root,
so the Go rescue covers nearly every Go self-hosted app rather than a fragile subset
(A8). Merely *naming* a package on the advisory page is not enough (A3/A4,
and the coolify and frappe cases in E1/A6), nor is the project simply being
well-run: release cadence does not explain the effect (A7). Nor is it just OSV
covering some ecosystems better than others: holding the ecosystem fixed, about three
quarters of the gap remains (E2). Nor is it only recent advisories awaiting import:
older advisories do catch up where they name a package, but among advisories at least a
year old a +74-point registry gap remains, and no-package Docker-only apps stay blind at
every age (L1). Apps in PHP, Ruby, Python
or JavaScript that ship only as Docker images or install scripts stay almost entirely
blind.

For maintainers, these results are turned into practical steps in
[`docs/maintainer-checklist.md`](../docs/maintainer-checklist.md).

## The database series (S1-S14): how the advisory databases link CVEs

A second line of studies looks at the databases themselves: GitHub's Advisory Database, the CVE List,
OSV and the PyPA and RustSec databases. Each study is pre-registered the same way; most read pinned bulk
copies (git commits, CVE List releases) inside a sealed job and then check a seeded sample live by hand.
"Held" counts the frozen predictions that held. Where a study turns up single-record fixes, they are sent
to the database one record per pull request, each checked by hand first.

| # | Study | Question | Result | Held | Where |
|---|---|---|---|---|---|
| S1 | CVE reuse | Do repository advisories that reuse a CVE already held by another reviewed advisory still get imported? | 19 of 37 (51.4%) vs 90.5% for other advisories | 4 of 5 | [`cve-reuse-s1/`](cve-reuse-s1/RESULTS.md) |
| S2 | CVE lookup | Which affected packages does a CVE-based search of GitHub's database fail to return? | 93 hidden records; 80 (86.0%) name a package the CVE's holder lacks | 4 of 6 | [`cve-lookup-s2/`](cve-lookup-s2/RESULTS.md) |
| S3 | late CVEs | Where do CVEs go when they are assigned after GitHub has reviewed the advisory? | 642 of 3,694 CVE-less reviewed advisories have their CVE only on an unreviewed twin | 5 of 6 | [`late-cve-s3/`](late-cve-s3/RESULTS.md) |
| S4 | OSV bridge | Does OSV.dev connect the CVEs that GitHub's CVE search misses? | Late-CVE pairs: 619 of 648 (95.5%) linked; CVE-reuse pairs: only 18 of 96 (18.8%) | 4 of 4 | [`osv-bridge-s4/`](osv-bridge-s4/RESULTS.md) |
| S5 | second CVEs | Who issues a second CVE for a flaw whose reviewed advisory already has one? | 56 of 71 (78.9%) came from VulnCheck | 4 of 5 | [`second-cve-s5/`](second-cve-s5/RESULTS.md) |
| S6 | rejected aliases | How many live reviewed GitHub advisories still list a CVE that the CVE List marks REJECTED? | 54 of 36,244 | 3 of 6 | [`rejected-alias-s6/`](rejected-alias-s6/RESULTS.md) |
| S7 | missing aliases | What is behind the 143 CVE aliases on reviewed advisories that are not in the CVE List? | 138 (96.5%) are still RESERVED | 2 of 6 (1 inconclusive) | [`reserved-alias-s7/`](reserved-alias-s7/RESULTS.md) |
| S8 | GitHub-CNA gap | How many CVEs issued by GitHub's own CNA are missing from GitHub's Advisory Database? | 6,064 of 13,769 (44.0%) have no live advisory; follow-up list of advisories missing their CVE alias in [`cna-gap-s8-alias/`](cna-gap-s8-alias/README.md) | 4 of 6 | [`cna-gap-s8/`](cna-gap-s8/RESULTS.md) |
| S9a | late alias | Are GitHub-CNA CVEs that reach NVD after their advisory listed on the reviewed advisory they cite? | 65 of 7,703 (0.84%) are missing, 64 of them late | 4 of 6 | [`cna-gap-s9a/`](cna-gap-s9a/RESULTS.md) |
| S9b | split source | How often does a GitHub-CNA CVE name one advisory as its source but link another? | 13 of 13,769 (0.09%) | 5 of 6 | [`cna-gap-s9b-split-source/`](cna-gap-s9b-split-source/RESULTS.md) |
| S9c | reserve timing | Was the missing CVE reserved before GitHub reviewed the advisory? | No: 61 of 64 (95.3%) were reserved after review, and none of those advisories was edited afterwards | 6 of 6 (one rests on 3 cases) | [`cna-gap-s9c-reserve-timing/`](cna-gap-s9c-reserve-timing/RESULTS.md) |
| S10 | other CNAs | Is the gap special to GitHub's CNA? | No: 22.9% of other CNAs' CVEs lack a live advisory, vs 43.8% for GitHub's | 3 of 6 | [`cna-gap-s10-cna-compare/`](cna-gap-s10-cna-compare/RESULTS.md) |
| S11 | CVE field | Does a repository advisory that lists its CVE keep that CVE out of GitHub's database? | No: 27.2% are still in (bound was 20%) | 4 of 6 | [`cna-gap-s11-repo-cve-field/`](cna-gap-s11-repo-cve-field/RESULTS.md) |
| S12 | listing timing | Does listing the CVE on the repository advisory before or after NVD publishes it predict coverage? | Yes: 5.3% covered if listed by NVD's publication day, 100% if later; the rule is right for 95.5% | 6 of 6 | [`cna-gap-s12-listing-timing/`](cna-gap-s12-listing-timing/RESULTS.md) |
| S13 | PyPA rejected CVEs | How many live PyPA (PYSEC) advisories rest on a CVE its CNA rejected? | 21 of 7,631; 10 are open-webui records whose huntr CVEs were rejected in August 2026, after five siblings had been withdrawn in July | 4 of 6 | [`pysec-rejected-s13/`](pysec-rejected-s13/RESULTS.md) |
| S14 | Rust GitHub-only | How many GitHub-reviewed Rust advisories have no RustSec advisory, so cargo-audit cannot see them? | Pre-registered 2026-11-09; job queued | pending | [`rust-ghsa-only-s14/`](rust-ghsa-only-s14/PREREG.md) |

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

In the database series (S1-S14) the plan is usually called `PREREG.md`, and the job's raw output sits
next to `RESULTS.md`.

## Shared measure

An advisory is **scanner-visible** when OSV holds a record (by its GHSA id or a CVE
alias) that names at least one package; otherwise it is **scanner-blind**: a tool that
matches installed packages against OSV cannot find it. Eligibility is "published and
at least 14 days old" at the snapshot. The same `classify` code is copied verbatim
between studies so every study scores an advisory identically.

Made with AI agents working for MV2 of Munim, Inc.
