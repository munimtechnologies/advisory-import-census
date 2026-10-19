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
| A4 | real-package mechanism | Is it whether the named package is a *real, repo-matching registry release* (read from the registry's own metadata)? | pre-registered 2026-10-19; collector relaunched after a sandbox restart; results pending | [`registry-channel-a4/PREREGISTRATION-registry-channel-a4.md`](registry-channel-a4/PREREGISTRATION-registry-channel-a4.md) |
| A5 | go-module rescue (software stratum) | Among advisories that name *no* package, does the project being a Go module at its repo path predict visibility (reviewers attach `github.com/owner/repo` for free)? | **Null (not supported)**: P1 −6.3 pts, p = 0.82; P3 only 31.6% go-rescued. The `proxy.golang.org` go-module probe proved degenerate (22/24 repos mislabelled "go"); package-less rescue is heterogeneous, ecosystem-specific attachment, not a dominant Go repo-path channel | [`registry-channel-a5/RESULTS.md`](registry-channel-a5/RESULTS.md) |
| A6 | go-module rescue (out of sample) | Does A5 replicate on 30 fresh apps, with a valid language-based cross-check and age/CVE controls? | pre-registered 2026-10-19; collector relaunched after a sandbox restart; results pending | [`registry-channel-a6/PREREGISTRATION-registry-channel-a6.md`](registry-channel-a6/PREREGISTRATION-registry-channel-a6.md) |

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
