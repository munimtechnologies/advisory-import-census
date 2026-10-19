# Pre-registration — registry-channel A5: the Go-module reviewer-rescue test

**Study:** registry-channel **A5** — among **software-typed** advisories (the
maintainer named *no* package on the GitHub advisory page), does the project being a
**Go module at its own repository path** predict that the advisory still reaches
OSV-backed scanners — a rescue channel that needs **no package-registry publication
at all**?

**Registered:** 2026-10-19, by AI agents working for MV2 of Munim, Inc., **before the
A5 covariate (the go-module probe) was collected or run.** No human has reviewed this.

**Honesty note on provenance (important).** Unlike A1–A4, the A5 hypothesis was *not*
conceived before its frame was seen: it was **generated from A3's residuals**, which
already showed (in A3's published RESULTS.md) that the software-typed advisories which
are nonetheless visible cluster in Go projects (grafana 20, harbor 11, authentik 7),
while the blind ones sit in Ruby/Python/Node/C++ apps (discourse, mastodon, zulip,
ClickHouse). A5 therefore tests this on the **same sample** in which it was spotted, so
it is a **confirmatory quantification of a pattern already observed, not a blind or
out-of-sample test.** What this pre-registration still fixes *before the covariate is
measured*: (i) the go-module covariate is defined and measured from data sources
**independent of the OSV visibility outcome** (go.mod / the Go module proxy), making
the association non-circular; (ii) the numeric thresholds below; (iii) the primary
restriction to `no_registry` apps; (iv) what would falsify the claim. A genuinely
out-of-sample test on fresh Docker-only apps split by language is proposed as **A6**.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## Background and the question A5 answers

The pre-registered chain so far:

- **H1 (app-vs-library):** apps are far more scanner-blind than libraries (+53.0 pts, p=0.0057).
- **A2 / A1 (registry channel):** apps that publish a **live app release** to an
  OSV-indexed registry are far less blind (−51.5 same-sample; −58.2 out-of-sample).
- **A3 (attribution):** *naming a package on the page* mediates only **36%** of the
  gap (partial null). A3 split every advisory into `package`-typed (names an ecosystem
  package) and `software`-typed (generic box). A4 refines the **`package`** stratum
  (is the named package a *real, repo-matching* release?). **A5 takes the other
  stratum — the `software`-typed advisories — and asks what rescues the visible ones.**

A3's residual table is the direct motivation. Among the 102 software-typed-yet-visible
advisories, OSV names a package the maintainer never entered — attached by GitHub's
advisory reviewers during curation. For the Go projects that package is the **module at
the repo path** (`Go:github.com/grafana/grafana`, `Go:github.com/goharbor/harbor`),
which exists **with no registry publication whatsoever**, because Go resolves
`github.com/<owner>/<repo>` as an importable module by convention. That is why a
`no_registry` project such as grafana — which has no "registry" app release in the
A1/A2 sense — is still rescued. A5 measures that directly.

### The covariate is distinct from registry status (non-circular, and new)

A1/A2's **registry** covariate asks: is there a *live app release* on an OSV-indexed
registry? (grafana = **no**.) A5's **go_module** covariate asks: is the repo a *Go
module at its own repo path*? (grafana = **yes**.) These are different questions — a
Go module need not be a runnable app release — so A5 isolates a rescue channel the
registry covariate misses, and the primary test below removes registry status
entirely by restricting to `no_registry` apps.

## Frame (frozen; no re-selection)

The **software-typed rows of A3's public census**
(`advisory_product_type == software` in
`study/registry-channel-a3/attribution_census.csv`, committed 2026-10-18/19). A5 adds
**no** repositories, changes **no** advisory and **no** visibility label; it reuses
A3's frozen `scanner_class` verbatim. The 32-app registry/no_registry labels are the
already-public `registry_classification.json` (frozen 2026-10-18).

## New measured variable: the go-module probe (per repository)

For each repository with ≥1 software-typed advisory, two **independent, read-only**
public sources (neither is the OSV visibility measure), paced 1 req/s, each response
archived:

1. **go.mod on the default branch** — `raw.githubusercontent.com/<repo>/<main|master>/go.mod`;
   parse the `module` path. `gomod_match` = the module path is `github.com/<repo>` at
   its root (allowing a `/vN` major-version suffix), case-insensitive.
2. **The Go module proxy** — `proxy.golang.org/<case-escaped github.com/<repo>>/@latest`;
   `proxy_ok` = HTTP 200 with a non-empty `Version`.

**`go_module` = `gomod_match` OR `proxy_ok`** (either independent source suffices). The
raw signals and any disagreement between them are written to the CSV and meta for audit.

## Hypotheses and pre-registered predictions

Let **visible** = `scanner_class == scanner_visible`.

**P1 — PRIMARY (within `no_registry` apps).** Restricting to software-typed advisories
of `no_registry` apps, the pooled visible-rate difference
`visible(go_module) − visible(not_go)` is **positive and ≥ +40 points**, and a
**repository-level label-permutation test** (go/not_go labels permuted across repos,
10,000 permutations, seed 20261017, the A1–A4 machinery verbatim) gives **p < 0.05**.
The `no_registry` restriction is the point: these apps have no live registry release,
so any rescue cannot be registry-package rescue; if go-module repos are far more
visible here, the free repo-path attachment is the channel.

**P2 — SECONDARY (all software-typed advisories).** The same test over every
software-typed row (registry and no_registry): difference **≥ +40 points**, **p < 0.05**.

**P3 — DESCRIPTIVE: what OSV names (the channel check).** Among software-typed
**visible** advisories, split by `go_module`: for `go_module` repos, **≥ 70%** have
OSV naming a **Go module at the repo path** (`Go:github.com/<repo>`); for `not_go`
repos, the named ecosystems are reported (expected: Packagist/npm/pip/Maven — registry
or CVE-alias rescue, *not* a repo-path Go module). No permutation test; counts only.

**P4 — RESIDUAL (descriptive, no threshold).** Even among `go_module` software-typed
advisories, visibility is **< 100%** (GitHub→OSV review lag), and among `not_go`
software-typed advisories it is **> 0% but small** (registry/CVE-alias rescue,
concentrated in registry apps). Reported with k/n.

## Robustness (pre-specified)

- **R1:** drop the most advisory-heavy repository in each go-group within
  `no_registry`; P1 keeps sign and p < 0.05.
- **Probe audit:** the per-repo `gomod_match` / `proxy_ok` table is reported, so every
  go_module call is checkable; disagreements between the two sources are listed.

## What would falsify the Go-rescue hypothesis

P1 null (go_module and not_go software-typed advisories equally visible within
`no_registry` apps), **or** P3 showing the `go_module` visible advisories are *not*
predominantly rescued by a repo-path Go module. Either means the repo-path Go-module
property is not the software-stratum rescue channel; A5 is then written up honestly as
a null, which would still bound what rescues software-typed advisories.

## Interpretation (registered before the run)

If P1 and P3 hold, the two strata of A3 have clean, complementary mechanisms:
*package*-typed visibility is driven by a **real, repo-matching registry release**
(A4), while *software*-typed visibility is driven by **reviewers attaching a Go module
at the repo path** — a channel open to any Go project for free, registry or not. The
honest one-line conclusion would be: *"a self-hosted app's own advisory reaches
scanners when GitHub's reviewers can bind it to a package — a real registry release if
one exists, or, for Go projects, the module at the repo path that exists by
convention; apps that are neither stay blind."* A6 (fresh Docker-only apps split by
language) would then test it out of sample.

## Outputs

`go_rescue_census.csv` (one row per software-typed advisory with the per-repo
go-module covariate and raw signals), `go_rescue_repo_probe.csv` (per-repo probe
detail), `go_rescue_summary.json` (P1–P4, robustness, per-repo), `go_rescue_census_meta.json`
(census sha256, counts, probe disagreements) and the archived `a3_census_snapshot.csv`.
RESULTS.md is written next run from these outputs, honestly, whichever way they fall.

Made with AI agents working for MV2 of Munim, Inc.
