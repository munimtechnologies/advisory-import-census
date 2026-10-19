# Pre-registration — registry-channel A8: within Go apps, is the free "repo-path rescue" confined to modules whose `go.mod` path *is* the repo (root-match), and does it fail for vanity / non-root module paths?

**Status:** frozen and published **before** the go.mod-class × visibility contingency is
read. A8 is a **re-analysis of A6's already-published census** (no new advisory or
visibility data is collected); the only inputs are A6's committed artifacts, fetched
byte-for-byte at run time and recorded in `frozen_code_sha.json`. Made with AI agents
working for MV2 of Munim, Inc. Apache-2.0 (code) / CC BY 4.0 (text & data).

Frozen UTC: 2026-10-19.

## Background and why this is new

A6 established that, for self-hosted applications that publish to **no** language
registry, the advisory-import gap is *rescued* when the project is a Go module at its
repository path: package-less advisories of Go apps were 74.8% scanner-visible vs 0.2%
for non-Go, +74.6 pts (p = 0.0001), and 98.8% of the rescued advisories resolved as the
repo-path Go module `github.com/owner/repo` — the coordinate GitHub's reviewers attach
by default. A6 measured "is a Go module" with two signals: a degenerate
`proxy.golang.org` probe (discarded — it mislabelled 22/24 repos) and the robust one it
actually relied on, the `go.mod` file read from the default branch (`gomod_match`,
`gomod_module`, `gomod_status` in `oos_go_rescue_repo_probe.csv`).

A6 did **not** ask the mechanistic follow-up this study pre-registers. The default
reviewer attachment is `github.com/owner/repo`. OSV Go records are keyed by **module
path**. So the rescue should work precisely when the project's real module path *is*
`github.com/owner/repo` (root-match). It should **fail** when the real module path is a
**vanity import** (e.g. `filippo.io/mkcert`, `k8s.io/...`, `gopkg.in/...`) or a
subdirectory/monorepo path, because a scanner resolving the vanity coordinate queries
OSV for that coordinate and finds nothing — the reviewer-attached `github.com/owner/repo`
record does not match it. A8 tests whether the rescue is confined to root-match modules.

**Prior art.** A6 (this arc) and Safeguard.sh's Oct 2026 studies measure Go visibility
but treat "Go module" as a single binary; neither splits the Go stratum by whether the
declared module path is the repo root vs a vanity/non-root path and asks whether the
repo-path rescue depends on it. To our knowledge A8 is the first such test. A positive,
null, or degenerate (no vanity paths occur) result all count, provided the frame and
thresholds below are honoured.

## Sample (frozen)

Every repository in A6's published probe table
`study/registry-channel-a6/oos_go_rescue_repo_probe.csv` with `included == True`
**and** `gomod_status == 200` (a `go.mod` was read from `main` or `master`). These are
the "has-a-go.mod" repositories — the only ones for which a module-path class is
defined. Repositories with `included == True` but `gomod_status != 200` (no readable
`go.mod`) form a reported baseline row but are **not** part of the primary contrast.
`filebrowser/filebrowser` (archived, `included == False` in A6) is excluded, as in A6.

Advisory-level visibility and the package-less (software, no-package-named) restriction
are taken **verbatim** from A6's committed advisory census
`study/registry-channel-a6/oos_go_rescue_census.csv` — the exact column A6 used to
define its rescue numerator/denominator, reused unchanged. A8 collects no advisory data.

## Covariate (frozen definition)

For each sampled repository, read `gomod_module` and `gomod_match` from A6's probe table
(semantics confirmed from the committed A5/A6 collector `go_rescue_census.py`:
`gomod_match` is `True` iff the parsed `module` line, lowercased and `/`-stripped, equals
`github.com/<owner>/<repo>` or starts with `github.com/<owner>/<repo>/`, i.e. root at the
repo, allowing a `/vN` major-version suffix). Assign a **module-path class**:

```
root_match : gomod_match == True
            (module path is github.com/owner/repo [ /vN ])
non_root   : gomod_match == False AND gomod_module is non-empty
            (vanity domain e.g. filippo.io/..., or github.com/<other> or a subdir path)
no_gomod   : repo excluded from the primary contrast (gomod_status != 200), baseline only
```

The `non_root` class is further *described* (not used as a separate stratum unless each
is populated) as `vanity_domain` (module host is not `github.com`) vs
`github_nonroot` (host is `github.com` but path ≠ the repo root).

## Statistics (frozen)

Unit of visibility is the **package-less advisory**; unit of permutation is the
**repository** (A6-identical). Using A6's `permutation_test` helper verbatim (10,000
permutations, seed 20261017, two-sided), on the sampled go.mod-having repositories:

- **Primary effect:** pooled package-less visible-rate difference
  `visible(root_match) − visible(non_root)`, with a repository-level permutation p
  (shuffle the root_match/non_root repo labels).
- **Descriptive:** per-class visible rate with a Wilson 95% CI; the three-row table
  root_match / non_root / no_gomod; and, within `non_root`, the vanity_domain vs
  github_nonroot split.

## Pre-registered predictions and thresholds

| id | prediction | threshold | role |
|----|------------|-----------|------|
| **P1** | the repo-path rescue is **confined to root-match** modules: root-match apps' package-less advisories are far more visible than non-root ones | `visible(root_match) − visible(non_root) ≥ +40.0 pts` AND permutation `p < 0.05` → **CONFINED** | primary |
| **P2** | non-root (vanity/subdir) Go modules are **not** rescued: their package-less visible rate is low | `visible(non_root) ≤ 20%` | mechanism |
| **P3** | no-go.mod repos sit at the non-Go baseline | `visible(no_gomod)` reported vs A6's 0.2% non-Go baseline | descriptive (no threshold) |

**Power / degeneracy floor.** The primary test is **CONFOUNDED_INSEPARABLE** if either
class (`root_match` or `non_root`) contains **0** repositories, or if either contains
fewer than **4** package-less advisories — i.e. the vanity-path failure mode does not
occur often enough in real self-hosted Go apps to be tested. In that case A8 reports,
honestly, that self-hosted Go applications in this frame almost universally declare their
module at the repo root, so the theorised vanity-path blind spot is **empirically rare**,
and gives the descriptive table as its substance. If both classes are populated but
`non_root` has 1–3 advisories the result is **INCONCLUSIVE_UNDERPOWERED**.

**Falsification clause.** A8 does **not** support a root-match-confined rescue if
`visible(root_match) − visible(non_root) < +40 pts` OR permutation `p ≥ 0.05` OR
`visible(non_root) > 20%` (non-root modules turn out to be rescued too — which would mean
OSV/reviewers reconcile vanity paths better than assumed).

## Verdict rule (frozen)

```
if n(root_match)==0 or n(non_root)==0
   or advisories(root_match)<4 or advisories(non_root)<4:   CONFOUNDED_INSEPARABLE
elif advisories(non_root) < 4:                              INCONCLUSIVE_UNDERPOWERED
elif diff >= 40.0 and p < 0.05 and visible(non_root) <= 20: CONFINED
else:                                                       NOT_CONFINED
```

## Outputs

`gomod_class_summary.json` (per-class rates with Wilson CIs, the primary diff + p, the
vanity/github split, and the verdict), `gomod_class_per_repo.csv` (one row per sampled
repo: module path, class, package-less advisories, visible, visible_pct) and
`frozen_code_sha.json` (sha256 + git-blob-sha of each reused A6 artifact and of the
analysis code). A `RESULTS.md` will be written and shipped once the job returns, scoring
each prediction against the thresholds above and stating the verdict plainly, whatever it
is — including a CONFOUNDED_INSEPARABLE "vanity paths are empirically rare" finding.
