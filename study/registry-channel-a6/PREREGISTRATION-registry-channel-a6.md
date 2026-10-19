# Pre-registration — registry-channel A6: the Go-module rescue, out of sample

**Study:** registry-channel **A6**. On a **fresh frame of 30 self-hosted applications**
(none in any earlier frame), none of which ships a live app release on a non-Go
OSV-indexed registry: are the advisories of projects that are a **Go module at their
own repository path** far more likely to reach OSV-backed scanners, *especially* the
**software-typed** ones (the maintainer named no package on the GitHub advisory page)?

**Registered:** 2026-10-19, by AI agents working for MV2 of Munim, Inc., **before any
advisory, visibility or go-module data was collected for these 30 repositories**, and
**before the same-sample A5 result exists** (A5's job is still queued as this is
written, so neither result can have shaped this plan). No human has reviewed this.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## Why A6

A3 found that *naming a package on the page* explains only about a third of the
registry-channel gap. Its residuals showed that software-typed advisories which still
reach scanners cluster in Go projects (grafana, harbor, authentik), where OSV names
`Go:github.com/<owner>/<repo>`, a package that exists with **no registry
publication** because Go resolves the repository path as a module. A5 tests that on
A3's own sample, where the pattern was first noticed, so it can only confirm. **A6 is
the out-of-sample test**: new repos, frame frozen first, the same measure and
covariate code.

**Prior and parallel work.** Safeguard's 2026-10-18 study
(safeguard.sh, "GitHub Repository Advisories Missing From the Database (2026)")
checked 2,486 repository advisories from 45 heavy Go/npm/PyPI publishers and found
30.7% missing from GitHub's reviewed database and OSV, with no CVE a strong predictor
(77% vs 11% missing) and recent advisories missing more. It gives no per-ecosystem
breakdown and does not look at repository-path module attachment or self-hosted
apps distributed only as Docker images or binaries. As far as we can find, no
published work tests whether being a Go module at the repo path rescues advisories
that name no package. A6 also pre-registers controls for the two confounds that
study identified (R3 age, R4 CVE).

## Frame (frozen; `frame_apps.json`)

**Rule.** Widely used self-hosted applications (a server or app a user runs, not a
library or SDK), canonical home on GitHub, chosen **before any of their advisory
data was collected by this project** because they are well-known self-hosted apps with
security-advisory activity, picked so that both implementation languages are well
represented (16 expected Go, 14 expected non-Go). **No repo from any earlier frame**
(the 27 app-vs-library/A2 apps and the 32 A1/A3/A4/A5 apps; enforced by a unit test).
**No live app release on a non-Go OSV-indexed registry** (npm, PyPI, crates.io,
RubyGems, Packagist, Maven Central) under the A1/A2 rule, so the non-Go side cannot be
rescued by a registry package of its own. Go-module status is **not** a frame
criterion. It is the covariate, measured during the job.

Honest limit: the candidates were picked by an AI agent that may have general
background knowledge of these projects' advisory histories. Selection was not based
on blind rates, and none had been measured. A6's frame is also not random.

**Registry checks done before freezing (2026-10-19):**

| Candidate | Check | Outcome |
|---|---|---|
| kimai/kimai | Packagist `kimai/kimai` (active, repo github.com/kimai/kimai) | **dropped** (live Packagist app) |
| pterodactyl/panel | Packagist `pterodactyl/panel` (repo github.com/pterodactyl/panel) | **dropped** |
| thorsten/phpMyFAQ | Packagist `thorsten/phpmyfaq` 4.1.10 (2026-10-09) | **dropped** |
| librenms/librenms | Packagist `librenms/librenms` 26.9.1.1 (2026-09-22) | **dropped** |
| openemr/openemr, glpi-project/glpi (and glpi/glpi), FreshRSS/FreshRSS, Cacti/cacti | Packagist p2 metadata | 404, kept |
| mealie-recipes/mealie, langgenius/dify, jumpserver/jumpserver | PyPI `mealie`, `dify`, `jumpserver` | 404, kept |
| frappe/frappe | PyPI `frappe` is a 0.0.1 **placeholder** (2023), not a live app channel | kept (no_registry under the A1 rule; noted) |
| Mintplex-Labs/anything-llm | npm `anything-llm`: only version unpublished within a minute (2026-01-13) | kept |
| NginxProxyManager/nginx-proxy-manager | npm `nginx-proxy-manager` | 404, kept |
| chatwoot/chatwoot, opf/openproject, zammad/zammad | RubyGems `chatwoot`, `openproject`, `zammad` | 404, kept |
| TandoorRecipes/recipes | PyPI `tandoor` | 404, kept |
| Budibase/Budibase | npm `budibase` is a deprecated 2020 CLI (0.0.31) | **not included** (CLI ambiguity; left out rather than argued) |

The 16 expected-Go apps were not registry-checked: for them, Go-module status is the
measured covariate (a tagged Go module counts as "registry" under the A1 rule, so A6
deliberately does not use that label). The frame's frappe placeholder is worth watching: if
OSV names `PyPI:frappe` on its advisories, that is a reviewer attaching a *placeholder*
package, the same "free attachment" channel in a non-Go form, and it will be reported
under P3/P4.

**Mechanical hygiene (pre-specified):** a repo is dropped only if the GitHub API says
`archived: true` (a failed lookup is "unknown", not archived); repos the census marks
unreadable contribute no rows and are listed. Renames are recorded.

## Measures (all reused verbatim from published code)

- **Visibility** = `scanner_visible` from A3's published `attribution_census.py`
  (an OSV record by GHSA id or CVE alias names a package); eligibility = published and
  ≥ 14 days old; product type `package` / `software` / `other` from the advisory page.
- **go_module** = A5's published `probe_repo`: go.mod on main/master whose `module` is
  `github.com/<repo>` (optionally `/vN`) **or** proxy.golang.org `@latest` serves a
  version for `github.com/<repo>`. Independent of the OSV outcome.
- **language** (R2 only) = the GitHub API's primary `language`.

`fetch_deps.py` downloads the published A3/A5 files at run time and records their
sha256, so the code that ran can be checked byte for byte against the repository.

## Predictions (frozen)

Let **visible** = `scanner_class == scanner_visible`; tests are the A1–A5
repository-level label-permutation test (10,000 permutations, seed 20261017).

- **P1, primary (software-typed advisories).** `visible(go_module) − visible(not_go)`
  is **≥ +40 points** with **p < 0.05**.
- **P2, secondary (all eligible advisories).** Difference **≥ +30 points**, **p < 0.05**.
- **P3, channel check (descriptive).** Among `go_module` repos' visible
  software-typed advisories, **≥ 70%** have OSV naming a Go module at the repo path
  (`Go:github.com/<repo>` or a subpath of it).
- **P4, residual (descriptive).** `go_module` software-typed visibility < 100%
  (review lag); `not_go` software-typed visibility > 0% but small. Both reported as
  k/n.

**Power floor.** If fewer than **4 repos in either group** contribute software-typed
advisories, P1 is reported as **inconclusive (underpowered)**, not as a null.

## Robustness (pre-specified; reported whichever way they fall)

- **R1:** drop the most advisory-heavy repo in each group; P1 keeps sign and p < 0.05.
- **R2:** group by GitHub primary language == Go instead of the module probe (catches
  Go apps whose module lives in a subdirectory); P1 keeps sign.
- **R3 (age):** only advisories ≥ 90 days old (settled past review lag); difference
  keeps sign and is ≥ +30 points.
- **R4 (CVE):** P1 within advisories *with* a CVE and within those *without*; sign
  reported for each stratum where both groups are non-empty.
- **D1 (which record rescues):** among visible software-typed advisories, whether the
  package-naming OSV record is the advisory's **own GHSA** record (GitHub reviewers) or
  **only a CVE-alias** record (for example a Go vulnerability-database `GO-` entry).
  Counts only. This separates GitHub's reviewers from the Go team's own triage, which
  A5's design cannot do.

## What would falsify it

P1 missing its threshold (difference < +40 or p ≥ 0.05) with adequate power means the
Go-module rescue **does not replicate out of sample** and is written up as MISSED.
A difference ≤ 0 contradicts it. If P1 holds but P3 fails, Go apps are more visible
for some other reason than repo-path module attachment, and that is what we will
report.

## Interpretation (registered before the run)

If P1 and P3 hold out of sample, the practical rule for a self-hosted maintainer is:
*an advisory reaches scanners when it can be bound to a package. That means a real
registry release, or for a Go project the module at the repo path, which exists for
free. Docker-only apps in other languages stay blind unless the maintainer names a
package.* If D1 shows the rescue comes mostly through CVE-alias `GO-` records, the
credit goes to the Go vulnerability database's triage rather than to GitHub's
reviewers, and the write-up will say so.

## Outputs

`out/census/attribution_census.csv` + `attribution_census_meta.json` + `raw/` (A3
collector), `oos_go_rescue_census.csv`, `oos_go_rescue_repo_probe.csv`,
`oos_go_rescue_per_repo.csv`, `oos_go_rescue_summary.json`, `deps_sha256.json`.
RESULTS.md is written from these against the thresholds above, honestly.

Made with AI agents working for MV2 of Munim, Inc.
