# Pre-registration: is the advisory-import gap an application-vs-library effect?

*Pre-registration, written and committed to `munimtechnologies/advisory-import-census`
(`main`, Apache-2.0 code, CC BY 4.0 data) together with ALL of its analysis code
(`build_frame.py`, `app_library_census.py`, `test_frames.py`) BEFORE any sampling
frame is realized and BEFORE any advisory data for this test is pulled — exactly
as the AI-vs-control study was pre-registered. Status at commit: NOT YET RUN.*

## Why this test

The shipped AI-vs-control study (`study/2026-10-17/`) found **no AI-specific**
advisory-import gap (repository-level permutation p = 0.30, 49 repos). Its
*exploratory* split of the 30-repo control group suggested the real axis is
**application vs library**: among non-AI controls, 64.4% [61.4, 67.4] of
self-hosted *applications'* advisories were scanner-blind (corrected measure)
against 1.8% [0.9, 3.7] of *libraries'* advisories (exploratory permutation
p = 0.0003, 30 repos).

That split was (a) not pre-registered, (b) measured on a convenience control
group of 15 apps + 15 libraries chosen by hand, and (c) potentially circular:
the repositories had been picked while their blindness was already known. This
test removes all three weaknesses with a written labelling rule, an external
sampling frame fixed by frozen code before any advisory is pulled, and a larger
balanced sample drawn from entirely fresh repositories. A confirmatory,
pre-registered application-vs-library census of the import gap has not, to our
knowledge, been published; prior work (OSV, GHSA tooling) treats the gap as a
data-completeness problem, not as a project-type effect.

## Hypothesis

**H1 (primary, confirmatory).** The share of a repository's eligible security
advisories that are *scanner-blind* is higher for self-hosted **applications**
than for **libraries/frameworks**.

**H0.** No difference in scanner-blind share between applications and libraries.

Directional prediction, stated before data: applications higher by a large
margin (point-estimate difference > 30 percentage points; the exact pilot
magnitude is not required).

## Sampling frame (realized by frozen code, before any advisory data)

`build_frame.py` (committed with this file) selects two lists of up to
`TARGET_N = 40` repositories each by a criterion that is **independent of both
advisory visibility and advisory existence**, so the frame cannot be steered
toward the hypothesis:

- **Applications.** Source: the `awesome-selfhosted-data` machine-readable
  catalogue. Every entry whose `source_code_url` is a GitHub repo, is not
  archived, and carries a `stargazers_count` is a candidate; candidates are
  ranked by that stored star count (descending) and the top 40 are taken. Star
  count is read from the catalogue's own YAML, so **no GitHub API call** is made
  during selection.
- **Libraries/frameworks.** Source: the public, keyless `ecosyste.ms` packages
  API for `npmjs.org`, `pypi.org` and `proxy.golang.org`, each sorted by
  `dependent_repos_count` (descending). Each package is mapped to its GitHub
  `repository_url`; non-archived GitHub repos are taken in each registry's own
  dependents order and combined **round-robin across the three registries** (so
  the library group is balanced across ecosystems, not dominated by one),
  de-duplicated (first seen wins), to a total of 40.

**Exclusion.** Every repository used in census v0.1 or the AI-vs-control study is
excluded. The exclusion set is derived reproducibly from the already-published
dataset `study/2026-10-17/group_census.csv` (committed in v0.9.0): its distinct
`repo` values. The resolved set is written to `frame_exclude.txt`.

The realized frame (`frame_apps.json`, `frame_libs.json`, `frame_used.json`) is
**committed to the repository before `app_library_census.py` is run**. The
census is never run against an unfrozen frame.

### Labelling (application vs library)

The label comes from the sampling source *by construction*: the application list
is drawn from a self-hosted-application catalogue; the library list from
registry-dependents listings. This operationalizes the pilot's mechanism —
**distribution channel**: a library's primary released artifact is a package on a
public registry that other code imports as a dependency; an application's is a
runnable service installed via Docker/binary/`git clone`, not imported. Because a
repo can appear in only one source list by this construction, there is no
per-repo subjective call. Any repo that would qualify for both is kept in
whichever list ranks it (apps list takes precedence by construction) and this is
recorded.

## Eligibility and measurement

- **Eligible advisory:** a *published* GitHub repository security advisory at
  least 14 days old at the snapshot timestamp. Repos with zero eligible
  advisories stay in the frame (counted in `repos_in_frame`) but contribute no
  rows and do not enter the permutation test.
- **Primary measure — scanner-blind (corrected).** An advisory is **visible**
  iff an OSV record — found by its own GHSA id or by any of its CVE aliases —
  names at least one package; otherwise **blind**. This is the corrected measure
  validated by `reclassify.py` in the AI-vs-control study: it trusts OSV's own
  record rather than the (often free-text) package field on the repo advisory.
- **Secondary measure — own GHSA absent from OSV** (`own_id_not_in_osv`): the
  advisory's own GHSA id does not resolve in OSV at all.
- **OSV canary:** `GHSA-39mp-8hj3-5c49` must resolve during the run, or the run
  is void (guards against an OSV outage reading as universal blindness).

## Statistical plan (fixed now)

- Per repository: blind share = blind eligible / eligible.
- **Primary test:** two-sided permutation test of the pooled
  (application − library) difference in blind share, shuffling the
  application/library label across **repositories** (10,000 permutations,
  seed `20261017`). Repository-level, so advisory-heavy repos cannot dominate.
- Report Wilson 95% intervals for each group's pooled share, each group's
  repository median blind share, and the permutation p for the primary
  (corrected) and secondary (own-GHSA) measures.
- **Pre-specified robustness, reported regardless of outcome:** (a) repeat the
  primary test after dropping the single most advisory-heavy repository in each
  group; (b) repeat it within each publication period (before vs from 2026-05-01).

## Decision rule

H1 is supported iff the primary permutation p < 0.05 **and** the direction is
applications-higher. A null or reversed result is reported honestly as refuting
or failing to confirm the pilot. A negative result is a valid outcome of this
pre-registration and will be published either way.

## Reproducibility and outputs

- `app_library_census.py` writes `out/app_library_census.csv` (one row per
  advisory), `out/summary.json` (per-group and per-repo shares, permutation
  p-values, robustness, canary status), using the committed frame.
- Compute: one sealed job per stage — a frame-build job (needs the catalogue,
  ecosyste.ms and the published census CSV), then, after the frame is committed,
  a census job (`network: true`, `image: python:3.12`, GitHub Security Advisories
  + OSV, unauthenticated and self-paced on the rate-limit reset). Stdlib only.
- Data CC BY 4.0, code Apache-2.0, in `munimtechnologies/advisory-import-census`.

## Honest limits (stated in advance)

- Curated self-hosted catalogues over-represent server applications; registry
  dependents over-represent libraries. That contrast is the point, but the result
  speaks to "applications as catalogued on awesome-selfhosted" vs "top registry
  libraries", not to all software.
- Selecting by stars / dependents (not by advisory existence) means some frame
  repos will have no advisories; the realized per-group n of repos-with-advisories
  may be below 40 and is reported.
- OSV stands in for scanners generally; Dependabot reads GitHub's database
  directly and may differ. One snapshot; repository advisories change over time.
- A supported H1 is an association (distribution channel ↔ import gap), not a
  controlled experiment.

## Amendment 1 (2026-10-17, before any frame or advisory data existed)

A code review of the frozen `build_frame.py` (commit 21efe05) found that it did
**not** implement the apps-precedence rule stated under *Labelling* above: the
library list was never checked against the application catalogue, so a repo
listed on awesome-selfhosted that is also a top registry package could have
entered **both** groups, and the census would then have counted it twice under
opposite labels.

The fix implements the rule as written, read in its strict form: **every GitHub
repo the self-hosted catalogue lists** (including archived, excluded or starless
entries, which are still applications by the labelling rule) is skipped when the
library list is built; the next library in the same registry's dependents order
takes its place. Each skipped repo is recorded in
`frame_used.json` → `lib_diagnostics.skipped_as_applications`, and the frame
builder now stops with an error if any repo is in both groups. Three offline
tests cover it (`TestAppsPrecedence` in `test_frames.py`).

Nothing else changes: same sources, ranking, `TARGET_N`, exclusion set,
measures, statistics and decision rule. When this amendment was committed, the
first frame-build job (`aic-app-lib-frame-v1`) had not started and no frame had
been produced. That job is superseded by `aic-app-lib-frame-v2`, which runs the
amended code. If v1 does run, its output will not be used, and that will be
reported.

Known, unchanged limit worth stating now: the exclusion set is the distinct
`repo` values in `group_census.csv`, so a repository from an earlier sample that
had **no** eligible advisories (and so no rows) is not excluded. Such a repo
contributed nothing to the earlier tests, so reusing it does not double-count any
advisory. Any reuse will be listed in the write-up.

*Pre-registration and all analysis code written by AI agents working for MV2 of
Munim, Inc.*
