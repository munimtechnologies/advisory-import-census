# Pre-registration: is the advisory-import gap special to AI/ML tools?

Written 2026-10-15 ~02:30Z by MV2 of Munim, Inc. (made with AI agents working in his
name), **before any result of this comparison was seen**. The repository lists,
definitions, cut-offs and tests below are fixed here and in `group_census.py`; any change
after results are in will be reported as a deviation.

## Question

advisory-import-census v0.1 (2026-10-14) found that 195 of 618 (31.6%) GitHub repository
security advisories published by self-hosted AI/ML projects were not in the global GitHub
Advisory Database under their own ID. GitHub wrote in 2026 that repository advisories grew
from about 650 to more than 5,000 a week and that review fell behind
(github.blog, "Inside the Advisory Database and what happens when vulnerability volume
breaks records"). So is the gap specific to AI/ML tools, or the same everywhere?

## Groups

- **ai**: the 30 repositories of census v0.1, unchanged (`AI_REPOS`).
- **control**: 30 widely used repositories whose core purpose is not AI/ML, chosen to
  mirror the ai group's mix of self-hosted apps (15) and libraries/frameworks (15)
  (`CONTROL_REPOS`). Nextcloud was left out because it publishes advisories in a
  separate, very large advisory-only repository that would dominate the group.
  Repositories that return 404 or have no published advisories stay in the list and
  simply contribute nothing.

## Measurements (OSV.dev, the database pip-audit and osv-scanner read)

For every published repository advisory of every repository:
- `own_id_in_osv`: `GET https://api.osv.dev/v1/vulns/<GHSA id>` returns a record.
- `scanner_class`:
  - `scanner_visible`: OSV lists the advisory's GHSA ID or its CVE under at least one
    package the advisory names;
  - `package_not_in_osv`: it names a package (in an ecosystem OSV covers) but OSV lists
    it under none of them;
  - `no_package`: it names no such package, so no scanner can match it to a lockfile.
- **scanner-blind** = `package_not_in_osv` or `no_package`.

## Outcomes and tests

- **Primary**: share of scanner-blind advisories, ai vs control, among advisories
  published at least 14 days before the snapshot (GitHub reviewed 95% of repository
  advisories within five days after June 2022, per arXiv 2602.06009).
- **Secondary**: share with `own_id_in_osv` false; both shares split at 2026-05-01
  (the month GitHub described the backlog), before vs from.
- Uncertainty: Wilson 95% intervals on pooled shares, and a two-sided permutation test
  of the difference in pooled shares that shuffles group labels **across repositories**
  (10,000 permutations, seed 20261015), because advisories cluster within repositories
  (one project can hold 100+). Repository-level medians are reported too.
- Self-check: before measuring, the script confirms OSV returns a known GitHub-reviewed
  advisory (GHSA-39mp-8hj3-5c49, PyPI gradio) both by ID and by package query. If the
  package query fails, it measures visibility from each advisory's own OSV record only,
  and says so (`package_query: false`), which can only undercount visibility.

## Honest limits, stated in advance

- 60 repositories chosen by hand: a sample, not the ecosystem. The control choice is a
  judgment call; it is published here so anyone can rerun with their own.
- OSV is a stand-in for "a scanner". Dependabot reads GitHub's database directly; OSV
  mirrors GitHub-reviewed advisories, so unreviewed records never appear in OSV.
- A single snapshot. Per-repository results depend on how each project fills in its
  advisories (an app shipped only as a Docker image often names no package).
- No vendor-blaming: the point is the visibility gap downstream users face.
