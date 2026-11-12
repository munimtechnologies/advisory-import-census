# S20 pre-registration: GitHub-reviewed advisories frozen at "the newest release on review day"

Made by AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). Text: CC BY 4.0. Code: Apache-2.0.
Written 2026-11-12, before the census job ran. Nothing below has been seen in data yet.

## Question

When GitHub's curators review an advisory before a fix exists, they usually write the range as `<= X`,
where X is the newest release that day. In OSV this becomes `last_affected: X` and no `fixed` event.
If nobody moves the range later, every release after X counts as safe. Dependabot, `pip-audit`,
`osv-scanner` and `cargo audit --db osv`-style tools then say nothing about those releases, even when
they are still vulnerable.

We met this by hand in uutils coreutils on 2026-11-12
(docs/notes/uutils-advisory-ranges-2026-11-12.md): 16 reviewed records stop at 0.8.0, the newest release
when they were reviewed in April 2026, and for 8 of them the maintainers say 0.9.0 is also vulnerable.
S20 asks how common this is across all GitHub-reviewed advisories for **crates.io** and **PyPI**.

## Prior art (searched 2026-11-12)

- github/advisory-database PRs fix single records by hand, e.g. #8779, #9836, #10443, #11097 (reflex:
  the fix shipped about a year before the range was corrected).
- Slymaster/isitfixed (Go, Oct 2026) has a per-advisory check (IF003) that flags `last_affected` when
  later versions in the same major.minor line exist. It covers Go, npm, Maven and crates.io, not PyPI.
  It publishes no database-wide counts and does not compare X with the newest release on review day.
- We found no database-wide count of frozen ranges, and no cross-check against RustSec or PyPA.

## Method (frozen_ranges_s20.py, unit tests in test_frozen_ranges_s20.py)

1. Download OSV's full export for crates.io and PyPI (`all.zip`). Keep GHSA records that are not
   withdrawn, plus the ecosystem's own database: RUSTSEC-* for crates.io and PYSEC-* for PyPI.
2. Target: every ECOSYSTEM/SEMVER range of a GHSA record whose last event is `last_affected` and that has
   no `fixed` event.
3. For each package, list its releases from the registry (crates.io API, PyPI JSON API), with the
   upload date and yanked flag.
4. Reference day = `database_specific.github_reviewed_at`, or `published` if that is missing.
   **frozen** = X equals the newest non-yanked release uploaded on or before the reference day (stable
   only, or any release including pre-releases).
5. **later uncovered** = non-yanked releases above X that no range or version list of the same record
   covers.
6. **disputed** = later uncovered releases that a RUSTSEC/PYSEC record marks as affected for the same
   package. The record is linked by the GHSA ID or by a shared CVE alias.
7. Output: out/rows.csv (one row per target range) and out/summary.json.

## Predictions (graded in RESULTS.md)

- **P1.** For crates.io and PyPI separately, at least 50% of target ranges whose X exists in the
  registry are frozen.
- **P2.** For each ecosystem, at least 60% of frozen ranges have at least one later uncovered stable
  release.
- **P3.** Across both ecosystems, at least 15 rows are disputed.
- **P4 (control).** At least 16 crates.io rows for `coreutils` with X = 0.8.0 are frozen, with 0.9.0 as
  their first later uncovered release. If this fails, the method is wrong: no other number is reported
  until the cause is found.
- **P5 (hand check).** In each ecosystem, take the 20 frozen rows with a later uncovered stable release
  that come first when sorted by sha256(GHSA ID). In at least 25% of them, the first later uncovered
  release is still vulnerable. Grading: read the fix commit, PR or release notes and the boundary
  release's source, then grade each row V (still vulnerable), F (fixed) or U (unknown). The rate is
  V / (V + F). U rows are reported but left out of the rate.

Every disputed HIGH or CRITICAL row is also checked by hand before anyone acts on it.

## Limits

- A record re-reviewed after an edit gets a later `github_reviewed_at`, which can hide an earlier
  freeze, so frozen counts are a lower bound.
- A disputed row means two databases disagree. It does not prove which one is right.
- Upload dates come from the registries. Pre-releases and yanked releases are reported but don't count
  as "stable later releases".
- Only GitHub-reviewed records reach OSV. Unreviewed repository advisories (for example the uutils
  maintainers' own `uu_*` GHSAs) aren't in this census at all.
- Corrections go upstream one record at a time, at a pace maintainers can review. No bulk PRs.
