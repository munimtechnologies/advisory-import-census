# S21 pre-registration: pre-releases left out by an advisory's "introduced" bound (crates.io)

Registered 2026-11-13, before any census data was collected. Made by AI agents working for MV2 of Munim, Inc. Text CC BY 4.0, code Apache-2.0.

## Why

Under SemVer ordering, `0.26.0-beta.1 < 0.26.0`. A range that begins `introduced: 0.26.0` therefore treats every published 0.26.0 pre-release as unaffected. That's correct only if the vulnerable code first shipped in 0.26.0 itself. While checking hickory-dns advisories by hand (docs/notes/hickory-range-checks-2026-11-13.md), we found this pattern in 4 ranges. We also found a second form 3 times: the bound names a version that was never published (hickory-recursor 0.25.0, which only had alphas), so the alphas that carried the code are left out.

Prior art we checked: OSV's linter (ossf/osv-schema tools/osv-linter) has check PKG:002 "package-versions-exist". For a single record, it flags range events that name a version missing from the registry, which covers our second form. We found no check for the first form, a stable `introduced` bound that leaves out published pre-releases. We also found no database-wide count of either form for GitHub's crates.io advisories. Two earlier ideas were dropped because of prior art: a general range-gap census (Safeguard.sh) and a per-advisory fix checker (isitfixed).

## What the job does (prerelease_gap_s21.py)

1. It downloads OSV's crates.io export and keeps the non-withdrawn GHSA and RUSTSEC records.
2. It looks at every GHSA range whose `introduced` bound is a stable version other than `0`. For each one, it lists the bound version's pre-releases that are published and not yanked on crates.io (taken from the crates.io API at 1 request/second), and drops any that another range or the `versions` list of the same record already covers. It also flags bounds that crates.io never published.
3. For the remaining pre-releases, it checks whether a RustSec record linked by GHSA or CVE alias marks them as affected.
4. It makes a secondary count of `fixed` bounds at a stable version whose pre-releases are published. Those pre-releases count as affected, which is correct only if the fix came after them.

Every row is a candidate, not a finding. A gap only matters if the vulnerable code is already in the pre-release.

## Predictions (written before the run)

- **P1:** at least 15 GHSA ranges have one or more uncovered published pre-releases of their `introduced` version (`gap_rows >= 15`).
- **P2:** at least 5 ranges have an `introduced` bound that crates.io never published (`bound_unpublished_rows >= 5`). At least 2 of those also have published pre-releases of that version (`bound_unpublished_with_gap >= 2`).
- **P3:** most gap rows that are linked to a RustSec record are not covered by RustSec either: `gap_rustsec_covers / gap_with_rustsec < 0.5`. The reason is that RustSec ranges are usually written as `patched` with an implicit lower bound of 0, or as similar stable bounds.
- **P4 (hand check, graded by reading source):** we take up to 10 gap rows, chosen by sorting rows.csv by GHSA ID and picking every k-th one. For each, we read the advisory's fix commit and then the source of the first gap pre-release (docs.rs or the tag). The prediction is that at least 3 of the 10 contain the vulnerable code, meaning the gap is real.
- **Sanity check (must pass before any number is reported):** the unit tests pass, `ghsa_records >= 500`, and `errors.no_registry_data` is under 5% of the packages looked up. If any of these fail, we look for a bug and do not report numbers.

## Payoff

Each gap that is verified by reading source gets one "[GHSA-x] include pre-releases" correction PR on github/advisory-database, at most one a day. If the same advisory is in RustSec, a RustSec range fix follows the same route as RUSTSEC-2026-0514.

## Limits

This covers crates.io only. It uses one OSV snapshot and today's crates.io version lists, so yanking and later edits change the result. Unreviewed GHSAs, such as most of hickory's, are not in OSV's export, so the hickory cases that led to this study can't serve as a positive control. The unit tests use synthetic hickory-like version lists instead.
