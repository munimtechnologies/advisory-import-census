# S18b pre-registration: which S18 rows could a database actually add?

Frozen 2026-11-11 (UTC), before any S18b data was collected. Made with AI agents working for MV2 of
Munim, Inc. Text CC BY 4.0, code Apache-2.0.

## Why

S18 ([RESULTS](../repo-advisory-census-s18/RESULTS.md)) found 332 graded Rust repository advisories that
are in none of GitHub's global Advisory Database, RustSec or OSV. Grading turned up two kinds of
false positive that S18 could not see, because it matched by GHSA ID only and never checked crates.io:

1. A repository advisory with a CVE can duplicate a vulnerability that GitHub already holds under a
   different GHSA ID imported from NVD (uutils' `uu_split` advisory GHSA-g2fc-grr3-r5qg duplicates the
   reviewed GHSA-vx9m-xjwf-8cqm, which is filed under `coreutils`).
2. Some advisories name packages that are not crates.io crates (`std`, `Frontier`,
   `` `nono-proxy` component of `nono` ``), so GitHub and RustSec cannot add them as written.

Before anyone asks a database to add these rows, we want the actionable subset and a ranking by real
use (crates.io recent downloads).

## Prior art (2026-11-11)

S18 is the only frame-wide count of repository advisories missing from all three databases that we know
of (its PREREG lists the prior art). Nobody we know of has ranked such a gap by crates.io downloads or
removed CVE duplicates from it.

## Frame and method (script: actionable_s18b.py 0.1.0)

1. Input: S18's published `rows.csv`. Integrity check: exactly 1,720 rows, 427 `NEITHER`, and 332
   graded `NEITHER` rows (published before 2026-10-27, outside zip-rs/zip2). Only those 332 rows are
   studied.
2. Download OSV's `crates.io/all.zip` again. "Known" GHSA IDs: every GHSA record in it plus every GHSA
   that a live RUSTSEC record lists in `aliases` or `related`. CVE coverage: every CVE in the `aliases`
   of a live RUSTSEC record or a live GitHub-reviewed GHSA record, with that record's crates.
3. For each of the 59 repositories, read the public REST list of published repository advisories once
   (unauthenticated) and keep each advisory's CVE ID, withdrawal, Rust package names, vulnerable range
   and patched versions. No usernames, credits or other personal data are stored.
4. Look up every graded GHSA ID that is not "known" at `api.osv.dev/v1/vulns/<id>`, and every CVE ID
   at `api.osv.dev/v1/vulns/<cve>`.
5. Look up every Rust package name at `crates.io/api/v1/crates/<name>` (one request per second; names
   that are not valid crate names are not requested; `-`/`_` and case variants are tried). Keep the
   canonical name, recent downloads and the repository URL.
6. Status of each row, first match wins:
   - `API_MISSING`: the REST list did not return the advisory.
   - `WITHDRAWN`: withdrawn per the REST list.
   - `NOW_KNOWN`: the GHSA ID is now "known" or `api.osv.dev` returns it (picked up since S18).
   - `OSV_ERROR`: the OSV lookup failed.
   - `CVE_COVERED`: its CVE is covered by a live RUSTSEC or reviewed GHSA record, or OSV's record for
     the CVE names a crates.io package.
   - `ACTIONABLE`: at least one of its Rust package names exists on crates.io.
   - `CRATE_ERROR`: a crates.io lookup failed and none succeeded.
   - `NO_CRATE`: none of its Rust package names exists on crates.io (or none is a valid name).
   `API_MISSING`, `OSV_ERROR` and `CRATE_ERROR` are "unresolved".

**Gate** (otherwise nothing is graded): the integrity check passes; at least 500 RUSTSEC records in the
export; crates.io control lookups give `serde` FOUND and `mv2-s18b-no-such-crate-zz9` NOT_FOUND; the
REST list works for at least 90% of the 59 repositories; at most 10% of rows are unresolved.

## Predictions (graded on the 332 rows)

- **Q1:** at least 50% are `ACTIONABLE`.
- **Q2:** of the rows S18 marked as having a CVE (94), at least 20% are `CVE_COVERED`.
- **Q3:** `NO_CRATE` is between 5% and 35% of rows.
- **Q4:** of the rows S18 marked as having no CVE (238), at least 70% are `ACTIONABLE`.
- **Q5:** at most 5% are `NOW_KNOWN` (little changes in the days after S18).
- **Q6:** hand check of 8 `ACTIONABLE` rows drawn with seed 20261112: at least 7 confirmed. Confirmed
  means the advisory page is public and names the crate; the crate on crates.io belongs to the same
  project (its repository or homepage is the advisory's repository, or its page clearly describes the
  same project); `api.osv.dev` and `github.com/advisories/<id>` both return 404 for the GHSA ID; and if
  the advisory has a CVE, GitHub's advisory search finds no advisory for that CVE on that crate.

Exploratory, not predicted: `ACTIONABLE` by severity and repository; the 30 `ACTIONABLE` rows with the
highest crates.io recent downloads; whether a `CVE_COVERED` row is covered under the same crate or a
different one; CVEs that OSV holds only with Git ranges; how often a found crate's repository URL
matches the advisory's repository.

## Limits, stated in advance

- A crate with the same name may belong to another project (name squatting or reuse). The repository
  match is reported, and Q6 checks it by hand, but `ACTIONABLE` does not require it.
- "Actionable" means a database could add the row as written. It says nothing about whether the
  advisory is valid; GitHub and RustSec review that themselves.
- Recent downloads (90 days) rank use, not exposure, and repository-wide advisories often name an
  application crate that few people depend on.
- One snapshot, a day or two after S18.

## What we will do with the result

The graded result goes in RESULTS.md next to this file, whether the predictions held or not. Any
upstream follow-up is one precise report per database with the actionable rows, never bulk contact
with maintainers.
