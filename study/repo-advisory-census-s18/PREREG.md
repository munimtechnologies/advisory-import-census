# S18 pre-registration: published Rust repository advisories that no scanner database carries

Frozen 2026-11-10 (UTC), before any census data was collected. Made with AI agents working for MV2 of
Munim, Inc. Text CC BY 4.0, code Apache-2.0.

## Question

Maintainers can publish a GitHub *repository* security advisory on their own repository. Three
scanners read three different databases:

- Dependabot alerts only on advisories that GitHub has **reviewed** into its global Advisory Database.
  GitHub's docs say each repository advisory is reviewed "for consideration" as a global advisory, so
  inclusion isn't automatic.
- cargo-audit and cargo-deny read only the **RustSec** Advisory Database.
- osv-scanner reads **OSV**, which imports GitHub's global advisories and RustSec.

How many published repository advisories for Rust crates are in **none** of these, so that none of
the three scanners can report them? How are they distributed across repositories, CVE status and
severity?

## Why this is new (prior-art search, 2026-11-10)

- rustsec/advisory-db#1711 and our own S14 (study/rust-ghsa-only-s14) count GitHub-**reviewed**
  advisories missing from RustSec. Neither looks at repository advisories that never reached
  GitHub's global database.
- Academic work on the GitHub Advisory Database (for example the empirical study of GitHub security
  advisories and huntr, https://par.nsf.gov/servlets/purl/10618325) counts **unreviewed global**
  advisories, which come mostly from the NVD feed. That is a different population: those records exist
  in the global database, while the ones counted here do not.
- Our tools/rustsec_import_prep.py (v0.24.0+) flags NOT_IN_OSV per crate on request. This study is
  the first frame-wide count we know of.

## Seed observation (disclosed, excluded from grading)

While preparing RustSec imports on 2026-11-10, we read by hand the published advisory list of
zip-rs/zip2 (crate `zip`, about 102 million recent downloads on crates.io). It holds 34 published
repository advisories. GitHub's global database lists 6 for the `zip` crate and RustSec 5, which
together cover 9 distinct IDs. That leaves 25 in neither, including GHSA-5wm9-6g4v-jq7c (critical)
and GHSA-v59p-pxfc-8xvf (high), both of which return 404 at api.osv.dev. The 12 of the 25 we could read
in the REST response all have no CVE, while all 6 in GitHub's global database have one. This observation motivated the study, so **zip-rs/zip2 is excluded from all graded
predictions**. Its job count is reported separately as a check of the parser (gate below).

## Frame and method (script: repo_advisory_census.py 0.1.0)

1. Download OSV's crates.io export (`crates.io/all.zip`). Index each GHSA record (reviewed or not,
   withdrawn or not) and every GHSA ID that a live RUSTSEC record lists in `aliases` or `related`.
2. **Frame:** every GitHub repository named in a `https://github.com/OWNER/REPO/security/advisories/GHSA-...`
   reference of any record in the export. Renamed repositories that redirect to the same
   repository are counted once.
3. For each repository, read the public list of published advisories
   (`/security/advisories?state=published&page=N`, about one request per second, unauthenticated).
   Stop when a page adds no new ID. Up to 40 pages per repository.
4. Every listed ID that is not in the export is looked up once at `api.osv.dev/v1/vulns/<id>`.
5. For repositories with at least one ID that OSV doesn't know, read the public REST endpoint
   `GET /repos/OWNER/REPO/security-advisories?state=published` once (unauthenticated, waiting for the
   rate limit up to 150 minutes into the job). Keep only ecosystem, package name, severity,
   publication date, CVE presence and withdrawal. No usernames, credits or other personal data are stored.
6. Status of each listed ID, first match wins:
   - `WITHDRAWN`: withdrawn in the export (and not in RustSec) or per the REST endpoint.
   - `BOTH`: a live RUSTSEC record aliases it and it is a reviewed GHSA.
   - `RUSTSEC_ONLY`: aliased by a live RUSTSEC record only.
   - `GHSA_ONLY`: a reviewed GHSA only.
   - `OSV_UNREVIEWED_ONLY`: an unreviewed GHSA record in the export only.
   - `OSV_NOT_IN_EXPORT`: OSV knows it under crates.io but the export didn't have it (sync lag).
   - `OTHER_ECOSYSTEM`, `NO_PACKAGE`, `UNKNOWN_ECOSYSTEM` (REST step skipped or failed), `OSV_ERROR`.
   - **`NEITHER`**: unknown to OSV, and the repository advisory names the `rust` ecosystem.
7. **Rust rows** are the first six statuses plus `NEITHER`. **Graded rows** are Rust rows published
   before **2026-10-27** (at least two weeks of review time), outside zip-rs/zip2.

**Gate** (otherwise no prediction is graded and the run is reported as failed): at least 500 RUSTSEC
records in the export, at least 100 frame repositories, at least 200 listed IDs, and, if zip-rs/zip2
is in the frame, at least 30 IDs listed for it (a parser self-check against our hand count of 34).

## Predictions (graded on the graded rows)

- **P1:** at least 20 rows are `NEITHER`.
- **P2:** the `NEITHER` rows come from at least 5 distinct repositories.
- **P3:** CVE gradient. The share of `NEITHER` among rows without a CVE is at least 3 times the share
  among rows with a CVE (or the CVE share is 0 and the no-CVE share is above 0). Needs at least 10
  rows without a CVE, otherwise inconclusive.
- **P4:** at least 25% of `NEITHER` rows are high or critical.
- **P5:** at least 90% of frame repositories (excluding deleted repositories and duplicates) list
  without error (`OK`).
- **P6:** hand check. Of 8 `NEITHER` rows drawn with seed 20261111, at least 7 are confirmed by
  hand: the advisory page is public and names a Rust crate, api.osv.dev returns 404 for the ID,
  github.com/advisories/<id> does not exist, and rustsec.org has no advisory aliasing it.

Exploratory, not predicted: `NEITHER` by severity, repository and month; all-date `NEITHER` count;
the seed repository's status counts.

## Limits, stated in advance

- The frame only contains repositories that already have at least one advisory known to OSV for
  crates.io. Repositories whose advisories never reached any database are outside it, so totals are
  lower bounds.
- The HTML list is read logged-out. If GitHub changes the page layout, the gate's self-check should
  catch it.
- `NEITHER` depends on the maintainer having set the `rust` ecosystem. Advisories with no package
  (`NO_PACKAGE`) are reported but not counted.
- One run, one snapshot. GitHub's review queue changes daily.

## What we will do with the result

The graded result goes in RESULTS.md next to this file, whether the predictions held or not. Any
upstream follow-up (RustSec imports, a note to GitHub's curation team) will be one precise report per
database, with the published rows, never bulk contact with maintainers.
