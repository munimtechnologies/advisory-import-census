# S14: GitHub-reviewed Rust advisories that cargo-audit cannot see (pre-registration)

Frozen 2026-11-09 (UTC), before any data for this study was collected. Code: `ghsa_only_rust.py`
(v0.1.0), tests: `test_ghsa_only_rust.py`. Apache-2.0 code; the results data will be CC BY 4.0.
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

## Question

`cargo audit` and `cargo deny` check a project's `Cargo.lock` against the RustSec Advisory Database
([rustsec/advisory-db](https://github.com/rustsec/advisory-db)) only. GitHub imports RustSec advisories
into its own Advisory Database, but the other direction is manual: a crates.io advisory that a
maintainer publishes through GitHub reaches RustSec only if someone files it there. Projects have
noticed the gap in their own CI (for example [send/lexime#403](https://github.com/send/lexime/pull/403),
which added a separate GitHub-API check because a critical `zip` advisory, GHSA-m665-v7pm-7grj, never
reached `cargo deny`), and outside contributors file such imports by hand (rustsec/advisory-db
#3514-#3517, November 2026). We found no published count of how many GitHub-reviewed crates.io
advisories have no RustSec counterpart (searched 2026-11-09).

1. How many GitHub-reviewed, non-withdrawn crates.io advisories have no RustSec counterpart?
2. Is the gap growing (recent advisories more often GitHub-only than older ones)?
3. Where do the GitHub-only advisories come from, and how severe are they?

## Data (fetched and recorded by the job)

OSV's public crates.io export, `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip`,
which holds both the RUSTSEC records and GitHub's GHSA records for crates.io. The job records the
download time, size and SHA-256, and writes one row per eligible GHSA record (`rows.csv`).

## Definitions

- **Eligible GHSA record:** a `GHSA-*` record with `database_specific.github_reviewed` true, no
  `withdrawn` field, and at least one affected package in the `crates.io` ecosystem.
- **Covered**, checked in this order (the first match is the reason): the GHSA record lists a
  `RUSTSEC-*` ID in `aliases` or `related` (`alias_in_ghsa`); a RUSTSEC record lists the GHSA ID
  (`alias_in_rustsec`); a RUSTSEC record shares a CVE ID with it (`shared_cve`); the GHSA record
  links to `rustsec.org/advisories/RUSTSEC-...` or `github.com/rustsec/advisory-db` (`reference`).
  If every matching RUSTSEC record is withdrawn, the row is `COVERED_WITHDRAWN` (RustSec decided),
  not GitHub-only.
- **GHSA_ONLY:** eligible and not covered.
- **Graded rows:** eligible records published before 2026-10-01, so that advisories still in the normal
  filing lag do not count. Later ones are reported separately.
- **Repository advisory:** the record links to `github.com/<owner>/<repo>/security/advisories/GHSA-...`.
- **Recent / old:** GHSA `published` from 2025-01-01 to 2026-09-30 / from 2019-01-01 to 2022-12-31.

## Predictions (thresholds fixed now)

| | Prediction |
|---|---|
| P1 | At least 100 graded GHSA records are GHSA_ONLY. |
| P2 | The GHSA_ONLY share of recent graded records is at least 10 percentage points higher than that of old graded records. |
| P3 | At least 50% of GHSA_ONLY records link to a GitHub repository advisory. |
| P4 | At least 30% of GHSA_ONLY records have GitHub severity HIGH or CRITICAL. |
| P5 | GHSA_ONLY records cover at least 50 distinct crates. |
| P6 | Of a seeded sample (seed 20261109, up to 8) of GHSA_ONLY records, at least 6 are confirmed by hand live: `api.osv.dev/v1/vulns/<GHSA>` lists no RUSTSEC ID in aliases or related, an OSV query for the crate returns no RUSTSEC record that names the GHSA or shares its CVE, and no pull request in rustsec/advisory-db names the GHSA ID. |

Reported but not predicted: the share of GHSA_ONLY records whose CWE suggests denial of service,
the share whose crate already has another live RustSec advisory, the share with a CVE, counts by year,
and GHSA_ONLY records published on or after 2026-10-01.

## Sanity gate (floors, not expected values)

At least 500 RUSTSEC records and at least 300 eligible GHSA records in the export. If a floor fails,
the job writes no verdicts and the study is fixed in the open and re-run with the predictions unchanged.

## What happens with the result

The table is published as open data. RustSec's own guide lets anyone file an advisory for any crate
once its details are public, and its template has an `aliases` field for GHSA imports. After grading,
hand-checked GHSA_ONLY records may be filed as **one pull request at a time** (one advisory file each,
no second PR until the first is merged or answered), only where the flaw fits RustSec's scope (for
example, an ordinary panic is in scope only for code advertised as panic-free). Every PR says plainly
that it was prepared with AI agents and offers to stop if the maintainers would rather not receive them.

## Known limits

- One snapshot of OSV's export; RustSec's ID-sync job and GitHub's review both keep moving.
- Matching uses IDs and CVEs only. A RustSec advisory that describes the same flaw under no shared
  ID would be missed, which is one reason for the hand check in P6.
- Some GitHub-only records may be out of RustSec's scope on purpose (for example, applications that are
  not libraries, or panics); the study counts the gap, it does not say every row belongs in RustSec.
- GitHub's severity is GitHub's own rating.
