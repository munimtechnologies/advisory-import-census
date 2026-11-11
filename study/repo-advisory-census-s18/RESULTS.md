# S18 results: published Rust repository advisories that no scanner database carries

Graded 2026-11-11 (UTC) against [PREREG.md](PREREG.md) (frozen 2026-11-10, before any data). Made with AI
agents working for MV2 of Munim, Inc. Text and data CC BY 4.0, code Apache-2.0.

**Result: the gate passed and all six predictions held.** Of 1,149 graded Rust advisory rows, **332 are
published repository advisories that are in none of GitHub's global Advisory Database, RustSec or OSV**,
so Dependabot, cargo-audit/cargo-deny and osv-scanner cannot report them. They come from 59 repositories;
131 (39.5%) are rated high or critical. Two kinds of false positive turned up while grading (below), so
the robust core is the **238 rows that have no CVE**; a follow-up (S18b) measures how many of the
332 are actionable.

## Run

- Job `repo-advisory-census-s18-v1`, script `repo_advisory_census.py` 0.1.0, unit tests passed in the
  container first. Started 2026-11-11 01:39 UTC, finished 02:56 UTC.
- Input: OSV's `crates.io/all.zip`, fetched 2026-11-11T01:39:28Z, 3,828,416 bytes, sha256
  `d07cc6bb467cf5d1427ab63f45393d460ae55b385726cc139f93a538b078f3c1`.
- Outputs in this folder: [rows.csv](rows.csv) (every listed advisory and its status),
  [repos.csv](repos.csv), [sample.csv](sample.csv), [results.json](results.json). No usernames, credits
  or other personal data are stored.

## Gate

PASSED: 1,427 RUSTSEC records (needs 500), 271 frame repositories (needs 100), 1,720 listed IDs (needs
200), seed repository zip-rs/zip2 listed 35 IDs (needs 30; our hand count on 2026-11-10 was 34; the
difference of one was not investigated).

## Predictions

| | Prediction | Result | Held |
|---|---|---|---|
| P1 | at least 20 graded rows are `NEITHER` | **332** | yes |
| P2 | from at least 5 repositories | **59** | yes |
| P3 | no-CVE `NEITHER` share at least 3x the CVE share | no CVE: 238 of 384 (**62.0%**); CVE: 94 of 765 (**12.3%**); ratio 5.0x | yes |
| P4 | at least 25% high or critical | 131 of 332 (**39.5%**: 20 critical, 111 high) | yes |
| P5 | at least 90% of repositories list without error | 261 of 261 (**100%**; 10 more were duplicates of renamed repos) | yes |
| P6 | at least 7 of 8 seeded rows confirmed by hand | **8 of 8** by the pre-registered test (7 of 8 under a stricter reading, see below) | yes |

### P6 hand check (2026-11-11, about 03:30-04:00 UTC)

Pre-registered test: the advisory page is public and names a Rust crate; `api.osv.dev/v1/vulns/<id>`
returns 404; `github.com/advisories/<id>` does not exist; rustsec.org has no advisory aliasing it.
Positive control: `github.com/advisories/GHSA-6f2x-v7q7-m7m5` (a reviewed hickory-resolver advisory)
loaded normally with the same fetcher, so the 404s below are real.

| GHSA | Repository | Crate(s) | Sev. | CVE | Public page | OSV | GitHub DB | RustSec |
|---|---|---|---|---|---|---|---|---|
| GHSA-gcv3-45r8-25hc | boxlite-ai/boxlite | boxlite, boxlite-cli (+npm, pip, Go) | high | none | yes | 404 | 404 | 2 boxlite advisories, both about other bugs (OCI symlink, remount) |
| GHSA-m58v-wpjx-9fc8 | fulgur-rs/fulgur | fulgur, fulgur-cli | moderate | none | yes | 404 | 404 | 2 fulgur advisories, both other bugs (page amplification) |
| GHSA-6h5c-jjg5-wj59 | hickory-dns/hickory-dns | hickory-recursor, hickory-resolver | high | none | yes | 404 | 404 | no hickory-resolver page; hickory-recursor's only entry is a different bug |
| GHSA-9mm4-fgvc-x7rp | jdx/mise | mise | moderate | CVE-2026-71477 | yes | 404 | 404 (and no advisory found for the CVE) | no page |
| GHSA-mhp7-gmqr-h56w | nimiq/core-rs-albatross | nimiq-primitives | high | none | yes | 404 | 404 | no page |
| GHSA-w5f8-87h2-m573 | nimiq/core-rs-albatross | nimiq-network-libp2p | low | none | yes | 404 | 404 | no page |
| GHSA-54x6-c4c8-44fr | uutils/coreutils | coreutils | moderate | none | yes | 404 | 404 | no page |
| GHSA-g2fc-grr3-r5qg | uutils/coreutils | uu_split | low | CVE-2026-35375 | yes | 404 | 404 | no page |

**Stricter reading.** The last row passes the pre-registered test, but the same bug (CVE-2026-35375,
`split` rewriting non-UTF-8 filename bytes) is already in GitHub's database as the reviewed
GHSA-vx9m-xjwf-8cqm, imported from NVD on 2026-04-22 and filed under the `coreutils` crate. Scanners
therefore warn users of `coreutils` < 0.8.0 but not users who depend on `uu_split` directly. Counting
it as covered gives 7 of 8, which still meets P6.

## Two kinds of false positive found while grading (not predicted)

1. **CVE duplicates.** The census matches by GHSA ID only. When a maintainer's repository advisory
   carries a CVE, GitHub may already hold the same vulnerability under a *different* GHSA ID imported
   from NVD (the uu_split case above). Rows with a CVE (94 of 332) can therefore overcount.
2. **CVE records that OSV holds under the CVE ID.** `api.osv.dev/v1/vulns/GHSA-q455-m56c-85mh`
   (Rust's 2024 `std::process::Command` batch-file advisory) is a 404, but OSV serves `CVE-2024-24576`
   with that GHSA as an alias and a Git range only. The `std` "crate" is not on crates.io, so no
   lockfile scanner would match it anyway.
3. Related: some rows name packages that are not crates.io crates (`std`, `Frontier`,
   `` `nono-proxy` component of `nono` ``). GitHub can only add advisories for packages on a supported
   registry, so these rows are not reviewable as written.

None of these touch the 238 rows without a CVE as far as (1) and (2) go. (3) can affect any row.
**S18b** (pre-registered next to this file) looks up each row's CVE ID and every Rust package name on
crates.io to count the rows that are actually actionable, and ranks them by crates.io downloads.

## Disclosures

- **hickory-dns was checked by hand before this data existed.** On 2026-11-10 we read hickory-dns's
  advisory list while preparing RustSec imports and found 35 of its 38 advisories published on
  2026-09-03 in no database. It was not excluded from grading (PREREG named only zip-rs/zip2). Without
  hickory-dns, `NEITHER` is 297 rows from 58 repositories, so P1, P2 and P4 hold either way
  (hickory contributes 9 of the 131 high/critical rows).
- The three hickory-resolver advisories that GitHub did review (GHSA-5j98, -6f2x, -6w6g, reviewed
  2026-10-05) have no CVE. So GitHub does sometimes review advisories without a CVE. P3 describes a
  strong tendency, not a rule.
- One snapshot. GitHub's review queue changes daily. Rows published on or after 2026-10-27 (for example
  actix-multipart GHSA-48p4-xj33-4fw4, rustix GHSA-jh2m-fhpj-3vr7, and 25 of zip's) are listed in
  rows.csv but not graded.

## What the numbers say

- **The gap is recent.** 253 of the 332 graded rows (76%) were published between July and October
  2026 (43, 52, 85 and 73 per month; October counts only up to the 26th). Before 2026 the frame has
  only a handful per year. That looks like a growing review backlog, not old leftovers.
- **It is concentrated.** Five repositories hold 146 of the 332: hickory-dns/hickory-dns 35,
  uutils/coreutils 42, zcashfoundation/zebra 25, rustfs/rustfs 23 and surrealdb/surrealdb 21.
- **GitHub's own documentation sets the expectation.** "About repository security advisories" says
  that GitHub will review each published security advisory, add it to the GitHub Advisory Database,
  and that "This process can take up to 72 hours." Every graded row had been published for at least
  two weeks when the census ran.

## Next

- S18b: actionable subset and download-ranked list (job `repo-advisory-actionable-s18b-v1`).
- Upstream: one precise report per database with the actionable rows, never bulk contact with
  maintainers. RustSec imports continue one crate per pull request, as RustSec's maintainers asked.
