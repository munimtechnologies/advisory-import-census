# S18b results: which S18 rows could a vulnerability database actually add?

Graded 2026-11-12 (UTC) against the [pre-registration](PREREG.md), which was frozen on 2026-11-11 before any
S18b data was collected. Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0, code Apache-2.0.

## Run

- Script `actionable_s18b.py` 0.1.0, unit tests passed, run 2026-11-12 12:42-12:51 UTC.
- Input: S18 `rows.csv` (sha256 `57820589...d075f1`): 1,720 rows, 427 `NEITHER`, 332 graded. Integrity check passed.
- OSV `crates.io/all.zip` fetched 2026-11-12 12:42 UTC (sha256 `3a9909de...2893e1`, 1,452 RUSTSEC records).
- Gate **passed**. The crates.io controls were `serde` FOUND and `mv2-s18b-no-such-crate-zz9` NOT_FOUND. The REST
  advisory list worked for 59 of 59 repositories, and 0 rows were unresolved.
- Outputs (machine-written): [s18b_rows.csv](s18b_rows.csv), [crates.csv](crates.csv), [results.json](results.json),
  [sample.csv](sample.csv), [RESULTS-job.md](RESULTS-job.md).

## Status of the 332 rows

| status | rows | share |
|---|---|---|
| ACTIONABLE (a named Rust package exists on crates.io) | 275 | 82.8% |
| CVE_COVERED (its CVE is already in RustSec or a reviewed GHSA) | 22 | 6.6% |
| NO_CRATE (no named package exists on crates.io) | 29 | 8.7% |
| NOW_KNOWN (picked up by a database since S18) | 6 | 1.8% |

## Predictions

| | prediction | result | held |
|---|---|---|---|
| Q1 | at least 50% ACTIONABLE | 275 / 332 = 82.8% | yes |
| Q2 | at least 20% of the 94 CVE rows CVE_COVERED | 22 / 94 = 23.4% | yes |
| Q3 | NO_CRATE between 5% and 35% | 29 / 332 = 8.7% | yes |
| Q4 | at least 70% of the 238 no-CVE rows ACTIONABLE | 218 / 238 = 91.6% | yes |
| Q5 | at most 5% NOW_KNOWN | 6 / 332 = 1.8% | yes |
| Q6 | hand check of 8 seeded ACTIONABLE rows: at least 7 confirmed | 8 / 8 | yes |

### Q6 hand check (2026-11-12, ~13:15-13:45 UTC)

For each row we checked the four conditions in the PREREG. (1) The repository advisory page is public and
names the crate. (2) The crates.io crate belongs to the same project: the repository URL matched in
`crates.csv` for all 8, and we opened crates.io by hand for `mpp`, `nimiq-primitives` and
`nimiq-network-libp2p`. (3) `api.osv.dev/v1/vulns/<GHSA>` and `github.com/advisories/<GHSA>` both return
404. As controls, the same fetch tool returns GHSA-jfh8-c2jp-5v3q, and GitHub's search returns 14 advisories
for CVE-2021-44228. (4) If the advisory has a CVE, GitHub's advisory search finds no advisory for that CVE.

| GHSA | repository / crate | CVE | confirmed |
|---|---|---|---|
| GHSA-5rw2-6x5m-v22x | aws/s2n-quic / s2n-quic | CVE-2026-94450 (search: 0) | yes |
| GHSA-8xhq-x7vw-8rcw | tempoxyz/mpp-rs / mpp | none | yes |
| GHSA-929p-gjf6-5hqj | hickory-dns/hickory-dns / hickory-proto, hickory-net | none on the advisory (see note) | yes |
| GHSA-c45m-6x25-3cjq | nimiq/core-rs-albatross / nimiq-network-libp2p | CVE-2026-40094 (search: 0) | yes |
| GHSA-cg9x-2vfm-3j58 | superradcompany/microsandbox / microsandbox (+ -cli, -network) | none | yes |
| GHSA-mhp7-gmqr-h56w | nimiq/core-rs-albatross / nimiq-primitives | none | yes |
| GHSA-rhpr-p3gr-f4c9 | Orange-OpenSource/hurl / hurl | none | yes |
| GHSA-x298-9x87-fvjq | rustfs/rustfs / rustfs | CVE-2026-73290 (search: 0) | yes |

Note on GHSA-929p: the repository advisory lists no CVE, so it meets the PREREG rule. On 2026-11-08,
however, VulnCheck published CVE-2026-123581 for it, and GitHub now holds that CVE under an **unreviewed**
duplicate, GHSA-6w9h-68h2-v6xq, with no package attached. MV2 has proposed this advisory to RustSec in
rustsec/advisory-db#3559, with the CVE in `aliases`. Other hickory rows will likely look the same.

## Exploratory (not predicted)

- **By severity, ACTIONABLE:** 18 critical, 98 high, 129 moderate, 30 low.
- **Repository match:** for 255 of the 275 ACTIONABLE rows, the crate's crates.io repository is the
  advisory's repository. In the other 20 the names collide with unrelated crates. For example, `Frontier`
  (polkadot-evm/frontier) resolves to an unrelated crate `frontier` with 29 recent downloads and no
  repository. **255 is the better count of rows a database could add as written.**
- **CVE_COVERED:** 21 of the 22 rows are covered under a *different* crate from the one the advisory names
  (for example the uutils `uu_*` crates versus `coreutils`, as described in the PREREG), and only 1 under the
  same crate. We did not break the 21 down further.
- **Most-used ACTIONABLE rows** (crates.io downloads in the last 90 days), checked by hand on 2026-11-12:
  - **quinn-proto / quinn-udp (~155M):** GHSA-53rm-773f-4q8c and GHSA-wppq-2f6r-wfvm (quinn-proto, high) and
    GHSA-6pp4-4cxf-xf88 (quinn-udp, high), all published 2026-09-30 and fixed in quinn-proto 0.11.19 and
    quinn-udp 0.5.16 / 0.6.3. RustSec has quinn's August and 2026-09-14 advisories (RUSTSEC-2026-0338..0343)
    but not these three, and has no quinn-udp folder. None of the three has a CVE. MV2 has drafted the three
    RustSec entries from the fix commits (3eb7465, 3bba467 + d45b513, 462865a).
  - **inout (~134M):** GHSA-3832-prh6-8cpm, an out-of-bounds write through a safe API, affects only 0.2.3.
    That version was yanked two days after its release and fixed in 0.2.4. No advisory is planned (see
    below).
  - **tar (~78M):** GHSA-747h-hw98-c42x is an informational, low-severity note with no fix (concurrent
    filesystem mutation during `unpack`). It is a candidate for an informational entry, not a vulnerability
    entry.
  - **hickory-dns (~35M, 30 rows):** being imported to RustSec with the maintainers' agreement, in
    rustsec/advisory-db#3546, #3548, #3550, #3557 and #3559 so far.
- 68 CVEs are held by OSV only with Git ranges (listed in `results.json`).

## What this means

Of the 332 Rust repository advisories that S18 found in no scanner database, about 255 (77%) could be added
to RustSec or GitHub's reviewed database as written, because they name a real crates.io crate of the same
project. 116 of the 275 ACTIONABLE rows are rated high or critical. Only 6 were picked up by any database in
the days after S18.

## What we will do

As the PREREG says, any follow-up is one precise contribution at a time, never bulk contact. The three quinn
entries are drafted and go to RustSec as one normal pull request. The inout row is left alone on purpose: 0.2.3 was yanked by a RustSec maintainer who
also maintains the crate, so leaving it out of the database looks deliberate.

## Limits

- One snapshot (2026-11-12 12:42 UTC), and recent downloads rank use, not exposure.
- "Actionable" says nothing about whether an advisory is valid; the databases review that themselves.
- Q6 checked 8 rows by hand. The other 267 ACTIONABLE rows rely on the script's checks, and the 20 rows
  with a non-matching repository show that name lookups can mislead.
