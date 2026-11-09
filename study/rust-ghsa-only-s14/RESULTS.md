# S14 results: GitHub-reviewed Rust advisories that cargo-audit cannot see

Graded 2026-11-09 (UTC) against the frozen plan in [`PREREG.md`](PREREG.md). Job `rust-ghsa-only-s14-v1`
ran `ghsa_only_rust.py` 0.1.0 once (offline tests passed first); its raw output is in [`job-v1/`](job-v1/).
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). No result here has been reviewed
by a human. Apache-2.0 (code) / CC BY 4.0 (text and data).

**Result: 620 of 1,492 GitHub-reviewed crates.io advisories published before 2026-10-01 (41.6%) have no
RustSec counterpart, so `cargo audit` and `cargo deny` never report them. The gap is larger every year:
3.5% of 2021 advisories, 54.8% of 2025 and 73.4% of 2026 (January to September). All six predictions held.**

## Data

OSV's public crates.io export, `https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip`,
fetched 2026-11-09T10:49:19Z, 3,810,821 bytes, SHA-256
`7abffde76a9aa47070461693799de7ac508f56ac59e9aeb814351778d32c999b`. It held 3,063 records: 1,410 RUSTSEC
and 1,631 GHSA, of which 1,532 are eligible (GitHub-reviewed, not withdrawn, at least one crates.io package).
The sanity gate (at least 500 RUSTSEC and 300 eligible GHSA records) passed.

Graded rows (eligible, published before 2026-10-01): **1,492**. How each was matched:

| Status (reason) | Records |
|---|---|
| COVERED: the GHSA record lists a RUSTSEC ID (`alias_in_ghsa`) | 862 |
| COVERED: the GHSA record links to rustsec.org or rustsec/advisory-db (`reference`) | 9 |
| COVERED_WITHDRAWN: only a withdrawn RUSTSEC record names it | 1 |
| **GHSA_ONLY** | **620** |

No graded row was matched through a shared CVE, and only the one withdrawn case was matched through a
RUSTSEC record naming the GHSA. Wherever RustSec has a live advisory for the flaw, OSV's export already
carries the link on the GHSA side.

## Predictions

| | Prediction | Result | Held |
|---|---|---|---|
| P1 | At least 100 graded GHSA records are GHSA_ONLY | 620 | yes |
| P2 | Recent (2025-01-01..2026-09-30) GHSA_ONLY share at least 10 points above old (2019..2022) | 68.2% (434/636) vs 10.6% (58/546): +57.6 points | yes |
| P3 | At least 50% of GHSA_ONLY records link to a GitHub repository advisory | 86.1% (534/620) | yes |
| P4 | At least 30% of GHSA_ONLY records are HIGH or CRITICAL (GitHub's rating) | 42.3% (262/620) | yes |
| P5 | GHSA_ONLY records cover at least 50 distinct crates | 703 (some advisories name several crates) | yes |
| P6 | At least 6 of the 8 seeded GHSA_ONLY records confirmed by hand live | 8 of 8 | yes |

**6 of 6 held.**

### P6 by hand (2026-11-09 UTC, after the job finished)

For each record: `https://api.osv.dev/v1/vulns/<GHSA>` (no RUSTSEC ID in `aliases` or `related`, no
rustsec link in `references`); the crate's page on rustsec.org (`https://rustsec.org/packages/<crate>.html`,
which lists every RustSec advisory for the crate and returns 404 when there is none); and a GitHub search
of rustsec/advisory-db for the GHSA ID.

| GHSA | Crate | OSV aliases | RustSec advisories for the crate | Pull requests naming it |
|---|---|---|---|---|
| GHSA-3g92-f9ch-qjcm | p3-symmetric | none | none (404) | none |
| GHSA-65jj-fmw8-468q | zebrad | CVE-2026-52734 | none (404) | none |
| GHSA-7c4j-2m43-2mgh | nimiq-primitives | CVE-2026-34065 | none (404) | none |
| GHSA-7fw6-6mfj-g3q2 | ckb | none | 3, all from Sept 2021 (RUSTSEC-2021-0107/0108/0109), none for this 2022 flaw | none; issues [#1484](https://github.com/rustsec/advisory-db/issues/1484) and [#1711](https://github.com/rustsec/advisory-db/issues/1711) name it |
| GHSA-f8qm-hmm3-fv7f | namada-apps | none | none (404) | none |
| GHSA-hqmp-g7ph-x543 | quincy | none | none (404) | none |
| GHSA-mphm-gqh9-q59x | microbin | CVE-2023-27075 | none (404) | none; issue [#1711](https://github.com/rustsec/advisory-db/issues/1711) names it |
| GHSA-r5fr-9gmv-jggh | scim_proto, kanidm_proto | CVE-2026-46689 | none for either (404) | none |

**Deviation from the plan, stated openly:** P6 called for "an OSV query for the crate". That query is a POST
request, which the hand-checking tool cannot send, so the crate's rustsec.org page (the same RustSec
records, published by RustSec itself) was used instead. The `ckb` page was checked to confirm that
the package-page pattern works for a crate that has advisories.

## Correction to the pre-registration: there was an earlier count

PREREG.md says "We found no published count". That was wrong. RustSec maintainer amousset opened
[rustsec/advisory-db#1711](https://github.com/rustsec/advisory-db/issues/1711) on 2023-06-13 with
"Currently 92 missing advisories" (GitHub advisories from September 2021 to June 2023). The list came from
the sync command in [rustsec/rustsec#656](https://github.com/rustsec/rustsec/pull/656), which was merged
in February 2024 with the stated aim of running it in CI. The issue is still open. S14 is therefore an
**update and a trend**, not the first count. The two counts are not directly comparable: #1711 counted
GitHub advisories RustSec lacked as of June 2023, and S14 counts GitHub-reviewed records with no RustSec
link in OSV's export as of November 2026. For advisories published 2021-2023, S14 finds 106 still GitHub-only,
and both sampled records that appear on #1711's 2023 list (ckb, microbin) are still missing.

[#1484](https://github.com/rustsec/advisory-db/issues/1484) also explains one obstacle: GitHub's advisory
text is CC BY 4.0, and RustSec publishes under CC0. So an import cannot copy GitHub's wording, and each
advisory has to be written afresh. In 2023 the maintainers said they would "import them directly from GHSA
at some point".

## What else the data shows (exploratory, not predicted)

GHSA_ONLY share of graded records by year published:

| Year | Graded | GHSA_ONLY | Share |
|---|---|---|---|
| 2021 | 317 | 11 | 3.5% |
| 2022 | 229 | 47 | 20.5% |
| 2023 | 133 | 48 | 36.1% |
| 2024 | 177 | 80 | 45.2% |
| 2025 | 177 | 97 | 54.8% |
| 2026 (to Sept 30) | 459 | 337 | 73.4% |

- 506 of 620 (81.6%) carry a CVE. 130 (21.0%) have a CWE that suggests denial of service.
- **195 of 620 (31.5%) are for a crate that already has another live RustSec advisory.** Scope or notability is
  unlikely to explain why those crates are missing a RustSec advisory.
- Of the 40 eligible records published on or after 2026-10-01 (excluded from grading), 24 are GHSA-only. They
  include GHSA-m665-v7pm-7grj for `zip` (CRITICAL), the advisory whose absence from `cargo deny` led
  [send/lexime#403](https://github.com/send/lexime/pull/403) to add a separate GitHub check.

### Case: the `openssl` crate

`openssl` (rust-openssl) has **eight** GitHub-reviewed advisories published in April and May 2026, and RustSec
has none of them. The newest advisory on [rustsec.org/packages/openssl.html](https://rustsec.org/packages/openssl.html)
is RUSTSEC-2025-0022 from April 2025 (checked 2026-11-09). Four are rated HIGH and were fixed in 0.10.78
(released 2026-04-19):

| GHSA | CVE | Flaw (summarised) |
|---|---|---|
| GHSA-8c75-8mhr-p7r9 | CVE-2026-41678 | `aes::unwrap_key` had an inverted length assertion, so an undersized output buffer is written past its end |
| GHSA-ghm9-cr32-g9qj | CVE-2026-41681 | `MdCtxRef::digest_final` wrote the full digest without checking the output buffer length |
| GHSA-hppc-g8h3-xhp3 | CVE-2026-41898 | PSK and cookie callback trampolines passed an unchecked length to OpenSSL |
| GHSA-pqf5-4pqq-29f5 | CVE-2026-41676 | `Deriver::derive` / `PkeyCtxRef::derive` can overflow short buffers on OpenSSL 1.1.x |

The other four are GHSA-xp3w-r5p5-63rr (HIGH, `X509Ref::ocsp_responders`, fixed in 0.10.79),
GHSA-xv59-967r-8726 and GHSA-phqj-4mhp-q6mq (MODERATE), and GHSA-xmgf-hq76-4vx2 (LOW). A project
whose `Cargo.lock` pins `openssl` 0.10.77 passes `cargo audit` today, while GitHub's own alerts flag it.

## Limits

- One snapshot. P2's year-on-year rise mixes real growth with filing lag: older advisories have had more
  time to be imported (RustSec still imports 2025 advisories today), and one snapshot cannot separate the two.
- Matching uses IDs, CVEs and links. A RustSec advisory for the same flaw that shares none of them would be
  missed, but in the 8 hand-checked cases no such advisory exists.
- Some GitHub-only records are probably out of RustSec's scope on purpose (applications, crates with almost
  no users, ordinary panics). The study measures the gap. It does not claim that every row belongs in RustSec.
- Severity is GitHub's own rating.

## What happens next

Hand-checked rows that clearly fit RustSec's scope will be filed as new RustSec advisories, **one per pull
request**, written from scratch (CC0), starting with the `openssl` advisories. Each pull request says it was
prepared with AI agents and offers to stop if the maintainers would rather not receive them. `rows.csv` in
[`job-v1/`](job-v1/) lists all 1,532 eligible records with their status, so anyone can work from the same list.

## Reproduce

```
python -m unittest -v test_ghsa_only_rust
python ghsa_only_rust.py --data-dir ./data --out-dir ./out
```

OSV replaces the export continuously, so a re-run reads a newer snapshot. The SHA-256 above identifies the one
graded here.
