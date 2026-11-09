# S15 results: rejected CVEs across the source databases OSV serves

Graded 2026-11-09 (UTC) against the frozen plan in [`PREREG.md`](PREREG.md). Job `osv-rejected-s15-v1` ran
`osv_rejected.py` 0.1.0 once (offline tests passed first); its raw output is in [`job-v1/`](job-v1/).
Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com). No result here has been reviewed
by a human. Apache-2.0 (code) / CC BY 4.0 (text and data).

**Result: outside PyPA, 15 live source records rest on a rejected CVE: 12 in the Go vulnerability database and
3 in RustSec. None were found in the Haskell, R, Julia, Erlang/Elixir or OCaml databases. Measured as a share
of records with a CVE alias, Go and RustSec together (0.30%) are only slightly below PyPA (0.32%), so the
problem is not special to PyPA. 5 of 6 predictions held.**

## Data

OSV.dev's per-ecosystem exports for Go, crates.io, Hackage, GHC, CRAN, Julia, Hex, opam, Pub, SwiftURL and
PyPI (each zip's SHA-256, size and Last-Modified time are in [`job-v1/results.json`](job-v1/results.json); for
example PyPI `540a188d...`, Last-Modified 2026-11-09 09:33 GMT), and CVE List release `cve_2026-11-09_1500Z`,
read 2026-11-09T16:22:30Z (421,272 records). 42,127 OSV files, no parse errors; the gate passed.

| Source | Records | Live | Live with a CVE alias | Rows (live, with a REJECTED CVE alias) |
|---|---|---|---|---|
| PYSEC (PyPA) | 7,985 | 7,630 | 7,561 | 24 |
| GO (Go vulnerability database) | 4,808 | 4,771 | 4,446 | **12** |
| RUSTSEC | 1,410 | 1,385 | 593 | **3** |
| JLSEC (Julia) | 1,717 | 1,713 | 7 | 0 |
| EEF (Erlang/Elixir) | 310 | 310 | 309 | 0 |
| HSEC (Haskell) | 39 | 39 | 20 | 0 |
| OSEC (OCaml) | 36 | 36 | 24 | 0 |
| RSEC (R) | 14 | 14 | 0 | 0 |

Each row gets an action, as in S13: `DROP_ALIAS` (another CVE alias on the record is published),
`REPLACE_ALIAS` (the rejection names a published replacement), otherwise `WITHDRAW_CANDIDATE`.

| Source | WITHDRAW_CANDIDATE | DROP_ALIAS | REPLACE_ALIAS |
|---|---|---|---|
| GO | 6 | 6 | 0 |
| RUSTSEC | 0 | 3 | 0 |
| PYSEC | 15 | 5 | 4 |

The PYSEC count (24 rows) comes from OSV's copy of PyPA's records. It is not directly comparable to
[S13](../pysec-rejected-s13/RESULTS.md)'s 21, which read PyPA's own repository earlier the same day under
S13's own rules.

## Predictions

| | Prediction | Result | Held |
|---|---|---|---|
| P1 | >= 5 live non-PyPA source records hold a REJECTED CVE alias | 15 | yes |
| P2 | >= 50% of those are GO- records | 80.0% (12/15) | yes |
| P3 | >= 60% of GO- rows are UNREVIEWED | 58.3% (7/12) | **no** (one record short) |
| P4 | >= 50% of non-PyPA rows that list a GHSA have that GHSA live in OSV's export | 73.3% (11/15) | yes |
| P5 | GO+RUSTSEC share is lower than the PYSEC share | 0.298% (15/5,039) vs 0.317% (24/7,561) | yes (by 0.02 points) |
| P6 | >= 75% of the 6 seeded non-PyPA WITHDRAW_CANDIDATE rows still live with a REJECTED CVE at the source | 6 of 6 | yes |

**5 of 6 held.** P5 held, but only by 0.02 points, so the honest reading is that Go and RustSec carry about the
same share of records on rejected CVEs as PyPA, not a clearly lower one. P3 failed: 5 of the 12 Go rows are
REVIEWED, so the Go team's review does not catch rejections made after it.

### P6 by hand (2026-11-09, about 21:40 UTC)

Each Go record was read at `https://vuln.go.dev/ID/<id>.json` (no `withdrawn`, CVE still in `aliases`) and its
CVE at `https://cveawg.mitre.org/api/cve/<CVE>`. The sample happens to be all Go, because every non-PyPA
WITHDRAW_CANDIDATE row is a Go record.

| Go record | Review | CVE | CVE rejected | Why the CNA rejected it | GHSA |
|---|---|---|---|---|---|
| GO-2022-1205 (usememos/memos) | UNREVIEWED | CVE-2022-4685 | 2022-12-28 | incorrectly assigned | live |
| GO-2023-1494 (elgs/gosqljson) | REVIEWED | CVE-2014-125064 | 2023-02-22 | not a security issue | live |
| GO-2026-4505 (abhinavxd/libredesk) | UNREVIEWED | CVE-2026-26957 | 2026-06-09 | intended behaviour | **withdrawn** |
| GO-2026-4512 (refraction-networking/utls) | REVIEWED | CVE-2026-26995 | 2026-02-20 | external dependency's flaw | live |
| GO-2026-5939 (quay/claircore) | UNREVIEWED | CVE-2026-10517 | 2026-07-27 | misattributed to claircore | live |
| GO-2026-6575 (projectdiscovery/nuclei) | UNREVIEWED | CVE-2026-76819 | 2026-09-22 | flaw is in a dependency | live |

All six are live at vuln.go.dev and all six CVEs are REJECTED. GO-2026-4505 is the clearest case: both its CVE
and the GitHub advisory it was created from have been withdrawn, but the Go record stays.

## What else the data shows (descriptive, not predicted)

- The three RustSec rows are all `DROP_ALIAS`: RUSTSEC-2019-0033 (`http`) lists CVE-2019-25008, a rejected
  duplicate of CVE-2020-25574, and RUSTSEC-2023-0060 / RUSTSEC-2023-0061 (`libwebp-sys2`, `libwebp-sys`) list
  CVE-2023-5129, Google's rejected duplicate of CVE-2023-4863. All three were checked in RustSec's own files
  (`crates/<crate>/<id>.md`), so these aliases are not something OSV added. Each record also lists the
  published CVE, so scanners still match. Keeping the rejected ID may be deliberate, to help people who
  search by the old number.
- Who rejected the CVEs behind all 39 rows: huntr 13 (all on PyPA records), MITRE 8, GitHub 6, VulnCheck 5,
  Google 3, Red Hat 2, huntrdev 1, VulDB 1.
- 27 of the 39 CVEs were rejected after the database record was published, so the record was right when it
  was written; the databases have no routine for re-checking a CVE once it is listed.

## Limits

- One snapshot of each export; OSV's copy can lag the source repository by hours. P6 checked the sources.
- Records that OSV exports under several ecosystems are counted once.
- A rejected CVE does not prove there is no flaw. Several Go rows were rejected because the flaw lies in a
  dependency, and the Go team may prefer to keep the record for that reason.

## What happens next

Following the plan, any single-record fix is sent only after a hand check, one record per issue or pull
request, at most one a day per database, under that database's own rules. The first candidate is
GO-2026-4505, whose CVE and GitHub advisory are both withdrawn. The Go database takes such reports through
its issue tracker (golang/vulndb).

## Reproduce

```
python -m unittest -v test_osv_rejected
python osv_rejected.py --data-dir ./data --out-dir ./out
```
