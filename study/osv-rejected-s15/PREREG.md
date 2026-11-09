# S15 pre-registration: rejected CVEs across the source databases OSV serves

Frozen 2026-11-09 (UTC), before any S15 data was downloaded. Made with AI agents working for MV2 of
Munim, Inc. (mv2@munimtech.com). No human has reviewed this plan. Code Apache-2.0; text and data CC BY 4.0.

## Why

[S13](../pysec-rejected-s13/RESULTS.md) found 21 live PyPA (PYSEC) advisories that rest on a CVE its
CNA has rejected, 16 of them with no replacement CVE. [S6](../rejected-alias-s6/RESULTS.md) found 54
live GitHub-reviewed advisories in the same state. Scanners that read OSV.dev (osv-scanner, pip-audit,
cargo-audit via RustSec, govulncheck via the Go database, Trivy, Grype and others) also read the other
open source databases: the Go vulnerability database (GO-), RustSec (RUSTSEC-), the Haskell database
(HSEC-), the R database (RSEC-), Julia (JLSEC-), the Erlang Ecosystem Foundation (EEF-) and others.
Nobody we could find has counted how many of their live records rest on a rejected CVE, or compared
the databases on it.

Prior art searched on 2026-11-09: OSV.dev's FAQ (withdrawn records are hidden from queries but kept);
Socket's write-up of OSV's 2024 fix that stopped treating *disputed* NVD CVEs as withdrawn (rejected ones
still are, for OSV's own CVE- records only); ossf/cve-bin-tool PR #6030 (counts withdrawn records per
ecosystem, not rejected aliases); the Go database documentation (an excluded report reason
`NOT_A_VULNERABILITY` exists, but nothing on CVEs rejected after a report is published). None measures
live source records whose CVE alias was later rejected.

## Data

- OSV.dev's public per-ecosystem exports, `https://osv-vulnerabilities.storage.googleapis.com/<eco>/all.zip`,
  for Go, crates.io, Hackage, GHC, CRAN, Julia, Hex, opam, Pub, SwiftURL and PyPI. Each zip's sha256,
  size and Last-Modified header are recorded.
- The CVE Program's latest bulk CVE List release (CVEProject/cvelistV5, `*_all_CVEs_at_midnight.zip.zip`).
- A **source record** is a record whose ID prefix is not GHSA, MAL, CVE or OSV. Records exported under
  more than one ecosystem are counted once. GHSA records in the same exports are used only to say
  whether a source record's GHSA alias is withdrawn.
- A **row** is a live source record (no `withdrawn`) with at least one CVE alias whose CVE record is
  `REJECTED`. Actions, as in S13 0.1.1: `DROP_ALIAS` (another CVE alias is PUBLISHED), `REPLACE_ALIAS`
  (the rejection's full reason or `replacedBy` names a PUBLISHED CVE), otherwise `WITHDRAW_CANDIDATE`.
- Script `osv_rejected.py` 0.1.0, seed 20261109, sample of 6. Gate floors (sanity only): 1,000 GO
  records, 500 RUSTSEC, 2,000 PYSEC, 2,000 GHSA, 200,000 CVE records, parse errors at most 1%. If the
  gate fails, nothing is graded; a fixed re-run keeps these predictions.

OSV rewrites each record's `modified` time when related data changes (GO-2024-2611 shows
2026-10-14 for a 2024 record), so S13's "untouched since rejection" measure is not used here.

## Predictions (frozen)

| | Prediction | Why we expect it |
|---|---|---|
| P1 | >= 5 live source records outside PyPA hold a REJECTED CVE alias | Go and RustSec together hold several thousand records with CVE aliases; S6 and S13 rates (0.15-0.28%) would give about 5-15 |
| P2 | >= 50% of those non-PyPA rows are GO- records | The Go database is the largest non-PyPA source and auto-creates UNREVIEWED reports from GHSAs and CVEs |
| P3 | >= 60% of GO- rows are `UNREVIEWED` (needs at least 3 GO- rows) | An auto-created report inherits its source's CVE; a reviewed one has been read by the Go team |
| P4 | >= 50% of non-PyPA rows that list a GHSA have that GHSA live in OSV's export | S13: GitHub had withdrawn only 3 of 19 matching GHSAs |
| P5 | The share of live GO- plus RUSTSEC- records with a CVE alias that hold a REJECTED CVE is lower than the PYSEC share in the same run | Both are curated by small teams that review records by hand; PyPA's 2026 bulk import added 17 of S13's 21 rows |
| P6 | >= 75% of the seeded sample of non-PyPA `WITHDRAW_CANDIDATE` rows are still live with a REJECTED CVE when checked at the source (graded by hand) | S13's sample was 8 of 8 |

P2 to P4 are `INCONCLUSIVE_UNDERPOWERED` with fewer than 5 non-PyPA rows. P6 is checked by hand the day
the job output is read: `cveawg.mitre.org/api/cve/<CVE>` still REJECTED, and the record at its source
(`vuln.go.dev/ID/<id>.json`, `rustsec.org/advisories/<id>.html`, or the database's repository) still
live and still listing the CVE.

## What we will do with it

The results are published whichever way they fall. A row is only ever sent to its database as one
record per pull request or issue, after a hand check, at most one a day per database, following each
database's own contribution rules (the Go database takes reports through its issue tracker; RustSec
takes pull requests). Nothing is sent before the results are public.

## Limits known in advance

- One snapshot. OSV's export may lag the source repositories by hours.
- OSV may merge aliases across an alias group, so a CVE alias seen in OSV's copy might not be in the
  source file; P6 checks the source itself.
- A rejected CVE does not prove there is no flaw; a CNA may reject without giving a reason.
