# S6 pre-registration: reviewed GitHub advisories that still carry a REJECTED CVE

Frozen 2026-11-01 (UTC), before the job runs. Code: `rejected_alias.py` (tests: `test_rejected_alias.py`).
Licence: Apache-2.0 (code), CC BY 4.0 (text and data). Made with AI agents working for MV2 of Munim, Inc.

## Why

While grading the 31 twins that S5 left ungraded ([../second-cve-s5/RESULTS.md](../second-cve-s5/RESULTS.md)),
we found that 3 more GitHub-reviewed advisories hold a CVE alias that its CNA has REJECTED, on top of the
ImageMagick case S5 reported. In each one, the live CVE for the same flaw sits on an unreviewed GHSA that
lists no package:

| Reviewed GHSA | Package | Its CVE alias (state) | Live CVE for the same flaw | Held by |
|---|---|---|---|---|
| GHSA-273h-m46v-96q4 (ImageMagick PSB RLE) | 19 Magick.NET NuGet packages | CVE-2026-25984 (REJECTED 2026-02-23, "assigned in error") | CVE-2026-56367 (VulnCheck) | GHSA-rg39-4fm5-hrp2, no package |
| GHSA-h3m5-97jq-qjrf (OpenRemote removeAlarms IDOR, critical) | Maven io.openremote:openremote-manager | CVE-2026-56120 (REJECTED 2026-06-23, "duplicate of CVE-2026-56784") | CVE-2026-56784 (VulnCheck) | GHSA-pv42-3qx9-m56g, no package |
| GHSA-wr6m-jg37-68xh (OpenClaw Zalo webhook memory growth) | npm openclaw | CVE-2026-32066 (REJECTED 2026-03-23) | CVE-2026-28461 (VulnCheck) | GHSA-vfw9-h883-6h9x, no package |
| GHSA-r54r-wmmq-mh84 (OpenClaw ZIP extraction race) | npm openclaw | CVE-2026-28483 (REJECTED 2026-03-23) | CVE-2026-27670 (VulnCheck) | GHSA-2g8c-6qfq-528m, no package |

All CVE records were read from `cveawg.mitre.org/api/cve/` and the GitHub records from `api.github.com/advisories`
on 2026-11-01. In these cases, a lookup by the live CVE (`GET /advisories?cve_id=`) returns no affected package.

Prior art (searched 2026-11-01): single cases where a reviewed advisory's CVE was rejected because the report was
disputed, and the advisory was withdrawn (github/advisory-database #10444/#10497 sprintf-js; #8765-#8769 open-webui);
one rejected Next.js CVE named in #10224; rejected SQLite CVEs on *unreviewed* records (lilting.ch, August 2026);
#8051 (CVE aliases with no record at all). No count was found of reviewed advisories that still carry a rejected
CVE, or of how often a live replacement CVE exists elsewhere.

## Population and data

- Live (not withdrawn) GitHub-reviewed advisories in github/advisory-database at the commit the job reads.
- Each CVE alias is looked up in the CVE Program's bulk CVE List (latest CVEProject/cvelistV5 release asset
  `*_all_CVEs_at_midnight.zip.zip`). An alias not in the list counts as MISSING (reported, not predicted).
- **Row:** a live reviewed GHSA with at least one alias whose record has state REJECTED.
- **Replacement:** a CVE, not among the GHSA's aliases, whose record is PUBLISHED and which is either named in the
  rejection reason, or held by a live 2025-26 unreviewed GHSA that links the reviewed GHSA *and* whose CVE record
  cites the reviewed GHSA's ID.

## Predictions (frozen)

| | Claim |
|---|---|
| P1 | >= 20 live reviewed GHSAs hold at least one REJECTED CVE alias |
| P2 | >= 50% of those rows hold no PUBLISHED CVE alias at all |
| P3 | >= 40% of rows have a found replacement |
| P4 | >= 60% of the distinct REJECTED aliases were assigned by GitHub_M or VulnCheck |
| P5 | >= 70% of distinct replacement CVEs are held only by unreviewed GHSAs that list no package |
| P6 | >= 80% of a seeded sample (seed 20261103, up to 20 rows, one replacement each): the replacement CVE describes the same flaw as the reviewed GHSA, graded by hand |

If fewer than 5 rows are found, P2-P5 are reported as INCONCLUSIVE_UNDERPOWERED. P6 is graded from
`grading_sample.csv` (the two texts only, no states, holders or counts) **before** any other output is opened.
SAME needs the same component, the same weakness and overlapping versions; otherwise DIFFERENT or UNCLEAR
(UNCLEAR counts as not SAME). The job prints no counts.

## Reported but not predicted

Rejection-reason classes (duplicate / error / not_vuln / unspecified / other); rows whose GHSA was not modified
after the rejection date; rows by year; aliases MISSING from the CVE List; PUBLISHED aliases whose CVE record cites
only other GHSA IDs (possible mix-ups like OpenClaw GHSA-h3x4-hc5v-v2gm, whose alias CVE-2026-34426 describes the
flaw in GHSA-98ch-45wp-ch47). These lists are exploratory leads for hand checking, not findings.

## Limits

- Twins are searched only among 2025-26 unreviewed GHSAs. A replacement held elsewhere, or not linked, is missed,
  so P3 and P5 are lower bounds.
- The CVE List snapshot and the advisory-database commit are read minutes apart, not at the same instant.
- A rejected alias is a data-quality issue, not proof that the advisory is wrong. Which CVE should remain is the
  CNAs' call. The fix on GitHub's side is the curators' call.

## What happens with the results

No bulk outreach. Rows are checked by hand, and at most one data-fix suggestion a day goes to the curators
through GitHub's "Suggest improvements" form, each with its checked evidence.
