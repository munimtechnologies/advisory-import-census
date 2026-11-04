# S8 pre-registration: CVEs issued by GitHub's own CNA that GitHub's Advisory Database does not carry

Frozen 2026-11-04 (UTC), before the job runs. Code: `cna_gap.py` (tests: `test_cna_gap.py`).
Licence: Apache-2.0 (code), CC BY 4.0 (text and data). Made with AI agents working for MV2 of Munim, Inc.

## Why

GitHub is a CVE Numbering Authority (`GitHub_M` in CVE records; `security-advisories@github.com` in NVD). A
maintainer can request a CVE from a repository security advisory, and GitHub publishes the CVE record. Separately,
GitHub's **global** Advisory Database (github.com/advisories, the `/advisories` REST API, Dependabot, OSV's GHSA
feed) holds reviewed advisories for packages in supported registries, and unreviewed advisories built from NVD.

Several open issues report single CVEs that GitHub issued but that a lookup in the global database cannot find.
Checked on 2026-11-04 with public APIs:

- **CVE-2026-49481** (UpSnap, github/advisory-database#8831): the CVE record was published by `GitHub_M` on
  2026-08-12 with a description, CVSS 9.6 and CWE-78, and NVD has it (status Deferred). Yet
  `GET /advisories?cve_id=CVE-2026-49481` returns `[]` and the repository advisory GHSA-6mc7-6948-w5h4 is 404 as
  a global advisory. Its repository advisory lists the package with an empty ecosystem.
- **CVE-2026-56671** (ComfyUI, #8851): published by `GitHub_M` on 2026-07-31; `?cve_id=` returns `[]`.
- #10423 (2026-10-18) lists nine more "GitHub-reviewed and GitHub-issued CVEs" missing from the database, with
  no method or count.

## Prior art (searched 2026-11-04)

- **github/community discussion #181073** (mbauman, 2025-12-03, no staff answer) states the mechanism in one
  sentence: repository advisories from unreviewed ecosystems that GitHub reviews and gives a CVE "do not have the
  corresponding CVE imported into as an unreviewed global advisory (unlike all other CVEs)". No numbers.
- **github/advisory-database #10091** (Vaadin): when the CVE record was published *before* the repository
  advisory, an unreviewed copy from NVD did appear.
- Single-case reports: #8831, #8851, #9171, #10297, #10342, #10402, #10423, #10841; #7268 (non-ecosystem
  software). RBP Tracker (rbptracker.org) counts IDs still RESERVED, which is a different set.
- Our own S7 (study/reserved-alias-s7) covers the reverse direction: GHSA aliases with no CVE record.

**Not found anywhere:** a count, over all CVEs GitHub's CNA has published, of how many have no live advisory in
GitHub's own global database, and of why (repository-only advisory, or a global advisory that lacks the alias).

## What was known before freezing

NVD reports 22,707 records with sourceIdentifier `security-advisories@github.com` (read 2026-11-04 13:51 UTC,
one record shown). The two CVEs above, and the open issues listed. No coverage count was computed or looked up.

## Population and data

- **Population:** NVD records with `sourceIdentifier=security-advisories@github.com`, `published` date from
  2025-01-01 to 2026-09-30 inclusive, `vulnStatus` not `Rejected`. October 2026 onward is left out because review
  turnaround was reported at about five weeks (github/community discussion #209436); it is reported separately.
- **Global database:** github/advisory-database at the commit the job reads: every file under
  `advisories/github-reviewed/` and `advisories/unreviewed/2025/` and `/2026/` (an unreviewed advisory for a CVE
  first published in NVD in 2025-2026 is filed under 2025 or 2026). Index: CVE alias -> advisories (type,
  withdrawn), and GHSA ID -> type, withdrawn.
- **Coverage** of a CVE: `REVIEWED` (a live reviewed advisory lists it), `UNREVIEWED_ONLY`, `WITHDRAWN_ONLY`
  (only withdrawn advisories list it) or `NONE`. **Uncovered** = `NONE` or `WITHDRAWN_ONLY`.
- **Cited repository advisory:** the first `github.com/<owner>/<repo>/security/advisories/GHSA-...` URL among the
  NVD references. Uncovered kinds: `REPO_ONLY` (that GHSA is not in the global database at all),
  `GLOBAL_WITHOUT_ALIAS` (it is there, but no live advisory lists the CVE), `NO_REPO_ADVISORY_REF`.
- **Live sample:** 20 uncovered CVEs drawn with `random.Random(20261104)` from the uncovered rows sorted by CVE ID.
  For each: `GET https://api.github.com/advisories?cve_id=<CVE>` and
  `GET https://api.github.com/repos/<owner>/<repo>/security-advisories/<GHSA>` (package ecosystems). Both are
  readable without an account (checked on 2026-11-04 for CVE-2026-49481 and GHSA-6mc7-6948-w5h4).
  "Supported registry" = rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub, swift; an
  empty ecosystem or `other` is not one.

## Predictions (frozen)

| | Claim |
|---|---|
| P1 | Between 5% and 30% (inclusive) of population CVEs are uncovered |
| P2 | At most 3% of covered population CVEs are covered only by an unreviewed advisory (the #181073 mechanism: GitHub-issued CVEs are not imported as unreviewed) |
| P3 | At least 90% of uncovered CVEs are `REPO_ONLY` |
| P4 | The uncovered share is higher for CVEs published 2026-01-01..2026-09-30 than for those published in 2025 |
| P5 | At least 18 of the 20 sampled uncovered CVEs return `[]` from `GET /advisories?cve_id=` (validates the offline index against the live API) |
| P6 | At least 14 of the 20 sampled uncovered CVEs cite a repository advisory with no package in a supported registry |

Gates: if the job fetches fewer than 95% of NVD's reported total, or the population is under 1,000, P1-P4 are
INCONCLUSIVE. For P5 and P6, API errors are left out and the threshold is scaled to the CVEs read; with more than
4 errors the verdict is PENDING and the same two calls are made by hand for the same 20 CVEs (sample.csv) in the
next run, before reading any other output.

## Reported but not predicted

Coverage by month; uncovered kinds; the global state of the cited GHSA; the 25 repositories with the most
uncovered CVEs; NVD status of uncovered CVEs; the October 2026 window; and the named cases from #8831, #8851,
#9171, #10297, #10402 and #10423 (in NVD or not, coverage, cited GHSA).

## Limits

- NVD is the source for "GitHub's CNA published it". A CVE published at CVE.org but not yet in NVD is missed.
- Coverage is read from the public git export at one commit; the live site can be a few hours ahead.
- Unreviewed advisories filed before 2025 are not indexed, so a 2025-2026 CVE whose only global record is an
  older unreviewed advisory would count as uncovered. This should be rare; the live sample (P5) checks it.
- Uncovered is not a defect claim. Advisories outside the supported registries are out of scope for review by
  design ("We review advisories if they are for a vulnerability in a package that comes from a supported
  registry"). What S8 measures is narrower: GitHub issued the CVE, and a lookup by that CVE in GitHub's own
  database finds nothing, not even an unreviewed record (which, per #181073, other CNAs' CVEs do get; S8 does not
  test that part).

## What happens with the results

RESULTS.md and the per-CVE tables go in this folder. No bulk outreach and no per-row issues. At most one comment,
on an existing issue that asks this question (#10423 or #8851), and only with checked figures.
