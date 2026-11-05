# S8 results: CVEs issued by GitHub's own CNA that GitHub's Advisory Database does not carry

Graded 2026-11-05 (UTC) against `PREREG.md` (frozen 2026-11-04) and `AMENDMENT-1.md` (test fixtures only).
Job `cna-gap-s8-v2`: github/advisory-database commit `d1287b4afbb2162e934ca802152807fbed394acf`
(2026-11-05T09:36:51Z), NVD read 2026-11-05T10:39:23Z, **22,758 of 22,758** NVD records fetched (0 pages
failed), 161,406 global advisories indexed. Both gates passed (fetch 100%, population 13,769).

Licence: Apache-2.0 (code), CC BY 4.0 (text and data). Made with AI agents working for MV2 of Munim, Inc.

## Headline

**6,064 of 13,769 CVEs (44.0%) that GitHub's CNA published in NVD between 2025-01-01 and 2026-09-30 have no live
advisory in GitHub's own global Advisory Database**, not even an unreviewed one. A lookup by CVE ID
(`GET /advisories?cve_id=`, or the search on github.com/advisories) finds nothing for them. In a seeded live sample
of 20 of them, the API returned `[]` for all 20.

97.5% of these (5,913) cite a repository advisory that never became a global advisory. Only 6 of the 13,769 CVEs
had an unreviewed global record and no reviewed one, so in this data a GitHub-issued CVE is in the database almost
only when GitHub reviewed it.

## Predictions (exactly as frozen)

| | Claim | Result | Held |
|---|---|---|---|
| P1 | Between 5% and 30% (inclusive) of population CVEs are uncovered | 6,064 / 13,769 = **44.0%** | **no** |
| P2 | At most 3% of covered population CVEs are covered only by an unreviewed advisory (the #181073 mechanism: GitHub-issued CVEs are not imported as unreviewed) | 6 / 7,705 = 0.1% | yes |
| P3 | At least 90% of uncovered CVEs are `REPO_ONLY` | 5,913 / 6,064 = 97.5% | yes |
| P4 | The uncovered share is higher for CVEs published 2026-01-01..2026-09-30 than for those published in 2025 | 2026: 4,615 / 10,902 = 42.3%; 2025: 1,449 / 2,867 = **50.5%** | **no** |
| P5 | At least 18 of the 20 sampled uncovered CVEs return `[]` from `GET /advisories?cve_id=` | 20 / 20 (0 errors) | yes |
| P6 | At least 14 of the 20 sampled uncovered CVEs cite a repository advisory with no package in a supported registry | 16 / 20 (0 errors) | yes |

**4 of 6 held.** P1 failed high: the gap is larger than predicted. P4 failed: the 2025 share is higher than the
2026 share. No explanation for P4 is offered here; it was not tested.

## Coverage of the 13,769 population CVEs

| Coverage | CVEs |
|---|---|
| REVIEWED (a live reviewed advisory lists the CVE) | 7,699 |
| UNREVIEWED_ONLY | 6 |
| WITHDRAWN_ONLY (only withdrawn advisories list it) | 3 |
| NONE | 6,061 |

Uncovered kinds (6,064): `REPO_ONLY` 5,913; `GLOBAL_WITHOUT_ALIAS` 78 (the cited advisory is global, but no live
advisory lists the CVE; 3 of them cite a withdrawn advisory); `NO_REPO_ADVISORY_REF` 73.

NVD status of uncovered CVEs: Analyzed 3,410; Deferred 2,262; Awaiting Analysis 210; Modified 180; Undergoing
Analysis 2. So most of them are fully processed by NVD.

Uncovered share by month (uncovered / published): 2025-01 107/216, 2025-06 98/208, 2025-12 165/334,
2026-01 330/639, 2026-03 649/1,559, 2026-06 492/1,169, 2026-09 644/1,443. Every month is in `results.json`.

Repositories with the most uncovered CVEs: LabRedesCefetRJ/WeGIA 173, discourse/discourse 158,
InternationalColorConsortium/iccDEV 105, openemr/openemr 83, FreeRDP/FreeRDP 82, freescout-help-desk/freescout 73,
chamilo/chamilo-lms 72, coollabsio/coolify 69, rabbitmq/rabbitmq-server 69, ChurchCRM/CRM 68, OISF/suricata 67,
dataease/dataease 61, Dokploy/dokploy 57, vim/vim 54 (top 25 in `results.json`).

**October 2026 (reported, not predicted; review backlog):** 1,627 CVEs; 841 reviewed, 4 unreviewed only, 782 none.

## The live sample (P5, P6): `sample.csv`

All 20 sampled repository advisories were readable and `published`. Their package ecosystems, as the API returned them: empty 10,
`other` 2, a value that is not a registry 4 (`discourse`, `glpi`, `notesnook`, `frappe`), and a supported registry
4: maven (dataease, CVE-2025-49001), composer (coolify, CVE-2026-34149), go (leafwiki, CVE-2026-53529) and npm
(ruflo, CVE-2026-59726). So most uncovered CVEs are for software outside the registries GitHub reviews, which the
database docs put out of scope by design. About one in five in the sample (4/20; 95% Wilson interval 8% to 42%)
lists a package in a supported registry and is still not a global advisory. The sample is too small to size that
group.

## Hand checks (2026-11-05, public APIs, before writing this)

- **#10423's nine IDs.** CVE Services shows CVE-2026-108265, -108266, -108267, -108268, -108269, -92701, -33697 and
  -108362 PUBLISHED by `GitHub_M`; the repository advisory for -92702 carries that CVE. All nine are `REPO_ONLY` in
  the job's index. Repository advisory ecosystems read: CVE-2026-33697 (ultravioletrs/cocos, GHSA-vfgg-mvxx-mgg7,
  published 2026-03-23) lists **Go** package `github.com/ultravioletrs/cocos`, a supported registry; -92701 and
  -92702 (cocos) list an empty ecosystem; -108265 (Privasys/enclave-os-mini) and -108362 (Privasys/ra-tls-clients)
  list `other`. The other four were not read (rate limit).
- **`GLOBAL_WITHOUT_ALIAS`, five rows read by hand.** Two are a reviewed advisory with **no CVE alias at all**,
  where GitHub's CNA published the CVE after the advisory went global:
  - nokogiri GHSA-8678-w3jw-xfc2 (rubygems), published 2026-06-19 with `cve_id: null`; CVE-2026-57234 was
    published by `GitHub_M` on 2026-06-25 with the same title and that advisory as its only reference;
    `?cve_id=CVE-2026-57234` returns `[]`.
  - pnpm GHSA-72r4-9c5j-mj57 (npm), published 2026-06-27 with `cve_id: null`; CVE-2026-59194 (NVD 2026-07-06)
    cites it.
  Three are bundles or related advisories, not missing aliases: moquette GHSA-5f42-97gr-vfhq holds CVE-2026-85724
  and seven more moquette CVEs cite it; caddy GHSA-j8px-rmrx-76h9 holds CVE-2026-77281 and two more cite it;
  git-credential-manager GHSA-86c2-4x57-wc8g holds CVE-2024-50338 and is cited by Git's CVE-2024-52006.
  All 78 rows are sorted by the follow-up job `s8-alias-v1` (descriptive, `../cna-gap-s8-alias/` once it runs).

## Named cases (`named.csv`)

| Issue | CVEs | In NVD (GitHub CNA) | Coverage |
|---|---|---|---|
| #10423 | 108265-108269, 92701, 92702, 108362, 33697 | all 9 | all NONE, REPO_ONLY |
| #8851 | 56670-56673 | all 4 | all NONE, REPO_ONLY |
| #8831 | 49481 | yes | NONE, REPO_ONLY |
| #10402 | 92704 | yes (published 2026-11-04) | NONE, REPO_ONLY |
| #10297 | 92163 | not in NVD | - |
| #9171 | 63656 | not in NVD | - |

## Limits

- NVD is the source for "GitHub's CNA published it"; a CVE at CVE.org but not yet in NVD is missed.
- Coverage is read from the public git export at one commit; the live site can be a few hours ahead. The live
  sample (20/20 `[]`) found no sign of lag.
- Unreviewed advisories filed before 2025 are not indexed. A 2025-2026 CVE whose only global record is an older
  unreviewed advisory would be miscounted as uncovered; the live sample found none.
- Only the first repository advisory an NVD record cites is used for the kind.
- **Uncovered is not a defect claim.** The database reviews advisories for packages in supported registries, and
  most uncovered CVEs are outside them. What S8 shows is narrower and new: for 44% of the CVEs GitHub itself issued
  in 2025-2026, a CVE lookup in GitHub's database returns nothing, not even an unreviewed record. S8 did not
  measure how other CNAs' CVEs are covered, so it does not show that GitHub's CVEs are treated differently.

## Files

`results.json`, `RESULTS-job.md`, `cves.csv` (all 13,769), `uncovered.csv` (6,064), `sample.csv`, `named.csv`.
The per-CVE lookup tool `cve_where.py` at the repository root explains one CVE at a time.
