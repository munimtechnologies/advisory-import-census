# S6 results: reviewed GitHub advisories that still carry a REJECTED CVE

Graded 2026-11-01 (UTC) against the frozen [PREREG.md](PREREG.md). **3 of 6 predictions held (P1, P2, P6); P3, P4 and P5 failed.**
Made with AI agents working for MV2 of Munim, Inc. Code Apache-2.0; text and data CC BY 4.0.

Data: github/advisory-database commit `8c754a94a2` (2026-11-01T15:35:41Z); CVE List release `cve_2026-11-01_1700Z`
(`2026-11-01_all_CVEs_at_midnight.zip.zip`), read 2026-11-01T18:14:59Z. The job's own report is [RESULTS-job.md](RESULTS-job.md).
Per-row data: [rows.csv](rows.csv) (54 rows), [replacements.csv](replacements.csv) (15 pairs), [results.json](results.json).

## Predictions

| | Claim | Result | Held |
|---|---|---|---|
| P1 | >= 20 live reviewed GHSAs hold a REJECTED CVE alias | **54** (of 36,244 live reviewed; 32,550 have a CVE) | yes |
| P2 | >= 50% of those hold no PUBLISHED CVE alias | 54 of 54 (100%) | yes |
| P3 | >= 40% have a found replacement CVE | 14 of 54 (25.9%) | **no** |
| P4 | >= 60% of the rejected aliases were assigned by GitHub_M or VulnCheck | 18 of 54 (33.3%) | **no** |
| P5 | >= 70% of replacement CVEs are held only by packageless unreviewed GHSAs | 5 of 15 (33.3%) | **no** |
| P6 | >= 80% of the hand-graded sample: replacement describes the same flaw | 12 of 14 SAME (85.7%) | yes |

P6 was graded from `grading_sample.csv` (texts only) before any other output was opened: [grades.csv](grades.csv).
The sample held all 14 rows that had a replacement (the PREREG allowed up to 20). Of the 2 rows not graded SAME:
- **GHSA-f7jh-m6wp-jm7f (HAL console XSS): DIFFERENT.** Red Hat rejected CVE-2025-2901 as "redundant to CVE-2025-23366
  and CVE-2024-10234". The script sampled the second one (a WildFly deployment XSS). The HAL flaw matches CVE-2025-23366.
  When a rejection names two replacements, a person has to pick.
- **GHSA-gf47-qgg5-9g9q (Apache Thrift): UNCLEAR.** Apache rejected CVE-2026-41603 because it "incorrectly described the
  affected language binding and fixed version" and replaced it with CVE-2026-66053 (Python bindings, < 0.24.0). The
  reviewed GHSA lists Maven `libthrift` < 0.23.0 and cites two Java commits that enable hostname verification in
  `TSSLTransportFactory`. The CNA calls it the same CVE, but the package and code differ.

## Why the three predictions failed

The PREREG was built on 4 hand-found cases, all VulnCheck/GitHub_M with packageless twins. The full census looks different:

- **P4.** The largest group of rejected aliases comes from huntr (`@huntr_ai` 13, `@huntrdev` 2: 15 of 54), not
  GitHub_M (9) or VulnCheck (9). Then mitre 8, redhat 4, VulDB 3, apache 3, and Checkmarx, Liferay, hackerone 1 each.
- **P3.** Most rejections name no replacement. Reason classes: unspecified 18, other 14, duplicate 11, not a
  vulnerability 9, assigned in error 2. A replacement can only be found when the reason names one or a linked twin
  exists. That holds for 14 rows.
- **P5.** 9 of the 15 replacement CVEs are already held by **another reviewed GHSA**, not by a packageless unreviewed
  one (5 of 15). One (CVE-2024-10234) is held by no GHSA.

## Exploratory findings (not predicted; leads for hand checking)

1. **Reviewed duplicates.** The 9 "held by another reviewed GHSA" pairs mean two live reviewed advisories exist for one
   flaw, and one of them carries the dead CVE. All 9 were checked by hand against `api.github.com/advisories` on
   2026-11-01 (first GHSA holds the rejected CVE; second holds the live one):

   | Pair | Package | Verdict |
   |---|---|---|
   | GHSA-79jw-6wg7-r9g4 / GHSA-r5cq-9537-9rpf | npm `mixme` (both < 0.5.1) | duplicate |
   | GHSA-34rf-p3r3-58x2 / GHSA-g9cj-cfpp-4g2x | PyPI `gradio` (fixed in 4.13) | duplicate |
   | GHSA-p7v4-gm6j-cw9m / GHSA-98j2-3jv7-274m | Composer `mautic/core` (2.x < 2.16.5; 3.x < 3.2.4) | duplicate (3.x lower bounds differ) |
   | GHSA-p3j6-f45h-hw5f / GHSA-xfjj-f699-rc79 | Go `github.com/tiagorlampert/CHAOS` (same range) | duplicate |
   | GHSA-8h5w-f6q9-wg35 / GHSA-7q94-qpjr-xpgm | PyPI `langchain` (both < 0.0.247) | duplicate |
   | GHSA-h8hf-x3f4-xwgp / GHSA-f825-f98c-gj3g | npm `mongoose` (same two ranges) | duplicate |
   | GHSA-f7jh-m6wp-jm7f / GHSA-jhvj-f397-8w6q | Maven `org.jboss.hal:hal-console` (fixed 3.7.11.Final vs 3.7.7.Final) | probable duplicate, fix versions differ |
   | GHSA-rhm7-7469-rcpw / GHSA-hvcf-6324-cjh7 | `ezsystems/ezplatform-richtext` 3.3.x vs `ibexa/fieldtype-richtext` 4.6.x | not a duplicate: one flaw, two packages (the case in #10224) |
   | GHSA-gf47-qgg5-9g9q / GHSA-hwrj-9rr4-24xh | Maven `libthrift` vs PyPI `thrift` | not a duplicate (Java vs Python) |

   So 6 checked pairs are plain duplicates: a project that uses one of these packages gets two alerts for one flaw, and
   one of them names a dead CVE. Severity also differs inside pairs (for example LangChain 9.8 vs 7.5; mixme 7.1 vs 9.1).
2. **Open WebUI cluster.** 10 of the 54 rows are Open WebUI advisories whose huntr CVEs were rejected on 2026-08-13 or
   2026-08-31 with no reason given. An Open WebUI maintainer had five earlier advisories withdrawn after huntr
   rejected their CVEs (github/advisory-database #8765-#8769, merged 2026-09-02). A search on 2026-11-01 found no issue
   or PR about these 10. Some of them list fix versions and real fix commits (for example CVE-2024-8060, fixed in
   0.5.17, and CVE-2024-7806, CSRF fixed in 0.3.33), so a rejected ID does not by itself mean the advisory is wrong.
3. **CNA says "not a security issue".** 9 rows have a rejection reason of that kind (for example webrick
   CVE-2024-47220, Apache Camel camel-ldap CVE-2022-45046, Apache Zeppelin CVE-2024-31861, @clerk/clerk-js
   CVE-2025-63700). Several more in the "other" class give a reason that also points that way (a dependency's flaw,
   superuser-only, misattributed). Whether each reviewed advisory should stay is the curators' call.
4. **Untouched.** 41 of the 54 GHSAs were not modified after their alias was rejected.
5. **`missing.csv`** (143 aliases not in the CVE List) and **`mismatch.csv`** (89 published aliases whose record cites
   only other GHSA IDs) are raw leads only. Many mismatches are probably benign: a CVE record often cites the
   repository advisory's ID rather than the global one. Neither file was checked by hand.

## What happened when we acted on one row

Before this census ran, a "Suggest improvements" edit for the ImageMagick row (GHSA-273h-m46v-96q4) added the live
VulnCheck CVE-2026-56367 to its references and asked curators to set it as the CVE ID
([github/advisory-database#10828](https://github.com/github/advisory-database/pull/10828)). The ImageMagick maintainer
replied the same day: *"We don't want to assign the CVE that was provided. We did not request this so don't add it."*
The lesson: a CVE that a third party assigned is not automatically the right ID for a maintainer's advisory, even when
it describes the same flaw. Some maintainers deliberately publish without a CVE. Replacement suggestions from this
table should come only from a CNA's own `replacedBy`/"duplicate of" statement, or with the maintainer's agreement.

## Limits

- Replacement search covers only names in the rejection reason and linked 2025-26 unreviewed twins, so P3 and P5 are
  lower bounds.
- Both sources were fetched minutes apart (2026-11-01 ~18:12-18:15Z). The database's newest commit then was from 15:35Z,
  and the CVE List release from 17:00Z, so a change made between those times can be missed on one side.
- A rejected alias is a data-quality issue, not proof that an advisory is wrong.
- Of the counts, only the 14-row sample was graded by hand.
