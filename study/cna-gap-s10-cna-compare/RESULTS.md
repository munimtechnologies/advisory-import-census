# S10 results: GitHub-CNA vs other-CNA CVEs that cite a GitHub repository advisory

Part of [advisory-import-census](../../README.md). Pre-registration: [PREREG.md](PREREG.md). Code `cna_compare.py`
(Apache-2.0); text and data CC BY 4.0. Made with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).
Graded 2026-11-07 UTC.

Job output: [RESULTS-job.md](RESULTS-job.md), [results.json](results.json), live-lookup sample
[sample.csv](sample.csv). Job `s10-cna-compare-v1` ran 2026-11-07 03:09-03:21 UTC: all 124,810 NVD records
published 2025-01-01..2026-09-30 (0 failed pages), against advisory-database commit `b072a703` (2026-11-02).

**The per-CVE table (18,102 rows) is not in this folder.** It is just over the 2 MB limit of the tool that
publishes MV2's files, so it was refused. Follow-up S11 rebuilds the same table with this code at the same
database commit (fresh NVD read), reports how far it drifts from the counts below, and publishes it in parts in
[../cna-gap-s11-repo-cve-field/](../cna-gap-s11-repo-cve-field/) (see its AMENDMENT.md).

## Short answer

**The headline prediction failed.** GitHub's own CNA is not the only one whose CVEs go missing from GitHub's
Advisory Database. Of CVEs from *other* CNAs that cite a GitHub repository advisory, **22.9%** have no live
global advisory (predicted <= 10%), against **43.8%** for GitHub's CNA, a gap of 20.9 points (predicted >= 25).

What did hold is the narrower contrast. Where the cited repository advisory never became a global advisory,
**61.0%** of other-CNA CVEs still reach the database (almost always as an unreviewed, NVD-fed record), but only
**0.3%** of GitHub-CNA CVEs do (16 of 5,929). So the NVD feed rescues many other-CNA CVEs and almost no GitHub-CNA ones.

One descriptive split (not predicted) changes the picture. **VulnCheck** issued 2,758 of the 4,411 other-CNA
CVEs, and only 4.8% of those are uncovered. **Without VulnCheck, 879 of 1,653 other-CNA CVEs (53.2%) are uncovered:
more than GitHub's own 43.8%.** In the stratum where the cited repository advisory is not global: VulnCheck 122 of
1,395 uncovered (8.7%), all other CNAs 876 of 1,163 (75.3%). Zephyr (164 uncovered of 165), PHP (37 of 37),
Erlang/OTP (56) and rsync (34) lead the list.

## Gate

Passed: 124,810 of 124,810 NVD records; arm O 4,411 CVEs, arm G 13,691; both NOT_GLOBAL strata above 30.

## Predictions (frozen 2026-11-06)

| ID | Prediction | Value | Held |
|---|---|---|---|
| Q1 | Arm O: <= 10% uncovered | 1,011 of 4,411 = 22.9% | **no** |
| Q2 | Arm O uncovered share >= 25 points below arm G's | 22.9% vs 43.8% (20.9 points) | **no** |
| Q3 | NOT_GLOBAL stratum: arm O covered >= 80% AND arm G covered <= 5% | O 1,560/2,558 = 61.0%; G 16/5,929 = 0.3% | **no** (arm G part held, arm O part failed) |
| Q4 | Covered CVEs covered only by an unreviewed advisory: arm O >= 25% AND arm G <= 3% | O 2,127/3,400 = 62.6%; G 6/7,699 = 0.1% | yes |
| Q5 | >= 18 of 20 live `?cve_id=` lookups agree with the checkout | 20 of 20 | yes |
| Q6 | Live-global stratum: arm O DUP >= 5% and higher than arm G | O 599/1,852 = 32.3%; G 31/7,759 = 0.4% | yes |

**3 of 6 held.** The pre-registration said: "Q1 failing with Q2 holding would mean other CNAs' CVEs also fall
through, just less often; Q2 failing would mean the gap is not about who issued the CVE." Q2 failed narrowly, and
the VulnCheck split suggests the CNA's identity matters less than something that differs between CNAs.

## Descriptive (not predicted)

- Coverage, arm O: UNREVIEWED_ONLY 2,127, REVIEWED 1,273, NONE 1,008, WITHDRAWN_ONLY 3. Arm G: REVIEWED 7,693,
  NONE 5,989, UNREVIEWED_ONLY 6, WITHDRAWN_ONLY 3.
- Arm O by year: 2025 112 of 292 uncovered (38.4%); 2026 899 of 4,119 (21.8%).
- When an NVD-fed unreviewed record exists for an arm-O CVE, its `published` date equals NVD's (median 0 days,
  max 21).
- Q6's duplicates are mostly the S3 pattern: in arm O, 564 cited reviewed advisories hold no CVE (EMPTY) while an
  unreviewed record holds it.
- Every unreviewed record read by hand (6 of 6 below, plus the job's 10) lists **no affected package**
  (`vulnerabilities: []`). "Covered" here means a CVE lookup finds a record, not that Dependabot can alert on it.

## Hand checks (2026-11-07 UTC, before the counts were read)

Rows were picked from the middle of the per-CVE table, not from the job's seeded sample. Read live:
`cveawg.mitre.org/api/cve/<id>`, `api.github.com/advisories?cve_id=<id>` and the cited repository advisory page.
All nine agree with the job's labels.

| CVE | CNA | Job cell | Cited repository advisory | Live `?cve_id=` |
|---|---|---|---|---|
| CVE-2026-56243 | VulnCheck | O, NOT_GLOBAL, UNREVIEWED_ONLY | Cap-go/capgo GHSA-6g74-8cpq-g2c8, "No known CVE" | unreviewed GHSA-2c7m-fxr4-462c, no package |
| CVE-2026-93710 | CPANSec | O, NOT_GLOBAL, UNREVIEWED_ONLY | PerlDancer/Dancer2 GHSA-v527-r4px-7vx7, "No known CVE" | unreviewed GHSA-qp5m-r6hx-rjhj, no package |
| CVE-2026-100553 | VulnCheck | O, NOT_GLOBAL, UNREVIEWED_ONLY | openclaw/openclaw GHSA-h9jh-75j7-7hhx | unreviewed GHSA-9w3x-7vmw-xp4x, no package |
| CVE-2025-68622 | GitHub_M | G, NOT_GLOBAL, NONE | espressif/esp-usb GHSA-g65h-9ggq-9827, lists the CVE | `[]` |
| CVE-2026-45100 | GitHub_M | G, NOT_GLOBAL, NONE | OpenSIPS/opensips GHSA-35fr-6rv9-vp68, lists the CVE, package "opensips (C)" | `[]` |
| CVE-2026-45102 | GitHub_M | G, NOT_GLOBAL, NONE | OneUptime/oneuptime GHSA-g9cp-35m2-fjv6 | `[]` |
| CVE-2024-58381 | VulnCheck | O, DUP | pmmp/PocketMine-MP GHSA-h6j3-j35f-v2x7 (reviewed 2024-03-06, `cve_id` null) | unreviewed GHSA-w3w8-r2xc-3rp3 only |
| CVE-2024-58382 | VulnCheck | O, DUP | thephpleague/commonmark GHSA-c2pc-g5qf-rfrf | unreviewed GHSA-fv22-86fq-c33q only |
| CVE-2024-58383 | VulnCheck | O, DUP | froxlor/froxlor GHSA-34qg-65m4-f23m | unreviewed GHSA-x2wh-r8m8-h3h3 only |

## An idea from the hand checks, tested next (S11)

In every case read so far, the cited repository advisory that **says "No known CVE"** has an NVD-fed record in
GitHub's database, and the one that **lists the CVE** has none (Capgo and Dancer2 vs ESP-USB, OpenSIPS, and, read
after the counts, php-src GHSA-rwp7-7vc6-8477 / CVE-2024-11235 and Zephyr GHSA-hfww-j92m-x8fv / CVE-2024-10395).
The S9c case OpenC3 GHSA-2wvh-87g2-89hr / CVE-2026-42088 fits too: its reviewed advisory lacks the alias, and no
NVD-fed record holds the CVE either. If that holds widely, the NVD import is skipped when a repository
advisory already claims the CVE, whoever issued it. That would explain both GitHub's own gap and the
Zephyr/PHP/Erlang one. VulnCheck mostly assigns CVEs to advisories that never asked for one. This is a hypothesis
from a handful of cases, **not a finding**. It is pre-registered as S11 and tested on a seeded random sample.

## Limits

Coverage is from one checkout (2026-11-02); NVD read 2026-11-07. Unreviewed advisories read only from the 2025
and 2026 folders. "Uncovered" means no live global advisory lists the CVE; it says nothing about OSV or other
databases. One-sided: only CVEs whose NVD record cites a GitHub repository advisory.
