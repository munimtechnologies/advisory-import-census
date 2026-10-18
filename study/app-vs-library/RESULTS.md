# Result: the advisory-import gap is an application-vs-library effect (confirmed)

*Confirmatory, pre-registered census by MV2 of Munim, Inc. Snapshot
2026-10-18 08:48 UTC. The hypothesis, frame, measures, test and decision rule
were frozen in [`PREREGISTRATION-app-vs-library.md`](../../PREREGISTRATION-app-vs-library.md)
(Amendment 1) and [`AMENDMENT-2.md`](AMENDMENT-2.md) before any advisory data
was collected. Data CC BY 4.0, code Apache-2.0. The collection, analysis and
this write-up were made with AI agents working in MV2's name. Every number
below was checked against this run's own `summary.json` and CSV. No
independent human has reviewed it yet.*

## Verdict

**H1 is supported.** Self-hosted applications' published security advisories
are far more often invisible to package scanners than libraries' advisories
are. The repository-level permutation test gives **p = 0.0057** and the
difference points the predicted way, so both conditions of the pre-registered
decision rule are met. The difference, **+53.0 percentage points**, is also
larger than the pre-stated expectation of more than 30 points.

## Validity checks

- **OSV canary** `GHSA-39mp-8hj3-5c49` resolved, so OSV lookups were live and
  the run is valid.
- **All 80 frame repositories were readable.** No listing page or advisory
  page failed (`unreadable_repos: []`, `detail_failures: 0` everywhere).
- **The exact published collector ran.** It is
  `app_library_census_html.py` from commit `eb532df` (550 lines, SHA-256
  `1840ae5578804fe1138eda97d4169ae4d22f0ddb14032236c0784ab02ace4a00`, logged by
  the job). Its 29 offline tests passed before any page was fetched.
- **Hand spot-check against OSV (2026-10-18).** Four advisories were checked:
  three marked blind and one marked visible. All four agree with the CSV:
  - `GHSA-h6cc-rc6q-23j4` (Vaultwarden, high) is 404 on OSV. Its alias
    `CVE-2025-24364` exists, but `affected` lists only a Git commit range for
    `github.com/dani-garcia/vaultwarden` and no package.
  - `GHSA-4vj8-p63v-8p24` (Plane, critical) is 404 on OSV. Its alias
    `CVE-2026-105639` likewise has only a Git range.
  - `GHSA-5qpp-pqww-h7fp` (n8n, high) is 404 on OSV and has no CVE.
  - `GHSA-cw9w-vv67-hf73` (n8n, marked visible) names npm `n8n`.

## Primary result

An advisory counts as **scanner-blind** when no OSV record names any package.
OSV is searched under the advisory's own GHSA ID and under every CVE alias.

| Group | Repos in frame | Repos with eligible advisories | Eligible advisories | Scanner-blind | 95% CI (Wilson) | Repo-median blind |
|---|---:|---:|---:|---:|---|---:|
| Application | 40 | 27 | 909 | **482 (53.0%)** | 49.8–56.3% | 93.8% |
| Library | 40 | 5 | 11 | **0 (0.0%)** | 0.0–25.9% | 0.0% |

The primary test is a two-sided permutation test that shuffles the
application/library label across the 32 repositories with eligible advisories
(10,000 permutations, seed 20261017). It gives application − library =
**+53.0 points, p = 0.0057**.

**Secondary measure** (the advisory's own GHSA ID is absent from OSV): the
figures are identical. Applications are 482 of 909 (53.0%), libraries 0 of 11,
p = 0.0057. In this sample the CVE-alias lookup never moved an advisory from
blind to visible. 251 of the 482 blind advisories do carry a CVE. Where OSV
has those CVE records, the ones checked list only Git commit ranges and no
package. No package-manifest scanner (Dependabot, `npm audit`, `pip-audit`,
lock-file mode of OSV-Scanner) can match a Git range like that to a deployed
Docker image or install.

## Pre-specified robustness checks (reported regardless of outcome)

| Check | Eligible | Repos | Difference | p |
|---|---:|---:|---:|---:|
| Drop the most advisory-heavy repo in each group (`siyuan-note/siyuan`, `psf/requests`) | — | 30 | +54.1 | **0.0199** |
| Only advisories published before 2026-05-01 | 354 | 31 | +34.6 | 0.31 |
| Only advisories published from 2026-05-01 | 566 | 22 | +64.2 | 0.135 |

The result survives dropping the heaviest repositories. **Within each
publication period the difference still favours applications, but neither
period on its own reaches p < 0.05.** The library side is thin there: 5
library repositories have advisories before May 2026 and 1 has them after. The
application side is strongly bimodal (see below), so these split tests have
little power. We report this as a limit, not as support.

## Exploratory observations (not pre-registered; treat as hypotheses)

**1. Review lag explains part of the application number, but not all of it.**
Application advisories at least 90 days old are still mostly visible, yet more
than a third remain blind:

| Advisory age at snapshot | Application advisories | Blind |
|---|---:|---:|
| 14–29 days | 146 | 119 (81.5%) |
| 30 days or more | 763 | 363 (47.6%) |
| 90 days or more | 508 | 187 (36.8%) |

All 11 library advisories are at least 158 days old, so the groups are not
matched on age. Comparing like with like, applications' 36.8% blind at 90+ days
is still well above libraries' 0 of 11. That comparison was not
pre-registered.

**2. Within applications, what matters looks like whether the advisory names a
registry package.** The application group splits almost cleanly in two:

- **Mostly visible:** apps whose code is also published to a package registry,
  and whose advisories name that package:
  - `gogs` (Go `gogs.io/gogs`, 3 of 66 blind)
  - `payload` (npm `payload` and `@payloadcms/*`, 2 of 40)
  - `copyparty` (PyPI, 2 of 16)
  - `RSSHub` (npm, 1 of 7)
  - `lobehub` (npm, 0 of 14)
  - `pocketbase`, `syncthing` and `memos` (Go, 0 blind)
  - `code-server` (npm, 0 blind)
- **Mostly blind:** apps shipped only as images, binaries or source:
  - Immich, Stirling-PDF, paperless-ngx, Rocket.Chat, LibreChat, Twenty,
    Huginn, cal.diy and Pi-hole: 100% blind each (125 advisories together).
  - Plane 82 of 84, Penpot 23 of 24, Joplin 30 of 32, Hoppscotch 15 of 16,
    Vaultwarden 26 of 30.
- **Mixed:** n8n (58 of 210 blind), SiYuan (107 of 216) and Sentry (7 of 21).

This fits the mechanism stated in the pre-registration. A registry package
gives GitHub's reviewers something to attach the advisory to. An app shipped
only as a Docker image does not, so its advisory stays on the repository page
where no package scanner looks. A cleaner test would pre-register "does the
advisory name a registry package" as the predictor.

## Concurrent work

On the same day (2026-10-18), Safeguard.sh published a study of 2,486
repository advisories from 45 projects. All of those projects publish
packages, chosen as the top feeders of Go, npm and PyPI records. It found
30.7% missing from GitHub's reviewed database and OSV, mostly recent
advisories, with a median arrival delay of 5.4 days.
([source](https://safeguard.sh/resources/blog/github-repository-advisories-missing-from-advisory-database-2026-data))
That study looks only at packaged projects, matches by GHSA ID only, and does
not split by project type. Its lag finding agrees with observation 1 above.
This census adds the pre-registered application-vs-library contrast and the
CVE-alias check.

## Honest limits

- **The library side is small.** Only 5 of the 40 most-depended-on libraries
  published any eligible *repository* advisory (11 in total). Many popular
  libraries handle vulnerabilities through other channels. The library rate
  is therefore imprecise (upper 95% bound 25.9%). The test is at the
  repository level for this reason.
- **13 of the 40 applications published no repository advisories at all.**
  These include Apache Superset and Airflow, Elasticsearch, Odoo, Kong,
  Ollama, LocalAI, Appwrite and Meilisearch. They stay in the frame but
  contribute no rows. Several handle disclosure through their own process.
- **The groups are not matched.** Applications were chosen by stars and
  libraries by dependents, so they differ in size and in advisory age. The
  result is an association between distribution channel and the import gap,
  not a controlled experiment.
- **OSV stands in for scanners.** Dependabot reads GitHub's database directly,
  which may differ slightly. This is one snapshot, and advisories can still
  be imported later.
- **LibreChat was measured before** under its old path
  (`danny-avila/librechat`), so it is effectively re-measured here.
- **Access route.** Data came from github.com's public advisory pages,
  unauthenticated and paced at one request every 2.5 seconds, following
  Amendment 2. The 1,082 fetched pages are archived with the run output but
  not committed here because of their size.

## Files

- [`results/app_library_census.csv`](results/app_library_census.csv): one row
  per eligible advisory (920 rows), CC BY 4.0.
- [`results/summary.json`](results/summary.json): group shares, permutation
  tests, robustness checks and per-repository collection log.

## What to do with this

If you self-host an application, whether open source or not, don't expect
Dependabot, `npm audit` or `pip-audit` to tell you about that application's
own advisories. Watch its advisory page directly, or run
`python blindspot.py --package repo:OWNER/REPO` from this repository.

If you maintain an application, name a package (or an ecosystem-specific
identifier) in your advisories where one exists. That is what lets them reach
scanners.

*MV2, Munim, Inc., mv2@munimtech.com*
