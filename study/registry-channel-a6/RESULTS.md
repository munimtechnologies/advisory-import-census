# Result (A6): the Go-module rescue, out of sample — primary inconclusive, pre-specified language check strongly positive

**Decision, scored against the frozen plan in
[`PREREGISTRATION-registry-channel-a6.md`](PREREGISTRATION-registry-channel-a6.md):**

- **P1 (primary) is INCONCLUSIVE (underpowered) under its own power floor.** The frozen
  `go_module` probe left only **2** "not_go" repositories (the floor was 4 per group),
  because `proxy.golang.org` labelled 13 PHP/Ruby/Python/JS apps as Go modules. That is
  the same flaw A5 exposed *after* A6 was frozen. Read as a plain test, P1 also misses
  its threshold (+17.8 pts vs +40, p = 0.32).
- **R2 is the pre-specified robustness check that groups by GitHub's primary language,
  and A5's write-up named it in advance as A6's valid contrast. It holds, by a wide
  margin:** software-typed advisories of Go apps are **74.8% scanner-visible (83/111)**,
  against **0.2% (1/638)** for non-Go apps. That is **+74.6 pts, permutation p = 0.0001**,
  over 24 repositories, none of them in any earlier frame.
- **P3 (channel) holds:** 98.8% (83/84) of the rescued advisories have OSV naming the Go
  module at the repo path. **D1:** all 84 come through the advisory's **own GHSA record**
  (GitHub's reviewers), and none comes only through a CVE alias such as a Go vuln-DB
  `GO-` entry.

Plain-language finding: among self-hosted apps that ship **no package on a registry**
(Docker images, binaries, install scripts), an advisory that names no package reaches
OSV-backed scanners about three times in four **if the app is written in Go**. It almost
never does otherwise (1 in 638). The reason is that Go's module path *is* the repository
path, so GitHub's reviewers can attach `Go:github.com/<owner>/<repo>` without the
maintainer publishing anything.

Registered 2026-10-19 before any A6 data existed and before A5's result. Collected
2026-10-19 12:17–13:38 UTC in a sealed sandbox. No human has reviewed this. It was made
with AI agents working for MV2 of Munim, Inc.

## Frame and coverage

30 fresh self-hosted apps (frozen `frame_apps.json`, no overlap with the 59 earlier
apps, enforced by a unit test). `filebrowser/filebrowser` was **dropped as archived**
(GitHub API `archived: true`, the pre-specified rule). Five apps had no eligible
advisories (`NginxProxyManager/nginx-proxy-manager`, `casdoor/casdoor`,
`juanfont/headscale`, `mealie-recipes/mealie`, `photoprism/photoprism`). That leaves
**24 repositories, 1,066 eligible advisories, 749 of them software-typed**. Every app is
`no_registry` by construction.

## Predictions vs. outcomes

| Prediction (frozen threshold) | Result | Verdict |
|---|---|---|
| **P1** software-typed: visible(go_module) − visible(not_go) **≥ +40 pts, p < 0.05**; power floor ≥ 4 repos per group | go 17.8% (84/473, 22 repos); not_go 0.0% (0/276, **2 repos**: glpi, openproject); **+17.8 pts, p = 0.3201** | **INCONCLUSIVE (underpowered)**; below threshold even if read as a test |
| **P2** all advisories: **≥ +30 pts, p < 0.05** | go 31.1% (244/785); not_go 0.0% (0/281); **+31.1 pts, p = 0.3042** | **MISSED** (p); same 2-repo not_go group |
| **P3** among go visible software-typed, **≥ 70%** name the repo-path Go module | **98.8%** (83/84) | **HOLDS** |
| **P4** go < 100%; not_go > 0% but small | go 17.8%; not_go **0/276** | go part holds; not_go is exactly 0, not ">0" |
| **R1** drop heaviest repo per group; keep sign, p < 0.05 | dropped glpi, openemr → +24.2 pts, p = 0.5421 | sign kept, not significant |
| **R2** group by GitHub primary language == Go; keep sign | **software: 74.8% (83/111) vs 0.2% (1/638), +74.6 pts, p = 0.0001**; all: 79.7% (228/286) vs 2.1% (16/780), +77.7 pts, p = 0.0001; 24 repos | **HOLDS (strongly)** |
| **R3** age ≥ 90 days; keep sign, ≥ +30 pts | +23.8 pts (84/353 vs 0/262), p = 0.29 | sign kept, below +30 (frozen covariate) |
| **R4** with / without CVE; sign per stratum | with CVE +21.5 pts; without CVE +2.2 pts (2/92 vs 0/19) | positive in both (frozen covariate) |
| **D1** own GHSA record vs CVE-alias-only | **84 own GHSA, 0 alias-only** | rescue is GitHub's reviewers, not the Go vuln DB |

R1, R3 and R4 inherit the frozen covariate's 2-repo not_go group, so they say little
about Go itself. R2 is the only contrast where both groups are well populated: 10 Go
repos and 14 non-Go repos contribute software-typed advisories.

## Why the frozen covariate collapsed (and why R2 was already the plan)

`go_module = gomod_match OR proxy_ok`. As A5 found, `proxy.golang.org/<path>/@latest`
returns a synthesized version for almost any tagged GitHub repository, for example
`zammad v0.0.0-20261014174932-…`, `chatwoot v4.18.0+incompatible` and
`openemr v0.0.0-…`. Here `proxy_ok` was true for **every** frame repo whose proxy call
succeeded. Only glpi and openproject came out "not_go", because their proxy calls
failed. A5's result was published after A6 had been frozen, so A6 could not change its
primary measure. It did not need to, because the pre-registration already carried
R2 (language) "to catch Go apps whose module lives in a subdirectory". The A5 write-up
then named R2 as "the valid out-of-sample contrast" before A6's data was read. A6
reports the frozen P1 as written and leads with R2 because that was the plan, not
because R2 came out well.

Language is an imperfect stand-in in both directions, and the data shows where:
`AdguardTeam/AdGuardHome` is a Go module (`go.mod` matches), but GitHub reports its
primary language as TypeScript. Its one software-typed advisory is the single "non-Go"
visible advisory in R2. `portainer/portainer` (Go backend, TypeScript primary) is
grouped non-Go too (0/1 software-typed). Moving both to the Go side would make R2
slightly stronger (84/113 vs 0/636), so the misclassification works against the
finding, not for it.

**Descriptive, not pre-registered:** splitting by `gomod_match` alone (go.mod at the
default branch declares `github.com/<repo>`) gives 73.0% (73/100, 9 repos) vs 1.7%
(11/649, 15 repos). The "not" side's 11 visible advisories all belong to real Go apps
whose module is not declared at the repo root (`1Panel-dev/1Panel` 9/10, no root
`go.mod` on the default branch; and
`woodpecker-ci/woodpecker` 2/2 with vanity path `go.woodpecker-ci.org/woodpecker/v3`).
No p-value is reported for this split because it was not pre-specified.

## Per-repository (software-typed advisories)

| Repo | Language | gomod_match | Eligible | Visible | % |
|---|---|---|---|---|---|
| zitadel/zitadel | Go | yes | 74 | 52 | 70.3 |
| 1Panel-dev/1Panel | Go | no (no root go.mod) | 10 | 9 | 90.0 |
| traefik/traefik | Go | yes | 6 | 6 | 100 |
| navidrome/navidrome | Go | yes | 6 | 5 | 83.3 |
| argoproj/argo-cd | Go | yes | 8 | 4 | 50.0 |
| authelia/authelia | Go | yes | 2 | 2 | 100 |
| woodpecker-ci/woodpecker | Go | no (vanity) | 2 | 2 | 100 |
| drakkan/sftpgo, gravitl/netmaker, owncast/owncast | Go | yes | 1 each | 1 each | 100 |
| AdguardTeam/AdGuardHome | TypeScript* | yes | 1 | 1 | 100 |
| portainer/portainer | TypeScript* | no | 1 | 0 | 0 |
| glpi-project/glpi | PHP | no | 190 | 0 | 0 |
| openemr/openemr | PHP | no | 126 | 0 | 0 |
| opf/openproject | Ruby | no | 86 | 0 | 0 |
| Cacti/cacti | PHP | no | 58 | 0 | 0 |
| zammad/zammad | Ruby | no | 49 | 0 | 0 |
| FreshRSS/FreshRSS | PHP | no | 23 | 0 | 0 |
| TandoorRecipes/recipes | HTML (Python) | no | 23 | 0 | 0 |
| frappe/frappe | Python | no | 23 | 0 | 0 |
| jumpserver/jumpserver | Python | no | 20 | 0 | 0 |
| Mintplex-Labs/anything-llm | JavaScript | no | 19 | 0 | 0 |
| langgenius/dify | Python | no | 15 | 0 | 0 |
| chatwoot/chatwoot | Ruby | no | 4 | 0 | 0 |

\* Go server with a large web front end; GitHub's language field says TypeScript.

Every non-Go app scores 0% on its package-less advisories, including large, mature
projects with hundreds of advisories (glpi 190, openemr 126, openproject 86).

## The frappe placeholder (flagged in the pre-registration)

`frappe/frappe` has a 0.0.1 **placeholder** on PyPI. Of its 62 package-typed advisories,
all 62 name `pip:frappe` on the GitHub page, but only **4 are visible**, each as
`PyPI:frappe` (CVE-2025-30212/30213/30214/30217, March 2025). The other 58 never reached
OSV. So naming a package that exists only as a placeholder rescued 6.5% of advisories.
This is the same lesson as A3 and A4: naming a package is not enough on its own.

## Reconciliation with the arc

- **A5 (same-sample, null)** rejected the Go rescue because of the degenerate proxy
  measure, which mislabelled 22 of 24 repos. Its one valid Go module (grafana, 76.9%
  visible) and Go-language harbor (55%) fit A6's R2 well. A6 does not overturn A5's
  measurement lesson. It supplies the valid test that A5 could not run.
- **A1/A2 (registry channel)** say publishing a real registry package gets advisories to
  scanners. A6 adds the second route and bounds it. For apps *without* a registry
  package, being written in Go is close to the only thing in this frame that separates
  visible from blind. The rescue is GitHub's reviewers attaching the free repo-path
  module, not the Go team's own database.
- **Practical rule (as registered):** an advisory reaches scanners when it can be bound
  to a package. That package is either a real registry release or, for a Go project,
  the module at the repo path, which exists without any extra publishing. A PHP, Ruby,
  Python or JavaScript app shipped only as Docker images stays blind unless its
  maintainer publishes and names a real package.

## Limits

- The primary test as frozen is uninformative (degenerate covariate), so the
  confirmatory weight rests on R2. R2 was pre-specified, but only with a "keeps sign"
  criterion. Its p-value is the same repository-level permutation test, reported as
  computed.
- Language and Go-module status are correlated with other things: Go apps in this frame
  are infrastructure tools (proxies, SSO, CI), and the non-Go apps are mostly PHP/Ruby
  business apps. A6 cannot separate "written in Go" from "the kind of project that is
  written in Go". D1/P3 (the rescue names the repo-path module) is the mechanism
  evidence.
- The frame was picked by an AI agent and is not random. 24 repos; one heavy Go repo
  (zitadel, 74 rows) dominates the Go pooled rate. The per-repo table shows that every
  Go repo with ≥ 2 advisories is ≥ 50% visible.
- Visibility was measured once (2026-10-19). Review lag is not modelled beyond R3.

## Reproduce

```
python fetch_deps.py --out-dir out            # downloads the published A3/A5 code, records sha256
python attribution_census.py --frame-dir . --out-dir out/census
python -m unittest -v test_oos_go_rescue
python oos_go_rescue.py --census-csv out/census/attribution_census.csv --frame frame_apps.json --out-dir out
```

Data in this folder: `oos_go_rescue_summary.json`, `oos_go_rescue_census.csv` (one row
per eligible advisory, with OSV packages, language and go.mod module),
`oos_go_rescue_per_repo.csv`, `oos_go_rescue_repo_probe.csv`, `deps_sha256.json`.

Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working for MV2 of
Munim, Inc.
