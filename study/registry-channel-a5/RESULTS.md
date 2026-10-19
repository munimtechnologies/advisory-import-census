# Result (A5): the Go-module reviewer-rescue of package-less advisories — null (not supported)

**Decision: the pre-registered Go-module rescue hypothesis is NOT supported. Every
numeric prediction (P1, P2, P3) MISSED, and the pre-registered `go_module` measure
proved degenerate, so the primary contrast rests on only two "not-Go" repositories.**
A5 was pre-registered on 2026-10-18/19 before the covariate was collected, and is an
honest, confirmatory quantification on A3's own sample (not an out-of-sample test; A6
is that). This write-up is scored against the frozen thresholds in
[`PREREGISTRATION-registry-channel-a5.md`](PREREGISTRATION-registry-channel-a5.md).
No human has reviewed it; it was made with AI agents working for MV2 of Munim, Inc.

Census: 777 software-typed advisories across 24 repositories, read from A3's frozen
public census (`sha256 b550d716…a9123`), classification frozen 2026-10-18. Probe run
2026-10-19.

## Predictions vs. outcomes

| Prediction (frozen threshold) | Result | Verdict |
|---|---|---|
| **P1** primary, `no_registry` software-typed: visible(go) − visible(not_go) **≥ +40 pts**, **p < 0.05** | **−6.3 pts** (go 6.9%, 43/620; not_go 13.2%, 7/53); permutation **p = 0.8168**, 16 repos | **MISSED** (wrong sign, not significant) |
| **P2** secondary, all software-typed: difference **≥ +40 pts**, **p < 0.05** | **−0.1 pts** (go 13.1%, 95/724; not_go 13.2%, 7/53); **p = 1.0**, 24 repos | **MISSED** |
| **P3** channel check: among go visible, **≥ 70%** name a repo-path Go module | **31.6%** (30/95); not_go 0% (0/7) | **MISSED** |
| **P4** residual (descriptive): go < 100%; not_go > 0% but small | go 13.1%; not_go 13.2% (**equal, not small**) | reported |
| **R1** drop heaviest repo per group (`no_registry`): keep sign, p < 0.05 | dropped discourse, goauthentik → **+13.3 pts**, **p = 0.9317** (sign flipped, not significant) | does not hold |

The falsification clause fires on both of its conditions: P1 is null **and** P3 shows
the go-group's visible advisories are not predominantly rescued by a repo-path Go
module. The hypothesis — "being a Go module at the repo path is the rescue channel for
package-less advisories" — is therefore rejected on this sample.

## The measurement caveat (the real story)

The frozen measure was `go_module = gomod_match OR proxy_ok`, where `gomod_match` reads
`go.mod` on the default branch and `proxy_ok` is a 200 from `proxy.golang.org/<repo>/@latest`.
**`proxy_ok` was True for 22 of 24 repositories**, including projects in Ruby
(discourse, mastodon), Python (zulip), PHP (coolify, snipe-it, firefly-iii), Java
(keycloak), C# (jellyfin) and C++ (ClickHouse) — none of which is a Go module.

The per-repo probe (`go_rescue_repo_probe.csv`) shows why: `proxy.golang.org` returns a
synthesized pseudo-version for almost any tagged GitHub repository — `v…+incompatible`
when tags exist (e.g. `discourse v2026.9.0+incompatible`, `mastodon v4.7.3+incompatible`),
or a `v0.0.0-<timestamp>-<hash>` pseudo-version from the latest commit (keycloak,
uptime-kuma, zulip). The Go module proxy manufactures a module for any importable path;
a 200 from it does **not** mean the project is a Go module. **Only `gomod_match` is a
valid signal, and exactly one repository — `grafana/grafana` — satisfied it.** The other
21 "go" labels are artefacts of the proxy.

Consequently the pre-registered `OR proxy_ok` definition collapses the covariate: 22
"go" vs 2 "not_go" (ToolJet and goauthentik, whose proxy calls happened to error). The
primary P1 contrast is therefore both degenerate (nearly no variation) and underpowered
(2 not_go repos). This is logged honestly rather than patched after the fact, because
the measure was frozen before the data. **Reusable lesson: `proxy.golang.org` cannot be
used to detect whether a repository is a Go module; use `go.mod` (`module ==
github.com/<owner>/<repo>`) or GitHub's primary-language field instead.** A6 already
pre-registers the language-based grouping as robustness check R2, so the out-of-sample
test carries a valid covariate.

## What actually rescues package-less advisories

Among the 102 software-typed advisories that are visible, OSV names packages across
several ecosystems (an advisory may name more than one, so counts exceed 102):

| OSV ecosystem named | Advisories |
|---|---|
| Packagist (PHP) | 37 |
| Go (module path) | 39 |
| npm | 13 |
| PyPI | 7 |
| Maven | 6 |
| NuGet | 1 |

Of the 39 Go-ecosystem names, **30 are the module at the repo path** (`Go:github.com/<repo>`).
So repo-path Go modules rescue about 30% of the visible package-less advisories, not the
majority. The rest are rescued by reviewers or CVE aliases attaching the **real registry
package the project already ships** — Packagist for PHP apps (snipe-it carries most of
the 37), npm for JavaScript apps, PyPI, Maven. The honest picture is heterogeneous,
ecosystem-specific reviewer attachment; there is no single "free" channel, and the
repo-path Go module is one minority path among several.

## Per-repository visibility (software-typed advisories)

Highest-visibility repos are genuine infrastructure projects; the long zero tail is what
pulls the pooled go rate down.

| Repo | Registry group | gomod_match | Eligible | Visible | % |
|---|---|---|---|---|---|
| grafana/grafana | no_registry | **true** | 26 | 20 | 76.9 |
| goharbor/harbor | no_registry | false (proxy) | 20 | 11 | 55.0 |
| keycloak/keycloak | no_registry | false (proxy) | 11 | 6 | 54.5 |
| louislam/uptime-kuma | no_registry | false (proxy) | 10 | 5 | 50.0 |
| grokability/snipe-it | registry | false (proxy) | 71 | 35 | 49.3 |
| go-gitea/gitea | registry | false (proxy) | 15 | 3 | 20.0 |
| goauthentik/authentik | no_registry | **not_go** | 46 | 7 | 15.2 |
| jellyfin/jellyfin | no_registry | false (proxy) | 23 | 1 | 4.3 |
| discourse/discourse | no_registry | false (proxy) | 297 | 0 | 0.0 |
| mastodon/mastodon | no_registry | false (proxy) | 57 | 0 | 0.0 |
| metabase/metabase | no_registry | false (proxy) | 44 | 0 | 0.0 |
| zulip/zulip | no_registry | false (proxy) | 41 | 0 | 0.0 |
| outline/outline | no_registry | false (proxy) | 26 | 0 | 0.0 |
| requarks/wiki | no_registry | false (proxy) | 13 | 0 | 0.0 |
| ClickHouse/ClickHouse | no_registry | false (proxy) | 7 | 0 | 0.0 |

(Registry apps with few software-typed rows — directus, synapse, firefly-iii, netbox,
nocodb, open-webui, appsmith, coolify, ToolJet — are in `go_rescue_per_repo.csv`.)

Note that grafana (the one real Go module) is highly visible, consistent with A3's
observation. But harbor, keycloak and uptime-kuma are also highly visible without being
Go modules, and discourse/mastodon/metabase/zulip are Go-labelled yet fully blind. The
Go-module property does not separate visible from blind here.

## Reconciliation with the arc

A3 noticed that visible package-less advisories cluster in some Go projects (grafana,
harbor). A5 confirms grafana and harbor are highly visible, but shows that (i) harbor's
visibility is not explained by a repo-path Go module (its `go.mod` is not at the repo
path under this probe), and (ii) non-Go projects (authentik via PyPI, snipe-it via
Packagist) are rescued the same way. The registry-channel chain stands — publishing a
real package is what gets an advisory to scanners (A1/A2) — but the *specific* idea that
Go's repo-path convention is a distinct, dominant "free" rescue for package-less
advisories is not supported. A4 (the real-package test on the package-typed stratum) is
still queued and will refine the other half.

## Limits

- Same-sample and confirmatory by construction (stated in the pre-registration); A6 is
  the out-of-sample test.
- The frozen `go_module` measure is degenerate (above); treat P1/P2/R1 as uninformative
  on the Go question and rely on the ecosystem breakdown and per-repo table. The valid
  `gomod_match`-only split leaves one Go repo, too few for a test, so no corrected
  permutation test is reported here; A6's R2 (language grouping) supplies the valid
  out-of-sample contrast.
- Permutation units are repositories (16 in P1); small counts, wide CIs.
- Visibility is measured once; GitHub→OSV review lag is not modelled here (A6 R3 adds
  a 90-day age cut).

## Reproduce

```
# collector (paced, read-only, archives every response)
python go_rescue_census.py --classification registry_classification.json --out-dir out
# frozen tests
python go_rescue_analysis.py --csv out/go_rescue_census.csv --out-dir out
```

Inputs: A3's public `attribution_census.csv` (sha256 recorded in
`go_rescue_census_meta.json`) and the frozen `registry_classification.json`. Outputs:
`go_rescue_summary.json`, `go_rescue_census.csv`, `go_rescue_per_repo.csv`,
`go_rescue_repo_probe.csv`, `go_rescue_census_meta.json`.

Made with AI agents working for MV2 of Munim, Inc.
