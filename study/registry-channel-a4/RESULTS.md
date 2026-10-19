# Result (A4): the real-package refinement of the registry channel — null

**Decision: the pre-registered real-package hypothesis is NOT supported.** The primary
test P1 missed on both magnitude and significance (+14.4 pts, p = 0.9835, needed
≥ +40 pts and p < 0.05), and the mediation test P3 missed its threshold (mediated
fraction **0.128**, needed ≥ 0.50) **and** its secondary A4 claim (0.128 is **below**
A3's naming mediation of 0.36, not above it). The pre-registration's falsification
clause fires on every one of its conditions. The first-stage link P2 held strongly
(registry apps carry real packages, no_registry apps essentially never), but the
real-package property does **not** explain scanner visibility beyond what A3 already
measured — in fact it explains *less*.

A4 was pre-registered on 2026-10-19 before the covariate was collected and before the
A3 result was read, reusing the A1 frame and classification verbatim. This write-up is
scored against the frozen thresholds in
[`PREREGISTRATION-registry-channel-a4.md`](PREREGISTRATION-registry-channel-a4.md).
No human has reviewed it; it was made with AI agents working for MV2 of Munim, Inc.

Census: 1,429 eligible advisories across 25 repositories with advisories (of the frozen
32-app frame), snapshot 2026-10-19T09:40Z, OSV canary `GHSA-39mp-8hj3-5c49` resolved,
classification frozen 2026-10-18. Registry metadata was probed on npm, PyPI, Packagist,
RubyGems, crates.io and the Go proxy, paced one request per second, every page archived
under `out/raw/`. One repository (`grafana/grafana`) was unreadable this run (a control
character in a package coordinate) and is excluded, as pre-registered for parse faults.

## Predictions vs. outcomes

| Prediction (frozen threshold) | Result | Verdict |
|---|---|---|
| **P1** primary: within repos holding both strata, visible(real) − visible(not_real) **≥ +40 pts**, within-repo permutation **p < 0.05** | **+14.4 pts** (real 76.2%, 131/172; not_real 61.8%, 134/217), p = **0.9835**, 8 repos | **MISSED** (magnitude and significance) |
| **P2** first stage: registry apps' advisories are `real` more often, diff **> 0**, **p < 0.05** | **+40.1 pts** (registry 40.3%, 250/620; no_registry 0.2%, 2/809), p = **0.0219**, 25 repos | **held** |
| **P3** mediation: mediated fraction **≥ 0.50** and \|direct\| < \|total\|; secondary (A4 claim) fraction **≥ A3's 0.36** | total 67.7 pts, direct **59.0** pts, mediated **8.7** pts, fraction **0.128** | **MISSED** (0.128 < 0.50 and < 0.36; \|direct\| < \|total\| only) |
| **P4** residual (descriptive): real < 100% visible; not_real > 0% but small | real **74.2%** visible, not_real **28.5%** visible | reported |
| **R1** drop heaviest repo per group: P2 keeps sign, p < 0.05 | dropped discourse, open-webui → **+54.6 pts**, p = **0.0047**, 23 repos | holds (for P2) |
| **R3** `own_id_not_in_osv` reproduces P1's sign | **+14.4 pts**, p = 0.9835 | same as P1 (null) |

## The decisive quantity refutes the hypothesis

The pre-registration named the decisive test up front: **package-typed advisories that
resolve `no_match` or `absent`** — named a package, but not a real repo-matching release
(the coolify case) — should be **mostly blind** if the real-package refinement is right.
The resolution breakdown shows the opposite:

| `named_pkg_resolution` | n | visible | visible % |
|---|---|---|---|
| `yes` (real, repo-matching) | 252 | 187 | **74.2** |
| `no_match` (named, exists, points elsewhere) | 267 | 203 | **76.0** |
| `absent` (named, not on registry) | 59 | 22 | 37.3 |
| `unchecked` (unsupported ecosystem) | 100 | 67 | 67.0 |

`no_match` advisories are **76.0% visible — as visible as the real ones (74.2%)**. The
coolify anecdote that motivated A4 (a named-but-not-real npm package that stayed blind)
did not generalise: naming a package that is *not* the project's own release reaches
scanners about as often as naming the real one. Only the `absent` cases (the named
package does not exist on the registry at all) are meaningfully more blind, and they are
a small minority (59 of 1,429). So the real/not-real distinction does not separate
visible from blind, which is exactly why P1 is null.

## Mediation: the real-package split explains *less* than naming did

A3 found that *naming a package* mediated 36% of the registry→visibility gap (itself a
partial null against the 50% bar). A4's real-package split mediates only **12.8%** —
less than A3, the reverse of the secondary A4 claim. The registry effect is
overwhelmingly **direct** (59.0 of 67.7 pts survive stratifying on real vs not_real).
Within the `not_real` stratum alone, registry apps are still +67.1 pts more visible than
no_registry apps (72.6% vs 5.5%). Whatever the registry covariate captures, it is not
reducible to whether any single advisory names a real, repo-matching package.

## Ecosystem is the live confound (hands off to E1)

Among `real` advisories, visibility varies sharply by ecosystem — the pattern a
coverage confound would produce:

| Ecosystem of the real package | n | visible % |
|---|---|---|
| npm | 214 | 79.4 |
| PyPI (pip) | 21 | 47.6 |
| Packagist (composer) | 16 | 37.5 |
| Go | 1 | 100.0 |

A real npm release is twice as likely to be scanner-visible as a real Packagist release.
Because registry apps in this frame skew heavily npm (Ghost, directus, strapi, nocodb,
open-webui) while several no_registry apps are PHP/Packagist or Ruby, part of the raw
registry→visibility gap could be OSV simply indexing npm better than Packagist. That is
the pre-registered E1 question (ecosystem-coverage confound), whose analysis code was
frozen and committed last run **before** this census existed; E1 now runs on this
`real_package_census.csv`. On 25 repositories E1 is likely underpowered for a stratified
test and will most probably report INCONCLUSIVE with the per-ecosystem table above as
its substance; it is reported honestly either way.

## Reconciliation with the arc

The registry-channel chain still stands: publishing your own code to an OSV-indexed
registry is strongly associated with your advisories reaching scanners (H1, A2, A1), and
A4's P2 confirms the first stage — registry apps carry real packages, no_registry apps
almost never (0.2%). What A4 removes is a tempting *mechanism* for it. It is **not** that
the named package has to be your real, repo-matching release: homonym packages
(`no_match`) reach scanners just as well, and the registry effect is mostly direct. Two
candidates remain open — OSV's uneven ecosystem coverage (E1) and a project-level
property of registry-publishing projects (release discipline, reviewer familiarity) that
no single-advisory covariate captures.

## Limits

- 25 repositories with eligible advisories; permutation units are repositories, so P1's
  within-repo test rests on only 8 repos holding both strata — low power, wide CIs. The
  null is therefore "no detectable effect," not "proven zero"; but the resolution
  breakdown (no_match ≈ real) is a direct, non-inferential refutation of the mechanism.
- `grafana/grafana` was unreadable this run and is excluded; A5 showed grafana is highly
  visible, so its exclusion does not inflate the registry group.
- `real` requires registry metadata to point back to the exact owner/repo; projects that
  publish under a scoped or renamed package would be undercounted as `no_match`, which
  *weakens* the hypothesis test conservatively — yet the hypothesis still failed.
- Visibility is measured once; GitHub→OSV review lag is not modelled here.

## Reproduce

```
# collector (paced, read-only, archives every advisory + registry response)
python real_package_census.py --frame-dir . --out-dir out
# offline unit tests for the parser and the real-package probe
python -m unittest -v test_real_package
# frozen tests (P1–P4, robustness, resolution breakdown)
python real_package_analysis.py --csv out/real_package_census.csv \
  --classification registry_classification.json --out-dir out
```

Inputs: the frozen `frame_apps.json` / `registry_classification.json` (from A1) and the
public GitHub advisory pages + OSV API + registry metadata APIs. Outputs:
`real_package_summary.json` (P1–P4, robustness, resolution breakdown, per-repo),
`real_package_census.csv` (one row per eligible advisory, with named packages,
`named_pkg_resolution` and `real_package`), `real_package_census_meta.json` (canary,
counts, unreadable repos) and the archived `out/raw/` HTML.

Made with AI agents working for MV2 of Munim, Inc.
