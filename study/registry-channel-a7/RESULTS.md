# Result (A7): the registry→visibility effect survives adjustment for release cadence

**Decision: SURVIVES.** The registry-channel effect is **not** reducible to a
repository-level release-cadence covariate. The primary test P1 passed on both
magnitude and significance — the cadence-tertile-stratified direct effect is
**+59.6 pts** (adjusted permutation **p = 0.0017**), against a frozen bar of
≥ +25 pts and p < 0.05. The mediation prediction P2 is falsified: cadence mediates
only **1.1%** of the registry effect (0.7 of 60.3 pts), far below the 0.50 bar and
smaller than both A3's naming mediation (0.36) and A4's real-package mediation
(0.128). Descriptively (P3) cadence and visibility do **not** co-vary (Spearman
ρ = −0.068), and the "registry projects are just better-run, higher-cadence
projects" story fails at its first step: registry repos actually release *slightly
less* often (40.3/yr) than no_registry repos (44.5/yr).

A7 was pre-registered on 2026-10-19 **before** the release-cadence covariate was
collected, with the analysis code (`release_cadence_analysis.py`) and its unit tests
(`test_release_cadence.py`) committed in the same change and reused byte-for-byte at
run time (`frozen_code_sha.json` records the sha256 and git-blob-sha of each). This
write-up is scored against the frozen thresholds in
[`PREREGISTRATION-registry-channel-a7.md`](PREREGISTRATION-registry-channel-a7.md).
No human has reviewed it; it was made with AI agents working for MV2 of Munim, Inc.

Covariate measured 2026-10-19T14:56Z over the 25 repositories that carry eligible
advisories in the frozen A4 census (the 32-app out-of-sample frame). Advisory
grouping and visibility are taken verbatim from that census and classification; A7
only adds the repository-level release count. **All 25 repositories had a readable
release count — none excluded, no rate-limit gap.**

## Predictions vs. outcomes

| Prediction (frozen threshold) | Result | Verdict |
|---|---|---|
| **P1** primary: cadence-tertile-stratified direct effect **≥ +25.0 pts** AND adjusted permutation **p < 0.05** → SURVIVES | **direct +59.6 pts**, adjusted p = **0.0017** (10,000 perms, within-tertile, 25 repos); crude total +60.3 pts, p = 0.0015 | **SURVIVES** |
| **P2** mediation: `mediated_fraction ≥ 0.50` → cadence explains the effect; report vs A3 (0.36) and A4 (0.128) | mediated **0.7 pts**, fraction **0.011** — below 0.50, and below both A3 and A4 | **falsified** (cadence does not mediate) |
| **P3** descriptive: cadence and visibility co-vary; registry repos release more | Spearman ρ = **−0.068**; mean releases/yr registry **40.3** vs no_registry **44.5** | reported (no threshold) — relationship absent, and the sign is backwards |
| **Power floor** ≥ 2 tertiles with both groups and ≥ 4 advisories/group | **3 of 3 tertiles** usable; all comparisons defined | met (not underpowered) |

## The effect is present at every cadence level

The decisive picture is the per-tertile table: if cadence drove the gap, the
registry advantage would shrink or vanish once repositories of similar cadence are
compared. It does not — the registry advantage is large and positive in **all three**
cadence tertiles, and is in fact *widest* among the highest-cadence projects.

| Cadence tertile | registry visible | no_registry visible | difference |
|---|---|---|---|
| T1 (lowest cadence) | 64.8% (160/247) | 14.2% (69/485) | **+50.6 pts** |
| T2 (middle) | 79.2% (84/106) | 20.8% (30/144) | **+58.4 pts** |
| T3 (highest cadence) | 79.0% (211/267) | 3.9% (7/180) | **+75.1 pts** |

Because registry and no_registry repositories are present across all three tertiles
with ample advisories in each, the stratified test is fully powered (unlike E1's two
usable strata and A4's eight both-strata repos), and the within-tertile permutation p
(0.0017) is computed on the whole sample rather than a thin subset.

## The confound's own premise fails

The hypothesis A7 was built to test is intuitive: "publishes to a registry" might be
a proxy for a diligent, frequently-releasing project whose maintainers are active
enough that GitHub reviews and imports their advisories, so the registry channel per
se does nothing. That premise requires registry projects to release *more* often.
They do not. Mean release cadence is **40.3/yr for registry repos and 44.5/yr for
no_registry repos**, and the per-repo Spearman correlation between cadence and
visibility is **−0.068** — indistinguishable from zero and, if anything, slightly
negative. High-cadence no_registry projects (ClickHouse at 92/yr, coolify at 124/yr,
metabase at 72/yr, mastodon at 35/yr) are 0% visible, while low-cadence registry
projects like nocodb (22.5/yr, 100% visible) and grokability/snipe-it (22.8/yr,
45.9% visible) are far more visible. Release discipline is simply not what separates
visible from blind.

## Reconciliation with the arc

A7 closes the most plausible remaining *repository-level* alternative to the registry
channel. The chain now reads: the advisory-import gap is an application-vs-library
effect (H1, +53.0 pts); within applications it tracks whether the project publishes
to an OSV-indexed registry (A2 same-sample, A1 out-of-sample); and that registry
effect is **not** explained by whether any single advisory names a package (A3,
mediates 0.36), by whether the named package is a real repo-matching release (A4,
0.128), by the project's release cadence (A7, 0.011), and — for the Go stratum — is
replaced by the free repo-path module channel (A6). What remains genuinely open is
OSV's uneven **ecosystem** coverage (E1 was underpowered at 2 strata; the pooled E2
test is queued to decide it). Everything measured so far points the same way: an
advisory reaches scanners when it can be *bound to a package that an OSV ecosystem
indexes* — a real registry release, or a Go module path — and project-level virtue
(cadence) does not substitute for that binding.

## Limits

- Permutation units are repositories (25). The stratified test is well powered
  because both groups populate all three tertiles, but a 25-repo sample still yields
  wide per-tertile CIs; the null on mediation is "no detectable cadence mediation,"
  not "proven zero."
- Release cadence is one operationalisation of maintainer diligence (published
  GitHub releases per year). A project that ships via tags or a changelog rather than
  the Releases API would read as low-cadence; `discourse/discourse` publishes exactly
  one GitHub release (0.07/yr) yet is an actively maintained project, which is a known
  limitation of this proxy. It biases toward *finding* a cadence effect among such
  repos, and none appeared.
- Visibility is measured once; GitHub→OSV review lag is not modelled here.
- Grouping and visibility are inherited verbatim from the A4 census snapshot
  (2026-10-19T09:40Z); A7 does not re-collect them.

## Reproduce

```
# fetch the frozen collector + analysis from raw main, recording sha256 + blob-sha
python -I fetch_frozen.py
# collect release cadence (one GitHub REST request per repo) and run the frozen tests
python -I release_cadence_analysis.py --out-dir out
# offline unit tests for the tertile split, stratified effect, Spearman and verdict rule
python -m unittest -v test_release_cadence
```

Inputs: the frozen A4 `real_package_census.csv` + `registry_classification.json`
(visibility and grouping) and the public GitHub REST API (release counts, read-only,
one request per repository). Outputs: `cadence_adjusted_summary.json` (P1–P3,
per-tertile detail, per-repo cadence, verdict), `release_cadence.csv` (one row per
repository) and `frozen_code_sha.json` (hashes of the reused analysis code).

Made with AI agents working for MV2 of Munim, Inc.
