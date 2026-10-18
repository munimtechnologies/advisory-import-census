# Result (A1): out-of-sample replication of the registry-channel mechanism — replicated

**Project:** advisory-import-census (MV2 of Munim, Inc.)
**Pre-registration:** [PREREGISTRATION-registry-channel-a1.md](PREREGISTRATION-registry-channel-a1.md),
frame + classification frozen and committed before any advisory data was collected.
**Snapshot:** 2026-10-18T20:12:49+00:00 (collector `app_library_census_html.py`, commit `eb532df`;
analysis `registry_channel_analysis.py`, unchanged from A2).
**Made with AI agents working for MV2 of Munim, Inc.** Apache-2.0 (code) / CC BY 4.0 (text & data).

## What was tested

A2 (same 27-repo sample, commit `310b6bb`) found that self-hosted applications which
ship their own code to an OSV-indexed registry are far less *scanner-blind* than
Docker-/binary-only apps (−51.5 points, p = 0.0077). A1 applies the identical frozen
rule to 32 **new** self-hosted applications sharing no repository with earlier frames.

## Coverage (who actually entered the test)

| | Frame | Repos with ≥1 eligible advisory | Eligible advisories |
|---|---|---|---|
| `registry` | 11 | 10 | 620 |
| `no_registry` | 21 | 16 | 837 |

Repos with zero eligible advisories drop out, as pre-registered (6 of the 32 frame repos
published no eligible GitHub repository advisory at snapshot: appwrite, janhq/jan,
mattermost, nextcloud/server, jenkins, apache/superset). Unreadable repos (not counted
as zero): none. OSV canary (GHSA-39mp-8hj3-5c49) resolved: true.

## Primary result (P1)

| | Blind % (95% Wilson CI) | Repo-median blind % |
|---|---|---|
| `registry` | 26.6% ([23.3%, 30.2%]) | 27.2% |
| `no_registry` | 84.8% ([82.2%, 87.1%]) | 100.0% |

`registry − no_registry` = **−58.2 points**, repository-level permutation test
(seed 20261017, 10,000 permutations), two-sided **p = 0.0017** (26 repositories).

## Scoring against the pre-registered predictions

- **P1** (negative and p < 0.05): **MET** — the difference is −58.2 points with p = 0.0017,
  and the effect is larger out of sample than A2's −51.5 points.
- **P2** (repo-median lower in `registry`): **MET** — 27.2% vs 100.0%.
- **P3** (sign unchanged after dropping heaviest repo per group, dropped
  discourse/discourse and open-webui/open-webui): **MET**, difference −44.8 points,
  p = 0.0086.
- Secondary (`own_id_not_in_osv`): −58.2 points, p = 0.0017 (identical here because every
  scanner-blind advisory in this frame is also one whose own GHSA id fails to resolve in OSV).

### Verdict — replicated
The registry-channel effect replicates out of sample: on 32 apps that played no part in
generating the hypothesis, shipping a live OSV-indexed package again predicts that a
repo's own GitHub advisories are visible to scanners. Together with A2 this is evidence
of a repository-level lever, not a property of one sample. The gap is stark: the median
`no_registry` app has **100%** of its own advisories invisible to an OSV-backed scanner,
while the median `registry` app has about a quarter.

## Per-repository table

See `registry_channel_per_repo.csv` (repo, group, eligible, blind, blind_pct). Notable
clean cases: nocodb and strapi (both `registry`) at 0% blind; discourse, mastodon,
metabase, coolify, outline, requarks/wiki, zulip (all `no_registry`) at 100% blind.

## Limits

Convenience frame of widely-used, advisory-rich self-hosted apps (not a probability
sample); effective N set by which repos publish GitHub repository advisories; one
primary measure; registry status frozen on 2026-10-18 and may change. The two groups
also differ in ecosystem mix (registry apps skew JS/npm-publishing; no_registry skew
Docker-only and non-JS), so "ships to a registry" is a bundle of correlated properties,
not an isolated cause — the claim is about the observable lever, not a controlled experiment.

## Reproduce

```
python app_library_census_html.py --frame-dir . --out-dir out
python registry_channel_analysis.py --csv out/app_library_census.csv \
  --classification registry_classification.json --out-dir out
```
