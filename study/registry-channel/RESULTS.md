# Result: within self-hosted applications, the advisory-import gap is a *registry-channel* effect (supported)

**Project:** advisory-import-census (MV2 of Munim, Inc.)
**Snapshotted:** 2026-10-18, after the pre-registered permutation test was run in a sealed sandbox.
**Made with AI agents working for MV2 of Munim, Inc.** Apache-2.0 (code) / CC BY 4.0 (text & data).

This write-up reports the outcome of the test frozen in
[`PREREGISTRATION-registry-channel.md`](PREREGISTRATION-registry-channel.md).
The hypothesis, the covariate rule, the per-repository classification, the
analysis code and the three predictions were all committed
([`58b49df`](https://github.com/munimtechnologies/advisory-import-census/commit/58b49df21e5e610de8222245afde5ce0fa614aa6))
**before** the test was run. Nothing below was changed after seeing the result.

## Background

The confirmed application-vs-library census
([`study/app-vs-library/RESULTS.md`](../app-vs-library/RESULTS.md), committed at
`141a3ade`) established **H1**: self-hosted **applications** are far more
*scanner-blind* than **libraries** — 53.0% of eligible application advisories name
no package in OSV (so a dependency scanner reading OSV cannot match them) versus
0% for libraries (+53.0 points, repository-level permutation **p = 0.0057**).

That write-up also recorded an **exploratory observation** (obs #2): *within*
applications, the visible repos looked like the ones that also ship a package to a
public registry (gogs, payload, copyparty, …), while the ~100%-blind ones looked
like the Docker-only apps (Immich, paperless-ngx, Plane, …). Obs #2 was generated
*from* the data and never tested. **H2** turns it into a falsifiable test.

## Hypothesis (H2, registry channel)

Among application repositories that have eligible advisories, those whose project
publishes its own application code to a public language registry OSV indexes have a
**lower** repository-level blind rate than those distributed only as Docker images
/ binaries / source.

## What was done

- **Input (no re-collection):** the 909 eligible application advisories across the
  **27** application repositories in `app_library_census.csv` committed at
  `141a3ade`.
- **Covariate (frozen before the test):** each repo classified `registry` /
  `no_registry` by a crisp, objective rule — an **official** package carrying the
  app's **own** code, on a registry OSV indexes, as a **live channel** (for Go, a
  **tagged** semantic version, not a pseudo-version). 19 of 27 were individually
  verified against the registry by fetch on 2026-10-18; the rest from documented
  Docker-only distribution. Result: **12 `registry`, 15 `no_registry`**. The full
  per-repo basis is in [`registry_classification.json`](registry_classification.json).
- **Test:** the census's **own** repository-level permutation test, copied
  verbatim (pooled blind rate per group, labels permuted across repositories, seed
  20261017, 10,000 permutations, two-sided). Statistic =
  `blind%(registry) − blind%(no_registry)`.
- **Where:** executed in the sealed MV2-Compete sandbox, which downloaded the
  pinned CSV from `raw.githubusercontent.com/...141a3ade/...`. Offline unit tests
  (`test_registry_channel.py`) passed first (`python -m unittest`, exit 0).

## Result

All 27 repositories were classified (`classification_covers_all: true`; 27
classified == 27 with advisories).

| Group | Repos | Eligible advisories | Scanner-blind | Pooled blind rate (95% CI) | Repo-median blind |
|---|---:|---:|---:|---:|---:|
| `registry` | 12 | 413 | 103 | **24.9%** (21.0–29.3%) | **4.8%** |
| `no_registry` | 15 | 496 | 379 | **76.4%** (72.5–79.9%) | **100.0%** |

- **Primary (P1):** `registry − no_registry` = **−51.5 percentage points**,
  two-sided **p = 0.0077** (27 repositories, repository-level permutation). The
  difference is negative and p < 0.05. **P1 is met.**
- **Secondary:** the same test on `own_id_not_in_osv` gives the identical −51.5
  points, p = 0.0077 (for these repos, "names no package" and "own GHSA id absent
  from OSV" coincide).
- **Repo-median (P2):** 4.8% (`registry`) vs 100.0% (`no_registry`) — lower in
  `registry`. **P2 is met.**
- **Robustness (P3):** dropping the most advisory-heavy repo in **each** group
  (`n8n-io/n8n`, `siyuan-note/siyuan`) leaves the sign unchanged and strengthens
  it: **−75.0 points, p = 0.0001** (25 repositories). **P3 is met.**

**All three pre-registered predictions are met. H2 is supported on this sample.**

### The counter-signals we flagged in advance held up

- `n8n-io/n8n` (`registry`) is itself 27.6%-blind (58 of 210) — a registry repo
  that is still partly blind. It did not sink the effect, but it is why `registry`
  pools at 24.9% rather than near 0%.
- `laurent22/joplin` (`registry`, npm) is 93.8% blind (30 of 32): its advisories
  concern the desktop/mobile app, not the published `joplin` CLI package, so
  shipping *a* package did not make *those* advisories matchable. This is the
  honest boundary of the mechanism (see Limitations).
- On the other side, `siyuan-note/siyuan` (`no_registry`) is only 49.5% blind
  (107 of 216) — the least-blind `no_registry` repo — which is why the robustness
  drop *raised* the gap.

Per-repo numbers are in [`registry_channel_per_repo.csv`](results/registry_channel_per_repo.csv);
full output in [`registry_channel_summary.json`](results/registry_channel_summary.json).

## What this means

For these 27 widely-used self-hosted applications, **whether a project ships an
official, live package to a registry OSV indexes is strongly associated with
whether its own security advisories are machine-matchable by a dependency
scanner.** Docker-only / binary-only apps are almost entirely invisible to OSV-
reading scanners (repo-median 100% blind); apps with a live registry package are
mostly visible (repo-median 4.8% blind).

- **If you self-host**, this says the same thing H1 did, more sharply: for an app
  distributed only as a Docker image or binary, do **not** rely on Dependabot /
  `npm audit` / `pip-audit` to tell you about the app's *own* advisories — watch
  its advisory page (or GitHub releases) directly.
- **If you maintain a self-hosted app**, publishing an official package to the
  registry for your ecosystem — and naming it in your GHSA advisories — is a
  concrete, low-cost lever that is associated with your advisories reaching
  scanners. (joplin shows this is necessary but not automatic: the *advisory*
  still has to name the package that is actually affected.)

## Honest limitations (unchanged from the pre-registration)

- **Same sample.** This reuses the exact 27 repositories that generated obs #2, so
  it is **confirmatory-of-mechanism on the generating sample, not an independent
  replication.** The strong, pre-specified test is a *new* application frame
  (different repos), which is the planned next step. Treat the effect size as an
  upper-ish estimate until replicated.
- **Association, not proof of cause.** `registry`/`no_registry` co-varies with
  other things (ecosystem, project age, maturity of the security process). We show
  the covariate predicts the gap; we do not prove publishing a package *causes*
  visibility.
- **The package must match the advisory.** joplin and n8n show that shipping a
  package is **not sufficient** per-advisory: visibility also needs the advisory to
  name the affected package. So the lever is "publish *and* attribute", not
  "publish".
- **Low power / imbalance.** 12 vs 15 repositories, unit = repository.
- **OSV as a scanner proxy**, single snapshot, two correlated measures reported
  (primary is `blind`). AI-made; no independent human review yet.

## Reproduce

```
python registry_channel_analysis.py \
  --csv app_library_census.csv \
  --classification registry_classification.json \
  --out-dir out
```
(`app_library_census.csv` = the file committed at `141a3ade`; seed 20261017 is
baked in.) Outputs `registry_channel_summary.json` and
`registry_channel_per_repo.csv`, reproduced here under `results/`.

---

*Made with AI agents working for MV2 of Munim, Inc. Questions: mv2@munimtech.com.
Code Apache-2.0, text & data CC BY 4.0.*
