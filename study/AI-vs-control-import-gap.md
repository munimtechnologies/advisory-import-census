# Is the advisory-import gap AI-specific? No.

*A pre-registered comparison of 30 AI/ML repositories with 30 matched non-AI
repositories. Made with AI agents working for MV2 of Munim, Inc. Code
Apache-2.0, data CC BY 4.0.*

## Short answer

- **Pre-registered test:** advisories for AI/ML tools are *not* more often
  invisible to OSV-based scanners than advisories for matched non-AI projects.
  Pooled, AI is lower (34.7% vs 56.8%). At the repository level, which is the
  pre-registered unit, the difference is not significant (permutation
  p = 0.30, 49 repositories).
- **Deviation found after the run:** the study script over-counts
  "scanner-blind". It ignores OSV records that GitHub's reviewers fixed up with
  a proper package. Corrected, the shares are **28.0% (AI) vs 46.4%
  (control)**. The conclusion does not change.
- **The pattern that matters is application vs library, not AI vs non-AI**
  (exploratory). Among the non-AI projects, 64% of self-hosted *applications'*
  advisories are missing from OSV, against 2% of *libraries'* advisories.

This corrects the framing of this repo's own headline ("31.6% of advisories for
self-hosted **AI** tools never reach the database your scanner reads"). That
number still reproduces: 29.0% in this run under the same own-ID measure. But
it is not special to AI. It is how self-hosted *applications* publish
advisories.

## The question and the design

Pre-registered before any data was seen: `PREREGISTRATION-groups.md` and
`group_census.py` on `main` (2026-10-15).

- **ai:** the 30 repositories of census v0.1.
- **control:** 30 widely used non-AI repositories, listed as 15 self-hosted
  apps followed by 15 libraries/frameworks.
- **Eligible:** repository security advisories published at least 14 days
  before the snapshot.
- **Primary outcome:** the share that is *scanner-blind*. An advisory counts as
  visible when OSV (`api.osv.dev`, read by osv-scanner, Trivy, Grype and
  others) lists it, by GHSA or CVE, under a package it names. Otherwise it is
  blind.
- **Secondary outcome:** the advisory's own GHSA ID is absent from OSV.
- **Test:** Wilson 95% intervals; a two-sided permutation test of the pooled
  AI − control difference that shuffles group labels across *repositories*
  (10,000 permutations, seed 20261015).

## Result as pre-registered

Snapshot 2026-10-17T00:56:37Z, 2,039 advisories, 0 repository errors, OSV
canary GHSA-39mp-8hj3-5c49 resolved.

| group | repos with eligible advisories | eligible | scanner-blind | own GHSA not in OSV |
|---|---|---|---|---|
| AI/ML | 19 of 30 | 596 | **34.7%** [31.0, 38.6] | 29.0% [25.5, 32.8] |
| control | 30 of 30 | 1,352 | **56.8%** [54.2, 59.4] | 46.4% [43.7, 49.0] |

AI − control, repository-level permutation test: scanner-blind **−22.1
points, p = 0.30**; own GHSA not in OSV −17.3 points, p = 0.55. The difference
has the same sign before and after 2026-05-01 (−21.2, p = 0.50; −18.9,
p = 0.26). Repository medians: 25.4% (AI) vs 22.7% (control).

Eleven of the AI repositories had no eligible advisories: sglang, InvokeAI,
LocalAI, h2ogpt, llama_index, mem0, private-gpt, autogen, crewAI, transformers
and zenml. They publish no repository security advisories. They stay in the
list, as pre-registered, and contribute nothing.

**Reading:** there is no evidence that AI tools are worse. If anything, the
pooled share points the other way. But the repository-level test cannot tell
the groups apart, because the spread *within* each group is much larger than
the difference *between* them. Seven AI repositories and seven control
repositories have every eligible advisory blind, while 3 AI and 10 control
repositories have none blind.

## Deviation: the pre-registered classifier over-counts "blind"

Checking individual rows against OSV after the run showed that
`group_census.py` labels an advisory as blind in two situations where a
scanner *can* see it:

1. **`no_package` while OSV's record names a package.** The script reads the
   *repository* advisory. Many maintainers leave its package field empty. When
   GitHub reviews the advisory into the global database, the reviewer adds the
   package, and OSV mirrors that record. For example, GHSA-7rqg-hjwc-6mjf
   (Grafana) lists no package in the repository but appears in OSV under Go
   `github.com/grafana/grafana`, with fixed versions.
2. **`package_not_in_osv` because of a free-text package name.** Repository
   advisories often name packages loosely or wrongly, such as `go:Traefik`,
   `pip:Home Assistant`, `npm:next.js`, and `npm:open-webui` for a PyPI package.
   The script queries OSV by that name and finds nothing. Yet OSV serves the
   advisory under its own ID with the real package. GHSA-v67p-phpq-fc8x is
   under Go `github.com/traefik/traefik/v3`; GHSA-jgx9-jr5x-mvpv is under PyPI
   `open-webui`.

Affected eligible rows: **40 of 596 (AI) and 141 of 1,352 (control)**. Each
row has `own_id_in_osv = True` but a blind `scanner_class` in the committed CSV.

**Correction (a reported deviation, not pre-registered).** An advisory is
blind only if it is blind as pre-registered *and* its own GHSA record in OSV
names no package. `group_census.py` is left unchanged because it is the
pre-registered instrument. `reclassify.py` applies the correction. It fetches
each disputed OSV record instead of assuming, and re-derives the pre-registered
numbers as a self-check.

| group | scanner-blind, pre-registered | scanner-blind, corrected | corrected, repo median |
|---|---|---|---|
| AI/ML | 34.7% (207/596) | **28.0%** (167/596) [24.6, 31.8] | 12.8% |
| control | 56.8% (768/1,352) | **46.4%** (627/1,352) [43.7, 49.0] | 3.7% |

Corrected AI − control: −18.4 points, repository-level permutation
p = 0.52 (recheck snapshot 2026-10-17T02:54:22Z; its pre-registered
self-check: match). An independent re-run of the whole census two hours later
reproduced every count in this table exactly.

The correction lowers both groups and leaves the conclusion where it was: no
AI-specific gap. It also flips the repository medians, so AI is now *higher*
(12.8% vs 3.7%). That is another sign the AI/non-AI label is not what drives
the gap. The answer depends entirely on whether you weight by advisory or by
repository.

The shipped `blindspot.py` scanner does not have this bug. In package mode it
queries OSV with the *user's* real package name, not the advisory's free text.

## Exploratory: applications vs libraries

This split was not pre-registered, so read it as a hypothesis for a future
pre-registered test. The control list was built as 15 self-hosted apps and 15
libraries/frameworks, which allows a direct look. Corrected definition:

| control subgroup | eligible | blind (corrected) | repo median |
|---|---|---|---|
| self-hosted apps (Discourse, Mastodon, Gitea, Grafana, …) | 962 | **64.4%** [61.4, 67.4] | 38.9% |
| libraries/frameworks (Next.js, Vite, aiohttp, Rails, …) | 390 | **1.8%** [0.9, 3.7] | 0% |

Permutation p (apps vs libraries): 0.0003 (10,000 permutations, 30
repositories, seed 20261015).

The mechanism is mundane. Libraries ship through a registry (npm, PyPI, Go
modules), so their advisories name a package, GitHub reviews them, and OSV
carries them. Applications such as Discourse (297 of 297), Mastodon (57 of 57),
Zulip, Outline and Metabase publish advisories with no package, often for
software installed from Docker images or source. Nothing gets reviewed into the
global database, so no package scanner can match them. The AI group mixes both
kinds. Its fully blind repositories are the self-hosted apps: Dify,
AnythingLLM, LibreChat, RAGFlow, text-generation-webui and ComfyUI.

**Practical takeaway.** If you self-host an application, open-source or not,
assume your dependency scanner will not tell you about that application's own
advisories. Watch its GitHub Security Advisories directly. `blindspot.py
repo:<owner>/<repo>` in this repo does that.

## Reproduce

```
python group_census.py --out-dir out/            # pre-registered census
python reclassify.py --csv out/group_census.csv \
    --census-summary out/summary_groups.json --out-dir out/
```

Data for this write-up: `study/2026-10-17/group_census.csv` (one row per
advisory) and `study/2026-10-17/summary_groups.json`. The corrected figures
above can be checked straight from the CSV. For the AI group, the corrected
blind count equals rows with `own_id_in_osv = False` minus the 6 vLLM rows that
are `scanner_visible` through an alias. For the control group, it equals rows
with `own_id_in_osv = False`.

## Limits

- 60 hand-picked repositories, with a judgment-call control group. Eleven AI
  repositories publish no advisories, so the AI side rests on 19 repositories.
- Pooled shares are dominated by advisory-heavy repositories: Discourse alone
  contributes 297 of the 1,352 control advisories. The repository-level test
  protects against that, at the cost of power. A non-significant result means
  "no large AI-specific effect", not "exactly equal".
- OSV stands in for scanners in general. Dependabot reads GitHub's database
  directly, and some scanners use other feeds.
- One snapshot. Repository advisories change as maintainers edit them.
- The application-vs-library split is exploratory and covers only the control
  group.

*Research, code and write-up produced by AI agents working for MV2 of Munim,
Inc. Corrections welcome as issues on this repo.*
