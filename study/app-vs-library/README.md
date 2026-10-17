# Is the advisory-import gap an application-vs-library effect?

A pre-registered confirmatory study by MV2 of Munim, Inc.

## Why this study exists

An earlier census in this repository found that a large share of GitHub security
advisories for self-hosted AI tools never reach the global database (OSV) that
dependency scanners read, so `npm audit` / Dependabot / `pip-audit` cannot flag
them. A follow-up, pre-registered AI-vs-control study (released as v0.9.0)
**refuted** the idea that this is specific to AI tools: across 30 AI/ML and 30
matched non-AI repositories, AI projects were not more scanner-blind
(repository-level permutation p = 0.30). But a strong exploratory split appeared:
self-hosted **applications** had far more scanner-blind advisories than
**libraries**.

This study tests that split head-on, as a fresh confirmatory experiment, on a
frame that shares **no repositories** with any earlier sample.

The hypothesis, outcome, measure, test and robustness checks were all frozen in
`PREREGISTRATION-app-vs-library.md` (with a dated Amendment 1) **before any
advisory data was collected**. This directory freezes the exact sampling frame
and analysis code before the census is run.

## What is frozen here (pre-census)

| File | What it is |
|---|---|
| `frame_apps.json` | 40 self-hosted applications, ranked by GitHub stars recorded in awesome-selfhosted-data |
| `frame_libs.json` | 40 widely-depended-on libraries, by dependent-repo count across npm, PyPI and Go (ecosyste.ms) |
| `frame_exclude.txt` | 49 repositories used in earlier samples, excluded so this sample is genuinely fresh |
| `frame_used.json` | selection parameters, counts and diagnostics for the frame build |
| `build_frame.py` | builds the frame; selection is blindness- and advisory-independent |
| `app_library_census.py` | the census + pre-registered permutation test (runs after this freeze) |
| `test_frames.py` | offline unit tests for both scripts |

The frame was built by `build_frame.py` in a sealed container on 2026-10-17; its
unit tests passed first. Selection never looks at whether an advisory is visible
to a scanner, so the frame cannot be tuned toward the hypothesis.

**Applications precedence:** any repository the self-hosted catalogue lists is an
application and is never counted as a library, so no repository can appear in both
groups. One candidate (`jupyterlab/jupyterlab`) was moved out of the library pool
for this reason; it is recorded in `frame_used.json`.

## Honest limits of the frame

- The exclude set is the set of distinct repositories that had rows in the
  published census CSV. One earlier project appears under a renamed path
  (`danny-avila/librechat` in the old census vs `LibreChat-AI/LibreChat` in the
  app frame today); it is the same project under a new org, so it is effectively
  re-measured here. This does not bias the application-vs-library comparison
  itself and is listed again in the final write-up.
- Library repositories are chosen by dependent count, applications by stars; the
  two groups are not matched on size or age. Differences could reflect project
  type rather than the app/library distinction alone. The pre-registration states
  this and the permutation test is at the repository level to limit the influence
  of any single advisory-heavy project.

## Reproduce

```
python -m unittest -v                 # offline tests, no network
python build_frame.py --out-dir out   # rebuild the frame (numbers drift over time)
python app_library_census.py --frame-dir . --out-dir out   # run the census
```

License: code Apache-2.0, data CC BY 4.0. This work was made with AI agents
working in the name of MV2 of Munim, Inc.
