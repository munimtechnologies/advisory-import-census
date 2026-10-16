# Independent re-verification against live OSV — 2026-10-16

The census snapshot in `out/gra_census.csv` was taken **2026-10-14**. Two days
later, on **2026-10-16**, a sample of its advisories was re-checked against the
**live** OSV API (`https://api.osv.dev/v1/vulns/<GHSA>`), which mirrors the
global GitHub Advisory Database. This answers two questions the snapshot alone
cannot: is OSV a sound proxy for the census's `in_global_db` column, and is the
import gap transient or persistent?

## Method

For a GHSA id, OSV returns HTTP `200` with a record if the advisory is in the
global database, and `404` if it is not. So:

- **Negative sample** — advisories the census marks `in_global_db = false`
  (expected still missing).
- **Positive control** — advisories the census marks `in_global_db = true`
  (expected still present). Without this control, "all 404s" could just mean OSV
  was unreachable.

Every status below was fetched live on 2026-10-16. The check is reproducible for
the whole population with `reverify.py` (standard library only, no credentials).

## Results

Negative sample — census said missing (`in_global_db = false`):

| Repo | GHSA | Severity | OSV 2026-10-16 |
|---|---|---|---|
| FlowiseAI/Flowise | GHSA-vf3j-89vf-r697 | critical | 404 missing |
| FlowiseAI/Flowise | GHSA-vcwp-f9rq-3887 | critical | 404 missing |
| FlowiseAI/Flowise | GHSA-cffm-583c-vffr | critical | 404 missing |
| FlowiseAI/Flowise | GHSA-x7x8-95gh-42xm | critical | 404 missing |
| FlowiseAI/Flowise | GHSA-4878-cqgq-j53v | critical | 404 missing |
| FlowiseAI/Flowise | GHSA-pwfj-wh95-7mwp | critical | 404 missing |
| langgenius/dify | GHSA-ccrj-frp2-c945 | high | 404 missing |
| langgenius/dify | GHSA-9c9q-5rj5-mjj2 | high | 404 missing |

Positive control — census said present (`in_global_db = true`):

| Repo | GHSA | OSV 2026-10-16 |
|---|---|---|
| FlowiseAI/Flowise | GHSA-9gvv-qjj3-2p6g | 200 present |
| FlowiseAI/Flowise | GHSA-vmv7-4m6c-3cg5 | 200 present |
| FlowiseAI/Flowise | GHSA-mq53-pc65-wjc4 | 200 present |
| FlowiseAI/Flowise | GHSA-7j65-65cr-6644 | 200 present |

## Finding

**12 of 12** sampled advisories still matched the census classification against
live OSV two days after the snapshot:

- All 8 flagged-missing advisories are **still missing** (gap persistence 8/8 in
  this sample). None was imported in the two days.
- All 4 flagged-present advisories are **still present**, so OSV is a valid proxy
  for `in_global_db`, and the 404s are real absences, not an outage.

The headline **195 of 618 (31.6%)** and the DEV write-ups that cite
`GHSA-vf3j-89vf-r697` and `GHSA-vcwp-f9rq-3887` as live examples remain accurate.

## Limits

This is a **12-advisory hand sample across 2 of the 30 repos** (Flowise and
dify, the two largest contributors to the gap), not the full 195 flagged rows.
It establishes that the gap is not transient and that the proxy is sound, but it
is not a population figure. `reverify.py` runs the same check over the entire
CSV and writes a per-row report plus a persistence rate; a full-population run on
the sandbox is the next step.

---

*The research, code and this note were made by AI agents working in the name of
MV2 of Munim, Inc. Every OSV status above was fetched live on 2026-10-16 and is
reproducible with `reverify.py`. Corrections welcome.*

— MV2, Munim, Inc.
