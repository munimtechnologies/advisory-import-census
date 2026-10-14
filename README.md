# The advisory-import gap for self-hosted AI/ML tools

**How many security advisories that AI/ML maintainers publish on GitHub never reach the
global GitHub Advisory Database under their own ID — so Dependabot and `npm/pip audit`
can't warn you — and for how long.**

By MV2 of Munim, Inc. Research and code made with AI agents working in his name; every
headline claim is checked against the linked public pages. Code is Apache-2.0; the dataset
(`out/gra_census.csv`, `out/summary.json`) is CC BY 4.0.

## Why this matters

When a maintainer publishes a GitHub **repository security advisory** (a "GRA", at
`github.com/{owner}/{repo}/security/advisories`), it only protects downstream users if
GitHub also imports it into the **global** GitHub Advisory Database. That global database
is what Dependabot alerts, `npm audit`, `pip-audit`, and OSV scanners read. A GRA that is
published on the repo but never imported into the global database is invisible to every one
of those tools: the fix exists, the advisory exists, but nothing tells users to upgrade.

## What's new here

The most detailed public model of GitHub's advisory-review pipeline
([arXiv:2602.06009](https://arxiv.org/abs/2602.06009)) collects repository advisories
**only** through the global database's `repository_advisory_url` field — so an advisory that
was *never imported* cannot appear in it by construction (its unreviewed set contains zero
repository-advisory-sourced records). We could find no published count of how many
maintainer-published GRAs never reach the global database, nor any measurement focused on
the self-hosted AI/ML ecosystem — which ships fast and is widely self-hosted. As far as we
can find, this is the first such census.

## Headline result (snapshot 2026-10-14)

Across **30** widely used self-hosted AI/ML repositories, **19** had at least one published
repository advisory, for **618** advisories in total:

- **195 of 618 (31.6%)** are **not in the global database under their own GHSA ID** — so
  Dependabot and OSV scanners cannot flag them.
- Of those 195: **90** have **no global presence at all** (no record under any ID), and
  **18** carry a CVE that has only a thin NVD-sourced record under a *different* ID. The
  remaining 87 have no CVE assigned, so there is nothing to cross-reference them by.
- Days a not-imported advisory has been missing (at snapshot): **median 91.1**, **max
  999.7**.
- For contrast, when GitHub *does* review and import a GRA, it is fast: **median 3.2 days**
  from publication to `github_reviewed_at`. The missing ones are not merely "in the queue."

**Seven projects have 100% of their published advisories missing from the global database:**
langgenius/dify (21/21), danny-avila/LibreChat (29/29), Mintplex-Labs/anything-llm (25/25),
oobabooga/text-generation-webui (12/12), infiniflow/ragflow (8/8), comfyanonymous/ComfyUI
(4/4), and feast-dev/feast (1/1). Several of these ship with known, maintainer-acknowledged
vulnerabilities whose advisories a dependency scanner will never surface.

Full per-repo counts are in [`out/summary.json`](out/summary.json); one row per advisory is
in [`out/gra_census.csv`](out/gra_census.csv).

## Method

All data is public, unauthenticated, and read-only metadata. No system is scanned, probed,
or logged into.

1. For each target repo, list the maintainers' **published** repository advisories via the
   public REST endpoint `GET /repos/{owner}/{repo}/security-advisories?state=published`.
2. Build the set of GHSA IDs present in
   [github/advisory-database](https://github.com/github/advisory-database) from a **blobless,
   no-checkout clone** — `git ls-tree` yields every filename (= every GHSA ID) without
   downloading the JSON blobs. This is a direct, authoritative read of the global database
   (386,391 GHSA records at snapshot), not a third-party mirror.
3. A GRA counts as **imported** iff its own GHSA ID is a file in that global set. Absent ones
   are "not imported under their own ID" — exactly the set the arXiv pipeline study cannot
   see.
4. For each absent GRA that carries a CVE, ask the global API whether that CVE has **any**
   global record (usually a thin NVD-sourced one under a different GHSA). This separates "no
   global presence at all" from "covered only under a different record."

The exact commands used in the recorded compute run (see `out/summary.json` provenance):

```
git clone --filter=blob:none --no-checkout --depth 1 \
    https://github.com/github/advisory-database /tmp/advdb
python census.py --advdb /tmp/advdb --out-dir out
```

Unit tests for the pure helpers (no network, no clone): `python -m unittest -v`.

### Independent cross-check with OSV

[OSV.dev](https://osv.dev) is the open mirror of the global GitHub Advisory Database, so a
GHSA that OSV does not know is not in the global database. Every "not imported" ID we spot-
checked by hand returned **404 from both** `https://github.com/advisories/{id}` **and**
`https://api.osv.dev/v1/vulns/{id}`, matching the clone-based result. You can reproduce the
membership test without a clone by querying OSV per ID.

## Spot-checks verified live on 2026-10-14

Each was confirmed 404 at both `github.com/advisories/{id}` and `api.osv.dev/v1/vulns/{id}`:

| GHSA | Project | Severity | Published | Days missing |
|---|---|---|---|---|
| [GHSA-x7x8-95gh-42xm](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-x7x8-95gh-42xm) | FlowiseAI/Flowise | Critical | 2026-08-31 | 44 |
| [GHSA-ccrj-frp2-c945](https://github.com/langgenius/dify/security/advisories/GHSA-ccrj-frp2-c945) | langgenius/dify | High | 2026-08-19 | 56 |
| [GHSA-823j-m4cj-hmjf](https://github.com/vllm-project/vllm/security/advisories/GHSA-823j-m4cj-hmjf) | vllm-project/vllm | High | 2026-10-06 | 8 |

Two further cases anchor the method and sit in the dataset: the critical Flowise
authenticated-RCE via custom MCP `npx` ([GHSA-vcwp-f9rq-3887](https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-vcwp-f9rq-3887),
missing 44 days) and a vLLM Nemotron-VL decompression-bomb DoS
([GHSA-mm38-5g96-7j6x](https://github.com/vllm-project/vllm/security/advisories/GHSA-mm38-5g96-7j6x),
missing 5 days) — both published, both absent from the global database and OSV at snapshot.

## Honest limits

- A **sample** of repos and a single **snapshot** in time; not the whole ecosystem.
- Membership is tested by **GHSA-ID presence** in the global database. This can over-count
  "missing" if an advisory was re-imported under a *different* GHSA ID with the same content;
  the CVE-coverage column bounds that for advisories carrying a CVE (many of these do not).
- Curation lag may be intentional, and advisories can still be imported later. "Missing"
  means "not present under its own ID at snapshot time," not "wrongly withheld." No vendor or
  maintainer is blamed; the gap is a pipeline-coverage measurement.
- Unauthenticated API data only; repos with zero published advisories contribute nothing.

## Dataset schema (`out/gra_census.csv`)

One row per published repository advisory:
`repo, ghsa_id, cve_id, severity, published_at, state, in_global_db, global_path_kind,
github_reviewed_at, days_to_import, days_missing, cve_global_coverage`.

## Related work by MV2

- [self-hosted-ai-security-checklist](https://github.com/munimtechnologies/self-hosted-ai-security-checklist)
  tracks the same Dependabot-blind-advisory problem for this ecosystem.
- Three package-mapping corrections MV2 contributed to github/advisory-database so that
  critical Flowise CVE records become visible to Dependabot: PRs #10347, #10348, #10350.
