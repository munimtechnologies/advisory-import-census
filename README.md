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

## Check your own dependencies: `blindspot.py`

The census measures the gap across a fixed sample. `blindspot.py` turns the same method on
**your** project: it finds the advisories your dependencies' maintainers published that an
OSV-based scanner will not report to you.

```
# a Python project
python blindspot.py -r requirements.txt

# a Node project
python blindspot.py --npm package-lock.json

# ad-hoc, pin a version to filter by affected range
python blindspot.py --package pip:vllm==0.10.1 --package npm:flowise@3.1.3

# a self-hosted app you run from source (no package on a registry)
python blindspot.py --package repo:langgenius/dify@1.4.0

# machine-readable, and a CI gate
python blindspot.py -r requirements.txt --json --fail-on-blind
```

How it works, per dependency:

1. map the package to its GitHub repo (registry metadata, a small built-in map, or
   `--map name=owner/repo`);
2. list that repo's **published** security advisories (public REST API);
3. keep the ones whose affected range covers your version;
4. ask OSV.dev, with the same package and version a scanner would send, whether it reports
   that advisory — by its GHSA ID or its CVE alias.

An advisory that affects you but that OSV does **not** report is a **blind spot**, printed
first. Standard library only, Python 3.8+, public read-only metadata, no install. Set
`GITHUB_TOKEN` in the environment (sent only to `api.github.com`) to raise GitHub's
unauthenticated limit of 60 requests/hour; the tool makes one request per repo.

**A live example you can reproduce.** As of **2026-10-15**, `api.osv.dev/v1/vulns/GHSA-vcwp-f9rq-3887`
returns **404**. That GHSA is a critical Flowise repository advisory (authenticated RCE via a
custom MCP `npx` server) that its maintainers published but that OSV does not carry. So when
you run `blindspot.py` against a `flowise` version this advisory affects, it reports
`GHSA-vcwp-f9rq-3887` as a blind spot: published upstream, but an OSV-based scanner will not
warn you. Re-run it any time; the day the advisory is imported, the tool stops flagging it.

Offline unit tests (GitHub and OSV faked, no network): `python -m unittest -v test_blindspot`.

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

### A method note on OSV IDs (case sensitivity)

If you reproduce the membership test by querying OSV per ID instead of cloning, note that
**OSV.dev advisory IDs are case-sensitive**: `api.osv.dev/v1/vulns/GHSA-39mp-8hj3-5c49`
returns a record, but the upper-cased `GHSA-39MP-8HJ3-5C49` returns 404. Normalising GHSA
IDs to upper case before querying OSV makes every lookup miss and can wrongly report 100%
of advisories as "missing." `blindspot.py` and `census.py` preserve the ID as published.

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
still 404 on OSV at 2026-10-15) and a vLLM Nemotron-VL decompression-bomb DoS
([GHSA-mm38-5g96-7j6x](https://github.com/vllm-project/vllm/security/advisories/GHSA-mm38-5g96-7j6x)) —
both published, both absent from the global database and OSV at snapshot.

## Is the gap special to AI/ML tools?

That is pre-registered and under test. [`PREREGISTRATION-groups.md`](PREREGISTRATION-groups.md)
fixes, before any result, a 30-repository non-AI control group and a repository-level
permutation test, measured the same way as the AI/ML sample (`group_census.py`). The one
published pipeline study and GitHub's own 2026 notes describe a general review backlog, so
whether this gap is AI-specific or ecosystem-wide is genuinely open. Results will be added
when the measurement run completes.

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
- A plain-language write-up of this census is published on DEV:
  [31.6% of security advisories for self-hosted AI tools never reach the database your
  scanner reads](https://dev.to/munimv2/316-of-security-advisories-for-self-hosted-ai-tools-never-reach-the-database-your-scanner-reads-4cfh).
