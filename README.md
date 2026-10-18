# The advisory-import gap for self-hosted AI/ML tools

**How many security advisories that AI/ML maintainers publish on GitHub never reach the
global GitHub Advisory Database under their own ID — so Dependabot and `npm/pip audit`
can't warn you — and for how long.**

By MV2 of Munim, Inc. Research and code made with AI agents working in his name; every
headline claim is checked against the linked public pages. Code is Apache-2.0; the dataset
(`out/gra_census.csv`, `out/summary.json`) is CC BY 4.0.

> **Update (v0.9.0): the gap is not AI-specific.** A pre-registered comparison with 30
> matched non-AI repositories found AI/ML advisories are *not* more often invisible to
> OSV-based scanners (repository-level permutation p = 0.30). The pattern that matters looks
> like **self-hosted applications vs libraries** (exploratory: 64% vs 2% blind). The 31.6%
> below still reproduces; read it as a property of self-hosted applications, not of AI.
>
> **Update (2026-10-18): the application-vs-library split is confirmed.** A pre-registered
> census of 40 fresh applications and 40 libraries found 53.0% of application advisories
> scanner-blind against 0 of 11 for libraries (repository-level permutation p = 0.0057).
> Results and limits: [`study/app-vs-library/RESULTS.md`](study/app-vs-library/RESULTS.md).
> Details: [Is the gap special to AI/ML tools?](#is-the-gap-special-to-aiml-tools-no) and
> [`study/AI-vs-control-import-gap.md`](study/AI-vs-control-import-gap.md).

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

### Per-repo coverage, with the date it was pulled

The 31.6% is one moment for one sample, and each project moves on its own (an import or a
new advisory changes its row), so each per-repo figure carries the time it was pulled.
Quote a row with its date. (A reader of the DEV write-up suggested dating figures per repo;
this table is that change.) The other 11 of the 30 surveyed repos had no published
repository advisories at the snapshot.

| Repo | Published advisories | Not in global DB under own GHSA | Share missing | Pulled (UTC) |
|---|---:|---:|---:|---|
| open-webui/open-webui | 165 | 21 | 12.7% | 2026-10-14 14:01 |
| FlowiseAI/Flowise | 130 | 28 | 21.5% | 2026-10-14 14:01 |
| vllm-project/vllm | 104 | 35 | 33.7% | 2026-10-14 14:01 |
| langflow-ai/langflow | 37 | 4 | 10.8% | 2026-10-14 14:01 |
| danny-avila/LibreChat | 29 | 29 | 100% | 2026-10-14 14:01 |
| gradio-app/gradio | 29 | 1 | 3.4% | 2026-10-14 14:01 |
| Mintplex-Labs/anything-llm | 25 | 25 | 100% | 2026-10-14 14:01 |
| langgenius/dify | 21 | 21 | 100% | 2026-10-14 14:01 |
| BerriAI/litellm | 17 | 3 | 17.6% | 2026-10-14 14:01 |
| oobabooga/text-generation-webui | 12 | 12 | 100% | 2026-10-14 14:01 |
| bentoml/BentoML | 11 | 0 | 0% | 2026-10-14 14:01 |
| mlflow/mlflow | 10 | 3 | 30.0% | 2026-10-14 14:01 |
| langchain-ai/langchain | 9 | 0 | 0% | 2026-10-14 14:01 |
| infiniflow/ragflow | 8 | 8 | 100% | 2026-10-14 14:01 |
| comfyanonymous/ComfyUI | 4 | 4 | 100% | 2026-10-14 14:01 |
| ray-project/ray | 4 | 0 | 0% | 2026-10-14 14:01 |
| deepset-ai/haystack | 1 | 0 | 0% | 2026-10-14 14:01 |
| xorbitsai/inference | 1 | 0 | 0% | 2026-10-14 14:01 |
| feast-dev/feast | 1 | 1 | 100% | 2026-10-14 14:01 |
| **All 19** | **618** | **195** | **31.6%** | 2026-10-14 14:01 |

To see where one project stands today, run `python blindspot.py --package repo:OWNER/REPO`
— it lists that repo's published advisories and which of them OSV serves right now.

## Check your own dependencies: `blindspot.py`

The census measures the gap across a fixed sample. `blindspot.py` turns the same method on
**your** project: it finds the advisories your dependencies' maintainers published that an
OSV-based scanner will not report to you.

```
# best: a lock file, so every direct and transitive dependency is checked
# at its exact version (see "Lock files" below for the formats)
python blindspot.py --lock uv.lock
python blindspot.py --lock package-lock.json
python blindspot.py --lock go.mod            # Go modules (also go.sum)

# a Python project (hashed `pip-compile --generate-hashes` output is fine)
python blindspot.py -r requirements.txt

# a Python project that declares its dependencies in pyproject.toml
# (PEP 621 [project] or legacy Poetry; needs Python 3.11+ for the stdlib
#  tomllib, or `pip install tomli` on older Python)
python blindspot.py --pyproject pyproject.toml

# a Node project's package.json (ranges like ^1.2.0 check every version)
python blindspot.py --npm package.json

# ad-hoc, pin a version to filter by affected range
python blindspot.py --package pip:vllm==0.10.1 --package npm:flowise@3.1.3

# a Go module (mapped to its repo by its own path; no registry lookup)
python blindspot.py --package go:github.com/gin-gonic/gin@v1.9.1

# a self-hosted app you run from source (no package on a registry)
python blindspot.py --package repo:langgenius/dify@1.4.0

# machine-readable, and a CI gate
python blindspot.py --lock uv.lock --json --fail-on-blind

# accept a known blind spot without turning the gate off
python blindspot.py --lock uv.lock --fail-on-blind \
  --ignore GHSA-xxxx-xxxx-xxxx --ignore-file blindspot-ignore.txt

# also write the blind spots as SARIF 2.1.0, for GitHub code scanning
python blindspot.py --lock uv.lock --sarif blindspot.sarif
```

Installed from this repo (`pip install .`), the same tool is also the `advisory-blindspot`
console command, with identical flags.

How it works, per dependency:

1. map the package to its GitHub repo (registry metadata, a small built-in map,
   `--map name=owner/repo`, or — for a Go module — its own path, by the verified rules in
   [`docs/go-vanity-coverage.md`](docs/go-vanity-coverage.md));
2. list that repo's **published** security advisories (public REST API);
3. keep the ones whose affected range covers your version;
4. ask OSV.dev, with the same package and version a scanner would send, whether it reports
   that advisory — by its GHSA ID or its CVE alias.

An advisory that affects you but that OSV does **not** report is a **blind spot**, printed
first. Standard library only, Python 3.9+ (reading a `pyproject.toml` or a TOML lock file
needs Python 3.11+ for the stdlib `tomllib`, or the `tomli` backport), public read-only
metadata, no install. Set `GITHUB_TOKEN` in the environment (sent only to `api.github.com`)
to raise GitHub's unauthenticated limit of 60 requests/hour; the tool makes one request per
repo.

### Lock files (`--lock`)

A manifest with ranges (`flask>=2`, `^1.2.0`) can't say which version you run, so every
advisory for that package is listed as *range unclear*; and a manifest names only your
**direct** dependencies. A lock file gives the exact version of every package you install,
transitive ones included, so each advisory is matched against the version you actually
ship. `--lock` (repeatable) recognises the file by its name:

| File | Ecosystem | Notes |
|---|---|---|
| `uv.lock`, `poetry.lock` | PyPI | the project itself and local `directory`/`editable` packages are left out |
| `pylock.toml`, `pylock.NAME.toml` | PyPI | [PEP 751](https://peps.python.org/pep-0751/); packages with no `version` are left out |
| `Pipfile.lock` | PyPI | `default` and `develop`; path/VCS entries with no `==` version are left out |
| `package-lock.json`, `npm-shrinkwrap.json` | npm | lockfile v1, v2 and v3 |
| `yarn.lock` | npm | classic (v1) and Berry (v2+); `npm:` aliases count as the real package; workspace, link, file and patch entries are left out |
| `pnpm-lock.yaml` | npm | lockfile v5, v6 and v9 (the `packages:` map; peer suffixes dropped); read line by line, no YAML library |
| `go.mod`, `go.sum` | Go | `go.mod` reads the `require` directives (direct and `// indirect`) at their selected versions; `go.sum` lists every version in the build graph. Each module maps to its repo **by its own path**, with no registry call: `github.com/*`, `gopkg.in/*`, and the verified vanity hosts listed in [`docs/go-vanity-coverage.md`](docs/go-vanity-coverage.md) (`golang.org/x`, `k8s.io`, `cloud.google.com/go`, `google.golang.org/grpc`, OpenTelemetry, etcd, …) |

**Big lock files and GitHub's rate limit.** Each distinct GitHub repo behind your
dependencies costs one API request. Without a token the limit is 60 an hour; the workflow
token in GitHub Actions allows 1,000 an hour per repository
([GitHub docs](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api)).
If the limit is reached, blindspot stops asking GitHub and reports the remaining repos as
**not checked** (`unchecked_repos` in the JSON, an *Incomplete* warning in the text and job
summary). `--fail-on-blind` then fails, because a check that could not see everything must
not pass the gate. Re-run after the hourly reset.

**Correction (0.7.0).** Earlier versions read a hashed requirements file
(`pip-compile --generate-hashes`, `uv pip compile --generate-hashes`) as if nothing was
pinned: the `\` line continuation hid the `==` pin, so every advisory for those packages was
reported as *range unclear* instead of being matched to your version. 0.7.0 joins
continuation lines and drops per-requirement options such as `--hash`, so the pin is kept.

### Accepting a known blind spot (`--ignore`)

Some blind spots you can't fix today: there may be no patched version yet, or you have
reviewed the advisory and accepted the risk. Rather than turn `--fail-on-blind` off for
everything, accept that advisory by id and keep the gate on for the rest:

- `--ignore GHSA-...` (repeatable) accepts one advisory, matched by its **GHSA or CVE id**,
  case-insensitively.
- `--ignore-file PATH` reads a file of ids, one per line (blank lines and `#` comments are
  skipped, so you can note *why* each is accepted).

An accepted advisory is still listed — under **Accepted blind spots** — but it is not counted
in `blind_spots`, does not fail `--fail-on-blind`, and is left out of the SARIF output, so no
code scanning alert is raised for a gap you have chosen to accept. The JSON report adds an
`ignored` flag per finding and an `ignored_blind_spots` total. Accept by id, not by package,
so a *new* advisory on the same dependency still trips the gate.

**A live example you can reproduce.** As of **2026-10-15**, `api.osv.dev/v1/vulns/GHSA-vcwp-f9rq-3887`
returns **404**. That GHSA is a critical Flowise repository advisory (authenticated RCE via a
custom MCP `npx` server) that its maintainers published but that OSV does not carry. So when
you run `blindspot.py` against a `flowise` version this advisory affects, it reports
`GHSA-vcwp-f9rq-3887` as a blind spot: published upstream, but an OSV-based scanner will not
warn you. Re-run it any time; the day the advisory is imported, the tool stops flagging it.

Offline unit tests (GitHub and OSV faked, no network): `python -m unittest -v test_blindspot`.

## Run it in CI: the GitHub Action

This repository is also a composite GitHub Action, so you can gate pull requests on the same
check without installing anything (`blindspot.py` is standard-library only). Add
`.github/workflows/blindspot.yml` to your project
([full example](examples/blindspot-ci.yml)):

```yaml
permissions:
  contents: read
jobs:
  blindspot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: munimtechnologies/advisory-import-census@v0.9.9
        with:
          lock: uv.lock          # or package-lock.json, yarn.lock, pnpm-lock.yaml, go.mod, ...
          # requirements: requirements.txt
          # pyproject: pyproject.toml
          fail-on-blind: "true"
```

Pin a release tag (as above) or a commit SHA. Releases from v0.9.1 on add the Go vanity
module mappings described in [`docs/go-vanity-coverage.md`](docs/go-vanity-coverage.md); the
Action's inputs have not changed since v0.8.0, so an older pin keeps working.

Inputs: `lock`, `requirements`, `npm`, `pyproject`, and `packages` (any whitespace-separated
list, matching the CLI's `--lock`, `-r`, `--npm`, `--pyproject`, and `--package`); `map` for
`NAME=OWNER/REPO` overrides; `ignore` (whitespace- or newline-separated advisory ids to accept
as known blind spots, matching the CLI's `--ignore`); `fail-on-blind` (default `true`) to fail
the job when a blind spot is found or the check was incomplete; `sarif` to also write a SARIF
file (below); and `github-token` (defaults to the workflow token, only sent to
`api.github.com`). The runner's `python3` is 3.11+, so `pyproject` files and TOML lock files
are read with the standard-library `tomllib` and no install. Every run writes a Markdown table
to the **job summary**: an *Incomplete* warning if the rate limit was reached, blind spots
first, then any accepted blind spots, then a collapsed list of advisories OSV does report. A
weekly `schedule:` trigger is worth adding — an advisory can be published upstream *after* you
merged a dependency, and the gap has a median life of 91 days, so a one-off check goes stale.

Offline unit tests for the summary renderer: `python -m unittest -v test_action_summary`.

### Blind spots as code scanning alerts (SARIF)

Set the `sarif` input and upload the file with `github/codeql-action/upload-sarif`, and each
blind spot becomes an alert in your repository's **Security** tab
([full example](examples/blindspot-code-scanning.yml)):

```yaml
permissions:
  contents: read
  security-events: write
jobs:
  blindspot:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: munimtechnologies/advisory-import-census@v0.9.9
        with:
          lock: package-lock.json
          sarif: blindspot.sarif
          fail-on-blind: "false"
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: blindspot.sarif
          category: advisory-blindspot
```

- **Where the alert points.** Each alert sits on the line of your manifest or lock file that
  declares the dependency. `packages` specs have no manifest, so their alerts point at the
  workflow file that lists them (the CLI's `--sarif-anchor FILE` does the same by hand).
- **What is in it.** One rule per advisory, carrying its GHSA ID, summary, affected and
  patched ranges, and a link to the maintainers' advisory. GitHub's critical / high / medium /
  low comes from the advisory's own severity (`security-severity` 9.5 / 8.0 / 5.5 / 2.0).
  Advisories that OSV *does* report are left out, because an OSV-based scanner already alerts
  on them; advisories accepted with `ignore` are left out too.
- **When it closes.** Fingerprints are stable per advisory, package, version and manifest, so
  an alert stays one alert across runs. A run with no blind spots still uploads an empty
  result set, so an alert closes by itself once the advisory reaches OSV, you upgrade past
  the affected range, or you accept it with `ignore`.
- Code scanning is free for public repositories; private repositories need GitHub Code
  Security.

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
(The `--ignore` list is matched case-insensitively against the advisory id — that comparison
is local and never a key into OSV, so it is safe to accept `ghsa-...` or `GHSA-...` either way.)

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

## Is the gap special to AI/ML tools? No.

This was pre-registered before any data was seen
([`PREREGISTRATION-groups.md`](PREREGISTRATION-groups.md), `group_census.py`): the 30 AI/ML
repositories above against 30 widely used non-AI repositories (15 self-hosted apps, 15
libraries/frameworks), measured the same way, with a repository-level permutation test. The
full write-up, data and a reported classifier correction are in
[`study/AI-vs-control-import-gap.md`](study/AI-vs-control-import-gap.md) (release v0.9.0).

| group | eligible advisories | scanner-blind, pre-registered | scanner-blind, corrected |
|---|---:|---:|---:|
| AI/ML (19 of 30 repos publish advisories) | 596 | 34.7% | 28.0% |
| non-AI control (30 of 30) | 1,352 | 56.8% | 46.4% |

- **AI tools are not worse.** AI − control is −22.1 points pooled, permutation p = 0.30
  (corrected: −18.4 points, p = 0.52). The spread *within* each group is far larger than the
  difference *between* them.
- **Exploratory, not pre-registered:** within the non-AI group, **self-hosted applications'**
  advisories are 64.4% blind against **1.8%** for libraries (p = 0.0003). Libraries ship
  through a registry, so their advisories name a package and get reviewed into the global
  database; applications installed from Docker images or source often publish advisories
  with no package, which no package scanner can match. The AI group's fully blind repos
  (Dify, AnythingLLM, LibreChat, RAGFlow, text-generation-webui, ComfyUI) are all
  self-hosted applications.
- **Confirmed (2026-10-18).** A pre-registered application-vs-library census of a fresh,
  frozen frame (40 self-hosted applications, 40 most-depended-on libraries, no repository
  reused from earlier samples) found **53.0%** of 909 application advisories scanner-blind
  against **0 of 11** library advisories: +53.0 points, repository-level permutation
  **p = 0.0057** (32 repos), so H1 is supported. It holds after dropping the heaviest repo in
  each group (p = 0.02); within each publication period alone it points the same way but is
  not significant (library side: 5 and 1 repos). Exploratory: part of the application figure
  is review lag on recent advisories, yet 36.8% of application advisories 90+ days old are
  still blind, and apps whose advisories name a registry package (gogs, Payload, copyparty)
  are mostly visible. Full write-up, limits and data:
  [`study/app-vs-library/RESULTS.md`](study/app-vs-library/RESULTS.md).

**Practical takeaway:** if you self-host an application, open-source or not, don't expect
your dependency scanner to tell you about that application's own advisories. Watch them
directly: `python blindspot.py --package repo:OWNER/REPO`.

## Honest limits

- A **sample** of repos and a single **snapshot** in time; not the whole ecosystem.
- Membership is tested by **GHSA-ID presence** in the global database. This can over-count
  "missing" if an advisory was re-imported under a *different* GHSA ID with the same content;
  the CVE-coverage column bounds that for advisories carrying a CVE (many of these do not).
- Curation lag may be intentional, and advisories can still be imported later. "Missing"
  means "not present under its own ID at snapshot time," not "wrongly withheld." No vendor or
  maintainer is blamed; the gap is a pipeline-coverage measurement.
- Unauthenticated API data only; repos with zero published advisories contribute nothing.
- `blindspot.py` finds a package's repo from PyPI / npm metadata, or, for a Go module, from
  its own path. A `replace` directive in `go.mod` is not followed. Go modules on
  `github.com`, `gopkg.in` and the vanity hosts verified in
  [`docs/go-vanity-coverage.md`](docs/go-vanity-coverage.md) are mapped; any other host is
  reported as unmapped rather than guessed (map it with `--map`). Lock files for other
  ecosystems (Cargo, Composer, ...) are not read yet; use `--package` with `--map`.

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
