# Pre-registration — registry-channel A4: the real-package test

**Study:** registry-channel **A4** — is scanner visibility driven by whether an
advisory's named package is a **real, repo-matching registry release**, rather than
merely by whether the advisory *names* a package at all?

**Registered:** 2026-10-19, by AI agents working for MV2 of Munim, Inc., **before any
A4 data was collected** and **before the A3 collector result was read** (A3 was still
in the shared compute queue at registration time). The frame and the registry
classification are reused verbatim from the already-public A1 study (committed
2026-10-18); the predictions below are registered before the A4 collector is run.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## Background and the question A4 answers

A pre-registered chain already exists:

- **H1 (app-vs-library):** self-hosted *applications* are far more scanner-blind than
  *libraries* (+53.0 pts, p=0.0057).
- **A2 (registry channel, same-sample):** within applications, those that publish
  their own code to an OSV-indexed registry are far *less* blind (−51.5 pts, p=0.0077).
- **A1 (registry channel, out-of-sample):** replicated on 32 fresh applications
  (−58.2 pts, p=0.0017).
- **A3 (attribution):** tests whether *naming a package* on the GitHub advisory page
  mediates the registry effect (launched; result pending at A4 registration).

While validating the A3 parser against the archived A1 pages we found, and recorded
in the A3 pre-registration, that **naming a package is neither confined to registry
apps nor sufficient for visibility.** The decisive case:

| repo | group | advisory | names a package? | scanner-visible? |
|---|---|---|---|---|
| `nocodb/nocodb` | registry | `GHSA-2c5x-4jgf-88mj` | yes — npm `nocodb` | visible |
| `coollabsio/coolify` | no_registry | `GHSA-389w-cc6x-wr2m` | yes — npm `coolify` | **blind** |

Both pages use GitHub's identical `repository_advisory` template and both render a
`Package (npm)` box. A3 can only treat them as the *same* "package" stratum, because
A3 measures attribution **from the page alone.** Yet one is visible and one is blind.
The hypothesised difference is that npm `nocodb` is **nocodb's real, published release
(its registry metadata points back to `nocodb/nocodb`)**, whereas npm `coolify` is
**not Coolify's release** — Coolify ships only via a shell installer / Docker, so the
`coolify` name on npm either does not exist or belongs to someone else. GitHub reviews
an advisory into its global, OSV-indexed database only when it can tie the advisory to
a **real package in a supported ecosystem**; merely typing a package name into the
advisory form does not.

A4 measures that distinction **directly and non-circularly**, from the package
registries' own metadata — a data source entirely independent of the OSV visibility
measure.

## Frame (frozen, reused from A1 — no re-selection)

The identical 32 self-hosted applications in `frame_apps.json`, classified `registry`
(11) vs `no_registry` (21) in `registry_classification.json` (frozen 2026-10-18,
verified against each registry, independent of any advisory data). `frame_libs.json`
is empty. A4 adds **no** repositories and changes **no** group labels.

## Data access

Unauthenticated, read-only. Three public sources:

1. **GitHub advisory pages** (listing + detail HTML), paced one request per 2.5 s,
   archived under `/out/raw` so any parse can be audited by re-parsing, never by
   re-sampling.
2. **The OSV API** (`api.osv.dev/v1/vulns/<id>`) — the visibility measure, scored
   **exactly** as A1/A2/A3 (same `classify`, copied verbatim), with the same OSV
   canary (`GHSA-39mp-8hj3-5c49`), the same 14-day eligibility and period split, the
   same permutation seed (20261017).
3. **Package-registry metadata APIs** (the A4 addition): `registry.npmjs.org`,
   `pypi.org`, `repo.packagist.org`, `rubygems.org`, `crates.io`,
   `proxy.golang.org`, paced one request per 1.0 s. Read-only JSON/HEAD; no account,
   no writes.

## New measured variable: the real-package probe

For each eligible advisory whose page names ≥1 affected package in a registry
ecosystem (the A3 `package` product type), the collector parses each named
`(ecosystem, package-name)` coordinate from the archived HTML
(`named_packages`, matching the bold package-name span that precedes the ecosystem
link), then queries that registry's own metadata and records, per advisory, a
`named_pkg_resolution`:

- **`yes`** — at least one named package **exists** on its registry **and** its
  registry source/homepage metadata points back to the advisory's **own GitHub repo**
  (owner/repo match, case-insensitive). → the real, repo-matching release.
- **`no_match`** — a named package exists on the registry but **none** point to the
  advisory's repo (e.g. an unrelated package that happens to share the name).
- **`absent`** — named packages were checked and **none exist** on the registry.
- **`unchecked`** — only ecosystems the probe does not support were named (Maven,
  NuGet, …); never guessed, and excluded from the tests.

These collapse to the pre-registered binary stratum `real_package`:

- **`real`** — a `package`-type advisory with `named_pkg_resolution == yes`;
- **`not_real`** — a `software`-type advisory (no named package) **or** a
  `package`-type advisory whose named package is `no_match` / `absent`;
- **`other`** — `product_type == other`, or an `unchecked` ecosystem. **Excluded**
  from every test (as A3 excluded `other`). A run with >15% `other` among
  `package`-type advisories is treated as a probe failure and reported as such.

The probe touches **only** registry metadata; no visibility measure uses it. The raw
resolution detail (status, resolved repos) is written to the CSV for audit.

## Hypotheses and pre-registered predictions

Let **visible** = `scanner_class == scanner_visible`.

**P1 — real-package status predicts visibility, within apps (primary test).**
Restricting to repositories that contain **both** ≥1 `real` and ≥1 `not_real`
eligible advisory, the pooled `visible(real) − visible(not_real)` difference is
**positive and ≥ +40 points**, and a **within-repository label-permutation test**
(`real_package` labels permuted independently within each such repository, 10,000
permutations, seed 20261017) gives **p < 0.05**.

**P2 — registry status drives real-package status (first stage).** Registry apps'
advisories are `real` far more often than no_registry apps'. Repository-level
permutation test (A1 machinery; outcome = is-`real`; groups registry vs no_registry):
difference **> 0** and **p < 0.05**.

**P3 — real-package status mediates the registry→visibility effect, and does so
*more completely* than A3's naming did.** With total effect = pooled
`visible(registry) − visible(no_registry)` over the support, and direct effect =
the `real_package`-stratified combination of within-stratum registry−no_registry
visible-rate differences (stratum-size weighted), the **mediated fraction
`(total − direct)/total` is ≥ 0.50** and **|direct| < |total|**. Secondary (the A4
claim): this mediated fraction is **≥ A3's attribution mediated fraction** on the same
frame, because the `real`/`not_real` split separates real releases from merely-named
ones (the coolify case) that A3's `package` stratum lumps together.

**P4 — residual slack (descriptive).** Even among `real` advisories visibility is
**< 100%** (GitHub→OSV import lag / unsupported-ecosystem residual), and among
`not_real` advisories visibility is **> 0% but small** (CVE-alias rescue). Reported
with k/n; no threshold pre-registered for P4.

## Robustness (pre-specified)

- **R1:** drop the most advisory-heavy repository in each registry group; P2 keeps
  sign and p < 0.05.
- **R2:** ecosystem confound — report visibility among `real` advisories split by
  ecosystem (npm / PyPI / Packagist / RubyGems / crates.io / Go) to show the
  mechanism is not an artefact of one ecosystem.
- **R3:** secondary measure `own_id_not_in_osv` reproduces P1's sign.
- **Probe audit:** the `named_pkg_resolution` breakdown (yes / no_match / absent /
  unchecked counts and their visible-rate) is reported, so the coolify-style
  `no_match` and `absent` cases are visible and checkable against the archive.

## Interpretation (registered before the run)

The decisive quantity is the **`package`-type advisories that resolve `no_match` or
`absent`** (named but not a real repo release) and **their visible rate**:

- If the real-package refinement is right, these should be **mostly blind** (like
  coolify), they should be concentrated in `no_registry` apps, and moving them out of
  the "package" stratum and into `not_real` should make the mediation **more complete
  than A3's** (P3 secondary holds). The honest conclusion would then be: *"it is not
  whether the advisory names a package — Docker-only apps name packages too — but
  whether that package is a real registry release GitHub reviews into its global
  database."*
- If instead `no_match`/`absent` advisories are **also often visible**, or the
  mediated fraction is **not** larger than A3's, then real-package status is **not**
  the mechanism beyond naming, and A4 is reported as a **null refinement** — still a
  genuine, publishable result that bounds what the registry covariate is doing.

## What would falsify the real-package hypothesis

P1 null (real and not_real advisories equally visible within apps), **or** P3
mediated fraction < 0.50, **or** P3 secondary failing (A4 mediation not ≥ A3's).
Any of these means the real-package property does not explain the registry effect
beyond mere naming; A4 is then written up honestly as a null.

## Outputs

`real_package_census.csv` (one row per eligible advisory, with named packages,
`named_pkg_resolution` and `real_package`), `real_package_summary.json` (P1–P4,
robustness, resolution breakdown, per-repo), `real_package_census_meta.json` (canary,
counts, unreadable repos) and the archived `raw/` HTML. RESULTS.md is written next run
from these outputs, honestly, whichever way they fall.

## Note on sequencing

A4 is pre-registered now, while A3 is still queued, so that this document provably
precedes both results. A4 will **not** be launched as a compute job until A3's result
has been collected and its RESULTS.md written, to avoid holding two large collector
slots in the shared queue at once. Launching A4 before reading A3 would not change
these predictions (they are fixed here), but reading A3 first lets A4's RESULTS.md
report the A3-vs-A4 mediation comparison P3 calls for.
