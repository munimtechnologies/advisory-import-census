# Pre-registration — registry-channel A3: the attribution mechanism

**Study:** registry-channel **A3** — does *package attribution on the GitHub
advisory page* mediate the registry-channel effect on scanner visibility?

**Registered:** 2026-10-18, by AI agents working for MV2 of Munim, Inc., **before
any A3 advisory data was collected.** The frame and the registry classification are
reused verbatim from the already-public A1 study (committed 2026-10-18); the
predictions below are registered before the A3 collector is run.

Apache-2.0 (code) / CC BY 4.0 (text & data).

## Background and the question A3 answers

Three earlier pre-registered results established and replicated a mechanism:

- **H1 (app-vs-library):** self-hosted *applications* are far more "scanner-blind"
  (their published security advisories carry no package that an OSV-based scanner
  can match) than *libraries* (+53.0 pts, p=0.0057).
- **A2 (registry channel, same-sample):** within applications, those that publish
  their own code to an OSV-indexed package registry are far *less* blind than
  Docker/binary-only apps (−51.5 pts, p=0.0077).
- **A1 (registry channel, out-of-sample):** replicated on 32 fresh applications
  sharing no repository with the earlier samples (−58.2 pts, p=0.0017).

A1/A2 establish **that** the registry covariate predicts visibility, but not the
**mechanism**. The hypothesised mechanism is *attribution*: an advisory becomes
visible to scanners only when GitHub reviews it into a global, package-scoped
record, and GitHub only does that when the advisory **names an affected package in
a supported registry ecosystem**. On github.com this is directly observable: a
reviewed, package-scoped advisory renders a **"Package"** section with an ecosystem
link (e.g. `ecosystem:npm`), whereas a repository-level advisory renders a
**"Software"** section with a generic product name and **no** ecosystem link.

A3 tests whether this **Package-vs-Software attribution mediates the registry
effect**: registry apps are less blind *because* their advisories name a package,
and a registry app's advisory that still names no package should be just as blind
as a Docker-only app's advisory.

## Frame (frozen, reused from A1 — no re-selection)

The identical 32 self-hosted applications in `frame_apps.json`, classified
`registry` (11) vs `no_registry` (21) in `registry_classification.json`
(frozen 2026-10-18, verified against each package registry, independent of any
advisory data). `frame_libs.json` is empty (applications only). A3 adds **no**
repositories and changes **no** group labels.

## Data access (identical route to A1)

Unauthenticated, read-only GitHub advisory pages + the OSV API, paced one request
every 2.5 s, for open-access research. Every fetched page is archived under
`/out/raw` so the parse can be audited by re-parsing, never by re-sampling. The
visibility measure (`scanner_blind`, `own_id_in_osv`) is scored **exactly** as in
A1/A2 (same code, copied verbatim). A1's result (−58.2 pts) is the reference; A3's
own visibility gap is re-measured on this fresh snapshot and reported alongside it.

## New measured variable: advisory product type (the attribution)

For each eligible advisory, parsed deterministically from its archived detail HTML:

- **`package`** — the page contains at least one affected-package coordinate in a
  registry ecosystem, detected by an `…/advisories?query=ecosystem%3A<name>` link
  inside the advisory's affected-products box. (The ecosystem name(s) are also
  recorded, for the ecosystem robustness check.)
- **`software`** — the page has an affected-products box (a "Software" or "Package"
  header with a product name) but **no** ecosystem coordinate link.
- **`other`** — neither is detectable (parse ambiguity). Reported and **excluded**
  from the attribution tests; a run with >10% `other` is treated as a parse failure.

Eligibility (published, ≥14 days old), the period split, the OSV canary, the
permutation seed (20261017) and the robustness rules are unchanged from A1.

### Transparency note (added 2026-10-18 during parser validation, BEFORE the full A3 run)

While validating the parser against the already-archived A1 detail pages, we found
that **naming a package is not confined to registry apps, and does not guarantee
visibility.** Example: `coollabsio/coolify` (classified `no_registry`, ~100% blind
in A1) advisory `GHSA-389w-cc6x-wr2m` renders a `Package` box naming npm `coolify`,
yet is scanner-blind. Both the blind coolify page and the visible nocodb page use
GitHub's identical `repository_advisory` template with a `Package`/`ecosystem:npm`
link; we found **no** on-page marker that distinguishes a reviewed (OSV-indexed)
advisory from an unreviewed one. We also saw that some `no_registry` apps name
packages often (appsmith, coolify — both JS) while others never do (discourse,
ClickHouse). We record this **before** running A3 so the result is honest either way.
Our updated expectation is therefore that P2/P3 may come back **null** — i.e. on-page
attribution does *not* account for the registry effect — which would itself be the
novel finding (see Interpretation). The predictions below are left as originally
written (what the attribution hypothesis predicts); the data decides.

## Hypotheses and pre-registered predictions

Let **visible** = `scanner_class == scanner_visible` (the complement of blind).

**P1 — attribution predicts visibility, within apps (primary mechanism test).**
Restricting to repositories that contain **both** ≥1 `package`-type and ≥1
`software`-type eligible advisory (i.e. apps where attribution varies internally),
the pooled visible-rate difference `visible(package) − visible(software)` is
**positive and ≥ +40 points**, and a **within-repository label-permutation test**
(product-type labels permuted independently within each such repository, 10,000
permutations, seed 20261017) gives **p < 0.05**.

**P2 — registry status drives attribution (first stage).** Registry apps' advisories
are `package`-type far more often than no_registry apps'. Repository-level
permutation test (A1 machinery; outcome = is-`package`; groups = registry vs
no_registry): difference **> 0** and **p < 0.05**.

**P3 — attribution mediates the registry→visibility effect.**
With the total effect = pooled `visible(registry) − visible(no_registry)`, and the
direct (attribution-adjusted) effect = the product-type-stratified combination of
the within-stratum registry−no_registry visible-rate differences (weighted by
stratum size), the **mediated fraction `(total − direct)/total` is ≥ 0.50** and
**|direct| < |total|**. I.e. conditioning on whether the advisory names a package
removes at least half of the registry gap.

**P4 — residual slack (descriptive, the novel quantities).** Even among
`package`-type advisories, visibility is **< 100%** (the GitHub→OSV import-lag /
unsupported-ecosystem residual), and among `software`-type advisories visibility is
**> 0% but small** (the CVE-alias rescue residual). Both residuals are reported with
k/n; no threshold is pre-registered for P4.

## Robustness (pre-specified)

- **R1:** drop the most advisory-heavy repository in each registry group; P2 keeps
  sign and p < 0.05.
- **R2:** ecosystem confound — report the attribution and visibility rates split by
  ecosystem (npm / PyPI / Packagist / Go / other) to show the mechanism is not an
  artefact of one ecosystem.
- **R3:** secondary measure `own_id_not_in_osv` reproduces P1's sign.

## Interpretation (registered before the run)

The decisive quantity is the **visible rate within the `package` stratum, split by
registry group** (reported by P3's strata detail):

- If on-page attribution is the mechanism, then **within advisories that name a
  package**, registry and no_registry apps should be *equally* visible (naming is
  all that matters), so P3's `package`-stratum registry−no_registry difference ≈ 0
  and the mediated fraction is large (≥ 0.50).
- If instead the registry covariate matters **beyond** naming — i.e. what counts is
  whether the named package is a *real, reviewed* registry release — then **within
  the `package` stratum**, registry apps stay far more visible than no_registry apps
  (whose named packages, like coolify's, are unreviewed), the mediated fraction is
  small, and P2/P3 come back null. In that case the honest conclusion is: *"it is not
  whether the advisory names a package — Docker-only apps name packages too — but
  whether that package is a real registry release GitHub reviews into its global
  database."* This refines the mechanism the playbook speculated about.

Either outcome is a genuine, publishable result.

## What would falsify the attribution hypothesis

If P1 is null (package and software advisories are equally visible within apps), or
if P3's mediated fraction is < 0.50 (attribution does not account for the registry
gap), the on-page-attribution mechanism is **not** supported and A3 is reported as a
null, with the P3 `package`-stratum split used to state the sharper mechanism above.
A clean null is a publishable result.

## Outputs

`attribution_census.csv` (one row per eligible advisory, with product type and
ecosystems), `attribution_summary.json` (P1–P4, robustness, per-repo), and the
archived `raw/` HTML. RESULTS.md is written next run from these outputs, honestly,
whichever way they fall.
