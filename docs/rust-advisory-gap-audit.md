# Rust advisory-gap audit: what we check, and what it has found

*MV2, Munim, Inc. · mv2@munimtech.com · page licence CC BY 4.0 · first published 2026-11-12, updated 2026-11-12 (about 21:00 UTC)*

Many Rust maintainers publish security advisories on their GitHub repository. Their users' scanners don't
read those advisories directly:

| Scanner | Reads |
|---|---|
| `cargo audit`, `cargo deny` | RustSec (rustsec/advisory-db) |
| Dependabot | GitHub's **reviewed** advisories only |
| `osv-scanner`, OSV-based tools | OSV, which imports RustSec and GitHub-reviewed |

An advisory that only exists as an unreviewed repository advisory is often invisible to all three. This audit
looks for those gaps crate by crate and, with the maintainers' consent where we ask, closes them with RustSec
pull requests. It was carried out by AI agents working for MV2 of Munim, Inc., and every pull request says so.

## Results so far (RustSec pull requests from munimv2)

| Crate | Advisories | Pull request | Outcome |
|---|---|---|---|
| openssl | 1 + 7 (2026) | rustsec/advisory-db#3531, #3533 | merged 2026-11-09 / 11-10: RUSTSEC-2026-0463, -0473 to -0479 |
| cap-primitives | 1 critical (sandbox escape) | #3542 | merged 2026-11-11: RUSTSEC-2026-0482 |
| rustix | 1 (unsound xattr functions) | #3543 | merged 2026-11-11: RUSTSEC-2026-0486 |
| hickory-proto | 5 | #3546 | merged 2026-11-11: RUSTSEC-2026-0487 to -0491 |
| russh | 6 high | #3538 | merged 2026-11-12: RUSTSEC-2026-0492 to -0496, and RUSTSEC-2024-0450 (an advisory dated 2024) |
| hickory-net (+ hickory-proto) | 4 high DNSSEC (+2) | #3548 | merged 2026-11-12: RUSTSEC-2026-0506 to -0509 (+ -0504, -0505) |
| hickory-proto (CVE aliases) | CVE IDs for RUSTSEC-2026-0487 to -0491 | #3557 | merged 2026-11-12 |
| hickory-resolver (+ hickory-recursor) | 4 high (+2) | #3550 | merged 2026-11-12: RUSTSEC-2026-0513 to -0516 (+ -0521, -0522) |
| hickory-net (+ hickory-proto) | 4 moderate (+2) | #3559 | merged 2026-11-12: RUSTSEC-2026-0517 to -0520 (+ -0511, -0512) |

Total merged so far: 39 RustSec advisories, plus CVE aliases added to 5 existing ones. Every merged hickory entry
carries its CVE. The hickory-dns import was agreed with its maintainers first (hickory-dns/hickory-dns#4168), and the
RustSec maintainer asked for the CVE backfill.

Per-crate notes with fix commits and version checks are in [`docs/notes/`](notes/). The hickory CVE map, with the
RustSec ID of every merged entry, is in [`docs/notes/hickory-cve-map-2026-11-12.md`](notes/hickory-cve-map-2026-11-12.md).

## When the maintainers import their own advisories

Sometimes asking works better than filing. On 2026-11-12 we pointed out in GitoxideLabs/gitoxide#3194 that none of
gitoxide's 21 advisories from 2026 was in RustSec. Its maintainer decided to do the import himself and opened
rustsec/advisory-db#3561 the same day (a draft: 66 entries across 35 crates for 26 GHSAs). He also said it "is now a
monthly process". That covers far more than we would have filed, and it will keep up with future releases. When a
project has many missing advisories, we ask first.

## What we check for each crate

1. **Coverage.** Every advisory on the repository's Security tab, compared with RustSec
   (`rustsec.org/packages/<crate>.html`), GitHub's reviewed database (`github.com/advisories/<GHSA>`: 404 means
   unreviewed) and OSV (`api.osv.dev/v1/vulns/<id>`). We also look for a CVE duplicate already in RustSec under
   another ID before calling anything missing.
2. **Fix commit.** Repository advisories rarely link one. We find it by comparing release tags and reading the
   diff, including GitHub's "Merge commit from fork" commits for privately developed fixes. RustSec wants the
   fix commit, PR or issue as the `url`.
3. **Version ranges against the code, not the form.** We list crates.io releases by date around each fix and
   open the source of the boundary releases on docs.rs.
4. **Which crate.** When code moves between crates (for example from hickory-proto to hickory-net), we check each
   crate separately, including crates with no fixed release (`patched = []` with an `unaffected` range).
5. **CVE IDs.** A CVE can be issued weeks after the repository advisory, by a different numbering authority. RustSec's
   automatic ID sync only picks it up when GitHub has reviewed the advisory, so we check OSV's CVE record for the GHSA
   right before filing and add the CVE by hand.
6. **Fresh text.** RustSec descriptions are rewritten from the fix commits, so they can be CC0.

## Kinds of error we have found in published advisory metadata

- **Pre-releases left out.** A range like `< 0.8.2` plus `0.9.0` misses `0.9.0-rc.1` to `rc.4`, which still
  contained the bug (openmls GHSA-gc79). The same happened with tauri's 3.0 alphas, and probably with the
  hickory-net 0.26.0 betas for GHSA-v44v (question open in rustsec/advisory-db#3559).
- **Off by one release.** "Affected `< 0.14.1`, patched `0.14.2`" when the fix landed after the 0.14.1 tag
  (cel GHSA-rjfc). The same pattern appears in cel GHSA-grff and in libp2p-gossipsub GHSA-g3g5 and GHSA-vrx6
  ([libp2p note](notes/libp2p-advisories-2026-11-12.md): seven high-severity 2026 advisories, none in RustSec).
- **No patched version, although a fix had been released** (a rustix advisory).
- **Inconsistent ranges across crates** after a code move (hickory GHSA-2vgh), and a lower bound that predates
  the vulnerable code (hickory-resolver `0.26.0-alpha.1`).
- **A database fix that only reached downstream users.** A critical cap-std sandbox escape was in RustSec only
  as a Wasmtime advisory, so direct cap-std users got no warning until RUSTSEC-2026-0482.
- **CVE issued later, never linked.** VulnCheck issued CVEs for 39 hickory-dns advisories in November 2026; GitHub
  filed each as a new unreviewed advisory instead of adding it to the existing one, so the CVE did not reach RustSec
  on its own.
- **A reviewed record frozen at the release that was newest when it was written.** For 8 uutils coreutils CVEs,
  GitHub's reviewed record says "last affected 0.8.0", but 0.9.0 shipped without the fix. The maintainers' own later
  advisories for the same CVEs say "fixed in 0.10.0", but they did not replace the reviewed records. Another 8
  reviewed records list no patched version at all
  ([uutils note](notes/uutils-advisory-ranges-2026-11-12.md)).

## Check your own crate in five minutes

1. Open `https://github.com/<owner>/<repo>/security/advisories` and list the GHSA IDs.
2. For each one: `https://github.com/advisories/<GHSA>` (404 = Dependabot won't report it) and
   `https://rustsec.org/packages/<crate>.html` (missing = cargo-audit won't report it).
3. For each fix, check that the first release with the fix matches the "patched" field. Then open the release
   just before it on docs.rs and confirm the bug is still there, so you know the range is right.
4. To add missing advisories to RustSec, open a pull request on rustsec/advisory-db with one file per advisory
   under `crates/<crate>/`. Name each file `RUSTSEC-0000-0000.<slug>.md` and set its `url` to the fix commit.
   The [RustSec contributing guide](https://github.com/rustsec/advisory-db/blob/main/CONTRIBUTING.md) has the
   format.

## Want us to look at your crate?

If you maintain a Rust crate or organisation and want this check done, open an issue in this repository or
email mv2@munimtech.com. For open-source crates it is free. You get a short public note like the ones in
[`docs/notes/`](notes/), and RustSec pull requests only if you want them. We don't contact maintainers in bulk.
The work is done by AI agents working for MV2 of Munim, Inc., and every result is checked against the source
before anything is filed.

Licence: this page is CC BY 4.0. The repository's code is Apache-2.0.
