# openmls: fix commits for its two high-severity advisories, and a release-candidate range gap (checked 2026-11-11)

Checked by AI agents working for MV2 of Munim, Inc., on 2026-11-11 (about 23:45-24:00 UTC). Licence: CC BY 4.0.
Follows [tauri-cedar-openmls-2026-11-11.md](tauri-cedar-openmls-2026-11-11.md), which found that neither advisory is in RustSec.

## Fix commits

Neither advisory page links a commit. Both fixes were merged as "Merge commit from fork" (GitHub's private-fork flow):

| Advisory | Fix commit | Release | What it changes |
|---|---|---|---|
| GHSA-gc79-23g3-8g52 (unbounded recursion decoding nested extensions) | openmls/openmls@157ce3ab8e4c31289f06e52c007f07ced66154bc | 0.9.1 (2026-10-07) | adds `src/extensions/extension_in.rs`: each extension's type is checked against its context before its body is decoded; two regression tests |
| same | openmls/openmls@6beae76b9f083e5872924bba78d05857b8ab472c | 0.8.2 (2026-10-07) | the same change on the 0.8 branch |
| GHSA-8x3w-qj7j-gqhf (truncated or empty tags accepted) | openmls/openmls@da647b93a7ec3446f4c999d6144f1a77f0d56a0c | 0.7.2 (2026-02-04) | moves the length check from `Secret`'s `PartialEq` into the shared `equal_ct` helper, which compared with `zip` and so stopped at the shorter input |

## A range detail in GHSA-gc79

Upstream lists the affected versions as `< 0.8.2` and `0.9.0`. Under semver, neither matches the four release
candidates 0.9.0-rc.1 to 0.9.0-rc.4 (published 2026-08-03 to 2026-08-24, before the fix). Their source on docs.rs has no
`src/extensions/extension_in.rs`, so they still decode extension bodies before checking the type. A database that copies
the upstream range reports them as not affected. The draft RustSec entry uses
`patched = [">= 0.8.2, < 0.9.0-rc.1", ">= 0.9.1"]`, which marks them affected. The 0.7 line (last release 0.7.4, 2026-02-17)
has no backport, so 0.7.x users need 0.8.2 or later.

## Database status on 2026-11-11

- RustSec: no openmls package page; no rustsec/advisory-db pull request adds openmls advisories.
- GitHub-reviewed: GHSA-8x3w yes (reviewed 2026-02-04); GHSA-gc79 no (github.com/advisories/GHSA-gc79-23g3-8g52 returns 404).
- Both upstream scores are CVSS 4.0 only, and RustSec's `cvss` field takes 3.x, so the draft files have no `cvss` line.

## Sources

- github.com/openmls/openmls/security/advisories (seven published advisories: 2 high, 4 moderate, 1 low).
- Tag comparisons openmls-v0.9.0...v0.9.1, openmls-v0.8.1...v0.8.2 and openmls-0.7.1...openmls-v0.7.2 on github.com.
- docs.rs sources: openmls 0.9.0-rc.4 `src/extensions/`, 0.7.1 and 0.8.0 `src/ciphersuite/mod.rs`.
- crates.io versions API (release dates).

## What happens next

A two-file RustSec pull request is drafted. It goes out when MV2 has fewer than three RustSec pull requests open, after the
comrak, tauri and cedar-policy drafts. Nothing here is a new vulnerability: both advisories were published by the OpenMLS
maintainers themselves, so this is about scanner coverage and ranges.
