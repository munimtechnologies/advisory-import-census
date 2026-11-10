# zip GHSA-m665-v7pm-7grj: upgrading to the listed patched version does not turn the fix on

Checked 2026-11-10 against the released source of the `zip` crate (zip-rs/zip2, MIT). Made with AI
agents working for MV2 of Munim, Inc. Text CC BY 4.0. Corrections welcome as an issue in this repository.

## What the advisory record says

GHSA-m665-v7pm-7grj / CVE-2026-115905 ("Zip Cloaking", critical) describes a parser differential.
`ZipArchive` trusts the central directory, while `ZipStreamReader` trusts the local file headers, so one
archive can show different files to a scanner and to a streaming extractor. GitHub's reviewed record
(published to the global database 2026-10-28) lists affected `<= 9.0.4` and patched `9.0.5`. The
record has no "Patches" or "Workarounds" section.

## What 9.0.5 actually does

- The fix, commit 8068ab4 ("Add opt-in header consistency validation to ZipStreamReader ..."), is in
  `v9.0.4...v9.0.5`.
- In `src/read/stream.rs` at v9.0.5, `ZipStreamReader::new` sets `enforce_header_consistency: false`.
  Its doc comment says: "For backward-compatibility, this doesn't check that the local headers match the
  central directory". `extract` runs the comparison only when the flag is set. Master was the same on
  2026-11-10.
- `ZipReadOptions` derives `Default`, so its `enforce_header_consistency` is `false` there too.
  `ZipArchive::by_index`, `by_name` and the other defaults use `ZipReadOptions::new()`. The full check
  runs only through `by_index_with_options` with the flag set, or through an explicit call to
  `ZipArchive::validate_header_consistency()`.
- The maintainers later published two follow-ups. GHSA-5wm9-6g4v-jq7c (critical) and
  GHSA-w577-2rfp-8gph (high) say that in 9.0.5 the opt-in mode itself writes entries before validating
  them and has no rollback; both list 9.1.0 as patched. On 2026-11-10 neither was in GitHub's global
  database or at api.osv.dev, and RustSec had neither.

## What this means for users

Dependabot and osv-scanner treat `zip >= 9.0.5` as not affected by GHSA-m665. A program that streams
untrusted archives with `ZipStreamReader::extract`, or reads them with `ZipArchive` defaults, gets no
header-consistency check after upgrading. Protection needs `zip >= 9.1.0` **and** an explicit
`enforce_header_consistency(true)`, or an explicit `validate_header_consistency()` call.

## Sources

- https://github.com/zip-rs/zip2/security/advisories/GHSA-m665-v7pm-7grj
- https://github.com/advisories/GHSA-m665-v7pm-7grj
- https://github.com/zip-rs/zip2/commit/8068ab480ccf8daa7411424e365fcdbe6d09443e
- https://github.com/zip-rs/zip2/compare/v9.0.4...v9.0.5
- https://github.com/zip-rs/zip2/blob/v9.0.5/src/read/stream.rs
- https://github.com/zip-rs/zip2/security/advisories/GHSA-5wm9-6g4v-jq7c
- https://github.com/zip-rs/zip2/security/advisories/GHSA-w577-2rfp-8gph

This note is part of study S18's background (study/repo-advisory-census-s18/PREREG.md).
