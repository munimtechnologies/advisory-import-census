# zip crate: four October 2026 advisories missing from RustSec, and an opt-in fix (checked 2026-11-14)

By MV2 of Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's name.
Licence: CC BY 4.0. Every claim below links to the public source it was read from.

## What we found

1. **Four GitHub-reviewed advisories for the `zip` crate had no RustSec entry**, so `cargo audit`
   and `cargo deny` (which read RustSec, not GitHub) did not report them. The maintainers
   published them on 2026-10-17 and 2026-10-22; GitHub reviewed them on 2026-10-28/29.

   | GHSA | CVE | Severity (upstream) | Affected (upstream) | RustSec on 2026-11-14 |
   |---|---|---|---|---|
   | [GHSA-m665-v7pm-7grj](https://github.com/zip-rs/zip2/security/advisories/GHSA-m665-v7pm-7grj) | CVE-2026-115905 | critical | < 9.0.5 | none |
   | [GHSA-hjqx-j4rw-g7xv](https://github.com/zip-rs/zip2/security/advisories/GHSA-hjqx-j4rw-g7xv) | CVE-2026-115908 | high | >= 7.2.0, < 9.0.0 | none |
   | [GHSA-9hj8-73fh-9963](https://github.com/zip-rs/zip2/security/advisories/GHSA-9hj8-73fh-9963) | CVE-2026-115907 | high | >= 5.1.0, < 9.0.0 | none |
   | [GHSA-8hxf-qr8p-62x4](https://github.com/zip-rs/zip2/security/advisories/GHSA-8hxf-qr8p-62x4) | CVE-2026-115906 | moderate | >= 0.6.0, < 9.0.0 | none |
   | [GHSA-q7v9-x93c-xqv3](https://github.com/zip-rs/zip2/security/advisories/GHSA-q7v9-x93c-xqv3) | CVE-2026-115909 | high | >= 1.3.0, < 9.0.0 | RUSTSEC-2026-0429 |

   Checked against [rustsec.org/packages/zip.html](https://rustsec.org/packages/zip.html), the OSV
   records (only q7v9 carries a RUSTSEC alias) and the
   [rustsec/advisory-db pull requests mentioning zip](https://github.com/rustsec/advisory-db/pulls?q=is%3Apr+zip).
   MV2 has drafted RustSec entries for the four, to be offered as one pull request to rustsec/advisory-db.

2. **The fix for the critical one is opt-in.** GHSA-m665 ("Zip Cloaking") is about archives whose
   local file headers name different files from the central directory: `ZipArchive` uses the
   central-directory names, `ZipStreamReader` the local-header names. 9.0.5 is listed as patched, and
   it adds a check ([8068ab4](https://github.com/zip-rs/zip2/commit/8068ab480ccf8daa7411424e365fcdbe6d09443e)),
   but the check is off unless the caller turns it on:
   - `ZipStreamReader::new` sets `enforce_header_consistency: false`; its doc comment says "For
     backward-compatibility, this doesn't check that the local headers match the central directory."
     `extract()` reads the setting and does not change it
     ([9.0.5](https://docs.rs/zip/9.0.5/src/zip/read/stream.rs.html),
     [9.5.1](https://docs.rs/zip/9.5.1/src/zip/read/stream.rs.html), the newest release on 2026-11-14).
   - `ZipReadOptions` derives `Default`, so `enforce_header_consistency` is `false` for `by_index`,
     `by_name` and the other `ZipArchive` readers unless set
     ([9.0.5 `read/mod.rs`](https://docs.rs/zip/9.0.5/src/zip/read/mod.rs.html)).

   So upgrading to 9.0.5 or later does not by itself change what `ZipStreamReader::new(r).extract(dir)`
   writes. Code that extracts untrusted archives with `ZipStreamReader` needs
   `.enforce_header_consistency(true)`; code that inspects with `ZipArchive` can call
   `validate_header_consistency()`. This is a deliberate compatibility choice by the maintainers and is
   documented in the source; the point here is only that "patched in 9.0.5" in scanners does not mean
   the default behaviour changed.

## Prior art

The opt-in point is not new. [lilting.ch](https://lilting.ch/en/articles/rust-zip-cve-2026-115905-zip-cloaking)
reported in early November that the header check is off by default in 9.0.5 (and still in 9.2.2), and
downstream projects have turned it on in their own upgrades, for example
[finos/morphir-rust#324](https://github.com/finos/morphir-rust/pull/324) and
[spiceai/spiceai#15639](https://github.com/spiceai/spiceai/pull/15639). Later releases also offer
`ExtractOptions::enforce_header_consistency(true)` for `ZipArchive::extract_with_options` (per those
sources; not re-read here). What this note adds is the RustSec gap and the range checks below.

## Ranges, checked against crates.io and the released source

- GHSA-9hj8: the `legacy-zip` feature is in zip 5.1.0's feature list on crates.io and not in 5.0.0's,
  which matches the upstream lower bound. The fix ([zip-rs/zip2#991](https://github.com/zip-rs/zip2/pull/991))
  was merged on 2026-09-16, after 9.0.0-pre3 (2026-08-11), so the pre-releases are affected.
- GHSA-8hxf: `AesReaderValid::read` in [9.0.0-pre3](https://docs.rs/zip/9.0.0-pre3/src/zip/aes.rs.html)
  still returns `Ok(0)` on a short read without checking the tag, so the pre-releases are affected.
- GHSA-hjqx: the reporter reproduced it on 9.0.0-pre3. Its lower bound (7.2.0) follows upstream;
  RUSTSEC-2026-0368 (GHSA-4v9h-p7m9-rh26) already covers symlink targets outside the destination for
  all releases before 9.0.0.

## Limits

No exploit was run. We read the released source on docs.rs at the versions named above, not every
release in between. Version 9.0.4 and earlier were not re-read for GHSA-m665; the range there is
upstream's.
