---
name: rust-advisory-range-check
description: Check whether a Rust security advisory's affected-version ranges (RUSTSEC, GHSA or CVE id, or an OSV/GitHub advisory JSON draft) match the versions crates.io actually published. Use it when reviewing, writing or importing a Rust advisory, when a range starts at a stable version that had pre-releases, or when a maintainer-only GHSA uses free-text ranges. Flags unpublished bounds, pre-releases left out of a range, unpublished fixes and missing RustSec entries.
license: Apache-2.0
metadata:
  author: MV2 of Munim, Inc. (mv2@munimtech.com)
  version: "0.1.0"
---

# Rust advisory range check

`scripts/advisory_range_check.py` compares an advisory's affected ranges with the version list
crates.io has published. It needs Python 3.8+ and nothing else (standard library only), plus
network access to api.osv.dev, crates.io and api.github.com.

## When to use it

- Before filing or reviewing a RustSec advisory (`crates/<name>/RUSTSEC-0000-0000.md`) or a
  GitHub Advisory Database change for a crates.io package.
- When an advisory's range starts at a stable version such as `>= 0.26.0` and the crate shipped
  `0.26.0-alpha.*` or `-beta.*` releases first. Under SemVer those pre-releases sort *below*
  `0.26.0`, so the range silently treats them as safe.
- When a GHSA was published only in the project's repository (not yet reviewed by GitHub, so
  OSV and `api.github.com/advisories` return 404). Its ranges are free text like
  `0.25.0 .. 0.26.1`; pass `--repo owner/name` to read it.

## How to run it

```sh
python scripts/advisory_range_check.py RUSTSEC-2026-0514
python scripts/advisory_range_check.py GHSA-29q9-p769-j8gq --repo hickory-dns/hickory-dns
python scripts/advisory_range_check.py CVE-2026-41678 --json
python scripts/advisory_range_check.py --file draft-osv.json
```

Exit code 1 means at least one R1, R2, R5 or R6 finding (so it can gate CI); 0 means none.

## Reading the findings

| Code | Meaning | What to do |
|---|---|---|
| R1 | A bound names a version crates.io never published | Use the real first affected release (often a pre-release) |
| R2 | A stable lower bound leaves out published pre-releases of it | Read the fix commit, then the pre-release's source; widen the range only if the vulnerable code is there |
| R3 | The fixed version isn't on crates.io yet | Wait for the release, or say "no fix published" |
| R4 | Pre-releases of the fix version are counted as affected | Fine if the fix landed after them; check the tag |
| R5 | A range matches no published version | Probably a typo or wrong package |
| R6 | Free-text range not understood | Read it by hand |
| R7 | No RustSec advisory for the crate names this GHSA/CVE | It may still need importing into RustSec |

**Every finding is a candidate, not a verdict.** Before you propose a range change, confirm it
against the released source (docs.rs or the git tag at both sides of the boundary) and check
that the bug's precondition exists in that release, not just the changed line. Do not file
corrections in bulk; send one well-checked change at a time to the advisory's maintainers.

## Limits

- crates.io only. Uses today's version lists; yanked versions count as not live.
- `a .. b` spans are read as inclusive at both ends.
- crates.io is queried at one request per second (its crawler policy); GitHub allows 60
  unauthenticated requests per hour.

Made with AI agents working for MV2 of Munim, Inc. Source and tests:
https://github.com/munimtechnologies/advisory-import-census/tree/main/tools/range-check
(Apache-2.0).
