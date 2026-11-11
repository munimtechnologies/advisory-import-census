# Two maintainer-published Rust advisories that no scanner database carries (rustix, cap-primitives)

Checked 2026-11-11 (UTC). Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0.

Both advisories were published by the crates' maintainer as GitHub repository security advisories, and both
fixes are released. On 2026-11-11 neither GHSA ID was in GitHub's global Advisory Database
(`github.com/advisories/<id>` returned 404), in OSV (`api.osv.dev/v1/vulns/<id>` returned 404) or in RustSec
(no `rustix` package page; the `cap-primitives` page lists only the 2024 Windows device-name advisory). So
Dependabot, cargo-audit / cargo-deny and osv-scanner report neither of them.

| Crate | Advisory | Severity (GitHub) | Published | Affected | Fixed in | crates.io downloads, last 90 days |
|---|---|---|---|---|---|---|
| rustix | [GHSA-jh2m-fhpj-3vr7](https://github.com/bytecodealliance/rustix/security/advisories/GHSA-jh2m-fhpj-3vr7) | high (unsoundness) | 2026-10-27 | >= 1.0.0, < 1.1.6 | 1.1.6 ([8e6aaa6](https://github.com/bytecodealliance/rustix/commit/8e6aaa6713d2bb64b1fdd8c472e3a32a10a76d70)) | 355,193,500 |
| cap-primitives (and cap-std) | [GHSA-hp8f-xmx4-4qrg](https://github.com/bytecodealliance/cap-std/security/advisories/GHSA-hp8f-xmx4-4qrg) | critical, CVSS 3.1 9.0 | 2026-08-20 | <= 4.0.2 except 3.4.6 | 3.4.6, 4.0.3 ([#419](https://github.com/bytecodealliance/cap-std/pull/419), [#421](https://github.com/bytecodealliance/cap-std/pull/421)) | 17,810,427 |

## What each one is

- **rustix:** the `getxattr` / `listxattr` families mark as initialized as many bytes as the system call
  reports. With a zero-length buffer the call is a size query that writes nothing, so a full `Vec` passed
  through `spare_capacity` ends up with its length past its capacity over unwritten memory: undefined
  behavior from safe code. 1.1.6 handles the zero-length case and adds `*_query` functions. The GitHub advisory
  still lists no patched version, although the fix commit is in v1.1.5...v1.1.6.
- **cap-primitives:** the resolver re-added a trailing `/` to the last path component before opening it with
  `O_NOFOLLOW`, which makes the OS follow a symlink there, so a symlink inside the sandbox could lead
  outside it (read and write). Affects Windows, macOS, FreeBSD without `O_RESOLVE_BENEATH`, and Linux without
  `openat2`. Wasmtime's advisory for the same bug reached RustSec as RUSTSEC-2026-0269 (filed under
  `wasmtime`), but projects that use cap-std or cap-primitives directly get no warning.

## What we did

One RustSec pull request per crate, with fresh CC0 descriptions, inviting the maintainer to object if they
would rather not have them listed. Links are added to [upstream-outcomes.md](../upstream-outcomes.md) when the
PRs are open. If you depend on these crates: update to rustix 1.1.6 and cap-primitives 3.4.6 / 4.0.3.

## How these were found

Both are rows of study S18 ([results](../../study/repo-advisory-census-s18/RESULTS.md)), which listed every
published repository advisory of 261 Rust repositories and found 332 in no scanner database. rustix's
advisory was published on S18's cutoff day and so was listed but not graded. A prior-art check on
2026-11-11 found that GitHub has already acknowledged its repository-advisory review backlog
([github/advisory-database#10425](https://github.com/github/advisory-database/issues/10425)), so we are not
reporting the backlog itself again; for Rust, RustSec imports reach cargo-audit users regardless of GitHub's
queue.
