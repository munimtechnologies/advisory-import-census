# russh: 21 GitHub-reviewed advisories with no RustSec entry, including Terrapin (checked 2026-11-14)

By MV2 of Munim, Inc. (mv2@munimtech.com). Made with AI agents working in MV2's name.
Licence: CC BY 4.0. Every claim below links to the public source it was read from.

## What we found

[russh](https://crates.io/crates/russh) is the most widely used pure-Rust SSH library. Its maintainer
publishes security advisories on GitHub ([31 so far](https://github.com/Eugeny/russh/security/advisories)),
and GitHub reviews most of them into its advisory database. `cargo audit` and `cargo deny` read
[RustSec](https://rustsec.org/packages/russh.html) instead, which on 2026-11-14 has 7 russh entries
(the [`crates/russh/` folder](https://github.com/rustsec/advisory-db/tree/main/crates/russh)):
RUSTSEC-2026-0154 (GHSA-g9f8), and the six high-severity advisories MV2 added in
[rustsec/advisory-db#3538](https://github.com/rustsec/advisory-db/pull/3538)
(RUSTSEC-2024-0450 and RUSTSEC-2026-0492..0496).

**21 GitHub-reviewed russh advisories have no RustSec entry.** Rust projects that rely on `cargo audit`
or `cargo deny` alone are not warned about any of them, whatever russh version they pin. The oldest is
[GHSA-cqvm-j2r2-hwpg](https://github.com/Eugeny/russh/security/advisories/GHSA-cqvm-j2r2-hwpg)
(CVE-2023-28113, March 2023). The best known is the
[Terrapin attack](https://terrapin-attack.com) (CVE-2023-48795,
[GHSA-45x7-px36-x8w8](https://github.com/Eugeny/russh/security/advisories/GHSA-45x7-px36-x8w8)),
fixed in russh 0.40.2 in December 2023: its [OSV record](https://api.osv.dev/v1/vulns/GHSA-45x7-px36-x8w8)
lists russh with no RUSTSEC alias, and no RustSec issue or pull request mentions it
([issues](https://github.com/rustsec/advisory-db/issues?q=CVE-2023-48795),
[PRs](https://github.com/rustsec/advisory-db/pulls?q=is%3Apr+terrapin)).

| GHSA | CVE | Severity (upstream) | Fixed in | Group |
|---|---|---|---|---|
| GHSA-cqvm-j2r2-hwpg (DH public values not checked) | CVE-2023-28113 | moderate | 0.36.2, 0.37.1 | A |
| GHSA-45x7-px36-x8w8 (Terrapin) | CVE-2023-48795 | moderate | 0.40.2 | A |
| GHSA-h5rc-j5f5-3gcm (window adjust overflow) | CVE-2025-54804 | moderate | 0.54.1 | A |
| GHSA-hpv4-5h6f-wqr3 (auth state kept across user change) | CVE-2026-46705 | moderate | 0.61.0 | A |
| GHSA-g9g7-5cgw-6v28 (keyboard-interactive prompt count) | CVE-2026-48107 | moderate | 0.61.0 | A |
| GHSA-76r6-x97p-67vr (lines before client identification) | CVE-2026-48108 | moderate | 0.61.0 | A |
| GHSA-cqjc-rmpq-xprq, GHSA-5xvq-cp9x-6p6r, GHSA-g9hv-x236-4qp3 | CVE-2026-73489, -73430, -73429 | moderate | 0.62.4 | B |
| GHSA-m65r-rprj-r5rg, GHSA-g6xm-f9xp-qq35, GHSA-w3jg-pjxf-73p4, GHSA-p8qx-h547-fjw9, GHSA-35g8-35p8-c8fw | | moderate / low | not yet checked | B |
| GHSA-j7h2-66j4-ghjf, GHSA-4wc5-f2rc-q74m, GHSA-fw5c-8223-6h42, GHSA-4p9f-7p9m-5vfg, GHSA-9wfm-jcj8-jfv9, GHSA-9264-jvgf-6w2f, GHSA-736f-c93q-9fwx | | moderate / low | not yet checked | C |

Group B and C rows list only the IDs; their CVEs and fixed versions will be checked one by one before
they are offered. The sibling crate [`pageant`](https://crates.io/crates/pageant) has two more
GitHub-reviewed advisories with no RustSec entry
([GHSA-g4mp-vgx3-xrvm](https://api.osv.dev/v1/vulns/GHSA-g4mp-vgx3-xrvm),
[GHSA-662x-8wvj-2276](https://api.osv.dev/v1/vulns/GHSA-662x-8wvj-2276)).
[GHSA-3hm4-p7h4-rvwp](https://github.com/Eugeny/russh/security/advisories/GHSA-3hm4-p7h4-rvwp)
(high, root cause in `ssh-key`) is not in GitHub's reviewed database on 2026-11-14 (OSV returns 404),
so it is not counted.

## How it was checked

- The list of advisories: the four pages of
  [Eugeny/russh/security/advisories](https://github.com/Eugeny/russh/security/advisories).
- Reviewed or not: `https://api.osv.dev/v1/vulns/<GHSA>` (a 404 means GitHub has not reviewed it),
  and the [OSV list for russh](https://osv.dev/list?q=russh&ecosystem=crates.io).
- Covered or not: a RUSTSEC alias in the OSV record, the files in `crates/russh/`, and
  [rustsec/advisory-db pull requests mentioning russh](https://github.com/rustsec/advisory-db/pulls?q=is%3Apr+russh).

## Group A, checked against the fix commits and crates.io

MV2 has drafted RustSec entries for group A, to be offered as one pull request to rustsec/advisory-db,
as #3538 was. For each one the fix commit was read:

| GHSA | Fix commit | What it does |
|---|---|---|
| 45x7 | [a355c62](https://github.com/Eugeny/russh/commit/a355c62d11352cf93c3f9fda7499e03753a938ae) | strict kex (`kex-strict-*-v00@openssh.com`), sequence-number reset after `NEWKEYS` |
| cqvm | [45d2d82](https://github.com/Eugeny/russh/commit/45d2d82930bf4a675bd57abfafec8fe4065befcd) | private exponent drawn in range; `1 < x < p-1` checks on both public values and the shared secret |
| h5rc | [0eb5e40](https://github.com/Eugeny/russh/commit/0eb5e406780890e21ff71dd25d731b30676478e5) | `saturating_add` on the channel send window, client and server |
| hpv4 | [b14354e](https://github.com/Eugeny/russh/commit/b14354e819a7c984cf9013e77d728f8611c88aae) | binds auth state to the (user, service) pair and resets it on change, with a regression test |
| g9g7 | [311f6cf](https://github.com/Eugeny/russh/commit/311f6cf129016d5edc8db474a29062b0e1d69889) | bounds the prompt count by the packet's remaining length before allocating |
| 76r6 | [22295fa](https://github.com/Eugeny/russh/commit/22295fa5056d25f3f19f8e56e88772dca496ccb2) | strict server-side reader for the client identification line; 255-byte lines, at most 20 pre-banner lines |

The [0.61.0 release notes](https://github.com/Eugeny/russh/releases/tag/v0.61.0) name hpv4, g9g7 and 76r6
but no commits; the three "Merge commit from fork" commits above were matched to them by their diffs.

Version bounds, against the [crates.io version list](https://crates.io/api/v1/crates/russh/versions):
- cqvm: fixed in 0.36.2 and 0.37.1; the only 0.37.0 release, 0.37.0-beta.1, was yanked on 2023-03-20
  (as were 0.36.0 and 0.36.1).
- g9g7: upstream starts the range at 0.37.0. The client in
  [0.36.2](https://github.com/Eugeny/russh/blob/v0.36.2/russh/src/client/encrypted.rs) has no
  keyboard-interactive support; [0.37.1](https://github.com/Eugeny/russh/blob/v0.37.1/russh/src/client/encrypted.rs)
  has it and passes the server's count to `Vec::with_capacity` unchecked.
- h5rc: in builds without overflow checks the addition wraps instead of panicking; the advisory's impact
  (a panic) applies where overflow checks are on.

A side check on an entry already merged: RUSTSEC-2026-0494 (GHSA-4r3c, name-list bounds) points at
[72b250a](https://github.com/Eugeny/russh/commit/72b250aa2dacb3bb1b13a84499c09bd9fc836158). The bounded
decoder (`MAX_NAME_LIST_BYTES = 16 * 1024`, `MAX_NAME_LIST_ENTRIES = 1024`) is in `russh/src/helpers.rs`
at [v0.61.0](https://github.com/Eugeny/russh/blob/v0.61.0/russh/src/helpers.rs) and not at the commit before it on main,
[fc6e3ab](https://github.com/Eugeny/russh/blob/fc6e3ab4cd4338e94ae64e17aeed2acee9335e6b/russh/src/helpers.rs),
and none of the three later fork merges touches that file, so the link is right.

## Limits

No exploit was run. Group B and C were only checked for coverage, not for ranges. We searched for prior
reports of the Terrapin gap in RustSec and found none, but we cannot rule out a discussion elsewhere.
