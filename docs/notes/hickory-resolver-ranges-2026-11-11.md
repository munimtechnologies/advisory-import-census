# hickory import status, and two recursor version ranges that look misplaced (2026-11-11)

Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0. Corrections welcome as an issue in this repository.

## Status of the hickory-dns import into RustSec

Background: hickory-dns published 38 security advisories on 2026-09-03 and none had reached RustSec
(see `hickory-2026-09-03-advisories.md`). The RustSec maintainer agreed to a step-by-step import in
https://github.com/rustsec/advisory-db/pull/3546.

| step | pull request | advisories | state on 2026-11-11 ~18:00 UTC |
|---|---|---|---|
| hickory-proto | rustsec/advisory-db#3546 | 5 (3 high) | merged: RUSTSEC-2026-0487 to 0491 |
| hickory-net, DNSSEC validation | rustsec/advisory-db#3548 | 4 high + 2 hickory-proto entries with no fixed release | lint passed, approved by the maintainer, not yet merged |
| hickory-resolver | being sent next | 4 high + 2 hickory-recursor entries with no fixed release | files ready (see below) |
| remaining moderate and low | later | about 25 | commit map prepared |

## Finding: the recursor advisories point at a resolver release that has no recursor

Two of the high-severity advisories concern the recursive resolver:

- GHSA-cx5j-p54p-q756: the recursor kept querying cyclic glueless sibling delegations (fix 308dcfd).
- GHSA-6h5c-jjg5-wj59: the recursor chased every glueless name server in a referral, with no per-request
  query budget, the NXNSAttack pattern (fixes 74062f3, at most 5 glueless name servers per delegation, and
  47cd005, at most 200 upstream queries per client request).

Both advisories give hickory-resolver as affected from **0.26.0-alpha.1** and hickory-recursor as affected
from 0.25.0-alpha.3 to **0.25.2**, with no fixed hickory-recursor release. The released source on docs.rs
says otherwise:

- hickory-resolver 0.26.0-alpha.1 has no `src/recursor/` folder. Its `src/` holds `dns_lru/`,
  `name_server/`, `system_conf/` and flat files. `src/recursor/` first appears in hickory-resolver
  **0.26.0-beta.1**.
- hickory-recursor **0.26.0-alpha.1** (2025-06-03, its last release) still ships the recursor
  (`recursor.rs`, `recursor_dns_handle.rs`, `recursor_pool.rs`). The fixes landed in 2026 in
  `crates/resolver/src/recursor/`, so that release has no fix either.

So the published ranges probably have "0.26.0-alpha.1" on the wrong crate. Read literally, they flag a
hickory-resolver release that cannot contain the bug, and they miss the last hickory-recursor release, which
does. The RustSec files prepared for these two advisories therefore use:

- hickory-resolver: `patched = [">= 0.26.2"]`, `unaffected = ["< 0.26.0-beta.1"]`
- hickory-recursor: `patched = []`, `unaffected = ["< 0.25.0-alpha.3"]` (no upper bound, so 0.26.0-alpha.1 is included)

The pull request states this plainly and offers to match upstream exactly if the maintainers prefer.

The other two resolver advisories match their upstream ranges. GHSA-5j98-2g5x-46v6 (`lookup()` returned `Ok`
for DNSSEC-bogus answers, fix 30720f4) affects all versions. GHSA-6w6g-hm98-mhgm (unbounded retries on
truncated responses, fix f9a7bc5) affects 0.26.0-beta.1 to 0.26.1, which matches `name_server_pool.rs`
first appearing in 0.26.0-beta.1.

## Limits

- This is a reading of released source trees and fix commits. Nothing was run.
- Only the maintainers can say which range they meant. The same "0.26.0-alpha.1" question may apply to
  other recursor advisories in the batch (9px7, 2hxp, 4jwp, 29q9, vcjp). Each will be checked the same way
  before it is filed.
- Lesson recorded earlier in this repository still holds: maintainer advisory metadata can be wrong in
  small ways (rustix "patched: none", the hickory-proto range in GHSA-2vgh). Check the source tree of the
  boundary releases before copying a range.
