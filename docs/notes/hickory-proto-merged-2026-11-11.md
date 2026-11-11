# hickory-proto: five advisories merged into RustSec (2026-11-11)

Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0. Corrections welcome as an issue in this repository.

## What landed

https://github.com/rustsec/advisory-db/pull/3546 was opened, approved and merged by a RustSec maintainer on 2026-11-11.
RustSec's lint passed the first time. These five hickory-proto advisories were published by the hickory-dns maintainers on
2026-09-03, but until now they were in no scanner database:

| upstream advisory | RustSec ID | issue | affected | fix commit |
|---|---|---|---|---|
| GHSA-hx8c-fjhc-hmf5 (high) | RUSTSEC-2026-0487 | panic on a malformed SVCB/HTTPS `alpn` value in the text parser | 0.20.1 to 0.26.1 | 80eaf9e |
| GHSA-x962-5xwx-fr8x (low) | RUSTSEC-2026-0488 | integer underflow while reporting a malformed TSIG record | 0.26.0 to 0.26.1 | b1246a8 |
| GHSA-wgfr-mphw-j5g4 (high) | RUSTSEC-2026-0489 | panic on an SVCB/HTTPS parameter value that is a lone quote | 0.20.1 to 0.26.1 | c663b60 |
| GHSA-4rph-pmrw-mwpw (high) | RUSTSEC-2026-0490 | zone file lexer panic on a token of 4,096+ characters | 0.24.0 to 0.26.1 | 0494e15 |
| GHSA-67wc-6jq8-ghrc (moderate) | RUSTSEC-2026-0491 | memory amplification from record counts in the message header | 0.18 and later, before 0.26.2 | 280c0e5 |

All five are fixed in hickory-proto 0.26.2. `cargo audit` and `cargo deny` now report them for any lockfile with an
affected hickory-proto, and OSV.dev imports RustSec, so osv-scanner picks them up too.

## Next: hickory-net DNSSEC validation (agreed in the PR thread)

When asked about the next steps in the PR, the RustSec maintainer replied "Sounds good!". The next batch covers the four
high-severity DNSSEC validation advisories for hickory-net, all fixed in hickory-net 0.26.2:

- GHSA-588m-chg6-8jqj: inverted NSEC3 wraparound comparison (fix 87ee4f8)
- GHSA-qw83-5pm2-ggp5: NSEC wraparound detection trusted an unvalidated SOA record (fix e5ca40a)
- GHSA-2vgh-3wfw-qj7c: RRSIG signer name not checked against the RRset's zone (fix 019535e)
- GHSA-p2jv-r3m3-7wf4: NSEC3 owner names not checked against the zone (fix 10840b8, with d2ee774)

It also covers two hickory-proto entries that have no fixed version (588m and p2jv), because the code moved to hickory-net
in 0.26.0-beta.1. These follow the existing RUSTSEC-2026-0118 pattern. The hickory-proto range for 2vgh stays open as a
question for the maintainers: its advisory lists 0.1 to 0.25.0-alpha.3, but its own text says the code moved in 0.26.0.

## Running tally of advisories merged into RustSec from this work

15 advisories: RUSTSEC-2026-0463 and RUSTSEC-2026-0473 to 0479 (rust-openssl), RUSTSEC-2026-0482 (cap-primitives),
RUSTSEC-2026-0486 (rustix), and RUSTSEC-2026-0487 to 0491 (hickory-proto). The six russh advisories in
https://github.com/rustsec/advisory-db/pull/3538 have the crate maintainer's approval. They are being brought in line with
the upstream version bounds, as the RustSec maintainer asked.
