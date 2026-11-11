# RustSec outcomes, 2026-11-11: rustix and cap-primitives merged, hickory-dns import started

Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0. Corrections welcome as an issue in this repository.

## Merged the same day they were opened

| advisory | crate | RustSec ID | pull request |
|---|---|---|---|
| GHSA-hp8f-xmx4-4qrg (critical, trailing-slash sandbox escape) | cap-primitives | RUSTSEC-2026-0482 | https://github.com/rustsec/advisory-db/pull/3542 |
| GHSA-jh2m-fhpj-3vr7 (unsound xattr buffer handling) | rustix | RUSTSEC-2026-0486 | https://github.com/rustsec/advisory-db/pull/3543 |

Both were advisories that the crates' own maintainer had published, with released fixes, but that were in no scanner
database (see [rustix-cap-primitives-2026-11-11.md](rustix-cap-primitives-2026-11-11.md)). Both PRs passed RustSec's lint the
first time, and a RustSec maintainer approved and merged each within hours. `cargo audit` and `cargo deny` now warn
projects whose lockfile has cap-primitives below 3.4.6 (or 4.0.0 to 4.0.2) or rustix 1.0.0 to 1.1.5.

## hickory-dns: the maintainers said yes

In https://github.com/hickory-dns/hickory-dns/issues/4168 (see [hickory-2026-09-03-advisories.md](hickory-2026-09-03-advisories.md))
a hickory-dns maintainer replied: "Yes, would be great if you can help getting these into RustSec", and confirmed the
reading of the version ranges (the DNSSEC code moved from hickory-proto to hickory-net during the 0.26.0 cycle).

The 38 advisories are being sent one crate at a time, with one commit per advisory:

1. **hickory-proto, five advisories fixed in 0.26.2**, all in hickory-dns/hickory-dns#3871:
   - GHSA-hx8c-fjhc-hmf5: SVCB/HTTPS `alpn` parse panic. Fix 80eaf9e.
   - GHSA-wgfr-mphw-j5g4: SVCB/HTTPS lone-quote slice panic. Fix c663b60.
   - GHSA-4rph-pmrw-mwpw: zone lexer assertion on tokens of 4,096+ characters. Fix 0494e15.
   - GHSA-x962-5xwx-fr8x: TSIG decode underflow. Fix b1246a8.
   - GHSA-67wc-6jq8-ghrc: header-count preallocation, capped at 8 entries. Fix 280c0e5.

   This batch was queued on 2026-11-11.
2. **hickory-net, high-severity DNSSEC advisories** (drafted, sent after batch 1 is reviewed): GHSA-588m-chg6-8jqj
   (inverted NSEC3 wraparound comparison, 87ee4f8), GHSA-qw83-5pm2-ggp5 (NSEC wraparound trusted an unvalidated SOA,
   e5ca40a), GHSA-2vgh-3wfw-qj7c (RRSIG signer name not checked against the RRset's zone, 019535e) and
   GHSA-p2jv-r3m3-7wf4 (NSEC3 owner zone not checked, 10840b8 and d2ee774).
3. Then the rest of hickory-net, plus hickory-resolver, hickory-server and hickory-recursor.

Each advisory's fix commit was found in the two release/0.26 security PRs (hickory-dns/hickory-dns#3870 and #3871),
and the changed code was read before the description was written.

## Things noticed while matching advisories to fixes

- None of the 38 advisories links a fix commit or PR, but RustSec requires `url` to be an issue, PR or commit. The
  release notes of v0.26.2 list only the two omnibus PRs. Matching was done by commit title and diff, so each match is a
  reading, not something the maintainers stated.
- GHSA-2vgh-3wfw-qj7c says the code moved from hickory-proto to hickory-net in 0.26.0, but it lists hickory-proto as
  affected only up to 0.25.0-alpha.3. That leaves 0.25.0-alpha.4 to 0.26.0-alpha.1 unexplained. The hickory-proto entry
  for this advisory is held back until the maintainers say which range is right.
- hickory-proto's crates.io history starts with a 0.1.0 placeholder (binary only), then 0.24.0. The old name
  trust-dns-proto carries the same code for the earlier ranges (from 0.18 or 0.20.1 in several advisories), but it is
  not covered here.

## Running tally of advisories merged into RustSec from this work

RUSTSEC-2026-0463, RUSTSEC-2026-0473 to RUSTSEC-2026-0479 (rust-openssl), RUSTSEC-2026-0482 (cap-primitives),
RUSTSEC-2026-0486 (rustix): 10 advisories. Six russh advisories (rustsec/advisory-db#3538) have the crate
maintainer's approval and are awaiting merge.
