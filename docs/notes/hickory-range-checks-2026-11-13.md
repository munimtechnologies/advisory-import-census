# hickory-dns advisories: affected ranges checked against released source (2026-11-13)

Licence: CC BY 4.0. Prepared with AI agents working for MV2 of Munim, Inc. (mv2@munimtech.com).

Before drafting RustSec entries for the hickory-dns advisories published on 2026-09-03, we read the code each fix changes in the releases on both sides of every upstream range boundary (tagged source on GitHub, and docs.rs for the 0.26.1/0.26.2 pair). For three of the seven advisories checked in the 2026-11-13 batches (57pw, 3jvh, wjgj, j2rc, vrv5, xv7c, 3w89), the affected ranges listed upstream don't match the code. In each case the fix itself is correct and is in hickory-net 0.26.2. Only the version ranges differ.

| Advisory | Upstream range | What the source shows | Effect |
|---|---|---|---|
| GHSA-3w89-7rx5-hpwx (CVE-2026-123578), UDP response with QDCOUNT=0 skips the question check | hickory-proto 0.25.0 .. 0.25.2; hickory-net 0.26.0 .. 0.26.1 | The same one-way check, `response_queries.iter().all(\|elem\| request_queries.contains(elem))`, which is true for an empty question section, is in hickory-proto v0.25.0-alpha.1 and v0.26.0-alpha.1 and in hickory-net v0.26.0-beta.1. hickory-proto 0.24.4 has no question check at all (a TODO). | Upstream misses the 0.25.0 alphas, 0.26.0-alpha.1 and the four hickory-net 0.26.0 betas. |
| GHSA-3jvh-8vj5-65rq (CVE-2026-123600), NSEC3 apex NODATA without an H(QNAME) match | hickory-proto 0.25.0-alpha.3 .. 0.25.2; hickory-net "0.26.0-alpha.1 .. 0.26.1" | hickory-net's first release is 0.26.0-beta.1. 0.26.0-alpha.1 is a hickory-proto release, and its `nsec3_validation.rs` still has the vulnerable `(None, None, None) if query_name == soa_name => Proof::Secure` arm. | Upstream misses hickory-proto 0.26.0-alpha.1. |
| GHSA-xv7c-h5g9-x25x (CVE-2026-123597), transient DS-fetch error cached as bogus | hickory-proto v0.25.0-alpha.1 .. 0.26.0-alpha.1; hickory-net 0.26.0-beta.1 .. 0.26.1 | In hickory-proto v0.25.2 and v0.26.0-alpha.1, `fetch_ds_records` also turns a lookup error into `ds_should_exist`, but `DnssecDnsHandle` has no validation cache in any hickory-proto release checked (v0.25.0-alpha.1, v0.25.2, v0.26.0-alpha.1; its fields are the inner handle, trust anchors, request depth and limits). `ValidationCache` and its `ProofErrorKind::Net` guard first appear in hickory-net 0.26.0-beta.1. | The "cached for the whole zone" effect the advisory describes can't happen in hickory-proto, so the hickory-proto range looks over-broad. |

## What we did with this
- 3jvh: the RustSec draft covers hickory-proto 0.26.0-alpha.1 (`unaffected = ["< 0.25.0-alpha.3", ">= 0.26.0-beta.1"]`) and says so in the pull request, offering to narrow it.
- 3w89: the RustSec draft uses `patched = [">= 0.26.2"]` for hickory-net (every release before the fix) and `unaffected = ["< 0.25.0-alpha.1", ">= 0.26.0-beta.1"]` for hickory-proto.
- xv7c: the RustSec draft has a hickory-net entry only, and explains why there is no hickory-proto entry, offering to add one that matches the upstream range.
The RustSec reviewers decide; these notes only record what the code shows.

## How to check
- Tagged source: `https://raw.githubusercontent.com/hickory-dns/hickory-dns/<tag>/crates/proto/src/udp/udp_client_stream.rs` (v0.24.4, v0.25.0-alpha.1, v0.26.0-alpha.1), `crates/net/src/udp/udp_client_stream.rs` (v0.26.0-beta.1), `crates/proto/src/dnssec/dnssec_dns_handle/mod.rs` (v0.25.2, v0.26.0-alpha.1), `crates/proto/src/xfer/dnssec_dns_handle.rs` (v0.25.0-alpha.1), `crates/net/src/dnssec/mod.rs` (v0.26.0-beta.1).
- Fix commits (from hickory-dns/hickory-dns#3871): 1e60815 (3w89), ffdfb29 (3jvh), 55efddf (xv7c).
- crates.io: hickory-net versions start at 0.26.0-beta.1 (2026-03-12). hickory-proto's only release before 0.24.0 is 0.1.0, a name placeholder with no library.

Limits: we sampled the boundary releases, not every release in between. We read the code but did not run an exploit against each release.
