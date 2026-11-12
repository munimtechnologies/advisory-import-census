# hickory-net: fix commits for four moderate advisories of 2026-09-03

Checked 2026-11-12 (UTC). Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0.
Corrections welcome as an issue in this repository.

The hickory-dns advisories published on 2026-09-03 do not link fix commits (see
[hickory-2026-09-03-advisories.md](hickory-2026-09-03-advisories.md)). RustSec needs a fix commit,
pull request or issue as each advisory's `url`, so we matched four more of them to their commits by
reading each diff. All five commits below are in hickory-dns/hickory-dns#3871 ("Security fixes
(release/0.26, part 2)", merged 2026-09-03, last commit "Bump version to 0.26.2").

| advisory | upstream severity | what the commit changes | fix commit |
|---|---|---|---|
| [GHSA-v44v-c8m4-gc43](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-v44v-c8m4-gc43) | moderate (CVSS 3.1 5.9) | UDP client reads the message ID from the first two bytes before parsing, ignores short or wrong-ID datagrams, and keeps listening instead of stopping after 3 datagrams | [07ff35c](https://github.com/hickory-dns/hickory-dns/commit/07ff35c1b33c1df27e398cee463e424cef951a82) |
| [GHSA-rx82-4p2j-j5cv](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-rx82-4p2j-j5cv) | moderate | DNSSEC validation cache key now holds the query and compares it (hickory-net); `Label`/`Name`/`LowerName` hashes now include label boundaries (hickory-proto) | [96b87c9](https://github.com/hickory-dns/hickory-dns/commit/96b87c9ab0f10c1331cef56f88742eb00bce71e1) + [9c82ce0](https://github.com/hickory-dns/hickory-dns/commit/9c82ce0c529d33ef4b3d6507e3b8dbbb5cd0dd48) |
| [GHSA-929p-gjf6-5hqj](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-929p-gjf6-5hqj) | moderate (CVSS 3.0 5.3) | a positive answer needs a record with the query name and the query type or CNAME | [77ec9c5](https://github.com/hickory-dns/hickory-dns/commit/77ec9c5d2e9481a0753bbaf1be3cd5175d300cff) |
| [GHSA-86vr-jm6c-7cpg](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-86vr-jm6c-7cpg) | moderate | RFC 8020 section 3.1 check: NXDOMAIN is bogus when the covering NSEC's next name is below the query name | [bfbe7ed](https://github.com/hickory-dns/hickory-dns/commit/bfbe7ede4021965526f065be9b415945ce575e29) |

## One range question (GHSA-v44v)

The advisory lists hickory-net `0.26.0 .. 0.26.1`. Reading the published source on docs.rs:

- **0.26.0:** `DnsResponse::from_buffer(response_buffer)?` ends the attempt on the first malformed
  datagram from the server's address, as the advisory describes. Wrong-ID datagrams are skipped, but
  only 3 datagrams are read before "udp receive attempts exceeded".
- **0.26.0-beta.1:** malformed datagrams are skipped, but a datagram with the wrong message ID returns
  `NetError::BadTransactionId` at once, and the same 3-datagram cap applies.

So the betas (crates.io: 0.26.0-beta.1 to beta.4, 2026-03-12 to 2026-04-14) look open to the same kind
of off-path abort by a different packet. We read only beta.1, and only the maintainers can say whether
the advisory should cover the betas. The RustSec draft keeps the published range and asks.

## Limits

- Matching is by reading each commit's diff against the advisory text. The maintainers have not
  confirmed these matches.
- 9c82ce0 changes hickory-proto, but GHSA-rx82 names only hickory-net, so the hickory-proto change has
  no advisory entry of its own.
- No code was run.
