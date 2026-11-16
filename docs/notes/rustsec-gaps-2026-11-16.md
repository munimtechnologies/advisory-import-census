# Six GitHub-reviewed Rust advisories missing from RustSec: rmcp, tar, serde_with (2026-11-16)

Checked by AI agents working for MV2 of Munim, Inc. on 2026-11-16. Licence: CC BY 4.0.

`cargo audit` and `cargo deny` read only the RustSec advisory database. Dependabot reads only GitHub's
advisory database. An advisory that GitHub has reviewed but RustSec has not imported is therefore invisible
to Rust projects whose CI gate is `cargo audit` or `cargo deny`. This note lists six such advisories in
three heavily used crates, each checked against its fix and release.

| Crate | Recent downloads (90 days, crates.io) | Advisory | Severity (upstream) | Fixed in | RustSec |
|---|---|---|---|---|---|
| rmcp (official Rust SDK for the Model Context Protocol) | 29.5M | GHSA-9pj6-vhgr-3mwh / CVE-2026-63128: Streamable HTTP server session-table leak (unauthenticated DoS) | High, CVSS 3.1 7.5 | 2.0.0 | none |
| rmcp | | GHSA-33f5-2c5q-wgwj / CVE-2026-63127: OAuth client does not check the `resource` field of protected resource metadata | High, CVSS 3.1 8.2 | 2.0.0 | none |
| rmcp | | GHSA-c9xm-49cp-xcr9: OAuth client fetches server-supplied `resource_metadata` URLs (SSRF) | Moderate (CVSS 4.0 only) | 2.0.0 | none (only listed as `related` in RUSTSEC-2026-0457, a later bypass) |
| rmcp | | GHSA-9g45-5xwm-f3wc / CVE-2026-64684: custom headers sent to cross-origin redirect targets | Moderate, CVSS 3.1 6.8 | 2.1.0 | none |
| tar | 80.6M | GHSA-3pv8-6f4r-ffg2: PAX header applied to an intermediate header entry (parser differential) | Moderate | 0.4.46 | none |
| serde_with | 113.3M | GHSA-7gcf-g7xr-8hxj: `KeyValueMap` serialization panics on an empty element | Moderate (CVSS 4.0 only) | 3.21.0 | none (no serde_with page) |

## How each was checked

- **RustSec side:** the crate's folder in rustsec/advisory-db (`crates/rmcp` has RUSTSEC-2026-0189, -0457, -0461
  and -0462; `crates/tar` has RUSTSEC-2018-0002, 2021-0080, 2026-0067 and 2026-0068; `crates/serde_with` does not
  exist), the aliases of each existing entry, and a search of the advisory-db pull requests and issues for every
  GHSA and CVE ID and crate name. Nothing was found, open or closed.
- **Fix side:** merge date of each fix PR against the crates.io publish date of the patched release, plus the
  source at the release tag:
  - rmcp #934, #935 and #937 were merged on 2026-06-27, and 2.0.0 was published on 2026-06-29. In `rmcp-v2.0.0`,
    `streamable_http_server/tower.rs` validates the initialize request before `create_session()`, and `auth.rs` has
    `validate_resource_metadata_resource` and the same-origin check for resource metadata URLs.
  - rmcp #936 was merged on 2026-07-01, and 2.1.0 was published on 2026-07-02. The default client's
    `redirect(reqwest::redirect::Policy::none())` is in `rmcp-v2.1.0` and absent from `rmcp-v2.0.0`.
  - tar-rs #454 (merge commit bab14dd) and serde_with #966 (c8a1d82) were merged on the same day as tar 0.4.46
    and serde_with 3.21.0, and GitHub's compare view shows each release tag contains its fix commit.
- **Lower bounds:** rmcp 0.1.5, the release before 0.2.0, has no Streamable HTTP transport, no `auth` module and
  no features for either, so the drafted rmcp entries use `unaffected = ["< 0.2.0"]`, the same bound the rmcp
  maintainers used in RUSTSEC-2026-0462. serde_with follows upstream (`KeyValueMap` was added in 2.3.0).

## Prior art (why this is a modest finding, not a new one)

Downstream projects have already noticed parts of this gap. Some note in their own pull requests that the
rmcp 1.x advisories are GitHub-only and that `cargo audit` never flagged them (for example google/capsem#255),
and others update tar and serde_with because of GitHub alerts (for example flox/flox#4699). What we could not
find anywhere is a RustSec entry, issue or pull request for any of the six. The rmcp maintainers file RustSec
entries themselves (the June and November batches), but not these four, which were published in between.

## What happens next

RustSec entries for all six are drafted, in the RustSec format, with descriptions written from the fix
commits (CC0). They will be proposed to rustsec/advisory-db as two pull requests (rmcp; tar and serde_with)
as review capacity allows. Until they are merged: Rust projects that depend on rmcp < 2.1.0, tar < 0.4.46 or
serde_with 2.3.0 to 3.20.x and rely on `cargo audit` / `cargo deny` should check GitHub's advisory database
too (for example with `osv-scanner` on `Cargo.lock`).

## Limits

This is a coverage check from public listings plus reading the fixes; no exploit was run. Download counts are
crates.io "recent downloads" on 2026-11-16 and include CI traffic. Exposure depends on features: the rmcp
issues need the Streamable HTTP or `auth` features, and the serde_with issue needs `KeyValueMap`.

MV2, Munim, Inc. (mv2@munimtech.com). Made with AI agents.
