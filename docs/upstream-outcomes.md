# Upstream outcomes

What happened to the fixes and reports that came out of this repository's studies. Prepared with AI agents
working for MV2 of Munim, Inc. (mv2@munimtech.com). This file records only what the upstream projects did,
with links. CC BY 4.0.

## Merged or fixed

| Date (UTC) | Where | What | Outcome |
|---|---|---|---|
| 2026-11-05 | [github/advisory-database#10366](https://github.com/github/advisory-database/pull/10366) | Flowise advisory | Merged |
| 2026-11-09 | [rustsec/advisory-db#3531](https://github.com/rustsec/advisory-db/pull/3531) | openssl `aes::unwrap_key` advisory, imported from the maintainers' GitHub advisory (study [S14](../study/rust-ghsa-only-s14/RESULTS.md)) | Merged as RUSTSEC-2026-0463 |
| 2026-11-10 | [rustsec/advisory-db#3533](https://github.com/rustsec/advisory-db/pull/3533) | The other seven 2026 openssl advisories, one commit each | Merged as RUSTSEC-2026-0473 to RUSTSEC-2026-0479 |
| 2026-11-10 | [google/osv.dev#6313](https://github.com/google/osv.dev/issues/6313) | Report from study [S16](../study/osv-cve-withdrawn-s16/RESULTS.md): every rejected 2026 CVE in its sample was still live on OSV.dev | Fixed by the OSV.dev team in [google/osv.dev#6314](https://github.com/google/osv.dev/pull/6314); S17 will check the deployed result |

## Open

| Since | Where | What |
|---|---|---|
| 2026-11-09 | [pypa/advisory-database#424](https://github.com/pypa/advisory-database/pull/424) | Withdraw PYSEC-2021-126, whose only CVE was rejected (study S13) |
| 2026-11-10 | [golang/vulndb#6961](https://github.com/golang/vulndb/issues/6961) | Withdraw GO-2026-4505, whose GHSA and CVE were withdrawn and rejected (study S15) |

The RustSec imports are counted in [`docs/rustsec-import-prep.md`](rustsec-import-prep.md).
