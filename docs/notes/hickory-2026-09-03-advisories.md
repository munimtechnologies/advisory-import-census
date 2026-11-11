# hickory-dns: the 38 advisories published on 2026-09-03 are not in RustSec

Checked 2026-11-11 (UTC). Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0.
Corrections welcome as an issue in this repository.

## Summary

The hickory-dns project published 38 repository security advisories on 2026-09-03
(https://github.com/hickory-dns/hickory-dns/security/advisories). Its SECURITY.md says that after an
embargo ends "an advisory goes to rustsec/advisory-db".

On 2026-11-11:

- **RustSec has none of the 38.** rustsec.org has no package page at all for hickory-resolver,
  hickory-server or hickory-dns. hickory-proto's page lists RUSTSEC-2025-0006, RUSTSEC-2026-0118 and
  RUSTSEC-2026-0119, hickory-net's lists RUSTSEC-2026-0120, and hickory-recursor's lists RUSTSEC-2026-0106.
  All of these cover advisories published before September. No open pull request in rustsec/advisory-db
  mentions hickory.
- **GitHub's reviewed Advisory Database has 3 of the 38**, all for hickory-resolver and all reviewed on
  2026-10-05: GHSA-5j98-2g5x-46v6, GHSA-6f2x-v7q7-m7m5 and GHSA-6w6g-hm98-mhgm. The query
  `api.github.com/advisories?ecosystem=rust&affects=hickory-proto,hickory-net,hickory-resolver,hickory-server,hickory-recursor,hickory-dns,hickory-client`
  returns 8 advisories, and the other 5 were published before September.
- So for **35 advisories (9 rated high by the project)**, cargo-audit and cargo-deny (RustSec),
  Dependabot (GitHub's reviewed database) and osv-scanner (OSV, which imports both) report nothing.
- **None of the 38 has a CVE ID** in the repository record. That includes the 3 that GitHub reviewed.

| crate | recent downloads (crates.io, 90 days) | 2026-09-03 advisories naming it | in RustSec | in GitHub's reviewed DB |
|---|---|---|---|---|
| hickory-proto | 34,120,022 | 21 | 0 | 0 |
| hickory-resolver | 32,194,995 | 10 | 0 | 3 |
| hickory-net | 18,902,104 | 19 | 0 | 0 |
| hickory-server | 3,261,950 | 4 | 0 | 0 |
| hickory-recursor | 2,703 | 7 | 0 | 0 |
| hickory-dns | 1,686 | 2 | 0 | 0 |

One advisory can name several crates, so the column does not add up to 38. The project rated 11 of the
38 high, 19 moderate and 8 low.

## Why it matters

Many entries give hickory-proto a range such as `<= 0.26.0-alpha.1` with **no patched version**, and give
hickory-net `0.26.0-beta.1 .. 0.26.1` patched in 0.26.2. Read literally, a project still on hickory-proto
0.24.x or 0.25.x has no fixed release in its line and gets no warning from any scanner. Only the
maintainers can say exactly how each range should be expressed for a database.

## All 38 advisories

The ranges are copied as the maintainers published them, in free text. The linked advisory is the
authority. "-" means the record gives no patched version for that crate. "Reviewed" means the advisory
is in GitHub's reviewed (global) database.

| # | advisory | project severity | crates: affected range -> patched | reviewed |
|---|---|---|---|---|
| 1 | [GHSA-67wc-6jq8-ghrc](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-67wc-6jq8-ghrc) | moderate | proto `>= 0.18` -> 0.26.2 | no |
| 2 | [GHSA-x962-5xwx-fr8x](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-x962-5xwx-fr8x) | low | proto `0.26.0 .. 0.26.1` -> 0.26.2 | no |
| 3 | [GHSA-hx8c-fjhc-hmf5](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-hx8c-fjhc-hmf5) | high | proto `v0.20.1 .. v0.26.1` -> 0.26.2 | no |
| 4 | [GHSA-wgfr-mphw-j5g4](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-wgfr-mphw-j5g4) | high | proto `v0.20.1 .. v0.26.1` -> 0.26.2 | no |
| 5 | [GHSA-4rph-pmrw-mwpw](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-4rph-pmrw-mwpw) | high | proto `0.24.0 .. 0.26.1` -> 0.26.2 | no |
| 6 | [GHSA-g5xf-qv55-wv37](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-g5xf-qv55-wv37) | moderate | hickory-dns `< 0.26.2` -> 0.26.2 | no |
| 7 | [GHSA-2f4m-fq7w-mrgx](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-2f4m-fq7w-mrgx) | moderate | hickory-dns `>=0.24.0, <=0.26.1` -> - | no |
| 8 | [GHSA-5r56-v84h-c3w5](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-5r56-v84h-c3w5) | moderate | server `>= 0.24.0` -> 0.26.2 | no |
| 9 | [GHSA-3w89-7rx5-hpwx](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3w89-7rx5-hpwx) | low | net `0.26.0 .. 0.26.1` -> 0.26.2; proto `0.25.0 .. 0.25.2` -> - | no |
| 10 | [GHSA-vrv5-968r-5ggm](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-vrv5-968r-5ggm) | low | net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2; proto `<= 0.26.0-alpha.1` -> - | no |
| 11 | [GHSA-p2jv-r3m3-7wf4](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-p2jv-r3m3-7wf4) | high | net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2; proto `<= 0.26.0-alpha.1` -> - | no |
| 12 | [GHSA-5j98-2g5x-46v6](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-5j98-2g5x-46v6) | high | resolver `*` -> 0.26.2 | yes (2026-10-05) |
| 13 | [GHSA-929p-gjf6-5hqj](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-929p-gjf6-5hqj) | moderate | proto `<= 0.26.0-alpha.1` -> -; net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 14 | [GHSA-8hq4-5836-w6q4](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-8hq4-5836-w6q4) | moderate | server `v0.25.0 .. v0.26.1` -> 0.26.2 | no |
| 15 | [GHSA-vcjp-57rr-mpfw](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-vcjp-57rr-mpfw) | moderate | recursor `v0.25.0 .. v0.25.2` -> -; resolver `v0.26.0 .. v0.26.1` -> 0.26.2 | no |
| 16 | [GHSA-v44v-c8m4-gc43](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-v44v-c8m4-gc43) | moderate | net `0.26.0 .. 0.26.1` -> 0.26.2 | no |
| 17 | [GHSA-6f2x-v7q7-m7m5](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-6f2x-v7q7-m7m5) | low (GitHub: moderate) | resolver `v0.25.0 .. v0.26.1` -> 0.26.2 | yes (2026-10-05) |
| 18 | [GHSA-cx5j-p54p-q756](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-cx5j-p54p-q756) | high | recursor `0.25.0-alpha.3 .. 0.25.2` -> -; resolver `0.26.0-alpha.1+` -> 0.26.2 | no |
| 19 | [GHSA-qw83-5pm2-ggp5](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-qw83-5pm2-ggp5) | high | net `v0.26.0 .. v0.26.1` -> 0.26.2 | no |
| 20 | [GHSA-9px7-7m25-f6q2](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-9px7-7m25-f6q2) | moderate | recursor `*` -> -; resolver `v0.26.0 .. v0.26.1` -> 0.26.2 | no |
| 21 | [GHSA-g8wg-4mwh-fjfv](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-g8wg-4mwh-fjfv) | moderate | server `<= 0.26.1` -> 0.26.2 | no |
| 22 | [GHSA-57pw-897j-v4j6](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-57pw-897j-v4j6) | moderate | net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2; proto `<= 0.26.0-alpha.1` -> - | no |
| 23 | [GHSA-7php-9j59-g3ch](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-7php-9j59-g3ch) | moderate | net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2; proto `<= 0.26.0-alpha.1` -> - | no |
| 24 | [GHSA-rx82-4p2j-j5cv](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-rx82-4p2j-j5cv) | moderate | net `v0.26.0-beta.1 .. v0.26.1` -> 0.26.2 | no |
| 25 | [GHSA-j2rc-wxwh-62g9](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-j2rc-wxwh-62g9) | low | net `v0.26.0-beta.1 .. v0.26.1` -> 0.26.2; proto `v0.24.0 .. v0.26.0-alpha.1` -> - | no |
| 26 | [GHSA-86vr-jm6c-7cpg](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-86vr-jm6c-7cpg) | moderate | proto `<= 0.26.0-alpha.1` -> -; net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 27 | [GHSA-624w-vvww-xvpw](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-624w-vvww-xvpw) | moderate | proto `0.25 .. 0.26.0-alpha.1` -> -; net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 28 | [GHSA-3r6v-f3jh-vvqm](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3r6v-f3jh-vvqm) | moderate | proto `<= 0.26.0-alpha.1` -> -; net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 29 | [GHSA-xv7c-h5g9-x25x](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-xv7c-h5g9-x25x) | low | proto `v0.25.0-alpha.1 ... 0.26.0-alpha.1` -> -; net `0.26.0-beta.1 ... 0.26.1` -> 0.26.2 | no |
| 30 | [GHSA-29q9-p769-j8gq](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-29q9-p769-j8gq) | low | recursor `0.25.0 .. 0.26.0-alpha.1` -> -; resolver `0.26.0-alpha.1 .. 0.26.1` -> 0.26.2; net `0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 31 | [GHSA-wjgj-fvg9-65w9](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-wjgj-fvg9-65w9) | low | proto `< v0.26.0-beta.1` -> -; net `v0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 32 | [GHSA-3jvh-8vj5-65rq](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-3jvh-8vj5-65rq) | moderate | proto `0.25.0-alpha.3 .. 0.25.2` -> -; net `0.26.0-alpha.1 .. 0.26.1` -> 0.26.2 | no |
| 33 | [GHSA-588m-chg6-8jqj](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-588m-chg6-8jqj) | high | net `v0.26.0-beta.1 .. v0.26.1` -> 0.26.2; proto `v0.25.0 .. v0.26.0-alpha.1` -> - | no |
| 34 | [GHSA-2hxp-x833-73f7](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-2hxp-x833-73f7) | moderate | recursor `*` -> -; resolver `v0.26.0-beta.1 .. v0.26.1` -> 0.26.2 | no |
| 35 | [GHSA-4jwp-xjwm-333g](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-4jwp-xjwm-333g) | moderate | recursor `0.25.0-alpha.3 .. 0.26.0-alpha.1` -> -; resolver `0.26.0 .. 0.26.1` -> 0.26.2; proto `0.26.0 .. 0.26.1` -> 0.26.2; server `0.25.0-alpha.1 .. 0.26.1` -> 0.26.2 | no |
| 36 | [GHSA-6w6g-hm98-mhgm](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-6w6g-hm98-mhgm) | high | resolver `0.26.0-beta.1 ... 0.26.1` -> 0.26.2 | yes (2026-10-05) |
| 37 | [GHSA-2vgh-3wfw-qj7c](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-2vgh-3wfw-qj7c) | high | proto `0.1 .. 0.25.0-alpha.3` -> -; net `v0.26.0-beta.1 .. 0.26.1` -> 0.26.2 | no |
| 38 | [GHSA-6h5c-jjg5-wj59](https://github.com/hickory-dns/hickory-dns/security/advisories/GHSA-6h5c-jjg5-wj59) | high | recursor `0.25.0-alpha.3 .. 0.25.2` -> -; resolver `0.26.0-alpha.1 .. 0.26.1` -> 0.26.2 | no |

proto = hickory-proto, net = hickory-net, resolver = hickory-resolver, server = hickory-server,
recursor = hickory-recursor, hickory-dns = the server binary crate.

## How this was checked

1. The repository's published advisories, read from
   `api.github.com/repos/hickory-dns/hickory-dns/security-advisories?state=published&per_page=100`:
   42 in total, 38 of them with publication date 2026-09-03.
2. GitHub's reviewed database, read from the `affects=` query above (8 results).
3. RustSec, read from the rustsec.org package page of each crate and from a search of pull requests in
   rustsec/advisory-db for "hickory".
4. Download counts from `crates.io/api/v1/crates/<crate>` on 2026-11-11.
5. The hickory-proto and hickory-recursor ranges were cross-checked against the machine-read records
   saved by this repository's `rustsec_import_prep.py` run of 2026-11-10 (job rustsec-import-prep-v2).

## Limits

- This note counts records. It does not judge how severe each issue is, and it does not test any code.
- Whether and how these go into RustSec is the maintainers' call. hickory-dns maintainers have filed
  RustSec advisories themselves before (rustsec/advisory-db #2813 and #2835). MV2 is asking them in a
  public issue in hickory-dns/hickory-dns before filing anything.
- hickory-dns/hickory-dns is inside the frame of this repository's pre-registered study S18
  (study/repo-advisory-census-s18/PREREG.md). This hand check was made before S18's data was collected and
  will be reported as such in S18's results. Its predictions were frozen on 2026-11-10 and are not changed.
- The 3 reviewed advisories have no CVE either. That weakens the idea, noted from the zip seed case, that
  GitHub reviews only repository advisories that carry a CVE.
