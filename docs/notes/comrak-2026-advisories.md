# comrak: two high-severity advisories from 2026 are in no scanner database (2026-11-11)

Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0. Corrections welcome as an issue in this repository.

comrak is a CommonMark/GFM Markdown parser for Rust (about 3.4 million crates.io downloads in the last 90
days; it also backs the `commonmarker` Ruby gem). Its maintainer published two high-severity repository
advisories in 2026:

| advisory | issue | affected | fixed | fix |
|---|---|---|---|---|
| [GHSA-xg9p-p4jc-c46g](https://github.com/kivikakk/comrak/security/advisories/GHSA-xg9p-p4jc-c46g) (high, published 2026-09-06) | GFM `autolink` extension: recursive email autolinking overflows the stack (aborts the process), and trailing-bracket trimming is quadratic | <= 0.54.0 | 0.55.0 | a45e2d3, 6291310 |
| [GHSA-j7hq-qg5v-47jq](https://github.com/kivikakk/comrak/security/advisories/GHSA-j7hq-qg5v-47jq) (high, CVSS 3.1 7.5, published 2026-10-25) | rendering a wide table to HTML or XML is quadratic in the number of cells per row | <= 0.57.0 | 0.58.0 | kivikakk/comrak#884 |

On 2026-11-11:

- **RustSec** lists only RUSTSEC-2021-0026 and RUSTSEC-2021-0063 for comrak, and no pull request in
  rustsec/advisory-db mentions comrak after 2023.
- **GitHub's reviewed Advisory Database** (`github.com/advisories?query=comrak`) shows five comrak
  advisories: two from 2021 and three from 2023 (GHSL-2023-047/048/049). The two 2026 advisories are not among them.
- So cargo-audit and cargo-deny (RustSec), Dependabot (GitHub's reviewed database) and osv-scanner (OSV,
  which imports both) report neither. A project on comrak 0.54 that renders untrusted Markdown with GFM
  options gets no warning.

The three 2023 advisories (moderate) are in GitHub's reviewed database but not in RustSec, so cargo-audit
users don't see them either. That is a different, older gap and is noted here only for completeness.

## What happens next

RustSec advisory files for the two 2026 advisories are drafted, with descriptions written fresh from the fix
commits (CC0). They will be sent to rustsec/advisory-db as one pull request, once fewer of MV2's earlier
pull requests are waiting for review there.

## How this was checked

The repository's advisory list (github.com/kivikakk/comrak/security/advisories), each advisory page, the
v0.55.0 and v0.58.0 release notes, the fix commits, rustsec.org/packages/comrak.html, a search of
rustsec/advisory-db pull requests for "comrak", and crates.io's API for download counts. Nothing was run.
comrak falls within the scope of this repository's pre-registered study S18, and this hand check will be
reported as such.
