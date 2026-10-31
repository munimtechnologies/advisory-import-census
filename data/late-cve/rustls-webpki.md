# Late CVEs on rustls-webpki: the CVE sits on a package-less twin

Checked 2026-10-31 (UTC) with public APIs. Made with AI agents working for MV2 of Munim, Inc.
Licence: CC BY 4.0. Part of advisory-import-census (code Apache-2.0).

## What we found

All four 2026 reviewed GitHub advisories for the Rust crate `rustls-webpki` were published from
rustls/webpki's own repository advisories **without a CVE**. On 2026-09-18 the CNA VulnCheck
assigned a CVE to each one (all four CVE records were published between 13:20:10Z and 13:20:12Z and
name the rustls/webpki repository advisory as the vendor advisory). The GitHub Advisory Database then
created a **separate unreviewed advisory** for each CVE (all at 2026-09-18T15:32:18Z) with an
**empty `vulnerabilities` list**. The reviewed records still have `cve_id: null`.

| Reviewed GHSA (crates.io `rustls-webpki`, `cve_id: null`) | RustSec | Later CVE (assigner, published) | Unreviewed GHSA holding the CVE (no packages) |
|---|---|---|---|
| GHSA-pwjx-qhcg-rvj4 (CRL Distribution Point matching) | RUSTSEC-2026-0049 | CVE-2026-93602 (VulnCheck, 2026-09-18) | GHSA-8hrm-p5h4-6vcx |
| GHSA-965h-392x-2mh5 (URI name constraints) | RUSTSEC-2026-0098 | CVE-2026-93600 (VulnCheck, 2026-09-18) | GHSA-fr4g-m728-g2mf |
| GHSA-xgp8-3hg3-c2mh (wildcard name constraints) | RUSTSEC-2026-0099 | CVE-2026-93601 (VulnCheck, 2026-09-18) | GHSA-27hx-xqx9-p6hq |
| GHSA-82j2-j2ch-gfr8 (CRL BIT STRING panic) | RUSTSEC-2026-0104 | CVE-2026-93599 (VulnCheck, 2026-09-18) | GHSA-g42g-9vm4-7gfj |

## Why it matters

- A lookup by CVE (`GET /advisories?cve_id=CVE-2026-93599`) returns only the unreviewed record, which
  names no package or version range. A scanner or SBOM tool that joins on CVE finds no affected crate.
- Dependabot alerts on `rustls-webpki` still work, because the reviewed records match by package.
- OSV already links them: RUSTSEC-2026-0104 lists both `CVE-2026-93599` and `GHSA-82j2-j2ch-gfr8`
  as aliases (and the same holds for the other three).

This is one project's instance of the largest group counted in
github/advisory-database#10224 (559 CVEs on 2026-10-08 whose only holder is an unreviewed GHSA,
while a reviewed GHSA for the same bug has no CVE). That issue gives no breakdown by CNA or timing.
Here all four come from one CNA batch, assigned five to six months after the reviewed records.

## Repeat the checks

```
GET https://api.github.com/advisories/GHSA-82j2-j2ch-gfr8          # type reviewed, cve_id null
GET https://api.github.com/advisories?cve_id=CVE-2026-93599       # only GHSA-g42g-9vm4-7gfj, vulnerabilities []
GET https://cveawg.mitre.org/api/cve/CVE-2026-93599               # assignerShortName VulnCheck
GET https://api.osv.dev/v1/vulns/RUSTSEC-2026-0104                # aliases CVE-2026-93599, GHSA-82j2-j2ch-gfr8
```

Same pattern for the other three rows. The repository advisory itself
(`GET /repos/rustls/webpki/security-advisories/GHSA-82j2-j2ch-gfr8`) also has `cve_id: null`.

## Limits

- One project, four advisories, one CNA. This shows the pattern exists; it does not measure how
  common it is or which CNAs cause most of #10224's 559.
- The fix (adding the CVE to the reviewed record and withdrawing or merging the twin) is the
  curators' and maintainers' call; whether the database can do it is described in #10224.
