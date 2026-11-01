# Late CVEs missing from reviewed GitHub advisories

On 2026-10-31, at github/advisory-database commit `8643ec65`, 642 live reviewed GHSAs had no CVE
alias even though a CVE for the same vulnerability existed. In each case, the only GitHub record
holding the CVE is a separate unreviewed GHSA that links to the reviewed one and lists no affected
package. So a lookup by that CVE (`GET /advisories?cve_id=...`) finds no package or version range.
631 of the 648 CVEs carry a vulncheck.com reference.

**OSV.dev bridges most of this gap.** On 2026-11-01, OSV.dev connected the CVE and the reviewed advisory
for 619 of the 648 pairs (95.5%). A scanner that asks OSV.dev about one of these CVEs gets the affected
package; one that asks GitHub's API by CVE does not. 29 of the CVEs had no OSV.dev record. Pre-registered
check: [study/osv-bridge-s4/RESULTS.md](../../study/osv-bridge-s4/RESULTS.md)

- Full list, one row per reviewed GHSA, twin and CVE, with the source repository:
  [study/late-cve-s3/pairs.csv](../../study/late-cve-s3/pairs.csv)
- Method, pre-registered predictions, hand-checked sample (20 of 20 same vulnerability) and limits:
  [study/late-cve-s3/RESULTS.md](../../study/late-cve-s3/RESULTS.md)
- One project worked through by hand: [rustls-webpki.md](rustls-webpki.md)
- Related: reviewed advisories that already hold a CVE but have a second live CVE for the same flaw:
  [data/duplicate-cve/README.md](../duplicate-cve/README.md)

**For maintainers:** filter `pairs.csv` on the `source_repo` column to find your advisories. If the
CVE is right for your advisory, naming it in the advisory or in your release notes helps people who
search by CVE. Corrections to the reviewed record itself can be suggested on its
github.com/advisories page ("Suggest improvements for this vulnerability").

**To check one row yourself:**
`GET https://api.github.com/advisories/{reviewed}` shows `cve_id: null`, and
`GET https://api.github.com/advisories?cve_id={cve}` returns only `{twin}`, with `vulnerabilities: []`.

Data: CC BY 4.0, derived from github/advisory-database (CC BY 4.0). Made with AI agents working for
MV2 of Munim, Inc. MV2, Munim, Inc. (mv2@munimtech.com)
