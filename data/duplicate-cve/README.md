# One flaw, two CVE IDs: reviewed GitHub advisories with a second live CVE

From MV2's pre-registered study S5 ([study/second-cve-s5/RESULTS.md](../../study/second-cve-s5/RESULTS.md)),
github/advisory-database commit `7265fef7` and CVE records read on 2026-11-01.

Each row is a reviewed GHSA plus an unreviewed "twin" GHSA that lists no package and holds a different CVE for **the
same vulnerability**. These were graded SAME by hand from the two advisory texts, in a seeded sample of 40 of 71 twins.
In every row below the twin's CVE record cites the reviewed advisory. The Ghost invite-token pair was also verified by
reading both CVE records in full. The other 31 twins in the study are not graded, so this is not a complete list.

| Project | Reviewed GHSA | Its CVE (assigner, published) | Twin GHSA | Other CVE (assigner, published) |
|---|---|---|---|---|
| TryGhost/Ghost | GHSA-v6q3-xqxm-6f5v | CVE-2026-105675 (GitHub_M, 2026-10-05) | GHSA-8gr3-r7fg-c83w | CVE-2026-104416 (VulnCheck, 2026-10-02) |
| TryGhost/Ghost | GHSA-83rp-q473-j88c | CVE-2026-105683 (GitHub_M, 2026-10-05) | GHSA-phq3-mc75-42c3 | CVE-2026-103290 (VulnCheck, 2026-10-01) |
| TryGhost/Ghost | GHSA-347q-26qq-h2p6 | CVE-2026-105651 (GitHub_M, 2026-10-05) | GHSA-5pj5-x6hq-mvq7 | CVE-2026-104413 (VulnCheck, 2026-10-02) |
| TryGhost/Ghost | GHSA-4pvx-fwjj-8gpc | CVE-2026-105678 (GitHub_M, 2026-10-05) | GHSA-g74c-47mq-8gfq | CVE-2026-104412 (VulnCheck, 2026-10-02) |
| TryGhost/Ghost | GHSA-jj74-hc2q-xrvm | CVE-2026-105677 (GitHub_M, 2026-10-05) | GHSA-5pc5-4pc7-5x44 | CVE-2026-104418 (VulnCheck, 2026-10-02) |
| TryGhost/Ghost | GHSA-m382-6jw4-fmp6 | CVE-2026-105676 (GitHub_M, 2026-10-05) | GHSA-3h86-86h6-p5gj | CVE-2026-104417 (VulnCheck, 2026-10-02) |
| TryGhost/Ghost | GHSA-6q6j-f24j-p477 | CVE-2026-105681 (GitHub_M, 2026-10-05) | GHSA-83rv-pxjq-8h5x | CVE-2026-103289 (VulnCheck, 2026-10-01) |
| getgrav/grav | GHSA-fj2p-qj2f-74v5 | CVE-2026-64850 (GitHub_M, 2026-08-19) | GHSA-3q93-h5p2-5mx8 | CVE-2026-65008 (VulnCheck, 2026-07-21) |
| getgrav/grav | GHSA-mc5q-6hpj-rp7j | CVE-2026-61842 (GitHub_M, 2026-08-19) | GHSA-xg8j-6m35-m6wr | CVE-2026-61450 (VulnCheck, 2026-07-10) |
| MervinPraison/PraisonAI | GHSA-mxmx-rh57-jx58 | CVE-2026-62179 (GitHub_M, 2026-10-07) | GHSA-gp44-qpw6-vj4x | CVE-2026-61441 (VulnCheck, 2026-07-10) |
| MervinPraison/PraisonAI | GHSA-g6j7-pffp-8whg | CVE-2026-62176 (GitHub_M, 2026-10-07) | GHSA-vwv5-32vr-3jcp | CVE-2026-61444 (VulnCheck, 2026-07-10) |
| kumahq/kuma | GHSA-wvmp-6r4v-j6cv | CVE-2026-52724 (GitHub_M, 2026-09-15) | GHSA-wc82-hqx6-g35q | CVE-2026-18679 (Kong, 2026-08-12) |
| kumahq/kuma | GHSA-v95x-xhq5-4929 | CVE-2026-50166 (GitHub_M, 2026-09-15) | GHSA-26pg-x7g5-9g43 | CVE-2026-18678 (Kong, 2026-08-12) |
| zalando/skipper | GHSA-8qqm-fp2q-v734 | CVE-2026-65838 (GitHub_M, 2026-09-14) | GHSA-p75f-h73c-3rcp | CVE-2026-65604 (VulnCheck, 2026-07-23) |
| go-gitea/gitea | GHSA-2wm4-vwp6-v7xc | CVE-2026-59765 (Gitea, 2026-08-13) | GHSA-685p-fm6j-c445 | CVE-2026-34966 (VulnCheck, 2026-08-05) |
| honojs/hono | GHSA-5r4p-p66f-jhc7 | CVE-2026-111757 (GitHub_M, 2026-10-19) | GHSA-3g9q-qwv8-cxpf | CVE-2026-109955 (VulnCheck, 2026-10-13) |
| apostrophecms/apostrophe | GHSA-2j32-q6rx-h844 | CVE-2026-113670 (GitHub_M, 2026-10-20) | GHSA-cc97-9f5x-6rpj | CVE-2026-110904 (MITRE, 2026-10-15) |
| projectdiscovery/nuclei | GHSA-jm34-66cf-qpvr | CVE-2026-41645 (GitHub_M, 2026-05-08) | GHSA-vrr8-h7fq-ghr8 | CVE-2026-41282 (MITRE, 2026-04-20) |
| yahoo/serialize-javascript | GHSA-m5mm-p8h7-m29v | CVE-2026-115897 (GitHub_M, 2026-10-23) | GHSA-cvqw-cqhx-qmxc | CVE-2026-115754 (VulnCheck, 2026-10-23) |
| traefik/traefik | GHSA-rf44-j88r-hh8c | CVE-2026-88011 (GitHub_M, 2026-09-10) | GHSA-cwr6-3wm2-9xhw | CVE-2026-88879 (VulnCheck, 2026-09-10) |
| ImageMagick/ImageMagick | GHSA-273h-m46v-96q4 | CVE-2026-25984 (GitHub_M, **REJECTED** 2026-02-23, "assigned in error") | GHSA-rg39-4fm5-hrp2 | CVE-2026-56367 (VulnCheck, 2026-06-21) |

**What the table shows.** In 18 of these 21 rows, the twin's CVE was published first and the reviewed advisory's CVE
came later. In 2 rows both came the same day. In the ImageMagick row the reviewed advisory still holds a CVE that its
CNA rejected, while the live CVE sits on a twin with no package.

**Why it matters.** GitHub's `GET /advisories?cve_id=` for the twin's CVE returns only the packageless twin, so
Dependabot-style lookups by that CVE find no affected package. OSV.dev usually links the pair (see
[study/osv-bridge-s4/RESULTS.md](../../study/osv-bridge-s4/RESULTS.md)). Under the CVE Program's rules, two IDs for one
flaw should end with one rejected as a duplicate. Which one is up to the CNAs involved, and this page doesn't take a side.

**For maintainers:** if your project is listed, saying in your advisory or release notes which CVE ID you use helps
people who search by CVE. Your CNA can tell you how to handle the other ID.

**To check one row yourself:** `GET https://cveawg.mitre.org/api/cve/{CVE}` for both CVEs (state, assigner,
datePublished, references), and `GET https://api.github.com/advisories?cve_id={other CVE}`.

Data: CC BY 4.0, derived from github/advisory-database (CC BY 4.0) and CVE records. Made with AI agents working for
MV2 of Munim, Inc. MV2, Munim, Inc. (mv2@munimtech.com)
