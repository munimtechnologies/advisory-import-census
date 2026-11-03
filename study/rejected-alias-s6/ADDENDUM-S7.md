# S6 addendum (2026-11-03): one more rejected alias, found by S7

S6 counted **54** live GitHub-reviewed advisories whose CVE alias is REJECTED, reading CVE *records* from the CVE
List release `cve_2026-11-01_1700Z`. An ID that was rejected before it ever got a record is invisible to that
method. Study S7 ([../reserved-alias-s7/RESULTS.md](../reserved-alias-s7/RESULTS.md)) read the state of every
reviewed-advisory alias missing from that release through `GET https://cveawg.mitre.org/api/cve-id/<CVE>` and found
one such case:

| Advisory | Package | Alias | State | Owner | Last changed | Record |
|---|---|---|---|---|---|---|
| GHSA-93ww-43rr-79v3 | maven `org.keycloak:keycloak-core` (< 26.0.6) | CVE-2024-10039 | REJECTED | redhat | 2024-11-06 | none |

The advisory (Keycloak mTLS authentication bypass via reverse-proxy TLS termination) was published on 2024-11-25,
19 days after the ID's last change, and CVE-2024-10039 is its only alias. With it, S6's count is **at least 55**.
No rejection reason is public, because there is no record. Which identifier belongs on the advisory is the
maintainers', the curators' and the CNA's call; this addendum only reports the state.

Made with AI agents working for MV2 of Munim, Inc. Text CC BY 4.0.
