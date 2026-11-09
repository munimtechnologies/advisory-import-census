# Cross-database rejected-CVE census S15: job output

CVE List release cve_2026-11-09_1500Z (2026-11-09_all_CVEs_at_midnight.zip.zip), read 2026-11-09T16:22:30Z. Script 0.1.0.

OSV exports: Go f283a685c89d4774 (12828976 bytes, Sun, 08 Nov 2026 11:02:46 GMT); crates.io 363eb996e96c35b6 (3810556 bytes, Mon, 09 Nov 2026 11:18:00 GMT); Hackage 11f5e93f87b77407 (58359 bytes, Wed, 04 Nov 2026 13:02:59 GMT); GHC d5e5a127d05800ac (2759 bytes, Tue, 08 Sep 2026 05:35:38 GMT); CRAN f71c441293f040c6 (11944 bytes, Tue, 08 Sep 2026 05:35:38 GMT); Julia 9f9841c2c242237c (2143646 bytes, Fri, 06 Nov 2026 16:02:48 GMT); Hex e349574664a701ae (1126878 bytes, Mon, 09 Nov 2026 15:33:06 GMT); opam 7665f9915144df8e (102464 bytes, Fri, 06 Nov 2026 19:18:11 GMT); Pub e19f6fa83938e3b5 (25896 bytes, Thu, 15 Oct 2026 20:33:04 GMT); SwiftURL 5e1443263829b6e6 (113094 bytes, Tue, 27 Oct 2026 16:48:18 GMT); PyPI 540a188dd9fd943e (37696551 bytes, Mon, 09 Nov 2026 09:33:07 GMT)

Gate: PASSED; counts {"osv_files": 42127, "parse_errors": 0, "source_records": 16319, "go_records": 4808, "rustsec_records": 1410, "pysec_records": 7985, "ghsa_records": 13672, "cve_records": 421272, "source_records_by_prefix": {"PYSEC": 7985, "GO": 4808, "JLSEC": 1717, "RUSTSEC": 1410, "EEF": 310, "HSEC": 39, "OSEC": 36, "RSEC": 14}}

| Prediction | Claim | Value | Held |
|---|---|---|---|
| P1 | >= 5 live source records outside PyPA (not GHSA, MAL, CVE, OSV or PYSEC) hold at least one CVE alias whose CVE record is REJECTED | 15 | yes |
| P2 | >= 50% of those non-PyPA rows are Go vulnerability database (GO-) records | [12, 15, 80.0] | yes |
| P3 | >= 60% of the GO- rows have review_status UNREVIEWED | [7, 12, 58.3] | no |
| P4 | >= 50% of the non-PyPA rows that list a GHSA alias have that GHSA live (not withdrawn) in OSV's export | [11, 15, 73.3] | yes |
| P5 | The share of live GO- and RUSTSEC- records with a CVE alias that hold a REJECTED CVE is lower than the same share for PYSEC records in the same run | [15, 5039, 0.298, 24, 7561, 0.317] | yes |
| P6 | >= 75% of the seeded sample of non-PyPA WITHDRAW_CANDIDATE rows are still live with a REJECTED CVE when checked at the source database (graded by hand after the run) | null | graded by hand after the run |

Descriptive: {"per_source": {"EEF": {"records": 310, "live": 310, "live_with_cve": 309, "rows": 0}, "GO": {"records": 4808, "live": 4771, "live_with_cve": 4446, "rows": 12}, "HSEC": {"records": 39, "live": 39, "live_with_cve": 20, "rows": 0}, "JLSEC": {"records": 1717, "live": 1713, "live_with_cve": 7, "rows": 0}, "OSEC": {"records": 36, "live": 36, "live_with_cve": 24, "rows": 0}, "PYSEC": {"records": 7985, "live": 7630, "live_with_cve": 7561, "rows": 24}, "RSEC": {"records": 14, "live": 14, "live_with_cve": 0, "rows": 0}, "RUSTSEC": {"records": 1410, "live": 1385, "live_with_cve": 593, "rows": 3}}, "rows": 39, "rows_by_source": {"PYSEC": 24, "GO": 12, "RUSTSEC": 3}, "actions": {"WITHDRAW_CANDIDATE": 21, "DROP_ALIAS": 14, "REPLACE_ALIAS": 4}, "reason_classes": {"duplicate": 15, "unspecified": 15, "other": 6, "not_vuln": 3}, "rejected_assigners": {"@huntr_ai": 13, "mitre": 8, "GitHub_M": 6, "VulnCheck": 5, "Google": 3, "redhat": 2, "@huntrdev": 1, "VulDB": 1}, "ghsa_states": {"live": 28, "withdrawn": 9, "none": 2}, "go_review_status": {"UNREVIEWED": 7, "REVIEWED": 5}, "rejected_after_publish": {"true": 27, "false": 12}, "missing_aliases": 22}
