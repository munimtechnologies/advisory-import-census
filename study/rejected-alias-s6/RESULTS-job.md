# Rejected-alias census S6: job output

advisory-database commit 8c754a94a2b53a40596f738abc8bf9c075923320 (2026-11-01T15:35:41Z); CVE List release cve_2026-11-01_1700Z (2026-11-01_all_CVEs_at_midnight.zip.zip), read 2026-11-01T18:14:59Z.

| Prediction | Claim | Value [k, n, %] | Held |
|---|---|---|---|
| P1 | >= 20 live reviewed GHSAs hold at least one CVE alias whose CVE record is REJECTED | 54 | yes |
| P2 | >= 50% of those GHSAs hold no PUBLISHED CVE alias at all | [54, 54, 100.0] | yes |
| P3 | >= 40% of those GHSAs have a found replacement: a PUBLISHED CVE named in the rejection reason or held by a linking 2025-26 unreviewed GHSA and citing the reviewed GHSA | [14, 54, 25.9] | no |
| P4 | >= 60% of the distinct REJECTED aliases were assigned by GitHub_M or VulnCheck | [18, 54, 33.3] | no |
| P5 | >= 70% of distinct replacement CVEs are held only by unreviewed GHSAs that list no package | [5, 15, 33.3] | no |
| P6 | >= 80% of the seeded grading sample: the replacement CVE describes the same flaw as the reviewed GHSA (graded by hand from grading_sample.csv before results are opened) | null | graded by hand after the run |

Descriptive: {"live_reviewed": 36244, "live_unreviewed_loaded": 122272, "reviewed_with_cve": 32550, "alias_states": {"MISSING": 143, "PUBLISHED": 32353, "REJECTED": 54}, "rows": 54, "reason_classes": {"unspecified": 18, "other": 14, "duplicate": 11, "not_vuln": 9, "error": 2}, "rejected_assigners": {"@huntr_ai": 13, "GitHub_M": 9, "VulnCheck": 9, "mitre": 8, "redhat": 4, "VulDB": 3, "apache": 3, "@huntrdev": 2, "Checkmarx": 1, "Liferay": 1, "hackerone": 1}, "untouched_since_rejection": 41, "rows_by_reviewed_year": {"2021": 2, "2022": 7, "2023": 3, "2024": 7, "2025": 17, "2026": 18}, "replacement_pairs": 15, "replacement_via": {"reason": 11, "cites": 4}, "replacement_held_by_reviewed": 9, "replacement_held_by_none": 1, "mismatch_aliases": 89, "missing_aliases": 143}
