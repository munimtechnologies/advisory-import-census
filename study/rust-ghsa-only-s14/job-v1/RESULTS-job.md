# S14 job output (machine-written, not yet graded by hand)

Script ghsa_only_rust.py 0.1.0. Made with AI agents working in MV2's (Munim, Inc.) name.

Provenance: `{"bytes": 3810821, "fetched_utc": "2026-11-09T10:49:19Z", "sha256": "7abffde76a9aa47070461693799de7ac508f56ac59e9aeb814351778d32c999b", "source": "https://osv-vulnerabilities.storage.googleapis.com/crates.io/all.zip"}`

Counts: `{"eligible_ghsa": 1532, "ghsa_records": 1631, "records": 3063, "rustsec_records": 1410}`

Gate: PASSED (`{"eligible_ghsa": 1532, "min_ghsa": 300, "min_rustsec": 500, "passed": true, "rustsec_records": 1410}`)

Graded rows (GHSA published before 2026-10-01): 1492; GHSA_ONLY: 620

| prediction | result | held |
|---|---|---|
| P1_ghsa_only_at_least_100 | `{"value": 620}` | True |
| P2_recent_minus_old_at_least_10pts | `{"diff_pts": 57.6, "old": {"ghsa_only": 58, "n": 546, "share": 0.10622710622710622}, "recent": {"ghsa_only": 434, "n": 636, "share": 0.6823899371069182}}` | True |
| P3_repo_advisory_share_at_least_50pct | `{"of": 620, "share": 0.8612903225806452, "value": 534}` | True |
| P4_high_or_critical_share_at_least_30pct | `{"of": 620, "share": 0.42258064516129035, "value": 262}` | True |
| P5_distinct_crates_at_least_50 | `{"value": 703}` | True |
| P6_hand_check | `{"note": "graded by hand from sample.csv, at least 6 of 8"}` | None |

Status/reason counts: `{"COVERED/alias_in_ghsa": 862, "COVERED/reference": 9, "COVERED_WITHDRAWN/alias_in_rustsec": 1, "GHSA_ONLY": 620}`

Exploratory (not predicted): `{"eligible_by_year": {"2021": 317, "2022": 229, "2023": 133, "2024": 177, "2025": 177, "2026": 459}, "ghsa_only_by_year": {"2021": 11, "2022": 47, "2023": 48, "2024": 80, "2025": 97, "2026": 337}, "ghsa_only_crate_in_rustsec": 195, "ghsa_only_dos_like": 130, "ghsa_only_on_or_after_cutoff": 24, "ghsa_only_with_cve": 506, "rows_on_or_after_cutoff": 40}`

Seeded hand-check sample (seed 20261109): GHSA-3g92-f9ch-qjcm, GHSA-65jj-fmw8-468q, GHSA-7c4j-2m43-2mgh, GHSA-7fw6-6mfj-g3q2, GHSA-f8qm-hmm3-fv7f, GHSA-hqmp-g7ph-x543, GHSA-mphm-gqh9-q59x, GHSA-r5fr-9gmv-jggh
