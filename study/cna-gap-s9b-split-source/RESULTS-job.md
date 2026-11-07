# S9b: GitHub-CNA CVEs whose record names a different source advisory than it links (job output)

advisory-database 9f58b825cb0cc6baa792ddb37e7c227a5d525395 2026-10-30T15:42:09Z; cves.csv sha256 4088acc78d3211e8a5c3d2f4ddd5a308859d0fa348df02b9da1b69294481ae58; run 2026-11-06T19:59:30Z.

Gate: PASSED {"rows": true, "read_share": true, "known_cases": true}

| Prediction | Claim | Value | Held |
|---|---|---|---|
| P1 | SPLIT CVEs are between 0.2% and 3% of population CVEs whose record was read | [13, 13769, 0.09] | no |
| P2 | >= 95% of MATCH+SPLIT CVEs are MATCH | [13677, 13690, 99.91] | yes |
| P3 | >= 90% of SPLIT CVEs name a source advisory that is absent from the global database clone | [13, 13, 100.0] | yes |
| P4 | >= 70% of SPLIT CVEs had no live global advisory in S8 (coverage NONE or WITHDRAWN_ONLY) | [13, 13, 100.0] | yes |
| P5 | >= 60% of SPLIT CVEs share their umbrella advisory with at least one other SPLIT CVE | [9, 13, 69.23] | yes |
| P6 | >= 80% of SPLIT CVEs whose umbrella is a live global advisory are not in that advisory's aliases | [11, 11, 100.0] | yes |

Descriptive: {"population_rows": 13769, "class": {"MATCH": 13677, "SPLIT": 13, "NO_REF": 72, "NO_SOURCE": 7, "NOT_PUBLISHED": 0, "NO_RECORD": 0, "FETCH_ERROR": 0}, "assigner_of_read": {"GitHub_M": 13769}, "split_umbrellas": 6, "split_umbrellas_with_own_match_cve": 2, "split_source_global": {"NONE": 13}, "split_umbrella_global": {"REVIEWED": 11, "NONE": 2}, "split_s8_coverage": {"NONE": 13}, "split_by_nvd_month": {"2026-02": 2, "2026-07": 1, "2026-09": 10}, "split_top_umbrellas": {"moquette-io/moquette GHSA-5f42-97gr-vfhq": 7, "caddyserver/caddy GHSA-j8px-rmrx-76h9": 2, "laravel/framework GHSA-5vg9-5847-vvmq": 1, "outline/outline GHSA-c8xf-3j86-7686": 1, "outline/outline GHSA-mx2c-3g2x-5m9m": 1, "quinn-rs/quinn GHSA-4w2j-m93h-cj5j": 1}, "split_bundle_sizes": {"1": 4, "2": 1, "7": 1}, "sample_http_status": {"404": 10}}
