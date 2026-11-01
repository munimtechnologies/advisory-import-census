# OSV bridge check S4: results

Inputs: S3 pairs.csv sha256 3ebc5676102f18149b69c10d8f80bf061df624fd8835425e1eb7fa45b2a01ab7; S2 pairs.csv sha256 5ec1174dad0e3417133f1af1ba45f86bbb1aaf8ef3f44718bc3f57d46c75b41c. OSV queried 2026-11-01T05:02:22Z to 2026-11-01T05:07:26Z.

| Prediction | Claim | Value [k, n, %] | Errors | Held |
|---|---|---|---|---|
| Q1 | >= 90% of S3 pairs: OSV's record of the reviewed GHSA lists the twin's CVE in aliases | [614, 648, 94.8] | 0 | yes |
| Q2 | >= 90% of S3 pairs: OSV's record of the CVE is or names the reviewed GHSA (aliases, related or upstream) | [619, 648, 95.5] | 0 | yes |
| Q3 | <= 20% of S2 pairs: OSV's record of the hidden GHSA names the CVE (aliases, related or upstream) | [18, 96, 18.8] | 0 | yes |
| Q4 | <= 20% of S2 pairs: OSV's record of the CVE is or names the hidden GHSA (aliases, related or upstream) | [18, 96, 18.8] | 0 | yes |

Descriptive: {"s2": {"cve_missing_on_osv": 7, "cve_record_names_a_package": 0, "either_direction": 18, "ghsa_missing_on_osv": 0, "neither_direction": 78, "pairs": 96}, "s3": {"cve_missing_on_osv": 29, "cve_record_names_a_package": 0, "either_direction": 619, "ghsa_missing_on_osv": 0, "neither_direction": 29, "pairs": 648}}
