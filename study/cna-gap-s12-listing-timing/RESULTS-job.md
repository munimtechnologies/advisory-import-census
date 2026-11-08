# S12: does a repository advisory that lists the CVE before NVD publishes it keep the NVD-fed record out? (job output)

Frame sha256 819b43ea612c80725c5aada9055a745346953e5db9e79940624dce550349e323; rows 18102; pools {"OO_COV": 211, "OO_UNC": 791}; sampled {"OO_COV": 211, "OO_UNC": 200}; run 2026-11-08T14:56:46Z.

Gate: PASSED {"frame_sha256": true, "rows": true, "strata": true, "s11_sample": true, "errors": true, "parse": true, "dates": true, "known": true}

Known cases: [{"ghsa": "GHSA-6g74-8cpq-g2c8", "want": "NO_CVE", "got": "NO_CVE", "want_day": "", "got_time": "2026-05-07T09:59:26Z"}, {"ghsa": "GHSA-g9cp-35m2-fjv6", "want": "LISTS_THIS", "got": "LISTS_THIS", "want_day": "", "got_time": "2026-05-07T14:21:04Z"}, {"ghsa": "GHSA-hfww-j92m-x8fv", "want": "LISTS_THIS", "got": "LISTS_THIS", "want_day": "", "got_time": "2025-02-03T06:59:59Z"}, {"ghsa": "GHSA-p97w-927q-8vxq", "want": "LISTS_THIS", "got": "LISTS_THIS", "want_day": "2026-10-08", "got_time": "2026-10-08T10:19:43Z"}, {"ghsa": "GHSA-hvpp-6mp9-frx4", "want": "LISTS_THIS", "got": "LISTS_THIS", "want_day": "2026-03-02", "got_time": "2026-03-02T08:13:31Z"}, {"ghsa": "GHSA-9wm4-9m6g-w38x", "want": "LISTS_THIS", "got": "LISTS_THIS", "want_day": "2026-07-09", "got_time": "2026-07-09T09:21:53Z"}]

| Prediction | Claim | Value | Held |
|---|---|---|---|
| T1 | Lists this CVE and published on or before NVD's day: covered share <= 12% | [44.6, 835.6, 5.3, 237] | yes |
| T2 | Lists this CVE and published after NVD's day: covered share >= 75% | [47.0, 47.0, 100.0, 39] | yes |
| T3 | Says No known CVE: covered share >= 80% | [89.2, 89.2, 100.0, 74] | yes |
| T4 | OO_UNC: <= 5% of dated listing pages were published after NVD's day | [0, 200, 0.0, 200] | yes |
| T5 | OO_COV: >= 40% of dated listing pages were published after NVD's day | [39, 76, 51.3, 76] | yes |
| T6 | The timing rule is right for >= 88% of CVEs (pool-weighted) | [957.4, 1002.0, 95.5] | yes |

Cells: {"OO_COV": {"NO_CVE": 74, "LISTS_OTHER": 25, "LT_EARLY": 37, "LT_LATE": 39, "LT_NODATE": 0, "UNPARSED": 0, "GONE": 36, "ERROR": 0}, "OO_UNC": {"NO_CVE": 0, "LISTS_OTHER": 0, "LT_EARLY": 200, "LT_LATE": 0, "LT_NODATE": 0, "UNPARSED": 0, "GONE": 0, "ERROR": 0}}
