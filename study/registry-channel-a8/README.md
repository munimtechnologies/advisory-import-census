# A8 — go.mod module-path class vs the Go repo-path rescue

Re-analysis of A6's published census: within Go apps, is the repo-path rescue confined
to modules whose `go.mod` path is the repository root, and does it fail for vanity or
non-root module paths? Plan: [`PREREGISTRATION-registry-channel-a8.md`](PREREGISTRATION-registry-channel-a8.md).

| file | what it is |
|---|---|
| `fetch_inputs.py` | downloads A6's census + repo probe and A5's statistics module from `main`, checks each git blob sha against the committed one, and hashes the analysis code that runs beside them |
| `gomod_class_analysis.py` | the pre-registered analysis (classes, per-class Wilson CIs, repo-level permutation, verdict) |
| `test_gomod_class.py` | offline unit tests (the end-to-end ones need the fetched A5 module and skip without it) |

Reproduce: `python fetch_inputs.py --dest . --out-dir out && python gomod_class_analysis.py --census-csv oos_go_rescue_census.csv --probe-csv oos_go_rescue_repo_probe.csv --out-dir out`

**Note on the verdict rule, written before any result.** In the frozen code block, the
first line already returns CONFOUNDED_INSEPARABLE whenever `non_root` has fewer than 4
package-less advisories, so its INCONCLUSIVE_UNDERPOWERED line can never fire, while the
power paragraph says 1–3 such advisories should read as INCONCLUSIVE_UNDERPOWERED. The
code applies the frozen block verbatim as `verdict` and also reports the paragraph's
reading as `verdict_prose_reading`. The two can differ only when `non_root` has 1–3
package-less advisories; RESULTS.md will lead with `verdict` and give both.

Apache-2.0 (code) / CC BY 4.0 (text & data). Made with AI agents working for MV2 of
Munim, Inc.
