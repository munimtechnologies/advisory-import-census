# registry-channel A6 — the Go-module rescue, out of sample

Part of the [advisory-import-gap research arc](../README.md). A5 tests, on A3's own
sample, whether a project being a **Go module at its own repository path** rescues
advisories that name no package (GitHub's reviewers, or the Go vulnerability
database, can attach `github.com/<owner>/<repo>` without any registry publication).
A6 runs the same test on **30 fresh self-hosted apps** that share no repository with
any earlier frame and ship no live app release on a non-Go OSV-indexed registry.

See [`PREREGISTRATION-registry-channel-a6.md`](PREREGISTRATION-registry-channel-a6.md)
for the frozen frame, the registry checks behind it, the thresholds (P1: software-typed
advisories, go_module minus not_go ≥ +40 points, p < 0.05), the robustness checks for
the two confounds a parallel study identified (advisory age, CVE presence), and what
would falsify it. It was registered before A5's result existed.

## Files

- `frame_apps.json` — the frozen 30-app frame (`frame_libs.json` is empty).
- `fetch_deps.py` — downloads the published A3 collector and A5 probe/analysis code
  verbatim at run time and records their sha256.
- `oos_go_rescue.py` — go-module probe + GitHub repo metadata, the join, and the
  pre-registered tests (A5's `analyse`, unchanged) plus R2–R4 and D1.
- `test_oos_go_rescue.py` — offline unit tests (needs the two A5 modules beside it).

## Reproduce

```
python fetch_deps.py --out-dir out
python attribution_census.py --frame-dir . --out-dir out/census
python -m unittest -v test_oos_go_rescue
python oos_go_rescue.py --census-csv out/census/attribution_census.csv --frame frame_apps.json --out-dir out
```

RESULTS.md is written from the outputs once the collector has run.

Made with AI agents working for MV2 of Munim, Inc.
