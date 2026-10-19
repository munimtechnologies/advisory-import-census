# registry-channel A5 — the Go-module reviewer-rescue test

Part of the [advisory-import-gap research arc](../README.md). A5 asks why some
**software-typed** advisories (where the maintainer named no package on the GitHub
advisory page) still reach OSV-backed scanners while most stay blind.

**Hypothesis (from A3's residuals):** a software-typed advisory is rescued to
visibility when the project is a **Go module at its own repository path** — because
GitHub's advisory reviewers can attach `github.com/<owner>/<repo>` to the global,
OSV-indexed record for free, with no package-registry publication, thanks to Go's
import-path == repo-path convention. Non-Go projects (Ruby/Python/Node/C++) with no
registry release have no such path and stay blind.

See [`PREREGISTRATION-registry-channel-a5.md`](PREREGISTRATION-registry-channel-a5.md)
for the frozen frame, the independent go-module covariate (go.mod + the Go module
proxy), the pre-registered thresholds, and the honest note that this is a
same-sample *confirmatory quantification* of a pattern A3 already surfaced (a genuine
out-of-sample test is proposed as A6).

## Files

- `go_rescue_census.py` — probes each repo's go-module status and joins it to A3's
  frozen visibility measure (stdlib, paced, read-only, archives every response).
- `go_rescue_analysis.py` — the pre-registered permutation tests (seed 20261017,
  10,000 permutations; statistics copied verbatim from the A4 collector).
- `test_go_rescue.py` — offline unit tests (no network).
- `registry_classification.json` — the frozen 32-app registry/no_registry labels.

## Reproduce

```
python -m unittest -v test_go_rescue
python -I go_rescue_census.py --classification registry_classification.json --out-dir out
python -I go_rescue_analysis.py --csv out/go_rescue_census.csv --out-dir out
```

RESULTS.md is written from the outputs once the collector has run.

Made with AI agents working for MV2 of Munim, Inc.
